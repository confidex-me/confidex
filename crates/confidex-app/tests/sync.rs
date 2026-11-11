#![cfg(not(target_arch = "wasm32"))]
use axum::{
    Router,
    body::{Body, to_bytes},
};
use confidex_app::{
    self as app, Command, DeviceKeys, Engine, Error, Output, Request,
    sync::{MAX_BODY, Reply, Report, Transport},
};
use confidex_storage::{SqliteStore, Store};
use confidex_vault::{envelope, kdf, lock, resources::MAX_OPEN_MEMORY, transfer_code};
use std::collections::BTreeMap;
use tower::ServiceExt;

const SERVER: &str = "https://sync.fixture.test/";
const PASSWORD: &str = "public-test-password";
const TAG: &str = "private-tag-never-on-server-fixture";
#[derive(Default)]
struct Keys(BTreeMap<[u8; 16], String>);
impl DeviceKeys for Keys {
    async fn remove(&mut self, id: [u8; 16]) -> bool {
        if let Some(mut key) = self.0.remove(&id) {
            zeroize::Zeroize::zeroize(&mut key);
        }
        true
    }

    async fn load(&mut self, id: [u8; 16]) -> Option<String> {
        self.0.get(&id).cloned()
    }
    async fn save(&mut self, id: [u8; 16], key: &str) -> bool {
        self.0.insert(id, key.into());
        true
    }
}
struct Server {
    router: Router,
    secret: [u8; 32],
    code: String,
    lose_reply: bool,
    corrupt_page: bool,
    paginated: bool,
    methods: Vec<String>,
    fake_cursor: Option<String>,
}
impl Transport for Server {
    async fn send(
        &mut self,
        url: &str,
        method: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Reply, Error> {
        self.methods.push(method.to_owned());
        assert!(url.starts_with(SERVER));
        assert!(!url.contains(&self.code));
        assert!(!body.windows(32).any(|v| v == self.secret));
        assert!(
            !body
                .windows(PASSWORD.len())
                .any(|v| v == PASSWORD.as_bytes())
        );
        assert!(!body.windows(TAG.len()).any(|v| v == TAG.as_bytes()));
        let response = self
            .router
            .clone()
            .oneshot(
                http::Request::builder()
                    .method(method)
                    .uri(format!("/{}", url.strip_prefix(SERVER).unwrap()))
                    .header("Content-Type", content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let headers = response.headers();
        let mut result = Reply {
            status: response.status().as_u16(),
            content_type: headers
                .get("Content-Type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .into(),
            etag: headers
                .get("ETag")
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned),
            cursor: headers
                .get("Sync-Cursor")
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned),
            max_body: headers
                .get("Sync-Max-Body-Bytes")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok()),
            body: to_bytes(response.into_body(), MAX_BODY)
                .await
                .unwrap()
                .to_vec(),
        };
        if method == "GET"
            && url.contains("/records?")
            && result.body.windows(15).any(|w| w == b"\"has_more\":true")
        {
            self.paginated = true;
        }
        if method == "HEAD"
            && let Some(cursor) = &self.fake_cursor
        {
            result.cursor = Some(cursor.clone());
        }
        if self.corrupt_page && method == "GET" && url.contains("/records?") {
            let marker = b"name=\"record\"";
            if let Some(part) = result.body.windows(marker.len()).position(|w| w == marker) {
                let header = result.body[part..]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .unwrap()
                    + part
                    + 4;
                result.body[header + 32] ^= 1;
            }
        }
        if self.lose_reply && method == "POST" && url.ends_with("/records") && result.status == 200
        {
            self.lose_reply = false;
            return Err(Error::Network);
        }
        Ok(result)
    }
}
async fn run(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    server: &mut Server,
    command: Command,
) -> Result<Output, Error> {
    engine
        .execute_with_transport(
            store,
            keys,
            server,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
}
async fn sync(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    server: &mut Server,
) -> Report {
    for _ in 0..128 {
        let Output::Synced(report) = run(
            engine,
            store,
            keys,
            server,
            Command::Sync {
                server: SERVER.into(),
            },
        )
        .await
        .unwrap() else {
            panic!("sync output")
        };
        if !report.more {
            return report;
        }
    }
    panic!("sync did not converge")
}
async fn draft(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    server: &mut Server,
    record: [u8; 16],
) -> app::Draft {
    let Output::Draft(d) = run(engine, store, keys, server, Command::Open { record })
        .await
        .unwrap()
    else {
        panic!("draft")
    };
    d
}
async fn search_rows(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    server: &mut Server,
    query: &str,
) -> Vec<app::Summary> {
    for _ in 0..32 {
        match run(
            engine,
            store,
            keys,
            server,
            Command::Search {
                query: query.into(),
                after: None,
                tag: None,
                refresh: false,
            },
        )
        .await
        .unwrap()
        {
            Output::Indexing => (),
            Output::Rows { rows, .. } => return rows,
            _ => panic!("search output"),
        }
    }
    panic!("search did not finish");
}
async fn advance_branch(
    store: &mut SqliteStore,
    vault: &lock::OpenedVault,
    parent: &confidex_storage::Head,
    epoch: u64,
    deleted: bool,
    replace: bool,
) -> confidex_storage::Head {
    use confidex_storage::{Head, HeadChange, StoredObject, SyncCommit};
    let wire = store
        .object(vault.vault_id(), parent.revision)
        .await
        .unwrap();
    let opened = envelope::open(
        &wire,
        vault.keys(),
        vault.anchor(),
        Some(&parent.revision),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let record = if deleted {
        confidex_vault::record::Record::default()
    } else {
        opened.record
    };
    let wire = envelope::seal(
        &record,
        vault.keys(),
        envelope::Options {
            vault_id: vault.vault_id(),
            record_id: parent.record,
            parents: &[parent.revision],
            epoch,
            kind: if deleted {
                envelope::EventKind::Deletion
            } else {
                envelope::EventKind::Content
            },
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
        .unwrap()
        .id();
    let head = Head {
        record: parent.record,
        revision,
    };
    let previous = store.sync_state(vault.vault_id()).await.unwrap();
    store
        .publish_branches(
            vault.vault_id(),
            &SyncCommit {
                current: previous.clone().unwrap(),
                previous,
                objects: vec![StoredObject {
                    head: head.clone(),
                    wire,
                    tags: record.tags.clone(),
                }],
                heads: vec![HeadChange {
                    head: head.clone(),
                    expected: replace.then_some(parent.revision),
                }],
            },
        )
        .await
        .unwrap();
    head
}

async fn record_branches(
    store: &mut SqliteStore,
    vault: [u8; 16],
    record: [u8; 16],
) -> Vec<confidex_storage::Head> {
    let mut all = Vec::new();
    loop {
        let page = store.branch_heads(vault, all.last(), None).await.unwrap();
        if page.is_empty() {
            break;
        }
        all.extend(page);
    }
    all.into_iter()
        .filter(|head| head.record == record)
        .collect()
}

#[test]
fn a_bridge_exchanges_unchanged_history_with_a_folder_only_device() {
    let dir = tempfile::tempdir().unwrap();
    let shared = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut a = SqliteStore::open(&dir.path().join("bridge.sqlite")).unwrap();
            let mut b = SqliteStore::open(&dir.path().join("folder-only.sqlite")).unwrap();
            let mut c = SqliteStore::open(&dir.path().join("http-only.sqlite")).unwrap();
            let (mut ea, mut eb, mut ec) =
                (Engine::default(), Engine::default(), Engine::default());
            let (mut ka, mut kb, mut kc) = (Keys::default(), Keys::default(), Keys::default());
            let mut server = Server {
                router: confidexsyncd::native::router(
                    confidexsyncd::native::Index::open(":memory:")
                        .await
                        .unwrap(),
                    vec![confidexsyncd::native::Blobs::posix(dir.path().join("objects")).unwrap()],
                    confidexsyncd::Limits::default(),
                ),
                secret: [0; 32],
                code: String::new(),
                lose_reply: false,
                corrupt_page: false,
                paginated: false,
                methods: vec![],
                fake_cursor: None,
            };
            let Output::Created(created) = run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::Create {
                    name: "Bridge".into(),
                    password: PASSWORD.into(),
                    remember: true,
                },
            )
            .await
            .unwrap() else {
                panic!("create")
            };
            let id = created.info.id;
            let code = transfer_code::decode(&created.key).unwrap();
            server.secret = *code.secret;
            server.code = created.key.clone();
            let mut original = app::new_record().unwrap();
            original.title = "Original bridge record".into();
            original.tags = vec![TAG.into()];
            let Output::Saved(root) = run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::Save {
                    draft: original,
                    epoch: 1,
                },
            )
            .await
            .unwrap() else {
                panic!("save")
            };
            ea.synchronize_folder(&mut a, shared.path(), &mut || true)
                .await
                .unwrap();
            let locks = app::local_sync::locks(shared.path(), code.id).unwrap();
            b.create(&confidex_storage::StoredVault {
                info: created.info.clone(),
                lock: locks[0].clone(),
            })
            .await
            .unwrap();
            run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::Unlock {
                    vault: id,
                    password: PASSWORD.into(),
                    key: created.key.clone(),
                    remember: true,
                },
            )
            .await
            .unwrap();
            eb.synchronize_folder(&mut b, shared.path(), &mut || true)
                .await
                .unwrap();
            assert!(server.methods.is_empty());
            run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::SyncConfig {
                    server: Some(SERVER.into()),
                },
            )
            .await
            .unwrap();
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            run(
                &mut ec,
                &mut c,
                &mut kc,
                &mut server,
                Command::Import {
                    name: "HTTP only".into(),
                    password: PASSWORD.into(),
                    key: created.key.clone(),
                    server: SERVER.into(),
                    remember: true,
                    use_device_unlock: None,
                },
            )
            .await
            .unwrap();
            sync(&mut ec, &mut c, &mut kc, &mut server).await;
            let mut from_folder = draft(&mut eb, &mut b, &mut kb, &mut server, root.record).await;
            let mut from_http = draft(&mut ec, &mut c, &mut kc, &mut server, root.record).await;
            from_folder.title = "From folder".into();
            from_http.title = "From HTTP".into();
            let Output::Saved(folder_head) = run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::Save {
                    draft: from_folder,
                    epoch: 2,
                },
            )
            .await
            .unwrap() else {
                panic!("folder save")
            };
            run(
                &mut ec,
                &mut c,
                &mut kc,
                &mut server,
                Command::Save {
                    draft: from_http,
                    epoch: 2,
                },
            )
            .await
            .unwrap();
            sync(&mut ec, &mut c, &mut kc, &mut server).await;
            eb.synchronize_folder(&mut b, shared.path(), &mut || true)
                .await
                .unwrap();
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            assert!(
                search_rows(&mut ea, &mut a, &mut ka, &mut server, "From folder")
                    .await
                    .is_empty()
            );
            let checkpoint = a.sync_state(id).await.unwrap();
            ea.synchronize_folder(&mut a, shared.path(), &mut || true)
                .await
                .unwrap();
            assert_eq!(a.sync_state(id).await.unwrap(), checkpoint);
            assert_eq!(
                search_rows(&mut ea, &mut a, &mut ka, &mut server, "From folder")
                    .await
                    .len(),
                1
            );
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut ec, &mut c, &mut kc, &mut server).await;
            eb.synchronize_folder(&mut b, shared.path(), &mut || true)
                .await
                .unwrap();
            assert_eq!(a.snapshot(id).await.unwrap().heads.len(), 2);
            assert_eq!(
                a.snapshot(id).await.unwrap().heads,
                b.snapshot(id).await.unwrap().heads
            );
            assert_eq!(
                a.snapshot(id).await.unwrap().heads,
                c.snapshot(id).await.unwrap().heads
            );
            let Output::Draft(mut late) = run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::OpenRevision {
                    record: folder_head.record,
                    revision: folder_head.revision,
                },
            )
            .await
            .unwrap() else {
                panic!("selected folder branch")
            };
            late.title = "Folder grandchild".into();
            run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::Save {
                    draft: late,
                    epoch: 3,
                },
            )
            .await
            .unwrap();
            let requests = server.methods.len();
            eb.synchronize_folder(&mut b, shared.path(), &mut || true)
                .await
                .unwrap();
            assert_eq!(server.methods.len(), requests);
            ea.synchronize_folder(&mut a, shared.path(), &mut || true)
                .await
                .unwrap();
            server.lose_reply = true;
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::Sync {
                        server: SERVER.into()
                    }
                )
                .await,
                Err(Error::Network)
            ));
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut ec, &mut c, &mut kc, &mut server).await;
            ea.synchronize_folder(&mut a, shared.path(), &mut || true)
                .await
                .unwrap();
            eb.synchronize_folder(&mut b, shared.path(), &mut || true)
                .await
                .unwrap();
            let left = a.snapshot(id).await.unwrap();
            assert_eq!(left.objects.len(), 4);
            assert_eq!(left.heads.len(), 2);
            assert_eq!(left.heads, b.snapshot(id).await.unwrap().heads);
            assert_eq!(left.heads, c.snapshot(id).await.unwrap().heads);
            for object in left.objects {
                assert_eq!(
                    b.object(id, object.head.revision).await.unwrap(),
                    object.wire
                );
                assert_eq!(
                    c.object(id, object.head.revision).await.unwrap(),
                    object.wire
                );
            }
            assert!(
                app::sync::configured_server(&mut b, id)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
}

#[test]
fn two_devices_restore_preserve_branches_and_signed_deletions() {
    let dir = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut a = SqliteStore::open(&dir.path().join("a.sqlite")).unwrap();
            let mut b = SqliteStore::open(&dir.path().join("b.sqlite")).unwrap();
            let (mut ea, mut eb) = (Engine::default(), Engine::default());
            let (mut ka, mut kb) = (Keys::default(), Keys::default());
            let mut server = Server {
                router: confidexsyncd::native::router(
                    confidexsyncd::native::Index::open(":memory:")
                        .await
                        .unwrap(),
                    vec![confidexsyncd::native::Blobs::posix(dir.path().join("objects")).unwrap()],
                    confidexsyncd::Limits::default(),
                ),
                secret: [0; 32],
                code: String::new(),
                lose_reply: false,
                corrupt_page: false,
                paginated: false,
                methods: vec![],
                fake_cursor: None,
            };
            let Output::Created(created) = run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::Create {
                    name: "A".into(),
                    password: PASSWORD.into(),
                    remember: true,
                },
            )
            .await
            .unwrap() else {
                panic!("create")
            };
            let id = created.info.id;
            server.secret = *transfer_code::decode(&created.key).unwrap().secret;
            server.code = created.key.clone();
            let mut d = app::new_record().unwrap();
            d.title = "Original".into();
            d.tags = vec![TAG.into()];
            let record = d.record;
            for index in 0..17 {
                let mut extra = app::new_record().unwrap();
                extra.title = format!("Extra {index}");
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::Save {
                        draft: extra,
                        epoch: 1,
                    },
                )
                .await
                .unwrap();
            }
            run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::Save { draft: d, epoch: 1 },
            )
            .await
            .unwrap();
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::Sync {
                        server: SERVER.into()
                    }
                )
                .await,
                Err(Error::SyncDisabled)
            ));
            run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::SyncConfig {
                    server: Some(SERVER.into()),
                },
            )
            .await
            .unwrap();
            server.lose_reply = true;
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::Sync {
                        server: SERVER.into()
                    }
                )
                .await,
                Err(Error::Network)
            ));
            assert!(
                sync(&mut ea, &mut a, &mut ka, &mut server)
                    .await
                    .conflicts
                    .is_empty()
            );
            let before = a.sync_state(id).await.unwrap();
            server.methods.clear();
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::CheckSync {
                        server: SERVER.into()
                    }
                )
                .await
                .unwrap(),
                Output::SyncUnchanged
            ));
            assert_eq!(server.methods, ["HEAD"]);
            assert_eq!(a.sync_state(id).await.unwrap(), before);
            server.fake_cursor = Some("0".into());
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::CheckSync {
                        server: SERVER.into()
                    }
                )
                .await,
                Err(Error::Integrity)
            ));
            assert_eq!(a.sync_state(id).await.unwrap(), before);
            server.fake_cursor = None;
            run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::Import {
                    name: "B".into(),
                    password: PASSWORD.into(),
                    key: created.key.clone(),
                    server: SERVER.into(),
                    remember: true,
                    use_device_unlock: None,
                },
            )
            .await
            .unwrap();
            let checkpoint = b.sync_state(id).await.unwrap();
            assert!(
                search_rows(&mut eb, &mut b, &mut kb, &mut server, "Original")
                    .await
                    .is_empty()
            );
            server.corrupt_page = true;
            assert!(matches!(
                run(
                    &mut eb,
                    &mut b,
                    &mut kb,
                    &mut server,
                    Command::Sync {
                        server: SERVER.into()
                    }
                )
                .await,
                Err(Error::Integrity)
            ));
            assert!(b.head(id, record).await.unwrap().is_none());
            assert_eq!(b.sync_state(id).await.unwrap(), checkpoint);
            assert!(b.tagged_heads(id, TAG, None).await.unwrap().is_empty());
            server.corrupt_page = false;
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            assert_eq!(
                search_rows(&mut eb, &mut b, &mut kb, &mut server, "Original")
                    .await
                    .len(),
                1
            );
            assert!(server.paginated);
            let Output::Rows { rows, .. } = run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::List {
                    after: None,
                    tag: Some(TAG.into()),
                },
            )
            .await
            .unwrap() else {
                panic!("tagged rows")
            };
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].head.record, record);
            assert_eq!(rows[0].tags, [TAG]);
            let mut da = draft(&mut ea, &mut a, &mut ka, &mut server, record).await;
            let mut db = draft(&mut eb, &mut b, &mut kb, &mut server, record).await;
            assert_eq!(db.title, "Original");
            da.title = "A offline change".into();
            da.tags = vec!["a-tag".into()];
            db.title = "B offline change".into();
            db.tags = vec!["b-tag".into()];
            run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::Save {
                    draft: da,
                    epoch: 10,
                },
            )
            .await
            .unwrap();
            run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::Save {
                    draft: db,
                    epoch: 10,
                },
            )
            .await
            .unwrap();
            let branch_a = a.head(id, record).await.unwrap().unwrap();
            let branch_b = b.head(id, record).await.unwrap().unwrap();
            let original_a = a.object(id, branch_a.revision).await.unwrap();
            let original_b = b.object(id, branch_b.revision).await.unwrap();
            server.methods.clear();
            let Output::Synced(pushed) = run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::CheckSync {
                    server: SERVER.into(),
                },
            )
            .await
            .unwrap() else {
                panic!("local change was skipped");
            };
            assert_eq!(pushed.uploaded, 1);
            assert_eq!(server.methods.first().unwrap(), "HEAD");
            assert!(server.methods.iter().any(|m| m == "POST"));
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            server.methods.clear();
            let Output::Synced(report) = run(
                &mut eb,
                &mut b,
                &mut kb,
                &mut server,
                Command::CheckSync {
                    server: SERVER.into(),
                },
            )
            .await
            .unwrap() else {
                panic!("remote change was skipped");
            };
            assert_eq!(server.methods.first().unwrap(), "HEAD");
            assert!(report.conflicts.is_empty());
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            let tips = record_branches(&mut a, id, record).await;
            assert_eq!(tips.len(), 2);
            assert!(tips.contains(&branch_a) && tips.contains(&branch_b));
            assert_eq!(tips, record_branches(&mut b, id, record).await);
            assert_eq!(
                b.branch_heads(id, None, Some("a-tag")).await.unwrap().len(),
                1
            );
            assert_eq!(
                b.branch_heads(id, None, Some("b-tag")).await.unwrap().len(),
                1
            );
            let stored = a.vault(id).await.unwrap();
            let opened = lock::open(
                &stored.lock,
                PASSWORD.as_bytes(),
                &server.secret,
                kdf::REQUIRED_MEMORY,
            )
            .unwrap();
            let equal_a = advance_branch(&mut a, &opened, &branch_a, 20, false, true).await;
            let equal_b = advance_branch(&mut b, &opened, &branch_a, 21, false, true).await;
            assert_ne!(equal_a.revision, equal_b.revision);
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            let tips = record_branches(&mut a, id, record).await;
            assert_eq!(tips.len(), 3);
            assert!(tips.contains(&equal_a) && tips.contains(&equal_b) && tips.contains(&branch_b));
            assert_eq!(tips, record_branches(&mut b, id, record).await);
            let edited = advance_branch(&mut a, &opened, &equal_a, 30, false, true).await;
            let deleted = advance_branch(&mut b, &opened, &equal_a, 31, true, true).await;
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            let tips = record_branches(&mut a, id, record).await;
            assert_eq!(tips.len(), 4);
            assert!(tips.contains(&edited) && tips.contains(&deleted));
            assert_eq!(tips, record_branches(&mut b, id, record).await);
            let wire = a.object(id, deleted.revision).await.unwrap();
            let verified = envelope::verify(
                &wire,
                opened.anchor(),
                Some(&deleted.revision),
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            assert_eq!(verified.header().kind, envelope::EventKind::Deletion);
            assert_eq!(verified.header().parents, [equal_a.revision]);
            let Output::TrashPage { rows, .. } = run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::Trash { after: None },
            )
            .await
            .unwrap() else {
                panic!("trash");
            };
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].head, deleted);
            assert_eq!(rows[0].source, equal_a.revision);
            assert!(
                verified
                    .open(opened.keys(), MAX_OPEN_MEMORY)
                    .unwrap()
                    .entries
                    .is_empty()
            );
            assert_eq!(a.object(id, branch_a.revision).await.unwrap(), original_a);
            assert_eq!(a.object(id, branch_b.revision).await.unwrap(), original_b);
            let count = a.snapshot(id).await.unwrap().objects.len();
            for n in 0..270 {
                advance_branch(&mut a, &opened, &edited, 40 + n, false, n == 0).await;
            }
            let first = app::sync::step(&mut a, &mut server, &opened, SERVER)
                .await
                .unwrap();
            assert_eq!(first.uploaded, 8);
            assert!(first.conflicts.is_empty());
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            assert_eq!(record_branches(&mut b, id, record).await.len(), 11);
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            let tips = record_branches(&mut a, id, record).await;
            assert_eq!(tips.len(), 273);
            assert_eq!(tips, record_branches(&mut b, id, record).await);
            let snapshot = a.snapshot(id).await.unwrap();
            assert_eq!(snapshot.objects.len(), count + 270);
            assert_eq!(
                b.snapshot(id).await.unwrap().objects.len(),
                snapshot.objects.len()
            );
            for object in snapshot.objects {
                assert_eq!(
                    b.object(id, object.head.revision).await.unwrap(),
                    object.wire
                );
            }
            use confidex_storage::{Head, HeadChange, StoredObject, SyncCommit};
            let parents: Vec<_> = tips
                .iter()
                .filter(|h| h.revision != deleted.revision)
                .take(2)
                .cloned()
                .collect();
            let source = a.object(id, parents[0].revision).await.unwrap();
            let content = envelope::open(
                &source,
                opened.keys(),
                opened.anchor(),
                None,
                MAX_OPEN_MEMORY,
            )
            .unwrap()
            .record;
            let wire = envelope::seal(
                &content,
                opened.keys(),
                envelope::Options {
                    vault_id: id,
                    record_id: record,
                    parents: &parents.iter().map(|h| h.revision).collect::<Vec<_>>(),
                    epoch: 1,
                    kind: envelope::EventKind::Content,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let revision = envelope::verify(&wire, opened.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .id();
            let head = Head { record, revision };
            let previous = a.sync_state(id).await.unwrap();
            a.publish_branches(
                id,
                &SyncCommit {
                    current: previous.clone().unwrap(),
                    previous,
                    objects: vec![StoredObject {
                        head: head.clone(),
                        wire: wire.clone(),
                        tags: content.tags.clone(),
                    }],
                    heads: parents
                        .iter()
                        .map(|p| HeadChange {
                            head: head.clone(),
                            expected: Some(p.revision),
                        })
                        .collect(),
                },
            )
            .await
            .unwrap();
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            let tips = record_branches(&mut b, id, record).await;
            assert_eq!(tips.len(), 272);
            assert!(tips.contains(&head) && parents.iter().all(|p| !tips.contains(p)));
            assert_eq!(tips, record_branches(&mut a, id, record).await);
            assert_eq!(b.object(id, revision).await.unwrap(), wire);
            assert_eq!(b.snapshot(id).await.unwrap().objects.len(), count + 271);
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::CheckSync {
                        server: SERVER.into()
                    }
                )
                .await
                .unwrap(),
                Output::SyncUnchanged
            ));
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::RestoreDeleted {
                        head: deleted.clone(),
                        source: equal_a.revision,
                        epoch: 310,
                    },
                )
                .await,
                Ok(Output::Restored)
            ));
            sync(&mut ea, &mut a, &mut ka, &mut server).await;
            sync(&mut eb, &mut b, &mut kb, &mut server).await;
            let restored = record_branches(&mut b, id, record).await;
            assert_eq!(restored, record_branches(&mut a, id, record).await);
            assert_eq!(restored.len(), tips.len());
            assert!(!restored.contains(&deleted));
            assert!(
                tips.iter()
                    .filter(|tip| **tip != deleted)
                    .all(|tip| restored.contains(tip))
            );
            let newest = restored.iter().find(|tip| !tips.contains(tip)).unwrap();
            let wire = b.object(id, newest.revision).await.unwrap();
            let header = envelope::verify(
                &wire,
                opened.anchor(),
                Some(&newest.revision),
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            assert_eq!(header.header().parents, [deleted.revision]);
            assert_eq!(header.header().kind, envelope::EventKind::Content);
            run(
                &mut ea,
                &mut a,
                &mut ka,
                &mut server,
                Command::SyncConfig { server: None },
            )
            .await
            .unwrap();
            assert!(matches!(
                run(
                    &mut ea,
                    &mut a,
                    &mut ka,
                    &mut server,
                    Command::Sync {
                        server: SERVER.into()
                    }
                )
                .await,
                Err(Error::SyncDisabled)
            ));
        });
}
