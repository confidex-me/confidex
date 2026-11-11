#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Output, Request, local_sync};
use confidex_storage::{Head, SqliteStore, Store, StoredVault};
use confidex_vault::{kdf, lock, transfer_code};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const PASSWORD: &str = "public-folder-password";
struct Keys;
impl DeviceKeys for Keys {
    async fn remove(&mut self, _: [u8; 16]) -> bool {
        true
    }
    async fn load(&mut self, _: [u8; 16]) -> Option<String> {
        None
    }
    async fn save(&mut self, _: [u8; 16], _: &str) -> bool {
        false
    }
}
async fn command(engine: &mut Engine, store: &mut SqliteStore, command: Command) -> Output {
    engine
        .execute(
            store,
            &mut Keys,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
        .unwrap()
}
async fn fixture(path: &Path) -> (SqliteStore, Engine, app::Created, lock::OpenedVault, Head) {
    let mut store = SqliteStore::open(path).unwrap();
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        &mut store,
        Command::Create {
            name: "Public folder fixture".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("create")
    };
    let vault = lock::open(
        &store.vault(created.info.id).await.unwrap().lock,
        PASSWORD.as_bytes(),
        &transfer_code::decode(&created.key).unwrap().secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let mut draft = app::new_record().unwrap();
    draft.title = "Private folder title".into();
    let mut field = app::field("password/v1").unwrap();
    field
        .values
        .insert("password".into(), "private-folder-secret".into());
    draft.fields.push(field);
    let Output::Saved(head) =
        command(&mut engine, &mut store, Command::Save { draft, epoch: 1 }).await
    else {
        panic!("save")
    };
    (store, engine, created, vault, head)
}
async fn bootstrap(
    path: &Path,
    folder: &Path,
    created: &app::Created,
) -> (SqliteStore, Engine, lock::OpenedVault) {
    let code = transfer_code::decode(&created.key).unwrap();
    let locks = local_sync::locks(folder, code.id).unwrap();
    assert_eq!(locks.len(), 1);
    let vault = lock::open(
        &locks[0],
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    store
        .create(&StoredVault {
            info: created.info.clone(),
            lock: locks[0].clone(),
        })
        .await
        .unwrap();
    let mut engine = Engine::default();
    command(
        &mut engine,
        &mut store,
        Command::Unlock {
            vault: created.info.id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await;
    (store, engine, vault)
}
async fn open(engine: &mut Engine, store: &mut SqliteStore, head: &Head) -> app::Draft {
    let Output::Draft(draft) = command(
        engine,
        store,
        Command::OpenRevision {
            record: head.record,
            revision: head.revision,
        },
    )
    .await
    else {
        panic!("draft")
    };
    draft
}
async fn save(engine: &mut Engine, store: &mut SqliteStore, draft: app::Draft) -> Head {
    let Output::Saved(head) = command(engine, store, Command::Save { draft, epoch: 2 }).await
    else {
        panic!("save")
    };
    head
}
fn records(root: &Path, created: &app::Created) -> PathBuf {
    let id = transfer_code::decode(&created.key).unwrap().id;
    root.join("confidex-sync-v1")
        .join(id.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .join("records")
}
fn blob(root: &Path, created: &app::Created, wire: &[u8]) -> PathBuf {
    let digest = Sha256::digest(wire)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    records(root, created).join(format!("{digest}.{}.record", wire.len()))
}
#[test]
fn shared_folder_preserves_parallel_edits_deletions_and_late_children() {
    let dir = tempfile::tempdir().unwrap();
    let shared = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let (mut a, mut ea, created, va, root) = fixture(&dir.path().join("a.sqlite")).await;
            assert_eq!(
                local_sync::synchronize(&mut a, &va, shared.path(), &mut || true)
                    .await
                    .unwrap()
                    .uploaded,
                1
            );
            let (mut b, mut eb, vb) =
                bootstrap(&dir.path().join("b.sqlite"), shared.path(), &created).await;
            assert_eq!(
                local_sync::synchronize(&mut b, &vb, shared.path(), &mut || true)
                    .await
                    .unwrap()
                    .downloaded,
                1
            );
            let mut draft_a = open(&mut ea, &mut a, &root).await;
            let mut draft_b = open(&mut eb, &mut b, &root).await;
            draft_a.title = "Equal branch content".into();
            draft_b.title = draft_a.title.clone();
            let branch_a = save(&mut ea, &mut a, draft_a).await;
            let branch_b = save(&mut eb, &mut b, draft_b).await;
            assert_ne!(branch_a.revision, branch_b.revision);
            for (store, vault) in [(&mut a, &va), (&mut b, &vb)] {
                local_sync::synchronize(store, vault, shared.path(), &mut || true)
                    .await
                    .unwrap();
            }
            local_sync::synchronize(&mut a, &va, shared.path(), &mut || true)
                .await
                .unwrap();
            let id = created.info.id;
            assert_eq!(
                a.snapshot(id).await.unwrap().heads,
                b.snapshot(id).await.unwrap().heads
            );
            assert_eq!(a.snapshot(id).await.unwrap().heads.len(), 2);
            let mut late = open(&mut eb, &mut b, &branch_a).await;
            late.title = "Late branch".into();
            command(
                &mut ea,
                &mut a,
                Command::Delete {
                    record: root.record,
                    expected: branch_a.revision,
                    epoch: 3,
                },
            )
            .await;
            local_sync::synchronize(&mut a, &va, shared.path(), &mut || true)
                .await
                .unwrap();
            local_sync::synchronize(&mut b, &vb, shared.path(), &mut || true)
                .await
                .unwrap();
            let late = save(&mut eb, &mut b, late).await;
            local_sync::synchronize(&mut b, &vb, shared.path(), &mut || true)
                .await
                .unwrap();
            local_sync::synchronize(&mut a, &va, shared.path(), &mut || true)
                .await
                .unwrap();
            let left = a.snapshot(id).await.unwrap();
            let right = b.snapshot(id).await.unwrap();
            assert_eq!(left.heads, right.heads);
            assert_eq!(left.heads.len(), 3);
            assert_eq!(left.objects.len(), 5);
            assert!(left.heads.contains(&branch_b) && left.heads.contains(&late));
            for object in left.objects {
                assert_eq!(
                    b.object(id, object.head.revision).await.unwrap(),
                    object.wire
                );
                assert_eq!(
                    std::fs::read(blob(shared.path(), &created, &object.wire)).unwrap(),
                    object.wire
                );
                for secret in ["Private folder title", "private-folder-secret", PASSWORD] {
                    assert!(
                        !object
                            .wire
                            .windows(secret.len())
                            .any(|bytes| bytes == secret.as_bytes())
                    );
                }
            }
            assert_eq!(
                local_sync::synchronize(&mut a, &va, shared.path(), &mut || false)
                    .await
                    .err(),
                Some(local_sync::Error::Canceled)
            );
            let absent = dir.path().join("unavailable-share");
            assert_eq!(
                local_sync::synchronize(&mut a, &va, &absent, &mut || true)
                    .await
                    .err(),
                Some(local_sync::Error::Unavailable)
            );
            assert!(!absent.exists());
        });
}
#[test]
fn folder_publication_crosses_object_and_tip_batch_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let shared = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let (mut a, mut engine, created, vault, root) =
                fixture(&dir.path().join("a.sqlite")).await;
            let mut draft = open(&mut engine, &mut a, &root).await;
            draft.title = "Equal public wide branch".into();
            for _ in 0..270 {
                save(&mut engine, &mut a, draft.clone()).await;
            }
            let report = local_sync::synchronize(&mut a, &vault, shared.path(), &mut || true)
                .await
                .unwrap();
            assert_eq!(report.uploaded, 271);
            let (mut b, _, vault_b) =
                bootstrap(&dir.path().join("b.sqlite"), shared.path(), &created).await;
            let report = local_sync::synchronize(&mut b, &vault_b, shared.path(), &mut || true)
                .await
                .unwrap();
            assert_eq!(report.downloaded, 271);
            assert_eq!(report.pending, 0);
            let left = a.snapshot(created.info.id).await.unwrap();
            let right = b.snapshot(created.info.id).await.unwrap();
            assert_eq!(left.heads.len(), 270);
            assert_eq!(left.heads, right.heads);
            assert_eq!(left.objects.len(), right.objects.len());
            for object in left.objects {
                assert_eq!(
                    b.object(created.info.id, object.head.revision)
                        .await
                        .unwrap(),
                    object.wire
                );
            }
            let repeated = local_sync::synchronize(&mut b, &vault_b, shared.path(), &mut || true)
                .await
                .unwrap();
            assert_eq!(
                (repeated.downloaded, repeated.uploaded, repeated.pending),
                (0, 0, 0)
            );
        });
}

#[test]
fn incomplete_delivery_corruption_and_failed_publication_preserve_local_tips() {
    let dir = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        let (mut a,mut engine,created,va,root)=fixture(&dir.path().join("a.sqlite")).await;
        let mut draft=open(&mut engine,&mut a,&root).await;draft.title="New private title".into();
        let child=save(&mut engine,&mut a,draft).await;
        local_sync::synchronize(&mut a,&va,source.path(),&mut ||true).await.unwrap();
        let path=dir.path().join("b.sqlite");
        let (mut b,_,vb)=bootstrap(&path,source.path(),&created).await;
        local_sync::synchronize(&mut b,&vb,destination.path(),&mut ||true).await.unwrap();
        let id=created.info.id;
        let parent_wire=a.object(id,root.revision).await.unwrap();let child_wire=a.object(id,child.revision).await.unwrap();
        std::fs::write(blob(destination.path(),&created,&child_wire),&child_wire).unwrap();
        let pending=local_sync::synchronize(&mut b,&vb,destination.path(),&mut ||true).await.unwrap();
        assert!(pending.pending>0);assert!(b.snapshot(id).await.unwrap().heads.is_empty());
        assert!(b.snapshot(id).await.unwrap().objects.is_empty());
        let parent=blob(destination.path(),&created,&parent_wire);
        std::fs::write(&parent,&parent_wire[..parent_wire.len()-1]).unwrap();
        assert!(local_sync::synchronize(&mut b,&vb,destination.path(),&mut ||true).await.unwrap().pending>0);
        let mut bad=parent_wire.clone();*bad.last_mut().unwrap()^=1;std::fs::write(&parent,&bad).unwrap();
        assert_eq!(local_sync::synchronize(&mut b,&vb,destination.path(),&mut ||true).await.err(),Some(local_sync::Error::App(app::Error::Integrity)));
        assert!(b.snapshot(id).await.unwrap().heads.is_empty());
        std::fs::write(&parent,&parent_wire).unwrap();
        let injector=rusqlite::Connection::open(&path).unwrap();
        injector.execute_batch("CREATE TRIGGER fail_folder BEFORE INSERT ON heads BEGIN SELECT RAISE(ABORT,'public folder fixture'); END;").unwrap();
        assert_eq!(local_sync::synchronize(&mut b,&vb,destination.path(),&mut ||true).await.err(),Some(local_sync::Error::App(app::Error::Storage(confidex_storage::Error::Storage))));
        assert!(b.snapshot(id).await.unwrap().heads.is_empty());
        injector.execute_batch("DROP TRIGGER fail_folder").unwrap();
        local_sync::synchronize(&mut b,&vb,destination.path(),&mut ||true).await.unwrap();
        let restored=b.snapshot(id).await.unwrap();assert_eq!(restored.heads,vec![child]);assert_eq!(restored.objects.len(),2);
        for object in restored.objects {assert_eq!(a.object(id,object.head.revision).await.unwrap(),object.wire);}
        std::fs::write(blob(destination.path(),&created,&bad),&bad).unwrap();
        assert_eq!(local_sync::synchronize(&mut b,&vb,destination.path(),&mut ||true).await.err(),Some(local_sync::Error::App(app::Error::Integrity)));
    });
}

async fn folder_command(
    engine: &mut Engine,
    store: &mut SqliteStore,
    mut command: local_sync::Command,
) -> Result<local_sync::Reply, local_sync::Error> {
    engine
        .execute_folder(store, &mut Keys, &mut command, &mut || true)
        .await
}
#[test]
fn folder_configuration_and_import_preserve_local_and_http_state() {
    let dir = tempfile::tempdir().unwrap();
    let shared = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        let (mut a, mut ea, created, _, head) = fixture(&dir.path().join("a.sqlite")).await;
        let id = created.info.id;
        let root = shared.path().canonicalize().unwrap().to_str().unwrap().to_owned();
        let configured = folder_command(&mut ea, &mut a, local_sync::Command::Configure { path: Some(root.clone()) }).await.unwrap();
        assert!(matches!(configured, local_sync::Reply::State { vault, path: Some(path) } if vault == id && path == root));
        assert!(!shared.path().join("confidex-sync-v1").exists());
        command(&mut ea, &mut a, Command::SyncConfig { server: Some("https://public.example.test/".into()) }).await;
        assert!(matches!(folder_command(&mut ea, &mut a, local_sync::Command::Status).await.unwrap(), local_sync::Reply::State { path: Some(path), .. } if path == root));
        let mut checkpoint: serde_json::Value = serde_json::from_slice(&a.sync_state(id).await.unwrap().unwrap()).unwrap();
        checkpoint["cursor"] = 42.into();
        checkpoint["private_future_setting"] = "keep".into();
        let previous = a.sync_state(id).await.unwrap();
        a.publish_branches(id, &confidex_storage::SyncCommit { previous, current: serde_json::to_vec(&checkpoint).unwrap(), objects: vec![], heads: vec![] }).await.unwrap();
        folder_command(&mut ea, &mut a, local_sync::Command::Configure { path: None }).await.unwrap();
        let mut disabled = checkpoint.clone(); disabled.as_object_mut().unwrap().remove("folder");
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&a.sync_state(id).await.unwrap().unwrap()).unwrap(), disabled);
        let before = a.sync_state(id).await.unwrap();
        assert_eq!(folder_command(&mut ea, &mut a, local_sync::Command::Configure { path: Some(dir.path().join("missing").to_str().unwrap().into()) }).await.err(), Some(local_sync::Error::Unavailable));
        assert_eq!(a.sync_state(id).await.unwrap(), before);
        folder_command(&mut ea, &mut a, local_sync::Command::Configure { path: Some(root.clone()) }).await.unwrap();
        assert!(matches!(folder_command(&mut ea, &mut a, local_sync::Command::Sync).await.unwrap(), local_sync::Reply::Synced { report, .. } if report.uploaded == 1));
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&a.sync_state(id).await.unwrap().unwrap()).unwrap(), checkpoint);
        command(&mut ea, &mut a, Command::Lock).await;
        command(&mut ea, &mut a, Command::Unlock { vault: id, password: PASSWORD.into(), key: created.key.clone(), remember: false }).await;
        assert!(matches!(folder_command(&mut ea, &mut a, local_sync::Command::Status).await.unwrap(), local_sync::Reply::State { path: Some(path), .. } if path == root));
        command(&mut ea, &mut a, Command::SyncConfig { server: None }).await;
        assert!(matches!(folder_command(&mut ea, &mut a, local_sync::Command::Status).await.unwrap(), local_sync::Reply::State { path: Some(path), .. } if path == root));
        assert!(matches!(folder_command(&mut ea, &mut a, local_sync::Command::Sync).await.unwrap(), local_sync::Reply::Synced { report, .. } if report.uploaded == 0));
        let mut b = SqliteStore::open(&dir.path().join("b.sqlite")).unwrap();
        let mut eb = Engine::default();
        let import = |password: &str, name: &str| local_sync::Command::Import { name: name.into(), password: password.into(), key: created.key.clone(), path: root.clone(), remember: false };
        assert_eq!(folder_command(&mut eb, &mut b, import("wrong", "Other name")).await.err(), Some(local_sync::Error::App(app::Error::Auth)));
        assert!(b.vaults().await.unwrap().is_empty());
        assert_eq!(eb.execute_folder(&mut b, &mut Keys, &mut import(PASSWORD, "Other name"), &mut || false).await.err(), Some(local_sync::Error::Canceled));
        assert!(b.vaults().await.unwrap().is_empty());
        let opened = folder_command(&mut eb, &mut b, import(PASSWORD, "Imported folder")).await.unwrap();
        assert!(matches!(opened, local_sync::Reply::Opened { info, server: None, remembered: false } if info.id == id && info.name == "Imported folder"));
        assert!(matches!(folder_command(&mut eb, &mut b, local_sync::Command::Sync).await.unwrap(), local_sync::Reply::Synced { report, .. } if report.downloaded == 1));
        assert_eq!(b.snapshot(id).await.unwrap().heads, vec![head]);
        let before = a.snapshot(id).await.unwrap();
        assert!(matches!(folder_command(&mut ea, &mut a, import(PASSWORD, "Must not rename")).await.unwrap(), local_sync::Reply::Opened { info, server: None, .. } if info.name == created.info.name));
        assert_eq!(a.snapshot(id).await.unwrap().heads, before.heads);
        assert_eq!(a.snapshot(id).await.unwrap().objects.len(), before.objects.len());
        std::fs::rename(shared.path(), dir.path().join("unmounted")).unwrap();
        assert_eq!(folder_command(&mut eb, &mut b, local_sync::Command::Sync).await.err(), Some(local_sync::Error::Unavailable));
        folder_command(&mut eb, &mut b, local_sync::Command::Configure { path: None }).await.unwrap();
        assert_eq!(folder_command(&mut eb, &mut b, local_sync::Command::Sync).await.err(), Some(local_sync::Error::App(app::Error::SyncDisabled)));
    });
}
