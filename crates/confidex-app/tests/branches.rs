#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Error, Output, Request};
use confidex_storage::{Head, HeadChange, SqliteStore, Store, StoredObject, SyncCommit};
use confidex_vault::{envelope, kdf, lock, resources::MAX_OPEN_MEMORY, transfer_code};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Keys(BTreeMap<[u8; 16], String>);
impl DeviceKeys for Keys {
    async fn remove(&mut self, id: [u8; 16]) -> bool {
        self.0.remove(&id);
        true
    }
    async fn load(&mut self, id: [u8; 16]) -> Option<String> {
        self.0.get(&id).cloned()
    }
    async fn save(&mut self, id: [u8; 16], value: &str) -> bool {
        self.0.insert(id, value.into());
        true
    }
}
async fn run(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    command: Command,
) -> Result<Output, Error> {
    engine
        .execute(
            store,
            keys,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
}
async fn open(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    head: &Head,
) -> app::Draft {
    let Output::Draft(draft) = run(
        engine,
        store,
        keys,
        Command::OpenRevision {
            record: head.record,
            revision: head.revision,
        },
    )
    .await
    .unwrap() else {
        panic!("draft")
    };
    draft
}
async fn tips(store: &mut SqliteStore, id: [u8; 16]) -> Vec<Head> {
    let mut result = vec![];
    loop {
        let page = store.branch_heads(id, result.last(), None).await.unwrap();
        if page.is_empty() {
            return result;
        }
        result.extend(page);
    }
}

async fn trash(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
) -> Vec<app::DeletedVersion> {
    let mut output = Vec::new();
    let mut after = None;
    for _ in 0..4 {
        let Output::TrashPage { rows, next } = run(engine, store, keys, Command::Trash { after })
            .await
            .unwrap()
        else {
            panic!("trash");
        };
        output.extend(rows);
        after = next;
        if after.is_none() {
            return output;
        }
    }
    panic!("trash pagination did not finish");
}

async fn rows(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    query: &str,
    refresh: bool,
    list: bool,
) -> Vec<app::Summary> {
    let mut after = None;
    let mut output = Vec::new();
    let mut refresh = refresh;
    for _ in 0..80 {
        let command = if list {
            Command::List {
                after: after.clone(),
                tag: None,
            }
        } else {
            Command::Search {
                query: query.into(),
                after: after.clone(),
                tag: None,
                refresh,
            }
        };
        let result = run(engine, store, keys, command).await.unwrap();
        refresh = false;
        match result {
            Output::Indexing => (),
            Output::Rows { rows, more, next } => {
                output.extend(rows);
                if !more {
                    return output;
                }
                after = next;
            }
            _ => panic!("rows"),
        }
    }
    panic!("pagination did not finish")
}

#[test]
fn an_open_draft_can_fork_after_edits_and_deletions_from_another_connection() {
    let dir = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let path = dir.path().join("draft.sqlite");
            let mut store = SqliteStore::open(&path).unwrap();
            let mut keys = Keys::default();
            let mut engine = Engine::default();
            let Output::Created(created) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Create {
                    name: "Public branches".into(),
                    password: "Public password".into(),
                    remember: true,
                },
            )
            .await
            .unwrap() else {
                panic!("create")
            };
            let id = created.info.id;
            let vault = lock::open(
                &store.vault(id).await.unwrap().lock,
                b"Public password",
                &transfer_code::decode(&created.key).unwrap().secret,
                kdf::REQUIRED_MEMORY,
            )
            .unwrap();
            let mut peer_store = SqliteStore::open(&path).unwrap();
            let mut peer = Engine::default();
            run(
                &mut peer,
                &mut peer_store,
                &mut keys,
                Command::Unlock {
                    vault: id,
                    password: "Public password".into(),
                    key: String::new(),
                    remember: true,
                },
            )
            .await
            .unwrap();
            let mut original = app::new_record().unwrap();
            original.title = "Original".into();
            original.fields.push(app::field("password/v1").unwrap());
            let Output::Saved(root) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Save {
                    draft: original,
                    epoch: 1,
                },
            )
            .await
            .unwrap() else {
                panic!("root")
            };
            let base = open(&mut engine, &mut store, &mut keys, &root).await;
            let mut remote = base.clone();
            remote.title = "Peer edit".into();
            let Output::Saved(remote) = run(
                &mut peer,
                &mut peer_store,
                &mut keys,
                Command::Save {
                    draft: remote,
                    epoch: 2,
                },
            )
            .await
            .unwrap() else {
                panic!("peer")
            };
            let before = store.snapshot(id).await.unwrap();
            let mut draft = base.clone();
            draft.title = "My unsaved content".into();
            for deletion in [false, true] {
                let Output::Saved(saved) = run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Save {
                        draft: draft.clone(),
                        epoch: 1,
                    },
                )
                .await
                .unwrap() else {
                    panic!("save")
                };
                let current = tips(&mut store, id).await;
                assert!(current.contains(&saved));
                assert!(current.contains(&remote));
                assert_eq!(current.len(), if deletion { 3 } else { 2 });
                let wire = store.object(id, saved.revision).await.unwrap();
                let verified = envelope::verify(
                    &wire,
                    vault.anchor(),
                    Some(&saved.revision),
                    MAX_OPEN_MEMORY,
                )
                .unwrap();
                assert_eq!(verified.header().parents, [root.revision]);
                assert_eq!(
                    open(&mut engine, &mut store, &mut keys, &saved).await.title,
                    "My unsaved content"
                );
                if !deletion {
                    run(
                        &mut peer,
                        &mut peer_store,
                        &mut keys,
                        Command::Delete {
                            record: root.record,
                            expected: saved.revision,
                            epoch: 3,
                        },
                    )
                    .await
                    .unwrap();
                    assert!(matches!(
                        run(
                            &mut engine,
                            &mut store,
                            &mut keys,
                            Command::Delete {
                                record: root.record,
                                expected: saved.revision,
                                epoch: 4,
                            }
                        )
                        .await,
                        Err(Error::Storage(confidex_storage::Error::Conflict))
                    ));
                }
            }
            let found = rows(&mut engine, &mut store, &mut keys, "", true, false).await;
            assert_eq!(found.len(), 2);
        let local = found.iter().find(|row| row.head != remote).unwrap().head.clone();
        let previous = store.sync_state(id).await.unwrap();
        store.publish_branches(id,&SyncCommit {
            previous,
            current:serde_json::to_vec(&serde_json::json!({"server":"http://example.test/","enabled":true,"cursor":2,"heads":[remote]})).unwrap(),
            objects:vec![],heads:vec![],
        }).await.unwrap();
        let before_join = tips(&mut store,id).await;
        run(&mut engine,&mut store,&mut keys,Command::Resolve {
            record:root.record,local:local.revision,remote:remote.revision,keep_local:true,epoch:4,
        }).await.unwrap();
        let joined = tips(&mut store,id).await;
        assert_eq!(joined.len(),2);
        assert!(!joined.contains(&local) && !joined.contains(&remote));
        let joined = joined.into_iter().find(|head| !before_join.contains(head)).unwrap();
        let wire = store.object(id,joined.revision).await.unwrap();
        let opened = envelope::open(&wire,vault.keys(),vault.anchor(),Some(&joined.revision),MAX_OPEN_MEMORY).unwrap();
        assert_eq!(opened.revision.header().kind,envelope::EventKind::Content);
        let mut expected = [local.revision,remote.revision];
        expected.sort_unstable();
        assert_eq!(opened.revision.header().parents,expected);
        for object in before.objects {
                assert_eq!(
                    store.object(id, object.head.revision).await.unwrap(),
                    object.wire
                );
            }
        });
}

#[test]
fn selected_revision_edits_and_deletions_preserve_other_branches() {
    let dir = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&dir.path().join("branches.sqlite")).unwrap();
            let (mut engine, mut keys) = (Engine::default(), Keys::default());
            let Output::Created(created) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Create {
                    name: "Public branch commands".into(),
                    password: "Public password".into(),
                    remember: true,
                },
            )
            .await
            .unwrap() else {
                panic!("create")
            };
            let id = created.info.id;
            let mut draft = app::new_record().unwrap();
            draft.record = [0; 16];
            draft.title = "Original".into();
            let mut field = app::field("password/v1").unwrap();
            field
                .values
                .insert("password".into(), "public-secret-fixture".into());
            draft.fields.push(field);
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Save {
                    draft: draft.clone(),
                    epoch: 1,
                },
            )
            .await
            .unwrap();
            let root = store.head(id, draft.record).await.unwrap().unwrap();
            let stale = open(&mut engine, &mut store, &mut keys, &root).await;
            let mut other = app::new_record().unwrap();
            other.record = [255; 16];
            other.title = "Other record".into();
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Save {
                    draft: other,
                    epoch: 1,
                },
            )
            .await
            .unwrap();
            let other = store.head(id, [255; 16]).await.unwrap().unwrap();
            assert_eq!(
                rows(&mut engine, &mut store, &mut keys, "", false, false)
                    .await
                    .len(),
                2
            );
            let stored = store.vault(id).await.unwrap();
            let vault = lock::open(
                &stored.lock,
                b"Public password",
                &transfer_code::decode(&created.key).unwrap().secret,
                kdf::REQUIRED_MEMORY,
            )
            .unwrap();
            app::sync::configure(&mut store, &vault, Some("https://sync.fixture.test/"))
                .await
                .unwrap();
            let checkpoint = store.sync_state(id).await.unwrap();
            let mut metadata: serde_json::Value =
                serde_json::from_slice(checkpoint.as_ref().unwrap()).unwrap();
            metadata["public-preserved-fixture"] = "keep".into();
            let current = serde_json::to_vec(&metadata).unwrap();
            store
                .publish_branches(
                    id,
                    &SyncCommit {
                        previous: checkpoint,
                        current,
                        objects: vec![],
                        heads: vec![],
                    },
                )
                .await
                .unwrap();
            let checkpoint = store.sync_state(id).await.unwrap();
            let wire = store.object(id, root.revision).await.unwrap();
            let mut content =
                envelope::open(&wire, vault.keys(), vault.anchor(), None, MAX_OPEN_MEMORY)
                    .unwrap()
                    .record;
            let mut branches = vec![];
            for start in (0..270).step_by(90) {
                let mut objects = vec![];
                let mut changes = vec![];
                for index in start..start + 90 {
                    content.tags = vec![format!("branch-{index}")];
                    let wire = envelope::seal(
                        &content,
                        vault.keys(),
                        envelope::Options {
                            vault_id: id,
                            record_id: root.record,
                            parents: &[root.revision],
                            epoch: index,
                            kind: envelope::EventKind::Content,
                        },
                        MAX_OPEN_MEMORY,
                    )
                    .unwrap();
                    let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
                        .unwrap()
                        .id();
                    let head = Head {
                        record: root.record,
                        revision,
                    };
                    branches.push(head.clone());
                    objects.push(StoredObject {
                        head: head.clone(),
                        wire,
                        tags: content.tags.clone(),
                    });
                    changes.push(HeadChange {
                        head,
                        expected: (index == 0).then_some(root.revision),
                    });
                }
                store
                    .publish_branches(
                        id,
                        &SyncCommit {
                            previous: checkpoint.clone(),
                            current: checkpoint.clone().unwrap(),
                            objects,
                            heads: changes,
                        },
                    )
                    .await
                    .unwrap();
            }
            let before = store.snapshot(id).await.unwrap();
            assert_eq!(before.heads.len(), 271);
            let found = rows(&mut engine, &mut store, &mut keys, "Original", true, false).await;
            assert_eq!(found.len(), 270);
            assert_eq!(
                found
                    .iter()
                    .map(|r| r.head.revision)
                    .collect::<BTreeSet<_>>()
                    .len(),
                270
            );
            assert_eq!(
                rows(&mut engine, &mut store, &mut keys, "", false, true)
                    .await
                    .len(),
                271
            );
            assert!(
                rows(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    "public-secret-fixture",
                    false,
                    false
                )
                .await
                .is_empty()
            );
            assert_eq!(
                open(&mut engine, &mut store, &mut keys, &branches[269])
                    .await
                    .tags,
                ["branch-269"]
            );
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::OpenRevision {
                        record: other.record,
                        revision: branches[0].revision
                    }
                )
                .await,
                Err(Error::Storage(confidex_storage::Error::Conflict))
            ));
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::OpenRevision {
                        record: root.record,
                        revision: root.revision
                    }
                )
                .await,
                Err(Error::Storage(confidex_storage::Error::Conflict))
            ));
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::CheckDraft { draft: stale }
                )
                .await,
                Ok(Output::Checked { .. })
            ));
            assert_eq!(
                store.snapshot(id).await.unwrap().objects.len(),
                before.objects.len()
            );
            let mut edit = open(&mut engine, &mut store, &mut keys, &branches[0]).await;
            let stale = edit.clone();
            edit.title = "Edited branch".into();
            edit.fields[0]
                .values
                .insert("password".into(), "changed-public-fixture".into());
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Save {
                        draft: edit,
                        epoch: 2
                    }
                )
                .await
                .unwrap(),
                Output::Saved(_)
            ));
            let known: BTreeSet<_> = before.heads.iter().map(|h| h.revision).collect();
            let current = tips(&mut store, id).await;
            assert_eq!(current.len(), 271);
            assert!(!current.contains(&branches[0]));
            let edited = current
                .iter()
                .find(|h| !known.contains(&h.revision))
                .unwrap()
                .clone();
            let opened = open(&mut engine, &mut store, &mut keys, &edited).await;
            assert_eq!(opened.title, "Edited branch");
            assert_eq!(
                rows(&mut engine, &mut store, &mut keys, "Original", false, false)
                    .await
                    .len(),
                269
            );
            let found = rows(&mut engine, &mut store, &mut keys, "Edited", false, false).await;
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].head, edited);
            assert_eq!(
                opened.fields[0].values["password"],
                "changed-public-fixture"
            );
            assert_eq!(
                open(&mut engine, &mut store, &mut keys, &branches[269])
                    .await
                    .fields[0]
                    .values["password"],
                "public-secret-fixture"
            );
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::CheckDraft { draft: stale }
                )
                .await,
                Ok(Output::Checked { .. })
            ));
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Delete {
                    record: root.record,
                    expected: branches[269].revision,
                    epoch: 3,
                },
            )
            .await
            .unwrap();
            let current = tips(&mut store, id).await;
            assert_eq!(current.len(), 271);
            assert!(current.contains(&edited) && current.contains(&other));
            assert!(!current.contains(&branches[269]));
            assert_eq!(
                rows(&mut engine, &mut store, &mut keys, "Original", false, false)
                    .await
                    .len(),
                268
            );
            assert_eq!(
                rows(&mut engine, &mut store, &mut keys, "", false, true)
                    .await
                    .len(),
                270
            );
            assert_eq!(store.sync_state(id).await.unwrap(), checkpoint);
            assert_eq!(
                open(&mut engine, &mut store, &mut keys, &other).await.title,
                "Other record"
            );
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Open {
                        record: other.record
                    }
                )
                .await
                .unwrap(),
                Output::Draft(_)
            ));
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Open {
                        record: root.record
                    }
                )
                .await,
                Err(Error::Storage(confidex_storage::Error::Conflict))
            ));
            let mut after = None;
            let mut exports = Vec::new();
            loop {
                let page = engine
                    .export_selection(&mut store, after, &mut |_| true)
                    .await
                    .unwrap();
                exports.extend(page.rows.into_iter().map(|row| row.head.clone()));
                if !page.more {
                    break;
                }
                after = page.next;
            }
            assert_eq!(exports.len(), 270);
            assert_eq!(exports.iter().collect::<BTreeSet<_>>().len(), 270);
            for selection in [
                app::export_flow::Selection::All,
                app::export_flow::Selection::Records(vec![edited.clone(), branches[1].clone()]),
            ] {
                let all = matches!(&selection, app::export_flow::Selection::All);
                let writer = app::export::writer(
                    app::export::Format::BitwardenJson,
                    app::export::Options::default(),
                    0,
                )
                .unwrap();
                let review = engine
                    .prepare_export(
                        &mut store,
                        &selection,
                        writer,
                        app::export::Limits::default(),
                        &mut |_| true,
                    )
                    .await
                    .unwrap();
                assert_eq!(review.records, if all { 270 } else { 2 });
            }
            let deleted = current
                .iter()
                .find(|h| h.record == root.record && !known.contains(&h.revision) && **h != edited)
                .unwrap();
            let wire = store.object(id, deleted.revision).await.unwrap();
            let verified = envelope::verify(
                &wire,
                vault.anchor(),
                Some(&deleted.revision),
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            assert_eq!(verified.header().kind, envelope::EventKind::Deletion);
            assert_eq!(verified.header().parents, [branches[269].revision]);
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::OpenRevision {
                        record: root.record,
                        revision: deleted.revision
                    }
                )
                .await,
                Err(Error::Input)
            ));
            for object in before.objects {
                assert_eq!(
                    store.object(id, object.head.revision).await.unwrap(),
                    object.wire
                );
            }
            run(&mut engine, &mut store, &mut keys, Command::Lock)
                .await
                .unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Unlock {
                        vault: id,
                        password: "Public password".into(),
                        key: String::new(),
                        remember: false,
                    }
                )
                .await
                .unwrap(),
                Output::Opened { .. }
            ));
            assert_eq!(
                open(&mut engine, &mut store, &mut keys, &edited)
                    .await
                    .title,
                "Edited branch"
            );
            let expected = store.snapshot(id).await.unwrap();
            let Output::Backup(archive) =
                run(&mut engine, &mut store, &mut keys, Command::ExportBackup)
                    .await
                    .unwrap()
            else {
                panic!("backup")
            };
            let mut target = SqliteStore::open(&dir.path().join("restored.sqlite")).unwrap();
            let (mut restored, mut target_keys) = (Engine::default(), Keys::default());
            run(
                &mut restored,
                &mut target,
                &mut target_keys,
                Command::InspectBackup { archive },
            )
            .await
            .unwrap();
            run(
                &mut restored,
                &mut target,
                &mut target_keys,
                Command::RestoreBackup {
                    name: "Restored branches".into(),
                    password: "Public password".into(),
                    key: created.key.clone(),
                    remember: false,
                },
            )
            .await
            .unwrap();
            let snapshot = target.snapshot(id).await.unwrap();
            assert_eq!(snapshot.heads, expected.heads);
            assert_eq!(snapshot.objects.len(), expected.objects.len());
            for object in expected.objects {
                assert_eq!(
                    target.object(id, object.head.revision).await.unwrap(),
                    object.wire
                );
            }
            assert_eq!(
                open(&mut restored, &mut target, &mut target_keys, &edited)
                    .await
                    .title,
                "Edited branch"
            );
            let entries = trash(&mut restored, &mut target, &mut target_keys).await;
            assert_eq!(entries.len(), 1);
            assert_eq!(&entries[0].head, deleted);
            assert_eq!(entries[0].source, branches[269].revision);
            assert_eq!(entries[0].title, "Original");

            let source = &branches[1];
            let wire = envelope::seal(
                &confidex_vault::record::Record::default(),
                vault.keys(),
                envelope::Options {
                    vault_id: id,
                    record_id: root.record,
                    parents: &[deleted.revision, source.revision],
                    epoch: 4,
                    kind: envelope::EventKind::Deletion,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let merged = Head {
                record: root.record,
                revision: envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
                    .unwrap()
                    .id(),
            };
            let previous = target.sync_state(id).await.unwrap();
            target
                .publish_branches(
                    id,
                    &SyncCommit {
                        current: previous.clone().or(checkpoint).unwrap(),
                        previous,
                        objects: vec![StoredObject {
                            head: merged.clone(),
                            wire,
                            tags: vec![],
                        }],
                        heads: [deleted, source]
                            .into_iter()
                            .map(|old| HeadChange {
                                head: merged.clone(),
                                expected: Some(old.revision),
                            })
                            .collect(),
                    },
                )
                .await
                .unwrap();
            let entries = trash(&mut restored, &mut target, &mut target_keys).await;
            assert!(entries.iter().all(|row| row.head == merged));
            assert_eq!(
                entries.iter().map(|row| row.source).collect::<BTreeSet<_>>(),
                BTreeSet::from([source.revision, branches[269].revision])
            );
            let restore = |source| Command::RestoreDeleted { head: merged.clone(), source, epoch: 5 };
            assert!(matches!(
                run(&mut restored, &mut target, &mut target_keys, restore(edited.revision)).await,
                Err(Error::Input)
            ));
            let result = run(
                &mut restored,
                &mut target,
                &mut target_keys,
                Command::PreviewDeleted { head: merged.clone(), source: source.revision },
            ).await.unwrap();
            assert!(matches!(result, Output::Historical { draft: Some(draft), .. } if draft.tags == ["branch-1"]));
            let previous = tips(&mut target, id).await;
            assert!(matches!(
                run(&mut restored, &mut target, &mut target_keys, restore(source.revision)).await,
                Ok(Output::Restored)
            ));
            let current = tips(&mut target, id).await;
            assert_eq!(current.len(), previous.len());
            assert!(previous.iter().filter(|head| **head != merged).all(|head| current.contains(head)));
            let new = current.iter().find(|head| !previous.contains(head)).unwrap();
            let mut payloads = Vec::new();
            for head in [new, source] {
                let wire = target.object(id, head.revision).await.unwrap();
                let opened = envelope::open(&wire, vault.keys(), vault.anchor(), Some(&head.revision), MAX_OPEN_MEMORY).unwrap();
                if head == new {
                    assert_eq!(opened.revision.header().parents, [merged.revision]);
                }
                payloads.push(opened.record.encode_content(MAX_OPEN_MEMORY).unwrap().bytes);
            }
            assert_eq!(payloads[0], payloads[1]);
            assert!(trash(&mut restored, &mut target, &mut target_keys).await.is_empty());
            let count = target.snapshot(id).await.unwrap().objects.len();
            assert!(matches!(
                run(&mut restored, &mut target, &mut target_keys, restore(source.revision)).await,
                Err(Error::Storage(confidex_storage::Error::Conflict))
            ));
            assert_eq!(target.snapshot(id).await.unwrap().objects.len(), count);
        });
}
