#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Error, Output, Request};
use confidex_storage::{SqliteStore, Store};
use std::collections::{BTreeMap, BTreeSet};
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
    async fn save(&mut self, id: [u8; 16], text: &str) -> bool {
        self.0.insert(id, text.into());
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
#[test]
fn history_pages_are_causal_pinned_authenticated_and_separate_from_current_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&path).unwrap();
            let mut keys = Keys::default();
            let mut engine = Engine::default();
            let Output::Created(created) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Create {
                    name: "Public history fixture".into(),
                    password: "Public password".into(),
                    remember: true,
                },
            )
            .await
            .unwrap() else {
                panic!("create")
            };
            let vault = created.info.id;
            let mut draft = app::new_record().unwrap();
            let record = draft.record;
            draft.title = "Original".into();
            draft.fields.push(app::field("password/v1").unwrap());
            let mut revisions = Vec::new();
            for i in 0..18 {
                draft.fields[0]
                    .values
                    .insert("password".into(), format!("Private value sentinel {i}"));
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Save {
                        draft: draft.clone(),
                        epoch: 10_000 - i,
                    },
                )
                .await
                .unwrap();
                let Output::Draft(opened) =
                    run(&mut engine, &mut store, &mut keys, Command::Open { record })
                        .await
                        .unwrap()
                else {
                    panic!("open")
                };
                draft = opened;
                revisions.push(draft.revision.unwrap());
            }
            let root = revisions[0];
            let pinned = *revisions.last().unwrap();
            let Output::History(first) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::History {
                    record,
                    cursor: None,
                },
            )
            .await
            .unwrap() else {
                panic!("history")
            };
            assert_eq!(first.head, pinned);
            assert_eq!(first.revisions[0].revision, pinned);
            assert_eq!(first.revisions.len(), 16);
            assert!(first.revisions.iter().all(|r| r.changes.changed.len() == 1));
            assert!(
                !serde_json::to_string(&first)
                    .unwrap()
                    .contains("Private value sentinel")
            );
            draft.title = "New head after page one".into();
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Save {
                    draft: draft.clone(),
                    epoch: 20_000,
                },
            )
            .await
            .unwrap();
            let new_head = store.head(vault, record).await.unwrap().unwrap().revision;
            let Output::History(second) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::History {
                    record,
                    cursor: first.next,
                },
            )
            .await
            .unwrap() else {
                panic!("page")
            };
            assert_eq!(second.head, pinned);
            assert!(second.next.is_none() && second.revisions.last().unwrap().created);
            let all = first
                .revisions
                .iter()
                .chain(&second.revisions)
                .map(|r| r.revision)
                .collect::<Vec<_>>();
            assert_eq!(all.len(), 18);
            assert_eq!(all.iter().copied().collect::<BTreeSet<_>>().len(), 18);
            assert_eq!(all.last(), Some(&root));
            let Output::Historical {
                draft: Some(past), ..
            } = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Historical {
                    record,
                    revision: root,
                },
            )
            .await
            .unwrap()
            else {
                panic!("historical")
            };
            assert_eq!(
                past.fields[0].values["password"],
                "Private value sentinel 0"
            );
            assert_eq!(
                store.head(vault, record).await.unwrap().unwrap().revision,
                new_head
            );
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Historical {
                        record,
                        revision: [99; 32]
                    }
                )
                .await,
                Err(Error::Input)
            ));
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::History {
                        record,
                        cursor: Some(app::history::Cursor {
                            head: pinned,
                            offset: usize::MAX
                        })
                    }
                )
                .await,
                Err(Error::Input)
            ));
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::SaveRevision {
                    draft: past.clone(),
                    parent: new_head,
                    epoch: 21_000,
                },
            )
            .await
            .unwrap();
            let Output::History(merged) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::History {
                    record,
                    cursor: None,
                },
            )
            .await
            .unwrap() else {
                panic!("merged")
            };
            assert!(merged.revisions[0].merged);
            let head = merged.head;
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Delete {
                    record,
                    expected: head,
                    epoch: 22_000,
                },
            )
            .await
            .unwrap();
            let Output::History(deleted) = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::History {
                    record,
                    cursor: None,
                },
            )
            .await
            .unwrap() else {
                panic!("deleted")
            };
            assert!(deleted.revisions[0].deleted);
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Historical {
                        record,
                        revision: deleted.head
                    }
                )
                .await
                .unwrap(),
                Output::Historical { draft: None, .. }
            ));
            let mut other = app::new_record().unwrap();
            other.title = "Other record".into();
            let other_id = other.record;
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Save {
                    draft: other,
                    epoch: 23_000,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Historical {
                        record: other_id,
                        revision: root
                    }
                )
                .await,
                Err(Error::Input)
            ));
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::History {
                    record,
                    cursor: None,
                },
            )
            .await
            .unwrap();
            let mut wire = store.object(vault, root).await.unwrap();
            *wire.last_mut().unwrap() ^= 1;
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute(
                    "UPDATE objects SET wire=?1 WHERE vault=?2 AND revision=?3",
                    rusqlite::params![wire, vault.as_slice(), root.as_slice()],
                )
                .unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Historical {
                        record,
                        revision: root
                    }
                )
                .await,
                Err(Error::Integrity)
            ));
            run(&mut engine, &mut store, &mut keys, Command::Lock)
                .await
                .unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::History {
                        record,
                        cursor: None
                    }
                )
                .await,
                Err(Error::Locked)
            ));
        });
}
