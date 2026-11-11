#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Output, Request};
use confidex_storage::{SqliteStore, Store};

#[derive(Default)]
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
async fn run(
    engine: &mut Engine,
    store: &mut SqliteStore,
    command: Command,
) -> Result<Output, app::Error> {
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
}
async fn search(
    engine: &mut Engine,
    store: &mut SqliteStore,
    query: &str,
    after: Option<confidex_storage::Head>,
    refresh: bool,
) -> (Vec<app::Summary>, bool, Option<confidex_storage::Head>) {
    let mut refresh = refresh;
    for _ in 0..64 {
        let output = run(
            engine,
            store,
            Command::Search {
                query: query.into(),
                tag: None,
                after: after.clone(),
                refresh,
            },
        )
        .await
        .unwrap();
        refresh = false;
        match output {
            Output::Indexing => (),
            Output::Rows { rows, more, next } => return (rows, more, next),
            _ => panic!("search output"),
        }
    }
    panic!("index did not finish");
}

#[test]
fn encrypted_search_covers_all_pages_changes_refresh_and_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("search.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&path).unwrap();
            let mut engine = Engine::default();
            let Output::Created(created) = run(
                &mut engine,
                &mut store,
                Command::Create {
                    name: "Search fixture".into(),
                    password: "public-fixture-password".into(),
                    remember: false,
                },
            )
            .await
            .unwrap() else {
                panic!("create");
            };
            let note_index = app::template("login").unwrap().len();
            for i in 1..=150u128 {
                let mut draft = app::new_record().unwrap();
                draft.record = i.to_be_bytes();
                draft.title = format!("Account {i}");
                draft.tags = vec!["work".into()];
                let mut login = app::template("login").unwrap();
                login[0]
                    .values
                    .insert("username".into(), "usernameonlytoken".into());
                login[1]
                    .values
                    .insert("password".into(), "passwordonlytoken".into());
                login[2].values.insert(
                    "url".into(),
                    format!("https://service.example.test/project{i:04}"),
                );
                draft.fields.extend(login);
                let mut note = app::field("note/v1").unwrap();
                note.values
                    .insert("text".into(), format!("publicnote unique{i:04}"));
                draft.fields.push(note);
                let mut protected = app::field("secure-note/v1").unwrap();
                protected
                    .values
                    .insert("text".into(), "protectedonlytoken".into());
                draft.fields.push(protected);
                run(&mut engine, &mut store, Command::Save { draft, epoch: 1 })
                    .await
                    .unwrap();
            }
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    Command::Search {
                        query: "unique0150".into(),
                        tag: None,
                        after: None,
                        refresh: false,
                    }
                )
                .await
                .unwrap(),
                Output::Indexing
            ));
            let damaged = store
                .head(created.info.id, 17u128.to_be_bytes())
                .await
                .unwrap()
                .unwrap();
            let original = store
                .object(created.info.id, damaged.revision)
                .await
                .unwrap();
            let mut corrupt = original.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute(
                    "UPDATE objects SET wire=?1 WHERE vault=?2 AND revision=?3",
                    rusqlite::params![
                        corrupt,
                        created.info.id.as_slice(),
                        damaged.revision.as_slice()
                    ],
                )
                .unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    Command::Search {
                        query: "unique0150".into(),
                        tag: None,
                        after: None,
                        refresh: false,
                    }
                )
                .await,
                Err(app::Error::Integrity)
            ));
            connection
                .execute(
                    "UPDATE objects SET wire=?1 WHERE vault=?2 AND revision=?3",
                    rusqlite::params![
                        original,
                        created.info.id.as_slice(),
                        damaged.revision.as_slice()
                    ],
                )
                .unwrap();
            drop(connection);
            let (rows, _, _) = search(&mut engine, &mut store, "unique0150", None, false).await;
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].head.record, 150u128.to_be_bytes());
            assert_eq!(
                search(&mut engine, &mut store, "project0150", None, false)
                    .await
                    .0
                    .len(),
                1
            );
            for query in [
                "protectedonlytoken",
                "passwordonlytoken",
                "usernameonlytoken",
                "---",
            ] {
                assert!(
                    search(&mut engine, &mut store, query, None, false)
                        .await
                        .0
                        .is_empty(),
                    "{query}"
                );
            }
            let (first, more, next) = search(&mut engine, &mut store, "account", None, false).await;
            assert_eq!(first.len(), 128);
            assert!(more);
            let (last, more, _) = search(&mut engine, &mut store, "account", next, false).await;
            assert_eq!(last.len(), 22);
            assert!(!more);
            let Output::Rows { rows, .. } = run(
                &mut engine,
                &mut store,
                Command::Search {
                    query: String::new(),
                    tag: Some("missing".into()),
                    after: None,
                    refresh: false,
                },
            )
            .await
            .unwrap() else {
                panic!("tags");
            };
            assert!(rows.is_empty());
            let target = 150u128.to_be_bytes();
            let Output::Draft(mut draft) =
                run(&mut engine, &mut store, Command::Open { record: target })
                    .await
                    .unwrap()
            else {
                panic!("open");
            };
            draft.fields[note_index].protected = true;
            run(&mut engine, &mut store, Command::Save { draft, epoch: 2 })
                .await
                .unwrap();
            assert!(
                search(&mut engine, &mut store, "unique0150", None, false)
                    .await
                    .0
                    .is_empty()
            );
            let Output::Draft(mut draft) =
                run(&mut engine, &mut store, Command::Open { record: target })
                    .await
                    .unwrap()
            else {
                panic!("open");
            };
            draft.fields[note_index].protected = false;
            draft.fields[note_index].type_name = "note/v1".into();
            draft.fields[note_index]
                .values
                .insert("text".into(), "replacementnote".into());
            run(&mut engine, &mut store, Command::Save { draft, epoch: 3 })
                .await
                .unwrap();
            assert_eq!(
                search(&mut engine, &mut store, "replacementnote", None, false)
                    .await
                    .0
                    .len(),
                1
            );
            let head = store.head(created.info.id, target).await.unwrap().unwrap();
            run(
                &mut engine,
                &mut store,
                Command::Delete {
                    record: target,
                    expected: head.revision,
                    epoch: 4,
                },
            )
            .await
            .unwrap();
            assert!(
                search(&mut engine, &mut store, "replacementnote", None, false)
                    .await
                    .0
                    .is_empty()
            );

            let mut other = Engine::default();
            run(
                &mut other,
                &mut store,
                Command::Unlock {
                    vault: created.info.id,
                    password: "public-fixture-password".into(),
                    key: created.key.clone(),
                    remember: false,
                },
            )
            .await
            .unwrap();
            let Output::Draft(mut draft) = run(
                &mut other,
                &mut store,
                Command::Open {
                    record: 1u128.to_be_bytes(),
                },
            )
            .await
            .unwrap() else {
                panic!("open");
            };
            draft.title = "externalchange".into();
            run(&mut other, &mut store, Command::Save { draft, epoch: 5 })
                .await
                .unwrap();
            assert_eq!(
                search(&mut engine, &mut store, "externalchange", None, true)
                    .await
                    .0
                    .len(),
                1
            );
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    Command::Search {
                        query: "x".repeat(4097),
                        tag: None,
                        after: None,
                        refresh: false,
                    }
                )
                .await,
                Err(app::Error::Input)
            ));

            run(&mut engine, &mut store, Command::Lock).await.unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    Command::Search {
                        query: "externalchange".into(),
                        tag: None,
                        after: None,
                        refresh: false,
                    }
                )
                .await,
                Err(app::Error::Locked)
            ));
            run(
                &mut engine,
                &mut store,
                Command::Unlock {
                    vault: created.info.id,
                    password: "public-fixture-password".into(),
                    key: created.key.clone(),
                    remember: false,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                search(&mut engine, &mut store, "externalchange", None, false)
                    .await
                    .0
                    .len(),
                1
            );
            run(
                &mut engine,
                &mut store,
                Command::Create {
                    name: "Second fixture".into(),
                    password: "public-fixture-password".into(),
                    remember: false,
                },
            )
            .await
            .unwrap();
            assert!(
                search(&mut engine, &mut store, "externalchange", None, false)
                    .await
                    .0
                    .is_empty()
            );
            drop(store);
            let persisted = std::fs::read(&path).unwrap();
            for marker in [
                "publicnote",
                "externalchange",
                "replacementnote",
                "protectedonlytoken",
            ] {
                assert!(
                    !persisted
                        .windows(marker.len())
                        .any(|window| window == marker.as_bytes())
                );
            }
        });
}
