use super::{PERSONAL, parse};
use confidex_app::{
    Command, DeviceKeys, Engine, Output, Request,
    import::{Plan, Status},
    import_apply::{Action, Choice, Error, Match, Selection},
};
use confidex_storage::{SqliteStore, Store};
use confidex_vault::{envelope, kdf, lock, resources::MAX_OPEN_MEMORY, transfer_code};
const PASSWORD: &str = "public-zip-import-test-password";
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
fn selection(plan: &Plan) -> Selection {
    Selection {
        container_reviewed: true,
        choices: plan
            .items
            .iter()
            .map(|item| Choice {
                action: if matches!(item.status, Status::Ready | Status::Review) {
                    Action::Create
                } else {
                    Action::Skip
                },
                reviewed: true,
            })
            .collect(),
    }
}
async fn search(engine: &mut Engine, store: &mut SqliteStore, text: &str) -> usize {
    loop {
        match command(
            engine,
            store,
            Command::Search {
                query: text.into(),
                after: None,
                tag: None,
                refresh: false,
            },
        )
        .await
        {
            Output::Rows { rows, .. } => return rows.len(),
            Output::Indexing => (),
            _ => panic!("Unexpected search output"),
        }
    }
}

#[test]
fn zip_preview_apply_reopen_and_repeat_keep_binary_records_and_protection() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.sqlite");
            let mut store = SqliteStore::open(&path).unwrap();
            let mut engine = Engine::default();
            let Output::Created(created) = command(
                &mut engine,
                &mut store,
                Command::Create {
                    name: "Public ZIP fixture".into(),
                    password: PASSWORD.into(),
                    remember: false,
                },
            )
            .await
            else {
                panic!("Unexpected create output")
            };
            let id = created.info.id;
            let expected = parse(PERSONAL);
            let choices = selection(&expected);
            let review = engine
                .review_import(&mut store, id, parse(PERSONAL), &mut |_| true)
                .await
                .unwrap();
            assert!(store.heads(id, None).await.unwrap().is_empty());
            for (actual, expected) in engine
                .import_plan(review.token)
                .unwrap()
                .items
                .iter()
                .zip(&expected.items)
            {
                assert_eq!(actual.record_bytes(), expected.record_bytes());
            }
            let mut unreviewed = selection(&expected);
            unreviewed.container_reviewed = false;
            assert_eq!(
                engine
                    .apply_import(&mut store, review.token, &unreviewed, 42, &mut |_| true)
                    .await,
                Err(Error::InvalidChoice)
            );
            assert!(store.heads(id, None).await.unwrap().is_empty());
            engine.begin_import().unwrap();
            let review = engine
                .review_import(&mut store, id, parse(PERSONAL), &mut |_| true)
                .await
                .unwrap();
            let report = engine
                .apply_import(&mut store, review.token, &choices, 43, &mut |_| true)
                .await
                .unwrap();
            assert_eq!(report.added, 3);
            let stored = store.vault(id).await.unwrap();
            let code = transfer_code::decode(&created.key).unwrap();
            let vault = lock::open(
                &stored.lock,
                PASSWORD.as_bytes(),
                &code.secret,
                kdf::REQUIRED_MEMORY,
            )
            .unwrap();
            let mut actual = Vec::new();
            for head in store.heads(id, None).await.unwrap() {
                let wire = store.object(id, head.revision).await.unwrap();
                for plaintext in [
                    b"PUBLIC-FIXTURE-PASSWORD".as_slice(),
                    b"scanpart.txt".as_slice(),
                ] {
                    assert!(!wire.windows(plaintext.len()).any(|w| w == plaintext));
                }
                let mut record = envelope::open(
                    &wire,
                    vault.keys(),
                    vault.anchor(),
                    Some(&head.revision),
                    MAX_OPEN_MEMORY,
                )
                .unwrap()
                .record;
                assert!(record.extra.remove("confidex.import.origin").is_some());
                actual.push(
                    record
                        .encode_content(MAX_OPEN_MEMORY)
                        .unwrap()
                        .bytes
                        .to_vec(),
                );
            }
            let mut expected: Vec<_> = expected
                .items
                .iter()
                .map(|item| item.record_bytes().to_vec())
                .collect();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected);
            drop(store);
            drop(engine);
            let mut store = SqliteStore::open(&path).unwrap();
            let mut engine = Engine::default();
            command(
                &mut engine,
                &mut store,
                Command::Unlock {
                    vault: id,
                    password: PASSWORD.into(),
                    key: created.key.clone(),
                    remember: false,
                },
            )
            .await;
            assert_eq!(search(&mut engine, &mut store, "Second").await, 1);
            assert_eq!(
                search(&mut engine, &mut store, "PUBLIC-FIXTURE-PASSWORD").await,
                0
            );
            engine.begin_import().unwrap();
            let review = engine
                .review_import(&mut store, id, parse(PERSONAL), &mut |_| true)
                .await
                .unwrap();
            assert!(
                review
                    .items
                    .iter()
                    .all(|item| item.matching == Match::Duplicate)
            );
            let choices = Selection {
                container_reviewed: true,
                choices: review
                    .items
                    .iter()
                    .map(|_| Choice {
                        action: Action::Skip,
                        reviewed: true,
                    })
                    .collect(),
            };
            let report = engine
                .apply_import(&mut store, review.token, &choices, 44, &mut |_| true)
                .await
                .unwrap();
            assert_eq!(report.skipped, 3);
            assert_eq!(store.snapshot(id).await.unwrap().objects.len(), 3);
            for input in [
                include_bytes!("../import_fixtures/bitwarden_zip/duplicate.zip").as_slice(),
                include_bytes!("../import_fixtures/bitwarden_zip/restricted.zip").as_slice(),
            ] {
                engine.begin_import().unwrap();
                let review = engine
                    .review_import(&mut store, id, parse(input), &mut |_| true)
                    .await
                    .unwrap();
                assert_eq!(review.container_status, Status::Blocked);
                let choices = Selection {
                    container_reviewed: true,
                    choices: review
                        .items
                        .iter()
                        .map(|_| Choice {
                            action: Action::Skip,
                            reviewed: true,
                        })
                        .collect(),
                };
                assert_eq!(
                    engine
                        .apply_import(&mut store, review.token, &choices, 45, &mut |_| true)
                        .await,
                    Err(Error::InvalidChoice)
                );
                assert_eq!(store.snapshot(id).await.unwrap().objects.len(), 3);
            }
        });
}
