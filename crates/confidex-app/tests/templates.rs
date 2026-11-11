#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{self as app, Command, DeviceKeys, Engine, Output, Request};
use confidex_storage::SqliteStore;

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
async fn run(engine: &mut Engine, store: &mut SqliteStore, command: Command) -> Output {
    engine
        .execute(
            store,
            &mut Keys,
            &mut Request {
                generation: 0,
                command,
            },
        )
        .await
        .result
        .unwrap()
}

#[test]
fn every_catalogue_and_utility_template_survives_encrypted_storage_and_a_process_restart() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("templates.sqlite");
            let mut store = SqliteStore::open(&path).unwrap();
            let mut engine = Engine::default();
            let Output::Created(created) = run(
                &mut engine,
                &mut store,
                Command::Create {
                    name: "Public catalogue fixture".into(),
                    password: "Public-catalogue-fixture".into(),
                    remember: false,
                },
            )
            .await
            else {
                panic!("create");
            };
            let mut expected = Vec::new();
            for id in app::templates::ids() {
                let mut draft = app::new_record().unwrap();
                draft.title = id.into();
                draft.fields = app::template(id).unwrap();
                draft.sections = Some(
                    app::templates::get(id)
                        .map(|t| t.sections())
                        .unwrap_or_default(),
                );
                draft.tags = vec!["public".into(), "template-test".into()];
                for (index, field) in draft.fields.iter_mut().enumerate() {
                    let value = match field.type_name.as_str() {
                        "date/v1" => "29/02/2024".into(),
                        "month-year/v1" => "02/2024".into(),
                        "url/v1" => format!("https://example.test/{index}"),
                        "password/v1" => format!("Public-{index}-fixture"),
                        "text/v1" | "note/v1" | "secure-note/v1" | "username/v1" | "secret/v1" => {
                            format!("Public {index} café")
                        }
                        _ => continue,
                    };
                    for target in field.values.values_mut() {
                        target.clone_from(&value);
                    }
                }
                let record = draft.record;
                let fields = draft.fields.clone();
                let Output::Saved(_) =
                    run(&mut engine, &mut store, Command::Save { draft, epoch: 1 }).await
                else {
                    panic!("save {id}");
                };
                let Output::Draft(saved) =
                    run(&mut engine, &mut store, Command::Open { record }).await
                else {
                    panic!("open {id}");
                };
                assert_eq!(saved.fields.len(), fields.len(), "{id}");
                for (before, after) in fields.iter().zip(&saved.fields) {
                    assert_eq!(after.values, before.values, "{id}: {}", before.name);
                    assert_eq!(after.protected, before.protected, "{id}: {}", before.name);
                }
                expected.push(saved);
            }
            assert_eq!(expected.len(), 25);
            run(&mut engine, &mut store, Command::Lock).await;
            drop(engine);
            drop(store);
            let mut store = SqliteStore::open(&path).unwrap();
            let mut engine = Engine::default();
            run(
                &mut engine,
                &mut store,
                Command::Unlock {
                    vault: created.info.id,
                    password: "Public-catalogue-fixture".into(),
                    key: created.key.clone(),
                    remember: false,
                },
            )
            .await;
            for before in expected {
                let Output::Draft(after) = run(
                    &mut engine,
                    &mut store,
                    Command::Open {
                        record: before.record,
                    },
                )
                .await
                else {
                    panic!("open");
                };
                assert_eq!(after.title, before.title);
                assert_eq!(after.tags, before.tags);
                assert_eq!(after.fields.len(), before.fields.len(), "{}", before.title);
                for (a, b) in after.fields.iter().zip(&before.fields) {
                    assert_eq!(a.name, b.name);
                    assert_eq!(a.type_name, b.type_name);
                    assert_eq!(a.values, b.values);
                    assert_eq!(a.data.as_deref(), b.data.as_deref());
                    assert_eq!(a.protected, b.protected);
                }
                assert_eq!(after.sections, before.sections);
            }
        });
}
