use confidex_app::{Command, DeviceKeys, Engine, Output, Request};
use confidex_native::open_store;
use confidex_storage::VaultId;

struct NoKeys;
impl DeviceKeys for NoKeys {
    async fn remove(&mut self, _: VaultId) -> bool {
        true
    }
    async fn load(&mut self, _: VaultId) -> Option<String> {
        None
    }
    async fn save(&mut self, _: VaultId, _: &str) -> bool {
        false
    }
}

#[test]
fn headless_clients_share_the_gui_store_and_reopen_encrypted_records() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/vaults.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut writer = Engine::default();
            let mut store = open_store(&path).unwrap();
            let Output::Created(created) = writer
                .execute(
                    &mut store,
                    &mut NoKeys,
                    &mut Request {
                        generation: 1,
                        command: Command::Create {
                            name: "Headless fixture".into(),
                            password: "public-test-password".into(),
                            remember: false,
                        },
                    },
                )
                .await
                .result
                .unwrap()
            else {
                panic!("expected created vault");
            };
            let mut draft = confidex_app::new_record().unwrap();
            draft.title = "Shared record".into();
            let record = draft.record;
            let mut field = confidex_app::field("password/v1").unwrap();
            field
                .values
                .insert("password".into(), "PUBLIC-FIXTURE".into());
            draft.fields.push(field);
            writer
                .execute(
                    &mut store,
                    &mut NoKeys,
                    &mut Request {
                        generation: 2,
                        command: Command::Save { draft, epoch: 1 },
                    },
                )
                .await
                .result
                .unwrap();
            drop(writer);
            drop(store);

            let mut reader = Engine::default();
            let mut store = open_store(&path).unwrap();
            assert!(matches!(
                reader
                    .execute(
                        &mut store,
                        &mut NoKeys,
                        &mut Request {
                            generation: 3,
                            command: Command::Unlock {
                                vault: created.info.id,
                                password: "public-test-password".into(),
                                key: created.key.clone(),
                                remember: false,
                            },
                        },
                    )
                    .await
                    .result,
                Ok(Output::Opened { .. })
            ));
            let Output::Draft(draft) = reader
                .execute(
                    &mut store,
                    &mut NoKeys,
                    &mut Request {
                        generation: 4,
                        command: Command::Open { record },
                    },
                )
                .await
                .result
                .unwrap()
            else {
                panic!("expected stored record");
            };
            assert_eq!(draft.title, "Shared record");
            assert_eq!(draft.fields[0].values["password"], "PUBLIC-FIXTURE");
        });
}

#[test]
fn database_parent_errors_are_returned_without_replacing_files() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("file");
    std::fs::write(&parent, b"keep").unwrap();
    assert!(matches!(
        open_store(&parent.join("vaults.sqlite")),
        Err(confidex_storage::Error::Storage)
    ));
    assert_eq!(std::fs::read(parent).unwrap(), b"keep");
}
