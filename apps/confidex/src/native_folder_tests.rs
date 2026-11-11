use super::*;
use confidex_app::DeviceKeys;
use confidex_app::local_sync::{self, Command as Folder, Reply};
use confidex_storage::{SqliteStore, VaultId};
struct Keys;
impl DeviceKeys for Keys {
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
fn receive(runtime: &mut NativeRuntime) -> Output {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(response) = runtime.receive() {
            assert_eq!(response.generation, 19);
            return response.result.unwrap();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "native folder response"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}
fn send(runtime: &mut NativeRuntime, command: Command) -> Output {
    runtime
        .send(Request {
            generation: 19,
            command,
        })
        .unwrap();
    receive(runtime)
}
#[test]
fn native_executor_opens_exchanges_and_cancels_queued_folder_jobs() {
    let directory = tempfile::tempdir().unwrap();
    let shared = tempfile::tempdir().unwrap();
    let path = directory.path().join("a.sqlite");
    let created = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut engine = Engine::default();
            let mut store = SqliteStore::open(&path).unwrap();
            let mut run = Request {
                generation: 19,
                command: Command::Create {
                    name: "Public folder runtime".into(),
                    password: "public-password".into(),
                    remember: false,
                },
            };
            let Output::Created(created) = engine
                .execute(&mut store, &mut Keys, &mut run)
                .await
                .result
                .unwrap()
            else {
                panic!("create")
            };
            let mut draft = confidex_app::new_record().unwrap();
            draft.title = "Public shared record".into();
            engine
                .execute(
                    &mut store,
                    &mut Keys,
                    &mut Request {
                        generation: 19,
                        command: Command::Save { draft, epoch: 1 },
                    },
                )
                .await
                .result
                .unwrap();
            created
        });
    let mut a = NativeRuntime::new(path, egui::Context::default()).unwrap();
    assert!(a.folder_available());
    assert!(matches!(
        send(
            &mut a,
            Command::Unlock {
                vault: created.info.id,
                password: "public-password".into(),
                key: created.key.clone(),
                remember: false
            }
        ),
        Output::Opened { .. }
    ));
    assert!(matches!(
        send(
            &mut a,
            Command::Folder(Folder::Configure {
                path: Some(shared.path().to_str().unwrap().into())
            })
        ),
        Output::Folder(Ok(Reply::State { path: Some(_), .. }))
    ));
    assert!(
        matches!(send(&mut a, Command::Folder(Folder::Sync)), Output::Folder(Ok(Reply::Synced { report, .. })) if report.uploaded == 1)
    );
    let stale = a.folder_epoch.load(Ordering::Relaxed);
    a.cancel_folder();
    a.sender
        .as_ref()
        .unwrap()
        .try_send((
            Request {
                generation: 19,
                command: Command::Folder(Folder::Sync),
            },
            stale,
        ))
        .unwrap();
    assert!(matches!(
        receive(&mut a),
        Output::Folder(Err(local_sync::Error::Canceled))
    ));
    assert!(matches!(
        send(&mut a, Command::Folder(Folder::Sync)),
        Output::Folder(Ok(Reply::Synced { .. }))
    ));
    assert!(matches!(send(&mut a, Command::Lock), Output::Locked));
    assert!(matches!(
        send(&mut a, Command::Folder(Folder::Status)),
        Output::Folder(Err(local_sync::Error::App(Error::Locked)))
    ));
    let mut b =
        NativeRuntime::new(directory.path().join("b.sqlite"), egui::Context::default()).unwrap();
    let output = send(
        &mut b,
        Command::Folder(Folder::Import {
            name: "Public second device".into(),
            password: "public-password".into(),
            key: created.key.clone(),
            path: shared.path().to_str().unwrap().into(),
            remember: false,
        }),
    );
    assert!(
        matches!(output, Output::Folder(Ok(Reply::Opened { info, remembered:false, server:None })) if info.id == created.info.id)
    );
    assert!(
        matches!(send(&mut b, Command::Folder(Folder::Sync)), Output::Folder(Ok(Reply::Synced { report, .. })) if report.downloaded == 1)
    );
    assert!(
        matches!(send(&mut b, Command::List { after:None,tag:None }), Output::Rows { rows, more:false, .. } if rows.len() == 1 && rows[0].title == "Public shared record")
    );
}
