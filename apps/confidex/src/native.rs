#[cfg(all(test, feature = "export-check"))]
use confidex_app::DeviceKeys;
use confidex_app::{Command, Engine, Error, Output, Request, Response, import_flow as flow};
#[cfg(any(not(target_os = "macos"), all(test, feature = "export-check")))]
use confidex_native::Credentials;
#[cfg(target_os = "macos")]
use confidex_native::TouchIdKeys;
#[cfg(all(test, feature = "export-check"))]
use confidex_storage::{SqliteStore, VaultId};
use confidex_ui::Runtime;
use eframe::egui;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use std::{path::PathBuf, sync::mpsc};

struct ImportControl<'a> {
    operation: u32,
    canceled: &'a AtomicU32,
    generation: u32,
    replies: &'a mpsc::Sender<Response>,
    ctx: &'a egui::Context,
    last: std::time::Instant,
    phase: Option<flow::Phase>,
}
impl ImportControl<'_> {
    fn progress(&mut self, progress: flow::Progress) -> bool {
        if self.operation != 0 && self.canceled.load(Ordering::Relaxed) == self.operation {
            return false;
        }
        if self.phase != Some(progress.phase) || self.last.elapsed().as_millis() >= 40 {
            self.last = std::time::Instant::now();
            self.phase = Some(progress.phase);
            if self
                .replies
                .send(Response {
                    generation: self.generation,
                    result: Ok(Output::VendorImport(Ok(flow::Reply::Progress {
                        operation: self.operation,
                        progress,
                    }))),
                })
                .is_err()
            {
                return false;
            }
            self.ctx.request_repaint();
        }
        true
    }
}
impl confidex_app::import_apply::Control for ImportControl<'_> {
    async fn checkpoint(&mut self, value: confidex_app::import_apply::Progress) -> bool {
        self.progress(value.into())
    }
}
impl flow::Control for ImportControl<'_> {
    fn parsing(&mut self, value: confidex_app::import::Progress) -> bool {
        self.progress(value.into())
    }
}

struct ExportControl<'a> {
    operation: u32,
    canceled: &'a AtomicU32,
    generation: u32,
    replies: &'a mpsc::Sender<Response>,
    ctx: &'a egui::Context,
    last: std::time::Instant,
    phase: Option<confidex_app::export::Phase>,
}
impl ExportControl<'_> {
    fn progress(&mut self, progress: confidex_app::export::Progress) -> bool {
        if self.operation != 0 && self.canceled.load(Ordering::Relaxed) == self.operation {
            return false;
        }
        if self.phase != Some(progress.phase) || self.last.elapsed().as_millis() >= 40 {
            self.last = std::time::Instant::now();
            self.phase = Some(progress.phase);
            if self
                .replies
                .send(Response {
                    generation: self.generation,
                    result: Ok(Output::VendorExport(Ok(
                        confidex_app::export_flow::Reply::Progress {
                            operation: self.operation,
                            progress,
                        },
                    ))),
                })
                .is_err()
            {
                return false;
            }
            self.ctx.request_repaint();
        }
        true
    }
}
impl confidex_app::export_flow::Control for ExportControl<'_> {
    async fn checkpoint(&mut self, progress: confidex_app::export::Progress) -> bool {
        self.progress(progress)
    }
    fn computing(&mut self, progress: confidex_app::export::Progress) -> bool {
        self.progress(progress)
    }
}
pub struct NativeRuntime {
    #[cfg(target_os = "macos")]
    device_unlock_minutes: Arc<AtomicU32>,
    #[cfg(target_os = "macos")]
    touch_id: bool,
    canceled: Arc<AtomicU32>,
    export_canceled: Arc<AtomicU32>,
    folder_epoch: Arc<AtomicU32>,
    sender: Option<tokio::sync::mpsc::Sender<(Request, u32)>>,
    replies: mpsc::Receiver<Response>,
    _runtime: tokio::runtime::Runtime,
}
impl NativeRuntime {
    pub fn new(path: PathBuf, ctx: egui::Context) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()?;
        let (sender, mut requests) = tokio::sync::mpsc::channel::<(Request, u32)>(4);
        let (replies, receiver) = mpsc::channel();
        let canceled = Arc::new(AtomicU32::new(0));
        let cancel_flag = canceled.clone();
        let export_canceled = Arc::new(AtomicU32::new(0));
        let export_cancel_flag = export_canceled.clone();
        let folder_epoch = Arc::new(AtomicU32::new(0));
        let folder_control = folder_epoch.clone();
        let mut executor = tokio::runtime::Builder::new_current_thread();
        #[cfg(feature = "sync")]
        executor.enable_all();
        let executor = executor.build()?;
        #[cfg(feature = "sync")]
        let mut transport = {
            let _guard = executor.enter();
            crate::sync_transport::Net::new()?
        };
        #[cfg(not(feature = "sync"))]
        let mut transport = confidex_app::sync::Offline;
        #[cfg(target_os = "macos")]
        let touch_id = TouchIdKeys::available();
        #[cfg(target_os = "macos")]
        let device_unlock_minutes = Arc::new(AtomicU32::new(u32::from(
            confidex_app::device_unlock::DEFAULT_MINUTES,
        )));
        #[cfg(target_os = "macos")]
        let minutes = device_unlock_minutes.clone();
        runtime.spawn_blocking(move || {
            let mut engine = Engine::default();
            let mut store = None;
            while let Some((mut request, folder_generation)) = requests.blocking_recv() {
                #[cfg(target_os = "macos")]
                let mut keys = TouchIdKeys::new(minutes.load(Ordering::Relaxed) as u16, touch_id);
                #[cfg(not(target_os = "macos"))]
                let mut keys = Credentials;
                if store.is_none() {
                    store = confidex_native::open_store(&path).ok();
                }
                let response =
                    if let Some(store) = &mut store {
                        if let Command::Folder(command) = &mut request.command {
                            Response {
                                generation: request.generation,
                                result: Ok(Output::Folder(executor.block_on(
                                    engine.execute_folder(store, &mut keys, command, &mut || {
                                        folder_control.load(Ordering::Relaxed) == folder_generation
                                    }),
                                ))),
                            }
                        } else if let Command::VendorImport(command) = &mut request.command {
                            let mut control = ImportControl {
                                operation: command.operation().unwrap_or(0),
                                canceled: &cancel_flag,
                                generation: request.generation,
                                replies: &replies,
                                ctx: &ctx,
                                last: std::time::Instant::now(),
                                phase: None,
                            };
                            Response {
                                generation: request.generation,
                                result: Ok(Output::VendorImport(executor.block_on(
                                    engine.execute_import(store, command, &mut control),
                                ))),
                            }
                        } else if let Command::VendorExport(command) = &mut request.command {
                            let mut control = ExportControl {
                                operation: command.operation().unwrap_or(0),
                                canceled: &export_cancel_flag,
                                generation: request.generation,
                                replies: &replies,
                                ctx: &ctx,
                                last: std::time::Instant::now(),
                                phase: None,
                            };
                            Response {
                                generation: request.generation,
                                result: Ok(Output::VendorExport(executor.block_on(
                                    engine.execute_export(store, command, &mut control),
                                ))),
                            }
                        } else {
                            executor.block_on(engine.execute_with_transport(
                                store,
                                &mut keys,
                                &mut transport,
                                &mut request,
                            ))
                        }
                    } else {
                        Response {
                            generation: request.generation,
                            result: Err(Error::Storage(confidex_storage::Error::Storage)),
                        }
                    };
                if replies.send(response).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        Ok(Self {
            #[cfg(target_os = "macos")]
            device_unlock_minutes,
            #[cfg(target_os = "macos")]
            touch_id,
            canceled,
            export_canceled,
            folder_epoch,
            sender: Some(sender),
            replies: receiver,
            _runtime: runtime,
        })
    }
}
impl Runtime for NativeRuntime {
    #[cfg(target_os = "macos")]
    fn device_unlock_label(&self) -> Option<&'static str> {
        self.touch_id.then_some("vault-touch-id-unlock")
    }

    #[cfg(target_os = "macos")]
    fn set_device_unlock_minutes(&mut self, minutes: u16) {
        self.device_unlock_minutes
            .store(u32::from(minutes), Ordering::Relaxed);
    }

    fn pick_folder(&mut self, done: confidex_ui::FolderFileCompletion) {
        std::thread::spawn(move || {
            use confidex_ui::FolderFileReply;
            done(match rfd::FileDialog::new().pick_folder() {
                Some(path) => match path.to_str() {
                    Some(path) => FolderFileReply::Selected(path.to_owned()),
                    None => FolderFileReply::Failed,
                },
                None => FolderFileReply::Canceled,
            });
        });
    }
    fn folder_available(&self) -> bool {
        true
    }
    fn cancel_folder(&mut self) {
        self.folder_epoch.fetch_add(1, Ordering::Relaxed);
    }
    fn save_export(
        &mut self,
        transfer: confidex_app::export_flow::Transfer,
        done: confidex_ui::ExportFileCompletion,
    ) {
        crate::export_files::save(transfer, done);
    }
    fn cancel_export(&mut self, operation: u32) {
        if operation != 0 {
            self.export_canceled.store(operation, Ordering::Relaxed);
        }
    }
    fn cancel_import(&mut self, operation: u32) {
        if operation != 0 {
            self.canceled.store(operation, Ordering::Relaxed);
        }
    }
    fn default_sync_server(&self) -> Option<String> {
        cfg!(feature = "sync").then(|| crate::sync_defaults::DEFAULT_SYNC_SERVER.to_owned())
    }
    fn send(&mut self, request: Request) -> Result<(), Error> {
        if matches!(
            &request.command,
            Command::Catalog
                | Command::Select { .. }
                | Command::Create { .. }
                | Command::Unlock { .. }
                | Command::EnrollDeviceUnlock { .. }
                | Command::Import { .. }
                | Command::Lock
                | Command::RestoreBackup { .. }
                | Command::RemoveVault { .. }
                | Command::Folder(confidex_app::local_sync::Command::Import { .. })
        ) {
            self.cancel_folder();
        }
        let folder_generation = self.folder_epoch.load(Ordering::Relaxed);
        self.sender
            .as_ref()
            .ok_or(Error::Locked)?
            .try_send((request, folder_generation))
            .map_err(|_| Error::Storage(confidex_storage::Error::Storage))
    }
    fn receive(&mut self) -> Option<Response> {
        self.replies.try_recv().ok()
    }
}
impl Drop for NativeRuntime {
    fn drop(&mut self) {
        self.cancel_folder();
        self.sender.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "export-check")]
    #[test]
    fn real_runtime_dispatches_exports_and_keeps_cancel_channels_independent() {
        use confidex_app::{export, export_flow as flow};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public-native-export.sqlite");
        struct PublicKeys;
        impl DeviceKeys for PublicKeys {
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
        let created = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let mut engine = Engine::default();
                let mut store = SqliteStore::open(&path).unwrap();
                let response = engine
                    .execute(
                        &mut store,
                        &mut PublicKeys,
                        &mut Request {
                            generation: 1,
                            command: Command::Create {
                                name: "Public runtime export".into(),
                                password: "public-native-password".into(),
                                remember: false,
                            },
                        },
                    )
                    .await;
                let Output::Created(created) = response.result.unwrap() else {
                    panic!("created");
                };
                let mut draft = confidex_app::new_record().unwrap();
                draft.title = "Public record".into();
                let mut password = confidex_app::field("password/v1").unwrap();
                password
                    .values
                    .insert("password".into(), "PUBLIC-NATIVE-EXPORT".into());
                draft.fields.push(password);
                engine
                    .execute(
                        &mut store,
                        &mut PublicKeys,
                        &mut Request {
                            generation: 1,
                            command: Command::Save { draft, epoch: 1 },
                        },
                    )
                    .await
                    .result
                    .unwrap();
                created
            });
        fn send(runtime: &mut NativeRuntime, command: Command) -> Output {
            runtime
                .send(Request {
                    generation: 91,
                    command,
                })
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(response) = runtime.receive() {
                    assert_eq!(response.generation, 91);
                    if matches!(
                        response.result,
                        Ok(Output::VendorExport(Ok(flow::Reply::Progress { .. })))
                    ) {
                        continue;
                    }
                    return response.result.unwrap();
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "runtime response timeout"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        let mut runtime = NativeRuntime::new(path, egui::Context::default()).unwrap();
        assert!(matches!(
            send(
                &mut runtime,
                Command::Unlock {
                    vault: created.info.id,
                    password: "public-native-password".into(),
                    key: created.key.clone(),
                    remember: false
                }
            ),
            Output::Opened { .. }
        ));
        let Output::VendorExport(Ok(flow::Reply::Begun { formats, .. })) =
            send(&mut runtime, Command::VendorExport(flow::Command::Begin))
        else {
            panic!("begin");
        };
        assert_eq!(formats.len(), 3);
        let Output::VendorExport(Ok(flow::Reply::Listed { page, .. })) = send(
            &mut runtime,
            Command::VendorExport(flow::Command::List {
                operation: 16,
                after: None,
            }),
        ) else {
            panic!("list");
        };
        let head = page.rows[0].head.clone();
        let Output::VendorExport(Ok(flow::Reply::Fields {
            operation: 160,
            fields,
            ..
        })) = send(
            &mut runtime,
            Command::VendorExport(flow::Command::Fields {
                operation: 160,
                head,
                start: 0,
            }),
        )
        else {
            panic!("field sources");
        };
        assert_eq!(fields.items.len(), 1);
        assert_eq!(
            (
                fields.items[0].index,
                fields.items[0].type_name.as_str(),
                fields.items[0].key.as_str()
            ),
            (0, "password/v1", "password")
        );
        assert!(
            !serde_json::to_string(&fields)
                .unwrap()
                .contains("PUBLIC-NATIVE-EXPORT")
        );
        let prepare = |operation| {
            Command::VendorExport(flow::Command::Prepare {
                operation,
                created_at: 1_735_689_600,
                format: export::Format::KeepassXml,
                options: export::Options::Plain,
                selection: flow::Selection::All,
            })
        };
        let Output::VendorExport(Ok(flow::Reply::Reviewed { review, .. })) =
            send(&mut runtime, prepare(17))
        else {
            panic!("review");
        };
        runtime.cancel_export(18);
        assert!(matches!(
            send(
                &mut runtime,
                Command::VendorExport(flow::Command::Generate {
                    operation: 18,
                    token: review.token,
                    consent: export::Consent::Lossless
                })
            ),
            Output::VendorExport(Err(flow::Error::Export(export::Error::Canceled)))
        ));
        let Output::VendorExport(Ok(flow::Reply::Reviewed { review, .. })) =
            send(&mut runtime, prepare(19))
        else {
            panic!("retry");
        };
        runtime.cancel_import(20);
        let Output::VendorExport(Ok(flow::Reply::Ready { ready, .. })) = send(
            &mut runtime,
            Command::VendorExport(flow::Command::Generate {
                operation: 20,
                token: review.token,
                consent: export::Consent::Lossless,
            }),
        ) else {
            panic!("ready");
        };
        let Output::VendorExport(Ok(flow::Reply::Chunk { chunk, .. })) = send(
            &mut runtime,
            Command::VendorExport(flow::Command::Chunk {
                token: ready.token,
                offset: 0,
            }),
        ) else {
            panic!("chunk");
        };
        assert!(chunk.next.is_none());
        let marker = b"PUBLIC-NATIVE-EXPORT";
        assert!(
            chunk
                .bytes
                .windows(marker.len())
                .any(|bytes| bytes == marker)
        );
        assert!(matches!(send(&mut runtime, Command::Lock), Output::Locked));
        assert!(matches!(
            send(
                &mut runtime,
                Command::VendorExport(flow::Command::Chunk {
                    token: ready.token,
                    offset: 0
                })
            ),
            Output::VendorExport(Err(flow::Error::InvalidSession))
        ));
    }
    #[test]
    fn progress_is_throttled_but_cancellation_is_not() {
        let canceled = AtomicU32::new(0);
        let (replies, receiver) = mpsc::channel();
        let ctx = egui::Context::default();
        let mut control = ImportControl {
            operation: 7,
            canceled: &canceled,
            generation: 1,
            replies: &replies,
            ctx: &ctx,
            last: std::time::Instant::now(),
            phase: None,
        };
        let progress = flow::Progress {
            phase: flow::Phase::Parse,
            current: 0,
            total: 0,
        };
        assert!(control.progress(progress));
        control.last = std::time::Instant::now() + std::time::Duration::from_secs(60);
        for current in 1..1000 {
            assert!(control.progress(flow::Progress {
                current,
                ..progress
            }));
        }
        assert_eq!(receiver.try_iter().count(), 1);
        canceled.store(7, Ordering::Relaxed);
        assert!(!control.progress(progress));
        assert!(receiver.try_recv().is_err());
    }
}

#[cfg(test)]
#[path = "native_folder_tests.rs"]
mod folder_tests;
