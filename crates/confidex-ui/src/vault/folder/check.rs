//! Synthetic folder host for browser checks. This module has no filesystem access.
use super::*;
use std::collections::VecDeque;
struct Host {
    context: egui::Context,
    path: Option<String>,
    replies: VecDeque<Response>,
    pending: Option<(u32, Instant)>,
}
fn info() -> VaultInfo {
    VaultInfo {
        id: [7; 16],
        name: "Public folder fixture".into(),
    }
}
impl Runtime for Host {
    fn folder_available(&self) -> bool {
        true
    }
    fn pick_folder(&mut self, done: FolderFileCompletion) {
        done(FolderFileReply::Selected(
            "/Public fixtures/Dropbox/Travel documents/Confidex shared vault".into(),
        ));
    }
    fn cancel_folder(&mut self) {
        if let Some((generation, _)) = self.pending.take() {
            self.replies.push_back(Response {
                generation,
                result: Ok(Output::Folder(Err(FolderError::Canceled))),
            });
        }
    }
    fn send(&mut self, request: Request) -> Result<(), Error> {
        let result = match &request.command {
            Command::Catalog => Ok(Output::Catalog(vec![info()])),
            Command::Select { .. } => Ok(Output::Selected {
                info: info(),
                remembered: true,
                device_unlock_verified_at: None,
            }),
            Command::Unlock { .. } => Ok(Output::Opened {
                info: info(),
                remembered: false,
                server: None,
                device_unlock_verified_at: None,
            }),
            Command::Folder(command) => match command {
                FolderCommand::Status => Ok(Output::Folder(Ok(Reply::State {
                    vault: info().id,
                    path: self.path.clone(),
                }))),
                FolderCommand::Configure { path } => {
                    self.path = path.clone();
                    Ok(Output::Folder(Ok(Reply::State {
                        vault: info().id,
                        path: path.clone(),
                    })))
                }
                FolderCommand::Sync => {
                    self.pending =
                        Some((request.generation, Instant::now() + Duration::from_secs(2)));
                    self.context
                        .request_repaint_after(Duration::from_millis(30));
                    return Ok(());
                }
                FolderCommand::Import { password, path, .. } => {
                    if password != "public-password" {
                        Ok(Output::Folder(Err(FolderError::App(Error::Auth))))
                    } else {
                        self.path = Some(path.clone());
                        Ok(Output::Folder(Ok(Reply::Opened {
                            info: info(),
                            remembered: false,
                            server: None,
                        })))
                    }
                }
            },
            Command::Search { .. } | Command::List { .. } => Ok(Output::Rows {
                rows: vec![],
                more: false,
                next: None,
            }),
            Command::Lock => Ok(Output::Locked),
            _ => Err(Error::Input),
        };
        self.replies.push_back(Response {
            generation: request.generation,
            result,
        });
        Ok(())
    }
    fn receive(&mut self) -> Option<Response> {
        if let Some(response) = self.replies.pop_front() {
            return Some(response);
        }
        let (generation, due) = self.pending?;
        if Instant::now() < due {
            self.context
                .request_repaint_after(Duration::from_millis(30));
            return None;
        }
        self.pending = None;
        Some(Response {
            generation,
            result: Ok(Output::Folder(Ok(Reply::Synced {
                vault: info().id,
                report: app::local_sync::Report {
                    downloaded: 1,
                    uploaded: 1,
                    pending: 2,
                },
            }))),
        })
    }
}
impl VaultApp {
    pub fn folder_fixture(context: &egui::Context) -> Result<Self, String> {
        Self::new(
            context,
            Box::new(Host {
                context: context.clone(),
                path: None,
                replies: VecDeque::new(),
                pending: None,
            }),
        )
    }
    pub fn folder_fixture_status(&self) -> (Option<&str>, usize, bool, bool) {
        (
            self.folder.path.as_deref(),
            self.folder.pending,
            self.folder.phase != Phase::Idle,
            self.folder.error.is_some(),
        )
    }
}
