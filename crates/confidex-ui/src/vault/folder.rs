use super::*;
use app::local_sync::{Command as FolderCommand, Error as FolderError, Reply};
use std::sync::mpsc;
#[cfg(feature = "export-check")]
mod check;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Phase {
    #[default]
    Idle,
    BeforeHttp,
    Http,
    AfterHttp,
}
pub enum FolderFileReply {
    Selected(String),
    Canceled,
    Failed,
}
pub type FolderFileCompletion = Box<dyn FnOnce(FolderFileReply) + Send>;
pub(super) struct State {
    pub path: Option<String>,
    pub error: Option<FolderError>,
    pub pending: usize,
    pub phase: Phase,
    pub loading: Option<bool>,
    failed: bool,
    pub import_path: Option<String>,
    pub picking: bool,
    pub after_config: bool,
    sender: mpsc::Sender<(u32, bool, FolderFileReply)>,
    receiver: mpsc::Receiver<(u32, bool, FolderFileReply)>,
}
impl Default for State {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            path: None,
            error: None,
            pending: 0,
            phase: Phase::Idle,
            loading: None,
            failed: false,
            import_path: None,
            picking: false,
            after_config: false,
            sender,
            receiver,
        }
    }
}
impl VaultApp {
    pub(super) fn pick_folder(&mut self, importing: bool) {
        let sender = self.folder.sender.clone();
        let generation = self.generation;
        let ctx = self.context.clone();
        self.folder.picking = true;
        self.folder.error = None;
        self.busy = true;
        self.runtime.pick_folder(Box::new(move |reply| {
            let _ = sender.send((generation, importing, reply));
            ctx.request_repaint();
        }));
    }
    pub(super) fn poll_folder(&mut self) {
        while let Ok((generation, importing, reply)) = self.folder.receiver.try_recv() {
            if generation != self.generation {
                continue;
            }
            self.folder.picking = false;
            self.busy = false;
            match reply {
                FolderFileReply::Selected(path) if importing => {
                    if self.screen != Screen::Import {
                        self.name.clear();
                        self.clear_credentials();
                    }
                    self.folder.import_path = Some(path);
                    self.files.importing = false;
                    self.screen = Screen::Import;
                    self.remember = true;
                    self.pending_focus = Some(egui::Id::unique(("vault-input", "name")));
                }
                FolderFileReply::Selected(path) => self.request(
                    Command::Folder(FolderCommand::Configure { path: Some(path) }),
                    false,
                ),
                FolderFileReply::Canceled => (),
                FolderFileReply::Failed => self.folder.error = Some(FolderError::Unavailable),
            }
        }
    }
    pub(super) fn folder_setting(&mut self, group: &mut form::Group<'_>) {
        if !self.runtime.folder_available() {
            return;
        }
        let title = self.locale.text("folder-sync");
        let hint = self.locale.text("folder-sync-hint");
        let enabled = !self.busy && !self.editing;
        let row = group.row(
            form::Row {
                title: &title,
                description: &hint,
                control_width: 200.,
            },
            |ui, _| {
                if matches!(self.folder.phase, Phase::BeforeHttp | Phase::AfterHttp) {
                    if self.button(ui, "folder-cancel", "vault-cancel", true) {
                        self.runtime.cancel_folder();
                    }
                } else if self.button(ui, "folder-choose", "folder-choose", enabled) {
                    self.pick_folder(false);
                }
            },
        );
        let mut bounds = row.row;
        if let Some(path) = self.folder.path.clone() {
            let row = group.row(
                form::Row {
                    title: &path,
                    description: "",
                    control_width: 200.,
                },
                |ui, _| {
                    if self.button(ui, "folder-disconnect", "folder-disconnect", enabled) {
                        self.request(
                            Command::Folder(FolderCommand::Configure { path: None }),
                            false,
                        );
                    }
                },
            );
            self.bounds.insert("folder-path".into(), row.label);
            bounds = bounds.union(row.row);
        }
        self.bounds.insert("preferences-folder".into(), bounds);
    }

    pub(super) fn folder_feedback(&mut self, ui: &mut egui::Ui) {
        let p = THEMES[self.theme].colors;
        if let Some(error) = self.folder.error {
            let message = match error {
                FolderError::App(error) => error_key(error),
                FolderError::Unavailable => "folder-unavailable",
                FolderError::Canceled => return,
            };
            let response = ui.label(RichText::new(self.locale.text(message)).color(p.error));
            self.bounds.insert("folder-error".into(), response.rect);
            ui.add_space(Metrics::SM);
        }
        if self.folder.pending > 0 {
            let response = ui.label(self.locale.text("folder-pending"));
            self.bounds.insert("folder-pending".into(), response.rect);
            design::muted(ui, p, self.locale.text("folder-pending-hint"));
            ui.add_space(Metrics::SM);
        }
        if matches!(self.folder.phase, Phase::BeforeHttp | Phase::AfterHttp)
            && self.button(ui, "folder-cancel", "vault-cancel", true)
        {
            self.runtime.cancel_folder();
        }
    }
    pub(super) fn transports_available(&self) -> bool {
        self.runtime.sync_available() || self.runtime.folder_available()
    }
    pub(super) fn sync_configured(&self) -> bool {
        self.sync_enabled && self.runtime.sync_available()
            || self.folder.path.is_some() && self.runtime.folder_available()
    }
    pub(super) fn start_sync(&mut self, automatic: bool) {
        self.folder.error = None;
        self.folder.pending = 0;
        self.folder.failed = false;
        self.sync_report = None;
        self.sync_automatic = automatic;
        if self.runtime.folder_available() && self.folder.path.is_some() {
            self.folder.phase = Phase::BeforeHttp;
            self.request(Command::Folder(FolderCommand::Sync), false);
        } else {
            self.request_http_sync(automatic);
        }
    }
    pub(super) fn request_http_sync(&mut self, automatic: bool) {
        let server = self.sync_server.clone();
        self.sync_automatic = automatic;
        self.request(
            if automatic {
                Command::CheckSync { server }
            } else {
                Command::Sync { server }
            },
            false,
        );
    }
    pub(super) fn after_folder_pull(&mut self) {
        if self.sync_enabled && self.runtime.sync_available() {
            self.folder.phase = Phase::Http;
            self.request_http_sync(self.sync_automatic);
        } else {
            self.finish_folder_sync();
        }
    }
    pub(super) fn finish_http_folder(&mut self) -> bool {
        if self.folder.phase != Phase::Http {
            return false;
        }
        if !self.folder.failed {
            self.folder.phase = Phase::AfterHttp;
            self.request(Command::Folder(FolderCommand::Sync), false);
        } else {
            self.finish_folder_sync();
        }
        true
    }
    pub(super) fn finish_folder_sync(&mut self) {
        self.folder.phase = Phase::Idle;
        self.sync_schedule.finish(self.folder.failed);
        if self.folder.failed {
            self.files.after_sync = false;
        }
        self.sync_automatic = false;
        self.screen = Screen::Open;
        if self.files.after_sync {
            self.files.after_sync = false;
            self.request(Command::ExportBackup, false);
        } else if let Some(draft) = &self.draft {
            self.request(
                Command::CheckRevision {
                    record: draft.record,
                    revision: draft.revision,
                },
                false,
            );
        } else {
            self.request_list(None);
        }
    }
    pub(super) fn folder_http_failed(&mut self, error: Error) {
        self.files.after_sync = false;
        if let Some(report) = &mut self.sync_report {
            report.more = false;
        }
        if !self.sync_automatic
            || !matches!(error, Error::Network | Error::Server(408 | 429 | 500..=599))
        {
            self.folder.error = Some(FolderError::App(error));
        }
        let failed_before = self.folder.failed;
        self.folder.failed = true;
        if failed_before {
            self.finish_folder_sync();
        } else {
            self.folder.phase = Phase::AfterHttp;
            self.request(Command::Folder(FolderCommand::Sync), false);
        }
    }
    pub(super) fn folder_reply(&mut self, result: Result<Reply, FolderError>) {
        match result {
            Ok(Reply::State { vault, path }) => {
                if self.active.as_ref().map(|v| v.id) != Some(vault) {
                    self.request_failed(Error::Integrity);
                    return;
                }
                self.folder.path = path;
                self.folder.error = None;
                self.folder.pending = 0;
                if let Some(automatic) = self.folder.loading.take() {
                    self.sync_after_list = self.sync_configured().then_some(automatic);
                    self.request_list(None);
                } else {
                    self.sync_schedule.saved();
                }
            }
            Ok(Reply::Synced { vault, report }) => {
                if self.active.as_ref().map(|v| v.id) != Some(vault) {
                    self.folder.phase = Phase::Idle;
                    self.request_failed(Error::Integrity);
                    return;
                }
                self.folder.pending = report.pending;
                if self.folder.phase == Phase::BeforeHttp {
                    self.after_folder_pull();
                } else {
                    self.finish_folder_sync();
                }
            }
            Ok(Reply::Opened { .. }) => unreachable!(),
            Err(error) => {
                if error != FolderError::Canceled
                    && !(self.sync_automatic && error == FolderError::Unavailable)
                {
                    self.folder.error = Some(error);
                }
                let phase = self.folder.phase;
                self.folder.failed = error != FolderError::Canceled;
                if error == FolderError::Canceled && phase != Phase::Idle {
                    self.files.after_sync = false;
                    self.finish_folder_sync();
                } else if phase == Phase::BeforeHttp {
                    self.after_folder_pull();
                } else if phase == Phase::AfterHttp {
                    self.finish_folder_sync();
                } else if let Some(automatic) = self.folder.loading.take() {
                    self.sync_after_list = self.sync_enabled.then_some(automatic);
                    self.request_list(None);
                } else if let FolderError::App(error) = error {
                    self.folder.error = None;
                    self.request_failed(error);
                }
            }
        }
    }
}
