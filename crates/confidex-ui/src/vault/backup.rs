use super::*;
use std::sync::mpsc;

pub enum BackupFileRequest {
    Open,
    Save(Vec<u8>),
}
pub enum BackupFileReply {
    Opened(Vec<u8>),
    Saved,
    DownloadStarted,
    Cancelled,
    Failed,
    TooLarge,
}
pub type BackupFileCompletion = Box<dyn FnOnce(BackupFileReply) + Send>;
type Handler = Box<dyn FnMut(BackupFileRequest, BackupFileCompletion)>;
pub(super) struct Files {
    handler: Option<Handler>,
    sender: mpsc::Sender<(u32, BackupFileReply)>,
    receiver: mpsc::Receiver<(u32, BackupFileReply)>,
    pub bytes: Option<Vec<u8>>,
    pub importing: bool,
    pub after_sync: bool,
    pub busy: bool,
    pub notice: Option<&'static str>,
}
impl Default for Files {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            handler: None,
            sender,
            receiver,
            bytes: None,
            importing: false,
            after_sync: false,
            busy: false,
            notice: None,
        }
    }
}
impl Files {
    pub fn clear(&mut self) {
        self.bytes = None;
        self.importing = false;
        self.after_sync = false;
        self.busy = false;
        self.notice = None;
    }
}
impl VaultApp {
    pub fn set_backup_file_handler(
        &mut self,
        handler: impl FnMut(BackupFileRequest, BackupFileCompletion) + 'static,
    ) {
        self.files.handler = Some(Box::new(handler));
    }
    pub(super) fn backup_file(&mut self, ctx: &egui::Context, request: BackupFileRequest) {
        let sender = self.files.sender.clone();
        let generation = self.generation;
        let ctx = ctx.clone();
        self.files.busy = true;
        self.busy = true;
        self.files.notice = None;
        let done = Box::new(move |reply| {
            let _ = sender.send((generation, reply));
            ctx.request_repaint();
        });
        if let Some(handler) = &mut self.files.handler {
            handler(request, done);
        } else {
            done(BackupFileReply::Failed);
        }
    }
    pub(super) fn poll_backup(&mut self) {
        while let Ok((generation, reply)) = self.files.receiver.try_recv() {
            if generation != self.generation {
                continue;
            }
            self.files.busy = false;
            self.busy = false;
            match reply {
                BackupFileReply::Opened(archive) => {
                    self.request(Command::InspectBackup { archive }, true)
                }
                BackupFileReply::Saved => self.files.notice = Some("backup-saved"),
                BackupFileReply::DownloadStarted => {
                    self.files.notice = Some("backup-download-started")
                }
                BackupFileReply::Cancelled => (),
                BackupFileReply::Failed => self.files.notice = Some("backup-file-error"),
                BackupFileReply::TooLarge => self.files.notice = Some("backup-limit"),
            }
        }
    }
    pub(super) fn backup_screen(&mut self, ui: &mut egui::Ui) {
        self.form(ui, Metrics::CREATE_WIDTH, 460., |app, ui| {
            let ready = app.files.bytes.is_some();
            dialog::Form {
                id: "vault-backup",
                actions: if ready { 2 } else { 3 },
                min_action_width: 200.,
            }
            .show(
                ui,
                app,
                |app, ui| {
                    ui.heading(app.locale.text("backup-export"));
                },
                |app, ui, index| {
                    if ready && index == 0 {
                        if app.primary(
                            ui,
                            "backup-save",
                            "backup-save",
                            !app.busy && !app.files.busy,
                        ) {
                            let bytes = app.files.bytes.as_ref().unwrap().clone();
                            app.backup_file(ui.ctx(), BackupFileRequest::Save(bytes));
                        }
                    } else if !ready && index == 0 {
                        if app.primary(
                            ui,
                            "backup-sync",
                            "backup-sync",
                            !app.busy && app.sync_enabled && app.runtime.sync_available(),
                        ) {
                            app.files.after_sync = true;
                            app.sync_report = None;
                            app.request(
                                Command::Sync {
                                    server: app.sync_server.clone(),
                                },
                                false,
                            );
                        }
                    } else if !ready && index == 1 {
                        if app.button(ui, "backup-offline", "backup-offline", !app.busy) {
                            app.files.after_sync = false;
                            app.request(Command::ExportBackup, false);
                        }
                    } else if app.button(
                        ui,
                        "backup-cancel",
                        "vault-cancel",
                        !app.busy && !app.files.busy,
                    ) {
                        app.files.clear();
                        app.screen = Screen::Open;
                    }
                },
                |app, ui| {
                    app.feedback(ui);
                    if let Some(message) = app.files.notice {
                        ui.label(app.locale.text(message));
                        ui.add_space(Metrics::SM);
                    }
                    design::muted(ui, THEMES[app.theme].colors, app.locale.text("backup-hint"));
                    if !ready {
                        design::muted(
                            ui,
                            THEMES[app.theme].colors,
                            app.locale.text("backup-sync-question"),
                        );
                    }
                },
            );
        });
    }
}
