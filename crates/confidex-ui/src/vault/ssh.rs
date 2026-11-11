use super::*;
use crate::{ImageFile, ImageReply, ImageRequest};
use std::sync::mpsc;
#[cfg(test)]
mod tests;

enum FileEvent {
    Pick(u64, ImageReply),
    Save(RecordId, u64, ImageReply),
}

pub(super) struct State {
    target: Option<(RecordId, u64)>,
    token: u64,
    source: String,
    password: String,
    password_required: bool,
    reveal: bool,
    pending: bool,
    picking: bool,
    pub checking: bool,
    candidate: Option<app::Field>,
    error: Option<&'static str>,
    notice: Option<(u64, &'static str)>,
    sender: mpsc::Sender<FileEvent>,
    receiver: mpsc::Receiver<FileEvent>,
}
impl Default for State {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            target: None,
            token: 0,
            source: String::new(),
            password: String::new(),
            password_required: false,
            reveal: false,
            pending: false,
            picking: false,
            checking: false,
            candidate: None,
            error: None,
            notice: None,
            sender,
            receiver,
        }
    }
}
impl State {
    pub fn clear(&mut self) {
        self.token += 1;
        self.target = None;
        self.source.zeroize();
        self.password.zeroize();
        self.reveal = false;
        self.password_required = false;
        self.pending = false;
        self.picking = false;
        self.checking = false;
        self.candidate = None;
        self.error = None;
        self.notice = None;
        while self.receiver.try_recv().is_ok() {}
    }
    pub fn active(&self) -> bool {
        self.picking || self.pending || self.checking || self.candidate.is_some()
    }
    pub fn is_open(&self) -> bool {
        self.target.is_some()
    }
    pub fn removed(&mut self, key: u64) {
        if self.target.is_some_and(|(_, target)| target == key) {
            self.clear();
        }
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.clear();
    }
}

impl VaultApp {
    pub(super) fn ssh_pick(&mut self, ctx: &egui::Context, request: ImageRequest) {
        let sender = self.ssh.sender.clone();
        let token = self.ssh.token;
        let ctx = ctx.clone();
        self.ssh.picking = true;
        self.file_drop.error = None;
        self.host_file_request(
            request,
            Box::new(move |reply| {
                let _ = sender.send(FileEvent::Pick(token, reply));
                ctx.request_repaint();
            }),
        );
    }
    pub(super) fn ssh_drop(
        &mut self,
        ctx: &egui::Context,
        record: RecordId,
        key: u64,
        file: egui::DroppedFileHandle,
    ) {
        self.ssh.clear();
        self.ssh.target = Some((record, key));
        self.ssh_pick(
            ctx,
            ImageRequest::Dropped {
                file,
                image: false,
                bytes: app::ssh::MAX_KEY,
            },
        );
    }
    pub(super) fn ssh_reply(&mut self, token: u64, result: Result<app::Field, app::ssh::Error>) {
        if self.ssh.token != token || !self.ssh.pending {
            return;
        }
        self.ssh.pending = false;
        self.ssh.password.zeroize();
        match result {
            Ok(field) => self.ssh.candidate = Some(field),
            Err(error) => {
                self.ssh.password_required |= matches!(
                    error,
                    app::ssh::Error::PassphraseRequired | app::ssh::Error::Authentication
                );
                self.ssh.error = Some(match error {
                    app::ssh::Error::Limit => "ssh-limit",
                    app::ssh::Error::Unsupported => "ssh-unsupported",
                    app::ssh::Error::PassphraseRequired => "ssh-password",
                    app::ssh::Error::Authentication => "ssh-auth",
                    app::ssh::Error::Invalid => "ssh-invalid",
                });
            }
        }
    }
    fn ssh_submit(&mut self) {
        if self.ssh.source.len() > app::ssh::MAX_KEY || self.ssh.password.len() > 4096 {
            self.ssh.error = Some("ssh-limit");
            return;
        }
        let request = Request {
            generation: self.generation,
            command: Command::ImportSsh {
                token: self.ssh.token,
                data: self.ssh.source.as_bytes().to_vec(),
                password: self
                    .ssh
                    .password_required
                    .then(|| self.ssh.password.clone()),
            },
        };
        self.ssh.error = None;
        match self.runtime.send(request) {
            Ok(()) => self.ssh.pending = true,
            Err(_) => self.ssh.error = Some("vault-error-input"),
        }
    }
    pub(super) fn poll_ssh(&mut self) {
        while let Ok(event) = self.ssh.receiver.try_recv() {
            let (token, reply) = match event {
                FileEvent::Pick(token, reply) => (token, reply),
                FileEvent::Save(record, key, reply) => {
                    if self
                        .draft
                        .as_ref()
                        .is_some_and(|draft| draft.record == record)
                        && self.field_ids.contains(&key)
                    {
                        let notice = match reply {
                            ImageReply::Saved => Some("gallery-image-saved"),
                            ImageReply::DownloadStarted => Some("gallery-image-download"),
                            ImageReply::Cancelled => None,
                            _ => Some("vault-error-input"),
                        };
                        self.ssh.notice = notice.map(|notice| (key, notice));
                    }
                    continue;
                }
            };
            if token != self.ssh.token || self.ssh.target.is_none() {
                continue;
            }
            self.ssh.picking = false;
            match reply {
                ImageReply::Opened(mut file) if file.bytes.len() <= app::ssh::MAX_KEY => {
                    match String::from_utf8(std::mem::take(&mut *file.bytes)) {
                        Ok(text) => {
                            self.ssh.source.zeroize();
                            self.ssh.source = text;
                            self.ssh.password_required = false;
                            self.ssh.password.zeroize();
                            self.ssh_submit();
                        }
                        Err(error) => {
                            let mut bytes = error.into_bytes();
                            bytes.zeroize();
                            self.ssh.error = Some("ssh-invalid");
                        }
                    }
                }
                ImageReply::Opened(_) | ImageReply::TooLarge => {
                    self.ssh.error = Some("ssh-file-limit");
                }
                ImageReply::Cancelled | ImageReply::Saved | ImageReply::DownloadStarted => (),
                _ => self.ssh.error = Some("vault-error-input"),
            }
        }
        if self.busy || self.attachments.busy || self.ssh.checking || self.ssh.candidate.is_none() {
            return;
        }
        let Some((record, key)) = self.ssh.target else {
            return;
        };
        let Some(index) = self.field_ids.iter().position(|id| *id == key) else {
            self.ssh.clear();
            return;
        };
        let Some(mut draft) = self
            .draft
            .as_ref()
            .filter(|draft| draft.record == record && self.editing)
            .cloned()
        else {
            self.ssh.clear();
            return;
        };
        let candidate = self.ssh.candidate.as_ref().unwrap();
        draft.fields[index].data = candidate.data.clone();
        draft.fields[index].values.clone_from(&candidate.values);
        self.ssh.checking = true;
        self.request(Command::CheckDraft { draft }, false);
    }
    pub(super) fn ssh_checked(&mut self, result: Result<(), Error>) {
        self.ssh.checking = false;
        self.busy = false;
        if let Err(error) = result {
            self.ssh.candidate = None;
            self.ssh.error = Some(if error == Error::RecordLimit {
                "gallery-image-full"
            } else {
                "vault-error-input"
            });
            return;
        }
        if let Some((record, key)) = self.ssh.target
            && let Some(index) = self.field_ids.iter().position(|id| *id == key)
            && let Some(draft) = self.draft.as_mut().filter(|draft| draft.record == record)
            && let Some(candidate) = self.ssh.candidate.take()
        {
            draft.fields[index].data = candidate.data.clone();
            draft.fields[index].values.clone_from(&candidate.values);
            self.revealed.retain(|(id, _)| *id != key);
            self.clipboard.clear();
            self.attachments.invalidate_size();
        }
        self.ssh.clear();
    }
    pub(super) fn ssh_editor(&mut self, ui: &mut egui::Ui, record: RecordId, key: u64) -> bool {
        if self.ssh.target != Some((record, key)) {
            return false;
        }
        let p = THEMES[self.theme].colors;
        dialog::Form {
            id: "ssh-import-form",
            actions: 3,
            min_action_width: 120.,
        }
        .show(
            ui,
            self,
            |app, ui| {
                ui.label(app.locale.text("ssh-private"));
                let input = ui.add_enabled(
                    !app.ssh.active(),
                    egui::TextEdit::multiline(&mut app.ssh.source)
                        .id(egui::Id::unique(("ssh-source", key)))
                        .password(!app.ssh.reveal)
                        .desired_width(f32::INFINITY)
                        .desired_rows(4)
                        .char_limit(app::ssh::MAX_KEY),
                );
                app.hits.insert(format!("ssh-{key}-source"), input.rect);
                design::checkbox(ui, &mut app.ssh.reveal, app.locale.text("vault-reveal"));
                if app.ssh.password_required {
                    ui.label(app.locale.text("ssh-passphrase"));
                    let enabled = !app.ssh.active();
                    let input = design::field_with_id(
                        ui,
                        egui::Id::unique(("ssh-password", key)),
                        &mut app.ssh.password,
                        true,
                        false,
                        enabled,
                    );
                    app.hits.insert(format!("ssh-{key}-password"), input.rect);
                    if input.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter))
                        && !app.ssh.active()
                    {
                        app.ssh_submit();
                    }
                }
            },
            |app, ui, index| {
                let action = ["gallery-file-choose", "ssh-import", "vault-cancel"][index];
                let enabled =
                    index == 2 || !app.ssh.active() && (index == 0 || !app.ssh.source.is_empty());
                if app.action(
                    ui,
                    &format!("ssh-{key}-action-{index}"),
                    action,
                    enabled,
                    if index == 1 {
                        ButtonRole::Primary
                    } else {
                        ButtonRole::Secondary
                    },
                ) {
                    match index {
                        0 => {
                            app.ssh_pick(
                                ui.ctx(),
                                ImageRequest::OpenLimited {
                                    bytes: app::ssh::MAX_KEY,
                                },
                            );
                        }
                        1 => app.ssh_submit(),
                        _ => app.ssh.clear(),
                    }
                }
            },
            |app, ui| {
                if app.ssh.active() {
                    design::spinner(ui, p, Metrics::ICON, &app.locale.text("ssh-import"));
                }
                if let Some(error) = app.ssh.error {
                    let mut args = fluent_bundle::FluentArgs::new();
                    args.set("limit", (app::ssh::MAX_KEY / 1024) as i64);
                    let response = ui.colored_label(p.error, app.locale.format(error, &args));
                    app.bounds
                        .insert(format!("ssh-{key}-notice"), response.rect);
                }
            },
        );
        true
    }
    pub(super) fn ssh_actions(
        &mut self,
        ui: &mut egui::Ui,
        record: RecordId,
        key: u64,
        values: &mut BTreeMap<String, String>,
        data: &mut Option<app::Bytes>,
        editing: bool,
    ) {
        let private = values
            .get("private_key")
            .filter(|text| !text.is_empty())
            .cloned();
        let count = if editing {
            1 + 2 * usize::from(private.is_some())
        } else {
            usize::from(private.is_some())
        };
        layout::grid(
            ui,
            &format!("ssh-{key}-actions"),
            count,
            120.,
            3,
            Metrics::SM,
            |ui, index| {
                if editing && index == 0 {
                    if self.button(
                        ui,
                        &format!("ssh-{key}-import"),
                        "ssh-import",
                        !self.busy && !self.attachments.busy && !self.ssh.is_open(),
                    ) {
                        self.ssh.clear();
                        self.ssh.target = Some((record, key));
                    }
                } else if editing && index == 2 {
                    if self.button(
                        ui,
                        &format!("ssh-{key}-clear"),
                        "field-clear",
                        !self.busy && !self.ssh.is_open(),
                    ) {
                        for value in values.values_mut() {
                            value.zeroize();
                        }
                        values.clear();
                        *data = Some(Vec::new().into());
                        self.revealed.retain(|(id, _)| *id != key);
                        self.clipboard.clear();
                        self.attachments.invalidate_size();
                    }
                } else if self.button(
                    ui,
                    &format!("ssh-{key}-save"),
                    "gallery-file-save",
                    !self.busy,
                ) {
                    let sender = self.ssh.sender.clone();
                    let ctx = ui.ctx().clone();
                    self.host_file_request(
                        ImageRequest::Save(ImageFile {
                            name: "private-key.openssh".into(),
                            bytes: private.as_ref().unwrap().as_bytes().to_vec().into(),
                        }),
                        Box::new(move |reply| {
                            let _ = sender.send(FileEvent::Save(record, key, reply));
                            ctx.request_repaint();
                        }),
                    );
                }
            },
        );
        if let Some(mut private) = private {
            private.zeroize();
        }
        if let Some((target, message)) = self.ssh.notice
            && target == key
        {
            ui.label(self.locale.text(message));
        }
    }
}
