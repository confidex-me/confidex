use super::*;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Lock,
    Close,
}

impl VaultApp {
    pub fn request_close(ctx: &egui::Context) {
        ctx.data_mut(|data| data.insert_temp(egui::Id::unique("native-quit-request"), true));
        ctx.request_repaint();
    }
    pub fn has_unsaved_changes(&self) -> bool {
        self.editing
            && self.draft.as_ref().is_some_and(|draft| {
                draft.revision.is_none()
                    || self.edit_baseline.as_ref() != Some(draft)
                    || self.tag_editor.pending()
                    || !self.pending_totp.is_empty()
                    || self.ssh.active()
                    || self.ssh.is_open()
                    || self.attachments.window.open
                    || self.attachments.busy
                    || self.attachments.checking
                    || self.attachments.pending.is_some()
            })
    }

    pub(super) fn request_lock(&mut self) {
        if self.has_unsaved_changes() {
            self.preferences.close(&self.context);
            self.exit = Some(Action::Lock);
        } else {
            self.screen = Screen::Locking;
            self.request(Command::Lock, true);
        }
    }

    pub(super) fn check_close(&mut self, ctx: &egui::Context) {
        if ctx.viewport_id() != egui::ViewportId::ROOT {
            return;
        }
        let quit = ctx
            .data_mut(|data| data.remove_temp::<bool>(egui::Id::unique("native-quit-request")))
            .unwrap_or(false);
        if !(quit || ctx.input(|input| input.viewport().close_requested())) {
            return;
        }
        if self.has_unsaved_changes() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.request_repaint();
            self.exit = Some(Action::Close);
        } else if quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    pub(super) fn exit_dialog(&mut self, ctx: &egui::Context) {
        let Some(action) = self.exit else { return };
        let response = dialog::Confirmation {
            title: &self.locale.text("vault-exit-title"),
            body: &self.locale.text("vault-exit-body"),
            confirm: &self.locale.text(match action {
                Action::Lock => "vault-exit-lock",
                Action::Close => "vault-exit-close",
            }),
            cancel: &self.locale.text("vault-cancel"),
            role: ButtonRole::Danger,
        }
        .show(
            ctx,
            THEMES[self.theme].colors,
            egui::Id::unique("record-exit"),
        );
        self.bounds.insert("exit-dialog".into(), response.rect);
        self.hits.insert("exit-cancel".into(), response.cancel.rect);
        self.hits
            .insert("exit-confirm".into(), response.confirm.rect);
        match response.action {
            Some(dialog::Action::Cancel) => self.exit = None,
            Some(dialog::Action::Confirm) => {
                self.exit = None;
                match action {
                    Action::Lock => {
                        self.screen = Screen::Locking;
                        self.request(Command::Lock, true);
                    }
                    Action::Close => {
                        self.clear_private();
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            None => (),
        }
    }
}
