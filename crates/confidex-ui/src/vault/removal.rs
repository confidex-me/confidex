use super::*;

#[derive(Default)]
pub(super) struct State {
    pub open: bool,
    pub target: Option<VaultInfo>,
    pub pending: bool,
    pub removing: bool,
    pub confirmation: u8,
    partial: bool,
    password: String,
    key: String,
    prepared: Option<app::Created>,
    synchronize: bool,
    copy_after_prepare: bool,
    synchronized: bool,
    conflicts: bool,
    refresh: bool,
    pub error: Option<Error>,
}
impl State {
    pub fn cancel_credentials(&mut self) {
        self.password.zeroize();
        self.key.zeroize();
        self.prepared = None;
    }

    pub fn clear(&mut self) {
        self.password.zeroize();
        self.key.zeroize();
        *self = Self::default();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.password.zeroize();
        self.key.zeroize();
    }
}
impl VaultApp {
    pub(super) fn removal_action(&mut self, ui: &mut egui::Ui, vault: &VaultInfo) {
        ui.add_space(Metrics::LG);
        let p = THEMES[self.theme].colors;
        let title = self.locale.text("remove-vault");
        let font = design::fonts::medium(design::density(ui).body);
        let control_width = ui
            .fonts_mut(|fonts| fonts.layout_no_wrap(title.clone(), font, p.text).size().x)
            + 2. * ui.spacing().button_padding.x;
        form::group(ui, p, "", |group| {
            group.row(
                form::Row {
                    title: &title,
                    description: &self.locale.text("remove-vault-hint"),
                    control_width,
                },
                |ui, _| {
                    let response = design::button(
                        ui,
                        p,
                        &title,
                        ButtonRole::Danger,
                        ui.available_width(),
                        !self.busy,
                    );
                    self.hits.insert("remove-vault".into(), response.rect);
                    if response.clicked() {
                        self.removal.clear();
                        self.removal.target = Some(vault.clone());
                        self.removal.open = true;
                    }
                },
            );
        });
    }
    fn prepare_removal(&mut self, synchronize: bool) {
        let Some(vault) = self.removal.target.as_ref().map(|v| v.id) else {
            return;
        };
        self.removal.pending = true;
        self.removal.synchronize = synchronize;
        self.removal.refresh |= synchronize;
        self.removal.error = None;
        self.request(
            Command::PrepareRemoval {
                vault,
                password: self.removal.password.clone(),
                key: self.removal.key.clone(),
                synchronize,
            },
            false,
        );
    }
    pub(super) fn close_removal(&mut self) {
        let refresh = self.removal.refresh
            && self.screen == Screen::Open
            && self
                .removal
                .target
                .as_ref()
                .is_some_and(|target| self.active.as_ref().is_some_and(|v| v.id == target.id));
        self.removal.open = false;
        self.removal.confirmation = 0;
        self.removal.cancel_credentials();
        if !self.removal.pending {
            self.removal.clear();
        }
        if refresh && !self.busy {
            if let Some(draft) = &self.draft {
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
    }
    pub(super) fn removal_failed(&mut self, error: Error) {
        self.removal.pending = false;
        self.removal.removing = false;
        self.removal.error = Some(error);
        self.removal.confirmation = 0;
        self.busy = false;
        if !self.removal.open {
            self.close_removal();
        }
    }
    pub(super) fn removal_prepared(
        &mut self,
        created: app::Created,
        report: Option<app::sync::Report>,
    ) {
        self.removal.pending = false;
        if !self.removal.open
            || self
                .removal
                .target
                .as_ref()
                .is_none_or(|v| v.id != created.info.id)
        {
            self.close_removal();
            return;
        }
        self.removal.prepared = Some(created);
        if let Some(report) = report {
            self.removal.refresh = true;
            self.removal.conflicts = !report.conflicts.is_empty();
            self.removal.synchronized = !report.more && !self.removal.conflicts;
            if report.more && !self.removal.conflicts {
                self.prepare_removal(true);
            }
        }
    }
    pub(super) fn removed(&mut self, vault: VaultId, result: Result<(), Error>) {
        let current = self.active.as_ref().is_some_and(|v| v.id == vault);
        if current {
            let removal = std::mem::take(&mut self.removal);
            let preferences = std::mem::take(&mut self.preferences);
            self.clear_private();
            self.active = None;
            self.screen = Screen::Catalog;
            self.generation = self
                .generation
                .checked_add(1)
                .expect("session generation exhausted");
            self.removal = removal;
            self.preferences = preferences;
        }
        match result {
            Ok(()) => {
                self.catalog.retain(|v| v.id != vault);
                self.removal.clear();
                self.preferences_vault = None;
                self.preferences_section = 0;
                if current || self.active.is_none() {
                    self.preferences.clear();
                }
            }
            Err(error) => {
                self.removal.pending = false;
                self.removal.removing = false;
                self.removal.partial = true;
                self.removal.confirmation = 0;
                self.removal.error = Some(error);
                self.preferences_vault = self.removal.target.clone();
            }
        }
    }
    pub(super) fn removal_dialog(&mut self, ctx: &egui::Context) {
        if !self.removal.open {
            return;
        }
        let Some(target) = self.removal.target.clone() else {
            return;
        };
        let current =
            self.screen == Screen::Open && self.active.as_ref().is_some_and(|v| v.id == target.id);
        let copy_id = egui::Id::unique("remove-vault-key").with(target.id);
        if self.removal.copy_after_prepare
            && let Some(created) = &self.removal.prepared
        {
            self.clipboard.request(ctx, copy_id, created.key.clone());
            self.removal.copy_after_prepare = false;
        }
        let p = THEMES[self.theme].colors;
        let title = self.locale.text("remove-vault");
        let mut args = fluent_bundle::FluentArgs::new();
        args.set("name", target.name.as_str());
        let warning = self.locale.format("remove-vault-warning", &args);
        let confirm = self.locale.text(match self.removal.confirmation {
            0 => "vault-confirm-delete",
            1 => "remove-vault-confirm-want",
            _ => "remove-vault-confirm-final",
        });
        let cancel = self.locale.text("vault-cancel");
        let response = dialog::Confirmation {
            title: &title,
            body: &warning,
            confirm: &confirm,
            cancel: &cancel,
            role: ButtonRole::Danger,
        }
        .show_with(
            ctx,
            p,
            egui::Id::unique("remove-vault-confirmation"),
            [
                !self.busy && self.clipboard.state(copy_id) != value::CopyState::Pending,
                !self.removal.removing,
            ],
            |ui| {
                if current && self.editing {
                    ui.add_space(Metrics::MD);
                    ui.colored_label(p.error, self.locale.text("remove-vault-unsaved"));
                }
                if !current && !self.removal.partial {
                    ui.add_space(Metrics::MD);
                    ui.label(self.locale.text("remove-vault-unlock-hint"));
                    let label = ui.label(self.locale.text("vault-password"));
                    let input =
                        design::field(ui, &mut self.removal.password, true, false, !self.busy)
                            .labelled_by(label.id);
                    self.hits.insert("remove-password".into(), input.rect);
                    secret_key_field(
                        ui,
                        &self.locale,
                        &mut self.hits,
                        "remove-secret-key",
                        &mut self.removal.key,
                        true,
                        !self.busy,
                    );
                    design::muted(ui, p, self.locale.text("remove-vault-key-hint"));
                }
                if self.runtime.sync_available() && !self.removal.partial {
                    ui.add_space(Metrics::MD);
                    design::muted(ui, p, self.locale.text("remove-vault-sync-hint"));
                    let label = self.locale.text(
                        if self.removal.pending
                            && self.removal.synchronize
                            && !self.removal.removing
                        {
                            "vault-working"
                        } else {
                            "sync-now"
                        },
                    );
                    let r = design::button(
                        ui,
                        p,
                        &label,
                        ButtonRole::Secondary,
                        ui.available_width(),
                        !self.busy,
                    );
                    self.hits.insert("remove-sync".into(), r.rect);
                    if r.clicked() {
                        self.removal.synchronized = false;
                        self.prepare_removal(true);
                    }
                    if self.removal.synchronized {
                        ui.label(self.locale.text("remove-vault-synced"));
                    }
                    if self.removal.conflicts {
                        ui.colored_label(p.error, self.locale.text("remove-vault-conflicts"));
                    }
                }
                ui.add_space(Metrics::MD);
                let label = self.locale.text(
                    if self.removal.pending && !self.removal.synchronize && !self.removal.removing {
                        "vault-working"
                    } else {
                        match self.clipboard.state(copy_id) {
                            value::CopyState::Copied => "vault-copied",
                            value::CopyState::Pending => "vault-copy-pending",
                            value::CopyState::Failed => "vault-copy-failed",
                            value::CopyState::Idle => "vault-copy-key",
                        }
                    },
                );
                let r = design::button(
                    ui,
                    p,
                    &label,
                    ButtonRole::Secondary,
                    ui.available_width(),
                    !self.busy && !self.removal.partial,
                );
                self.hits.insert("remove-copy-key".into(), r.rect);
                if r.clicked() {
                    if let Some(created) = &self.removal.prepared {
                        self.clipboard.request(ctx, copy_id, created.key.clone());
                    } else {
                        self.removal.copy_after_prepare = true;
                        self.prepare_removal(false);
                    }
                }
                if let Some(error) = self.removal.error {
                    ui.add_space(Metrics::MD);
                    ui.colored_label(
                        p.error,
                        self.locale
                            .text(if self.removal.partial || error == Error::Credentials {
                                "remove-vault-cleanup-error"
                            } else {
                                error_key(error)
                            }),
                    );
                }
            },
        );
        self.bounds.insert("remove-dialog".into(), response.rect);
        self.bounds.insert("remove-body".into(), response.body);
        self.hits
            .insert("remove-confirm".into(), response.confirm.rect);
        self.hits
            .insert("remove-cancel".into(), response.cancel.rect);
        match response.action {
            Some(dialog::Action::Confirm) if self.removal.confirmation < 2 => {
                self.removal.confirmation += 1;
            }
            Some(dialog::Action::Confirm) => {
                self.removal.pending = true;
                self.removal.removing = true;
                self.removal.error = None;
                self.request(Command::RemoveVault { vault: target.id }, false);
            }
            Some(dialog::Action::Cancel) => self.close_removal(),
            None => (),
        }
    }
}
