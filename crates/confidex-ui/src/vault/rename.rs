use super::*;

#[derive(Default)]
pub(super) struct State {
    target: Option<VaultInfo>,
    pub name: String,
    pub pending: bool,
    pub error: Option<Error>,
}

impl VaultApp {
    pub(super) fn renamed(&mut self, info: VaultInfo, conflict: bool) {
        for current in self
            .catalog
            .iter_mut()
            .chain(self.active.iter_mut())
            .chain(self.preferences_vault.iter_mut())
            .chain(self.removal.target.iter_mut())
        {
            if current.id == info.id {
                *current = info.clone();
            }
        }
        if let Some(created) = &mut self.created
            && created.info.id == info.id
        {
            created.info = info.clone();
        }
        if self.rename.target.as_ref().is_some_and(|v| v.id == info.id) {
            let conflict = conflict && self.rename.name.trim() != info.name;
            self.rename.pending = false;
            self.rename.error =
                conflict.then_some(Error::Storage(confidex_storage::Error::Conflict));
            if !conflict {
                self.rename.name.clone_from(&info.name);
            }
            self.rename.target = Some(info);
        }
    }

    pub(super) fn rename_setting(&mut self, ui: &mut egui::Ui, vault: &VaultInfo) {
        if self.rename.target.as_ref().is_none_or(|v| v.id != vault.id) {
            self.rename = State {
                target: Some(vault.clone()),
                name: vault.name.clone(),
                ..Default::default()
            };
        }
        let p = THEMES[self.theme].colors;
        form::group(ui, p, "", |group| {
            group.row(
                form::Row {
                    title: &self.locale.text("vault-name"),
                    description: &self.locale.text("rename-vault-hint"),
                    control_width: 360.,
                },
                |ui, label| {
                    let input = design::field(ui, &mut self.rename.name, false, false, !self.busy)
                        .labelled_by(label);
                    self.hits.insert("rename-name".into(), input.rect);
                    if input.changed() {
                        self.rename.error = None;
                    }
                },
            );
        });
        let name = self.rename.name.trim().to_owned();
        let valid = !name.is_empty() && name.len() <= 128;
        if let Some(error) = self.rename.error {
            ui.colored_label(
                p.error,
                self.locale.text(
                    if error == Error::Storage(confidex_storage::Error::Conflict) {
                        "rename-vault-conflict"
                    } else {
                        error_key(error)
                    },
                ),
            );
        } else if self.rename.name != vault.name && !valid {
            ui.colored_label(p.error, self.locale.text("vault-error-input"));
        }
        if self.rename.name != vault.name || self.rename.pending {
            ui.add_space(Metrics::SM);
            layout::grid(
                ui,
                "rename-actions",
                2,
                120.,
                2,
                Metrics::SM,
                |ui, index| {
                    let key = if index == 0 {
                        if self.rename.pending {
                            "vault-working"
                        } else {
                            "vault-save"
                        }
                    } else {
                        "vault-cancel"
                    };
                    let response = design::button(
                        ui,
                        p,
                        &self.locale.text(key),
                        if index == 0 {
                            ButtonRole::Primary
                        } else {
                            ButtonRole::Secondary
                        },
                        ui.available_width(),
                        !self.busy && (index == 1 || (valid && name != vault.name)),
                    );
                    self.hits.insert(
                        if index == 0 {
                            "rename-save"
                        } else {
                            "rename-cancel"
                        }
                        .into(),
                        response.rect,
                    );
                    if response.clicked() {
                        if index == 0 {
                            self.rename.pending = true;
                            self.rename.error = None;
                            self.request(
                                Command::RenameVault {
                                    vault: vault.id,
                                    expected: self.rename.target.as_ref().unwrap().name.clone(),
                                    name: name.clone(),
                                },
                                false,
                            );
                        } else {
                            self.rename.name.clone_from(&vault.name);
                            self.rename.error = None;
                        }
                    }
                },
            );
        }
    }
}
