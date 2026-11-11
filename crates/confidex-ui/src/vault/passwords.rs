use super::*;

impl VaultApp {
    pub fn restore_generator_preferences(&mut self, storage: Option<&dyn eframe::Storage>) {
        self.generator_preferences = design::password::GeneratorPreferences::restore(storage);
    }
    pub(super) fn password_field(
        &mut self,
        ui: &mut egui::Ui,
        prefix: &str,
        field: value::ValueField<'_>,
    ) -> design::password::FieldOutput {
        let strength = self.locale.password_strength();
        let generator = self.locale.generator_labels();
        let before = self.generator_preferences;
        let output = design::password::Field {
            value: field,
            strength: design::password::Labels::new(&strength),
            generator: design::password::GeneratorLabels::new(&generator),
            preferences: &mut self.generator_preferences,
            evaluator: &mut self.passwords,
        }
        .show(ui, THEMES[self.theme].colors);
        self.defaults_changed |= before != self.generator_preferences;
        if let Some(generator) = &output.generator {
            self.hits
                .insert(format!("{prefix}-generate"), generator.opener.rect);
            if let Some(rect) = generator.popup {
                self.bounds.insert(format!("{prefix}-generator"), rect);
            }
            for (name, response) in &generator.controls {
                self.hits
                    .insert(format!("{prefix}-generator-{name}"), response.rect);
            }
        }
        output
    }
    pub(super) fn new_master_password(&mut self, ui: &mut egui::Ui) {
        let label = ui.label(self.locale.text("vault-password"));
        let mut password = zeroize::Zeroizing::new(std::mem::take(&mut self.password));
        let mut revealed = self.show_password;
        let labels = [
            "vault-copy-value",
            "vault-copy-pending",
            "vault-copied",
            "vault-copy-failed",
            "vault-reveal",
            "vault-hide",
            "vault-large-type",
            "vault-empty-value",
        ]
        .map(|key| self.locale.text(key));
        let id = egui::Id::unique(("vault-input", "password"));
        let feedback = self.clipboard.state(id);
        let enabled = !self.busy;
        let output = self.password_field(
            ui,
            "master",
            value::ValueField {
                id,
                value: &mut password,
                kind: value::Kind::Password,
                protected: true,
                editing: true,
                enabled,
                revealed: &mut revealed,
                feedback,
                labels: value::Labels {
                    copy: &labels[0],
                    pending: &labels[1],
                    copied: &labels[2],
                    failed: &labels[3],
                    show: &labels[4],
                    hide: &labels[5],
                    large: &labels[6],
                    empty: &labels[7],
                },
            },
        );
        self.show_password = revealed;
        output.value.input.clone().labelled_by(label.id);
        if output.value.input.changed() {
            self.clipboard.invalidate(id);
        }
        self.hits.insert("password".into(), output.value.input.rect);
        if let Some(rect) = output.strength {
            self.bounds.insert("master-password-strength".into(), rect);
        }
        if output.value.copy.clicked() {
            self.clipboard.request(ui.ctx(), id, password.to_string());
        }
        let field = self.locale.text("vault-password");
        let title = self.name.clone();
        self.large_value(
            ui,
            large_type::Value {
                id,
                title: &title,
                field: &field,
                text: &password,
            },
            &output.value,
        );
        if output
            .generator
            .as_ref()
            .is_some_and(|output| output.changed)
        {
            self.repeated.zeroize();
            self.repeated.push_str(&password);
        }
        self.password = std::mem::take(&mut *password);
    }
}
