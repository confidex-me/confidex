use super::*;
use design::card;

impl VaultApp {
    pub(super) fn card_field(
        &mut self,
        ui: &mut egui::Ui,
        id: egui::Id,
        source: &app::Field,
        values: &mut BTreeMap<String, String>,
        editing: bool,
    ) {
        let p = THEMES[self.theme].colors;
        let Ok(mut record) = app::field_record(source) else {
            ui.label(self.locale.text("gallery-card-unsupported"));
            return;
        };
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
        let names = card::FIELDS.map(|key| self.locale.text(&format!("gallery-card-{key}")));
        let checks = [
            "gallery-card-unsupported",
            "gallery-card-unchecked",
            "gallery-card-valid",
            "gallery-card-invalid",
        ]
        .map(|key| self.locale.text(key));
        let feedback = card::FIELDS.map(|key| self.clipboard.state(id.with(key)));
        let output = self.card_fields.entry(id.value()).or_default().show(
            ui,
            p,
            card::Card {
                id,
                values: &mut record.entries[0].value,
                editing,
                protected: source.protected,
                feedback,
                labels: card::Labels {
                    fields: std::array::from_fn(|i| names[i].as_str()),
                    value: value::Labels {
                        copy: &labels[0],
                        pending: &labels[1],
                        copied: &labels[2],
                        failed: &labels[3],
                        show: &labels[4],
                        hide: &labels[5],
                        large: &labels[6],
                        empty: &labels[7],
                    },
                    unsupported: &checks[0],
                    unchecked: &checks[1],
                    valid: &checks[2],
                    invalid: &checks[3],
                },
            },
        );
        for (key, output) in output {
            let field_id = id.with(key);
            let text = record.entries[0]
                .value
                .get(key)
                .and_then(confidex_vault::record::Value::as_str)
                .unwrap_or("");
            if editing && output.input.changed() {
                let value = values.entry(key.into()).or_default();
                value.zeroize();
                value.push_str(text);
                self.attachments.invalidate_size();
                self.clipboard.invalidate(field_id);
            }
            self.hits
                .insert(format!("card-{}-{key}", id.value()), output.input.rect);
            self.hits
                .insert(format!("card-{}-{key}-copy", id.value()), output.copy.rect);
            if let Some(reveal) = &output.reveal {
                self.hits
                    .insert(format!("card-{}-{key}-reveal", id.value()), reveal.rect);
            }
            if output.copy.clicked() {
                self.clipboard.request(ui.ctx(), field_id, text.into());
            }
            let index = card::FIELDS.iter().position(|k| *k == key).unwrap();
            self.large_value(
                ui,
                large_type::Value {
                    id: field_id,
                    title: &source.name,
                    field: &names[index],
                    text,
                },
                &output,
            );
        }
        if source.opaque > 0 {
            design::muted(ui, p, self.locale.text("vault-opaque-fields"));
        }
    }
}
