use super::*;
use confidex_vault::location;

pub(super) fn valid_values(values: &BTreeMap<String, String>) -> bool {
    values.len() == location::FIELDS.len()
        && location::FIELDS.iter().all(|key| values.contains_key(*key))
        && location::parse(&values["latitude"], &values["longitude"]).is_ok()
}
pub(super) fn valid(field: &app::Field) -> bool {
    field.type_name != "location/v1"
        || if field.values.is_empty() {
            field.source.is_some()
        } else {
            valid_values(&field.values)
        }
}
impl VaultApp {
    pub(super) fn location_field(
        &mut self,
        ui: &mut egui::Ui,
        id: egui::Id,
        source: &app::Field,
        values: &mut BTreeMap<String, String>,
    ) {
        if values.is_empty() {
            design::muted(
                ui,
                THEMES[self.theme].colors,
                self.locale.text("vault-opaque-fields"),
            );
            return;
        }
        let mut editor = design::location::Editor {
            name: values.get("name").cloned().unwrap_or_default(),
            latitude: values.get("latitude").cloned().unwrap_or_default(),
            longitude: values.get("longitude").cloned().unwrap_or_default(),
        };
        let value_labels = [
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
        let output = editor.show(
            ui,
            THEMES[self.theme].colors,
            id,
            true,
            design::location::Labels {
                name: &self.locale.text("field-location"),
                latitude: &self.locale.text("field-latitude"),
                longitude: &self.locale.text("field-longitude"),
                invalid: &self.locale.text("field-invalid-coordinates"),
                value: value::Labels::new(&value_labels),
            },
        );
        if output.changed {
            for (key, text) in [
                ("name", &editor.name),
                ("latitude", &editor.latitude),
                ("longitude", &editor.longitude),
            ] {
                let value = values.entry(key.into()).or_default();
                if value != text {
                    value.zeroize();
                    value.push_str(text);
                    self.clipboard.invalidate(id.with(key));
                }
            }
            self.clipboard.invalidate(id.with("location"));
            self.attachments.invalidate_size();
        }
        if let Some((key, text)) = output.copy {
            self.clipboard.request(ui.ctx(), id.with(key), text);
        }
        for (key, rect) in output.hits {
            self.hits
                .insert(format!("location-{}-{key}", id.value()), rect);
        }
        if source.opaque > 0 {
            design::muted(
                ui,
                THEMES[self.theme].colors,
                self.locale.text("vault-opaque-fields"),
            );
        }
    }
}
