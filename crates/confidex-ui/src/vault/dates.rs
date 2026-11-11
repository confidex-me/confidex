use super::*;
use design::date::{self, Precision};

pub(super) fn valid(field: &app::Field) -> bool {
    let Some(precision) = Precision::from_type(&field.type_name) else {
        return true;
    };
    match field.values.get("date") {
        Some(text) => date::parse(text, precision).is_ok(),
        None => field.source.is_some(),
    }
}
impl VaultApp {
    pub(super) fn date_field(
        &mut self,
        ui: &mut egui::Ui,
        id: egui::Id,
        key: u64,
        source: &app::Field,
        values: &mut BTreeMap<String, String>,
    ) {
        let Some(precision) = Precision::from_type(&source.type_name) else {
            return;
        };
        let Some(text) = values.get_mut("date") else {
            design::muted(
                ui,
                THEMES[self.theme].colors,
                self.locale.text("vault-opaque-fields"),
            );
            return;
        };
        let reference = time::OffsetDateTime::from_unix_timestamp((epoch() / 1000) as i64)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
            .date();
        let editor = self
            .date_fields
            .entry(id.value())
            .or_insert_with(|| date::Editor::new(text, reference));
        editor.protected = source.protected;
        editor.revealed = self.revealed.contains(&(key, "date".into()));
        editor.feedback = self.clipboard.state(id.with("date"));
        if editor.text != *text {
            editor.text.zeroize();
            editor.text.clone_from(text);
        }
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
        let strings = [
            if precision == Precision::Day {
                "field-date"
            } else {
                "field-month-year"
            },
            "field-calendar",
            "field-clear",
            "vault-copy-value",
            "field-invalid-date",
            "field-year",
            "field-month",
            "field-weekdays",
        ]
        .map(|key| self.locale.text(key));
        let weekdays: Vec<_> = strings[7].split(',').collect();
        let output = editor.show(
            ui,
            THEMES[self.theme].colors,
            id,
            precision,
            true,
            date::Labels {
                name: &strings[0],
                hint: if precision == Precision::Day {
                    "DD/MM/YYYY"
                } else {
                    "MM/YYYY"
                },
                calendar: &strings[1],
                value: value::Labels::new(&value_labels),
                invalid: &strings[4],
                year: &strings[5],
                month: &strings[6],
                weekdays: std::array::from_fn(|i| weekdays.get(i).copied().unwrap_or("")),
            },
        );
        if source.protected && !editor.revealed {
            self.revealed.remove(&(key, "date".into()));
        }
        if output.changed {
            text.zeroize();
            text.push_str(&editor.text);
            self.attachments.invalidate_size();
            self.clipboard.invalidate(id.with("date"));
        }
        if output.copy {
            self.clipboard
                .request(ui.ctx(), id.with("date"), text.clone());
        }
        for (control, rect) in output.hits {
            let key = format!("date-{}-{control}", id.value());
            self.bounds.insert(key.clone(), rect);
            self.hits.insert(key, rect);
        }
        if let Some(rect) = output.popup {
            self.bounds
                .insert(format!("date-{}-popup", id.value()), rect);
        }
    }
}
