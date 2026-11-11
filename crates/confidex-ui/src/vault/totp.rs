use super::*;
use confidex_vault::record::{Entry, Mapping, Record, Value};
use design::totp;

type Edit<'a> = (&'a mut BTreeMap<String, String>, &'a mut Option<app::Bytes>);

impl VaultApp {
    pub(super) fn totp_problem(&self, id: egui::Id, field: &app::Field) -> Option<&'static str> {
        if field.type_name != "totp/v1" {
            return None;
        }
        if let Some(editor) = self.totp_fields.get(&id.value()) {
            let mut retired = Record::default();
            editor
                .apply(&mut retired.extra)
                .err()
                .map(totp::Issue::message)
        } else {
            app::field_record(field)
                .is_err()
                .then_some("gallery-totp-error-secret")
        }
    }
    pub(super) fn totp_field(
        &mut self,
        ui: &mut egui::Ui,
        id: egui::Id,
        source: &app::Field,
        edit: Option<Edit<'_>>,
    ) {
        let mut record = app::field_record(source).unwrap_or_else(|_| Record {
            entries: vec![Entry {
                name: String::new(),
                type_name: "totp/v1".into(),
                value: Mapping::new(),
                extra: Mapping::new(),
            }],
            tags: vec![],
            extra: Mapping::new(),
        });
        let editor = if edit.is_some() {
            Some(self.totp_fields.entry(id.value()).or_insert_with(|| {
                totp::Editor::read(&record.entries[0].value).unwrap_or_default()
            }))
        } else {
            None
        };
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default();
        let copy_id = id.with("code");
        if self
            .totp_times
            .get(&id.value())
            .is_some_and(|(last, expires)| now.as_secs() < *last || now.as_secs() >= *expires)
        {
            self.clipboard.invalidate(copy_id);
        }
        let output = totp::Field {
            id: id.with("value"),
            value: &record.entries[0].value,
            editor,
            now,
            enabled: !self.busy,
            feedback: self.clipboard.state(copy_id),
        }
        .show(ui, THEMES[self.theme].colors, &self.locale);
        let changed = output
            .controls
            .iter()
            .any(|(_, response)| response.changed());
        if changed {
            if output.valid {
                self.pending_totp.remove(&id.value());
            } else {
                self.pending_totp.insert(id.value());
            }
        }
        if changed || output.code.is_none() {
            self.clipboard.invalidate(copy_id);
        }
        if let Some((values, data)) = edit
            && changed
            && output.valid
            && self.totp_fields[&id.value()]
                .apply(&mut record.entries[0].value)
                .is_ok()
        {
            for key in ["algorithm", "digits", "period", "t0"] {
                if let Some(next) = record.entries[0].value.get(key) {
                    let next = next
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| next.as_u64().map(|n| n.to_string()))
                        .unwrap_or_default();
                    let value = values.entry(key.into()).or_default();
                    value.zeroize();
                    value.push_str(&next);
                }
            }
            if let Some(Value::Binary(secret)) = record.entries[0].value.get("secret") {
                *data = Some(secret.clone().into());
            }
            self.attachments.invalidate_size();
        }
        self.hits
            .insert(format!("totp-{}-copy", id.value()), output.copy.rect);
        self.bounds
            .insert(format!("totp-{}-code", id.value()), output.code_rect);
        self.bounds
            .insert(format!("totp-{}-timer", id.value()), output.timer_rect);
        for (key, response) in output.controls {
            self.hits
                .insert(format!("totp-{}-{key}", id.value()), response.rect);
        }
        if let Some(code) = output.code {
            self.totp_times.insert(
                id.value(),
                (
                    now.as_secs(),
                    now.as_secs()
                        .saturating_add(u64::from(code.valid_for_seconds)),
                ),
            );
            if output.copy.clicked() {
                self.clipboard
                    .request(ui.ctx(), copy_id, code.as_str().into());
            }
        } else {
            self.totp_times.remove(&id.value());
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
