//! External export form. The host owns worker requests and file publication.
use super::{self as kit, ButtonRole, Metrics as M, dialog, layout, window};
use crate::{i18n::Localizer, theme::Palette};
use confidex_app::{
    export::{self, Format},
    export_flow as flow,
};
use eframe::egui::{self, Rect, Vec2};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};
mod csv;
pub use csv::State as CsvState;
#[cfg(feature = "export-check")]
pub use csv::check as check_csv_setup;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stage {
    #[default]
    Loading,
    Setup,
    Review,
    Generating,
    Collecting,
    Ready,
    Saving,
    Complete,
    Failed,
}
pub enum Event {
    Fields {
        operation: u32,
        head: confidex_storage::Head,
        start: usize,
    },
    Review,
    Generate,
    Save,
    ChooseKeyfile,
    ClearKeyfile,
    Cancel,
    Restart,
}
#[derive(Default)]
pub struct State {
    pub window: window::State,
    pub stage: Stage,
    pub formats: Vec<export::FormatInfo>,
    pub format: usize,
    pub organization: bool,
    pub csv: CsvState,
    pub rows: Vec<flow::Row>,
    pub all: bool,
    pub selected: BTreeSet<usize>,
    pub review: Option<flow::Review>,
    pub issues: Vec<flow::IssueRow>,
    pub allow_losses: bool,
    pub plaintext_ack: bool,
    pub operation: u32,
    pub progress: Option<export::Progress>,
    pub password: Zeroizing<String>,
    pub use_password: bool,
    pub use_keyfile: bool,
    pub keyfile: Option<confidex_app::import_flow::File>,
    pub error: Option<flow::Error>,
    pub notice: Option<&'static str>,
    pub waiting: bool,
    pub bytes: usize,
    pub hits: BTreeMap<String, Rect>,
    pub bounds: BTreeMap<String, Rect>,
    query: Zeroizing<String>,
    filtered: Vec<usize>,
    filtered_rows: usize,
    enter: bool,
    issue_page: usize,
    events: Vec<Event>,
}
impl State {
    pub fn clear(&mut self) {
        let operation = self.operation;
        *self = Self::default();
        self.operation = operation;
    }
    pub fn next_operation(&mut self) -> u32 {
        self.operation = self
            .operation
            .checked_add(1)
            .expect("export operation exhausted");
        self.operation
    }
    pub fn selected_format(&self) -> Option<Format> {
        self.formats.get(self.format).map(|f| f.format)
    }
    pub fn selection(&self) -> flow::Selection {
        if self.all {
            flow::Selection::All
        } else {
            flow::Selection::Records(
                self.selected
                    .iter()
                    .filter_map(|&i| self.rows.get(i).map(|r| r.head.clone()))
                    .collect(),
            )
        }
    }
    pub fn configured(&self) -> bool {
        if self.waiting || (!self.all && self.selected.is_empty()) {
            return false;
        }
        match self.selected_format() {
            Some(Format::Kdbx) => {
                (self.use_password || self.use_keyfile)
                    && (!self.use_keyfile
                        || self.keyfile.as_ref().is_some_and(|file| file.bytes > 0))
                    && (!self.use_password || self.password.len() <= 4096)
                    && (self.use_keyfile || !self.password.is_empty())
            }
            Some(Format::BitwardenEncryptedJson) => {
                self.use_password
                    && !self.password.is_empty()
                    && self.password.len() <= export::MAX_PASSWORD_BYTES
            }
            Some(Format::Csv) => self.csv.valid(),
            None => false,
            _ => true,
        }
    }
    pub fn can_generate(&self) -> bool {
        !self.waiting
            && self.stage == Stage::Review
            && self.review.as_ref().is_some_and(|r| {
                r.blocked == 0
                    && (r.losses == 0 || self.allow_losses)
                    && (r.file.encrypted || self.plaintext_ack)
            })
    }
    pub fn request_csv_fields(&mut self, head: confidex_storage::Head, start: usize) -> bool {
        if self.stage != Stage::Setup
            || self.selected_format() != Some(Format::Csv)
            || self.waiting
            || self.csv.waiting()
            || self.csv.profile().is_some()
        {
            return false;
        }
        let Some(fields) = self
            .rows
            .iter()
            .find(|row| row.head == head && (self.all || self.selected.contains(&row.index)))
            .map(|row| row.fields)
        else {
            return false;
        };
        let operation = self.next_operation();
        self.csv
            .begin_fields(operation, head.clone(), start, fields);
        self.progress = None;
        self.events.push(Event::Fields {
            operation,
            head,
            start,
        });
        true
    }
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
    fn hit(&mut self, id: &str, response: &egui::Response) {
        if response.enabled() {
            self.hits.insert(id.into(), response.rect);
        }
    }
    pub fn show_window(&mut self, ctx: &egui::Context, p: Palette, locale: &Localizer) {
        self.hits.clear();
        self.bounds.clear();
        let mut host = std::mem::take(&mut self.window);
        let open = host.open;
        if let Some(output) = host.show(
            ctx,
            p,
            window::Window {
                id: egui::Id::unique("record-export-window"),
                title: &locale.text("export-title"),
                close_label: &locale.text("window-close"),
                size: Vec2::new(820., 740.),
            },
            |ui| self.show(ui, p, locale),
        ) {
            self.bounds.insert("export-window".into(), output.rect);
            self.bounds.insert("export-window-body".into(), output.body);
            if let Some(close) = output.close {
                self.hits.insert("export-close".into(), close.rect);
            }
        }
        if open && !host.open {
            self.events.push(Event::Cancel);
        }
        self.window = host;
    }
    fn show(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        self.enter = false;
        layout::scroll(ui, "export-form-scroll", false, |ui| {
            let sections = dialog::Form {
                id: "export-form",
                actions: if self.stage == Stage::Review { 3 } else { 2 },
                min_action_width: 200.,
            }
            .show(
                ui,
                self,
                |state, ui| state.content(ui, p, locale),
                |state, ui, index| state.action(ui, p, locale, index),
                |state, ui| state.notifications(ui, p, locale),
            );
            self.bounds
                .insert("export-content".into(), sections.content);
            self.bounds
                .insert("export-actions".into(), sections.actions);
            self.bounds
                .insert("export-notifications".into(), sections.notifications);
        });
    }
    fn content(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        match self.stage {
            Stage::Setup => self.setup(ui, p, locale),
            Stage::Review => {
                if let Some(review) = &self.review {
                    ui.label(&review.file.name);
                    ui.label(count(locale, "export-records", review.records));
                    ui.label(count(locale, "export-losses", review.losses));
                    ui.label(count(locale, "export-blocked", review.blocked));
                }
                ui.add_space(M::LG);
                self.issue_page = self
                    .issue_page
                    .min(self.issues.len().saturating_sub(1) / flow::PAGE_SIZE);
                let start = self.issue_page * flow::PAGE_SIZE;
                let end = self.issues.len().min(start + flow::PAGE_SIZE);
                layout::scroll_content(ui, "export-issues", 240., |ui| {
                    for row in &self.issues[start..end] {
                        let code = match row.issue.code {
                            export::Code::UnsupportedField => "unsupported-field",
                            export::Code::UnknownValue => "unknown-value",
                            export::Code::UnknownMetadata => "unknown-metadata",
                            export::Code::Protection => "protection",
                            export::Code::FieldOrder => "field-order",
                            export::Code::FieldNames => "field-names",
                            export::Code::MultipleUrls => "urls",
                            export::Code::TotpParameters => "totp",
                            export::Code::Attachments => "attachments",
                            export::Code::Tags => "tags",
                            export::Code::Sections => "sections",
                            export::Code::SourceContext => "source-context",
                            export::Code::History => "history",
                        };
                        let kind = if row.issue.severity == export::Severity::Blocked {
                            "export-issue-blocked"
                        } else {
                            "export-issue-loss"
                        };
                        let title = if row.title.is_empty() {
                            locale.text("vault-untitled")
                        } else {
                            row.title.clone()
                        };
                        ui.label(format!(
                            "{} · {}. {}",
                            locale.text(kind),
                            row.issue.record + 1,
                            title
                        ));
                        if let Some(field) = row.issue.field {
                            ui.label(format!(
                                "{}. {}",
                                field + 1,
                                row.field_name.as_deref().unwrap_or_default()
                            ));
                        }
                        kit::muted(ui, p, locale.text(&format!("export-code-{code}")));
                        ui.separator();
                    }
                    if self.issues.is_empty() {
                        ui.label(locale.text("export-no-losses"));
                    }
                });
                if self.issues.len() > flow::PAGE_SIZE {
                    layout::grid(ui, "export-issue-pages", 2, 120., 2, M::SM, |ui, index| {
                        let (key, enabled) = if index == 0 {
                            ("export-previous", self.issue_page > 0)
                        } else {
                            ("export-next", end < self.issues.len())
                        };
                        let response = kit::button(
                            ui,
                            p,
                            &locale.text(key),
                            ButtonRole::Secondary,
                            ui.available_width(),
                            enabled,
                        );
                        self.hit(key, &response);
                        if response.clicked() {
                            if index == 0 {
                                self.issue_page -= 1;
                            } else {
                                self.issue_page += 1;
                            }
                        }
                    });
                }
                if let Some(review) = &self.review {
                    if review.losses > 0 {
                        let response = kit::checkbox(
                            ui,
                            &mut self.allow_losses,
                            locale.text("export-allow-losses"),
                        );
                        self.hit("export-allow-losses", &response);
                    }
                    if !self.review.as_ref().unwrap().file.encrypted {
                        let response = kit::checkbox(
                            ui,
                            &mut self.plaintext_ack,
                            locale.text("export-plaintext-ack"),
                        );
                        self.hit("export-plaintext-ack", &response);
                    }
                }
            }
            Stage::Ready | Stage::Saving | Stage::Complete => {
                if let Some(review) = &self.review {
                    ui.label(&review.file.name);
                }
                ui.label(count(locale, "export-bytes", self.bytes));
            }
            Stage::Failed => {
                ui.label(locale.text("export-restart-hint"));
            }
            _ => {
                let label = locale.text(if self.stage == Stage::Loading {
                    "export-reviewing"
                } else {
                    "export-writing"
                });
                if let Some(progress) = self.progress {
                    kit::progress(
                        ui,
                        p,
                        progress.current as f32 / progress.total.max(1) as f32,
                        &label,
                    );
                } else {
                    ui.label(label);
                }
            }
        }
    }
    fn setup(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        if self.formats.is_empty() {
            ui.label(locale.text("export-no-formats"));
            return;
        }
        let label = ui.label(locale.text("export-format"));
        let previous = self.selected_format();
        let format_label = |info: &export::FormatInfo| {
            if info.format == Format::BitwardenEncryptedJson {
                locale.text("import-format-encrypted")
            } else {
                info.label.clone()
            }
        };
        let response = kit::Select::from_id_salt("export-format")
            .selected_text(format_label(&self.formats[self.format]))
            .width(ui.available_width())
            .show_ui(ui, |ui| {
                self.bounds
                    .insert("export-format-options".into(), ui.clip_rect());
                for index in 0..self.formats.len() {
                    let response = ui.selectable_value(
                        &mut self.format,
                        index,
                        format_label(&self.formats[index]),
                    );
                    self.hit(&format!("export-format-{index}"), &response);
                }
            })
            .response
            .labelled_by(label.id);
        self.hit("export-format", &response);
        if previous != self.selected_format() {
            self.organization = false;
            self.csv = CsvState::default();
            self.password.zeroize();
            self.keyfile = None;
            self.use_keyfile = false;
            self.use_password = matches!(
                self.selected_format(),
                Some(Format::Kdbx | Format::BitwardenEncryptedJson)
            );
            self.events.push(Event::ClearKeyfile);
        }
        if matches!(
            self.selected_format(),
            Some(Format::BitwardenJson | Format::BitwardenEncryptedJson)
        ) {
            ui.add_space(M::LG);
            let label = ui.label(locale.text("export-bitwarden-profile"));
            let selected = if self.organization {
                "export-bitwarden-organization"
            } else {
                "export-bitwarden-personal"
            };
            let response = kit::Select::from_id_salt("export-bitwarden-profile")
                .selected_text(locale.text(selected))
                .width(ui.available_width())
                .show_ui(ui, |ui| {
                    for (organization, key) in [
                        (false, "export-bitwarden-personal"),
                        (true, "export-bitwarden-organization"),
                    ] {
                        let response = ui.selectable_value(
                            &mut self.organization,
                            organization,
                            locale.text(key),
                        );
                        self.hit(key, &response);
                    }
                })
                .response
                .labelled_by(label.id);
            self.hit("export-bitwarden-profile", &response);
        }
        ui.add_space(M::LG);
        let all = kit::checkbox(ui, &mut self.all, locale.text("export-all-records"));
        self.hit("export-all-records", &all);
        if !self.all {
            let label = ui.label(locale.text("export-find-record"));
            let response = kit::field_with_id(
                ui,
                ui.make_persistent_id("export-find"),
                &mut self.query,
                false,
                false,
                true,
            )
            .labelled_by(label.id);
            self.hit("export-find", &response);
            self.enter |= response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if response.changed() || self.filtered_rows != self.rows.len() {
                let query = Zeroizing::new(self.query.to_lowercase());
                self.filtered = self
                    .rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| {
                        query.is_empty() || r.title.to_lowercase().contains(query.as_str())
                    })
                    .map(|(i, _)| i)
                    .collect();
                self.filtered_rows = self.rows.len();
            }
            let filtered = std::mem::take(&mut self.filtered);
            egui::ScrollArea::vertical()
                .id_salt("export-record-selection")
                .max_height(180.)
                .show_rows(
                    ui,
                    if ui.ctx().content_rect().width() < 600. {
                        44.
                    } else {
                        24.
                    },
                    filtered.len(),
                    |ui, range| {
                        for index in range.map(|i| filtered[i]) {
                            let mut selected = self.selected.contains(&index);
                            let title = if self.rows[index].title.is_empty() {
                                locale.text("vault-untitled")
                            } else {
                                self.rows[index].title.clone()
                            };
                            let mut label = egui::text::LayoutJob::simple(
                                title,
                                super::fonts::regular(kit::density(ui).body),
                                p.text,
                                (ui.available_width() - 40.).max(1.),
                            );
                            label.wrap.max_rows = 1;
                            let label = ui.fonts_mut(|fonts| fonts.layout_job(label));
                            let response = kit::checkbox(ui, &mut selected, label);
                            self.hit(&format!("export-record-{index}"), &response);
                            if response.changed() {
                                if selected {
                                    self.selected.insert(index);
                                } else {
                                    self.selected.remove(&index);
                                }
                            }
                        }
                    },
                );
            self.filtered = filtered;
            ui.label(count(locale, "export-selected", self.selected.len()));
        }
        if matches!(
            self.selected_format(),
            Some(Format::Kdbx | Format::BitwardenEncryptedJson)
        ) {
            ui.add_space(M::LG);
            let password = kit::checkbox(ui, &mut self.use_password, locale.text("vault-password"));
            self.hit("export-use-password", &password);
            if !self.use_password {
                self.password.zeroize();
            }
            let field = kit::field_with_id(
                ui,
                ui.make_persistent_id("export-password"),
                &mut self.password,
                true,
                false,
                self.use_password,
            )
            .labelled_by(password.id);
            self.hit("export-password", &field);
            self.enter |= field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if self.selected_format() == Some(Format::Kdbx) {
                let keyfile =
                    kit::checkbox(ui, &mut self.use_keyfile, locale.text("import-use-keyfile"));
                self.hit("export-use-keyfile", &keyfile);
                if keyfile.changed() && !self.use_keyfile {
                    self.keyfile = None;
                    self.events.push(Event::ClearKeyfile);
                }
                ui.label(
                    self.keyfile
                        .as_ref()
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| locale.text("import-no-file")),
                );
                let choose = kit::button(
                    ui,
                    p,
                    &locale.text("import-choose-file"),
                    ButtonRole::Secondary,
                    ui.available_width(),
                    self.use_keyfile && !self.waiting,
                );
                self.hit("export-choose-keyfile", &choose);
                if choose.clicked() {
                    self.events.push(Event::ChooseKeyfile);
                }
            }
        }
    }
    fn action(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer, index: usize) {
        let (id, key, event, enabled) = if index == 1 && self.stage == Stage::Review {
            (
                "export-change",
                "export-change",
                Event::Restart,
                !self.waiting,
            )
        } else if index > 0 {
            (
                "export-cancel",
                if self.stage == Stage::Complete {
                    "window-close"
                } else {
                    "vault-cancel"
                },
                Event::Cancel,
                true,
            )
        } else {
            match self.stage {
                Stage::Setup => (
                    "export-review",
                    "export-review",
                    Event::Review,
                    self.configured(),
                ),
                Stage::Review => (
                    "export-generate",
                    "export-generate",
                    Event::Generate,
                    self.can_generate(),
                ),
                Stage::Ready => ("export-save", "vault-save", Event::Save, !self.waiting),
                Stage::Complete | Stage::Failed => (
                    "export-restart",
                    "export-restart",
                    Event::Restart,
                    !self.waiting,
                ),
                _ => ("export-working", "vault-working", Event::Review, false),
            }
        };
        let response = kit::button(
            ui,
            p,
            &locale.text(key),
            if index == 0 {
                ButtonRole::Primary
            } else {
                ButtonRole::Secondary
            },
            ui.available_width(),
            enabled,
        );
        self.hit(id, &response);
        let enter = index == 0
            && enabled
            && !egui::Popup::is_any_open(ui.ctx())
            && (self.enter
                || (ui.memory(|m| m.focused().is_none())
                    && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))));
        if response.clicked() || enter {
            self.events.push(event);
        }
    }
    fn notifications(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        if let Some(error) = self.error {
            let key = match error {
                flow::Error::Changed => "export-changed",
                flow::Error::Export(export::Error::Canceled) => "export-canceled",
                flow::Error::Export(export::Error::Limit | export::Error::Allocation) => {
                    "export-limit"
                }
                flow::Error::Export(export::Error::UnsupportedFormat) => "export-no-formats",
                _ => "export-error",
            };
            ui.colored_label(p.error, locale.text(key));
        }
        if let Some(notice) = self.notice {
            ui.label(locale.text(notice));
        }
        if self.stage == Stage::Setup
            && matches!(
                self.selected_format(),
                Some(Format::BitwardenJson | Format::BitwardenEncryptedJson)
            )
        {
            kit::muted(ui, p, locale.text("export-bitwarden-profile-hint"));
            ui.add_space(M::XS);
        }
        kit::muted(ui, p, locale.text("export-local-hint"));
        if self.review.as_ref().is_some_and(|r| !r.file.encrypted) {
            kit::muted(ui, p, locale.text("export-plaintext-hint"));
        }
    }
}
fn count(locale: &Localizer, key: &str, value: usize) -> String {
    let mut args = fluent_bundle::FluentArgs::new();
    args.set("count", value as f64);
    locale.format(key, &args)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state(stage: Stage) -> State {
        let mut state = State::default();
        state.window.open = true;
        state.stage = stage;
        state.all = true;
        state.formats = vec![export::FormatInfo {
            format: Format::KeepassXml,
            label: "Public test format".into(),
        }];
        state.rows = vec![flow::Row {
            index: 0,
            head: confidex_storage::Head {
                record: [1; 16],
                revision: [2; 32],
            },
            title: "Public record".into(),
            fields: 1,
        }];
        state.review = Some(flow::Review {
            token: [3; 16],
            vault: [4; 16],
            format: Format::KeepassXml,
            file: flow::File {
                name: "public.json".into(),
                media_type: "application/json".into(),
                encrypted: false,
            },
            records: 1,
            losses: 1,
            blocked: 0,
        });
        state.issues = vec![flow::IssueRow {
            issue: export::Issue {
                record: 0,
                field: Some(0),
                severity: export::Severity::Loss,
                code: export::Code::Protection,
            },
            title: "Public record".into(),
            field_name: Some("Public field".into()),
        }];
        state
    }
    #[test]
    fn consent_cannot_override_blockers_and_clear_keeps_operation_counter() {
        let mut state = state(Stage::Review);
        assert!(!state.can_generate());
        state.allow_losses = true;
        assert!(!state.can_generate());
        state.plaintext_ack = true;
        assert!(state.can_generate());
        state.review.as_mut().unwrap().blocked = 1;
        assert!(!state.can_generate());
        state.password.push_str("PUBLIC-PASSWORD");
        assert_eq!(state.next_operation(), 1);
        state.clear();
        assert_eq!(state.next_operation(), 2);
        assert!(state.password.is_empty());
        assert!(state.rows.is_empty());
        assert!(state.issues.is_empty());
    }
    #[test]
    fn forms_keep_actions_then_notifications_inside_wide_and_narrow_windows() {
        for width in [1320., 820., 390.] {
            for stage in [
                Stage::Setup,
                Stage::Review,
                Stage::Loading,
                Stage::Generating,
                Stage::Ready,
                Stage::Saving,
                Stage::Failed,
                Stage::Complete,
            ] {
                let ctx = egui::Context::default();
                kit::setup(&ctx);
                let locale = Localizer::new(1).unwrap();
                let mut state = state(stage);
                state.error = (stage == Stage::Failed).then_some(flow::Error::Changed);
                for frame in 0..3 {
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(width, 1000.),
                            )),
                            ..Default::default()
                        },
                        |ui| state.show_window(ui.ctx(), crate::theme::THEMES[0].colors, &locale),
                    );
                    output.textures_delta.clear();
                    if frame == 2 {
                        let window = state.bounds["export-window"];
                        let content = state.bounds["export-content"];
                        let actions = state.bounds["export-actions"];
                        let notices = state.bounds["export-notifications"];
                        assert!(ctx.content_rect().contains_rect(window));
                        assert!(
                            window.contains_rect(actions),
                            "{width} {stage:?}: {actions:?} outside {window:?}"
                        );
                        assert!(content.bottom() < actions.top());
                        if stage == Stage::Review {
                            for id in ["export-allow-losses", "export-plaintext-ack"] {
                                assert!(state.hits[id].bottom() < actions.top());
                            }
                        }
                        assert!(actions.bottom() < notices.top());
                        assert!(
                            window.contains_rect(notices),
                            "{width} {stage:?}: notices {notices:?} outside {window:?}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn credential_input_is_masked_and_selection_is_explicit() {
        let ctx = egui::Context::default();
        kit::setup(&ctx);
        let mut state = state(Stage::Setup);
        state.all = false;
        state.rows[0].title = "公開".repeat(64);
        state.formats[0].format = Format::Kdbx;
        state.use_password = true;
        state.password.push_str("PUBLIC-MUST-NOT-RENDER");
        assert!(!state.configured());
        state.selected.insert(0);
        assert!(state.configured());
        assert!(
            matches!(state.selection(),flow::Selection::Records(rows) if rows.len()==1 && rows[0].record==[1;16])
        );
        for frame in 0..3 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(390., 1000.),
                    )),
                    ..Default::default()
                },
                |ui| {
                    state.show_window(
                        ui.ctx(),
                        crate::theme::THEMES[0].colors,
                        &Localizer::new(0).unwrap(),
                    )
                },
            );
            output.textures_delta.clear();
            if frame == 2 {
                assert!(state.hits["export-record-0"].height() <= 44.);
            }
            for shape in output.shapes {
                if let egui::Shape::Text(text) = shape.shape {
                    assert!(!text.galley.job.text.contains("PUBLIC-MUST-NOT-RENDER"));
                }
            }
        }
    }

    #[test]
    fn kdbx_requires_a_secret_and_preserves_empty_password_with_keyfile() {
        let mut state = state(Stage::Setup);
        state.formats[0].format = Format::Kdbx;
        state.use_password = true;
        assert!(!state.configured());
        state.password.push_str("public");
        assert!(state.configured());
        state.password.zeroize();
        state.use_keyfile = true;
        assert!(!state.configured());
        state.keyfile = Some(confidex_app::import_flow::File {
            name: "public.key".into(),
            bytes: 32,
        });
        assert!(state.configured());
        state.use_password = false;
        assert!(state.configured());
        state.keyfile.as_mut().unwrap().bytes = 0;
        assert!(!state.configured());
    }
    #[test]
    fn enter_from_password_activates_review_and_secondary_enter_does_not() {
        let ctx = egui::Context::default();
        kit::setup(&ctx);
        let mut state = state(Stage::Setup);
        state.formats[0].format = Format::Kdbx;
        state.use_password = true;
        state.password.push_str("public");
        let locale = Localizer::new(0).unwrap();
        let draw = |state: &mut State, events| {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(1320., 1000.),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| state.show_window(ui.ctx(), crate::theme::THEMES[0].colors, &locale),
            );
            output.textures_delta.clear();
        };
        let click = |state: &mut State, id: &str| {
            for _ in 0..3 {
                draw(state, vec![]);
            }
            let pos = state.hits[id].center();
            for pressed in [true, false] {
                draw(
                    state,
                    vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
        };
        let enter = |state: &mut State| {
            for pressed in [true, false] {
                draw(
                    state,
                    vec![egui::Event::Key {
                        key: egui::Key::Enter,
                        physical_key: None,
                        pressed,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    }],
                );
            }
        };
        click(&mut state, "export-password");
        enter(&mut state);
        assert_eq!(
            state
                .take_events()
                .iter()
                .filter(|e| matches!(e, Event::Review))
                .count(),
            1
        );
        state.all = false;
        state.selected.insert(0);
        click(&mut state, "export-find");
        enter(&mut state);
        let events = state.take_events();
        assert_eq!(
            events.iter().filter(|e| matches!(e, Event::Review)).count(),
            1
        );
        assert!(!events.iter().any(|e| matches!(e, Event::Cancel)));
        state.all = true;
        click(&mut state, "export-cancel");
        state.take_events();
        enter(&mut state);
        let events = state.take_events();
        assert_eq!(
            events.iter().filter(|e| matches!(e, Event::Cancel)).count(),
            1
        );
        assert!(!events.iter().any(|e| matches!(e, Event::Review)));
    }
    #[test]
    fn a_large_loss_report_renders_only_a_bounded_page() {
        let ctx = egui::Context::default();
        kit::setup(&ctx);
        let mut state = state(Stage::Review);
        state.issues = (0..100_000)
            .map(|index| flow::IssueRow {
                issue: export::Issue {
                    record: index / 10,
                    field: Some(index % 10),
                    severity: export::Severity::Loss,
                    code: export::Code::Protection,
                },
                title: format!("Public record {index}"),
                field_name: None,
            })
            .collect();
        state.review.as_mut().unwrap().records = 10_000;
        state.review.as_mut().unwrap().losses = 100_000;
        let locale = Localizer::new(0).unwrap();
        for page in [0, 100_000usize.div_ceil(flow::PAGE_SIZE) - 1] {
            state.issue_page = page;
            for _ in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(1320., 1000.),
                        )),
                        ..Default::default()
                    },
                    |ui| state.show_window(ui.ctx(), crate::theme::THEMES[0].colors, &locale),
                );
                output.textures_delta.clear();
                assert!(
                    output.shapes.len() < 1500,
                    "unbounded report draw: {}",
                    output.shapes.len()
                );
            }
            assert_eq!(state.hits.contains_key("export-previous"), page > 0);
            assert_eq!(state.hits.contains_key("export-next"), page == 0);
        }
    }
}
