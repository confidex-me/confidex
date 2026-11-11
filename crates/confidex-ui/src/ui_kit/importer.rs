//! Import composition. Hosts provide files, backend replies and clipboard access.
use super::{self as kit, ButtonRole, Metrics as M, dialog, fonts, layout, record, value, window};
use crate::{i18n::Localizer, theme::Palette};
use confidex_app::{
    Draft,
    import::{Code, Format, Status},
    import_apply::{Action, Choice, Match, Review, Selection},
    import_flow::{self as flow, Row},
};
use eframe::egui::{self, Rect, RichText, Vec2};
use fluent_bundle::FluentArgs;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};
mod credentials;
mod csv;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Stage {
    #[default]
    Source,
    Unlock,
    Csv,
    Loading,
    Review,
    Progress,
    Complete,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileRequest {
    Records,
    Keyfile,
}
impl FileRequest {
    pub fn limit(self) -> usize {
        match self {
            Self::Records => flow::MAX_FILE_BYTES,
            Self::Keyfile => flow::MAX_KEYFILE_BYTES,
        }
    }
}
pub enum Event {
    ChooseFile,
    ChooseKeyfile,
    ClearKeyfile,
    Review,
    Unlock,
    Request(flow::Command),
    Copy {
        id: egui::Id,
        value: Zeroizing<String>,
    },
    Cancel,
    Done,
}
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Group {
    account: Option<String>,
    vault: Option<String>,
}
impl Drop for Group {
    fn drop(&mut self) {
        self.account.zeroize();
        self.vault.zeroize();
    }
}

#[derive(Default)]
pub struct State {
    pub window: window::State,
    pub stage: Stage,
    pub source: String,
    pub target: String,
    pub file: Option<flow::File>,
    pub format: Option<Format>,
    pub password: Zeroizing<String>,
    pub use_password: bool,
    pub use_keyfile: bool,
    pub keyfile: Option<flow::File>,
    unlock_token: Option<[u8; 16]>,
    pub csv: Option<flow::CsvSetup>,
    csv_profile: Option<String>,
    csv_keep_mapping: bool,
    pub operation: u32,
    pub review: Option<Review>,
    pub rows: Vec<Row>,
    pub preview: Option<Draft>,
    pub selected: Option<usize>,
    pub choices: Vec<Choice>,
    pub progress: Option<flow::Progress>,
    pub report: Option<confidex_app::import_apply::Report>,
    pub error: Option<flow::Error>,
    pub hits: BTreeMap<String, Rect>,
    pub bounds: BTreeMap<String, Rect>,
    pub cancelling: bool,
    pub waiting: bool,
    pub item_ack: bool,
    pub container_ack: bool,
    query: String,
    filtered: Vec<usize>,
    dirty: bool,
    groups: BTreeMap<Group, usize>,
    row_groups: Vec<usize>,
    group: Option<usize>,
    group_ack: bool,
    detail: bool,
    revealed: BTreeSet<usize>,
    candidates: Option<flow::Candidates>,
    candidate_start: usize,
    events: Vec<Event>,
    focus_source: bool,
    source_enter: bool,
    focus_action: bool,
    large: super::large_type::State,
}
impl State {
    pub fn open(&mut self, opener: &egui::Response, target: String) {
        self.clear();
        self.target = target;
        self.focus_source = true;
        self.window.open(opener);
    }
    pub fn clear(&mut self) {
        self.source.zeroize();
        self.target.zeroize();
        self.query.zeroize();
        self.preview = None;
        self.file = None;
        self.format = None;
        self.password.zeroize();
        self.keyfile = None;
        self.use_password = false;
        self.use_keyfile = false;
        self.unlock_token = None;
        self.csv = None;
        self.csv_profile = None;
        self.csv_keep_mapping = false;
        self.rows.clear();
        self.groups.clear();
        self.review = None;
        self.choices.clear();
        self.filtered.clear();
        self.row_groups.clear();
        self.revealed.clear();
        self.large.clear();
        self.candidates = None;
        self.error = None;
        self.report = None;
        self.progress = None;
        self.item_ack = false;
        self.container_ack = false;
        self.group_ack = false;
        self.group = None;
        self.selected = None;
        self.detail = false;
        self.cancelling = false;
        self.waiting = false;
        self.focus_action = false;
        self.events.clear();
        self.stage = Stage::Source;
        self.dirty = true;
    }
    pub fn file_selected(&mut self, file: flow::File) {
        self.csv = None;
        self.keyfile = None;
        self.detail = false;
        self.format = match file
            .name
            .rsplit_once('.')
            .map(|(_, suffix)| suffix.to_ascii_lowercase())
            .as_deref()
        {
            Some("zip") => Some(Format::BitwardenZip),
            Some("1pux") => Some(Format::Onepassword1pux),
            Some("csv") => Some(Format::Csv),
            Some("kdbx") => Some(Format::Kdbx),
            _ => None,
        };
        self.file = Some(file);
        self.error = None;
    }
    pub fn preparing(&mut self, operation: u32) {
        self.operation = operation;
        self.stage = Stage::Loading;
        self.progress = None;
        self.review = None;
        self.preview = None;
        self.rows.clear();
        self.groups.clear();
        self.candidates = None;
        self.large.clear();
        self.error = None;
        self.cancelling = false;
    }
    pub fn unlocking(&mut self, operation: u32) {
        self.operation = operation;
        self.stage = Stage::Loading;
        self.progress = None;
        self.error = None;
    }
    pub fn accept(&mut self, result: Result<flow::Reply, flow::Error>) {
        let reply = match result {
            Ok(reply) => reply,
            Err(error) => {
                if !self.cancelling
                    && self.csv.is_some()
                    && matches!(self.stage, Stage::Csv | Stage::Loading)
                    && (error == flow::Error::InvalidOptions
                        || matches!(error,flow::Error::Parse(error) if error.kind!=confidex_app::import::ErrorKind::Canceled))
                {
                    self.error = Some(error);
                    self.stage = Stage::Csv;
                    return;
                }
                if !self.cancelling
                    && matches!(
                        error,
                        flow::Error::Authentication | flow::Error::InvalidOptions
                    )
                    && self.unlock_token.is_some()
                {
                    self.error = Some(error);
                    self.stage = Stage::Unlock;
                    self.focus_source = true;
                    return;
                }
                self.password.zeroize();
                self.keyfile = None;
                self.unlock_token = None;
                if self.review.is_none() {
                    self.csv = None;
                }
                self.error = if (self.cancelling && error == flow::Error::Authentication)
                    || matches!(
                        error,
                        flow::Error::Apply(confidex_app::import_apply::Error::Canceled)
                    )
                    || matches!(error, flow::Error::Parse(error) if error.kind == confidex_app::import::ErrorKind::Canceled)
                {
                    None
                } else {
                    Some(error)
                };
                self.cancelling = false;
                if self.review.is_some() && self.error.is_some() {
                    self.stage = Stage::Review;
                } else if self.stage != Stage::Review {
                    self.stage = Stage::Source;
                    self.csv = None;
                    self.file = None;
                    self.review = None;
                    self.rows.clear();
                }
                return;
            }
        };
        if self.cancelling
            && matches!(
                &reply,
                flow::Reply::Reviewed { .. }
                    | flow::Reply::PasswordRequired { .. }
                    | flow::Reply::KdbxRequired { .. }
                    | flow::Reply::CsvRequired { .. }
                    | flow::Reply::Rows { .. }
                    | flow::Reply::Preview { .. }
                    | flow::Reply::Candidates { .. }
            )
        {
            return;
        }
        let kdbx_credentials = matches!(&reply, flow::Reply::KdbxRequired { .. });
        match reply {
            flow::Reply::Begun { .. } => (),
            flow::Reply::CsvRequired {
                operation,
                mut setup,
            } if operation == self.operation => {
                if self.csv_keep_mapping
                    && let Some(old) = &self.csv
                    && old.token == setup.token
                    && old.mapping.delimiter == setup.mapping.delimiter
                    && old.mapping.header == setup.mapping.header
                    && old.mapping.columns.len() == setup.mapping.columns.len()
                {
                    setup.mapping = old.mapping.clone();
                } else {
                    self.csv_profile = None;
                }
                self.csv_keep_mapping = false;
                self.file = Some(setup.file.clone());
                self.csv = Some(setup);
                self.stage = Stage::Csv;
                self.error = None;
                self.focus_action = true;
            }
            flow::Reply::PasswordRequired {
                operation,
                token,
                file,
            }
            | flow::Reply::KdbxRequired {
                operation,
                token,
                file,
            } if operation == self.operation => {
                self.format = Some(if kdbx_credentials {
                    Format::Kdbx
                } else {
                    Format::BitwardenEncryptedJson
                });
                self.use_password = true;
                self.use_keyfile = false;
                self.keyfile = None;
                self.unlock_token = Some(token);
                self.file = Some(file);
                self.stage = Stage::Unlock;
                self.focus_source = true;
            }
            flow::Reply::Reviewed {
                operation,
                file,
                review,
            } if operation == self.operation => {
                self.password.zeroize();
                self.keyfile = None;
                self.unlock_token = None;
                let token = review.token;
                self.choices = review
                    .items
                    .iter()
                    .map(|item| Choice {
                        action: if item.matching == Match::New
                            && matches!(item.status, Status::Ready | Status::Review)
                        {
                            Action::Create
                        } else {
                            Action::Skip
                        },
                        reviewed: false,
                    })
                    .collect();
                self.file = Some(file);
                self.review = Some(review);
                self.group = None;
                self.group_ack = false;
                self.query.zeroize();
                self.rows.clear();
                self.groups.clear();
                self.row_groups.clear();
                self.selected = None;
                self.preview = None;
                self.item_ack = false;
                self.container_ack = false;
                self.stage = Stage::Loading;
                self.dirty = true;
                self.events
                    .push(Event::Request(flow::Command::Rows { token, start: 0 }));
            }
            flow::Reply::Rows {
                token,
                start,
                rows,
                next,
            } if self.token() == Some(token) && start == self.rows.len() => {
                for mut row in rows {
                    if row.index != self.rows.len() {
                        self.error = Some(flow::Error::InvalidOptions);
                        return;
                    }
                    let id = self.groups.len();
                    let group = Group {
                        account: row.source_account.take(),
                        vault: row.source_vault.take(),
                    };
                    self.row_groups
                        .push(*self.groups.entry(group).or_insert(id));
                    self.rows.push(row);
                }
                self.dirty = true;
                if let Some(start) = next {
                    self.events
                        .push(Event::Request(flow::Command::Rows { token, start }));
                } else {
                    self.stage = Stage::Review;
                    self.focus_action = true;
                    self.group_ack = self.groups.len() <= 1;
                    if !self.rows.is_empty() {
                        self.select(0);
                    }
                }
            }
            flow::Reply::Preview {
                token,
                index,
                draft,
            } if self.token() == Some(token) && self.selected == Some(index) => {
                self.preview = Some(draft);
                self.revealed.clear();
                if self
                    .review
                    .as_ref()
                    .is_some_and(|review| review.items[index].candidates > 0)
                {
                    self.events.push(Event::Request(flow::Command::Candidates {
                        token,
                        index,
                        after: 0,
                    }));
                }
            }
            flow::Reply::Candidates {
                token,
                index,
                after,
                candidates,
            } if self.token() == Some(token) && self.selected == Some(index) => {
                self.candidates = Some(candidates);
                self.candidate_start = after;
            }
            flow::Reply::Progress {
                operation,
                progress,
            } if operation == self.operation => self.progress = Some(progress),
            flow::Reply::Applied { operation, report } if operation == self.operation => {
                self.csv = None;
                self.stage = Stage::Complete;
                self.focus_action = true;
                self.preview = None;
                self.rows.clear();
                self.groups.clear();
                self.report = Some(report);
                self.cancelling = false;
            }
            flow::Reply::Canceled => {
                self.csv = None;
                self.password.zeroize();
                self.keyfile = None;
                self.unlock_token = None;
                self.cancelling = false;
                if matches!(self.stage, Stage::Loading | Stage::Progress) {
                    self.stage = Stage::Source;
                    self.preview = None;
                    self.file = None;
                    self.rows.clear();
                    self.review = None;
                }
            }
            _ => (),
        }
    }
    pub fn token(&self) -> Option<[u8; 16]> {
        self.review
            .as_ref()
            .map(|review| review.token)
            .or(self.unlock_token)
            .or(self.csv.as_ref().map(|csv| csv.token))
    }
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
    pub fn selection(&self) -> Selection {
        Selection {
            container_reviewed: self.container_ack,
            choices: self
                .choices
                .iter()
                .enumerate()
                .map(|(index, choice)| {
                    let mut choice = choice.clone();
                    if !self.in_group(index) {
                        choice.action = Action::Skip;
                    }
                    choice.reviewed = self.item_ack;
                    choice
                })
                .collect(),
        }
    }
    fn in_group(&self, index: usize) -> bool {
        self.group
            .is_none_or(|group| self.row_groups.get(index) == Some(&group))
    }
    fn selected_count(&self) -> usize {
        self.choices
            .iter()
            .enumerate()
            .filter(|(i, c)| self.in_group(*i) && c.action != Action::Skip)
            .count()
    }
    fn needs_item_ack(&self) -> bool {
        self.review.as_ref().is_some_and(|review| {
            review.items.iter().enumerate().any(|(i, item)| {
                self.in_group(i)
                    && self.choices[i].action != Action::Skip
                    && (item.status == Status::Review || item.matching != Match::New)
            })
        })
    }
    fn can_apply(&self) -> bool {
        self.stage == Stage::Review
            && !self.waiting
            && !self.cancelling
            && self.error.is_none()
            && self.preview.is_some()
            && self.group_ack
            && self.selected_count() > 0
            && self.review.as_ref().is_some_and(|r| {
                !matches!(r.container_status, Status::Blocked | Status::Excluded)
                    && (r.container_status != Status::Review || self.container_ack)
            })
            && (!self.needs_item_ack() || self.item_ack)
    }
    fn select(&mut self, index: usize) {
        self.selected = Some(index);
        self.error = None;
        self.preview = None;
        self.candidates = None;
        self.revealed.clear();
        if let Some(token) = self.token() {
            self.events
                .push(Event::Request(flow::Command::Preview { token, index }));
        }
    }
    pub fn show_window(
        &mut self,
        ctx: &egui::Context,
        p: Palette,
        locale: &Localizer,
        copy: &dyn Fn(egui::Id) -> value::CopyState,
    ) {
        if !self.window.open {
            self.hits.clear();
            self.bounds.clear();
        }
        let mut host = std::mem::take(&mut self.window);
        self.large.begin_frame();
        let open = host.open;
        if let Some(output) = host.show(
            ctx,
            p,
            window::Window {
                id: egui::Id::unique("record-import-window"),
                title: &locale.text("import-title"),
                close_label: &locale.text("window-close"),
                size: Vec2::new(1040., 760.),
            },
            |ui| self.show(ui, p, locale, copy),
        ) {
            self.bounds.insert("import-window".into(), output.rect);
            self.bounds.insert("import-window-body".into(), output.body);
            if let Some(close) = output.close {
                self.hits.insert("import-close".into(), close.rect);
            }
        }
        if open && !host.open {
            self.password.zeroize();
            self.events.push(Event::Cancel);
        }
        self.window = host;
        self.large.end_frame();
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        locale: &Localizer,
        copy: &dyn Fn(egui::Id) -> value::CopyState,
    ) {
        self.hits.clear();
        self.bounds.clear();
        self.source_enter = false;
        let busy = matches!(self.stage, Stage::Loading | Stage::Progress);
        let actions = if self.stage == Stage::Complete || busy {
            1
        } else {
            2
        };
        let columns = layout::columns(ui.available_width(), 200., M::SM, actions).min(2);
        let action_height = kit::density(ui).control * ((actions.div_ceil(columns)) as f32)
            + M::SM * ((actions.div_ceil(columns) - 1) as f32);
        let warnings = self
            .review
            .as_ref()
            .is_some_and(|r| !r.container_diagnostics.is_empty());
        let notice = if self.stage == Stage::Review {
            80. + if warnings { 100. } else { 0. }
                + if self.needs_item_ack() { 56. } else { 0. }
                + if self
                    .review
                    .as_ref()
                    .is_some_and(|r| r.container_status == Status::Review)
                {
                    56.
                } else {
                    0.
                }
        } else if self.stage == Stage::Csv {
            108. + if self.error.is_some() { 56. } else { 0. }
                + if self.csv_valid() { 0. } else { 40. }
        } else {
            72.
        };
        let body_height =
            (ui.available_height() - action_height - notice - 2. * M::LG - M::MD).max(80.);
        let mut sections = None;
        layout::scroll(ui, "import-form-scroll", false, |ui| {
            sections = Some(
                dialog::Form {
                    id: "import-form",
                    actions,
                    min_action_width: 200.,
                }
                .show(
                    ui,
                    self,
                    |state, ui| match state.stage {
                        Stage::Source => state.source_form(ui, p, locale),
                        Stage::Unlock => state.unlock_form(ui, p, locale),
                        Stage::Csv => state.csv_form(ui, p, locale, body_height),
                        Stage::Review => state.review_form(ui, p, locale, copy, body_height),
                        Stage::Loading | Stage::Progress => state.working(ui, p, locale),
                        Stage::Complete => state.complete(ui, p, locale),
                    },
                    |state, ui, index| state.action(ui, p, locale, index),
                    |state, ui| state.notifications(ui, p, locale),
                ),
            );
        });
        let output = sections.unwrap();
        self.bounds.insert("import-content".into(), output.content);
        self.bounds.insert("import-actions".into(), output.actions);
        self.bounds
            .insert("import-notifications".into(), output.notifications);
        if let Some(operation) = self.events.iter().rev().find_map(|event| match event {
            Event::Request(
                flow::Command::ConfigureCsv { operation, .. }
                | flow::Command::PreviewCsv { operation, .. },
            ) => Some(*operation),
            _ => None,
        }) {
            self.preparing(operation);
        }
    }
    fn source_form(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        kit::card(p).show(ui, |ui| {
            kit::muted(ui, p, locale.text("import-destination"));
            ui.label(RichText::new(&self.target).font(fonts::semibold(M::HEADING)));
        });
        ui.add_space(M::LG);
        ui.label(locale.text("import-source-account"));
        let response = kit::field_with_id(
            ui,
            ui.make_persistent_id("import-account"),
            &mut self.source,
            false,
            false,
            true,
        );
        self.hits.insert("import-account".into(), response.rect);
        self.source_enter =
            response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        if self.focus_source {
            response.request_focus();
            self.focus_source = false;
        }
        ui.add_space(M::LG);
        kit::card(p).show(ui, |ui| {
            kit::muted(ui, p, locale.text("import-export-file"));
            ui.add(
                egui::Label::new(
                    self.file
                        .as_ref()
                        .map(|file| file.name.clone())
                        .unwrap_or_else(|| locale.text("import-no-file")),
                )
                .truncate(),
            );
            kit::muted(
                ui,
                p,
                "Bitwarden JSON / ZIP · 1Password 1PUX · KeePass XML / KDBX · CSV".into(),
            );
        });
        ui.add_space(M::LG);
        ui.label(locale.text("import-format"));
        let response = kit::Select::from_id_salt("import-format")
            .selected_text(
                self.format
                    .map(|format| format_name(format, locale))
                    .unwrap_or_else(|| locale.text("import-format-auto")),
            )
            .width(ui.available_width())
            .show_ui(ui, |ui| {
                self.bounds.insert("import-formats".into(), ui.clip_rect());
                let response =
                    ui.selectable_value(&mut self.format, None, locale.text("import-format-auto"));
                if response.clicked() {
                    ui.close();
                }
                self.hits.insert("import-format-auto".into(), response.rect);
                for format in flow::FORMATS {
                    let response = ui.selectable_value(
                        &mut self.format,
                        Some(*format),
                        format_name(*format, locale),
                    );
                    if response.clicked() {
                        ui.close();
                    }
                    self.hits
                        .insert(format!("import-format-{format:?}"), response.rect);
                }
            });
        self.hits
            .insert("import-format".into(), response.response.rect);
    }
    fn unlock_form(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        ui.label(RichText::new(locale.text("import-unlock")).font(fonts::semibold(M::HEADING)));
        if let Some(file) = &self.file {
            kit::muted(ui, p, file.name.clone());
        }
        ui.add_space(M::LG);
        if self.format == Some(Format::Kdbx) {
            self.credentials_form(ui, p, locale);
            return;
        }
        let label = ui.label(locale.text("vault-password"));
        let response = kit::field_with_id(
            ui,
            ui.make_persistent_id("import-password"),
            &mut self.password,
            true,
            false,
            !self.waiting,
        )
        .labelled_by(label.id);
        self.hits.insert("import-password".into(), response.rect);
        self.source_enter =
            response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        if self.focus_source {
            response.request_focus();
            self.focus_source = false;
        }
    }
    fn review_form(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        locale: &Localizer,
        copy: &dyn Fn(egui::Id) -> value::CopyState,
        height: f32,
    ) {
        ui.horizontal_wrapped(|ui| {
            ui.label(count(locale, "import-record-count", self.rows.len()));
            ui.separator();
            ui.label(count(
                locale,
                "import-selected-count",
                self.selected_count(),
            ));
        });
        ui.horizontal_wrapped(|ui| {
            ui.allocate_ui(
                Vec2::new(
                    (ui.available_width() - if self.groups.len() > 1 { 220. } else { 0. })
                        .max(180.),
                    kit::density(ui).input,
                ),
                |ui| {
                    if kit::search_field(ui, p, &mut self.query, &locale.text("import-search"))
                        .changed()
                    {
                        self.dirty = true;
                    }
                    self.hits.insert("import-search".into(), ui.min_rect());
                },
            );
            if self.groups.len() > 1 {
                let text = self
                    .group
                    .and_then(|id| {
                        self.groups
                            .iter()
                            .find(|(_, value)| **value == id)
                            .map(|(key, _)| group_name(key, locale))
                    })
                    .unwrap_or_else(|| {
                        locale.text(if self.group_ack {
                            "import-all-sources"
                        } else {
                            "import-choose-sources"
                        })
                    });
                let response = kit::Select::from_id_salt("import-groups")
                    .selected_text(text)
                    .width(200.)
                    .show_ui(ui, |ui| {
                        let response = ui.selectable_label(
                            self.group.is_none() && self.group_ack,
                            locale.text("import-all-sources"),
                        );
                        self.hits.insert("import-all-sources".into(), response.rect);
                        if response.clicked() {
                            self.group = None;
                            self.group_ack = true;
                            self.item_ack = false;
                            self.dirty = true;
                        }
                        for (group, id) in &self.groups {
                            if ui
                                .selectable_label(
                                    self.group == Some(*id),
                                    group_name(group, locale),
                                )
                                .clicked()
                            {
                                self.group = Some(*id);
                                self.group_ack = true;
                                self.item_ack = false;
                                self.dirty = true;
                            }
                        }
                    });
                self.hits
                    .insert("import-groups".into(), response.response.rect);
            }
        });
        if self.dirty {
            let query = self.query.to_lowercase();
            self.filtered = self
                .rows
                .iter()
                .enumerate()
                .filter(|(i, row)| {
                    self.in_group(*i)
                        && (query.is_empty() || row.title.to_lowercase().contains(&query))
                })
                .map(|(i, _)| i)
                .collect();
            self.dirty = false;
            if self
                .selected
                .is_none_or(|index| !self.filtered.contains(&index))
            {
                if let Some(index) = self.filtered.first().copied() {
                    self.select(index);
                } else {
                    self.selected = None;
                    self.preview = None;
                    self.revealed.clear();
                }
            }
        }
        let wide = ui.available_width() >= 740.;
        let height = (height - 100.).max(80.);
        if wide {
            let left = (ui.available_width() * 0.4).clamp(260., 380.);
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    Vec2::new(left, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| self.list(ui, p, locale, height),
                );
                ui.add_space(M::SM);
                ui.allocate_ui_with_layout(
                    Vec2::new(ui.available_width(), height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| self.details(ui, p, locale, copy, height),
                );
            });
        } else if self.detail {
            if kit::button(
                ui,
                p,
                &locale.text("import-back-to-list"),
                ButtonRole::Quiet,
                ui.available_width(),
                true,
            )
            .clicked()
            {
                self.detail = false;
            }
            self.details(
                ui,
                p,
                locale,
                copy,
                height - kit::density(ui).control - M::SM,
            );
        } else {
            self.list(ui, p, locale, height);
        }
    }
    fn list(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer, height: f32) {
        if self.filtered.is_empty() {
            kit::muted(ui, p, locale.text("vault-no-results"));
        }
        let eligible: Vec<_> = self
            .filtered
            .iter()
            .copied()
            .filter(|i| {
                self.review.as_ref().is_some_and(|r| {
                    r.items[*i].matching == Match::New
                        && matches!(r.items[*i].status, Status::Ready | Status::Review)
                })
            })
            .collect();
        let mut checked = !eligible.is_empty()
            && eligible
                .iter()
                .all(|i| self.choices[*i].action != Action::Skip);
        if kit::checkbox(ui, &mut checked, locale.text("import-select-new")).changed() {
            for i in eligible {
                self.choices[i].action = if checked {
                    Action::Create
                } else {
                    Action::Skip
                };
            }
            self.item_ack = false;
        }
        let area = layout::scroll_rows(
            ui,
            "import-record-list",
            (height - 36.).max(40.),
            64.,
            self.filtered.len(),
            |ui, range| {
                for position in range {
                    let index = self.filtered[position];
                    let title = if self.rows[index].title.is_empty() {
                        locale.text("vault-untitled")
                    } else {
                        self.rows[index].title.clone()
                    };
                    let item = &self.review.as_ref().unwrap().items[index];
                    let status = status_key(item.status, item.matching);
                    let mutable = item.matching == Match::New
                        && matches!(item.status, Status::Ready | Status::Review);
                    let detail = format!(
                        "{} · {}",
                        count(locale, "import-field-count", self.rows[index].fields),
                        locale.text(status)
                    );
                    ui.push_id(index, |ui| {
                        ui.horizontal(|ui| {
                            let mut selected = self.choices[index].action != Action::Skip;
                            ui.add_enabled_ui(mutable, |ui| {
                                let response = kit::checkbox(ui, &mut selected, "");
                                response.widget_info(|| {
                                    egui::WidgetInfo::selected(
                                        egui::Role::CheckBox,
                                        mutable,
                                        selected,
                                        &title,
                                    )
                                });
                                if response.changed() {
                                    self.choices[index].action = if selected {
                                        Action::Create
                                    } else {
                                        Action::Skip
                                    };
                                    self.item_ack = false;
                                }
                            });
                            let response = record::template_choice(
                                ui,
                                p,
                                &title,
                                &detail,
                                kit::Icon::Key,
                                self.selected == Some(index),
                            );
                            self.hits
                                .insert(format!("import-row-{index}"), response.rect);
                            if response.clicked() {
                                self.select(index);
                                self.detail = true;
                            }
                        });
                    });
                }
            },
        );
        self.bounds.insert("import-list".into(), area.inner_rect);
    }
    fn details(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        locale: &Localizer,
        copy: &dyn Fn(egui::Id) -> value::CopyState,
        height: f32,
    ) {
        let area = layout::scroll_content(ui, "import-preview", height, |ui| {
            let Some(index) = self.selected else {
                kit::muted(ui, p, locale.text("import-select-record"));
                return;
            };
            ui.label(
                RichText::new(if self.rows[index].title.is_empty() {
                    locale.text("vault-untitled")
                } else {
                    self.rows[index].title.clone()
                })
                .font(fonts::semibold(M::HEADING)),
            );
            if self.review.as_ref().is_some_and(|r| {
                r.items[index].matching != Match::New
                    && matches!(r.items[index].status, Status::Ready | Status::Review)
            }) {
                kit::card(p).show(ui, |ui| {
                    ui.label(locale.text("import-decision"));
                    for (action, key) in [
                        (Action::Skip, "import-skip"),
                        (Action::Copy, "import-create-copy"),
                    ] {
                        let response = ui.radio_value(
                            &mut self.choices[index].action,
                            action,
                            locale.text(key),
                        );
                        self.hits.insert(key.into(), response.rect);
                        if response.changed() {
                            self.item_ack = false;
                        }
                    }
                    if matches!(
                        self.review.as_ref().unwrap().items[index].matching,
                        Match::Duplicate | Match::Conflict
                    ) && let Some(candidates) = &self.candidates
                    {
                        for (position, candidate) in candidates.items.iter().enumerate() {
                            let label = format!(
                                "{}: {}",
                                locale.text("import-update-existing"),
                                if candidate.title.is_empty() {
                                    locale.text("vault-untitled")
                                } else {
                                    candidate.title.clone()
                                }
                            );
                            let response = ui.radio_value(
                                &mut self.choices[index].action,
                                Action::Update(candidate.state.head.clone()),
                                label,
                            );
                            self.hits
                                .insert(format!("import-update-{position}"), response.rect);
                            if response.changed() {
                                self.item_ack = false;
                            }
                            for (flag, key) in [
                                (candidate.state.deleted, "import-existing-deleted"),
                                (candidate.state.local_changed, "import-existing-changed"),
                                (candidate.state.source_changed, "import-source-changed"),
                            ] {
                                if flag {
                                    kit::muted(ui, p, locale.text(key));
                                }
                            }
                        }
                        for (enabled, after, key) in [
                            (self.candidate_start > 0, 0, "import-first-matches"),
                            (
                                candidates.next.is_some(),
                                candidates.next.unwrap_or(0),
                                "import-more-matches",
                            ),
                        ] {
                            if enabled
                                && kit::button(
                                    ui,
                                    p,
                                    &locale.text(key),
                                    ButtonRole::Secondary,
                                    0.,
                                    true,
                                )
                                .clicked()
                                && let Some(token) = self.review.as_ref().map(|r| r.token)
                            {
                                self.events.push(Event::Request(flow::Command::Candidates {
                                    token,
                                    index,
                                    after,
                                }));
                            }
                        }
                    }
                });
            }
            let mut seen = BTreeSet::new();
            for diagnostic in &self.rows[index].diagnostics {
                let key = diagnostic_key(diagnostic.code);
                if seen.insert(key) {
                    kit::muted(ui, p, locale.text(key));
                }
            }
            let Some(draft) = &mut self.preview else {
                kit::spinner(ui, p, 20., &locale.text("import-loading-preview"));
                return;
            };
            for field_index in 0..=draft.fields.len() {
                if let Some(sections) = &draft.sections {
                    for section in sections
                        .iter()
                        .filter(|section| section.start == field_index)
                    {
                        ui.add_space(M::MD);
                        ui.strong(if section.name.is_empty() {
                            locale.text("field-section")
                        } else {
                            section.name.clone()
                        });
                    }
                }
                let Some(field) = draft.fields.get_mut(field_index) else {
                    break;
                };
                if field.values.values().all(String::is_empty) && field.opaque == 0 {
                    continue;
                }
                kit::card(p).show(ui, |ui| {
                    ui.label(if field.name.is_empty() {
                        locale.text("import-unnamed-field")
                    } else {
                        field.name.clone()
                    });
                    if let Some((key, text)) = field.values.iter_mut().next() {
                        let mut revealed = self.revealed.contains(&field_index);
                        let kind = match field.type_name.as_str() {
                            "ssh/v1" if key == "private_key" => value::Kind::Password,
                            "password/v1" | "secret/v1" => value::Kind::Password,
                            "note/v1" | "secure-note/v1" => value::Kind::Multiline,
                            _ => value::Kind::Text,
                        };
                        let id = ui.make_persistent_id(("import-value", index, field_index));
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
                        .map(|key| locale.text(key));
                        let output = value::ValueField {
                            id,
                            value: text,
                            kind,
                            protected: if field.type_name == "ssh/v1" {
                                key == "private_key"
                            } else {
                                field.protected
                            },
                            editing: false,
                            enabled: true,
                            revealed: &mut revealed,
                            feedback: copy(id),
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
                        }
                        .show(ui, p);
                        self.hits
                            .insert(format!("import-field-{field_index}-copy"), output.copy.rect);
                        if let Some(reveal) = &output.reveal {
                            self.hits
                                .insert(format!("import-field-{field_index}-reveal"), reveal.rect);
                        }
                        if revealed {
                            self.revealed.insert(field_index);
                        } else {
                            self.revealed.remove(&field_index);
                        }
                        if output.copy.clicked() {
                            self.events.push(Event::Copy {
                                id,
                                value: Zeroizing::new(text.clone()),
                            });
                        }
                        if let Some(large) = self.large.show(
                            ui,
                            p,
                            super::large_type::Value {
                                id,
                                title: &draft.title,
                                field: &field.name,
                                text,
                            },
                            output.large.as_ref(),
                            locale,
                            copy(id),
                        ) && large.copy.clicked()
                        {
                            self.events.push(Event::Copy {
                                id,
                                value: Zeroizing::new(text.clone()),
                            });
                        }
                    }
                    if field.opaque > 0 {
                        kit::muted(ui, p, locale.text("import-preview-retained"));
                    }
                });
                ui.add_space(M::SM);
            }
            if !draft.tags.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for tag in &draft.tags {
                        record::tag(ui, p, tag, record::TagRole::Neutral);
                    }
                });
            }
        });
        self.bounds.insert("import-preview".into(), area.inner_rect);
    }
    fn working(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        let phase = self.progress.map(|p| p.phase);
        let key = if self.cancelling {
            "import-canceling"
        } else {
            match phase {
                Some(flow::Phase::Inspect) => "import-inspecting",
                Some(flow::Phase::Parse) => "import-parsing",
                Some(flow::Phase::Seal) => "import-encrypting",
                Some(flow::Phase::Commit) => "import-committing",
                _ => "import-preparing",
            }
        };
        ui.label(RichText::new(locale.text(key)).font(fonts::semibold(M::HEADING)));
        if let Some(file) = &self.file {
            ui.add(egui::Label::new(&file.name).truncate());
        }
        ui.add_space(M::LG);
        let (current, total) = if self.stage == Stage::Loading
            && let Some(review) = &self.review
        {
            (self.rows.len(), review.items.len())
        } else {
            self.progress.map_or((0, 0), |p| (p.current, p.total))
        };
        if total > 0 {
            kit::progress(
                ui,
                p,
                current as f32 / total as f32,
                &format!("{current} / {total}"),
            );
        } else {
            kit::spinner(ui, p, 24., &locale.text(key));
        }
    }
    fn complete(&self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        ui.label(RichText::new(locale.text("import-complete")).font(fonts::semibold(M::HEADING)));
        ui.add_space(M::LG);
        if let Some(report) = self.report {
            layout::grid(ui, "import-result", 3, 80., 3, M::SM, |ui, index| {
                kit::card(p).show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            [report.added, report.updated, report.skipped][index].to_string(),
                        )
                        .font(fonts::semibold(28.)),
                    );
                    kit::muted(
                        ui,
                        p,
                        locale.text(["import-added", "import-updated", "import-skipped"][index]),
                    );
                });
            });
        }
    }
    fn action(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer, index: usize) {
        let (key, role, enabled) = match self.stage {
            Stage::Source => {
                if index == 0 {
                    ("import-choose-file", ButtonRole::Secondary, !self.waiting)
                } else {
                    (
                        "import-review",
                        ButtonRole::Primary,
                        self.file.is_some() && !self.source.trim().is_empty() && !self.waiting,
                    )
                }
            }
            Stage::Review => {
                if index == 0 {
                    ("import-apply", ButtonRole::Primary, self.can_apply())
                } else {
                    (
                        if self.csv.is_some() {
                            "import-csv-edit"
                        } else {
                            "import-back"
                        },
                        ButtonRole::Secondary,
                        true,
                    )
                }
            }
            Stage::Unlock => {
                if index == 0 {
                    (
                        "import-unlock",
                        ButtonRole::Primary,
                        self.credentials_ready() && !self.waiting,
                    )
                } else {
                    ("import-back", ButtonRole::Secondary, !self.waiting)
                }
            }
            Stage::Complete => ("import-done", ButtonRole::Primary, true),
            Stage::Csv => match index {
                0 => (
                    "import-review",
                    ButtonRole::Primary,
                    !self.waiting && self.csv_valid(),
                ),
                _ => ("import-back", ButtonRole::Secondary, !self.waiting),
            },
            _ => (
                "vault-cancel",
                ButtonRole::Secondary,
                !self.cancelling && self.progress.is_none_or(|p| p.phase != flow::Phase::Commit),
            ),
        };
        let response = kit::button(
            ui,
            p,
            &locale.text(key),
            role,
            ui.available_width(),
            enabled,
        );
        if enabled {
            self.hits.insert(key.into(), response.rect);
        }
        let primary = matches!(
            (self.stage, index),
            (Stage::Source, 1)
                | (Stage::Unlock, 0)
                | (Stage::Csv, 0)
                | (Stage::Review, 0)
                | (Stage::Complete, 0)
        );
        let preview_ready = self.stage != Stage::Review
            || self.rows.is_empty()
            || (self.preview.is_some()
                && self.selected.is_some_and(|index| {
                    self.review.as_ref().unwrap().items[index].candidates == 0
                        || self.candidates.is_some()
                }));
        if primary && self.focus_action && !self.waiting && preview_ready {
            if enabled {
                response.request_focus();
            }
            self.focus_action = false;
        }
        let enter = primary
            && enabled
            && !egui::Popup::is_any_open(ui.ctx())
            && (self.source_enter
                || (ui.memory(|m| m.focused().is_none())
                    && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))));
        if response.clicked() || enter {
            match self.stage {
                Stage::Source => self.events.push(if index == 0 {
                    Event::ChooseFile
                } else {
                    Event::Review
                }),
                Stage::Unlock => {
                    if index == 0 {
                        self.events.push(Event::Unlock);
                    } else {
                        self.events.push(Event::Cancel);
                        self.stage = Stage::Source;
                        self.file = None;
                        self.password.zeroize();
                        self.keyfile = None;
                        self.unlock_token = None;
                    }
                }
                Stage::Review => {
                    if index == 0 {
                        if let Some(token) = self.token() {
                            self.stage = Stage::Progress;
                            self.progress = None;
                            self.events.push(Event::Request(flow::Command::Apply {
                                operation: self.operation,
                                token,
                                selection: self.selection(),
                                epoch: 0,
                            }));
                        }
                    } else {
                        if self.csv.is_some() {
                            self.csv_configure(true);
                            return;
                        }
                        self.events.push(Event::Cancel);
                        self.stage = Stage::Source;
                        self.file = None;
                        self.preview = None;
                        self.rows.clear();
                        self.review = None;
                    }
                }
                Stage::Complete => self.events.push(Event::Done),
                Stage::Csv => match index {
                    0 => self.csv_preview(),
                    _ => {
                        self.events.push(Event::Cancel);
                        self.csv = None;
                        self.stage = Stage::Source;
                        self.file = None;
                    }
                },
                _ => {
                    self.password.zeroize();
                    self.cancelling = true;
                    self.events.push(Event::Cancel);
                }
            }
        }
    }
    fn notifications(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        if let Some(error) = self.error {
            ui.label(
                RichText::new(locale.text(
                    if error == flow::Error::Authentication && self.format == Some(Format::Kdbx) {
                        "import-error-credentials"
                    } else {
                        error_key(error)
                    },
                ))
                .color(p.error),
            );
        }
        if self.stage == Stage::Csv && !self.csv_valid() {
            let key = if self.csv.as_ref().is_some_and(|setup| {
                setup
                    .mapping
                    .columns
                    .iter()
                    .any(|column| column.name.len() > 4096)
            }) {
                "import-csv-name-limit"
            } else {
                "import-csv-title-limit"
            };
            kit::muted(ui, p, locale.text(key));
        }
        if self.stage == Stage::Review {
            if self.rows.is_empty() {
                kit::muted(ui, p, locale.text("import-no-records"));
            }
            if let Some(review) = &self.review {
                if !review.container_diagnostics.is_empty() {
                    layout::scroll_content(ui, "import-warnings", 72., |ui| {
                        let mut seen = BTreeSet::new();
                        for diagnostic in &review.container_diagnostics {
                            let text = diagnostic_key(diagnostic.code);
                            if seen.insert(text) {
                                kit::muted(ui, p, locale.text(text));
                            }
                        }
                    });
                }
                if review.container_status == Status::Review {
                    let response = kit::checkbox(
                        ui,
                        &mut self.container_ack,
                        locale.text("import-container-ack"),
                    );
                    self.hits
                        .insert("import-container-ack".into(), response.rect);
                }
            }
            if self.needs_item_ack() {
                let response =
                    kit::checkbox(ui, &mut self.item_ack, locale.text("import-item-ack"));
                self.hits.insert("import-item-ack".into(), response.rect);
            }
            if !self.group_ack {
                kit::muted(ui, p, locale.text("import-choose-sources-hint"));
            }
            kit::muted(ui, p, locale.text("import-review-hint"));
        } else {
            kit::muted(
                ui,
                p,
                locale.text(match self.stage {
                    Stage::Source => "import-source-hint",
                    Stage::Unlock if self.format == Some(Format::Kdbx) => "import-kdbx-hint",
                    Stage::Unlock => "import-password-hint",
                    Stage::Csv => "import-csv-hint",
                    Stage::Complete => "import-export-reminder",
                    _ => "import-working-hint",
                }),
            );
        }
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.source.zeroize();
        self.target.zeroize();
        self.query.zeroize();
    }
}
fn count(locale: &Localizer, key: &str, n: usize) -> String {
    let mut args = FluentArgs::new();
    args.set("count", n as i64);
    locale.format(key, &args)
}
fn format_name(format: Format, locale: &Localizer) -> String {
    match format {
        Format::BitwardenJson => "Bitwarden JSON",
        Format::Onepassword1pux => "1Password 1PUX",
        Format::KeepassXml => "KeePass XML",
        Format::BitwardenZip => "Bitwarden ZIP",
        Format::Csv => "CSV",
        Format::Kdbx => "KDBX",
        Format::BitwardenEncryptedJson => return locale.text("import-format-encrypted"),
    }
    .into()
}
fn group_name(group: &Group, locale: &Localizer) -> String {
    match (&group.account, &group.vault) {
        (Some(account), Some(vault)) => format!("{account} / {vault}"),
        (_, Some(vault)) if vault == "personal" => locale.text("import-personal"),
        (Some(name), _) | (_, Some(name)) => name.clone(),
        _ => locale.text("import-personal"),
    }
}
fn status_key(status: Status, matching: Match) -> &'static str {
    match status {
        Status::Blocked => "import-blocked",
        Status::Excluded => "import-excluded",
        _ => match matching {
            Match::Duplicate => "import-duplicate",
            Match::Conflict | Match::RepeatedSource { .. } | Match::RepeatedContent { .. } => {
                "import-conflict"
            }
            _ if status == Status::Review => "import-needs-review",
            _ => "import-ready",
        },
    }
}
fn diagnostic_key(code: Code) -> &'static str {
    match code {
        Code::SourceDataPreserved | Code::UnknownItemPreserved => "import-warning-preserved",
        Code::NotesProtectedByDefault => "import-warning-notes",
        Code::ProtectedUrlNotIndexed => "import-warning-protected",
        Code::ArchivedExcludedByDefault | Code::RecycleBinExcludedByDefault => {
            "import-warning-excluded"
        }
        Code::UnresolvedFieldReference => "import-warning-reference",
        Code::MissingSourceScope => "import-warning-scope",
        Code::MissingAttachment => "import-warning-attachment",
        Code::UnsupportedEncoding | Code::UnsupportedVersion | Code::UnsupportedFeature => {
            "import-warning-feature"
        }
        Code::SourceGroupsRequireReview => "import-warning-groups",
    }
}
fn error_key(error: flow::Error) -> &'static str {
    match error {
        flow::Error::Unsupported => "import-error-format",
        flow::Error::InvalidOptions => "import-error-options",
        flow::Error::Authentication => "import-error-password",
        flow::Error::AccountRestricted => "import-error-account",
        flow::Error::App(confidex_app::Error::Locked)
        | flow::Error::Apply(confidex_app::import_apply::Error::App(confidex_app::Error::Locked)) => {
            "import-error-locked"
        }
        flow::Error::Parse(error) if error.kind == confidex_app::import::ErrorKind::OwnBackup => {
            "import-error-backup"
        }
        flow::Error::Parse(error) if error.kind == confidex_app::import::ErrorKind::Limit => {
            "import-error-limit"
        }
        flow::Error::Parse(error) if error.kind == confidex_app::import::ErrorKind::KdfLimit => {
            "import-error-kdf-limit"
        }
        flow::Error::Parse(error)
            if error.kind == confidex_app::import::ErrorKind::UnsupportedEncoding =>
        {
            "import-error-encoding"
        }
        flow::Error::Apply(confidex_app::import_apply::Error::Limit) => "import-error-limit",
        _ => "import-error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidex_app::import_apply::Item;
    #[test]
    fn key_derivation_limits_have_a_specific_message() {
        for (kind, key) in [
            (
                confidex_app::import::ErrorKind::KdfLimit,
                "import-error-kdf-limit",
            ),
            (confidex_app::import::ErrorKind::Limit, "import-error-limit"),
        ] {
            assert_eq!(error_key(flow::Error::Parse(kind.into())), key);
        }
    }
    #[test]
    fn password_step_is_masked_retries_with_enter_and_clears_after_cancel() {
        for width in [1320., 820., 390.] {
            let ctx = egui::Context::default();
            kit::setup(&ctx);
            let locale = Localizer::new(0).unwrap();
            let mut state = State::default();
            state.window.open = true;
            state.accept(Ok(flow::Reply::PasswordRequired {
                operation: 0,
                token: [3; 16],
                file: flow::File {
                    name: "public-encrypted.json".into(),
                    bytes: 100,
                },
            }));
            state.password.push_str("public-only-hidden-password");
            let mut events = Vec::new();
            for frame in 0..5 {
                let keys = if frame < 3 {
                    vec![]
                } else {
                    vec![egui::Event::Key {
                        key: egui::Key::Enter,
                        physical_key: None,
                        pressed: frame == 3,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    }]
                };
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 844.),
                        )),
                        events: keys,
                        ..Default::default()
                    },
                    |ui| {
                        state.show_window(
                            ui.ctx(),
                            crate::theme::THEMES[0].colors,
                            &locale,
                            &|_| value::CopyState::Idle,
                        )
                    },
                );
                assert!(!output.shapes.iter().any(|shape|matches!(&shape.shape,egui::Shape::Text(text) if text.galley.job.text.contains("public-only-hidden-password"))));
                output.textures_delta.clear();
                events.extend(state.take_events());
            }
            assert!(events.iter().any(|event| matches!(event, Event::Unlock)));
            state.unlocking(1);
            state.accept(Err(flow::Error::Authentication));
            assert!(state.stage == Stage::Unlock);
            assert_eq!(state.password.as_str(), "public-only-hidden-password");
            assert!(state.file.is_some());
            state.cancelling = true;
            state.accept(Err(flow::Error::Authentication));
            assert!(state.password.is_empty());
            assert!(state.token().is_none());
            assert!(state.error.is_none());
            assert!(state.stage == Stage::Source);
        }
    }
    #[test]
    fn file_suffix_suggestions_reset_when_the_file_changes() {
        let mut state = State::default();
        for (name, expected) in [
            ("public.ZIP", Some(Format::BitwardenZip)),
            ("public.1pux", Some(Format::Onepassword1pux)),
            ("public.json", None),
        ] {
            state.file_selected(flow::File {
                name: name.into(),
                bytes: 1,
            });
            assert_eq!(state.format, expected);
        }
        state.format = Some(Format::BitwardenZip);
        state.clear();
        assert!(state.format.is_none());
    }
    fn reviewed(n: usize) -> State {
        let mut state = State::default();
        state.window.open = true;
        state.accept(Ok(flow::Reply::Reviewed {
            operation: 0,
            file: flow::File {
                name: "public.json".into(),
                bytes: 100,
            },
            review: Review {
                token: [1; 16],
                vault: [2; 16],
                items: (0..n)
                    .map(|_| Item {
                        status: Status::Ready,
                        matching: Match::New,
                        duplicate: None,
                        candidates: 0,
                    })
                    .collect(),
                container_status: Status::Ready,
                container_diagnostics: vec![],
            },
        }));
        state.take_events();
        state.accept(Ok(flow::Reply::Rows {
            token: [1; 16],
            start: 0,
            rows: (0..n)
                .map(|index| Row {
                    index,
                    title: format!("Public account {index:05}"),
                    source_vault: Some("personal".into()),
                    source_account: None,
                    fields: 1,
                    diagnostics: vec![],
                })
                .collect(),
            next: None,
        }));
        state.take_events();
        if n > 0 {
            state.accept(Ok(flow::Reply::Preview {
                token: [1; 16],
                index: 0,
                draft: Draft {
                    record: [0; 16],
                    revision: None,
                    title: "Public".into(),
                    fields: vec![],
                    tags: vec![],
                    sections: None,
                },
            }));
        }
        state
    }
    #[test]
    fn selection_requires_group_warning_and_conflict_consent() {
        let mut state = reviewed(3);
        assert!(state.can_apply());
        let draft = state.preview.take().unwrap();
        assert!(!state.can_apply());
        state.accept(Ok(flow::Reply::Preview {
            token: [1; 16],
            index: 0,
            draft,
        }));
        assert!(state.can_apply());
        state.error = Some(flow::Error::InvalidOptions);
        assert!(!state.can_apply());
        state.error = None;
        state.review.as_mut().unwrap().container_status = Status::Review;
        assert!(!state.can_apply());
        state.container_ack = true;
        assert!(state.can_apply());
        state.review.as_mut().unwrap().items[1].matching = Match::Conflict;
        state.choices[1].action = Action::Copy;
        assert!(!state.can_apply());
        state.item_ack = true;
        assert!(state.can_apply());
        state.row_groups[2] = 1;
        state.group = Some(0);
        assert_eq!(state.selection().choices[2].action, Action::Skip);
        state.group_ack = false;
        assert!(!state.can_apply());
        state.review.as_mut().unwrap().container_status = Status::Blocked;
        state.group_ack = true;
        assert!(!state.can_apply());
    }
    #[test]
    fn cancellation_discards_late_pages_and_keeps_a_committed_result() {
        let mut state = reviewed(3);
        state.stage = Stage::Loading;
        state.cancelling = true;
        state.accept(Ok(flow::Reply::Rows {
            token: [1; 16],
            start: 3,
            rows: vec![],
            next: Some(3),
        }));
        assert!(state.take_events().is_empty());
        assert!(state.stage == Stage::Loading);
        state.accept(Ok(flow::Reply::Canceled));
        assert!(state.stage == Stage::Source);
        state.cancelling = true;
        state.accept(Ok(flow::Reply::Applied {
            operation: 0,
            report: Default::default(),
        }));
        state.accept(Ok(flow::Reply::Canceled));
        assert!(state.stage == Stage::Complete);
    }
    #[test]
    fn another_file_resets_filters_and_multiple_vaults_require_a_choice() {
        let mut state = reviewed(2);
        let mut rows = std::mem::take(&mut state.rows);
        rows[0].source_vault = Some("personal".into());
        rows[1].source_vault = Some("organization".into());
        state.group = Some(99);
        state.query = "old filter".into();
        let mut review = state.review.take().unwrap();
        review.token = [7; 16];
        state.accept(Ok(flow::Reply::Reviewed {
            operation: 0,
            file: flow::File {
                name: "other.json".into(),
                bytes: 10,
            },
            review,
        }));
        assert!(state.group.is_none());
        assert!(state.query.is_empty());
        state.take_events();
        state.accept(Ok(flow::Reply::Rows {
            token: [7; 16],
            start: 0,
            rows,
            next: None,
        }));
        assert_eq!(state.groups.len(), 2);
        assert!(!state.can_apply());
        state.group = Some(1);
        state.group_ack = true;
        let selection = state.selection();
        assert_eq!(selection.choices[0].action, Action::Skip);
        assert_eq!(selection.choices[1].action, Action::Create);
    }
    #[test]
    fn ten_thousand_rows_are_virtual_and_secrets_do_not_paint_until_reveal() {
        for (width, height, locale) in [(1320., 1000., 0), (820., 900., 1), (390., 844., 1)] {
            let ctx = egui::Context::default();
            kit::setup(&ctx);
            let p = crate::theme::THEMES[0].colors;
            let locale = Localizer::new(locale).unwrap();
            let mut state = reviewed(10_000);
            let mut field = confidex_app::field("password/v1").unwrap();
            field.name = "Password".into();
            *field.values.values_mut().next().unwrap() = "public-hidden-needle".into();
            state.preview = Some(Draft {
                record: [0; 16],
                revision: None,
                title: "Public account".into(),
                fields: vec![field],
                tags: vec![],
                sections: None,
            });
            state.detail = true;
            for frame in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, height),
                        )),
                        ..Default::default()
                    },
                    |ui| state.show_window(ui.ctx(), p, &locale, &|_| value::CopyState::Idle),
                );
                assert!(!output.shapes.iter().any(|shape|matches!(&shape.shape,egui::Shape::Text(text) if text.galley.job.text.contains("public-hidden-needle"))));
                output.textures_delta.clear();
                if frame == 2 {
                    assert!(
                        state
                            .hits
                            .keys()
                            .filter(|key| key.starts_with("import-row-"))
                            .count()
                            < 30
                    );
                    assert!(
                        state.bounds["import-actions"].bottom()
                            <= state.bounds["import-window-body"].bottom(),
                        "width {width}: {:?}",
                        state.bounds
                    );
                    assert!(
                        state.bounds["import-actions"].bottom()
                            < state.bounds["import-notifications"].top()
                    );
                }
            }
            state.revealed.insert(0);
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(width, height),
                    )),
                    ..Default::default()
                },
                |ui| state.show_window(ui.ctx(), p, &locale, &|_| value::CopyState::Idle),
            );
            assert!(output.shapes.iter().any(|shape|matches!(&shape.shape,egui::Shape::Text(text) if text.galley.job.text.contains("public-hidden-needle"))));
            output.textures_delta.clear();
        }
    }
    #[test]
    fn enter_reviews_the_source_and_confirms_a_ready_selection() {
        for source in [true, false] {
            let ctx = egui::Context::default();
            kit::setup(&ctx);
            let locale = Localizer::new(0).unwrap();
            let mut state = if source {
                State::default()
            } else {
                reviewed(1)
            };
            state.window.open = true;
            if source {
                state.source = "public-account".into();
                state.file = Some(flow::File {
                    name: "public.json".into(),
                    bytes: 10,
                });
                state.focus_source = true;
            } else {
                state.preview = Some(Draft {
                    record: [0; 16],
                    revision: None,
                    title: "Public".into(),
                    fields: vec![],
                    tags: vec![],
                    sections: None,
                });
            }
            let mut events = Vec::new();
            for frame in 0..5 {
                let keys = if frame < 3 {
                    vec![]
                } else {
                    vec![egui::Event::Key {
                        key: egui::Key::Enter,
                        physical_key: None,
                        pressed: frame == 3,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    }]
                };
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(1320., 900.),
                        )),
                        events: keys,
                        ..Default::default()
                    },
                    |ui| {
                        state.show_window(
                            ui.ctx(),
                            crate::theme::THEMES[0].colors,
                            &locale,
                            &|_| value::CopyState::Idle,
                        )
                    },
                );
                output.textures_delta.clear();
                events.extend(state.take_events());
            }
            if source {
                assert!(events.iter().any(|event| matches!(event, Event::Review)));
            } else {
                assert!(
                    events
                        .iter()
                        .any(|event| matches!(event, Event::Request(flow::Command::Apply { .. })))
                );
            }
            assert!(!events.iter().any(|event| matches!(event, Event::Cancel)));
        }
    }
}
