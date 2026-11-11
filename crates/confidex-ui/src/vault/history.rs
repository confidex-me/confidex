use super::*;
use confidex_app::history::{Cursor, Revision};
use confidex_storage::{Head, RevisionId};

#[derive(Default)]
pub(super) struct State {
    pub record: Option<RecordId>,
    pub head: Option<RevisionId>,
    pub revisions: Vec<Revision>,
    pub next: Option<Cursor>,
    pub loaded: bool,
    pub loading: bool,
    pub error: Option<Error>,
    pub selected: Option<(RevisionId, u64)>,
    pub preview: Option<Draft>,
    pub window: window::State,
    deleted_head: Option<Head>,
    revealed: BTreeSet<(usize, String)>,
}
impl State {
    pub(super) fn preview_deleted(
        &mut self,
        head: Head,
        source: RevisionId,
        epoch: u64,
        opener: &egui::Response,
    ) {
        *self = Self {
            record: Some(head.record),
            deleted_head: Some(head),
            selected: Some((source, epoch)),
            loading: true,
            ..Default::default()
        };
        self.window.open(opener);
    }
    pub fn invalidate(&mut self) {
        self.head = None;
        self.revisions.clear();
        self.next = None;
        self.loaded = false;
        self.error = None;
    }
}
pub(super) fn date(epoch: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(epoch) * 1_000_000)
        .map(|d| {
            format!(
                "{}-{:02}-{:02} {:02}:{:02} UTC",
                d.year(),
                u8::from(d.month()),
                d.day(),
                d.hour(),
                d.minute()
            )
        })
        .unwrap_or_else(|_| "—".into())
}
fn summary(locale: &Localizer, revision: &Revision) -> String {
    if revision.deleted {
        return locale.text("history-deleted");
    }
    if revision.created {
        return locale.text("history-created");
    }
    let c = &revision.changes;
    let mut lines = Vec::new();
    if revision.merged {
        lines.push(locale.text("history-merged"));
    }
    for (key, names) in [
        ("history-added", &c.added),
        ("history-changed", &c.changed),
        ("history-removed", &c.removed),
    ] {
        if !names.is_empty() {
            let fields = names
                .iter()
                .map(|name| {
                    if name.name.is_empty() {
                        field_label(locale, &name.type_name)
                    } else {
                        name.name.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            let mut args = fluent_bundle::FluentArgs::new();
            args.set("fields", fields);
            lines.push(locale.format(key, &args));
        }
    }
    for (changed, key) in [
        (c.title, "history-title"),
        (c.tags, "history-tags"),
        (c.order, "history-order"),
        (c.properties, "history-properties"),
    ] {
        if changed {
            lines.push(locale.text(key));
        }
    }
    if c.omitted {
        lines.push("…".into());
    }
    if lines.is_empty() {
        lines.push(locale.text("history-unchanged"));
    }
    lines.join(" · ")
}
impl VaultApp {
    pub(super) fn history_list(&mut self, ui: &mut egui::Ui, draft: &Draft) {
        if draft.revision.is_none() {
            return;
        }
        if self.history.record != Some(draft.record) {
            self.history = State {
                record: Some(draft.record),
                ..Default::default()
            };
        }
        let mut history = std::mem::take(&mut self.history);
        let p = THEMES[self.theme].colors;
        let mut command = None;
        ui.add_space(Metrics::LG);
        let output = egui::CollapsingHeader::new(self.locale.text("history-heading"))
            .id_salt(("record-history", draft.record))
            .show(ui, |ui| {
                if !history.loaded && !history.loading && history.error.is_none() {
                    history.loading = true;
                    command = Some(Command::History {
                        record: draft.record,
                        cursor: draft
                            .revision
                            .map(|head| app::history::Cursor { head, offset: 0 }),
                    });
                }
                if history.revisions.len() == 1 && history.next.is_none() {
                    design::muted(ui, p, self.locale.text("history-only-version"));
                }
                if !history.revisions.is_empty() {
                    let area = layout::scroll_content(ui, "history-list", 320., |ui| {
                        for (index, revision) in history.revisions.iter().enumerate() {
                            let row = design::card(p).show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    let button = design::icon_button(
                                        ui,
                                        p,
                                        &self.locale.text("history-view"),
                                        Icon::Eye,
                                        !self.busy,
                                    );
                                    self.hits
                                        .insert(format!("history-view-{index}"), button.rect);
                                    if button.clicked() {
                                        history.selected =
                                            Some((revision.revision, revision.epoch));
                                        history.preview = None;
                                        history.revealed.clear();
                                        history.error = None;
                                        history.loading = true;
                                        history.window.open(&button);
                                        command = Some(Command::Historical {
                                            record: draft.record,
                                            revision: revision.revision,
                                        });
                                    }
                                    ui.label(date(revision.epoch));
                                    if Some(revision.revision) == history.head {
                                        record::tag(
                                            ui,
                                            p,
                                            &self.locale.text("history-current"),
                                            record::TagRole::Accent,
                                        );
                                    }
                                    if Some(revision.revision) == draft.revision
                                        && draft.revision != history.head
                                    {
                                        record::tag(
                                            ui,
                                            p,
                                            &self.locale.text("history-open-version"),
                                            record::TagRole::Neutral,
                                        );
                                    }
                                    let (rect, response) = ui.allocate_exact_size(
                                        Vec2::splat(20.),
                                        egui::Sense::hover(),
                                    );
                                    Icon::Check.paint(ui, rect, p.success);
                                    response.on_hover_text(self.locale.text("vault-verified"));
                                });
                                let description = summary(&self.locale, revision);
                                let mut job = egui::text::LayoutJob::simple(
                                    description.clone(),
                                    design::fonts::regular(design::density(ui).body),
                                    p.text_muted,
                                    ui.available_width(),
                                );
                                job.wrap.max_rows = 2;
                                let galley = ui.fonts_mut(|f| f.layout_job(job));
                                ui.add(egui::Label::new(galley)).on_hover_text(description);
                                if revision.changes.ambiguous {
                                    design::muted(ui, p, self.locale.text("history-ambiguous"));
                                }
                            });
                            self.bounds
                                .insert(format!("history-row-{index}"), row.response.rect);
                            ui.add_space(Metrics::SM);
                        }
                    });
                    self.bounds
                        .insert("history-viewport".into(), area.inner_rect);
                }
                if history.loading {
                    design::spinner(ui, p, 24., &self.locale.text("vault-working"));
                }
                if history.error.is_some() {
                    ui.colored_label(
                        p.error,
                        self.locale
                            .text(if history.error == Some(Error::Integrity) {
                                "vault-error-integrity"
                            } else {
                                "history-error"
                            }),
                    );
                    if self.button(ui, "history-retry", "vault-refresh", !self.busy) {
                        history.error = None;
                        history.loading = true;
                        command = Some(Command::History {
                            record: draft.record,
                            cursor: history.next.or_else(|| {
                                draft
                                    .revision
                                    .map(|head| app::history::Cursor { head, offset: 0 })
                            }),
                        });
                    }
                } else if let Some(cursor) = history.next
                    && self.button(
                        ui,
                        "history-more",
                        "vault-more",
                        !history.loading && !self.busy,
                    )
                {
                    history.loading = true;
                    command = Some(Command::History {
                        record: draft.record,
                        cursor: Some(cursor),
                    });
                }
            });
        self.hits
            .insert("history-toggle".into(), output.header_response.rect);
        self.history = history;
        if let Some(command) = command {
            self.request(command, false);
        }
    }
    pub(super) fn history_window(&mut self, ui: &mut egui::Ui) {
        if !self.history.window.open {
            return;
        }
        let mut history = std::mem::take(&mut self.history);
        let p = THEMES[self.theme].colors;
        let title = self.locale.text("history-view");
        let close = self.locale.text("window-close");
        let mut command = None;
        let output = history.window.show(
            ui.ctx(),
            p,
            window::Window {
                id: egui::Id::unique("history-window"),
                title: &title,
                close_label: &close,
                size: Vec2::new(720., 680.),
            },
            |ui| {
                let area = layout::scroll(ui, "history-record-values", false, |ui| {
                    if let Some((_, epoch)) = history.selected {
                        design::muted(ui, p, date(epoch));
                    }
                    if history.loading {
                        design::spinner(ui, p, 24., &self.locale.text("vault-working"));
                        return;
                    }
                    if history.error.is_some() {
                        ui.colored_label(
                            p.error,
                            self.locale
                                .text(if history.error == Some(Error::Integrity) {
                                    "vault-error-integrity"
                                } else {
                                    "history-error"
                                }),
                        );
                        if self.button(ui, "history-view-retry", "vault-refresh", !self.busy)
                            && let (Some(record), Some((revision, _))) =
                                (history.record, history.selected)
                        {
                            history.error = None;
                            history.loading = true;
                            command = Some(if let Some(head) = &history.deleted_head {
                                Command::PreviewDeleted {
                                    head: head.clone(),
                                    source: revision,
                                }
                            } else {
                                Command::Historical { record, revision }
                            });
                        }
                        return;
                    }
                    let Some(draft) = &mut history.preview else {
                        ui.label(self.locale.text("history-deleted"));
                        return;
                    };
                    ui.heading(if draft.title.is_empty() {
                        self.locale.text("vault-untitled")
                    } else {
                        draft.title.clone()
                    });
                    if let (Some(head), Some(source)) = (&history.deleted_head, draft.revision)
                        && self.button(ui, "trash-restore", "vault-trash-restore", !self.busy)
                    {
                        command = Some(Command::RestoreDeleted {
                            head: head.clone(),
                            source,
                            epoch: epoch(),
                        });
                    }
                    layout::flow(ui, Metrics::SM, |ui| {
                        for tag in &draft.tags {
                            record::tag(ui, p, tag, record::TagRole::Neutral);
                        }
                    });
                    let sources = draft.fields.clone();
                    let keys: Vec<_> = (0..sources.len() as u64).collect();
                    for index in 0..=draft.fields.len() {
                        if let Some(sections) = &draft.sections {
                            for section in sections.iter().filter(|section| section.start == index)
                            {
                                ui.add_space(Metrics::MD);
                                ui.label(
                                    RichText::new(if section.name.is_empty() {
                                        self.locale.text("field-section")
                                    } else {
                                        section.name.clone()
                                    })
                                    .strong(),
                                );
                            }
                        }
                        let Some(field) = draft.fields.get_mut(index) else {
                            break;
                        };
                        if !field_visible(field) {
                            continue;
                        }
                        ui.add_space(Metrics::MD);
                        design::card(p).show(ui, |ui| {
                            let kind = field_label(&self.locale, &field.type_name);
                            ui.label(
                                RichText::new(if field.name.is_empty() {
                                    &kind
                                } else {
                                    &field.name
                                })
                                .semibold(),
                            );
                            if !field.name.is_empty() && field.name != kind {
                                record::tag(ui, p, &kind, record::TagRole::Type);
                            }
                            if field.type_name == "wifi-qr/v1" {
                                self.wifi_field(
                                    ui,
                                    egui::Id::unique(("history-wifi", draft.revision, index)),
                                    &mut field.values,
                                    &sources,
                                    &keys,
                                    false,
                                );
                                return;
                            }
                            if field.type_name == "photo/v1" {
                                self.photo_readonly(ui, &format!("history-photo-{index}"), field);
                                return;
                            }
                            if field.type_name == "file/v1" {
                                self.file_readonly(ui, &format!("history-file-{index}"), field);
                                return;
                            }
                            if field.type_name == "card/v1" {
                                self.card_field(
                                    ui,
                                    egui::Id::unique(("history-card", draft.revision, index)),
                                    &sources[index],
                                    &mut field.values,
                                    false,
                                );
                                return;
                            }
                            if field.type_name == "totp/v1" {
                                self.totp_field(
                                    ui,
                                    egui::Id::unique(("history-totp", draft.revision, index)),
                                    &sources[index],
                                    None,
                                );
                                return;
                            }
                            let multiple = field.values.len() > 1;
                            for (key, text) in &mut field.values {
                                if text.is_empty() {
                                    continue;
                                }
                                let label = value_label(&self.locale, key);
                                if multiple {
                                    design::muted(ui, p, label.clone());
                                }
                                let id = egui::Id::unique((
                                    "history-value",
                                    draft.revision,
                                    index,
                                    key.as_str(),
                                ));
                                let mut revealed = history.revealed.contains(&(index, key.clone()));
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
                                let output = value::ValueField {
                                    id,
                                    value: text,
                                    kind: field_kind(&field.type_name, key),
                                    protected: value_protected(
                                        &field.type_name,
                                        field.protected,
                                        key,
                                    ),
                                    editing: false,
                                    enabled: true,
                                    revealed: &mut revealed,
                                    feedback: self.clipboard.state(id),
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
                                if revealed {
                                    history.revealed.insert((index, key.clone()));
                                } else {
                                    history.revealed.remove(&(index, key.clone()));
                                }
                                if let Some(reveal) = &output.reveal {
                                    self.hits.insert(
                                        format!("history-reveal-{index}-{key}"),
                                        reveal.rect,
                                    );
                                }
                                self.hits.insert(
                                    format!("history-copy-{index}-{key}"),
                                    output.copy.rect,
                                );
                                self.bounds.insert(
                                    format!("history-value-{index}-{key}"),
                                    output.viewport,
                                );
                                if output.copy.clicked() {
                                    self.clipboard.request(ui.ctx(), id, text.clone());
                                }
                                self.large_value(
                                    ui,
                                    large_type::Value {
                                        id,
                                        title: &draft.title,
                                        field: &label,
                                        text,
                                    },
                                    &output,
                                );
                                ui.add_space(Metrics::XS);
                            }
                            if field.opaque > 0 {
                                design::muted(ui, p, self.locale.text("vault-opaque-fields"));
                            }
                        });
                    }
                    ui.add_space(Metrics::MD);
                    design::muted(ui, p, self.locale.text("vault-verified"));
                });
                self.bounds
                    .insert("history-view-viewport".into(), area.inner_rect);
            },
        );
        if let Some(output) = output {
            if let Some(close) = output.close {
                self.hits.insert("history-close".into(), close.rect);
            }
            self.bounds.insert("history-window".into(), output.rect);
        }
        if matches!(command, Some(Command::RestoreDeleted { .. })) {
            history.window.close(ui.ctx());
        }
        if !history.window.open {
            self.attachments.clear();
            history.preview = None;
            if !history.loading {
                history.selected = None;
            }
            history.revealed.clear();
            self.large_type.clear();
        }
        self.history = history;
        if let Some(command) = command {
            self.request(command, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};
    #[derive(Clone, Default)]
    struct Host {
        requests: Rc<RefCell<Vec<Request>>>,
        replies: Rc<RefCell<VecDeque<Response>>>,
    }
    impl Runtime for Host {
        fn send(&mut self, request: Request) -> Result<(), Error> {
            self.requests.borrow_mut().push(request);
            Ok(())
        }
        fn receive(&mut self) -> Option<Response> {
            self.replies.borrow_mut().pop_front()
        }
    }
    fn draw(
        ctx: &egui::Context,
        app: &mut VaultApp,
        width: f32,
        events: Vec<egui::Event>,
    ) -> Vec<egui::epaint::ClippedShape> {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(width, 1100.),
                )),
                events,
                ..Default::default()
            },
            |ui| app.show(ui),
        );
        output.textures_delta.clear();
        std::mem::take(&mut output.shapes)
    }
    fn click(ctx: &egui::Context, app: &mut VaultApp, width: f32, id: &str) {
        let pos = app.hits[id].center();
        for pressed in [true, false] {
            draw(
                ctx,
                app,
                width,
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
        draw(ctx, app, width, vec![]);
    }
    fn reply(host: &Host, app: &mut VaultApp, output: Output) {
        host.replies.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Ok(output),
        });
        app.poll();
    }
    fn paints(shapes: &[egui::epaint::ClippedShape], text: &str) -> bool {
        shapes
            .iter()
            .any(|s| matches!(&s.shape,egui::Shape::Text(t) if t.galley.job.text.contains(text)))
    }
    #[test]
    fn history_is_lazy_and_modal_reveal_does_not_replace_or_cancel_the_editor() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let host = Host::default();
            let mut app = VaultApp::new(&ctx, Box::new(host.clone())).unwrap();
            ctx.all_styles_mut(|s| s.animation_time = 0.);
            app.busy = false;
            app.screen = Screen::Open;
            app.editing = true;
            app.mobile_detail = true;
            let mut draft = app::new_record().unwrap();
            draft.record = [8; 16];
            draft.revision = Some([2; 32]);
            draft.title = "Public unsaved title".into();
            let mut password = app::field("password/v1").unwrap();
            password.name = "password".into();
            password
                .values
                .insert("password".into(), "Public current sentinel".into());
            draft.fields.push(password);
            app.draft = Some(draft.clone());
            app.latest_revision = draft.revision;
            app.field_ids = vec![44];
            app.revealed.insert((44, "password".into()));
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(
                !host
                    .requests
                    .borrow()
                    .iter()
                    .any(|r| matches!(r.command, Command::History { .. }))
            );
            click(&ctx, &mut app, width, "history-toggle");
            assert!(matches!(
                host.requests.borrow().last().unwrap().command,
                Command::History {
                    cursor: Some(_),
                    ..
                }
            ));
            reply(
                &host,
                &mut app,
                Output::History(app::history::Page {
                    record: [8; 16],
                    head: [2; 32],
                    revisions: vec![app::history::Revision {
                        revision: [1; 32],
                        epoch: 1,
                        created: true,
                        deleted: false,
                        merged: false,
                        changes: app::history::Changes::default(),
                    }],
                    next: None,
                }),
            );
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "history-view-0");
            assert!(app.history.window.open && app.history.loading);
            let mut past = draft.clone();
            past.revision = Some([1; 32]);
            past.title = "Public historical title".into();
            past.fields[0].values.insert(
                "password".into(),
                "Public historical secret sentinel".into(),
            );
            let mut note = app::field("secure-note/v1").unwrap();
            note.values
                .insert("text".into(), "Public historical note sentinel".into());
            past.fields.push(note);
            past.sections = Some(vec![
                app::sections::Section::new("Public group", 0, 2),
                app::sections::Section::new("Public empty group", 2, 0),
            ]);
            reply(
                &host,
                &mut app,
                Output::Historical {
                    record: [8; 16],
                    revision: [1; 32],
                    epoch: 1,
                    draft: Some(past.clone()),
                },
            );
            let mut shapes = Vec::new();
            for _ in 0..3 {
                shapes = draw(&ctx, &mut app, width, vec![]);
            }
            assert!(!paints(&shapes, "Public historical secret sentinel"));
            assert!(!paints(&shapes, "Public historical note sentinel"));
            assert!(paints(&shapes, "Public historical title"));
            assert!(paints(&shapes, "Public group"));
            assert!(paints(&shapes, "Public empty group"));
            assert!(
                app.editing
                    && app.mobile_detail
                    && app.draft.as_ref().unwrap().title == "Public unsaved title"
            );
            let modal = app.bounds["history-window"];
            assert!(
                ctx.content_rect().expand(1.).contains_rect(modal),
                "{width}: {modal:?}"
            );
            click(&ctx, &mut app, width, "history-reveal-0-password");
            assert!(paints(
                &draw(&ctx, &mut app, width, vec![]),
                "Public historical secret sentinel"
            ));
            click(&ctx, &mut app, width, "history-close");
            assert!(app.history.preview.is_none() && app.history.revealed.is_empty());
            assert!(
                app.editing
                    && app.field_ids == [44]
                    && app.revealed.contains(&(44, "password".into()))
            );
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "history-view-0");
            draw(
                &ctx,
                &mut app,
                width,
                vec![egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            );
            assert!(!app.history.window.open && app.editing);
            reply(
                &host,
                &mut app,
                Output::Historical {
                    record: [8; 16],
                    revision: [1; 32],
                    epoch: 1,
                    draft: Some(past),
                },
            );
            assert!(app.history.preview.is_none() && !app.history.loading);
            assert_eq!(app.draft.as_ref().unwrap().title, "Public unsaved title");
            app.request(Command::Lock, true);
            assert!(
                app.history.record.is_none()
                    && app.history.revisions.is_empty()
                    && app.draft.is_none()
            );
        }
    }
}
