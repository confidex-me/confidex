use super::*;
#[cfg(test)]
mod tests;

pub(super) fn name_key(name: &str) -> String {
    format!(
        "starter-{}",
        name.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|part| !part.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("-")
    )
}

fn rows(featured: usize, total: usize, width: f32) -> Vec<Vec<usize>> {
    let mut rows = Vec::new();
    for (range, max) in [(0..featured, 3), (featured..total, 2)] {
        let columns = layout::columns(width, 220., Metrics::SM, max);
        let indices: Vec<_> = range.collect();
        rows.extend(indices.chunks(columns).map(<[usize]>::to_vec));
    }
    rows
}
fn next_row(rows: &[Vec<usize>], selected: usize, down: bool) -> usize {
    let row = rows
        .iter()
        .position(|row| row.contains(&selected))
        .unwrap_or(0);
    let column = rows[row].iter().position(|i| *i == selected).unwrap_or(0);
    let next = if down {
        (row + 1) % rows.len()
    } else {
        (row + rows.len() - 1) % rows.len()
    };
    rows[next][column.min(rows[next].len() - 1)]
}
fn icon(id: &str) -> Icon {
    match id {
        "login" | "api-key" | "ssh-key" | "crypto-wallet" | "password" => Icon::Key,
        "secure-note" | "document" | "software-license" | "medical-record" | "note" => Icon::Note,
        "credit-card" | "bank-account" | "rewards" | "membership" => Icon::Card,
        "identity"
        | "driver-license"
        | "passport"
        | "social-security-number"
        | "outdoor-license" => Icon::Identity,
        _ => Icon::Globe,
    }
}

impl VaultApp {
    pub(super) fn template_picker(&mut self, ui: &egui::Ui) {
        if !self.templates.open {
            return;
        }
        let mut window = std::mem::take(&mut self.templates);
        let mut chosen = None;
        let title = self.locale.text("vault-new-record");
        let close = self.locale.text("window-close");
        if let Some(output) = window.show(
            ui.ctx(),
            THEMES[self.theme].colors,
            window::Window {
                id: egui::Id::unique("record-templates"),
                title: &title,
                close_label: &close,
                size: Vec2::new(840., 700.),
            },
            |ui| {
                let p = THEMES[self.theme].colors;
                let search = design::search_field(
                    ui,
                    p,
                    &mut self.template_query,
                    &self.locale.text("vault-search-templates"),
                );
                self.hits.insert("template-search".into(), search.rect);
                let mut scroll_selected = self.template_focus || search.changed();
                if self.template_focus {
                    search.request_focus();
                    self.template_focus = false;
                }
                if search.changed() {
                    self.template_selection = 0;
                }
                let query = self.template_query.trim().to_lowercase();
                let options: Vec<_> = app::templates::ids()
                    .filter(|id| *id != "empty")
                    .filter_map(|kind| {
                        let title = template_label(&self.locale, kind);
                        let fields = app::template(kind).expect("known template");
                        let detail = fields
                            .iter()
                            .enumerate()
                            .map(|(index, field)| {
                                template_field_label(&self.locale, kind, index, field)
                            })
                            .collect::<Vec<_>>()
                            .join(" · ");
                        let text =
                            format!("{title} {detail} {}", kind.replace('-', " ")).to_lowercase();
                        let featured = app::templates::CATALOG[..app::templates::FEATURED]
                            .iter()
                            .any(|t| t.id == kind);
                        query
                            .split_whitespace()
                            .all(|word| text.contains(word))
                            .then_some((kind, title, detail, featured))
                    })
                    .collect();
                let featured = options.iter().take_while(|option| option.3).count();
                if !options.is_empty() {
                    self.template_selection = self.template_selection.min(options.len() - 1);
                    let rows = rows(
                        featured,
                        options.len(),
                        (ui.available_width() - 16.).max(1.),
                    );
                    if search.has_focus() || search.lost_focus() {
                        ui.input_mut(|input| {
                            for (key, down) in
                                [(egui::Key::ArrowDown, true), (egui::Key::ArrowUp, false)]
                            {
                                if input.consume_key(egui::Modifiers::NONE, key) {
                                    self.template_selection =
                                        next_row(&rows, self.template_selection, down);
                                    scroll_selected = true;
                                }
                            }
                            for (key, forward) in
                                [(egui::Key::ArrowRight, true), (egui::Key::ArrowLeft, false)]
                            {
                                if input.consume_key(egui::Modifiers::NONE, key) {
                                    self.template_selection = (self.template_selection
                                        + if forward { 1 } else { options.len() - 1 })
                                        % options.len();
                                    scroll_selected = true;
                                }
                            }
                            if input.consume_key(egui::Modifiers::NONE, egui::Key::Enter) {
                                chosen = Some(options[self.template_selection].0);
                            }
                        });
                    }
                }
                ui.add_space(Metrics::LG);
                let caption = self.locale.text(if options.is_empty() {
                    "template-no-results"
                } else {
                    "template-hint"
                });
                let caption_font = design::fonts::regular(design::density(ui).body);
                let width = ui.available_width();
                let caption =
                    ui.fonts_mut(|fonts| fonts.layout(caption, caption_font, p.text_muted, width));
                let mut hits = Vec::new();
                let mut empty = None;
                let geometry = layout::scroll_panel(
                    ui,
                    p,
                    "template-options",
                    (ui.available_height() - caption.size().y - Metrics::SM).max(1.),
                    |ui| {
                        for (range, columns) in [(0..featured, 3), (featured..options.len(), 2)] {
                            if range.is_empty() {
                                continue;
                            }
                            let start = range.start;
                            layout::grid(
                                ui,
                                &format!("template-grid-{start}"),
                                range.len(),
                                220.,
                                columns,
                                Metrics::SM,
                                |ui, position| {
                                    let index = start + position;
                                    let (kind, title, detail, featured) = &options[index];
                                    let response = ui
                                        .push_id(kind, |ui| {
                                            record::template_tile(
                                                ui,
                                                p,
                                                title,
                                                detail,
                                                icon(kind),
                                                index == self.template_selection,
                                                *featured,
                                            )
                                        })
                                        .inner;
                                    hits.push((format!("template-{kind}"), response.rect));
                                    if response.clicked() {
                                        chosen = Some(*kind);
                                    }
                                    if scroll_selected && index == self.template_selection {
                                        response.scroll_to_me(Some(egui::Align::Center));
                                    }
                                },
                            );
                            ui.add_space(Metrics::LG);
                        }
                    },
                    |ui| {
                        layout::grid(ui, "template-actions", 1, 160., 1, Metrics::SM, |ui, _| {
                            empty = Some(design::button(
                                ui,
                                p,
                                &template_label(&self.locale, "empty"),
                                ButtonRole::Secondary,
                                ui.available_width(),
                                true,
                            ));
                        });
                    },
                );
                if let Some(response) = empty {
                    self.hits.insert("template-empty".into(), response.rect);
                    if response.clicked() {
                        chosen = Some("empty");
                    }
                }
                self.hits.extend(hits);
                self.bounds
                    .insert("template-viewport".into(), geometry.content);
                self.bounds
                    .insert("template-footer".into(), geometry.footer);
                let response = ui.label(caption);
                self.bounds.insert("template-caption".into(), response.rect);
            },
        ) {
            if let Some(close) = output.close {
                self.hits.insert("template-close".into(), close.rect);
            }
            self.bounds.insert("template-window".into(), output.rect);
            self.bounds.insert("template-body".into(), output.body);
        }
        if let Some(kind) = chosen {
            match app::new_record().and_then(|mut draft| {
                draft.fields = app::template(kind)?;
                if kind != "empty" {
                    draft.tags.push(
                        app::templates::get(kind)
                            .map(|template| template.name.to_owned())
                            .unwrap_or_else(|| {
                                template_label(&Localizer::new(0).expect("English catalogue"), kind)
                            }),
                    );
                }
                for (index, field) in draft.fields.iter_mut().enumerate() {
                    field.name = template_field_label(&self.locale, kind, index, field);
                }
                if let Some(template) = app::templates::get(kind) {
                    let mut sections = template.sections();
                    for section in &mut sections {
                        section.name = self.locale.text(&name_key(&section.name));
                    }
                    draft.sections = Some(sections);
                }
                Ok(draft)
            }) {
                Ok(draft) => {
                    self.edit_baseline = None;
                    self.tag_editor.clear();
                    window.clear();
                    self.reset_field_ids(draft.fields.len());
                    self.revealed.clear();
                    self.clipboard.clear();
                    self.history = history::State::default();
                    self.latest_revision = None;
                    self.draft = Some(draft);
                    self.editing = true;
                    self.mobile_detail = true;
                    self.pending_focus = Some(egui::Id::unique("record-title"));
                }
                Err(error) => self.error = Some(error),
            }
        }
        if !window.open {
            self.template_query.zeroize();
        }
        self.templates = window;
    }
}
