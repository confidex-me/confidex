//! Shared record tag editor.
use super::{ButtonRole, Metrics, button, field_with_id, layout, record};
use crate::{i18n::Localizer, theme::Palette};
use confidex_storage::RecordId;
use confidex_vault::record::{MAX_TAG_BYTES, MAX_TAGS};
use eframe::egui;
use zeroize::Zeroize;

#[derive(Default)]
pub struct Editor {
    pub(crate) input: String,
    previous_layout: Option<(usize, bool)>,
}
impl Editor {
    pub fn pending(&self) -> bool {
        !self.input.is_empty()
    }
    pub fn has_pending_tag(&self) -> bool {
        !self.input.trim().is_empty()
    }
    pub fn clear(&mut self) {
        self.input.zeroize();
        self.previous_layout = None;
    }
    pub fn problem(&self, tags: &[String]) -> Option<&'static str> {
        let tag = self.input.trim();
        if tag.is_empty() {
            None
        } else if tag.len() > MAX_TAG_BYTES {
            Some("vault-tag-too-long")
        } else if tags.iter().any(|existing| existing == tag) {
            Some("vault-tag-duplicate")
        } else if tags.len() >= MAX_TAGS {
            Some("vault-tags-full")
        } else {
            None
        }
    }
    pub fn apply(&mut self, tags: &mut Vec<String>) -> bool {
        if self.problem(tags).is_some() {
            return false;
        }
        if !self.input.trim().is_empty() {
            tags.push(self.input.trim().to_owned());
        }
        self.clear();
        true
    }
}
impl Drop for Editor {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) struct Geometry {
    pub removes: Vec<egui::Rect>,
    pub input: egui::Rect,
    pub add: egui::Rect,
    pub can_add: bool,
}

pub struct Output {
    pub changed: bool,
    pub(crate) geometry: Geometry,
}

impl Editor {
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        palette: Palette,
        locale: &Localizer,
        record: RecordId,
        tags: &mut Vec<String>,
    ) -> Output {
        ui.add_space(Metrics::LG);
        let label = ui.label(locale.text("vault-tags"));
        let mut removes = Vec::new();
        let mut removed = None;
        if !tags.is_empty() {
            let remove_label = locale.text("vault-remove-tag");
            layout::flow(ui, Metrics::SM, |ui| {
                for (index, tag) in tags.iter().enumerate() {
                    let response = record::removable_tag(ui, palette, tag, &remove_label);
                    removes.push(response.rect);
                    if response.clicked() {
                        removed = Some(index);
                    }
                }
            });
            ui.add_space(Metrics::SM);
        }
        if let Some(index) = removed {
            tags.remove(index).zeroize();
        }
        let layout = (tags.len(), self.problem(tags).is_some());
        let reflowed = self.previous_layout != Some(layout);
        self.previous_layout = Some(layout);
        let input = field_with_id(
            ui,
            egui::Id::unique(("record-tag-input", record)),
            &mut self.input,
            false,
            false,
            true,
        )
        .labelled_by(label.id);
        let valid = self.has_pending_tag() && self.problem(tags).is_none();
        let enter = (input.has_focus() || input.lost_focus())
            && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
            && valid;
        let mut add = egui::Rect::NOTHING;
        let mut clicked = false;
        layout::grid(ui, "tag-actions", 1, 160., 1, Metrics::SM, |ui, _| {
            let response = button(
                ui,
                palette,
                &locale.text("vault-add-tag"),
                ButtonRole::Secondary,
                ui.available_width(),
                valid,
            );
            add = response.rect;
            if input.has_focus() && (reflowed || input.changed() || input.gained_focus()) {
                response.scroll_to_me(Some(egui::Align::BOTTOM));
            }
            clicked = response.clicked();
        });
        let added = (enter || clicked) && self.apply(tags);
        if added {
            input.request_focus();
        }
        Output {
            changed: added || removed.is_some(),
            geometry: Geometry {
                removes,
                input: input.rect,
                add,
                can_add: valid,
            },
        }
    }
}
