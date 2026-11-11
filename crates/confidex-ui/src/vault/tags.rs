use super::*;
use confidex_vault::record::{MAX_TAG_BYTES, MAX_TAGS};
#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct State {
    input: String,
    previous_layout: Option<(usize, bool)>,
}
impl State {
    pub(super) fn pending(&self) -> bool {
        !self.input.is_empty()
    }
    pub(super) fn clear(&mut self) {
        self.input.zeroize();
        self.previous_layout = None;
    }
    pub(super) fn problem(&self, tags: &[String]) -> Option<&'static str> {
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
    fn apply(&mut self, tags: &mut Vec<String>) -> bool {
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
impl Drop for State {
    fn drop(&mut self) {
        self.clear();
    }
}

impl VaultApp {
    pub(super) fn apply_pending_tag(&mut self, draft: &mut Draft) -> bool {
        let applied = self.tag_editor.apply(&mut draft.tags);
        if applied {
            self.attachments.invalidate_size();
        }
        applied
    }
    pub(super) fn record_tags(&mut self, ui: &mut egui::Ui, draft: &mut Draft) {
        let p = THEMES[self.theme].colors;
        ui.add_space(Metrics::LG);
        let label = ui.label(self.locale.text("vault-tags"));
        let mut removed = None;
        ui.add_enabled_ui(!self.busy, |ui| {
            if !draft.tags.is_empty() {
                layout::flow(ui, Metrics::SM, |ui| {
                    for (index, tag) in draft.tags.iter().enumerate() {
                        let response = record::removable_tag(
                            ui,
                            p,
                            tag,
                            &self.locale.text("vault-remove-tag"),
                        );
                        self.hits
                            .insert(format!("tag-remove-{index}"), response.rect);
                        if response.clicked() {
                            removed = Some(index);
                        }
                    }
                });
                ui.add_space(Metrics::SM);
            }
            if let Some(index) = removed {
                draft.tags.remove(index).zeroize();
                self.attachments.invalidate_size();
            }
            let layout = (
                draft.tags.len(),
                self.tag_editor.problem(&draft.tags).is_some(),
            );
            let reflowed = self.tag_editor.previous_layout != Some(layout);
            self.tag_editor.previous_layout = Some(layout);
            let input = design::field_with_id(
                ui,
                egui::Id::unique(("record-tag-input", draft.record)),
                &mut self.tag_editor.input,
                false,
                false,
                true,
            )
            .labelled_by(label.id);
            self.hits.insert("tag-input".into(), input.rect);
            let valid = !self.tag_editor.input.trim().is_empty()
                && self.tag_editor.problem(&draft.tags).is_none();
            let mut add = (input.has_focus() || input.lost_focus())
                && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
                && valid;
            layout::grid(ui, "tag-actions", 1, 160., 1, Metrics::SM, |ui, _| {
                let response = design::button(
                    ui,
                    p,
                    &self.locale.text("vault-add-tag"),
                    ButtonRole::Secondary,
                    ui.available_width(),
                    valid,
                );
                self.bounds.insert("tag-add".into(), response.rect);
                if input.has_focus() && (reflowed || input.changed() || input.gained_focus()) {
                    response.scroll_to_me(Some(egui::Align::BOTTOM));
                }
                if valid {
                    self.hits.insert("tag-add".into(), response.rect);
                }
                add |= response.clicked();
            });
            if add && self.apply_pending_tag(draft) {
                input.request_focus();
            }
        });
    }
}
