use super::*;
#[cfg(test)]
mod tests;

impl VaultApp {
    pub(super) fn apply_pending_tag(&mut self, draft: &mut Draft) -> bool {
        let applied = self.tag_editor.apply(&mut draft.tags);
        if applied {
            self.attachments.invalidate_size();
        }
        applied
    }

    pub(super) fn record_tags(&mut self, ui: &mut egui::Ui, draft: &mut Draft) {
        let output = ui
            .add_enabled_ui(!self.busy, |ui| {
                self.tag_editor.show(
                    ui,
                    THEMES[self.theme].colors,
                    &self.locale,
                    draft.record,
                    &mut draft.tags,
                )
            })
            .inner;
        for (index, rect) in output.geometry.removes.into_iter().enumerate() {
            self.hits.insert(format!("tag-remove-{index}"), rect);
        }
        self.hits.insert("tag-input".into(), output.geometry.input);
        self.bounds.insert("tag-add".into(), output.geometry.add);
        if output.geometry.can_add {
            self.hits.insert("tag-add".into(), output.geometry.add);
        }
        if output.changed {
            self.attachments.invalidate_size();
        }
    }
}
