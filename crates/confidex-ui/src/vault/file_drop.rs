use super::*;
use crate::ImageRequest;

#[derive(Default)]
pub(super) struct State {
    pub position: Option<egui::Pos2>,
    pub error: Option<(u64, &'static str)>,
}

impl VaultApp {
    pub fn set_file_drop_position(&mut self, position: Option<egui::Pos2>) {
        self.file_drop.position = position;
        self.context.request_repaint();
    }

    pub(super) fn file_drop_hint(&self, ui: &mut egui::Ui, key: u64) {
        let p = THEMES[self.theme].colors;
        if let Some((target, message)) = self.file_drop.error
            && target == key
        {
            ui.colored_label(p.error, self.locale.text(message));
        } else {
            design::muted(ui, p, self.locale.text("field-drop-file"));
        }
    }

    pub(super) fn record_file_drop(
        &mut self,
        ui: &egui::Ui,
        record: RecordId,
        key: u64,
        kind: &str,
        index: usize,
        response: &design::field::Response<()>,
    ) {
        if !matches!(kind, "file/v1" | "photo/v1" | "ssh/v1")
            || !self.editing
            || self.busy
            || !ui.is_enabled()
            || self.shortcuts_blocked
            || self.attachments.busy
            || self.ssh.is_open()
        {
            return;
        }
        let rect = response.rect.intersect(ui.clip_rect());
        if !rect.is_positive() {
            return;
        }
        self.bounds.insert(format!("file-drop-{index}"), rect);
        let position = self
            .file_drop
            .position
            .or_else(|| ui.ctx().pointer_latest_pos());
        let Some(position) = position.filter(|pos| rect.contains(*pos)) else {
            return;
        };
        if ui.ctx().layer_id_at(position) != Some(response.name.layer_id)
            || !ui.input(|input| {
                !input.raw.hovered_files.is_empty() || !input.raw.dropped_files.is_empty()
            })
        {
            return;
        }
        let p = THEMES[self.theme].colors;
        ui.painter().rect_stroke(
            rect.shrink(1.),
            Metrics::FIELD_RADIUS,
            egui::Stroke::new(2., p.accent),
            egui::StrokeKind::Inside,
        );
        let mut files = ui.input_mut(|input| std::mem::take(&mut input.raw.dropped_files));
        if files.is_empty() {
            return;
        }
        if files.len() != 1 {
            self.file_drop.error = Some((key, "field-drop-one"));
            return;
        }
        let file = files.pop().unwrap();
        if kind == "ssh/v1" {
            self.ssh_drop(ui.ctx(), record, key, file);
        } else {
            self.attachment_open(
                ui.ctx(),
                record,
                key,
                ImageRequest::Dropped {
                    file,
                    image: kind == "photo/v1",
                    bytes: crate::MAX_IMAGE_SOURCE_BYTES,
                },
            );
        }
    }
}
