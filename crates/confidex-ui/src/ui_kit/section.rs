//! Section actions do not change the caller's fields.
use super::{
    ButtonRole, button,
    field::{Field, Response},
};
use crate::theme::Palette;
use eframe::egui;

pub struct Section<'a> {
    pub header: Field<'a>,
    pub add_label: &'a str,
}
impl Section<'_> {
    pub fn show<R>(
        self,
        ui: &mut egui::Ui,
        p: Palette,
        body: impl FnOnce(&mut egui::Ui) -> R,
    ) -> Response<(R, Option<egui::Response>)> {
        let editing = self.header.editing;
        self.header.show(ui, p, |ui| {
            let inner = body(ui);
            let add = editing.then(|| {
                ui.separator();
                button(
                    ui,
                    p,
                    self.add_label,
                    ButtonRole::Quiet,
                    ui.available_width(),
                    true,
                )
            });
            (inner, add)
        })
    }
}
