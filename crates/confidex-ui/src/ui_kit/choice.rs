//! Callers supply stable values and localized captions.
use super::{Icon, Select, icon_button};
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect};
use std::collections::BTreeMap;

pub struct Labels<'a> {
    pub name: &'a str,
    pub empty: &'a str,
    pub copy: &'a str,
}
pub struct Field<'a> {
    pub id: Id,
    pub value: &'a mut String,
    pub options: &'a [(&'a str, &'a str)],
    pub editing: bool,
    pub labels: Labels<'a>,
}
pub struct Output {
    pub changed: bool,
    pub copy: bool,
    pub hits: BTreeMap<String, Rect>,
}
impl Field<'_> {
    pub fn show(self, ui: &mut egui::Ui, p: Palette) -> Output {
        let before = self.value.clone();
        let mut hits = BTreeMap::new();
        let caption = if self.value.is_empty() {
            self.labels.empty
        } else {
            self.options
                .iter()
                .find(|(value, _)| *value == self.value)
                .map_or(self.value.as_str(), |(_, label)| *label)
        }
        .to_owned();
        let copy = ui
            .horizontal(|ui| {
                let width =
                    (ui.available_width() - super::density(ui).icon - super::Metrics::SM).max(1.);
                if self.editing {
                    let menu = Select::from_id_salt(self.id)
                        .selected_text(&caption)
                        .width(width)
                        .show_ui(ui, |ui| {
                            let empty =
                                ui.selectable_label(self.value.is_empty(), self.labels.empty);
                            hits.insert("empty".into(), empty.rect);
                            if empty.clicked() {
                                self.value.clear();
                                ui.close();
                            }
                            for (index, (value, caption)) in self.options.iter().enumerate() {
                                let item =
                                    ui.selectable_label(self.value.as_str() == *value, *caption);
                                hits.insert(format!("option-{index}"), item.rect);
                                if item.clicked() {
                                    *self.value = (*value).into();
                                    ui.close();
                                }
                            }
                        });
                    let response = menu.response;
                    ui.ctx().accesskit_node_builder(response.id, |node| {
                        node.set_label(self.labels.name)
                    });
                    hits.insert("input".into(), response.rect);
                } else {
                    ui.allocate_ui_with_layout(
                        egui::vec2(width, super::density(ui).input),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| ui.add(egui::Label::new(caption).truncate()),
                    );
                }
                icon_button(ui, p, self.labels.copy, Icon::Copy, !self.value.is_empty())
            })
            .inner;
        hits.insert("copy".into(), copy.rect);
        Output {
            changed: before != *self.value,
            copy: copy.clicked(),
            hits,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_values_survive_rendering_and_localized_option_changes() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let mut value = "future-value".to_owned();
        for editing in [false, true] {
            let mut frame = ctx.run_ui(Default::default(), |ui| {
                let output = Field {
                    id: Id::unique("choice-test"),
                    value: &mut value,
                    options: &[("one", "Один")],
                    editing,
                    labels: Labels {
                        name: "Choice",
                        empty: "Empty",
                        copy: "Copy",
                    },
                }
                .show(ui, crate::theme::THEMES[0].colors);
                assert!(!output.changed);
            });
            frame.textures_delta.clear();
            assert_eq!(value, "future-value");
        }
    }
}
