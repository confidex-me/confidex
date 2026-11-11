//! Grouped form rows. Controls and application state belong to the caller.
use super::{Metrics as M, fonts};
use crate::theme::Palette;
use eframe::egui::{self, Rect, RichText, Vec2};

pub fn switch(
    ui: &mut egui::Ui,
    p: Palette,
    value: &mut bool,
    label: &str,
    enabled: bool,
) -> egui::Response {
    ui.add_enabled_ui(enabled, |ui| {
        let d = super::density(ui);
        let (rect, mut response) =
            ui.allocate_exact_size(Vec2::new(M::SWITCH_WIDTH, d.control), egui::Sense::click());
        if response.clicked() {
            *value = !*value;
            response.mark_changed();
            response.request_focus();
        }
        response.widget_info(|| {
            egui::WidgetInfo::selected(egui::Role::CheckBox, enabled, *value, label)
        });
        let size = if d.control >= 44. {
            Vec2::new(44., 26.)
        } else {
            Vec2::new(36., 22.)
        };
        let track = Rect::from_center_size(rect.center(), size);
        ui.painter().rect(
            track,
            size.y / 2.,
            if *value {
                p.accent
            } else if response.hovered() {
                p.hover
            } else {
                p.control
            },
            egui::Stroke::new(1., p.border),
            egui::StrokeKind::Inside,
        );
        let x = if *value {
            track.right() - size.y / 2.
        } else {
            track.left() + size.y / 2.
        };
        ui.painter().circle_filled(
            egui::pos2(x, track.center().y),
            size.y / 2. - 4.,
            if *value { p.on_accent } else { p.text_muted },
        );
        super::focus_ring(ui, response.rect, response.has_focus(), p.accent);
        response
    })
    .inner
}

pub struct Row<'a> {
    pub title: &'a str,
    pub description: &'a str,
    pub control_width: f32,
}
pub struct RowOutput<R> {
    pub row: Rect,
    pub label: Rect,
    pub control: Rect,
    pub stacked: bool,
    pub inner: R,
}
pub struct Group<'a> {
    ui: &'a mut egui::Ui,
    palette: Palette,
    first: bool,
}

pub fn group<R>(
    ui: &mut egui::Ui,
    p: Palette,
    title: &str,
    body: impl FnOnce(&mut Group<'_>) -> R,
) -> egui::InnerResponse<R> {
    ui.label(
        RichText::new(title)
            .font(fonts::semibold(M::LABEL))
            .color(p.text_muted),
    );
    ui.add_space(M::XS);
    super::card(p).inner_margin(0.).show(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 0.;
        body(&mut Group {
            ui,
            palette: p,
            first: true,
        })
    })
}
impl Group<'_> {
    pub fn row<R>(
        &mut self,
        row: Row<'_>,
        control: impl FnOnce(&mut egui::Ui, egui::Id) -> R,
    ) -> RowOutput<R> {
        let ui = &mut self.ui;
        let d = super::density(ui);
        let p = self.palette;
        if !self.first {
            ui.painter().hline(
                ui.available_rect_before_wrap().x_range(),
                ui.cursor().top(),
                egui::Stroke::new(1., p.border),
            );
        }
        self.first = false;
        let content_width = (ui.available_width() - 2. * M::LG).max(1.);
        let control_width = row.control_width.min(content_width);
        let min_label_width = if row.description.is_empty() {
            96.
        } else {
            240.
        };
        let stacked = content_width - control_width - M::LG < min_label_width;
        let label_width = if stacked {
            content_width
        } else {
            content_width - control_width - M::LG
        };
        let title = ui.fonts_mut(|fonts| {
            fonts.layout(
                row.title.to_owned(),
                fonts::medium(d.body),
                p.text,
                label_width,
            )
        });
        let description = ui.fonts_mut(|fonts| {
            fonts.layout(
                row.description.to_owned(),
                fonts::regular(M::LABEL),
                p.text_muted,
                label_width,
            )
        });
        let text_height = title.size().y
            + if row.description.is_empty() {
                0.
            } else {
                M::XS + description.size().y
            };
        let vertical_padding = if row.description.is_empty() && control_width <= M::SWITCH_WIDTH {
            M::SM
        } else {
            if d.body >= 15. { M::LG } else { M::MD }
        };
        let height = 2. * vertical_padding
            + if stacked {
                text_height + M::MD + d.control
            } else {
                text_height.max(d.control)
            };
        let (rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), height),
            egui::Sense::hover(),
        );
        let content = rect.shrink2(Vec2::new(M::LG, vertical_padding));
        let label = Rect::from_min_size(
            egui::pos2(
                content.left(),
                if stacked {
                    content.top()
                } else {
                    content.center().y - text_height / 2.
                },
            ),
            Vec2::new(label_width, text_height),
        );
        let mut text_ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(label)
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        text_ui.spacing_mut().item_spacing.y = M::XS;
        let label_id = text_ui
            .add(egui::Label::new(RichText::new(row.title).font(fonts::medium(d.body))).wrap())
            .id;
        if !row.description.is_empty() {
            text_ui.add(
                egui::Label::new(
                    RichText::new(row.description)
                        .font(fonts::regular(M::LABEL))
                        .color(p.text_muted),
                )
                .wrap(),
            );
        }
        let control_rect = if stacked {
            Rect::from_min_size(
                egui::pos2(content.left(), label.bottom() + M::MD),
                Vec2::new(content_width, d.control),
            )
        } else {
            Rect::from_center_size(
                egui::pos2(content.right() - control_width / 2., content.center().y),
                Vec2::new(control_width, d.control),
            )
        };
        let mut child = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(control_rect)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let inner = control(&mut child, label_id);
        RowOutput {
            row: rect,
            label,
            control: control_rect,
            stacked,
            inner,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn switch_supports_pointer_and_keyboard_and_ignores_disabled_input() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let mut value = false;
        let mut draw = |enabled, events| {
            let mut response = None;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    response = Some(switch(
                        ui,
                        crate::theme::THEMES[0].colors,
                        &mut value,
                        "Lock",
                        enabled,
                    ));
                },
            );
            output.textures_delta.clear();
            response.unwrap()
        };
        let response = draw(true, vec![]);
        let pos = response.rect.center();
        for pressed in [true, false] {
            draw(
                true,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        let response = draw(
            true,
            vec![egui::Event::Key {
                key: egui::Key::Space,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
        assert!(response.changed());
        for pressed in [true, false] {
            let response = draw(
                false,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
            assert!(!response.changed());
        }
        assert!(!value);
    }
    #[test]
    fn form_rows_wrap_labels_and_keep_controls_inside_the_group() {
        for width in [260., 320., 358., 390., 560., 800.] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            let p = crate::theme::THEMES[0].colors;
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                ui.set_width(width);
                let mut rows = Vec::new();
                let group = group(ui, p, "SECURITY", |group| {
                    rows.push(group.row(Row {
                        title: "Lock all open vaults after inactivity",
                        description: "A long description that must wrap without covering the choice or changing its value.",
                        control_width: 132.,
                    }, |ui, label| super::super::button(ui, p, "5 minutes", super::super::ButtonRole::Secondary, 132., true).labelled_by(label)));
                    rows.push(group.row(Row { title: "Lock when the screen locks", description: "", control_width: 52. },
                        |ui, label| switch(ui, p, &mut true, "Lock", true).labelled_by(label)));
                });
                assert_eq!(rows[0].stacked, width < 440.);
                assert!(!rows[1].stacked);
                for row in rows {
                    assert!(group.response.rect.contains_rect(row.row));
                    assert!(row.row.contains_rect(row.label));
                    assert!(row.row.contains_rect(row.control));
                    assert!(row.control.contains_rect(row.inner.rect));
                    assert!(!row.label.intersects(row.control));
                }
                assert!((group.response.rect.width() - width).abs() < 0.1);
            });
            output.textures_delta.clear();
        }
    }
}
