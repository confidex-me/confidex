//! Confirmation owns typography, padding, bounded content and action placement.
use super::{ButtonRole, Metrics as M, fonts, layout};
use crate::theme::Palette;
use eframe::egui::{self, Rect, RichText};
mod form;
pub use form::{Form, FormResponse};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Confirm,
    Cancel,
}
#[derive(Clone, Default)]
struct ReturnFocus(Option<FocusTarget>);
#[derive(Clone, Copy)]
pub(super) struct FocusTarget {
    pub id: egui::Id,
    pub layer: egui::LayerId,
}
pub(super) fn restore_focus_next_pass(ctx: &egui::Context, focus: FocusTarget) {
    let hook_id = egui::Id::unique("confidex-dialog-focus-hook");
    let pending_id = hook_id.with(ctx.viewport_id());
    ctx.data_mut(|data| data.insert_temp(pending_id, ReturnFocus(Some(focus))));
    if !ctx.data(|data| data.get_temp::<bool>(hook_id).unwrap_or(false)) {
        ctx.data_mut(|data| data.insert_temp(hook_id, true));
        ctx.on_begin_pass(
            "confidex-dialog-focus",
            std::sync::Arc::new(move |ui| {
                let pending = hook_id.with(ui.ctx().viewport_id());
                // The previous modal layer can block its opener for one more pass.
                if let Some(ReturnFocus(Some(target))) =
                    ui.ctx().data(|data| data.get_temp::<ReturnFocus>(pending))
                    && ui.memory(|memory| memory.is_above_modal_layer(target.layer))
                {
                    ui.ctx()
                        .data_mut(|data| data.remove::<ReturnFocus>(pending));
                    ui.memory_mut(|memory| memory.request_focus(target.id));
                } else if ui
                    .ctx()
                    .data(|data| data.get_temp::<ReturnFocus>(pending).is_some())
                {
                    ui.ctx().request_repaint();
                }
            }),
        );
    }
    ctx.request_repaint();
}
pub struct Confirmation<'a> {
    pub title: &'a str,
    pub body: &'a str,
    pub confirm: &'a str,
    pub cancel: &'a str,
    pub role: ButtonRole,
}
pub struct Response {
    pub action: Option<Action>,
    pub rect: Rect,
    pub title: Rect,
    pub body: Rect,
    pub cancel: egui::Response,
    pub confirm: egui::Response,
}
impl Confirmation<'_> {
    pub fn show(self, ctx: &egui::Context, p: Palette, id: egui::Id) -> Response {
        self.show_with(ctx, p, id, [true, true], |_| {})
    }
    /// Show extra content. The flags enable Confirm and Cancel, in that order.
    pub fn show_with(
        self,
        ctx: &egui::Context,
        p: Palette,
        id: egui::Id,
        enabled: [bool; 2],
        contents: impl FnOnce(&mut egui::Ui),
    ) -> Response {
        let viewport = ctx.content_rect();
        let padding = if viewport.width() < 400. { 20. } else { M::XL };
        let width = (viewport.width() - 2. * M::LG).min(440.) - 2. * padding - 2.;
        let focus_id = id.with("return-focus");
        let first = ctx.data(|data| data.get_temp::<ReturnFocus>(focus_id).is_none());
        if first {
            let focus = ctx
                .memory(|memory| memory.focused())
                .and_then(|id| ctx.read_response(id))
                .map(|response| FocusTarget {
                    id: response.id,
                    layer: response.layer_id,
                });
            ctx.data_mut(|data| data.insert_temp(focus_id, ReturnFocus(focus)));
        }
        let modal = egui::Modal::new(id)
            .area(egui::Modal::default_area(id).default_size(egui::vec2(
                width + 2. * padding + 2.,
                viewport.height() - 2. * M::LG,
            )))
            .frame(
                egui::Frame::new()
                    .fill(p.surface)
                    .stroke(egui::Stroke::new(1., p.border))
                    .corner_radius(12)
                    .inner_margin(padding)
                    .shadow(ctx.global_style().visuals.window_shadow),
            )
            .show(ctx, |ui| {
                ui.set_width(width);
                let d = super::density(ui);
                ui.spacing_mut().item_spacing = egui::Vec2::splat(M::SM);
                let measure = |text: &str| {
                    ui.fonts_mut(|f| {
                        f.layout_no_wrap(text.to_owned(), fonts::medium(d.body), p.text)
                    })
                    .size()
                    .x + 2. * M::LG
                };
                let action_width = measure(self.confirm).max(measure(self.cancel)).max(88.);
                let stacked = layout::columns(width, action_width, M::SM, 2) == 1;
                let mut parts = (Rect::NOTHING, Rect::NOTHING, None, None);
                Form {
                    id: "confirmation",
                    actions: 2,
                    min_action_width: action_width,
                }
                .show(
                    ui,
                    &mut parts,
                    |parts, ui| {
                        let title = ui
                            .add(
                                egui::Label::new(
                                    RichText::new(self.title)
                                        .font(fonts::semibold(M::DIALOG_TITLE)),
                                )
                                .wrap(),
                            )
                            .rect;
                        ui.add_space(M::XS);
                        let button_height = |text: &str| {
                            let line = ui
                                .fonts_mut(|f| {
                                    f.layout(
                                        text.to_owned(),
                                        fonts::medium(d.body),
                                        p.text,
                                        width - 2. * M::LG,
                                    )
                                })
                                .size()
                                .y;
                            (line + 2. * M::SM).max(d.control)
                        };
                        let actions_height = if stacked {
                            button_height(self.confirm) + button_height(self.cancel) + M::SM
                        } else {
                            d.control
                        };
                        let body_height = (viewport.height()
                            - 2. * M::LG
                            - 2. * padding
                            - 2.
                            - title.height()
                            - M::XS
                            - 2. * M::SM
                            - M::XL
                            - M::MD
                            - actions_height)
                            .max(24.);
                        let area = layout::scroll_content(ui, "dialog-body", body_height, |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(self.body)
                                        .font(fonts::regular(d.body))
                                        .color(p.text_muted),
                                )
                                .wrap(),
                            );
                            contents(ui);
                        });
                        let body = Rect::from_min_size(
                            area.inner_rect.min,
                            egui::vec2(
                                area.inner_rect.width(),
                                area.inner_rect.height().min(area.content_size.y),
                            ),
                        );
                        parts.0 = title;
                        parts.1 = body;
                    },
                    |parts, ui, index| {
                        let response = super::button(
                            ui,
                            p,
                            if index == 0 {
                                self.confirm
                            } else {
                                self.cancel
                            },
                            if index == 0 {
                                self.role
                            } else {
                                ButtonRole::Secondary
                            },
                            ui.available_width(),
                            enabled[index],
                        );
                        if index == 0 {
                            parts.2 = Some(response);
                        } else {
                            if first {
                                response.request_focus();
                            }
                            parts.3 = Some(response);
                        }
                    },
                    |_, _| {},
                );
                (parts.0, parts.1, parts.2.unwrap(), parts.3.unwrap())
            });
        let dismiss = modal.should_close();
        let (title, body, confirm, cancel) = modal.inner;
        let action = if confirm.clicked() {
            Some(Action::Confirm)
        } else if enabled[1] && (cancel.clicked() || dismiss) {
            Some(Action::Cancel)
        } else {
            None
        };
        if action.is_some() {
            let focus = ctx.data_mut(|data| data.remove_temp::<ReturnFocus>(focus_id));
            if let Some(ReturnFocus(Some(id))) = focus {
                restore_focus_next_pass(ctx, id);
            }
        }
        Response {
            action,
            rect: modal.response.rect,
            title,
            body,
            cancel,
            confirm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escape_cancels_and_returns_focus_to_the_opener() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let mut opener = None;
        for frame in 0..6 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800., 600.),
                    )),
                    events: if frame == 3 {
                        vec![egui::Event::Key {
                            key: egui::Key::Escape,
                            physical_key: None,
                            pressed: true,
                            repeat: false,
                            modifiers: Default::default(),
                        }]
                    } else {
                        vec![]
                    },
                    ..Default::default()
                },
                |ui| {
                    let source = ui.button("Open");
                    opener = Some(source.id);
                    if frame == 0 {
                        source.request_focus();
                    }
                    if frame < 4 {
                        let r = Confirmation {
                            title: "Apply changes?",
                            body: "Public fixture only.",
                            confirm: "Apply",
                            cancel: "Cancel",
                            role: ButtonRole::Primary,
                        }
                        .show(
                            ui.ctx(),
                            crate::theme::THEMES[0].colors,
                            egui::Id::unique("focus"),
                        );
                        if frame == 2 {
                            assert!(r.cancel.has_focus());
                        }
                        if frame == 3 {
                            assert_eq!(r.action, Some(Action::Cancel));
                        }
                    }
                },
            );
            output.textures_delta.clear();
        }
        assert_eq!(ctx.memory(|memory| memory.focused()), opener);
    }
    #[test]
    fn dialog_padding_and_actions_fit_the_viewport_with_long_copy() {
        for size in [
            egui::vec2(260., 400.),
            egui::vec2(320., 320.),
            egui::vec2(390., 550.),
            egui::vec2(900., 700.),
        ] {
            for long in [false, true] {
                let ctx = egui::Context::default();
                super::super::setup(&ctx);
                let body = if long {
                    "A longer explanation that must remain readable and scroll inside the dialog. "
                        .repeat(30)
                } else {
                    "Your vault will stay unchanged.".into()
                };
                for frame in 0..3 {
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                            ..Default::default()
                        },
                        |ui| {
                            let r = Confirmation {
                                title: "Apply changes?",
                                body: &body,
                                confirm: if long {
                                    "Save the demonstration changes"
                                } else {
                                    "Apply"
                                },
                                cancel: if long {
                                    "Return to editing the demonstration"
                                } else {
                                    "Cancel"
                                },
                                role: ButtonRole::Primary,
                            }
                            .show(
                                ui.ctx(),
                                crate::theme::THEMES[0].colors,
                                egui::Id::unique("geometry"),
                            );
                            if frame == 2 {
                                assert!(
                                    ui.ctx().content_rect().contains_rect(r.rect),
                                    "{size:?}: {:?} title {:?} body {:?} confirm {:?} cancel {:?}",
                                    r.rect,
                                    r.title,
                                    r.body,
                                    r.confirm.rect,
                                    r.cancel.rect
                                );
                                for rect in [r.title, r.body, r.cancel.rect, r.confirm.rect] {
                                    assert!(
                                        r.rect.contains_rect(rect),
                                        "{rect:?} outside {:?}",
                                        r.rect
                                    );
                                }
                                assert!(r.title.left() - r.rect.left() >= 20.);
                                assert!(
                                    r.body.bottom() + M::LG
                                        <= r.cancel.rect.top().min(r.confirm.rect.top()),
                                    "size={size:?} long={long} body={:?} cancel={:?} confirm={:?}",
                                    r.body,
                                    r.cancel.rect,
                                    r.confirm.rect
                                );
                                assert!(
                                    r.rect.bottom()
                                        - r.cancel.rect.bottom().max(r.confirm.rect.bottom())
                                        >= 20.
                                );
                                assert!(!r.cancel.rect.intersects(r.confirm.rect));
                            }
                        },
                    );
                    output.textures_delta.clear();
                }
            }
        }
    }
}
