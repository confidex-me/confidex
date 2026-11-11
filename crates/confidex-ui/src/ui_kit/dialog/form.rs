//! Form sections share one order in modal windows and page cards.
use super::{M, layout};
use eframe::egui::{self, Rect};

pub struct Form<'a> {
    pub id: &'a str,
    pub actions: usize,
    pub min_action_width: f32,
}
pub struct FormResponse {
    pub content: Rect,
    pub actions: Rect,
    pub notifications: Rect,
    pub columns: usize,
}
impl Form<'_> {
    pub fn show<T>(
        self,
        ui: &mut egui::Ui,
        state: &mut T,
        content: impl FnOnce(&mut T, &mut egui::Ui),
        mut action: impl FnMut(&mut T, &mut egui::Ui, usize),
        notifications: impl FnOnce(&mut T, &mut egui::Ui),
    ) -> FormResponse {
        ui.push_id(self.id, |ui| {
            let content = ui.scope(|ui| content(state, ui)).response.rect;
            ui.add_space(M::LG);
            let actions = ui.scope(|ui| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                layout::grid(
                    ui,
                    "actions",
                    self.actions,
                    self.min_action_width,
                    self.actions.min(2),
                    M::SM,
                    |ui, index| action(state, ui, index),
                )
            });
            ui.add_space(M::MD);
            let notifications = ui
                .scope(|ui| {
                    ui.set_min_width(ui.available_width());
                    notifications(state, ui)
                })
                .response
                .rect;
            FormResponse {
                content,
                actions: actions.response.rect,
                notifications,
                columns: actions.inner,
            }
        })
        .inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sections_keep_their_order_and_actions_wrap_without_losing_state() {
        for width in [280., 560.] {
            let ctx = egui::Context::default();
            super::super::super::setup(&ctx);
            let mut state = 0;
            for frame in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 800.),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        let form = Form {
                            id: "fixture",
                            actions: 3,
                            min_action_width: 200.,
                        }
                        .show(
                            ui,
                            &mut state,
                            |state, ui| {
                                *state += 1;
                                ui.label("Public form content");
                            },
                            |state, ui, index| {
                                *state += 1;
                                ui.add_sized(
                                    [ui.available_width(), 32.],
                                    egui::Button::new(format!("Action {index}")),
                                );
                            },
                            |state, ui| {
                                *state += 1;
                                ui.label("Public notification and caption");
                            },
                        );
                        if frame == 2 {
                            assert!(form.content.bottom() < form.actions.top());
                            assert!(form.actions.bottom() < form.notifications.top());
                            assert!((form.notifications.left() - form.actions.left()).abs() < 1.);
                            assert!((form.notifications.right() - form.actions.right()).abs() < 1.);
                            assert_eq!(form.columns, if width < 400. { 1 } else { 2 });
                            assert!(ui.ctx().content_rect().contains_rect(form.actions));
                        }
                    },
                );
                output.textures_delta.clear();
            }
            assert_eq!(state, 15);
        }
    }
    #[test]
    fn one_action_uses_the_whole_form_width() {
        let ctx = egui::Context::default();
        super::super::super::setup(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.set_width(700.);
            let mut button = Rect::NOTHING;
            let response = Form {
                id: "single",
                actions: 1,
                min_action_width: 200.,
            }
            .show(
                ui,
                &mut (),
                |_, ui| {
                    ui.label("Public form");
                },
                |_, ui, _| {
                    button = ui
                        .add_sized([ui.available_width(), 32.], egui::Button::new("Done"))
                        .rect;
                },
                |_, _| {},
            );
            assert_eq!(response.columns, 1);
            assert!((button.width() - 700.).abs() < 1.);
        });
        output.textures_delta.clear();
    }
}
