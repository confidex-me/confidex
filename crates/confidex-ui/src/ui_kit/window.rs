//! Hosts share content. The container selects a viewport or a canvas window.
use super::{Icon, Metrics as M, dialog, fonts};
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect, Vec2};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Host {
    Native,
    Floating,
    FullScreen,
}

#[derive(Default)]
pub struct State {
    pub open: bool,
    focus: Option<dialog::FocusTarget>,
    host: Option<Host>,
    raise: bool,
}
pub struct Window<'a> {
    pub id: Id,
    pub title: &'a str,
    pub close_label: &'a str,
    pub size: Vec2,
}
pub struct Output<R> {
    pub inner: R,
    pub rect: Rect,
    pub body: Rect,
    pub header: Rect,
    pub close: Option<egui::Response>,
    pub native: bool,
}
impl State {
    pub fn open(&mut self, opener: &egui::Response) {
        if !self.open {
            self.focus = Some(dialog::FocusTarget {
                id: opener.id,
                layer: opener.layer_id,
            });
            self.host = None;
        }
        self.open = true;
        self.raise = true;
        opener.ctx.request_repaint();
    }
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn close(&mut self, ctx: &egui::Context) {
        if let Some(focus) = self.focus {
            dialog::restore_focus_next_pass(ctx, focus);
        }
        self.clear();
        ctx.request_repaint();
    }
    pub fn show<R>(
        &mut self,
        ctx: &egui::Context,
        p: Palette,
        window: Window<'_>,
        mut content: impl FnMut(&mut egui::Ui) -> R,
    ) -> Option<Output<R>> {
        if !self.open {
            return None;
        }
        let native = !cfg!(target_arch = "wasm32")
            && !ctx.embed_viewports()
            && ctx.content_rect().width() >= 600.;
        let host = if native {
            Host::Native
        } else if ctx.content_rect().width() < 600. {
            Host::FullScreen
        } else {
            Host::Floating
        };
        let first = self.host != Some(host);
        self.host = Some(host);
        let (output, dismissed) = if native {
            let mut dismissed = false;
            let id = egui::ViewportId(window.id);
            if self.raise {
                ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Focus);
            }
            let output = ctx.show_viewport_immediate(
                id,
                egui::ViewportBuilder::default()
                    .with_title(window.title)
                    .with_inner_size(window.size)
                    .with_min_inner_size([280., 220.]),
                |ui, _class| {
                    let popup = egui::Popup::is_any_open(ui.ctx());
                    dismissed = ui.input(|i| i.viewport().close_requested());
                    let output = egui::CentralPanel::default()
                        .frame(egui::Frame::new().fill(p.surface))
                        .show(ui, |ui| frame(ui, p, &window, first, native, &mut content))
                        .inner;
                    dismissed |= !popup
                        && ui
                            .input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
                    Some(output)
                },
            );
            (output, dismissed)
        } else if ctx.content_rect().width() < 600. {
            let rect = ctx.content_rect();
            // Keep floating bounds when the viewport uses the full-screen host.
            let full_screen_id = window.id.with("full-screen");
            let modal = egui::Modal::new(full_screen_id)
                .area(
                    egui::Area::new(full_screen_id)
                        .kind(egui::UiKind::Modal)
                        .order(egui::Order::Foreground)
                        .fixed_pos(rect.min)
                        .sense(egui::Sense::hover()),
                )
                .frame(egui::Frame::new().fill(p.surface))
                .show(ctx, |ui| {
                    ui.set_width(rect.width());
                    ui.set_height(rect.height());
                    frame(ui, p, &window, first, native, &mut content)
                });
            let dismissed = modal.should_close();
            (
                Some(Output {
                    rect: modal.response.rect,
                    ..modal.inner
                }),
                dismissed,
            )
        } else {
            let rect = ctx.content_rect();
            let backdrop = egui::Modal::new(window.id.with("backdrop"))
                .frame(egui::Frame::NONE)
                .show(ctx, |ui| {
                    ui.allocate_exact_size(rect.size(), egui::Sense::hover());
                });
            // The window can already exist when the full-screen host changes.
            ctx.set_sublayer(
                backdrop.response.layer_id,
                egui::LayerId::new(egui::Order::Foreground, window.id),
            );
            let max = (rect.size() - Vec2::splat(2. * M::LG)).max(Vec2::splat(1.));
            let size = window.size.min(max);
            let response = egui::Window::new(window.title)
                .id(window.id)
                .order(egui::Order::Foreground)
                .title_bar(false)
                .collapsible(false)
                .resizable(true)
                .movable(true)
                .default_rect(Rect::from_center_size(rect.center(), size))
                .min_size(Vec2::new(280., 200.).min(max))
                .max_size(max)
                .constrain_to(rect.shrink(M::SM))
                .frame(
                    egui::Frame::new()
                        .fill(p.surface)
                        .stroke(egui::Stroke::new(1., p.border))
                        .corner_radius(12)
                        .shadow(ctx.global_style().visuals.window_shadow),
                )
                .show(ctx, |ui| frame(ui, p, &window, first, native, &mut content));
            let dismissed = backdrop.should_close();
            let output = response.and_then(|r| {
                r.inner.map(|inner| Output {
                    rect: r.response.rect,
                    ..inner
                })
            });
            (output, dismissed)
        };
        self.raise = false;
        if dismissed
            || output
                .as_ref()
                .and_then(|o| o.close.as_ref())
                .is_some_and(egui::Response::clicked)
        {
            self.close(ctx);
        }
        output
    }
}
fn frame<R>(
    ui: &mut egui::Ui,
    p: Palette,
    window: &Window<'_>,
    first: bool,
    native: bool,
    content: &mut impl FnMut(&mut egui::Ui) -> R,
) -> Output<R> {
    let size = ui.available_size().max(Vec2::splat(1.));
    let rect = Rect::from_min_size(ui.cursor().min, size);
    ui.set_min_size(size);
    let padding = if size.y < 300. { M::SM } else { M::LG };
    let inner = rect.shrink(padding);
    let (header, close, body) = if native {
        (Rect::NOTHING, None, inner)
    } else {
        let side = if ui.ctx().content_rect().width() < 600. {
            44.
        } else {
            super::density(ui).icon
        };
        let header = Rect::from_min_size(
            inner.min,
            Vec2::new(inner.width(), side.max(super::density(ui).control)),
        );
        let mut header_ui = ui.new_child(
            egui::UiBuilder::new()
                .id_salt("window-header")
                .max_rect(header)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
        );
        let close = super::icon_button_sized(
            &mut header_ui,
            p,
            window.close_label,
            Icon::Close,
            true,
            side,
        );
        let title_width = (header.width() - close.rect.width() - M::LG).max(1.);
        let title = header_ui.fonts_mut(|fonts| {
            let mut job = egui::text::LayoutJob::simple(
                window.title.to_owned(),
                fonts::semibold(M::DIALOG_TITLE),
                p.text,
                title_width,
            );
            job.wrap.max_rows = 1;
            fonts.layout_job(job)
        });
        header_ui.painter().galley(
            egui::pos2(header.left(), header.center().y - title.size().y / 2.),
            title,
            p.text,
        );
        if first || ui.memory(|memory| memory.focused().is_none()) {
            close.request_focus();
        }
        let body = Rect::from_min_max(egui::pos2(inner.left(), header.bottom() + M::LG), inner.max);
        (header, Some(close), body)
    };
    let mut body_ui = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("window-body")
            .max_rect(body)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    body_ui.set_clip_rect(body.intersect(ui.clip_rect()));
    let inner = content(&mut body_ui);
    ui.advance_cursor_after_rect(rect);
    Output {
        inner,
        rect,
        body,
        header,
        close,
        native,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canvas_windows_keep_their_header_and_close_above_scroll_content() {
        for size in [
            Vec2::new(195., 220.),
            Vec2::new(320., 440.),
            Vec2::new(390., 900.),
            Vec2::new(1320., 900.),
        ] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            let mut state = State {
                open: true,
                ..Default::default()
            };
            for frame in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ui| {
                        let r = state
                            .show(
                                ui.ctx(),
                                crate::theme::THEMES[0].colors,
                                Window {
                                    id: Id::unique("settings"),
                                    title: "Settings",
                                    close_label: "Close",
                                    size: Vec2::new(960., 680.),
                                },
                                |ui| {
                                    super::super::layout::scroll(ui, "body", false, |ui| {
                                        for _ in 0..100 {
                                            ui.label("Public content");
                                        }
                                    });
                                },
                            )
                            .unwrap();
                        if frame == 2 {
                            assert!(!r.native);
                            assert!(r.header.is_positive());
                            if size.x < 600. {
                                assert_eq!(r.rect, ctx.content_rect());
                            }
                            assert!(r.close.as_ref().unwrap().rect.bottom() <= r.body.top());
                            if size.x < 600. {
                                assert!(r.close.as_ref().unwrap().rect.top() <= M::LG + 1.);
                            }
                            assert!(r.rect.contains_rect(r.body));
                        }
                    },
                );
                output.textures_delta.clear();
            }
        }
    }
    #[test]
    fn native_backend_receives_a_separate_viewport_and_close_request() {
        use std::{cell::Cell, rc::Rc};
        for escape in [false, true] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            ctx.set_embed_viewports(false);
            let calls = Rc::new(Cell::new(0));
            let seen = calls.clone();
            egui::Context::set_immediate_viewport_renderer(move |ctx, mut viewport| {
                assert_eq!(viewport.builder.title.as_deref(), Some("Settings"));
                assert_ne!(viewport.ids.this, egui::ViewportId::ROOT);
                assert_eq!(viewport.ids.parent, egui::ViewportId::ROOT);
                let n = seen.get();
                seen.set(n + 1);
                let mut input = egui::RawInput {
                    viewport_id: viewport.ids.this,
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(600., 500.))),
                    ..Default::default()
                };
                input.viewports.insert(
                    viewport.ids.this,
                    egui::ViewportInfo {
                        parent: Some(viewport.ids.parent),
                        events: if n >= 2 && !escape {
                            vec![egui::ViewportEvent::Close]
                        } else {
                            vec![]
                        },
                        ..Default::default()
                    },
                );
                if n >= 2 && escape {
                    input.events.push(egui::Event::Key {
                        key: egui::Key::Escape,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    });
                }
                let mut output = ctx.run_ui(input, |ui| (viewport.viewport_ui_cb)(ui));
                output.textures_delta.clear();
            });
            let mut state = State {
                open: true,
                ..Default::default()
            };
            for _ in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(1320., 900.),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        let r = state
                            .show(
                                ui.ctx(),
                                crate::theme::THEMES[0].colors,
                                Window {
                                    id: Id::unique("native-settings"),
                                    title: "Settings",
                                    close_label: "Close",
                                    size: Vec2::new(600., 500.),
                                },
                                |ui| ui.label("Public native fixture"),
                            )
                            .unwrap();
                        assert!(r.native);
                        assert!(r.close.is_none());
                        assert_eq!(r.header, Rect::NOTHING);
                        assert_eq!(r.body, r.rect.shrink(M::LG));
                        assert!(r.body.contains_rect(r.inner.rect));
                    },
                );
                output.textures_delta.clear();
            }
            assert_eq!(calls.get(), 3);
            assert!(!state.open);
        }
    }
}
