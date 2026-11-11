//! A protected image form. State contains only window and camera geometry.
use super::{ButtonRole, Metrics as M, button, density, spinner, window};
use crate::theme::Palette;
use eframe::egui::{self, Color32, Id, Pos2, Rect, Response, Sense, Vec2};

const CHECK_DARK: Color32 = Color32::from_gray(30);
const CHECK_LIGHT: Color32 = Color32::from_gray(41);

#[derive(Default)]
pub struct State {
    window: window::State,
    camera: Camera,
    source: Option<Id>,
}
pub struct Image<'a> {
    pub id: Id,
    pub name: &'a str,
    pub source: &'a str,
    pub texture: Option<&'a egui::TextureHandle>,
    pub natural_size: Vec2,
    pub index: usize,
    pub count: usize,
    pub busy: bool,
    pub status: &'a str,
}
pub struct Labels<'a> {
    pub close: &'a str,
    pub previous: &'a str,
    pub next: &'a str,
    pub export: &'a str,
    pub webp: &'a str,
    pub png: &'a str,
    pub jpeg: &'a str,
    pub minus: &'a str,
    pub fit: &'a str,
    pub plus: &'a str,
    pub actual: &'a str,
    pub canvas: &'a str,
    pub help: &'a str,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Previous,
    Next,
    Webp,
    Png,
    Jpeg,
}
pub struct Output {
    pub action: Option<Action>,
    pub rect: Rect,
    pub canvas: Rect,
    pub image: Option<Rect>,
    pub controls: Vec<(&'static str, Response)>,
}
#[derive(Default)]
struct Camera {
    zoom: Option<f32>,
    pan: Vec2,
    scale: f32,
    multi: bool,
    gesture: Option<(f64, bool)>,
    touch_drag: bool,
    velocity: Vec2,
}
impl Camera {
    fn fit_scale(view: Rect, image: Vec2) -> f32 {
        let size = (view.size() - Vec2::splat(24.)).max(Vec2::splat(1.));
        (size.x / image.x).min(size.y / image.y).clamp(0.0001, 1.)
    }
    fn reset(&mut self) {
        *self = Self::default();
    }
    fn clamp(&mut self, view: Rect, image: Vec2) {
        // Allow movement at Fit and keep the image reachable.
        let max = ((image * self.scale - view.size()) * 0.5).max(Vec2::ZERO) + view.size() * 0.25;
        let clamped = self.pan.clamp(-max, max);
        for axis in 0..2 {
            if clamped[axis] != self.pan[axis] {
                self.velocity[axis] = 0.;
            }
        }
        self.pan = clamped;
    }
    fn zoom_at(&mut self, view: Rect, image: Vec2, point: Pos2, factor: f32) {
        if !factor.is_finite() || factor <= 0. || !point.is_finite() {
            return;
        }
        let old = self.zoom.unwrap_or_else(|| Self::fit_scale(view, image));
        let new = (old * factor).clamp((Self::fit_scale(view, image) * 0.1).min(0.01), 16.);
        let anchor = point - view.center();
        self.pan = anchor - (anchor - self.pan) * (new / old);
        self.zoom = Some(new);
        self.scale = new;
        self.clamp(view, image);
    }
    fn canvas(
        &mut self,
        ui: &mut egui::Ui,
        texture: Option<&egui::TextureHandle>,
        natural_size: Vec2,
        label: &str,
    ) -> (Response, Option<Rect>) {
        let (view, response) = ui.allocate_exact_size(
            ui.available_size().max(Vec2::splat(1.)),
            Sense::click_and_drag(),
        );
        let response = response.on_hover_text(label);
        response
            .widget_info(|| egui::WidgetInfo::labeled(egui::Role::Image, texture.is_some(), label));
        let painter = ui.painter().with_clip_rect(view.intersect(ui.clip_rect()));
        checkerboard(&painter, view);
        let Some(texture) = texture else {
            return (response, None);
        };
        let image = natural_size.max(Vec2::splat(1.));
        self.scale = self.zoom.unwrap_or_else(|| Self::fit_scale(view, image));
        let multi = ui.input(|i| i.multi_touch());
        if let Some(touch) = multi {
            if self
                .gesture
                .is_none_or(|(time, _)| time != touch.start_time)
            {
                self.gesture = Some((
                    touch.start_time,
                    view.contains(touch.start_pos) && response.contains_pointer(),
                ));
            }
        } else {
            self.gesture = None;
        }
        let active_multi = multi.filter(|_| self.gesture.is_some_and(|(_, allowed)| allowed));
        if let Some(touch) = active_multi {
            self.velocity = Vec2::ZERO;
            self.touch_drag = false;
            self.zoom_at(
                view,
                image,
                touch.center_pos - touch.translation_delta,
                touch.zoom_delta,
            );
            self.pan += touch.translation_delta;
        } else if !self.multi {
            if response.dragged() {
                self.velocity = Vec2::ZERO;
                self.pan += response.drag_delta();
                self.touch_drag |= ui.input(|i| {
                    i.raw
                        .events
                        .iter()
                        .any(|e| matches!(e, egui::Event::Touch { .. }))
                });
            }
            if response.drag_stopped() && self.touch_drag {
                self.velocity = ui
                    .input(|i| i.pointer.velocity())
                    .clamp(Vec2::splat(-4000.), Vec2::splat(4000.));
                self.touch_drag = false;
            }
            if response.contains_pointer() {
                let (zoom, scroll, source, point) = ui.input(|i| {
                    (
                        i.zoom_delta(),
                        i.smooth_scroll_delta,
                        i.scroll_source(),
                        i.pointer.latest_pos().unwrap_or(view.center()),
                    )
                });
                if zoom != 1. {
                    self.velocity = Vec2::ZERO;
                    self.zoom_at(view, image, point, zoom);
                } else if scroll != Vec2::ZERO {
                    self.velocity = Vec2::ZERO;
                    if source == Some(egui::MouseWheelSource::Wheel) {
                        self.zoom_at(view, image, point, (scroll.y * 0.002).exp());
                    } else {
                        self.pan += scroll;
                    }
                }
            }
        }
        self.multi = active_multi.is_some();
        if response.clicked() {
            response.request_focus();
        }
        if response.double_clicked() {
            if self.zoom.is_some() {
                self.reset();
            } else {
                self.zoom_at(
                    view,
                    image,
                    response.interact_pointer_pos().unwrap_or(view.center()),
                    1. / self.scale,
                );
            }
        }
        if response.has_focus() {
            let delta = ui.input_mut(|i| {
                let mut delta = Vec2::ZERO;
                for (key, v) in [
                    (egui::Key::ArrowLeft, Vec2::new(40., 0.)),
                    (egui::Key::ArrowRight, Vec2::new(-40., 0.)),
                    (egui::Key::ArrowUp, Vec2::new(0., 40.)),
                    (egui::Key::ArrowDown, Vec2::new(0., -40.)),
                ] {
                    if i.consume_key(egui::Modifiers::NONE, key) {
                        delta += v;
                    }
                }
                if i.consume_key(egui::Modifiers::NONE, egui::Key::Home) {
                    self.reset();
                }
                delta
            });
            self.pan += delta;
        }
        if self.velocity.length() > 2. {
            let dt = ui.input(|i| i.stable_dt).min(0.04);
            self.pan += self.velocity * dt;
            self.velocity *= (-8. * dt).exp();
            ui.ctx().request_repaint();
        }
        self.scale = self.zoom.unwrap_or_else(|| Self::fit_scale(view, image));
        self.clamp(view, image);
        // The canvas owns wheel input at its boundaries as well.
        if response.contains_pointer() || active_multi.is_some() {
            ui.input_mut(|i| i.smooth_scroll_delta = Vec2::ZERO);
        }
        if response.hovered() || response.dragged() {
            ui.ctx().set_cursor_icon(if response.dragged() {
                egui::CursorIcon::Grabbing
            } else {
                egui::CursorIcon::Grab
            });
        }
        let rect = Rect::from_center_size(view.center() + self.pan, image * self.scale);
        painter.image(
            texture.id(),
            rect,
            Rect::from_min_max(Pos2::ZERO, Pos2::new(1., 1.)),
            Color32::WHITE,
        );
        (response, Some(rect))
    }
}
fn checkerboard(painter: &egui::Painter, rect: Rect) {
    painter.rect_filled(rect, 0., CHECK_DARK);
    let mut mesh = egui::Mesh::default();
    let size = 12.;
    for y in 0..(rect.height() / size).ceil() as usize {
        for x in 0..(rect.width() / size).ceil() as usize {
            if (x + y) % 2 == 0 {
                mesh.add_colored_rect(
                    Rect::from_min_size(
                        rect.min + Vec2::new(x as f32 * size, y as f32 * size),
                        Vec2::splat(size),
                    )
                    .intersect(rect),
                    CHECK_LIGHT,
                );
            }
        }
    }
    painter.add(mesh);
}
impl State {
    pub fn is_open(&self) -> bool {
        self.window.open
    }
    pub fn open(&mut self, opener: &Response) {
        self.window.open(opener);
        self.reset_view();
    }
    pub fn close(&mut self, ctx: &egui::Context) {
        self.window.close(ctx);
        self.source = None;
        self.reset_view();
    }
    pub fn reset_view(&mut self) {
        self.camera.reset();
    }
    pub fn transform(&self) -> (f32, Vec2) {
        (self.camera.scale, self.camera.pan)
    }
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        p: Palette,
        image: Image<'_>,
        labels: Labels<'_>,
    ) -> Option<Output> {
        if self.source != Some(image.id) {
            self.camera.reset();
            self.source = Some(image.id);
        }
        let mut window = std::mem::take(&mut self.window);
        let output = window.show(
            ctx,
            p,
            window::Window {
                id: Id::unique("image-viewer"),
                title: image.name,
                close_label: labels.close,
                size: Vec2::new(1040., 760.),
            },
            |ui| self.form(ui, p, &image, &labels),
        );
        let closed = !window.open;
        self.window = window;
        if closed {
            self.source = None;
            self.camera.reset();
        }
        output.map(|output| {
            let mut form = output.inner;
            form.rect = output.rect;
            if let Some(close) = output.close {
                form.controls.push(("close", close));
            }
            form
        })
    }
    fn form(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        image: &Image<'_>,
        labels: &Labels<'_>,
    ) -> Output {
        let mut controls = Vec::new();
        let mut action = None;
        ui.add(egui::Label::new(egui::RichText::new(image.source).color(p.text_muted)).truncate());
        ui.horizontal_wrapped(|ui| {
            for (key, label, enabled, command) in [
                ("prev", labels.previous, image.index > 0, Action::Previous),
                (
                    "next",
                    labels.next,
                    image.index + 1 < image.count,
                    Action::Next,
                ),
            ] {
                let r = button(ui, p, label, ButtonRole::Quiet, 0., enabled && !image.busy);
                if r.clicked() {
                    action = Some(command);
                }
                controls.push((key, r));
                if key == "prev" {
                    ui.label(format!("{} / {}", image.index + 1, image.count));
                }
            }
            let export = button(ui, p, labels.export, ButtonRole::Secondary, 0., !image.busy);
            egui::Popup::menu(&export).show(|ui| {
                for (key, label, command) in [
                    ("viewer-original", labels.webp, Action::Webp),
                    ("png", labels.png, Action::Png),
                    ("jpeg", labels.jpeg, Action::Jpeg),
                ] {
                    let r = button(ui, p, label, ButtonRole::Quiet, 0., !image.busy);
                    if r.clicked() {
                        action = Some(command);
                        ui.close();
                    }
                    controls.push((key, r));
                }
            });
            controls.push(("export", export));
            if image.busy {
                spinner(ui, p, M::ICON, image.status);
            }
        });
        if image.texture.is_none() {
            ui.label(image.status);
        }
        ui.add_space(M::SM);
        let compact = ui.available_width() < 340.;
        let footer = density(ui).control * if compact { 2. } else { 1. }
            + if compact { 3. } else { 2. } * M::SM;
        let size = Vec2::new(
            ui.available_width(),
            (ui.available_height() - footer).max(1.),
        );
        let mut canvas = None;
        let mut pixels = None;
        ui.scope_builder(
            egui::UiBuilder::new().max_rect(Rect::from_min_size(ui.cursor().min, size)),
            |ui| {
                let (r, rect) =
                    self.camera
                        .canvas(ui, image.texture, image.natural_size, labels.canvas);
                canvas = Some(r.rect);
                pixels = rect;
            },
        );
        ui.add_space(M::SM);
        ui.horizontal_wrapped(|ui| {
            for (key, label, factor) in [
                ("minus", labels.minus, 0.8),
                ("fit", labels.fit, 0.),
                ("plus", labels.plus, 1.25),
                ("actual", labels.actual, -1.),
            ] {
                let r = button(ui, p, label, ButtonRole::Quiet, 0., image.texture.is_some());
                if r.clicked() {
                    if factor == 0. {
                        self.camera.reset();
                    } else if let (Some(_), Some(view)) = (image.texture, canvas) {
                        let factor = if factor < 0. {
                            1. / self.camera.scale.max(0.0001)
                        } else {
                            factor
                        };
                        self.camera
                            .zoom_at(view, image.natural_size, view.center(), factor);
                    }
                }
                controls.push((key, r));
            }
            if !compact {
                ui.label(format!("{:.0}%", self.camera.scale * 100.));
                if ui.available_width() > 180. {
                    ui.add(
                        egui::Label::new(egui::RichText::new(labels.help).color(p.text_muted))
                            .truncate(),
                    );
                }
            }
        })
        .response
        .on_hover_text(labels.help);
        Output {
            action,
            rect: Rect::NOTHING,
            canvas: canvas.unwrap(),
            image: pixels,
            controls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zoom_keeps_the_anchor_and_bounds_keep_the_image_reachable() {
        let view = Rect::from_min_size(Pos2::ZERO, Vec2::new(600., 400.));
        let image = Vec2::new(1200., 800.);
        let anchor = Pos2::new(360., 240.);
        let mut camera = Camera::default();
        let fit = Camera::fit_scale(view, image);
        let before = (anchor - view.center() - camera.pan) / fit;
        camera.zoom_at(view, image, anchor, 3.);
        let after = (anchor - view.center() - camera.pan) / camera.scale;
        assert!((before - after).length() < 0.01);
        camera.pan = Vec2::new(1e6, -1e6);
        camera.clamp(view, image);
        let rect = Rect::from_center_size(view.center() + camera.pan, image * camera.scale);
        assert!(rect.intersect(view).area() >= view.area() * 0.5);
        let scale = camera.scale;
        camera.zoom_at(view, image, anchor, f32::NAN);
        assert_eq!(camera.scale, scale);
        camera.reset();
        camera.scale = Camera::fit_scale(view, image);
        camera.clamp(view, image);
        assert_eq!(camera.pan, Vec2::ZERO);
    }
    fn draw(
        ctx: &egui::Context,
        camera: &mut Camera,
        texture: &egui::TextureHandle,
        events: Vec<egui::Event>,
    ) -> Rect {
        let mut rect = Rect::NOTHING;
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(640., 480.))),
                events,
                ..Default::default()
            },
            |ui| {
                rect = camera
                    .canvas(
                        ui,
                        Some(texture),
                        texture.size_vec2(),
                        "Image: drag to move, pinch to zoom",
                    )
                    .0
                    .rect;
            },
        );
        output.textures_delta.clear();
        rect
    }
    #[test]
    fn two_finger_scroll_moves_a_fitted_image_without_zooming() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let texture = ctx.load_texture(
            "fit-pan",
            egui::ColorImage::filled([1200, 800], Color32::WHITE),
            Default::default(),
        );
        let mut camera = Camera::default();
        let view = draw(&ctx, &mut camera, &texture, vec![]);
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![egui::Event::PointerMoved(view.center())],
        );
        let scale = camera.scale;
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                source: egui::MouseWheelSource::Unknown,
                phase: egui::TouchPhase::Move,
                delta: Vec2::new(70., 50.),
                modifiers: Default::default(),
            }],
        );
        assert!(camera.pan.x > 1. && camera.pan.y > 1.);
        assert_eq!(camera.scale, scale);
        assert_eq!(ctx.zoom_factor(), 1.);
        assert_eq!(ctx.input(|i| i.smooth_scroll_delta), Vec2::ZERO);
    }
    #[test]
    fn mouse_wheel_drag_and_two_fingers_change_only_the_camera() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let texture = ctx.load_texture(
            "viewer-test",
            egui::ColorImage::filled([1200, 800], Color32::WHITE),
            Default::default(),
        );
        let mut camera = Camera::default();
        let view = draw(&ctx, &mut camera, &texture, vec![]);
        draw(&ctx, &mut camera, &texture, vec![]);
        camera.zoom_at(view, texture.size_vec2(), view.center(), 4.);
        let point = view.center();
        let old = camera.pan;
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![
                egui::Event::PointerMoved(point),
                egui::Event::PointerButton {
                    pos: point,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
        );
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![egui::Event::PointerMoved(point + Vec2::new(50., 30.))],
        );
        assert!((camera.pan - old).length() > 10.);
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![egui::Event::PointerButton {
                pos: point + Vec2::new(50., 30.),
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }],
        );
        let old = camera.scale;
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![egui::Event::PointerMoved(point), egui::Event::Zoom(1.5)],
        );
        assert!(camera.scale > old);
        let old = camera.pan;
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                source: egui::MouseWheelSource::Trackpad,
                phase: egui::TouchPhase::Move,
                delta: Vec2::new(35., 25.),
                modifiers: Default::default(),
            }],
        );
        assert!((camera.pan - old).length() > 1.);
        let touch = |id, pos, phase| egui::Event::Touch {
            device_id: egui::TouchDeviceId(1),
            id: egui::TouchId(id),
            phase,
            pos,
            force: None,
        };
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![
                touch(0, point - Vec2::new(40., 0.), egui::TouchPhase::Start),
                touch(1, point + Vec2::new(40., 0.), egui::TouchPhase::Start),
            ],
        );
        let old = camera.scale;
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![
                touch(0, point - Vec2::new(70., 0.), egui::TouchPhase::Move),
                touch(1, point + Vec2::new(90., 0.), egui::TouchPhase::Move),
            ],
        );
        assert!(camera.scale > old);
        assert_eq!(ctx.zoom_factor(), 1.);
        draw(
            &ctx,
            &mut camera,
            &texture,
            vec![
                touch(0, point, egui::TouchPhase::End),
                touch(1, point, egui::TouchPhase::End),
            ],
        );
    }
    #[test]
    fn viewer_form_keeps_controls_outside_the_canvas_at_each_width() {
        for size in [
            Vec2::new(320., 440.),
            Vec2::new(390., 900.),
            Vec2::new(1320., 1000.),
        ] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            let texture = ctx.load_texture(
                "form-test",
                egui::ColorImage::filled([320, 220], Color32::WHITE),
                Default::default(),
            );
            let mut viewer = State::default();
            viewer.window.open = true;
            for _ in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ui| {
                        super::super::apply_density(ui.ctx(), false);
                        let out = viewer
                            .show(
                                ui.ctx(),
                                crate::theme::THEMES[0].colors,
                                Image {
                                    id: Id::unique("sample"),
                                    name: "photo-public-sample.webp",
                                    source: "Travel documents · WebP · 320×220",
                                    texture: Some(&texture),
                                    natural_size: texture.size_vec2(),
                                    index: 0,
                                    count: 3,
                                    busy: false,
                                    status: "Visible until closed",
                                },
                                Labels {
                                    close: "Close",
                                    previous: "Previous",
                                    next: "Next",
                                    export: "Export…",
                                    webp: "WebP",
                                    png: "PNG",
                                    jpeg: "JPEG · white background",
                                    minus: "−",
                                    fit: "Fit",
                                    plus: "+",
                                    actual: "100%",
                                    canvas: "Image",
                                    help: "Drag to pan · pinch to zoom",
                                },
                            )
                            .unwrap();
                        assert!(
                            out.rect.contains_rect(out.canvas),
                            "canvas outside window at {size:?}"
                        );
                        for (key, response) in out.controls {
                            assert!(
                                out.rect.contains_rect(response.rect),
                                "{key} outside window at {size:?}"
                            );
                            assert!(
                                !out.canvas.intersects(response.rect),
                                "{key} overlaps image canvas"
                            );
                        }
                    },
                );
                output.textures_delta.clear();
            }
            viewer.close(&ctx);
            assert!(!viewer.is_open());
            assert_eq!(viewer.transform(), (0., Vec2::ZERO));
        }
    }
    #[test]
    fn bounded_texture_uses_full_resolution_for_one_to_one_zoom() {
        let ctx = egui::Context::default();
        let texture = ctx.load_texture(
            "bounded",
            egui::ColorImage::filled([8, 6], Color32::WHITE),
            Default::default(),
        );
        let mut camera = Camera {
            zoom: Some(1.),
            ..Default::default()
        };
        let natural = Vec2::new(7198., 5384.);
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(800., 600.))),
                ..Default::default()
            },
            |ui| {
                let (_, rect) = camera.canvas(ui, Some(&texture), natural, "Image");
                assert_eq!(rect.unwrap().size(), natural);
                assert_eq!(camera.scale, 1.);
            },
        );
        output.textures_delta.clear();
    }
    #[test]
    fn checkerboard_is_dim_and_does_not_depend_on_the_theme() {
        for theme in crate::theme::THEMES {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            theme.apply(&ctx);
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                let rect = ui.available_rect_before_wrap();
                checkerboard(ui.painter(), rect);
            });
            output.textures_delta.clear();
            let colors: Vec<_> = output
                .shapes
                .iter()
                .flat_map(|shape| match &shape.shape {
                    egui::Shape::Mesh(mesh) => {
                        mesh.vertices.iter().map(|v| v.color).collect::<Vec<_>>()
                    }
                    egui::Shape::Rect(rect) => vec![rect.fill],
                    _ => vec![],
                })
                .collect();
            assert!(colors.contains(&CHECK_DARK) && colors.contains(&CHECK_LIGHT));
        }
    }
}
