//! Shared visual components. Screens supply data and actions; this module owns geometry.
use crate::theme::Palette;
use eframe::egui::{self, RichText, Vec2};
pub mod card;
pub mod choice;
pub mod date;
pub mod dialog;
pub mod exporter;
pub mod field;
pub mod fonts;
pub mod graph;
mod icons;
pub mod image_viewer;
pub mod importer;
pub mod large_type;
pub mod layout;
pub mod location;
pub mod password;
mod progress;
pub mod record;
pub mod section;
mod select;
pub mod settings;
pub mod totp;
pub mod value;
pub mod wifi_qr;
pub mod window;
pub use icons::Icon;
pub use progress::{progress, spinner};
pub use select::{Select, menu};

pub struct Metrics;
impl Metrics {
    pub const XS: f32 = 4.;
    pub const SM: f32 = 8.;
    pub const MD: f32 = 12.;
    pub const LG: f32 = 16.;
    pub const XL: f32 = 24.;
    pub const XXL: f32 = 32.;
    pub const BODY: f32 = 14.;
    pub const LABEL: f32 = 13.;
    pub const CAPTION: f32 = 12.;
    pub const TITLE: f32 = 24.;
    pub const HEADING: f32 = 20.;
    pub const DIALOG_TITLE: f32 = 20.;
    pub const MONO: f32 = 13.;
    pub const CONTROL: f32 = 32.;
    pub const SWITCH_WIDTH: f32 = 52.;
    pub const SELECT_WIDTH: f32 = 144.;
    pub const SELECT_WIDE: f32 = 160.;
    pub const PANEL_NAV: f32 = 224.;
    pub const PANEL_BREAKPOINT: f32 = 820.;
    pub const ICON_BUTTON: f32 = 28.;
    pub const ICON: f32 = 20.;
    pub const RADIUS: u8 = 8;
    pub const FIELD_RADIUS: u8 = 6;
    pub const SIDEBAR: f32 = 216.;
    pub const RECORDS: f32 = 320.;
    pub const CONTENT_WIDTH: f32 = 720.;
    pub const BREAKPOINT: f32 = 960.;
    pub const CREATE_WIDTH: f32 = 560.;
    pub const UNLOCK_WIDTH: f32 = 432.;
    pub const KEY_WIDTH: f32 = 720.;
    pub const ROW: f32 = 56.;
    pub const AVATAR: f32 = 32.;
}

#[derive(Clone, Copy)]
pub struct Density {
    pub control: f32,
    pub input: f32,
    pub multiline: f32,
    pub icon: f32,
    pub body: f32,
    pub title: f32,
    pub heading: f32,
    pub row: f32,
    pub avatar: f32,
    pub field_padding: f32,
}
pub fn density(ui: &egui::Ui) -> Density {
    let touch = ui.ctx().content_rect().width() < 600.;
    let control = ui.spacing().interact_size.y;
    Density {
        control,
        input: control + if touch { 0. } else { 4. },
        multiline: 160.,
        icon: control.min(if touch { 40. } else { Metrics::ICON_BUTTON }),
        body: if touch { 15. } else { Metrics::BODY },
        title: if touch { 28. } else { Metrics::TITLE },
        heading: if touch { 24. } else { Metrics::HEADING },
        row: if touch { 72. } else { Metrics::ROW },
        avatar: if touch { 40. } else { Metrics::AVATAR },
        field_padding: Metrics::MD,
    }
}
pub fn apply_density(ctx: &egui::Context, compact: bool) {
    let touch = ctx.content_rect().width() < 600.;
    let body = if touch { 15. } else { Metrics::BODY };
    ctx.all_styles_mut(|s| {
        s.spacing.interact_size.y = if touch {
            44.
        } else {
            Metrics::CONTROL - if compact { 8. } else { 0. }
        };
        s.spacing.button_padding = if touch {
            Vec2::new(Metrics::LG, Metrics::SM)
        } else {
            Vec2::new(Metrics::MD, 6.)
        };
        s.text_styles
            .insert(egui::TextStyle::Body, fonts::regular(body));
        s.text_styles
            .insert(egui::TextStyle::Button, fonts::medium(body));
        s.text_styles.insert(
            egui::TextStyle::Heading,
            fonts::semibold(if touch { 24. } else { Metrics::HEADING }),
        );
        s.text_styles
            .insert(egui::TextStyle::Monospace, egui::FontId::monospace(body));
    });
}

#[derive(Clone, Copy)]
pub enum ButtonRole {
    Primary,
    Secondary,
    Danger,
    Quiet,
}
pub fn navigation_item(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    selected: bool,
) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), density(ui).control],
        egui::Button::new("").frame(false).selected(selected),
    );
    paint_row(ui, p, &response, selected);
    let mut job = egui::text::LayoutJob::simple(
        label.to_owned(),
        fonts::medium(density(ui).body),
        p.text,
        (response.rect.width() - 2. * Metrics::MD).max(1.),
    );
    job.wrap.max_rows = 1;
    let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    ui.painter().galley(
        egui::pos2(
            response.rect.left() + Metrics::MD,
            response.rect.center().y - galley.size().y / 2.,
        ),
        galley,
        p.text,
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Button, ui.is_enabled(), selected, label)
    });
    response
}

fn paint_row(ui: &egui::Ui, p: Palette, response: &egui::Response, selected: bool) {
    let fill = if response.is_pointer_button_down_on() || selected {
        p.hover
    } else if response.hovered() {
        p.control
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().rect(
        response.rect,
        Metrics::FIELD_RADIUS,
        fill,
        egui::Stroke::NONE,
        egui::StrokeKind::Inside,
    );
    focus_ring(ui, response.rect, response.has_focus(), p.accent);
}

pub fn navigation_action(ui: &mut egui::Ui, p: Palette, label: &str, icon: Icon) -> egui::Response {
    navigation_item_icon(ui, p, label, icon, false)
}

pub fn navigation_item_icon(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    icon: Icon,
    selected: bool,
) -> egui::Response {
    let response = ui.add_sized(
        [ui.available_width(), density(ui).control],
        egui::Button::new("").frame(false).selected(selected),
    );
    paint_row(ui, p, &response, selected);
    paint_action_label(ui, p, &response, label, icon);
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Button, ui.is_enabled(), selected, label)
    });
    response
}

fn paint_action_label(
    ui: &egui::Ui,
    p: Palette,
    response: &egui::Response,
    label: &str,
    icon: Icon,
) {
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(
            response.rect.left() + Metrics::MD + Metrics::ICON / 2.,
            response.rect.center().y,
        ),
        Vec2::splat(Metrics::ICON),
    );
    icon.paint(
        ui,
        icon_rect,
        if matches!(icon, Icon::Spinner) {
            p.accent
        } else {
            p.text_muted
        },
    );
    let mut job = egui::text::LayoutJob::simple(
        label.to_owned(),
        fonts::medium(density(ui).body),
        p.text,
        (response.rect.width() - 2. * Metrics::MD - Metrics::ICON - Metrics::SM).max(1.),
    );
    job.wrap.max_rows = 1;
    let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    ui.painter().galley(
        egui::pos2(
            icon_rect.right() + Metrics::SM,
            response.rect.center().y - galley.size().y / 2.,
        ),
        galley,
        p.text,
    );
}
fn focus_ring(ui: &egui::Ui, rect: egui::Rect, focused: bool, color: egui::Color32) {
    let rect = rect.expand(2.).intersect(ui.clip_rect());
    if focused && rect.is_positive() {
        ui.painter().rect_stroke(
            rect,
            Metrics::RADIUS,
            egui::Stroke::new(1., color),
            egui::StrokeKind::Inside,
        );
    }
}
pub fn button(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    role: ButtonRole,
    width: f32,
    enabled: bool,
) -> egui::Response {
    let color = match role {
        ButtonRole::Primary => p.on_accent,
        ButtonRole::Danger => p.background,
        _ => p.text,
    };
    let mut b = egui::Button::new(
        RichText::new(label)
            .font(fonts::medium(density(ui).body))
            .color(color),
    )
    .min_size(Vec2::new(width, ui.spacing().interact_size.y))
    .corner_radius(Metrics::FIELD_RADIUS);
    b = match role {
        ButtonRole::Primary => b.fill(p.accent).stroke(egui::Stroke::NONE),
        ButtonRole::Danger => b.fill(p.error),
        ButtonRole::Secondary => b.fill(p.control),
        ButtonRole::Quiet => b.frame_when_inactive(false).stroke(egui::Stroke::NONE),
    };
    let response = if width > 0. {
        ui.add_enabled_ui(enabled, |ui| ui.add_sized([width, density(ui).control], b))
            .inner
    } else {
        ui.add_enabled(enabled, b)
    };
    focus_ring(ui, response.rect, response.has_focus(), p.accent);
    response
}
pub fn field(
    ui: &mut egui::Ui,
    value: &mut String,
    secret: bool,
    multiline: bool,
    enabled: bool,
) -> egui::Response {
    field_with_id(ui, ui.next_auto_id(), value, secret, multiline, enabled)
}
pub fn field_with_id(
    ui: &mut egui::Ui,
    id: egui::Id,
    value: &mut String,
    secret: bool,
    multiline: bool,
    enabled: bool,
) -> egui::Response {
    if secret {
        // Do not keep credentials in the widget's undo cache.
        let mut state = egui::text_edit::TextEditState::load(ui.ctx(), id).unwrap_or_default();
        state.set_undoer(egui::util::undoer::Undoer::with_settings(
            egui::util::undoer::Settings {
                max_undos: 0,
                ..Default::default()
            },
        ));
        state.store(ui.ctx(), id);
    }
    let editor = if multiline {
        egui::TextEdit::multiline(value).desired_rows(3)
    } else {
        egui::TextEdit::singleline(value).password(secret)
    };
    let font = fonts::regular(density(ui).body);
    let padding = if multiline {
        Metrics::MD
    } else {
        input_padding(ui, &font)
    };
    let response = ui.add_enabled(
        enabled,
        editor
            .id(id)
            .desired_width(f32::INFINITY)
            .font(font)
            .min_size(Vec2::new(0., density(ui).input))
            .margin(egui::Margin {
                left: Metrics::MD as i8,
                right: Metrics::MD as i8,
                top: padding.ceil() as i8,
                bottom: padding.floor() as i8,
            }),
    );
    focus_ring(
        ui,
        response.rect,
        response.has_focus(),
        ui.visuals().selection.bg_fill,
    );
    response
}
fn input_padding(ui: &egui::Ui, font: &egui::FontId) -> f32 {
    let line = ui.fonts_mut(|fonts| fonts.row_height(font));
    ((density(ui).input - line) / 2.).max(0.)
}
pub fn search_field(
    ui: &mut egui::Ui,
    p: Palette,
    value: &mut String,
    hint: &str,
) -> egui::Response {
    let font = fonts::regular(density(ui).body);
    let padding = input_padding(ui, &font);
    let response = ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(RichText::new(hint).font(font.clone()))
            .font(font)
            .align(egui::Align2::LEFT_CENTER)
            .desired_width(f32::INFINITY)
            .margin(egui::Margin {
                left: 40,
                right: 12,
                top: padding.ceil() as i8,
                bottom: padding.floor() as i8,
            }),
    );
    let icon = egui::Rect::from_center_size(
        egui::pos2(response.rect.left() + 22., response.rect.center().y),
        Vec2::splat(Metrics::ICON),
    );
    Icon::Search.paint(ui, icon, p.text_muted);
    focus_ring(ui, response.rect, response.has_focus(), p.accent);
    response
}
pub struct Card {
    frame: egui::Frame,
}
impl Card {
    pub fn inner_margin(mut self, margin: impl Into<egui::Margin>) -> Self {
        self.frame = self.frame.inner_margin(margin);
        self
    }
    pub fn fill(mut self, color: egui::Color32) -> Self {
        self.frame = self.frame.fill(color);
        self
    }
    pub fn stroke(mut self, stroke: impl Into<egui::Stroke>) -> Self {
        self.frame = self.frame.stroke(stroke);
        self
    }
    pub fn show<R>(
        self,
        ui: &mut egui::Ui,
        body: impl FnOnce(&mut egui::Ui) -> R,
    ) -> egui::InnerResponse<R> {
        self.frame.show(ui, |ui| {
            ui.spacing_mut().item_spacing = Vec2::splat(Metrics::SM);
            let width = ui.available_width();
            ui.set_min_width(width);
            ui.set_max_width(width);
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), body)
                .inner
        })
    }
}
pub fn card(p: Palette) -> Card {
    Card {
        frame: egui::Frame::new()
            .fill(p.surface)
            .stroke(egui::Stroke::new(1., p.border))
            .corner_radius(Metrics::RADIUS)
            .inner_margin(Metrics::MD),
    }
}
pub fn badge(ui: &mut egui::Ui, icon: Icon, p: Palette, size: f32, accent: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, 11., if accent { p.accent } else { p.control });
    icon.paint(ui, rect, if accent { p.on_accent } else { p.text_muted });
}
pub fn muted(ui: &mut egui::Ui, p: Palette, text: String) {
    ui.add(egui::Label::new(egui::RichText::new(text).color(p.text_muted)).wrap());
}
pub fn initials(title: &str) -> String {
    title
        .chars()
        .filter(|c| !c.is_whitespace())
        .take(2)
        .flat_map(char::to_uppercase)
        .collect()
}

pub fn icon_button(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    icon: Icon,
    enabled: bool,
) -> egui::Response {
    icon_button_sized(ui, p, label, icon, enabled, density(ui).icon)
}
pub(super) fn icon_button_sized(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    icon: Icon,
    enabled: bool,
    side: f32,
) -> egui::Response {
    let response = ui
        .add_enabled(
            enabled,
            egui::Button::new("")
                .min_size(Vec2::splat(side))
                .frame_when_inactive(false)
                .stroke(egui::Stroke::NONE)
                .corner_radius(Metrics::FIELD_RADIUS),
        )
        .on_hover_text(label)
        .on_disabled_hover_text(label);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, label));
    focus_ring(ui, response.rect, response.has_focus(), p.accent);
    icon.paint(
        ui,
        response.rect,
        if matches!(icon, Icon::Spinner) {
            p.accent
        } else if enabled {
            p.text_muted
        } else {
            p.border
        },
    );
    response
}
pub fn checkbox(
    ui: &mut egui::Ui,
    checked: &mut bool,
    label: impl Into<egui::WidgetText>,
) -> egui::Response {
    let height = if ui.ctx().content_rect().width() < 600. {
        44.
    } else {
        24.
    };
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = height;
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        let response = ui.checkbox(checked, label);
        focus_ring(
            ui,
            response.rect,
            response.has_focus(),
            ui.visuals().selection.bg_fill,
        );
        response
    })
    .inner
}
pub fn setup(ctx: &egui::Context) {
    #[cfg(any(test, feature = "embedded-fonts"))]
    fonts::install(ctx);
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = Vec2::new(Metrics::SM, Metrics::SM);
        s.spacing.icon_spacing = Metrics::SM;
        s.spacing.button_padding = Vec2::new(Metrics::LG, Metrics::SM);
        s.spacing.interact_size.y = Metrics::CONTROL;
        s.text_styles
            .insert(egui::TextStyle::Body, fonts::regular(Metrics::BODY));
        s.text_styles
            .insert(egui::TextStyle::Button, fonts::medium(Metrics::BODY));
        s.text_styles
            .insert(egui::TextStyle::Small, fonts::regular(Metrics::CAPTION));
        s.text_styles
            .insert(egui::TextStyle::Heading, fonts::semibold(Metrics::HEADING));
        s.text_styles.insert(
            egui::TextStyle::Monospace,
            egui::FontId::monospace(Metrics::MONO),
        );
    });
    apply_density(ctx, false);
}
pub struct Workspace {
    pub sidebar: egui::Rect,
    pub records: egui::Rect,
    pub detail: egui::Rect,
}
impl Workspace {
    pub fn desktop(area: egui::Rect) -> Option<Self> {
        if area.width() < Metrics::BREAKPOINT {
            return None;
        }
        let sidebar = egui::Rect::from_min_max(
            area.min,
            egui::pos2(area.left() + Metrics::SIDEBAR, area.bottom()),
        );
        let records = egui::Rect::from_min_max(
            egui::pos2(sidebar.right(), area.top()),
            egui::pos2(sidebar.right() + Metrics::RECORDS, area.bottom()),
        );
        let detail = egui::Rect::from_min_max(egui::pos2(records.right(), area.top()), area.max);
        Some(Self {
            sidebar,
            records,
            detail,
        })
    }
}

pub fn record_row(
    ui: &mut egui::Ui,
    p: Palette,
    title: &str,
    detail: &str,
    selected: bool,
    enabled: bool,
) -> egui::Response {
    record_row_icon(ui, p, title, detail, selected, enabled, None).0
}
#[derive(Clone, Copy)]
pub enum RowIcon {
    Texture(egui::TextureId),
    External,
}
pub fn record_row_icon(
    ui: &mut egui::Ui,
    p: Palette,
    title: &str,
    detail: &str,
    selected: bool,
    enabled: bool,
    icon: Option<RowIcon>,
) -> (egui::Response, egui::Rect) {
    ui.add_enabled_ui(enabled, |ui| {
        let d = density(ui);
        let r = ui.add(
            egui::Button::new("")
                .min_size(Vec2::new(ui.available_width(), d.row))
                .frame(false),
        );
        paint_row(ui, p, &r, selected);
        r.widget_info(|| {
            egui::WidgetInfo::selected(egui::Role::Button, ui.is_enabled(), selected, title)
        });
        let painter = ui
            .painter()
            .with_clip_rect(r.rect.intersect(ui.clip_rect()));
        let avatar = egui::Rect::from_center_size(
            egui::pos2(
                r.rect.left() + Metrics::MD + d.avatar / 2.,
                r.rect.center().y,
            ),
            Vec2::splat(d.avatar),
        );
        painter.rect_filled(avatar, Metrics::FIELD_RADIUS, p.control);
        match icon {
            Some(RowIcon::Texture(texture)) => {
                painter.image(
                    texture,
                    avatar,
                    egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1., 1.)),
                    egui::Color32::WHITE,
                );
            }
            Some(RowIcon::External) => {}
            None => {
                painter.text(
                    avatar.center(),
                    egui::Align2::CENTER_CENTER,
                    initials(title),
                    fonts::medium(d.body),
                    p.text,
                );
            }
        }
        let title_font = fonts::medium(d.body + 2.);
        let (title_height, detail_height) = ui.fonts_mut(|f| {
            (
                f.row_height(&title_font),
                f.row_height(&fonts::regular(Metrics::CAPTION)),
            )
        });
        let pos = egui::pos2(
            avatar.right() + Metrics::MD,
            r.rect.center().y - (title_height + 2. + detail_height) / 2.,
        );
        for (text, at, font, color) in [
            (title, pos, title_font, p.text),
            (
                detail,
                pos + Vec2::new(0., title_height + 2.),
                fonts::regular(Metrics::CAPTION),
                p.text_muted,
            ),
        ] {
            let mut job = egui::text::LayoutJob::simple(
                text.to_owned(),
                font,
                color,
                (r.rect.right() - at.x - Metrics::MD).max(1.),
            );
            job.wrap.max_rows = 1;
            painter.galley(at, ui.fonts_mut(|fonts| fonts.layout_job(job)), color);
        }
        (r, avatar)
    })
    .inner
}

#[cfg(test)]
mod input_tests {
    use super::*;
    #[test]
    fn focus_outline_keeps_all_sides_inside_the_form_clip() {
        let ctx = egui::Context::default();
        let clip = egui::Rect::from_min_size(egui::pos2(20., 20.), egui::vec2(200., 80.));
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.set_clip_rect(clip);
            focus_ring(ui, clip, true, egui::Color32::YELLOW);
            focus_ring(
                ui,
                clip.translate(egui::vec2(0., 200.)),
                true,
                egui::Color32::YELLOW,
            );
        });
        let rings: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect) if rect.stroke.color == egui::Color32::YELLOW => {
                    Some(rect.rect)
                }
                _ => None,
            })
            .collect();
        assert_eq!(rings, [clip]);
        output.textures_delta.clear();
    }
    #[test]
    fn password_inputs_do_not_retain_undo_values() {
        for secret in [false, true] {
            let ctx = egui::Context::default();
            setup(&ctx);
            let id = egui::Id::unique("public-credential-input");
            let mut text = "public-test-only-password".to_owned();
            for _ in 0..3 {
                let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                    field_with_id(ui, id, &mut text, secret, false, true).request_focus();
                });
                output.textures_delta.clear();
            }
            let state = egui::text_edit::TextEditState::load(&ctx, id).unwrap();
            assert_eq!(
                state
                    .undoer()
                    .undo(&(egui::text::CCursorRange::default(), String::new()))
                    .is_some(),
                !secret
            );
        }
    }
    #[test]
    fn full_width_button_labels_are_centered_in_vertical_forms() {
        let ctx = egui::Context::default();
        setup(&ctx);
        let p = crate::theme::THEMES[0].colors;
        let mut buttons = Vec::new();
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.set_width(220.);
            for role in [
                ButtonRole::Primary,
                ButtonRole::Secondary,
                ButtonRole::Danger,
                ButtonRole::Quiet,
            ] {
                buttons.push(button(ui, p, "Confirm", role, 200., true).rect);
            }
        });
        output.textures_delta.clear();
        let text: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(t) if t.galley.job.text == "Confirm" => {
                    Some(t.galley.rect.translate(t.pos.to_vec2()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(text.len(), buttons.len());
        for (text, button) in text.iter().zip(buttons) {
            assert!((text.center().x - button.center().x).abs() < 1.);
        }
    }
    #[test]
    fn navigation_and_record_selection_share_the_same_surface_and_focus() {
        let ctx = egui::Context::default();
        setup(&ctx);
        let p = crate::theme::THEMES[0].colors;
        crate::theme::THEMES[0].apply(&ctx);
        for frame in 0..6 {
            let events = if frame >= 2 {
                vec![egui::Event::Key {
                    key: egui::Key::Tab,
                    physical_key: None,
                    pressed: frame % 2 == 0,
                    repeat: false,
                    modifiers: egui::Modifiers {
                        shift: frame >= 4,
                        ..Default::default()
                    },
                }]
            } else {
                vec![]
            };
            let mut responses = Vec::new();
            let mut clip = egui::Rect::NOTHING;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(220.);
                    clip = ui.clip_rect();
                    let nav = navigation_item(ui, p, "All items", true);
                    if frame == 0 {
                        nav.request_focus();
                    }
                    responses.push(nav);
                    responses.push(record_row(ui, p, "GitHub", "4 fields", true, true));
                    responses.push(record_row(ui, p, "Unselected", "4 fields", false, true));
                },
            );
            output.textures_delta.clear();
            for (i, response) in responses.iter().enumerate() {
                assert!(output.shapes.iter().any(|shape| {
                    matches!(&shape.shape, egui::Shape::Rect(r) if r.rect == response.rect && r.fill == if i < 2 { p.hover } else { egui::Color32::TRANSPARENT })
                }));
            }
            if frame % 2 == 1 {
                let focused = usize::from(frame == 3);
                for (index, response) in responses.iter().enumerate() {
                    assert_eq!(response.has_focus(), index == focused);
                }
                let rings: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Rect(rect) if rect.stroke.color == p.accent => Some(rect.rect),
                        _ => None,
                    })
                    .collect();
                assert_eq!(rings, [responses[focused].rect.expand(2.).intersect(clip)]);
            }
        }
    }
    #[test]
    fn rendered_density_uses_logical_retina_sizes_without_changing_zoom() {
        for (width, control, input, body, row) in
            [(1320., 32., 36., 14., 56.), (390., 44., 44., 15., 72.)]
        {
            let ctx = egui::Context::default();
            setup(&ctx);
            for frame in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 800.),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        apply_density(ui.ctx(), false);
                        let p = crate::theme::THEMES[0].colors;
                        let button = button(ui, p, "Save", ButtonRole::Primary, 0., true);
                        let field = field(ui, &mut String::new(), false, false, true);
                        let record = record_row(ui, p, "GitHub", "4 fields", true, true);
                        if frame == 2 {
                            assert!((button.rect.height() - control).abs() < 1.);
                            assert!(
                                (field.rect.height() - input).abs() < 1.,
                                "{width}: {:?} vs {input}",
                                field.rect
                            );
                            assert!((record.rect.height() - row).abs() < 1.);
                            assert_eq!(density(ui).body, body);
                            assert_eq!(ctx.zoom_factor(), 1.);
                            apply_density(ui.ctx(), true);
                            assert_eq!(
                                ctx.global_style().spacing.interact_size.y,
                                if width < 600. { 44. } else { 24. }
                            );
                        }
                    },
                );
                output.textures_delta.clear();
            }
        }
    }
    #[test]
    fn search_text_and_hint_share_a_centered_baseline() {
        for height in [36., 44.] {
            for value in ["", "GitHub"] {
                let ctx = egui::Context::default();
                setup(&ctx);
                let mut value = value.to_owned();
                let mut rect = egui::Rect::NOTHING;
                let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                    ui.set_width(200.);
                    ui.spacing_mut().interact_size.y = height;
                    rect = search_field(
                        ui,
                        crate::theme::THEMES[0].colors,
                        &mut value,
                        "Поиск записей",
                    )
                    .rect;
                });
                output.textures_delta.clear();
                assert!(
                    (rect.height() - (height + 4.)).abs() < 1.,
                    "{value}: {rect:?} vs {height}"
                );
                let text = output
                    .shapes
                    .iter()
                    .find_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) if !text.galley.job.text.is_empty() => Some(text),
                        _ => None,
                    })
                    .expect("search text or placeholder");
                let text_rect = text.galley.rect.translate(text.pos.to_vec2());
                assert!((text_rect.center().y - rect.center().y).abs() < 1.);
                assert!((text_rect.left() - rect.left() - 40.).abs() < 1.);
            }
        }
    }
}
