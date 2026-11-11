//! Record composition. Data and mutations stay with the caller.
use super::{Icon, Metrics as M, fonts};
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect, RichText, Sense, Vec2};
#[cfg(test)]
mod tile_tests;

pub enum TagRole {
    Neutral,
    Accent,
    Type,
}
pub fn template_choice(
    ui: &mut egui::Ui,
    p: Palette,
    title: &str,
    detail: &str,
    icon: Icon,
    selected: bool,
) -> egui::Response {
    let response = ui.add(
        egui::Button::new("")
            .min_size(Vec2::new(ui.available_width(), 64.))
            .fill(if selected { p.control } else { p.surface })
            .stroke(egui::Stroke::new(
                1.,
                if selected { p.accent } else { p.border },
            )),
    );
    let rect = response.rect;
    icon.paint(
        ui,
        Rect::from_center_size(
            egui::pos2(rect.left() + 28., rect.center().y),
            Vec2::splat(28.),
        ),
        p.accent,
    );
    let left = rect.left() + 56.;
    let width = (rect.right() - left - M::LG).max(1.);
    for (text, font, color, top) in [
        (title, fonts::medium(super::density(ui).body), p.text, 10.),
        (detail, fonts::regular(M::CAPTION), p.text_muted, 34.),
    ] {
        let mut job = egui::text::LayoutJob::simple(text.into(), font, color, width);
        job.wrap.max_rows = 1;
        let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
        ui.painter()
            .galley(egui::pos2(left, rect.top() + top), galley, color);
    }
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, true, format!("{title}: {detail}"))
    });
    response.on_hover_text(detail)
}
pub fn template_tile(
    ui: &mut egui::Ui,
    p: Palette,
    title: &str,
    detail: &str,
    icon: Icon,
    selected: bool,
    featured: bool,
) -> egui::Response {
    let d = super::density(ui);
    let title_font = fonts::medium(d.body);
    let detail_font = fonts::regular(d.body * 0.85);
    let line = ui.fonts_mut(|fonts| fonts.row_height(&title_font));
    let padding = M::MD;
    let height = padding * 2. + line * 3. + if featured { 32. + M::SM } else { 0. };
    let response = ui.add(
        egui::Button::new("")
            .min_size(Vec2::new(ui.available_width(), height))
            .fill(if selected { p.control } else { p.surface })
            .stroke(egui::Stroke::new(
                1.,
                if selected { p.accent } else { p.border },
            )),
    );
    let rect = response.rect;
    let icon_rect = Rect::from_min_size(rect.min + Vec2::splat(padding), Vec2::splat(32.));
    icon.paint(ui, icon_rect, p.accent);
    let origin = if featured {
        egui::pos2(rect.left() + padding, icon_rect.bottom() + M::SM)
    } else {
        egui::pos2(icon_rect.right() + M::SM, rect.top() + padding)
    };
    let width = (rect.right() - origin.x - padding).max(1.);
    let mut job = egui::text::LayoutJob::simple(title.into(), title_font, p.text, width);
    job.wrap.max_rows = 2;
    let title_galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    ui.painter().galley(origin, title_galley, p.text);
    let mut job = egui::text::LayoutJob::simple(detail.into(), detail_font, p.text_muted, width);
    job.wrap.max_rows = 1;
    let detail_galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    ui.painter().galley(
        origin + Vec2::new(0., line * 2.),
        detail_galley,
        p.text_muted,
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, true, format!("{title}: {detail}"))
    });
    response.on_hover_text(format!("{title}\n{detail}"))
}
pub fn tag(ui: &mut egui::Ui, p: Palette, text: &str, role: TagRole) -> egui::Response {
    tag_widget(ui, p, text, role, None)
}
pub fn removable_tag(
    ui: &mut egui::Ui,
    p: Palette,
    text: &str,
    remove_label: &str,
) -> egui::Response {
    tag_widget(ui, p, text, TagRole::Neutral, Some(remove_label))
}
fn tag_widget(
    ui: &mut egui::Ui,
    p: Palette,
    text: &str,
    role: TagRole,
    remove_label: Option<&str>,
) -> egui::Response {
    let (fill, stroke, color, padding) = match role {
        TagRole::Neutral => (
            p.control,
            egui::Stroke::NONE,
            p.text_muted,
            Vec2::new(8., 5.),
        ),
        TagRole::Accent => (
            p.accent.gamma_multiply(0.12),
            egui::Stroke::NONE,
            p.accent,
            Vec2::new(8., 5.),
        ),
        TagRole::Type => (
            egui::Color32::TRANSPARENT,
            egui::Stroke::new(1., p.border),
            p.text_muted,
            Vec2::new(6., 2.),
        ),
    };
    let icon_space = if remove_label.is_some() { 28. } else { 0. };
    let mut job = egui::text::LayoutJob::simple(
        text.to_owned(),
        fonts::medium(M::CAPTION),
        color,
        (ui.available_width() - 2. * padding.x - icon_space).max(1.),
    );
    job.wrap.max_rows = 1;
    let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    let mut size = galley.size() + 2. * padding + Vec2::new(icon_space, 0.);
    if remove_label.is_some() {
        size.y = size.y.max(super::density(ui).control);
    }
    let (rect, response) = ui.allocate_exact_size(
        size,
        if remove_label.is_some() {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    ui.painter()
        .rect(rect, 5., fill, stroke, egui::StrokeKind::Inside);
    let origin = egui::pos2(
        rect.left() + padding.x,
        rect.center().y - galley.size().y / 2.,
    );
    ui.painter().galley(origin, galley, color);
    if let Some(label) = remove_label {
        Icon::Close.paint(
            ui,
            Rect::from_center_size(
                egui::pos2(rect.right() - padding.x - 10., rect.center().y),
                Vec2::splat(20.),
            ),
            color,
        );
        super::focus_ring(ui, rect, response.has_focus(), p.accent);
        response.widget_info(|| {
            egui::WidgetInfo::labeled(
                egui::Role::Button,
                ui.is_enabled(),
                format!("{label}: {text}"),
            )
        });
        return response
            .on_hover_text(format!("{label}: {text}"))
            .on_hover_cursor(egui::CursorIcon::PointingHand);
    }
    response.on_hover_text(text)
}

pub fn toolbar(ui: &mut egui::Ui, p: Palette, context: &str, actions: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.with_layout(
            egui::Layout::right_to_left(egui::Align::Center).with_main_wrap(true),
            |ui| {
                ui.spacing_mut().item_spacing.x = M::SM;
                actions(ui);
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    tag(ui, p, context, TagRole::Accent).on_hover_text(context);
                });
            },
        );
    });
}

pub fn contents(
    ui: &mut egui::Ui,
    id: &str,
    height: f32,
    footer_height: f32,
    body: impl FnOnce(&mut egui::Ui),
    footer: Option<impl FnOnce(&mut egui::Ui)>,
) -> super::layout::PanelGeometry {
    let Some(footer) = footer else {
        return super::layout::PanelGeometry {
            content: super::layout::scroll_content(ui, id, height.max(1.), body).inner_rect,
            footer: Rect::NOTHING,
        };
    };
    let width = ui.available_width();
    let height = (height - footer_height - 2. * M::LG).max(1.);
    let area = super::layout::scroll_content(ui, id, height, body);
    ui.add_space(M::LG);
    let footer = ui
        .vertical(|ui| {
            ui.set_width(width);
            footer(ui);
        })
        .response
        .rect;
    super::layout::PanelGeometry {
        content: area.inner_rect,
        footer,
    }
}

pub fn add_field(
    ui: &mut egui::Ui,
    p: Palette,
    label: &str,
    choices: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let width = ui.available_width();
    let response = ui.add(
        egui::Button::new("")
            .min_size(Vec2::new(width, super::density(ui).control))
            .fill(p.surface)
            .stroke(egui::Stroke::new(1., p.border)),
    );
    super::menu(ui, &response, choices);
    super::paint_action_label(ui, p, &response, label, Icon::Plus);
    super::focus_ring(ui, response.rect, response.has_focus(), p.accent);
    response.on_hover_text(label)
}

pub fn heading(ui: &mut egui::Ui, title: &mut String, editing: bool, hint: &str) -> egui::Response {
    let d = super::density(ui);
    ui.add_space(M::LG);
    let height = ui
        .fonts_mut(|fonts| fonts.row_height(&fonts::semibold(d.title)))
        .max(ui.spacing().interact_size.y);
    ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            if editing {
                ui.add(
                    egui::TextEdit::singleline(title)
                        .id(Id::unique("record-title"))
                        .font(fonts::semibold(d.title))
                        .hint_text(RichText::new(hint).font(fonts::semibold(d.title)))
                        .frame(egui::Frame::NONE)
                        .margin(Vec2::ZERO)
                        .desired_width(f32::INFINITY),
                )
            } else {
                ui.add(
                    egui::Label::new(RichText::new(title.as_str()).font(fonts::semibold(d.title)))
                        .truncate(),
                )
                .on_hover_text(title.as_str())
            }
        },
    )
    .inner
}
