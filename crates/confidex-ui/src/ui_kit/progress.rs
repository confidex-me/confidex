//! Determinate and indeterminate progress use the same theme roles.
use super::{Metrics, fonts};
use crate::theme::Palette;
use eframe::egui::{self, Vec2};
pub fn progress(ui: &mut egui::Ui, p: Palette, fraction: f32, label: &str) -> egui::Response {
    let fraction = if fraction.is_finite() {
        fraction.clamp(0., 1.)
    } else {
        0.
    };
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), Metrics::XL),
        egui::Sense::hover(),
    );
    let fill =
        egui::Rect::from_min_size(rect.min, Vec2::new(rect.width() * fraction, rect.height()));
    ui.painter().rect_filled(rect, Metrics::RADIUS, p.control);
    if fraction > 0. {
        ui.painter().rect_filled(fill, Metrics::RADIUS, p.accent);
    }
    let galley =
        ui.painter()
            .layout_no_wrap(label.to_owned(), fonts::medium(Metrics::LABEL), p.text);
    let pos = rect.center() - galley.size() / 2.;
    ui.painter().galley(pos, galley.clone(), p.text);
    if fraction > 0. {
        ui.painter()
            .with_clip_rect(fill.intersect(ui.clip_rect()))
            .galley_with_override_text_color(pos, galley, p.on_accent);
    }
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::ProgressIndicator, true, label));
    response
}
pub fn spinner(ui: &mut egui::Ui, p: Palette, size: f32, label: &str) -> egui::Response {
    let response = ui.add(egui::Spinner::new().size(size).color(p.accent));
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::ProgressIndicator, true, label));
    response.on_hover_text(label)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percentage_text_is_centered() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let mut bar = egui::Rect::NOTHING;
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(600., 200.),
                )),
                ..Default::default()
            },
            |ui| {
                bar = progress(ui, crate::theme::THEMES[0].colors, 1., "100%").rect;
            },
        );
        output.textures_delta.clear();
        let text = output
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(text) if text.galley.job.text == "100%" => Some(text),
                _ => None,
            })
            .unwrap();
        let center = text.pos + text.galley.size() / 2.;
        assert!((center.x - bar.center().x).abs() < 0.1);
        assert!((center.y - bar.center().y).abs() < 0.1);
    }
}
