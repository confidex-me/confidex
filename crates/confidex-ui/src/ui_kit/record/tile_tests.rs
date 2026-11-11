use super::*;
use crate::i18n::Localizer;

#[test]
fn titles_and_details_fit_each_cell_in_every_available_language() {
    for (language, _) in Localizer::languages() {
        let locale = Localizer::new(*language).unwrap();
        let mut titles: Vec<_> = confidex_app::templates::ids()
            .map(|id| locale.text(&format!("template-{id}")))
            .collect();
        titles.sort_by_key(|title| std::cmp::Reverse(title.chars().count()));
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        for (mobile, width) in [(false, 240.), (true, 340.)] {
            super::super::apply_density(&ctx, mobile);
            for featured in [true, false] {
                for title in titles.iter().take(3) {
                    let mut bounds = Rect::NOTHING;
                    let mut painted = ctx.run_ui(egui::RawInput::default(), |ui| {
                        ui.set_width(width);
                        bounds = template_tile(
                            ui,
                            crate::theme::THEMES[0].colors,
                            title,
                            &locale.text("template-hint"),
                            Icon::Key,
                            false,
                            featured,
                        )
                        .rect;
                    });
                    painted.textures_delta.clear();
                    let text: Vec<_> = painted
                        .shapes
                        .iter()
                        .filter_map(|shape| {
                            if let egui::Shape::Text(text) = &shape.shape
                                && !text.galley.job.text.is_empty()
                            {
                                Some(text.galley.rect.translate(text.pos.to_vec2()))
                            } else {
                                None
                            }
                        })
                        .collect();
                    assert_eq!(text.len(), 2);
                    for rect in &text {
                        assert!(
                            bounds.expand(1.).contains_rect(*rect),
                            "{} {title} {featured} {rect:?} {bounds:?}",
                            locale.id()
                        );
                    }
                    assert!(
                        text[0].bottom() <= text[1].top() + 1.,
                        "{} {title}",
                        locale.id()
                    );
                }
            }
        }
    }
}
