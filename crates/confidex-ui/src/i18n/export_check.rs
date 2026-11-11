//! Check export messages in the browser worker and in test builds.
use super::*;
use eframe::egui;
use std::collections::BTreeSet;

fn keys(source: &str) -> BTreeSet<&str> {
    source
        .lines()
        .filter_map(|line| line.split_once(" = ").map(|(key, _)| key))
        .filter(|key| key.starts_with("export-"))
        .collect()
}
pub fn check_export_catalogues() -> Result<(), String> {
    let expected = keys(LOCALES[0].1);
    if expected.is_empty() {
        return Err("No export messages".into());
    }
    let mut args = FluentArgs::new();
    args.set("count", 2);
    let english = Localizer::new(0)?;
    for &(id, source) in LOCALES.iter().chain(DEFERRED) {
        if keys(source) != expected {
            return Err(format!("{id}: export message keys differ"));
        }
        let mut primary = FluentBundle::new(vec![
            id.parse().map_err(|_| format!("{id}: invalid locale"))?,
        ]);
        let resource = FluentResource::try_new(source.to_owned())
            .map_err(|(_, errors)| format!("{id}: {errors:?}"))?;
        primary
            .add_resource(resource)
            .map_err(|errors| format!("{id}: {errors:?}"))?;
        for key in &expected {
            let pattern = primary
                .get_message(key)
                .and_then(|m| m.value())
                .ok_or_else(|| format!("{id}: missing {key}"))?;
            let mut errors = Vec::new();
            let value = primary.format_pattern(pattern, Some(&args), &mut errors);
            if !errors.is_empty() || value.is_empty() {
                return Err(format!("{id} {key}: invalid message {errors:?}"));
            }
            // Spanish and Romanian use "Personal" for this option.
            let cognate = matches!((id, *key), ("es" | "ro", "export-bitwarden-personal"));
            if id != "en-US" && !cognate && value == english.format(key, &args) {
                return Err(format!("{id} {key}: English placeholder"));
            }
        }
    }
    let ctx = egui::Context::default();
    crate::ui_kit::fonts::install(&ctx);
    let mut checked = Ok(());
    let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
        checked = ui.fonts_mut(|fonts| {
            for (index, (id, _)) in LOCALES.iter().enumerate() {
                let locale = Localizer::new(index)?;
                for key in &expected {
                    let text: String = locale
                        .format(key, &args)
                        .chars()
                        .filter(|c| !matches!(c, '\u{2068}' | '\u{2069}'))
                        .collect();
                    for font in [
                        crate::ui_kit::fonts::regular(18.),
                        crate::ui_kit::fonts::medium(18.),
                        crate::ui_kit::fonts::semibold(18.),
                    ] {
                        for chr in text.chars().filter(|c| !c.is_control()) {
                            if !fonts.has_glyph(&font, chr) {
                                return Err(format!("{id} {key}: missing glyph {chr:?}"));
                            }
                        }
                        let galley = fonts.layout_no_wrap(text.clone(), font, egui::Color32::WHITE);
                        if galley
                            .rows
                            .iter()
                            .map(|row| row.glyphs.len())
                            .sum::<usize>()
                            != text.chars().count()
                        {
                            return Err(format!("{id} {key}: cursor mapping differs"));
                        }
                    }
                }
            }
            Ok(())
        });
    });
    output.textures_delta.clear();
    checked
}
