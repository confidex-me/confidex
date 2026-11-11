//! Use the same faces and weights in the native and browser hosts.
use eframe::egui::{self, FontData, FontFamily, FontId, RichText};
use std::sync::Arc;
pub const FILES: [&str; 7] = [
    "Inter-Regular.ttf",
    "Inter-Medium.ttf",
    "Inter-SemiBold.ttf",
    "JetBrainsMono-Regular.ttf",
    "DroidSansFallback.ttf",
    "NotoEmoji.ttf",
    "NotoSansTelugu.ttf",
];
#[cfg(any(test, feature = "embedded-fonts"))]
const EMBEDDED: [&[u8]; FILES.len()] = [
    include_bytes!("../../assets/fonts/Inter-Regular.ttf"),
    include_bytes!("../../assets/fonts/Inter-Medium.ttf"),
    include_bytes!("../../assets/fonts/Inter-SemiBold.ttf"),
    include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf"),
    include_bytes!("../../assets/fonts/DroidSansFallback.ttf"),
    include_bytes!("../../assets/fonts/NotoEmoji.ttf"),
    include_bytes!("../../assets/fonts/NotoSansTelugu.ttf"),
];
pub fn regular(size: f32) -> FontId {
    FontId::proportional(size)
}
pub fn medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("confidex-medium".into()))
}
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("confidex-semibold".into()))
}
pub trait Weight {
    fn semibold(self) -> Self;
}
impl Weight for RichText {
    fn semibold(self) -> Self {
        self.family(semibold(0.).family)
    }
}
#[cfg(any(test, feature = "embedded-fonts"))]
pub fn install(ctx: &egui::Context) {
    ctx.set_fonts(definitions(EMBEDDED.map(FontData::from_static)));
}

/// Use font data in the order of `FILES`.
pub fn definitions(
    [
        regular,
        medium_face,
        semibold_face,
        mono,
        cjk,
        emoji,
        telugu,
    ]: [FontData; FILES.len()],
) -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    for (name, face) in [
        ("confidex-cjk", cjk),
        ("confidex-emoji", emoji),
        ("confidex-telugu", telugu),
    ] {
        fonts.font_data.insert(name.into(), Arc::new(face));
    }
    // Keep emoji sequences in one face before egui's older emoji fallback.
    for faces in fonts.families.values_mut() {
        faces.insert(0, "confidex-emoji".into());
        faces.push("confidex-telugu".into());
        faces.push("confidex-cjk".into());
    }
    let fallback = fonts.families[&FontFamily::Proportional].clone();
    for (name, face, family) in [
        ("confidex-regular", regular, FontFamily::Proportional),
        ("confidex-medium", medium_face, medium(0.).family),
        ("confidex-semibold", semibold_face, semibold(0.).family),
    ] {
        fonts.font_data.insert(name.into(), Arc::new(face));
        let mut faces = vec![name.into()];
        faces.extend(fallback.clone());
        faces.push("Hack".into());
        fonts.families.insert(family, faces);
    }
    fonts
        .font_data
        .insert("confidex-mono".into(), Arc::new(mono));
    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .unwrap()
        .insert(0, "confidex-mono".into());
    fonts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_fallbacks_cover_text_and_shape_emoji_in_every_role() {
        let ctx = egui::Context::default();
        install(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.fonts_mut(|fonts| {
                for font in [
                    regular(18.),
                    medium(18.),
                    semibold(18.),
                    FontId::monospace(18.),
                ] {
                    for chr in
                        "Кириллица café e\u{301} 日本語かなカナ 简体中文繁體 한국어한글".chars()
                    {
                        assert!(fonts.has_glyph(&font, chr), "missing {chr:?} in {font:?}");
                    }
                    let replacement =
                        fonts.layout_no_wrap("◻".into(), font.clone(), egui::Color32::WHITE);
                    let replacement = replacement.rows[0].glyphs[0].uv_rect;
                    for emoji in ["🔐", "🧑🏽‍💻", "🇳🇱", "👨‍👩‍👧‍👦"]
                    {
                        let galley =
                            fonts.layout_no_wrap(emoji.into(), font.clone(), egui::Color32::WHITE);
                        // egui 0.35 has_glyph misidentifies the replacement face's other glyphs.
                        let visible: Vec<_> = galley
                            .rows
                            .iter()
                            .flat_map(|r| &r.glyphs)
                            .filter(|g| !g.uv_rect.is_nothing())
                            .collect();
                        assert_eq!(visible.len(), 1, "split emoji {emoji} in {font:?}");
                        assert_ne!(
                            visible[0].uv_rect, replacement,
                            "missing emoji {emoji} in {font:?}"
                        );
                        assert_eq!(galley.job.text, emoji);
                    }
                }
            });
        });
        output.textures_delta.clear();
    }
}
