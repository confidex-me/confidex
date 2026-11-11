//! Semantic roles used by components and egui's built-in widgets.
use eframe::egui::{self, Color32, Stroke};

mod solidcraft;
pub use solidcraft::THEMES;

#[derive(Clone, Copy)]
pub struct Palette {
    pub background: Color32,
    pub surface: Color32,
    pub control: Color32,
    pub hover: Color32,
    pub pressed: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_muted: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub error: Color32,
    pub success: Color32,
    pub warning: Color32,
}

#[derive(Clone, Copy)]
pub struct Theme {
    pub id: &'static str,
    pub label: &'static str,
    pub dark: bool,
    pub colors: Palette,
}

const BASE_THEMES: [Theme; 2] = [
    Theme {
        id: "dark",
        label: "theme-dark",
        dark: true,
        colors: Palette {
            background: Color32::from_rgb(15, 16, 18),
            surface: Color32::from_rgb(21, 22, 25),
            control: Color32::from_rgb(29, 31, 35),
            hover: Color32::from_rgb(38, 40, 45),
            pressed: Color32::from_rgb(47, 49, 55),
            border: Color32::from_rgb(43, 45, 50),
            text: Color32::from_rgb(237, 236, 231),
            text_muted: Color32::from_rgb(171, 170, 164),
            accent: Color32::from_rgb(226, 183, 94),
            on_accent: Color32::from_rgb(23, 20, 13),
            error: Color32::from_rgb(248, 113, 113),
            success: Color32::from_rgb(134, 239, 172),
            warning: Color32::from_rgb(253, 186, 116),
        },
    },
    Theme {
        id: "light",
        label: "theme-light",
        dark: false,
        colors: Palette {
            background: Color32::from_rgb(243, 244, 246),
            surface: Color32::from_rgb(255, 255, 255),
            control: Color32::from_rgb(236, 239, 243),
            hover: Color32::from_rgb(218, 225, 235),
            pressed: Color32::from_rgb(202, 214, 230),
            border: Color32::from_rgb(209, 213, 220),
            text: Color32::from_rgb(17, 24, 39),
            text_muted: Color32::from_rgb(75, 85, 99),
            accent: Color32::from_rgb(29, 78, 216),
            on_accent: Color32::from_rgb(255, 255, 255),
            error: Color32::from_rgb(185, 28, 28),
            success: Color32::from_rgb(21, 128, 61),
            warning: Color32::from_rgb(146, 64, 14),
        },
    },
];

impl Theme {
    pub fn apply(self, ctx: &egui::Context) {
        let p = self.colors;
        let mut v = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        v.panel_fill = p.background;
        v.window_fill = p.surface;
        v.extreme_bg_color = p.background;
        v.faint_bg_color = p.control;
        v.override_text_color = Some(p.text);
        v.hyperlink_color = p.accent;
        v.error_fg_color = p.error;
        v.warn_fg_color = p.warning;
        v.selection.bg_fill = p.accent;
        v.selection.stroke = Stroke::new(1., p.on_accent);
        v.window_stroke = Stroke::new(1., p.border);
        v.text_edit_bg_color = Some(p.background);
        v.window_corner_radius = egui::CornerRadius::same(12);
        for (widget, fill) in [
            (&mut v.widgets.noninteractive, p.surface),
            (&mut v.widgets.inactive, p.control),
            (&mut v.widgets.hovered, p.hover),
            (&mut v.widgets.active, p.pressed),
            (&mut v.widgets.open, p.pressed),
        ] {
            widget.bg_fill = fill;
            widget.weak_bg_fill = fill;
            widget.bg_stroke = Stroke::new(1., p.border);
            widget.fg_stroke = Stroke::new(1., p.text);
            widget.corner_radius = egui::CornerRadius::same(crate::ui_kit::Metrics::FIELD_RADIUS);
            widget.expansion = 0.;
        }
        v.widgets.active.bg_stroke = Stroke::new(1., p.accent);
        ctx.set_theme(if self.dark {
            egui::Theme::Dark
        } else {
            egui::Theme::Light
        });
        ctx.set_visuals(v);
        ctx.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn luminance(color: Color32) -> f64 {
        let linear = |c: u8| {
            let c = f64::from(c) / 255.;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
    }
    #[test]
    fn role_contrast_and_independent_contexts() {
        for theme in THEMES {
            for index in 0..2 {
                assert_ne!(
                    crate::i18n::Localizer::new(index)
                        .unwrap()
                        .text(theme.label),
                    theme.label
                );
            }
            let p = theme.colors;
            for (fg, bg) in [
                (p.text, p.surface),
                (p.text_muted, p.surface),
                (p.on_accent, p.accent),
                (p.accent, p.surface),
                (p.error, p.surface),
                (p.warning, p.surface),
                (p.success, p.surface),
                (p.text, p.pressed),
                (p.text, p.hover),
                (p.text, p.control),
            ] {
                let (a, b) = (luminance(fg), luminance(bg));
                assert!(
                    (a.max(b) + 0.05) / (a.min(b) + 0.05) >= 4.5,
                    "{} contrast: {fg:?} on {bg:?}",
                    theme.id
                );
            }
        }
        let dark = egui::Context::default();
        let light = egui::Context::default();
        THEMES[0].apply(&dark);
        THEMES[1].apply(&light);
        assert_eq!(
            dark.global_style().visuals.panel_fill,
            THEMES[0].colors.background
        );
        assert_eq!(
            light.global_style().visuals.panel_fill,
            THEMES[1].colors.background
        );
    }
}
