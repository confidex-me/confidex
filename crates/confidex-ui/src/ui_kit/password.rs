//! Local, pattern-aware estimates for password editors.
use super::{Metrics as M, value};
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect};
mod assessment;
mod generator;
pub use assessment::{Completion, Evaluator, Report, assess};
pub use generator::Config as GeneratorPreferences;

#[derive(Clone, Copy)]
pub struct GeneratorLabels<'a> {
    pub generate: &'a str,
    pub symbols: &'a str,
    pub words: &'a str,
    pub length: &'a str,
    pub count: &'a str,
    pub classes: [&'a str; 5],
    pub exclude_similar: &'a str,
    pub again: &'a str,
    pub use_password: &'a str,
    pub close: &'a str,
    pub separators: &'a str,
    pub entropy: &'a str,
    pub parameters: &'a str,
    pub random: &'a str,
}
impl<'a> GeneratorLabels<'a> {
    pub fn new(labels: &'a [String; 18]) -> Self {
        Self {
            generate: &labels[0],
            symbols: &labels[1],
            words: &labels[2],
            length: &labels[3],
            count: &labels[4],
            classes: [&labels[5], &labels[6], &labels[7], &labels[8], &labels[17]],
            exclude_similar: &labels[9],
            again: &labels[10],
            use_password: &labels[11],
            close: &labels[12],
            separators: &labels[16],
            entropy: &labels[13],
            parameters: &labels[14],
            random: &labels[15],
        }
    }
}
pub struct GeneratorOutput {
    pub opener: egui::Response,
    pub popup: Option<Rect>,
    pub preview: Option<Rect>,
    pub controls: Vec<(&'static str, egui::Response)>,
    pub changed: bool,
}
pub struct Field<'a> {
    pub value: value::ValueField<'a>,
    pub strength: Labels<'a>,
    pub generator: GeneratorLabels<'a>,
    pub preferences: &'a mut GeneratorPreferences,
    pub evaluator: &'a mut Evaluator,
}
pub struct FieldOutput {
    pub value: value::Output,
    pub strength: Option<Rect>,
    pub generator: Option<GeneratorOutput>,
}
impl Field<'_> {
    pub fn show(mut self, ui: &mut egui::Ui, p: Palette) -> FieldOutput {
        let id = self.value.id;
        let show_strength = self.value.editing || *self.value.revealed;
        let active = egui::Popup::is_id_open(ui.ctx(), id.with("generator-popup"));
        let label = if active {
            self.generator.close
        } else {
            self.generator.generate
        };
        let mut value = value::ValueField {
            value: &mut *self.value.value,
            revealed: &mut *self.value.revealed,
            kind: value::Kind::Password,
            ..self.value
        }
        .show_password(ui, p, label, active);
        let strength = strength(
            self.evaluator,
            ui,
            p,
            id,
            show_strength.then_some(self.value.value.as_str()),
            self.strength,
        );
        let generator = if value.accessory.is_some() {
            let output = generator_panel(ui, p, &mut self, &value);
            if output.changed {
                value.input.mark_changed();
            }
            Some(output)
        } else {
            close_generator(ui.ctx(), id);
            None
        };
        FieldOutput {
            value,
            strength,
            generator,
        }
    }
}
pub fn close_generator(ctx: &egui::Context, id: Id) {
    let popup = id.with("generator-popup");
    if egui::Popup::is_id_open(ctx, popup) {
        egui::Popup::close_id(ctx, popup);
    }
    ctx.data_mut(|data| data.remove::<generator::State>(id.with("generator-state")));
}
pub fn finish(ctx: &egui::Context) {
    if !egui::Popup::is_any_open(ctx) {
        ctx.data_mut(|data| data.remove_by_type::<generator::State>());
    }
}
fn generator_panel(
    ui: &mut egui::Ui,
    p: Palette,
    editor: &mut Field<'_>,
    field: &value::Output,
) -> GeneratorOutput {
    let id = editor.value.id;
    let password = &mut *editor.value.value;
    let preferences = &mut *editor.preferences;
    let labels = editor.generator;
    let strength_labels = editor.strength;
    let evaluator = &mut *editor.evaluator;
    let opener = field.accessory.as_ref().unwrap().clone();
    let input = &field.input;
    let popup_id = id.with("generator-popup");
    let cache = id.with("generator-state");
    let mut state = ui
        .data_mut(|data| data.remove_temp::<generator::State>(cache))
        .unwrap_or_default();
    state.config = *preferences;
    let toggled_closed = opener.clicked() && egui::Popup::is_id_open(ui.ctx(), popup_id);
    if opener.clicked() {
        if !egui::Popup::is_id_open(ui.ctx(), popup_id) {
            state.regenerate();
            input.scroll_to_me_animation(
                Some(egui::Align::TOP),
                egui::style::ScrollAnimation::none(),
            );
        }
        egui::Popup::toggle_id(ui.ctx(), popup_id);
        ui.ctx().request_repaint();
    }
    if !opener.enabled() {
        close_generator(ui.ctx(), id);
    }
    let mut controls = Vec::new();
    let mut changed = false;
    let mut restore_focus = toggled_closed;
    let width = ui.available_width();
    let mut preview = None;
    let popup = if egui::Popup::is_id_open(ui.ctx(), popup_id) {
        egui::Popup::open_id(ui.ctx(), popup_id);
        Some(
            ui.push_id(popup_id, |ui| {
                ui.set_width(width);
                ui.add_space(M::XS);
                super::card(p).show(ui, |ui| {
                    preview = Some(
                        egui::Frame::new()
                            .fill(p.background)
                            .stroke(egui::Stroke::new(1., p.border))
                            .corner_radius(M::FIELD_RADIUS)
                            .inner_margin(M::MD)
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                if let Some(error) = state.error {
                                    let message = match error {
                                        generator::Error::Parameters => labels.parameters,
                                        generator::Error::Random => labels.random,
                                    };
                                    ui.label(egui::RichText::new(message).color(p.error));
                                } else {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(state.candidate.as_str())
                                                .monospace(),
                                        )
                                        .selectable(true)
                                        .wrap(),
                                    );
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "≈{:.0} {}",
                                            state.bits, labels.entropy
                                        ))
                                        .size(M::CAPTION)
                                        .color(p.text_muted),
                                    );
                                }
                            })
                            .response
                            .rect,
                    );
                    ui.add_space(M::SM);
                    ui.horizontal(|ui| {
                        let r =
                            super::icon_button(ui, p, labels.again, super::Icon::Generate, true);
                        if r.clicked() {
                            state.regenerate();
                            ui.ctx().request_repaint();
                        }
                        controls.push(("again", r));
                        let valid = state.error.is_none() && !state.candidate.is_empty();
                        let r = super::button(
                            ui,
                            p,
                            labels.use_password,
                            super::ButtonRole::Primary,
                            0.,
                            valid,
                        );
                        if r.clicked() {
                            use zeroize::Zeroize;
                            password.zeroize();
                            password.push_str(&state.candidate);
                            changed = true;
                            restore_focus = true;
                            egui::Popup::close_id(ui.ctx(), popup_id);
                        }
                        controls.push(("use", r));
                    });
                    strength(
                        evaluator,
                        ui,
                        p,
                        id.with("candidate"),
                        Some(&state.candidate),
                        strength_labels,
                    );
                    ui.add_space(M::MD);
                    ui.separator();
                    ui.add_space(M::SM);
                    let before = state.config;
                    super::layout::grid(ui, "generator-mode", 2, 80., 2, M::SM, |ui, index| {
                        let words = index == 1;
                        let (label, key) = if words {
                            (labels.words, "words")
                        } else {
                            (labels.symbols, "symbols")
                        };
                        let r = generator_toggle(ui, p, label, state.config.words == words);
                        if r.clicked() {
                            state.config.words = words;
                        }
                        controls.push((key, r));
                    });
                    ui.add_space(M::SM);
                    ui.spacing_mut().slider_width = (ui.available_width() - 128.).max(24.);
                    let r = if state.config.words {
                        ui.add(
                            egui::Slider::new(&mut state.config.count, 1..=10).text(labels.count),
                        )
                    } else {
                        ui.add(
                            egui::Slider::new(&mut state.config.length, 8..=64).text(labels.length),
                        )
                    };
                    controls.push(("length", r));
                    {
                        ui.add_space(M::SM);
                        if state.config.words {
                            ui.label(labels.separators);
                        }
                        let row_width = ui.available_width();
                        super::layout::flow(ui, M::LG, |ui| {
                            for index in 0..6 {
                                let (label, key, checked) = if index < 5 {
                                    (
                                        labels.classes[index],
                                        [
                                            "lower",
                                            "upper",
                                            "digits",
                                            "punctuation",
                                            "other-punctuation",
                                        ][index],
                                        &mut state.config.classes[index],
                                    )
                                } else {
                                    (
                                        labels.exclude_similar,
                                        "exclude-similar",
                                        &mut state.config.exclude_similar,
                                    )
                                };
                                let font = egui::TextStyle::Button.resolve(ui.style());
                                let text_width = ui.fonts_mut(|fonts| {
                                    fonts.layout_no_wrap(label.into(), font, p.text).size().x
                                });
                                let width = (text_width
                                    + ui.spacing().icon_width
                                    + ui.spacing().icon_spacing
                                    + M::XS)
                                    .min(row_width);
                                if ui.available_size_before_wrap().x < width {
                                    ui.end_row();
                                }
                                let r = super::checkbox(ui, checked, label);
                                controls.push((key, r));
                            }
                        });
                    }
                    if before != state.config {
                        state.regenerate();
                        ui.ctx().request_repaint();
                    }
                })
            })
            .inner
            .response,
        )
    } else {
        None
    };
    if let Some(response) = &popup {
        let escape = ui.input(|input| input.key_pressed(egui::Key::Escape));
        if escape
            || (!opener.clicked()
                && !controls.iter().any(|(_, r)| r.clicked())
                && response.clicked_elsewhere())
        {
            egui::Popup::close_id(ui.ctx(), popup_id);
            restore_focus |= escape;
        }
    }
    let popup = popup.map(|response| response.rect);
    if !egui::Popup::is_id_open(ui.ctx(), popup_id) {
        state.clear();
        if restore_focus || ui.input(|input| input.key_pressed(egui::Key::Escape)) {
            input.request_focus();
        }
    }
    *preferences = state.config;
    ui.data_mut(|data| {
        data.insert_temp(cache, state);
    });
    GeneratorOutput {
        opener,
        popup,
        preview,
        controls,
        changed,
    }
}

fn generator_toggle(ui: &mut egui::Ui, p: Palette, label: &str, selected: bool) -> egui::Response {
    ui.add(
        egui::Button::selectable(selected, egui::RichText::new(label).color(p.text))
            .fill(p.control)
            .stroke(egui::Stroke::new(
                1.,
                if selected { p.accent } else { p.border },
            ))
            .corner_radius(M::FIELD_RADIUS)
            .min_size(egui::vec2(ui.available_width(), super::density(ui).control))
            .wrap(),
    )
}

#[derive(Clone, Copy)]
pub struct Labels<'a> {
    pub levels: [&'a str; 5],
    pub bits: &'a str,
    pub limit: &'a str,
    pub hint: &'a str,
    pub checking: &'a str,
    pub unavailable: &'a str,
    pub advice: [&'a str; 8],
}
impl<'a> Labels<'a> {
    pub fn new(text: &'a [String; 18]) -> Self {
        Self {
            levels: std::array::from_fn(|i| text[i].as_str()),
            bits: &text[5],
            limit: &text[6],
            hint: &text[7],
            checking: &text[8],
            unavailable: &text[9],
            advice: std::array::from_fn(|i| text[10 + i].as_str()),
        }
    }
}
pub fn strength(
    evaluator: &mut Evaluator,
    ui: &mut egui::Ui,
    p: Palette,
    id: Id,
    password: Option<&str>,
    labels: Labels<'_>,
) -> Option<Rect> {
    let result = evaluator.update(ui.ctx(), id, password);
    let password = password.filter(|password| !password.is_empty())?;
    let limited = password.chars().nth(100).is_some();
    let report = result.and_then(Result::ok);
    let score = report.map_or(0, |report| report.score);
    Some(
        ui.vertical(|ui| {
            ui.add_space(M::XS);
            let (rect, response) =
                ui.allocate_exact_size(egui::vec2(ui.available_width(), 4.), egui::Sense::hover());
            let color = match score {
                0 | 1 => p.error,
                2 => p.warning,
                _ => p.success,
            };
            let width = (rect.width() - 4. * M::XS).max(0.) / 5.;
            for i in 0..5 {
                let segment = Rect::from_min_size(
                    rect.min + egui::vec2(i as f32 * (width + M::XS), 0.),
                    egui::vec2(width, rect.height()),
                );
                ui.painter().rect_filled(
                    segment,
                    2.,
                    if report.is_some() && i <= score {
                        color
                    } else {
                        p.border
                    },
                );
            }
            response.on_hover_text(labels.hint);
            let text = match result {
                Some(Ok(report)) => format!(
                    "{} · ≈{:.0} {}",
                    labels.levels[report.score], report.bits, labels.bits
                ),
                Some(Err(())) => labels.unavailable.to_owned(),
                None => labels.checking.to_owned(),
            };
            ui.label(
                egui::RichText::new(text)
                    .size(M::CAPTION)
                    .color(p.text_muted),
            )
            .on_hover_text(labels.hint);
            if let Some(advice) = report.and_then(|report| report.advice) {
                ui.label(
                    egui::RichText::new(labels.advice[advice])
                        .size(M::CAPTION)
                        .color(p.text_muted),
                );
            }
            if limited {
                ui.label(
                    egui::RichText::new(labels.limit)
                        .size(M::CAPTION)
                        .color(p.text_muted),
                );
            }
        })
        .response
        .rect,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn patterns_matter_more_than_character_classes() {
        let strong = assess("trawler meadow cinnamon telescope").bits;
        for password in [
            "P@ssword1!",
            "1234567890",
            "qwertyuiop",
            "aaaaaaaaaaaaaaaaaaaa",
            "01/01/2024",
            "Robert",
        ] {
            let report = assess(password);
            assert!(report.bits < strong && report.score <= 1 && report.advice.is_some());
        }
        assert!(assess("k8J!b2Qz%7mT4v$R").bits > 40.);
        assert_eq!(assess("").bits, 0.);
        assert!(assess(&"密码🗝️".repeat(1000)).valid());
    }
    #[test]
    fn long_password_is_preserved_and_analysis_is_bounded() {
        let ctx = egui::Context::default();
        let text = "密码🗝️".repeat(1000);
        let original = text.clone();
        let id = Id::unique("password-test");
        let mut evaluator = Evaluator::default();
        let locale = crate::i18n::Localizer::new(0).unwrap();
        let text_labels = locale.password_strength();
        let mut output = ctx.run_ui(Default::default(), |ui| {
            assert!(
                strength(
                    &mut evaluator,
                    ui,
                    crate::theme::THEMES[0].colors,
                    id,
                    Some(&text),
                    Labels::new(&text_labels)
                )
                .is_some()
            );
            assert!(
                strength(
                    &mut evaluator,
                    ui,
                    crate::theme::THEMES[0].colors,
                    id,
                    None,
                    Labels::new(&text_labels)
                )
                .is_none()
            );
        });
        output.textures_delta.clear();
        assert!(evaluator.report(id).is_none());
        assert_eq!(text, original);
    }
}
