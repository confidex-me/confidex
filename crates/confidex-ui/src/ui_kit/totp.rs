//! TOTP presentation uses the core validator and generator.
use super::{Icon, Metrics as M, value::CopyState};
use crate::{i18n::Localizer, theme::Palette};
use confidex_vault::{
    record::{Mapping, Record, Value, ValueError},
    totp::{self, Algorithm, Code, Totp},
};
use eframe::egui::{self, Id, Rect, Response, RichText, Vec2};
use fluent_bundle::FluentArgs;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issue {
    Secret,
    Algorithm,
    Digits,
    Period,
    Start,
    Clock,
}
impl Issue {
    pub fn message(self) -> &'static str {
        match self {
            Self::Secret => "gallery-totp-error-secret",
            Self::Algorithm => "gallery-totp-error-algorithm",
            Self::Digits => "gallery-totp-error-digits",
            Self::Period => "gallery-totp-error-period",
            Self::Start => "gallery-totp-error-start",
            Self::Clock => "gallery-totp-error-clock",
        }
    }
}
fn issue(error: ValueError) -> Issue {
    match error {
        ValueError::Missing("algorithm")
        | ValueError::WrongType("algorithm")
        | ValueError::InvalidValue("algorithm") => Issue::Algorithm,
        ValueError::Missing("digits")
        | ValueError::WrongType("digits")
        | ValueError::InvalidValue("digits") => Issue::Digits,
        ValueError::Missing("period")
        | ValueError::WrongType("period")
        | ValueError::InvalidValue("period") => Issue::Period,
        ValueError::Missing("t0")
        | ValueError::WrongType("t0")
        | ValueError::InvalidValue("t0") => Issue::Start,
        _ => Issue::Secret,
    }
}

pub struct Editor {
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: String,
    pub start: String,
    pub revealed: bool,
}
impl Default for Editor {
    fn default() -> Self {
        Self {
            secret: String::new(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: "30".into(),
            start: "0".into(),
            revealed: false,
        }
    }
}
impl Drop for Editor {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.period.zeroize();
        self.start.zeroize();
    }
}
struct Parameters {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    start: u64,
}
impl Parameters {
    fn totp(&self) -> Result<Totp<'_>, Issue> {
        Totp::new(
            &self.secret,
            self.algorithm,
            self.digits,
            self.period,
            self.start,
        )
        .map_err(issue)
    }
}
impl Editor {
    pub fn read(value: &Mapping) -> Result<Self, Issue> {
        Totp::from_value(value).map_err(issue)?;
        let mut output = Self::default();
        let Value::Binary(secret) = &value["secret"] else {
            return Err(Issue::Secret);
        };
        let mut bits = 0u8;
        let mut buffer = 0u16;
        for byte in secret {
            buffer = (buffer << 8) | u16::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                output.secret.push(char::from(
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[usize::from((buffer >> bits) & 31)],
                ));
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            output.secret.push(char::from(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[usize::from((buffer << (5 - bits)) & 31)],
            ));
        }
        output.algorithm = match value.get("algorithm").and_then(Value::as_str) {
            Some("SHA256") => Algorithm::Sha256,
            Some("SHA512") => Algorithm::Sha512,
            _ => Algorithm::Sha1,
        };
        output.digits = value.get("digits").and_then(Value::as_u64).unwrap_or(6) as u8;
        output.period = value
            .get("period")
            .and_then(Value::as_u64)
            .unwrap_or(30)
            .to_string();
        output.start = value
            .get("t0")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .to_string();
        Ok(output)
    }
    fn parameters(&self) -> Result<Parameters, Issue> {
        let parameters = Parameters {
            secret: totp::decode_secret(&self.secret).map_err(|_| Issue::Secret)?,
            algorithm: self.algorithm,
            digits: self.digits,
            period: self.period.parse().map_err(|_| Issue::Period)?,
            start: self.start.parse().map_err(|_| Issue::Start)?,
        };
        parameters.totp()?;
        Ok(parameters)
    }
    pub fn apply(&self, value: &mut Mapping) -> Result<(), Issue> {
        let p = self.parameters()?;
        let algorithm = match p.algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        };
        let mut retired = Record::default();
        for (key, next) in [
            ("secret", Value::Binary(p.secret.to_vec())),
            ("algorithm", Value::from(algorithm)),
            ("digits", Value::from(p.digits)),
            ("period", Value::from(p.period)),
            ("t0", Value::from(p.start)),
        ] {
            if let Some(old) = value.insert(key.into(), next) {
                retired.extra.insert(key.into(), old);
            }
        }
        Ok(())
    }
    pub fn generate(&self, now: u64) -> Result<(Code, u32), Issue> {
        let p = self.parameters()?;
        let code = p.totp()?.generate(now).map_err(|_| Issue::Clock)?;
        Ok((code, p.period))
    }
}

pub struct Field<'a> {
    pub id: Id,
    pub value: &'a Mapping,
    pub editor: Option<&'a mut Editor>,
    pub now: Duration,
    pub enabled: bool,
    pub feedback: CopyState,
}
pub struct Output {
    pub rect: Rect,
    pub code_rect: Rect,
    pub timer_rect: Rect,
    pub copy: Response,
    pub code: Option<Code>,
    pub valid: bool,
    pub controls: Vec<(&'static str, Response)>,
}
impl Field<'_> {
    pub fn show(self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) -> Output {
        let response = ui
            .push_id(self.id, |ui| {
                ui.add_enabled_ui(self.enabled, |ui| {
                    let result = if let Some(editor) = self.editor.as_deref() {
                        editor.generate(self.now.as_secs())
                    } else {
                        Totp::from_value(self.value)
                            .map_err(issue)
                            .and_then(|totp| {
                                let period =
                                    self.value
                                        .get("period")
                                        .and_then(Value::as_u64)
                                        .unwrap_or(30) as u32;
                                totp.generate(self.now.as_secs())
                                    .map(|code| (code, period))
                                    .map_err(|_| Issue::Clock)
                            })
                    };
                    let mut output = draw_code(
                        ui,
                        p,
                        locale,
                        result,
                        self.feedback,
                        self.now.subsec_nanos(),
                    );
                    let mut controls = Vec::new();
                    if let Some(editor) = self.editor {
                        ui.add_space(M::LG);
                        let label = ui.label(locale.text("gallery-totp-secret"));
                        let width =
                            (ui.available_width() - super::density(ui).icon - M::SM).max(1.);
                        ui.horizontal(|ui| {
                            let input = ui
                                .allocate_ui_with_layout(
                                    Vec2::new(width, super::density(ui).input),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        super::field_with_id(
                                            ui,
                                            self.id.with("secret"),
                                            &mut editor.secret,
                                            !editor.revealed,
                                            false,
                                            true,
                                        )
                                        .labelled_by(label.id)
                                    },
                                )
                                .inner;
                            controls.push(("secret", input));
                            let reveal = super::icon_button(
                                ui,
                                p,
                                &locale.text(if editor.revealed {
                                    "gallery-hide-content"
                                } else {
                                    "gallery-reveal-content"
                                }),
                                if editor.revealed {
                                    Icon::EyeOff
                                } else {
                                    Icon::Eye
                                },
                                true,
                            );
                            if reveal.clicked() {
                                editor.revealed = !editor.revealed;
                            }
                            controls.push(("reveal", reveal));
                        });
                        let advanced = ui.collapsing(locale.text("gallery-totp-advanced"), |ui| {
                            let label = ui.label(locale.text("gallery-totp-algorithm"));
                            let select = super::Select::from_id_salt("algorithm")
                                .selected_text(match editor.algorithm {
                                    Algorithm::Sha1 => "SHA-1",
                                    Algorithm::Sha256 => "SHA-256",
                                    Algorithm::Sha512 => "SHA-512",
                                })
                                .width(ui.available_width())
                                .show_ui(ui, |ui| {
                                    for (index, (algorithm, name)) in [
                                        (Algorithm::Sha1, "SHA-1"),
                                        (Algorithm::Sha256, "SHA-256"),
                                        (Algorithm::Sha512, "SHA-512"),
                                    ]
                                    .into_iter()
                                    .enumerate()
                                    {
                                        let response = ui.selectable_value(
                                            &mut editor.algorithm,
                                            algorithm,
                                            name,
                                        );
                                        controls.push((
                                            ["algorithm-0", "algorithm-1", "algorithm-2"][index],
                                            response,
                                        ));
                                    }
                                });
                            controls.push(("algorithm", select.response.labelled_by(label.id)));
                            let label = ui.label(locale.text("gallery-totp-digits"));
                            let select = super::Select::from_id_salt("digits")
                                .selected_text(editor.digits.to_string())
                                .width(ui.available_width())
                                .show_ui(ui, |ui| {
                                    for digits in 6..=8 {
                                        let response = ui.selectable_value(
                                            &mut editor.digits,
                                            digits,
                                            digits.to_string(),
                                        );
                                        controls.push((
                                            ["digits-6", "digits-7", "digits-8"]
                                                [usize::from(digits - 6)],
                                            response,
                                        ));
                                    }
                                });
                            controls.push(("digits", select.response.labelled_by(label.id)));
                            for (key, label_key, value) in [
                                ("period", "gallery-totp-period", &mut editor.period),
                                ("start", "gallery-totp-start", &mut editor.start),
                            ] {
                                let label = ui.label(locale.text(label_key));
                                let input = super::field_with_id(
                                    ui,
                                    self.id.with(key),
                                    value,
                                    false,
                                    false,
                                    true,
                                )
                                .labelled_by(label.id);
                                controls.push((key, input));
                            }
                        });
                        controls.push(("advanced", advanced.header_response));
                        output.valid = editor.parameters().is_ok();
                    }
                    output.controls = controls;
                    output
                })
            })
            .inner;
        let mut output = response.inner;
        output.rect = response.response.rect;
        if self.enabled {
            ui.ctx().request_repaint_after(Duration::from_millis(33));
        }
        output
    }
}
fn draw_code(
    ui: &mut egui::Ui,
    p: Palette,
    locale: &Localizer,
    result: Result<(Code, u32), Issue>,
    feedback: CopyState,
    nanoseconds: u32,
) -> Output {
    ui.add_space(M::SM);
    let error = result.as_ref().err().copied();
    let valid = error.is_none_or(|error| error == Issue::Clock);
    let remaining = result
        .as_ref()
        .map_or(0, |(code, _)| code.valid_for_seconds);
    let period = result.as_ref().map_or(30, |(_, period)| *period);
    let display = Zeroizing::new(result.as_ref().map_or_else(
        |_| "—".to_owned(),
        |(code, _)| {
            let text = code.as_str();
            let split = text.len() / 2;
            format!("{} {}", &text[..split], &text[split..])
        },
    ));
    let mut code_rect = Rect::NOTHING;
    let mut timer_rect = Rect::NOTHING;
    let mut copy = None;
    let rect = ui
        .horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = M::SM;
            let diameter = super::density(ui).input.max(40.);
            let width =
                (ui.available_width() - super::density(ui).icon - diameter - 2. * M::SM).max(1.);
            code_rect = ui
                .allocate_ui_with_layout(
                    Vec2::new(width, 56.),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        egui::Frame::new()
                            .fill(p.background)
                            .stroke(egui::Stroke::new(1., p.border))
                            .corner_radius(M::FIELD_RADIUS)
                            .inner_margin(egui::Margin::symmetric(M::MD as i8, 8))
                            .show(ui, |ui| {
                                ui.set_min_width((width - 2. * M::MD - 2.).max(1.));
                                let measured = ui
                                    .fonts_mut(|fonts| {
                                        fonts.layout_no_wrap(
                                            display.to_string(),
                                            egui::FontId::monospace(32.),
                                            p.text,
                                        )
                                    })
                                    .size()
                                    .x;
                                let size = 32. * (ui.available_width() / measured.max(1.)).min(1.);
                                ui.label(
                                    RichText::new(display.as_str())
                                        .font(egui::FontId::monospace(size)),
                                );
                            })
                            .response
                            .rect
                    },
                )
                .inner;
            let mut args = FluentArgs::new();
            args.set("value", remaining);
            let label = if error.is_none() {
                locale.format("gallery-totp-remaining", &args)
            } else {
                locale.text("gallery-totp-no-code")
            };
            let fraction = ((f64::from(remaining) - f64::from(nanoseconds) / 1e9)
                / f64::from(period))
            .clamp(0., 1.) as f32;
            timer_rect = countdown(ui, p, diameter, remaining, period, fraction, &label).rect;
            let (icon, label) = match feedback {
                CopyState::Idle => (Icon::Copy, "vault-copy-value"),
                CopyState::Pending => (Icon::Refresh, "gallery-copy-pending"),
                CopyState::Copied => (Icon::Check, "gallery-copied"),
                CopyState::Failed => (Icon::Alert, "gallery-copy-failed"),
            };
            copy = Some(super::icon_button(
                ui,
                p,
                &locale.text(label),
                icon,
                result.is_ok() && feedback != CopyState::Pending,
            ));
        })
        .response
        .rect;
    if let Some(error) = error {
        ui.label(RichText::new(locale.text(error.message())).color(p.error));
    }
    Output {
        rect,
        code_rect,
        timer_rect,
        copy: copy.unwrap(),
        code: result.ok().map(|(code, _)| code),
        valid,
        controls: Vec::new(),
    }
}
fn countdown(
    ui: &mut egui::Ui,
    p: Palette,
    diameter: f32,
    seconds: u32,
    period: u32,
    fraction: f32,
    label: &str,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(diameter), egui::Sense::hover());
    let radius = diameter / 2. - 3.;
    ui.painter()
        .circle_stroke(rect.center(), radius, egui::Stroke::new(3., p.border));
    if fraction > 0. {
        let points = (0..=64)
            .map(|step| {
                let angle = -std::f32::consts::FRAC_PI_2
                    + std::f32::consts::TAU * fraction * step as f32 / 64.;
                rect.center() + Vec2::angled(angle) * radius
            })
            .collect();
        ui.painter()
            .add(egui::Shape::line(points, egui::Stroke::new(3., p.accent)));
    }
    let text = seconds.to_string();
    let measured = ui
        .fonts_mut(|fonts| {
            fonts.layout_no_wrap(
                period.to_string(),
                egui::FontId::monospace(M::LABEL),
                p.text,
            )
        })
        .size()
        .x;
    let font = egui::FontId::monospace(M::LABEL * ((diameter - 12.) / measured.max(1.)).min(1.));
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        font,
        p.text,
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::ProgressIndicator, true, label));
    response.on_hover_text(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Mapping {
        Mapping::from_iter([
            (
                "secret".into(),
                Value::Binary(b"12345678901234567890".to_vec()),
            ),
            ("future".into(), Value::Binary(vec![4, 2])),
        ])
    }
    #[test]
    fn editor_round_trips_base32_and_preserves_unknown_values() {
        for length in 1..=totp::MAX_SECRET {
            let mut value = fixture();
            value.insert(
                "secret".into(),
                Value::Binary((0..length).map(|n| n as u8).collect()),
            );
            let mut editor = Editor::read(&value).unwrap();
            for algorithm in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
                for digits in 6..=8 {
                    editor.algorithm = algorithm;
                    editor.digits = digits;
                    editor.apply(&mut value).unwrap();
                    assert_eq!(
                        value["secret"],
                        Value::Binary((0..length).map(|n| n as u8).collect())
                    );
                    assert_eq!(value["future"], Value::Binary(vec![4, 2]));
                    assert_eq!(
                        editor.generate(59).unwrap().0.as_str(),
                        Totp::from_value(&value)
                            .unwrap()
                            .generate(59)
                            .unwrap()
                            .as_str()
                    );
                }
            }
        }
    }
    #[test]
    fn boundaries_leading_zeroes_and_validation_use_core_rules() {
        let mut value = fixture();
        let mut editor = Editor::read(&value).unwrap();
        assert_eq!(editor.generate(59).unwrap().0.as_str(), "287082");
        assert_eq!(editor.generate(59).unwrap().0.valid_for_seconds, 1);
        assert_eq!(editor.generate(60).unwrap().0.valid_for_seconds, 30);
        assert_ne!(
            editor.generate(59).unwrap().0.as_str(),
            editor.generate(60).unwrap().0.as_str()
        );
        editor.digits = 8;
        assert_eq!(
            editor.generate(1_111_111_109).unwrap().0.as_str(),
            "07081804"
        );
        let before = value.clone();
        for bad in ["", "!bad!", "a b", &"A".repeat(209)] {
            editor.secret = bad.into();
            assert_eq!(editor.apply(&mut value), Err(Issue::Secret));
            assert_eq!(value, before);
        }
        editor = Editor::read(&value).unwrap();
        for bad in ["0", "86401", "-1", "not a number", "4294967296"] {
            editor.period = bad.into();
            assert_eq!(editor.apply(&mut value), Err(Issue::Period));
            assert_eq!(value, before);
        }
        editor.period = "30".into();
        editor.start = "18446744073709551616".into();
        assert_eq!(editor.apply(&mut value), Err(Issue::Start));
        editor.start = "60".into();
        assert!(matches!(editor.generate(59), Err(Issue::Clock)));
        editor.apply(&mut value).unwrap();
        assert_eq!(editor.generate(60).unwrap().0.valid_for_seconds, 30);
    }
    #[test]
    fn code_timer_and_copy_keep_their_slots_at_rollover_and_in_the_editor() {
        for screen_width in [390., 1320.] {
            for width in [240., 320., 680.] {
                let ctx = egui::Context::default();
                super::super::setup(&ctx);
                let value = fixture();
                let mut editor = Editor::read(&value).unwrap();
                let locale = Localizer::new(1).unwrap();
                let id = Id::unique("totp-test");
                let mut baseline = None;
                for editing in [false, true] {
                    for seconds in [59, 60, 61] {
                        for frame in 0..3 {
                            let mut bounds = None;
                            if editing && seconds == 59 && frame == 0 {
                                ctx.memory_mut(|memory| memory.request_focus(id.with("secret")));
                            }
                            let mut output =
                                ctx.run_ui(
                                    egui::RawInput {
                                        screen_rect: Some(Rect::from_min_size(
                                            egui::Pos2::ZERO,
                                            Vec2::new(screen_width, 900.),
                                        )),
                                        ..Default::default()
                                    },
                                    |ui| {
                                        super::super::apply_density(ui.ctx(), false);
                                        ui.set_width(width);
                                        let output = Field {
                                            id,
                                            value: &value,
                                            editor: editing.then_some(&mut editor),
                                            now: Duration::from_secs(seconds),
                                            enabled: true,
                                            feedback: CopyState::Idle,
                                        }
                                        .show(ui, crate::theme::THEMES[0].colors, &locale);
                                        let geometry =
                                            (output.code_rect, output.timer_rect, output.copy.rect);
                                        assert!(geometry.0.right() <= geometry.1.left());
                                        assert!(geometry.1.right() <= geometry.2.left());
                                        assert!(
                                            (geometry.1.center().y - geometry.2.center().y).abs()
                                                < 1.
                                        );
                                        assert!(output.rect.contains_rect(geometry.2));
                                        if editing {
                                            assert!(!editor.revealed);
                                            if frame == 2 {
                                                assert!(
                                                    output
                                                        .controls
                                                        .iter()
                                                        .find(|(name, _)| *name == "secret")
                                                        .unwrap()
                                                        .1
                                                        .has_focus()
                                                );
                                            }
                                        }
                                        bounds = Some(geometry);
                                    },
                                );
                            output.textures_delta.clear();
                            assert!(!output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(t) if t.galley.job.text.contains("GEZDGNBV"))));
                            if frame == 2 {
                                let geometry = bounds.unwrap();
                                if let Some(baseline) = baseline {
                                    assert_eq!(baseline, geometry);
                                } else {
                                    baseline = Some(geometry);
                                }
                                let seconds = (if seconds == 59 {
                                    1
                                } else {
                                    30 - (seconds - 60)
                                })
                                .to_string();
                                let text = output
                                    .shapes
                                    .iter()
                                    .find_map(|shape| match &shape.shape {
                                        egui::Shape::Text(t) if t.galley.job.text == seconds => {
                                            Some(t)
                                        }
                                        _ => None,
                                    })
                                    .unwrap();
                                assert!(
                                    (text.pos + text.galley.size() / 2.)
                                        .distance(geometry.1.center())
                                        < 0.1
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
