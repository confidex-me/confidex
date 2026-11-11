//! Card fields use the existing encrypted value schema.
use super::{Metrics as M, value};
use crate::theme::Palette;
use confidex_vault::record::{Mapping, Record, Value};
use eframe::egui::{self, Id};
use zeroize::Zeroizing;

pub const FIELDS: [&str; 6] = ["number", "holder", "expiry", "cvv", "pin", "brand"];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Unknown,
    Known { network: &'static str, valid: bool },
}
pub fn check(number: &str) -> Check {
    let digits = number
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'-');
    let head = digits.clone().take(4).collect::<Vec<_>>();
    let prefix = head.iter().try_fold(0u16, |n, b| {
        b.is_ascii_digit().then(|| n * 10 + u16::from(b - b'0'))
    });
    let network = if head.first() == Some(&b'4') {
        "Visa"
    } else if (head.first() == Some(&b'5')
        && head.get(1).is_some_and(|b| (b'1'..=b'5').contains(b)))
        || (head.len() == 4 && prefix.is_some_and(|n| (2221..=2720).contains(&n)))
    {
        "Mastercard"
    } else {
        return Check::Unknown;
    };
    let valid = digits.clone().all(|b| b.is_ascii_digit())
        && digits
            .rev()
            .enumerate()
            .map(|(i, b)| {
                let n = b - b'0';
                if i % 2 == 1 {
                    let doubled = n * 2;
                    if doubled > 9 { doubled - 9 } else { doubled }
                } else {
                    n
                }
            })
            .map(u64::from)
            .sum::<u64>()
            % 10
            == 0;
    Check::Known { network, valid }
}
#[derive(Default)]
pub struct State {
    revealed: [bool; 6],
}
impl State {
    pub fn conceal(&mut self) {
        self.revealed.fill(false);
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        card: Card<'_>,
    ) -> Vec<(&'static str, value::Output)> {
        let mut output = Vec::new();
        let mut retired = Record::default();
        for (index, key) in FIELDS.into_iter().enumerate() {
            let mut text = match card.values.get(key) {
                Some(value) => match value.as_str() {
                    Some(text) => Zeroizing::new(text.to_owned()),
                    None => {
                        ui.label(card.labels.unsupported);
                        continue;
                    }
                },
                None => Zeroizing::new(String::new()),
            };
            if !card.editing && text.is_empty() {
                continue;
            }
            ui.add_space(M::MD);
            ui.label(card.labels.fields[index]);
            let secret = card.protected || matches!(key, "number" | "cvv" | "pin");
            let field = value::ValueField {
                id: card.id.with(key),
                value: &mut text,
                kind: if secret {
                    value::Kind::Password
                } else {
                    value::Kind::Text
                },
                protected: secret,
                editing: card.editing,
                enabled: true,
                revealed: &mut self.revealed[index],
                feedback: card.feedback[index],
                labels: card.labels.value,
            }
            .show(ui, p);
            if card.editing
                && field.input.changed()
                && let Some(old) = card
                    .values
                    .insert(key.into(), Value::from(text.to_string()))
            {
                retired.extra.insert(key.into(), old);
            }
            if key == "number"
                && card.editing
                && text.bytes().filter(u8::is_ascii_digit).count() >= 13
            {
                let (caption, color) = match check(&text) {
                    Check::Unknown => (card.labels.unchecked.to_owned(), p.text_muted),
                    Check::Known { network, valid } => (
                        format!(
                            "{network} · {}",
                            if valid {
                                card.labels.valid
                            } else {
                                card.labels.invalid
                            }
                        ),
                        if valid { p.success } else { p.error },
                    ),
                };
                ui.label(egui::RichText::new(caption).small().color(color));
            }
            output.push((key, field));
        }
        output
    }
}
pub struct Labels<'a> {
    pub fields: [&'a str; 6],
    pub value: value::Labels<'a>,
    pub unsupported: &'a str,
    pub unchecked: &'a str,
    pub valid: &'a str,
    pub invalid: &'a str,
}
pub struct Card<'a> {
    pub id: Id,
    pub values: &'a mut Mapping,
    pub editing: bool,
    pub protected: bool,
    pub feedback: [value::CopyState; 6],
    pub labels: Labels<'a>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn view_conceals_secrets_and_fits_both_widths() {
        for (width, protected) in [(320., false), (320., true), (720., false), (720., true)] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            let mut state = State::default();
            let mut values = Mapping::from([
                ("number".into(), Value::from("4111 1111 1111 1111")),
                ("cvv".into(), Value::from("123")),
                ("holder".into(), Value::from("ALEX EXAMPLE")),
            ]);
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 1100.),
                    )),
                    ..Default::default()
                },
                |ui| {
                    super::super::apply_density(ui.ctx(), false);
                    let output = state.show(
                        ui,
                        crate::theme::THEMES[0].colors,
                        Card {
                            id: Id::unique("card"),
                            values: &mut values,
                            editing: false,
                            protected,
                            feedback: [value::CopyState::Idle; 6],
                            labels: Labels {
                                fields: ["Number", "Holder", "Expiry", "CVV", "PIN", "Brand"],
                                unsupported: "Unsupported",
                                unchecked: "Unchecked",
                                valid: "Checksum matches",
                                invalid: "Checksum does not match",
                                value: value::Labels {
                                    copy: "Copy",
                                    pending: "Pending",
                                    copied: "Copied",
                                    failed: "Failed",
                                    show: "Reveal",
                                    hide: "Hide",
                                    large: "Large",
                                    empty: "Empty",
                                },
                            },
                        },
                    );
                    for (_, r) in output {
                        assert!(r.rect.right() <= ui.max_rect().right() + 1.);
                    }
                },
            );
            out.textures_delta.clear();
            for shape in out.shapes {
                if let egui::Shape::Text(text) = shape.shape {
                    assert!(!text.galley.job.text.contains("4111 1111 1111 1111"));
                    assert_ne!(text.galley.job.text, "123");
                    if protected {
                        assert!(!text.galley.job.text.contains("ALEX EXAMPLE"));
                    }
                }
            }
        }
    }
    #[test]
    fn only_known_ranges_use_luhn() {
        for number in [
            "4111 1111 1111 1111",
            "5555-5555-5555-4444",
            "2221000000000009",
            "4000000000000000006",
        ] {
            assert!(
                matches!(check(number), Check::Known { valid: true, .. }),
                "{number}"
            );
        }
        for number in [
            "4111111111111112",
            "5555555555554445",
            "41111111111111O1",
            "4",
        ] {
            assert!(matches!(check(number), Check::Known { valid: false, .. }));
        }
        for number in [
            "",
            "9900123456789012",
            "LOCAL-1234",
            "5000000000000000",
            "5600000000000000",
            "2220000000000000",
            "2721000000000000",
        ] {
            assert_eq!(check(number), Check::Unknown);
        }
        assert!(matches!(
            check("2720000000000000"),
            Check::Known {
                network: "Mastercard",
                ..
            }
        ));
    }
}
