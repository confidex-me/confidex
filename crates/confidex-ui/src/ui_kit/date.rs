//! Civil dates retain their precision and do not use a time zone.
use super::{Icon, Metrics as M, value};
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect};
use std::collections::BTreeMap;
use time::{Date, Month};
use zeroize::Zeroize;

pub use confidex_vault::date::{Civil, Invalid, Precision, parse};

#[derive(Clone)]
pub struct Editor {
    pub text: String,
    pub protected: bool,
    pub revealed: bool,
    pub feedback: value::CopyState,
    year: i32,
    month: u8,
}
impl Drop for Editor {
    fn drop(&mut self) {
        self.text.zeroize();
        self.year.zeroize();
        self.month.zeroize();
    }
}
pub struct Labels<'a> {
    pub name: &'a str,
    pub hint: &'a str,
    pub calendar: &'a str,
    pub value: value::Labels<'a>,
    pub invalid: &'a str,
    pub year: &'a str,
    pub month: &'a str,
    pub weekdays: [&'a str; 7],
}
pub struct Output {
    pub valid: bool,
    pub changed: bool,
    pub copy: bool,
    pub hits: BTreeMap<String, Rect>,
    pub popup: Option<Rect>,
}
impl Editor {
    pub fn new(text: &str, reference: Date) -> Self {
        let value = parse(text, Precision::Day)
            .or_else(|_| parse(text, Precision::Month))
            .ok()
            .flatten();
        Self {
            text: text.into(),
            protected: false,
            revealed: false,
            feedback: value::CopyState::Idle,
            year: value.map_or(reference.year().clamp(1, 9999), |v| i32::from(v.year)),
            month: value.map_or(reference.month() as u8, |v| v.month),
        }
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        id: Id,
        precision: Precision,
        editing: bool,
        labels: Labels<'_>,
    ) -> Output {
        let before = self.text.clone();
        let mut output = Output {
            valid: true,
            changed: false,
            copy: false,
            hits: BTreeMap::new(),
            popup: None,
        };
        let panel = id.with("calendar-panel");
        let open = editing && egui::Popup::is_id_open(ui.ctx(), panel);
        let field = value::ValueField {
            id,
            value: &mut self.text,
            kind: value::Kind::Text,
            protected: self.protected,
            editing,
            enabled: ui.is_enabled(),
            revealed: &mut self.revealed,
            feedback: self.feedback,
            labels: labels.value,
        }
        .show_action(ui, p, labels.calendar, Icon::Calendar, open, labels.hint);
        ui.ctx()
            .accesskit_node_builder(field.input.id, |node| node.set_label(labels.name));
        output.hits.insert("input".into(), field.input.rect);
        output.hits.insert("copy".into(), field.copy.rect);
        output.copy = field.copy.clicked();
        if let Some(reveal) = &field.reveal {
            output.hits.insert("hide".into(), reveal.rect);
        }
        if self.protected && !self.revealed {
            egui::Popup::close_id(ui.ctx(), panel);
        }
        if field.input.changed()
            && let Ok(Some(date)) = parse(&self.text, precision)
        {
            self.year = i32::from(date.year);
            self.month = date.month;
        }
        let toggled = field.accessory.as_ref().is_some_and(|r| r.clicked());
        if let Some(opener) = &field.accessory {
            output.hits.insert("picker".into(), opener.rect);
            if opener.clicked() {
                if let Ok(Some(date)) = parse(&self.text, precision) {
                    self.year = i32::from(date.year);
                    self.month = date.month;
                }
                egui::Popup::toggle_id(ui.ctx(), panel);
                if egui::Popup::is_id_open(ui.ctx(), panel) {
                    field.input.scroll_to_me_animation(
                        Some(egui::Align::TOP),
                        egui::style::ScrollAnimation::none(),
                    );
                } else {
                    field.input.request_focus();
                }
            }
        } else {
            egui::Popup::close_id(ui.ctx(), panel);
        }
        if editing && egui::Popup::is_id_open(ui.ctx(), panel) {
            egui::Popup::open_id(ui.ctx(), panel);
            let response = ui
                .push_id(panel, |ui| {
                    ui.add_space(M::XS);
                    ui.horizontal_wrapped(|ui| {
                        let year = ui.label(labels.year);
                        ui.add(egui::DragValue::new(&mut self.year).range(1..=9999))
                            .labelled_by(year.id);
                        let month = ui.label(labels.month);
                        ui.add(egui::DragValue::new(&mut self.month).range(1..=12))
                            .labelled_by(month.id);
                    });
                    ui.add_space(M::SM);
                    if precision == Precision::Month {
                        let cell = ((ui.available_width() - 2. * M::SM) / 3.).max(28.);
                        let height = super::density(ui).control;
                        egui::Grid::new(id.with("months"))
                            .num_columns(3)
                            .spacing([M::SM, M::XS])
                            .show(ui, |ui| {
                                ui.spacing_mut().button_padding.x = M::XS;
                                for month in 1..=12 {
                                    let r = ui.add_sized(
                                        [cell, height],
                                        egui::Button::new(format!("{month:02}"))
                                            .selected(self.month == month),
                                    );
                                    output.hits.insert(format!("month-{month}"), r.rect);
                                    if r.clicked() {
                                        self.month = month;
                                        self.text = Civil {
                                            year: self.year as u16,
                                            month,
                                            day: None,
                                        }
                                        .text();
                                        egui::Popup::close_id(ui.ctx(), panel);
                                        field.input.request_focus();
                                    }
                                    if month % 3 == 0 {
                                        ui.end_row();
                                    }
                                }
                            });
                    } else {
                        let first = Date::from_calendar_date(
                            self.year,
                            Month::try_from(self.month).unwrap(),
                            1,
                        )
                        .unwrap();
                        let offset = first.weekday().number_days_from_monday() as usize;
                        let cell = ((ui.available_width() - 6. * M::XS) / 7.).max(1.);
                        let height = super::density(ui).control;
                        let selected = parse(&self.text, precision).ok().flatten();
                        egui::Grid::new(id.with("days"))
                            .num_columns(7)
                            .min_col_width(cell)
                            .max_col_width(cell)
                            .spacing([M::XS, M::XS])
                            .show(ui, |ui| {
                                ui.spacing_mut().button_padding.x = M::XS;
                                for name in labels.weekdays {
                                    ui.add_sized([cell, 20.], egui::Label::new(name).truncate());
                                }
                                ui.end_row();
                                for slot in 0..42 {
                                    let day = slot - offset as i32 + 1;
                                    if day > 0
                                        && let Ok(date) = first.replace_day(day as u8)
                                    {
                                        let chosen = selected.is_some_and(|s| {
                                            s.year as i32 == self.year
                                                && s.month == self.month
                                                && s.day == Some(day as u8)
                                        });
                                        let r = ui.add_sized(
                                            [cell, height],
                                            egui::Button::new(day.to_string()).selected(chosen),
                                        );
                                        output.hits.insert(format!("day-{day}"), r.rect);
                                        if r.clicked() {
                                            self.text = Civil {
                                                year: date.year() as u16,
                                                month: date.month() as u8,
                                                day: Some(date.day()),
                                            }
                                            .text();
                                            egui::Popup::close_id(ui.ctx(), panel);
                                            field.input.request_focus();
                                        }
                                    } else {
                                        ui.allocate_space(egui::vec2(cell, height));
                                    }
                                    if slot % 7 == 6 {
                                        ui.end_row();
                                    }
                                }
                            });
                    }
                    ui.min_rect()
                })
                .response;
            output.popup = Some(response.rect);
            let escape =
                ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
            if escape || !toggled && response.clicked_elsewhere() {
                egui::Popup::close_id(ui.ctx(), panel);
                if escape {
                    field.input.request_focus();
                }
            }
        }
        output.valid = parse(&self.text, precision).is_ok();
        if !output.valid {
            ui.colored_label(p.error, labels.invalid);
        }
        output.changed = before != self.text;
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draw(
        ctx: &egui::Context,
        editor: &mut Editor,
        width: f32,
        events: Vec<egui::Event>,
    ) -> (Output, Rect) {
        let mut result = None;
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width + 32., 800.),
                )),
                events,
                ..Default::default()
            },
            |ui| {
                ui.set_width(width);
                let field = ui.scope(|ui| {
                    editor.show(
                        ui,
                        crate::theme::THEMES[0].colors,
                        Id::unique("date"),
                        Precision::Day,
                        true,
                        Labels {
                            name: "Date",
                            hint: "DD/MM/YYYY",
                            calendar: "Calendar",
                            invalid: "Invalid date",
                            year: "Year",
                            month: "Month",
                            weekdays: ["M", "T", "W", "T", "F", "S", "S"],
                            value: value::Labels {
                                copy: "Copy",
                                pending: "Pending",
                                copied: "Copied",
                                failed: "Failed",
                                show: "Show",
                                hide: "Hide",
                                large: "Large",
                                empty: "Empty",
                            },
                        },
                    )
                });
                result = Some((field.inner, field.response.rect));
            },
        );
        output.textures_delta.clear();
        result.unwrap()
    }
    #[test]
    fn calendar_uses_one_value_row_and_opens_inline_without_changing_the_date() {
        for width in [220., 390., 680.] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            let mut editor = Editor::new(
                "29/02/2024",
                Date::from_calendar_date(2024, Month::February, 1).unwrap(),
            );
            let mut last = None;
            for _ in 0..3 {
                last = Some(draw(&ctx, &mut editor, width, vec![]));
            }
            let (closed, rect) = last.unwrap();
            assert!(rect.height() <= 45.);
            assert!(closed.popup.is_none());
            let input = closed.hits["input"];
            assert!(input.contains_rect(closed.hits["picker"]));
            assert!((closed.hits["copy"].center().y - input.center().y).abs() < 1.);
            editor.year = 2030;
            editor.month = 12;
            let point = closed.hits["picker"].center();
            for pressed in [true, false] {
                draw(
                    &ctx,
                    &mut editor,
                    width,
                    vec![
                        egui::Event::PointerMoved(point),
                        egui::Event::PointerButton {
                            pos: point,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
            let (opened, _) = draw(&ctx, &mut editor, width, vec![]);
            assert!(opened.popup.unwrap().top() >= input.bottom());
            assert_eq!(editor.text, "29/02/2024");
            assert_eq!((editor.year, editor.month), (2024, 2));
            draw(
                &ctx,
                &mut editor,
                width,
                vec![egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            );
            assert!(draw(&ctx, &mut editor, width, vec![]).0.popup.is_none());
            assert_eq!(editor.text, "29/02/2024");
        }
    }
    #[test]
    fn civil_dates_preserve_empty_input_and_precision() {
        assert_eq!(parse("", Precision::Day), Ok(None));
        let leap = parse("29/02/2024", Precision::Day).unwrap().unwrap();
        assert_eq!(leap.text(), "29/02/2024");
        for text in [
            "29/02/2023",
            "31/04/2024",
            "00/01/2024",
            "01/13/2024",
            "01/01/0000",
            "1/2/2024",
            "2024-02-29",
            "29/02/２０２４",
            "29/02/2024 ",
        ] {
            assert!(parse(text, Precision::Day).is_err(), "{text}");
        }
        let month = parse("02/2024", Precision::Month).unwrap().unwrap();
        assert_eq!(month.day, None);
        assert_eq!(month.text(), "02/2024");
        assert!(parse("02/2024", Precision::Day).is_err());
        assert!(parse("29/02/2024", Precision::Month).is_err());
        assert!(parse("13/2024", Precision::Month).is_err());
        assert!(parse("02/", Precision::Month).is_err());
    }
}
