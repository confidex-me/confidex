use super::*;
use confidex_app::import::formats::csv::TARGETS;

impl State {
    pub(super) fn csv_valid(&self) -> bool {
        self.csv.as_ref().is_some_and(|setup| {
            setup
                .mapping
                .columns
                .iter()
                .filter(|column| column.target == "title")
                .count()
                <= 1
                && setup.mapping.columns.iter().all(|column| {
                    column.name.len() <= 4096 && TARGETS.contains(&column.target.as_str())
                })
        })
    }
    pub(super) fn csv_configure(&mut self, keep: bool) {
        let Some(setup) = &self.csv else {
            return;
        };
        let command = flow::Command::ConfigureCsv {
            operation: self
                .operation
                .checked_add(1)
                .expect("import operation exhausted"),
            token: setup.token,
            delimiter: setup.mapping.delimiter,
            header: setup.mapping.header,
        };
        self.csv_keep_mapping = keep;
        self.operation = command.operation().unwrap();
        self.events.push(Event::Request(command));
    }
    pub(super) fn csv_preview(&mut self) {
        let Some(setup) = &self.csv else {
            return;
        };
        let command = flow::Command::PreviewCsv {
            operation: self
                .operation
                .checked_add(1)
                .expect("import operation exhausted"),
            token: setup.token,
            mapping: setup.mapping.clone(),
        };
        self.operation = command.operation().unwrap();
        self.events.push(Event::Request(command));
    }
    pub(super) fn csv_form(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        locale: &Localizer,
        height: f32,
    ) {
        let focus_column = self.focus_action && !self.csv_valid();
        let Some(mut setup) = self.csv.take() else {
            return;
        };
        let top = ui.cursor().top();
        ui.label(RichText::new(locale.text("import-csv-title")).font(fonts::semibold(M::HEADING)));
        kit::muted(ui, p, setup.file.name.clone());
        ui.add_space(M::SM);
        let header = kit::checkbox(
            ui,
            &mut setup.mapping.header,
            locale.text("import-csv-header"),
        );
        let mut configure = header.changed();
        self.hits.insert("import-csv-header".into(), header.rect);
        ui.add_space(M::SM);
        layout::grid(ui, "import-csv-controls", 2, 220., 2, M::MD, |ui, index| {
            if index == 0 {
                ui.label(locale.text("import-csv-delimiter"));
                let label = delimiter_name(setup.mapping.delimiter, locale);
                let response = kit::Select::from_id_salt("csv-delimiter")
                    .selected_text(label)
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        for (id, delimiter) in [
                            ("comma", b','),
                            ("semicolon", b';'),
                            ("tab", b'\t'),
                            ("pipe", b'|'),
                        ] {
                            let response = ui.selectable_value(
                                &mut setup.mapping.delimiter,
                                delimiter,
                                delimiter_name(delimiter, locale),
                            );
                            configure |= response.changed();
                            if response.clicked() {
                                ui.close();
                            }
                            self.hits
                                .insert(format!("import-csv-delimiter-{id}"), response.rect);
                        }
                    });
                self.hits
                    .insert("import-csv-delimiter".into(), response.response.rect);
            } else {
                ui.label(locale.text("import-csv-profile"));
                let label = self
                    .csv_profile
                    .as_deref()
                    .map(profile_name)
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        locale.text(
                            if setup
                                .mapping
                                .columns
                                .iter()
                                .all(|column| column.target == "secret/v1")
                            {
                                "import-csv-private"
                            } else {
                                "import-csv-custom"
                            },
                        )
                    });
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = M::SM;
                    let response = kit::Select::from_id_salt("csv-profile")
                        .selected_text(label)
                        .width((ui.available_width() - M::SM - kit::density(ui).icon).max(1.))
                        .show_ui(ui, |ui| {
                            let response = ui.selectable_label(
                                setup
                                    .mapping
                                    .columns
                                    .iter()
                                    .all(|column| column.target == "secret/v1"),
                                locale.text("import-csv-private"),
                            );
                            self.hits
                                .insert("import-csv-profile-private".into(), response.rect);
                            if response.clicked() {
                                ui.close();
                                self.csv_profile = None;
                                for column in &mut setup.mapping.columns {
                                    column.target = "secret/v1".into();
                                }
                            }
                            for profile in &setup.profiles {
                                let response = ui.selectable_label(
                                    self.csv_profile.as_deref() == Some(&profile.id),
                                    profile_name(&profile.id),
                                );
                                self.hits.insert(
                                    format!("import-csv-profile-{}", profile.id),
                                    response.rect,
                                );
                                if response.clicked() {
                                    ui.close();
                                    setup.mapping = profile.mapping.clone();
                                    self.csv_profile = Some(profile.id.clone());
                                    self.error = None;
                                }
                            }
                        });
                    self.hits
                        .insert("import-csv-profile".into(), response.response.rect);
                    let reset = kit::icon_button(
                        ui,
                        p,
                        &locale.text("import-csv-reset"),
                        kit::Icon::Refresh,
                        true,
                    );
                    self.hits.insert("import-csv-reset".into(), reset.rect);
                    configure |= reset.clicked();
                });
            }
        });
        ui.add_space(M::MD);
        let wide =
            layout::columns((ui.available_width() - 2. * M::MD).max(0.), 260., M::MD, 2) == 2;
        let line = ui.text_style_height(&egui::TextStyle::Body);
        let control = kit::density(ui).input.max(kit::density(ui).control);
        let row_height = 2. * M::MD
            + line
            + M::SM
            + (line + M::SM + control) * if wide { 1. } else { 2. }
            + if wide { 0. } else { M::MD }
            + M::SM;
        let rows_height = (height - (ui.cursor().top() - top)).max(row_height.min(120.));
        let area = layout::scroll_rows(
            ui,
            &format!("csv-columns-{}", self.operation),
            rows_height,
            row_height,
            setup.mapping.columns.len(),
            |ui, range| {
                for index in range {
                    ui.push_id(index, |ui| {
                        let column = &mut setup.mapping.columns[index];
                        kit::card(p).show(ui, |ui| {
                            ui.label(count(locale, "import-csv-column", index + 1));
                            ui.add_space(M::SM);
                            layout::grid(ui, "csv-column", 2, 260., 2, M::MD, |ui, part| {
                                if part == 0 {
                                    let label = ui.add(
                                        egui::Label::new(locale.text("vault-field-name"))
                                            .truncate(),
                                    );
                                    let response = kit::field_with_id(
                                        ui,
                                        ui.make_persistent_id("csv-name"),
                                        &mut column.name,
                                        false,
                                        false,
                                        column.target != "title",
                                    )
                                    .labelled_by(label.id);
                                    self.hits
                                        .insert(format!("import-csv-name-{index}"), response.rect);
                                    if response.changed() {
                                        self.error = None;
                                    }
                                } else {
                                    ui.add(
                                        egui::Label::new(locale.text("import-csv-as")).truncate(),
                                    );
                                    let response = kit::Select::from_id_salt("csv-target")
                                        .selected_text(target_name(&column.target, locale))
                                        .width(ui.available_width())
                                        .show_ui(ui, |ui| {
                                            self.bounds.insert(
                                                format!("import-csv-target-{index}-options"),
                                                ui.clip_rect(),
                                            );
                                            for target in TARGETS {
                                                let response = ui.selectable_value(
                                                    &mut column.target,
                                                    (*target).to_owned(),
                                                    target_name(target, locale),
                                                );
                                                if response.changed() {
                                                    self.csv_profile = None;
                                                    self.error = None;
                                                }
                                                self.hits.insert(
                                                    format!("import-csv-role-{index}-{target}"),
                                                    response.rect,
                                                );
                                                if response.clicked() {
                                                    ui.close();
                                                }
                                            }
                                        });
                                    if focus_column && index == 0 {
                                        response.response.request_focus();
                                    }
                                    self.hits.insert(
                                        format!("import-csv-target-{index}"),
                                        response.response.rect,
                                    );
                                }
                            });
                        });
                        ui.add_space(M::SM);
                    });
                }
            },
        );
        self.bounds
            .insert("import-csv-columns".into(), area.inner_rect);
        self.csv = Some(setup);
        if configure {
            self.csv_configure(false);
        }
    }
}
fn delimiter_name(delimiter: u8, locale: &Localizer) -> String {
    locale.text(match delimiter {
        b',' => "import-csv-comma",
        b';' => "import-csv-semicolon",
        b'\t' => "import-csv-tab",
        _ => "import-csv-pipe",
    })
}
fn profile_name(id: &str) -> &str {
    match id {
        "chromium" => "Chrome / Chromium",
        "firefox" => "Firefox",
        "apple-passwords" => "Apple Passwords",
        _ => "CSV",
    }
}
fn target_name(target: &str, locale: &Localizer) -> String {
    locale.text(match target {
        "title" => "vault-record-title",
        "username/v1" => "vault-username",
        "password/v1" => "vault-password",
        "url/v1" => "vault-url",
        "text/v1" => "vault-text",
        "secret/v1" => "vault-secret",
        "note/v1" => "vault-note",
        "secure-note/v1" => "vault-secure-note",
        _ => return "TOTP".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(count: usize) -> flow::CsvSetup {
        flow::CsvSetup {
            token: [4; 16],
            file: flow::File {
                name: "public.csv".into(),
                bytes: 100,
            },
            mapping: confidex_app::import::CsvMapping {
                delimiter: b',',
                header: false,
                columns: (0..count)
                    .map(|index| confidex_app::import::CsvColumn {
                        index,
                        name: String::new(),
                        target: "secret/v1".into(),
                    })
                    .collect(),
            },
            profiles: Vec::new(),
        }
    }
    #[test]
    fn column_changes_reset_preview_and_only_one_title_is_allowed() {
        let mut state = State::default();
        state.accept(Ok(flow::Reply::CsvRequired {
            operation: 0,
            setup: setup(3),
        }));
        state.csv.as_mut().unwrap().mapping.columns[0].target = "title".into();
        state.csv.as_mut().unwrap().mapping.columns[1].name = "Public custom label".into();
        assert!(state.csv_valid());
        state.csv.as_mut().unwrap().mapping.columns[1].target = "title".into();
        assert!(!state.csv_valid());
        state.csv.as_mut().unwrap().mapping.columns[1].target = "secure-note/v1".into();
        state.csv_configure(true);
        assert!(state.stage == Stage::Csv);
        assert!(matches!(
            &state.take_events()[0],
            Event::Request(flow::Command::ConfigureCsv { operation: 1, .. })
        ));
        state.accept(Ok(flow::Reply::CsvRequired {
            operation: 1,
            setup: setup(3),
        }));
        assert_eq!(
            state.csv.as_ref().unwrap().mapping.columns[1].name,
            "Public custom label"
        );
        state.csv_configure(false);
        state.take_events();
        state.accept(Ok(flow::Reply::CsvRequired {
            operation: 2,
            setup: setup(3),
        }));
        assert!(
            state
                .csv
                .as_ref()
                .unwrap()
                .mapping
                .columns
                .iter()
                .all(|column| column.name.is_empty() && column.target == "secret/v1")
        );
        state.csv_preview();
        state.take_events();
        state.accept(Err(flow::Error::Parse(
            confidex_app::import::ErrorKind::Malformed.into(),
        )));
        assert!(state.stage == Stage::Csv);
        assert!(state.csv.is_some());
        state.cancelling = true;
        state.accept(Ok(flow::Reply::CsvRequired {
            operation: state.operation,
            setup: setup(1),
        }));
        assert_eq!(state.csv.as_ref().unwrap().mapping.columns.len(), 3);
        state.accept(Ok(flow::Reply::Canceled));
        assert!(state.csv.is_none());
    }
    #[test]
    fn enter_previews_valid_columns_and_keeps_invalid_columns_on_screen() {
        for valid in [true, false] {
            let ctx = egui::Context::default();
            kit::setup(&ctx);
            let locale = Localizer::new(0).unwrap();
            let mut state = State::default();
            state.window.open = true;
            let mut setup = setup(3);
            if !valid {
                setup.mapping.columns[0].target = "title".into();
                setup.mapping.columns[1].target = "title".into();
            }
            state.accept(Ok(flow::Reply::CsvRequired {
                operation: 0,
                setup,
            }));
            let mut events = Vec::new();
            for frame in 0..5 {
                let keys = if frame < 3 {
                    Vec::new()
                } else {
                    vec![egui::Event::Key {
                        key: egui::Key::Enter,
                        physical_key: None,
                        pressed: frame == 3,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    }]
                };
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(820., 960.),
                        )),
                        events: keys,
                        ..Default::default()
                    },
                    |ui| {
                        state.show_window(
                            ui.ctx(),
                            crate::theme::THEMES[0].colors,
                            &locale,
                            &|_| value::CopyState::Idle,
                        )
                    },
                );
                output.textures_delta.clear();
                events.extend(state.take_events());
            }
            assert_eq!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::Request(flow::Command::PreviewCsv { .. }))),
                valid
            );
            assert!(state.window.open, "valid mapping: {valid}");
            assert!(!events.iter().any(|event| matches!(event, Event::Cancel)));
        }
    }
    #[test]
    fn hundreds_of_columns_are_virtual_and_actions_fit_three_widths() {
        for (width, locale) in [(1320., 0), (820., 1), (390., 1)] {
            let ctx = egui::Context::default();
            kit::setup(&ctx);
            let locale = Localizer::new(locale).unwrap();
            let mut state = State::default();
            state.window.open = true;
            state.accept(Ok(flow::Reply::CsvRequired {
                operation: 0,
                setup: setup(512),
            }));
            for _ in 0..3 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 960.),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        state.show_window(
                            ui.ctx(),
                            crate::theme::THEMES[0].colors,
                            &locale,
                            &|_| value::CopyState::Idle,
                        )
                    },
                );
                output.textures_delta.clear();
            }
            assert!(
                state
                    .hits
                    .keys()
                    .filter(|key| key.starts_with("import-csv-name-"))
                    .count()
                    < 12
            );
            assert!(
                state.bounds["import-actions"].bottom()
                    <= state.bounds["import-window-body"].bottom(),
                "{width}: {:?}",
                state.bounds
            );
            assert!(
                state.bounds["import-actions"].bottom()
                    < state.bounds["import-notifications"].top()
            );
        }
    }
}
