use super::*;

impl State {
    pub fn credentials_ready(&self) -> bool {
        if self.format == Some(Format::Kdbx) {
            (self.use_password || self.use_keyfile) && (!self.use_keyfile || self.keyfile.is_some())
        } else {
            !self.password.is_empty()
        }
    }
    pub fn keyfile_selected(&mut self, file: flow::File) {
        self.keyfile = Some(file);
        self.error = None;
        self.focus_action = true;
    }
    pub(super) fn credentials_form(&mut self, ui: &mut egui::Ui, p: Palette, locale: &Localizer) {
        let password = kit::checkbox(ui, &mut self.use_password, locale.text("vault-password"));
        self.hits
            .insert("import-use-password".into(), password.rect);
        if password.changed() {
            if !self.use_password {
                self.password.zeroize();
            }
            self.focus_source |= ui.input(|input| input.pointer.primary_released());
        }
        let response = kit::field_with_id(
            ui,
            ui.make_persistent_id("import-password"),
            &mut self.password,
            true,
            false,
            self.use_password && !self.waiting,
        )
        .labelled_by(password.id);
        self.hits.insert("import-password".into(), response.rect);
        self.source_enter =
            response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        ui.add_space(M::LG);
        let keyfile = kit::checkbox(ui, &mut self.use_keyfile, locale.text("import-use-keyfile"));
        self.hits.insert("import-use-keyfile".into(), keyfile.rect);
        if keyfile.changed() {
            if !self.use_keyfile {
                self.keyfile = None;
                self.events.push(Event::ClearKeyfile);
            }
            self.focus_source |= ui.input(|input| input.pointer.primary_released());
        }
        kit::card(p).show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    self.keyfile
                        .as_ref()
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| locale.text("import-no-file")),
                )
                .truncate(),
            );
        });
        let choose = kit::button(
            ui,
            p,
            &locale.text("import-choose-file"),
            ButtonRole::Secondary,
            ui.available_width(),
            self.use_keyfile && !self.waiting,
        );
        if choose.enabled() {
            self.hits
                .insert("import-choose-keyfile".into(), choose.rect);
        }
        if self.focus_source {
            if keyfile.changed() && self.use_keyfile && self.keyfile.is_none() {
                choose.request_focus();
            } else if self.use_password {
                response.request_focus();
            } else if self.use_keyfile {
                if self.keyfile.is_some() {
                    self.focus_action = true;
                } else {
                    choose.request_focus();
                }
            } else {
                password.request_focus();
            }
            self.focus_source = false;
        }
        if choose.clicked() {
            self.events.push(Event::ChooseKeyfile);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enabling_password_after_a_keyfile_keeps_enter_on_the_form_action() {
        for width in [1320., 820., 390.] {
            let ctx = egui::Context::default();
            kit::setup(&ctx);
            let locale = Localizer::new(0).unwrap();
            let p = crate::theme::THEMES[0].colors;
            let mut state = State::default();
            state.window.open = true;
            state.accept(Ok(flow::Reply::KdbxRequired {
                operation: 0,
                token: [1; 16],
                file: flow::File {
                    name: "public.kdbx".into(),
                    bytes: 100,
                },
            }));
            state.use_password = false;
            state.use_keyfile = true;
            state.keyfile_selected(flow::File {
                name: "public.key".into(),
                bytes: 32,
            });
            let draw = |state: &mut State, events| {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 960.),
                        )),
                        events,
                        ..Default::default()
                    },
                    |ui| state.show_window(ui.ctx(), p, &locale, &|_| value::CopyState::Idle),
                );
                output.textures_delta.clear();
            };
            for _ in 0..3 {
                draw(&mut state, vec![]);
            }
            let pos = state.hits["import-use-password"].center();
            draw(
                &mut state,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
            draw(
                &mut state,
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            );
            draw(&mut state, vec![]);
            for pressed in [true, false] {
                draw(
                    &mut state,
                    vec![egui::Event::Key {
                        key: egui::Key::Enter,
                        physical_key: None,
                        pressed,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    }],
                );
            }
            assert!(state.use_password);
            assert!(state.window.open);
            let events = state.take_events();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::Unlock))
                    .count(),
                1
            );
            assert!(!events.iter().any(|event| matches!(event, Event::Cancel)));
        }
    }
    #[test]
    fn credential_modes_keep_the_window_and_actions_fixed_and_values_masked() {
        for width in [1320., 820., 390.] {
            let ctx = egui::Context::default();
            kit::setup(&ctx);
            let locale = Localizer::new(0).unwrap();
            let p = crate::theme::THEMES[0].colors;
            let mut state = State::default();
            state.window.open = true;
            state.accept(Ok(flow::Reply::KdbxRequired {
                operation: 0,
                token: [1; 16],
                file: flow::File {
                    name: "public.kdbx".into(),
                    bytes: 100,
                },
            }));
            state.password.push_str("PUBLIC-MASKED-CREDENTIAL");
            let mut bounds = None;
            for mode in 0..5 {
                state.use_password = mode != 3 && mode != 4;
                state.use_keyfile = mode != 0 && mode != 4;
                state.keyfile = (mode == 2 || mode == 3).then(|| flow::File {
                    name: "public.key".into(),
                    bytes: 0,
                });
                for frame in 0..3 {
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(width, 960.),
                            )),
                            ..Default::default()
                        },
                        |ui| {
                            state.show_window(ui.ctx(), p, &locale, &|_| value::CopyState::Idle);
                        },
                    );
                    assert!(!format!("{:?}", output.shapes).contains("PUBLIC-MASKED-CREDENTIAL"));
                    output.textures_delta.clear();
                    if frame == 2 {
                        let current = (
                            state.bounds["import-window"],
                            state.bounds["import-actions"],
                        );
                        if let Some(first) = bounds {
                            assert_eq!(current, first);
                        } else {
                            bounds = Some(current);
                        }
                        assert_eq!(
                            state.hits.contains_key("import-unlock"),
                            matches!(mode, 0 | 2 | 3)
                        );
                        assert!(current.0.contains_rect(current.1));
                    }
                }
            }
            state.accept(Ok(flow::Reply::Canceled));
            assert!(state.password.is_empty());
            assert!(state.keyfile.is_none());
        }
    }
}
