use super::*;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Default)]
struct Host(Rc<RefCell<Vec<Request>>>);
impl Runtime for Host {
    fn send(&mut self, request: Request) -> Result<(), Error> {
        self.0.borrow_mut().push(request);
        Ok(())
    }
    fn receive(&mut self) -> Option<Response> {
        None
    }
}
fn draw(ctx: &egui::Context, app: &mut VaultApp, width: f32, events: Vec<egui::Event>) {
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(width, 1000.),
            )),
            events,
            ..Default::default()
        },
        |ui| app.show(ui),
    );
    output.textures_delta.clear();
}
fn click(ctx: &egui::Context, app: &mut VaultApp, width: f32, id: &str) {
    let pos = app.hits[id].center();
    for pressed in [true, false] {
        draw(
            ctx,
            app,
            width,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                },
            ],
        );
    }
    draw(ctx, app, width, vec![]);
}
fn fixture(ctx: &egui::Context, host: Host) -> VaultApp {
    let mut app = VaultApp::new(ctx, Box::new(host)).unwrap();
    app.screen = Screen::Open;
    app.busy = false;
    app.mobile_detail = true;
    app.editing = true;
    app.draft = Some(app::new_record().unwrap());
    app.draft.as_mut().unwrap().title = "Validation fixture".into();
    app
}

#[test]
fn title_is_required_for_click_and_enter_without_losing_the_draft() {
    for width in [260., 390., 1180.] {
        let ctx = egui::Context::default();
        let host = Host::default();
        let mut app = fixture(&ctx, host.clone());
        app.draft.as_mut().unwrap().tags = vec!["Login".into(), "Work".into()];
        for title in ["", " \t\n\u{2003}\u{3000}"] {
            app.draft.as_mut().unwrap().title = title.into();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(!app.hits.contains_key("save"));
            let message = app.bounds["title-error"];
            assert!(message.top() >= app.bounds["save"].bottom());
            assert!(message.top() >= app.bounds["cancel-edit"].bottom());
            assert!(app.bounds["record-footer"].contains_rect(message));
            let pos = app.bounds["save"].center();
            for pressed in [true, false] {
                draw(
                    &ctx,
                    &mut app,
                    width,
                    vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ],
                );
            }
            ctx.memory_mut(|memory| {
                memory.surrender_focus(memory.focused().unwrap_or(egui::Id::NULL))
            });
            draw(
                &ctx,
                &mut app,
                width,
                vec![egui::Event::Key {
                    key: egui::Key::Enter,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: Default::default(),
                }],
            );
            assert!(!host.0.borrow().iter().any(|r| matches!(
                r.command,
                Command::Save { .. } | Command::SaveRevision { .. }
            )));
            assert_eq!(app.draft.as_ref().unwrap().tags, ["Login", "Work"]);
        }
        app.draft.as_mut().unwrap().title = "  Рабочая почта  ".into();
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        assert!(!app.bounds.contains_key("title-error"));
        click(&ctx, &mut app, width, "save");
        let requests = host.0.borrow();
        let Command::Save { draft, .. } = &requests.last().unwrap().command else {
            panic!("save");
        };
        assert_eq!(draft.title, "  Рабочая почта  ");
        assert_eq!(draft.tags, ["Login", "Work"]);
    }
}

#[test]
fn every_empty_catalogue_starter_can_still_be_saved() {
    let ctx = egui::Context::default();
    let mut app = fixture(&ctx, Host::default());
    for template in app::templates::CATALOG {
        let mut draft = app::new_record().unwrap();
        draft.title = template.name.into();
        draft.fields = template.fields().unwrap();
        draft.sections = Some(template.sections());
        app.reset_field_ids(draft.fields.len());
        assert!(app.record_valid(&draft), "{}", template.id);
    }
}

#[test]
fn invalid_fields_block_click_and_enter_and_first_problem_navigation_reaches_the_field() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let host = Host::default();
        let mut app = fixture(&ctx, host.clone());
        let draft = app.draft.as_mut().unwrap();
        draft.fields = (0..12).map(|_| app::field("text/v1").unwrap()).collect();
        draft
            .fields
            .extend(["totp/v1", "date/v1", "location/v1"].map(|kind| app::field(kind).unwrap()));
        draft.fields.extend(app::template("wifi").unwrap());
        draft.fields[15]
            .values
            .insert("text".into(), "Public network".into());
        draft.fields[16]
            .values
            .insert("password".into(), "short".into());
        draft.fields[17].values.insert("ssid".into(), "15".into());
        draft.fields[17]
            .values
            .insert("password".into(), "16".into());
        draft.fields[13]
            .values
            .insert("date".into(), "31/02/2026".into());
        draft.fields[14]
            .values
            .insert("latitude".into(), "91".into());
        draft.fields[14]
            .values
            .insert("longitude".into(), "20".into());
        for field in &mut draft.fields {
            field.name = "Same".into();
        }
        for _ in 0..4 {
            draw(&ctx, &mut app, width, vec![]);
        }
        assert!(!app.hits.contains_key("save"));
        assert_eq!(app.record_problems(app.draft.as_ref().unwrap()).len(), 4);
        assert!(app.bounds["record-validation"].top() >= app.hits["first-problem"].bottom());
        ctx.memory_mut(|memory| memory.surrender_focus(memory.focused().unwrap_or(egui::Id::NULL)));
        draw(
            &ctx,
            &mut app,
            width,
            vec![egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
        assert!(
            !host
                .0
                .borrow()
                .iter()
                .any(|request| matches!(&request.command, Command::Save { .. }))
        );
        let before = app.draft.as_ref().unwrap().fields.clone();
        let first = egui::Id::unique(("record-fields", app.draft.as_ref().unwrap().record))
            .with(app.field_ids[12]);
        assert!(app.bounds["field-12"].top() > app.bounds["record-viewport"].bottom());
        click(&ctx, &mut app, width, "first-problem");
        for _ in 0..20 {
            draw(&ctx, &mut app, width, vec![]);
        }
        let viewport = app.bounds["record-viewport"];
        assert!(viewport.intersects(app.hits["field-name-12"]));
        assert_eq!(
            ctx.memory(|memory| memory.focused()),
            Some(first.with(("header", "name")))
        );
        for (field, before) in app.draft.as_ref().unwrap().fields.iter().zip(&before) {
            assert_eq!(field.values, before.values);
            assert_eq!(field.name, before.name);
            assert_eq!(field.data.as_deref(), before.data.as_deref());
        }
        click(
            &ctx,
            &mut app,
            width,
            &format!("totp-{}-secret", first.value()),
        );
        draw(
            &ctx,
            &mut app,
            width,
            vec![egui::Event::Text("JBSWY3DPEHPK3PXP".into())],
        );
        let draft = app.draft.as_mut().unwrap();
        draft.fields[13]
            .values
            .insert("date".into(), "28/02/2026".into());
        draft.fields[14]
            .values
            .insert("latitude".into(), "90".into());
        draft.fields[16]
            .values
            .insert("password".into(), "public-password".into());
        for _ in 0..4 {
            draw(&ctx, &mut app, width, vec![]);
        }
        assert!(!app.bounds.contains_key("record-validation"));
        assert!(app.hits.contains_key("save"));
        click(&ctx, &mut app, width, "save");
        let requests = host.0.borrow();
        let Command::Save { draft, .. } = &requests.last().unwrap().command else {
            panic!("save");
        };
        assert_eq!(draft.fields[15].values["text"], "Public network");
        assert!(!draft.fields[12].data.as_ref().unwrap().is_empty());
    }
}

#[test]
fn wifi_validation_follows_the_selected_security_and_references() {
    let ctx = egui::Context::default();
    let mut app = fixture(&ctx, Host::default());
    let mut draft = app::new_record().unwrap();
    draft.title = "Wi-Fi fixture".into();
    draft.fields = app::template("wifi").unwrap();
    app.reset_field_ids(draft.fields.len());
    draft.fields[0]
        .values
        .insert("text".into(), "Public network".into());
    for (auth, password, valid) in [
        ("WPA", "short", false),
        ("WPA", "public-password", true),
        (
            "WPA",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            true,
        ),
        ("WPA", "парольпароль", false),
        ("WEP", "abcde", true),
        ("WEP", "shorter", false),
        ("nopass", "ignored password", true),
    ] {
        draft.fields[2].values.insert("auth".into(), auth.into());
        draft.fields[1]
            .values
            .insert("password".into(), password.into());
        assert_eq!(app.record_valid(&draft), valid, "{auth} {password}");
    }
    draft.fields[2].values.insert("auth".into(), "WPA".into());
    draft.fields[1].type_name = "text/v1".into();
    assert!(!app.record_valid(&draft));
}
