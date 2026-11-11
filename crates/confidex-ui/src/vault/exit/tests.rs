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
fn fixture(ctx: &egui::Context) -> (VaultApp, Host) {
    let host = Host::default();
    let mut app = VaultApp::new(ctx, Box::new(host.clone())).unwrap();
    app.busy = false;
    app.screen = Screen::Open;
    app.editing = true;
    app.mobile_detail = true;
    let mut draft = app::new_record().unwrap();
    draft.revision = Some([1; 32]);
    draft.fields = app::template("login").unwrap();
    app.reset_field_ids(draft.fields.len());
    app.edit_baseline = Some(draft.clone());
    app.draft = Some(draft);
    host.0.borrow_mut().clear();
    (app, host)
}
fn frame(
    ctx: &egui::Context,
    app: &mut VaultApp,
    width: f32,
    close: bool,
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    let mut input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            Vec2::new(width, 1000.),
        )),
        events,
        ..Default::default()
    };
    if close {
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .events
            .push(egui::ViewportEvent::Close);
    }
    let mut output = ctx.run_ui(input, |ui| app.show(ui));
    output.textures_delta.clear();
    output
}
fn click(ctx: &egui::Context, app: &mut VaultApp, width: f32, id: &str) -> egui::FullOutput {
    let pos = app.hits[id].center();
    frame(ctx, app, width, false, vec![egui::Event::PointerMoved(pos)]);
    let mut output = None;
    for pressed in [true, false] {
        output = Some(frame(
            ctx,
            app,
            width,
            false,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            }],
        ));
    }
    output.unwrap()
}

#[test]
fn changes_to_any_record_component_need_an_exit_decision() {
    let ctx = egui::Context::default();
    let (mut app, _) = fixture(&ctx);
    assert!(!app.has_unsaved_changes());
    for part in 0..10 {
        let mut draft = app.edit_baseline.clone().unwrap();
        match part {
            0 => draft.title.push_str("Public title"),
            1 => draft.tags.push("Public tag".into()),
            2 => draft.sections = Some(vec![app::sections::Section::new("Public", 0, 2)]),
            3 => draft.fields.swap(0, 1),
            4 => draft.fields[0].name.push_str("Renamed"),
            5 => {
                draft.fields[1]
                    .values
                    .insert("password".into(), "public-fixture".into());
            }
            6 => draft.fields[0].protected = true,
            7 => draft.fields[0].data = Some(vec![1, 2, 3].into()),
            8 => draft.fields.push(app::field("text/v1").unwrap()),
            _ => draft.fields[0].source_key = Some("future-binding".into()),
        }
        app.draft = Some(draft);
        assert!(app.has_unsaved_changes(), "part {part}");
    }
    app.draft = app.edit_baseline.clone();
    assert!(!app.has_unsaved_changes());
    app.ssh.checking = true;
    assert!(app.has_unsaved_changes());
    app.ssh.checking = false;
    app.attachments.checking = true;
    assert!(app.has_unsaved_changes());
    app.attachments.checking = false;
    app.draft.as_mut().unwrap().revision = None;
    assert!(app.has_unsaved_changes());
    app.clear_private();
    assert!(app.edit_baseline.is_none() && !app.has_unsaved_changes());
}

#[test]
fn root_close_is_cancelled_until_the_user_discards_the_draft() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let (mut app, host) = fixture(&ctx);
        app.draft.as_mut().unwrap().title = "Public unsaved edit".into();
        let output = frame(&ctx, &mut app, width, true, vec![]);
        assert!(
            output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|cmd| matches!(cmd, egui::ViewportCommand::CancelClose))
        );
        assert!(app.exit == Some(Action::Close));
        for _ in 0..3 {
            frame(&ctx, &mut app, width, false, vec![]);
        }
        click(&ctx, &mut app, width, "exit-cancel");
        assert!(app.exit.is_none() && app.has_unsaved_changes());
        assert_eq!(app.draft.as_ref().unwrap().title, "Public unsaved edit");
        assert!(host.0.borrow().is_empty());
        frame(&ctx, &mut app, width, true, vec![]);
        for _ in 0..3 {
            frame(&ctx, &mut app, width, false, vec![]);
        }
        let output = click(&ctx, &mut app, width, "exit-confirm");
        assert!(
            output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|cmd| matches!(cmd, egui::ViewportCommand::Close))
        );
        assert!(app.draft.is_none() && app.edit_baseline.is_none());
    }
}

#[test]
fn a_close_request_is_guarded_even_when_the_window_has_no_ui_pass() {
    for native_quit in [false, true] {
        let ctx = egui::Context::default();
        let (mut app, _) = fixture(&ctx);
        app.draft.as_mut().unwrap().title.push_str("Unsaved");
        let mut input = egui::RawInput::default();
        if native_quit {
            VaultApp::request_close(&ctx);
        } else {
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .events
                .push(egui::ViewportEvent::Close);
        }
        let output = ctx.run_logic(&input, |ctx| {
            eframe::App::logic(&mut app, ctx, &mut eframe::Frame::_new_kittest())
        });
        assert!(
            output.viewport_commands[&egui::ViewportId::ROOT]
                .contains(&egui::ViewportCommand::CancelClose)
        );
        assert!(app.exit == Some(Action::Close) && app.has_unsaved_changes());
        assert!(
            !output.viewport_commands[&egui::ViewportId::ROOT]
                .contains(&egui::ViewportCommand::Close)
        );
    }
}

#[test]
fn lock_waits_for_discard_but_unchanged_records_do_not_prompt() {
    let ctx = egui::Context::default();
    let (mut app, host) = fixture(&ctx);
    app.draft.as_mut().unwrap().title.push_str("Unsaved");
    app.request_lock();
    assert!(app.exit == Some(Action::Lock) && host.0.borrow().is_empty());
    for _ in 0..3 {
        frame(&ctx, &mut app, 390., false, vec![]);
    }
    click(&ctx, &mut app, 390., "exit-cancel");
    assert!(app.exit.is_none() && app.has_unsaved_changes());
    app.request_lock();
    for _ in 0..3 {
        frame(&ctx, &mut app, 390., false, vec![]);
    }
    click(&ctx, &mut app, 390., "exit-confirm");
    assert!(
        host.0
            .borrow()
            .iter()
            .any(|r| matches!(r.command, Command::Lock))
    );
    assert!(app.draft.is_none() && app.edit_baseline.is_none());
    let (mut app, host) = fixture(&ctx);
    let output = frame(&ctx, &mut app, 1180., true, vec![]);
    assert!(app.exit.is_none());
    assert!(
        !output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .iter()
            .any(|cmd| matches!(cmd, egui::ViewportCommand::CancelClose))
    );
    app.request_lock();
    assert!(app.exit.is_none());
    assert!(
        host.0
            .borrow()
            .iter()
            .any(|r| matches!(r.command, Command::Lock))
    );
}

#[test]
fn invalid_totp_text_is_protected_before_it_can_enter_the_record() {
    let ctx = egui::Context::default();
    let (mut app, _) = fixture(&ctx);
    let mut field = app::field("totp/v1").unwrap();
    field.data = Some(vec![1; 20].into());
    let mut draft = app.draft.take().unwrap();
    draft.fields = vec![field];
    app.reset_field_ids(1);
    app.edit_baseline = Some(draft.clone());
    app.draft = Some(draft);
    for _ in 0..3 {
        frame(&ctx, &mut app, 1180., false, vec![]);
    }
    assert!(!app.has_unsaved_changes());
    let original = app.totp_fields.values().next().unwrap().secret.clone();
    let input = app
        .hits
        .keys()
        .find(|id| id.starts_with("totp-") && id.ends_with("-secret"))
        .unwrap()
        .clone();
    for text in ["invalid!", original.as_str()] {
        click(&ctx, &mut app, 1180., &input);
        frame(
            &ctx,
            &mut app,
            1180.,
            false,
            vec![
                egui::Event::Key {
                    key: egui::Key::A,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::COMMAND,
                },
                egui::Event::Text(text.into()),
            ],
        );
        frame(
            &ctx,
            &mut app,
            1180.,
            false,
            vec![egui::Event::Key {
                key: egui::Key::A,
                physical_key: None,
                pressed: false,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(app.totp_fields.values().next().unwrap().secret, text);
        assert!(app.draft == app.edit_baseline);
        assert_eq!(app.has_unsaved_changes(), text == "invalid!");
    }
    app.clear_private();
    assert!(app.pending_totp.is_empty());
}

#[test]
fn exit_actions_fit_every_enabled_locale_and_viewport() {
    for (locale, _) in Localizer::languages() {
        for width in [260., 390., 1180.] {
            let ctx = egui::Context::default();
            let (mut app, _) = fixture(&ctx);
            app.locale = Localizer::new(*locale).unwrap();
            app.draft.as_mut().unwrap().title.push_str("Unsaved");
            app.request_lock();
            for _ in 0..3 {
                frame(&ctx, &mut app, width, false, vec![]);
            }
            let rect = app.bounds["exit-dialog"];
            assert!(
                ctx.content_rect().contains_rect(rect),
                "{} {width}",
                app.locale.id()
            );
            for id in ["exit-cancel", "exit-confirm"] {
                assert!(
                    rect.contains_rect(app.hits[id]),
                    "{} {width} {id}",
                    app.locale.id()
                );
            }
        }
    }
}
