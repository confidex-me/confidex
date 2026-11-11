use super::*;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

const PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/public-ssh-key.pem"
));
const PASSWORD: &str = "public-fixture-passphrase";

#[derive(Clone, Default)]
struct Host {
    requests: Rc<RefCell<Vec<Request>>>,
    replies: Rc<RefCell<VecDeque<Response>>>,
}
impl Runtime for Host {
    fn send(&mut self, request: Request) -> Result<(), Error> {
        self.requests.borrow_mut().push(request);
        Ok(())
    }
    fn receive(&mut self) -> Option<Response> {
        self.replies.borrow_mut().pop_front()
    }
}
fn draw(
    ctx: &egui::Context,
    app: &mut VaultApp,
    width: f32,
    events: Vec<egui::Event>,
) -> Vec<egui::epaint::ClippedShape> {
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(width, 1100.),
            )),
            events,
            ..Default::default()
        },
        |ui| app.show(ui),
    );
    output.textures_delta.clear();
    std::mem::take(&mut output.shapes)
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
fn text(ctx: &egui::Context, app: &mut VaultApp, width: f32, id: &str, value: &str) {
    click(ctx, app, width, id);
    draw(ctx, app, width, vec![egui::Event::Text(value.into())]);
    draw(ctx, app, width, vec![]);
}
fn fixture(ctx: &egui::Context, host: Host) -> VaultApp {
    let mut app = VaultApp::new(ctx, Box::new(host)).unwrap();
    app.busy = false;
    app.screen = Screen::Open;
    app.editing = true;
    app.mobile_detail = true;
    let mut draft = app::new_record().unwrap();
    draft.title = "SSH fixture".into();
    let mut note = app::field("note/v1").unwrap();
    note.values.insert("text".into(), "Keep this note".into());
    draft.fields = vec![app::field("ssh/v1").unwrap(), note];
    draft.fields[0].name = "Same".into();
    app.draft = Some(draft);
    app
}
fn parsed(host: &Host, app: &VaultApp) {
    let requests = host.requests.borrow();
    let Command::ImportSsh {
        token,
        data,
        password,
    } = &requests.last().unwrap().command
    else {
        panic!("import");
    };
    host.replies.borrow_mut().push_back(Response {
        generation: app.generation,
        result: Ok(Output::Ssh {
            token: *token,
            result: app::ssh::import(data, password.as_deref()),
        }),
    });
}

#[test]
fn pasted_encrypted_keys_retry_and_apply_only_after_the_whole_record_check() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let host = Host::default();
        let mut app = fixture(&ctx, host.clone());
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        let key = app.field_ids[0];
        click(&ctx, &mut app, width, &format!("ssh-{key}-import"));
        text(
            &ctx,
            &mut app,
            width,
            &format!("ssh-{key}-source"),
            std::str::from_utf8(PEM).unwrap(),
        );
        assert_eq!(app.ssh.source.as_bytes(), PEM);
        assert!(!app.hits.contains_key("save"));
        let shapes = draw(&ctx, &mut app, width, vec![]);
        assert!(!shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.job.text.contains("BEGIN OPENSSH"))));
        click(&ctx, &mut app, width, &format!("ssh-{key}-action-1"));
        assert!(app.ssh.pending && !app.busy);
        parsed(&host, &app);
        draw(&ctx, &mut app, width, vec![]);
        assert!(app.ssh.password_required);
        text(&ctx, &mut app, width, &format!("ssh-{key}-password"), "bad");
        click(&ctx, &mut app, width, &format!("ssh-{key}-action-1"));
        parsed(&host, &app);
        draw(&ctx, &mut app, width, vec![]);
        assert_eq!(app.ssh.error, Some("ssh-auth"));
        let actions: Vec<_> = (0..3)
            .map(|index| app.hits[&format!("ssh-{key}-action-{index}")])
            .collect();
        assert!((actions[0].width() - actions[1].width()).abs() < 1.);
        assert!(
            app.bounds[&format!("ssh-{key}-notice")].top()
                >= actions.iter().map(|rect| rect.bottom()).fold(0., f32::max)
        );
        assert!(app.ssh.password.is_empty());
        text(
            &ctx,
            &mut app,
            width,
            &format!("ssh-{key}-password"),
            PASSWORD,
        );
        click(&ctx, &mut app, width, &format!("ssh-{key}-action-1"));
        parsed(&host, &app);
        draw(&ctx, &mut app, width, vec![]);
        assert!(app.ssh.checking);
        assert!(
            app.draft.as_ref().unwrap().fields[0]
                .data
                .as_ref()
                .unwrap()
                .is_empty()
        );
        {
            let requests = host.requests.borrow();
            let Command::CheckDraft { draft } = &requests.last().unwrap().command else {
                panic!("check");
            };
            assert_eq!(draft.fields[0].values["key_type"], "Ed25519");
            assert_eq!(draft.fields[0].name, "Same");
            assert_eq!(draft.fields[1].values["text"], "Keep this note");
        }
        host.replies.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Ok(Output::Checked { compressed: 1024 }),
        });
        draw(&ctx, &mut app, width, vec![]);
        draw(&ctx, &mut app, width, vec![]);
        assert!(!app.ssh.is_open() && app.ssh.source.is_empty());
        assert!(app.hits.contains_key("save"));
        assert_eq!(
            app.draft.as_ref().unwrap().fields[0].values["key_type"],
            "Ed25519"
        );
        assert_eq!(
            app.draft.as_ref().unwrap().fields[0].values["fingerprint"],
            "SHA256:2qK+2sSbXCzJHgO05gCz4xAdNqqtzCiM7ZiwlTuMTQ8"
        );
        assert!(!app.hits.contains_key("generate-0-private_key"));
        app.request(Command::Lock, true);
        assert!(app.draft.is_none() && app.ssh.source.is_empty() && app.ssh.password.is_empty());
    }
}

#[test]
fn oversized_files_name_the_limit_below_actions_and_keep_the_current_input() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let mut app = fixture(&ctx, Host::default());
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        let key = app.field_ids[0];
        click(&ctx, &mut app, width, &format!("ssh-{key}-import"));
        app.ssh.source = "Keep this input".into();
        for reply in [
            ImageReply::TooLarge,
            ImageReply::Opened(ImageFile {
                name: "oversized".into(),
                bytes: vec![0; app::ssh::MAX_KEY + 1].into(),
            }),
        ] {
            app.ssh
                .sender
                .send(FileEvent::Pick(app.ssh.token, reply))
                .unwrap();
            draw(&ctx, &mut app, width, vec![]);
            let shapes = draw(&ctx, &mut app, width, vec![]);
            assert_eq!(app.ssh.error, Some("ssh-file-limit"));
            assert_eq!(app.ssh.source, "Keep this input");
            assert!(shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.job.text.replace(['\u{2068}', '\u{2069}'], "").contains("64 KiB"))));
            let bottom = (0..3)
                .map(|index| app.hits[&format!("ssh-{key}-action-{index}")].bottom())
                .fold(0., f32::max);
            assert!(app.bounds[&format!("ssh-{key}-notice")].top() >= bottom);
            assert!(
                app.draft.as_ref().unwrap().fields[0]
                    .data
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn canceled_jobs_and_file_callbacks_cannot_replace_the_current_draft() {
    let ctx = egui::Context::default();
    let host = Host::default();
    let mut app = fixture(&ctx, host.clone());
    for _ in 0..3 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    let key = app.field_ids[0];
    click(&ctx, &mut app, 390., &format!("ssh-{key}-import"));
    let token = app.ssh.token;
    app.ssh.source = std::str::from_utf8(PEM).unwrap().into();
    app.ssh.password_required = true;
    app.ssh.password = PASSWORD.into();
    app.ssh_submit();
    click(&ctx, &mut app, 390., &format!("ssh-{key}-action-2"));
    let result = app::ssh::import(PEM, Some(PASSWORD));
    app.ssh_reply(token, result);
    app.ssh
        .sender
        .send(FileEvent::Pick(
            token,
            ImageReply::Opened(ImageFile {
                name: "public fixture".into(),
                bytes: PEM.to_vec().into(),
            }),
        ))
        .unwrap();
    draw(&ctx, &mut app, 390., vec![]);
    assert!(!app.ssh.is_open() && !app.ssh.active() && app.ssh.source.is_empty());
    assert!(
        app.draft.as_ref().unwrap().fields[0]
            .data
            .as_ref()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn escape_closes_only_the_key_import_and_file_export_keeps_exact_private_bytes() {
    let ctx = egui::Context::default();
    let host = Host::default();
    let mut app = fixture(&ctx, host);
    let field = app::ssh::import(PEM, Some(PASSWORD)).unwrap();
    let expected = field.values["private_key"].clone();
    app.draft.as_mut().unwrap().fields[0] = field;
    let exported = Rc::new(RefCell::new(None));
    let capture = exported.clone();
    crate::ImageHost::set_image_handler(&mut app, move |request, done| {
        if let ImageRequest::Save(file) = request {
            *capture.borrow_mut() = Some(file);
            done(ImageReply::DownloadStarted);
        } else {
            done(ImageReply::Cancelled);
        }
    });
    for _ in 0..3 {
        draw(&ctx, &mut app, 1180., vec![]);
    }
    let key = app.field_ids[0];
    click(&ctx, &mut app, 1180., &format!("ssh-{key}-save"));
    assert_eq!(
        exported.borrow().as_ref().unwrap().bytes.as_slice(),
        expected.as_bytes()
    );
    assert_eq!(app.ssh.notice, Some((key, "gallery-image-download")));
    click(&ctx, &mut app, 1180., &format!("ssh-{key}-import"));
    draw(
        &ctx,
        &mut app,
        1180.,
        vec![egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Default::default(),
        }],
    );
    assert!(app.editing && app.draft.is_some() && !app.ssh.is_open());
    assert_eq!(
        app.draft.as_ref().unwrap().fields[1].values["text"],
        "Keep this note"
    );
}
