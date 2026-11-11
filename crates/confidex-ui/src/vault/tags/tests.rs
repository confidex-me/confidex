use super::*;
use std::{cell::RefCell, rc::Rc};

#[test]
fn pending_tags_follow_core_byte_count_and_uniqueness_limits_without_rewriting_old_tags() {
    let mut tags = vec!["".into(), " work ".into(), "work".into(), "日本語".into()];
    let before = tags.clone();
    let mut state = State {
        input: " work ".into(),
        ..Default::default()
    };
    assert_eq!(state.problem(&tags), Some("vault-tag-duplicate"));
    assert!(!state.apply(&mut tags));
    assert_eq!(tags, before);
    state.input = "é".repeat(MAX_TAG_BYTES / 2 + 1);
    assert_eq!(state.problem(&tags), Some("vault-tag-too-long"));
    assert!(!state.apply(&mut tags));
    state.input = "é".repeat(MAX_TAG_BYTES / 2);
    assert!(state.apply(&mut tags));
    assert_eq!(&tags[..before.len()], before);
    assert!(state.input.is_empty());
    tags = (0..MAX_TAGS).map(|i| format!("Tag {i}")).collect();
    state.input = "Another".into();
    assert_eq!(state.problem(&tags), Some("vault-tags-full"));
    assert!(!state.apply(&mut tags));
    tags.pop();
    assert!(state.apply(&mut tags));
    state.input = " \t ".into();
    assert!(state.apply(&mut tags));
    assert_eq!(tags.len(), MAX_TAGS);
}

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
    draw_size(ctx, app, Vec2::new(width, 1000.), events);
}
fn draw_size(ctx: &egui::Context, app: &mut VaultApp, size: Vec2, events: Vec<egui::Event>) {
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            ..Default::default()
        },
        |ui| app.show(ui),
    );
    output.textures_delta.clear();
}

#[test]
fn long_forms_keep_all_action_rows_inside_a_short_or_narrow_viewport() {
    for size in [
        Vec2::new(260., 600.),
        Vec2::new(390., 600.),
        Vec2::new(1180., 600.),
        Vec2::new(390., 1000.),
    ] {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Host::default())).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        app.editing = true;
        app.mobile_detail = true;
        let mut draft = app::new_record().unwrap();
        draft.title = "Long form fixture".into();
        draft.fields = (0..30).map(|_| app::field("text/v1").unwrap()).collect();
        app.draft = Some(draft);
        for _ in 0..3 {
            draw_size(&ctx, &mut app, size, vec![]);
        }
        let footer = app.bounds["record-footer"];
        assert!(
            ctx.content_rect().contains_rect(footer),
            "{size:?}: {footer:?}"
        );
        for id in ["add-field", "save", "cancel-edit"] {
            assert!(footer.contains_rect(app.hits[id]), "{size:?}: {id}");
            assert!(app.hits[id].top() > app.bounds["record-viewport"].bottom());
        }
        assert!(app.hits["save"].top() > app.hits["add-field"].bottom());
        if size.x >= 390. {
            assert!((app.hits["save"].center().y - app.hits["cancel-edit"].center().y).abs() < 1.);
        } else {
            assert!(app.hits["cancel-edit"].top() > app.hits["save"].bottom());
        }
    }
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
fn key(ctx: &egui::Context, app: &mut VaultApp, width: f32, key: egui::Key) {
    for pressed in [true, false] {
        draw(
            ctx,
            app,
            width,
            vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
    }
}

#[test]
fn tag_add_enter_remove_and_save_keep_fields_and_never_save_a_duplicate() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let host = Host::default();
        let mut app = VaultApp::new(&ctx, Box::new(host.clone())).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        app.editing = true;
        app.mobile_detail = true;
        let mut draft = app::new_record().unwrap();
        draft.title = "Tags fixture".into();
        draft.tags = vec!["Original".into()];
        let record = draft.record;
        app.draft = Some(draft);
        app.tag_editor.input = " Screenshots ".into();
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        click(&ctx, &mut app, width, "tag-input");
        key(&ctx, &mut app, width, egui::Key::Enter);
        assert_eq!(
            app.draft.as_ref().unwrap().tags,
            ["Original", "Screenshots"]
        );
        assert!(
            !host
                .0
                .borrow()
                .iter()
                .any(|r| matches!(r.command, Command::Save { .. }))
        );
        app.tag_editor.input = "Screenshots".into();
        draw(&ctx, &mut app, width, vec![]);
        assert!(app.bounds["tag-error"].top() >= app.bounds["save"].bottom());
        assert!(app.bounds["tag-error"].top() >= app.bounds["cancel-edit"].bottom());
        assert!(!app.hits.contains_key("save") && !app.hits.contains_key("tag-add"));
        key(&ctx, &mut app, width, egui::Key::Enter);
        assert!(
            !host
                .0
                .borrow()
                .iter()
                .any(|r| matches!(r.command, Command::Save { .. }))
        );
        click(&ctx, &mut app, width, "tag-remove-1");
        assert_eq!(app.draft.as_ref().unwrap().tags, ["Original"]);
        click(&ctx, &mut app, width, "save");
        let requests = host.0.borrow();
        let Command::Save { draft, .. } = &requests.last().unwrap().command else {
            panic!("save");
        };
        assert_eq!(draft.record, record);
        assert_eq!(draft.tags, ["Original", "Screenshots"]);
        assert!(draft.fields.is_empty());
        assert!(app.tag_editor.input.is_empty());
    }
}

#[test]
fn cancel_and_lock_clear_pending_tags_without_writing_a_record() {
    let ctx = egui::Context::default();
    let host = Host::default();
    let mut app = VaultApp::new(&ctx, Box::new(host.clone())).unwrap();
    app.screen = Screen::Open;
    app.busy = false;
    app.editing = true;
    app.mobile_detail = true;
    app.draft = Some(app::new_record().unwrap());
    app.tag_editor.input = "Private fixture".into();
    for _ in 0..3 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    click(&ctx, &mut app, 390., "cancel-edit");
    assert!(app.tag_editor.input.is_empty() && app.draft.is_none());
    assert!(
        !host
            .0
            .borrow()
            .iter()
            .any(|r| matches!(r.command, Command::Save { .. }))
    );
    app.tag_editor.input = "Another fixture".into();
    app.clear_private();
    assert!(app.tag_editor.input.is_empty());
}
