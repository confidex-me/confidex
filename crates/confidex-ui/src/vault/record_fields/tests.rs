use super::*;
use crate::ImageHost as _;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Default)]
struct RuntimeStub(Rc<RefCell<Vec<Request>>>);
impl Runtime for RuntimeStub {
    fn send(&mut self, request: Request) -> Result<(), Error> {
        self.0.borrow_mut().push(request);
        Ok(())
    }
    fn receive(&mut self) -> Option<Response> {
        None
    }
}
fn draw(ctx: &egui::Context, app: &mut VaultApp, width: f32, events: Vec<egui::Event>) {
    draw_files(ctx, app, width, events, vec![]);
}
fn draw_files(
    ctx: &egui::Context,
    app: &mut VaultApp,
    width: f32,
    events: Vec<egui::Event>,
    dropped_files: Vec<egui::DroppedFileHandle>,
) {
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(width, 1100.),
            )),
            events,
            dropped_files,
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
fn key(ctx: &egui::Context, app: &mut VaultApp, width: f32, key: egui::Key) {
    draw(
        ctx,
        app,
        width,
        vec![egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Default::default(),
        }],
    );
    draw(ctx, app, width, vec![]);
}
fn fixture(ctx: &egui::Context, runtime: RuntimeStub) -> VaultApp {
    let mut app = VaultApp::new(ctx, Box::new(runtime)).unwrap();
    app.screen = Screen::Open;
    app.busy = false;
    app.mobile_detail = true;
    app.editing = true;
    let mut draft = app::new_record().unwrap();
    draft.title = "Record fields fixture".into();
    for text in ["Public A", "Public B", "Public tail"] {
        let mut field = app::field("text/v1").unwrap();
        field.name = "Same".into();
        field.values.insert("text".into(), text.into());
        draft.fields.push(field);
    }
    draft.sections = Some(vec![
        app::sections::Section::new("Same", 0, 1),
        app::sections::Section::new("Same", 1, 1),
        app::sections::Section::new("Same", 2, 0),
    ]);
    app.draft = Some(draft);
    app
}
fn texts(app: &VaultApp) -> Vec<String> {
    app.draft
        .as_ref()
        .unwrap()
        .fields
        .iter()
        .map(|field| field.values["text"].clone())
        .collect()
}

#[test]
fn quick_actions_append_independent_fields_and_focus_their_values() {
    for width in [260., 390., 1180.] {
        for language in ["en-US", "ru"] {
            let ctx = egui::Context::default();
            let runtime = RuntimeStub::default();
            let mut app = fixture(&ctx, runtime.clone());
            app.locale = Localizer::from_preferences(vec![language.to_owned()]).unwrap();
            app.draft.as_mut().unwrap().tags = vec!["Public tag".into()];
            ctx.all_styles_mut(|style| style.animation_time = 0.);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            for (button, kind, value) in [
                ("add-website", "url/v1", "url"),
                ("add-website", "url/v1", "url"),
                ("add-location", "location/v1", "name"),
            ] {
                click(&ctx, &mut app, width, button);
                for _ in 0..30 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                let draft = app.draft.as_ref().unwrap();
                let index = draft.fields.len() - 1;
                assert_eq!(draft.fields[index].type_name, kind);
                assert!(draft.fields[index].values.values().all(String::is_empty));
                let id =
                    egui::Id::unique(("record-fields", draft.record)).with(app.field_ids[index]);
                assert_eq!(
                    ctx.memory(|memory| memory.focused()),
                    Some(id.with(value).with("input"))
                );
                assert!(
                    ctx.content_rect()
                        .contains_rect(app.bounds["record-footer"]),
                    "{language} {width}"
                );
                assert_eq!(draft.tags, ["Public tag"]);
                assert_eq!(
                    draft.fields[..3]
                        .iter()
                        .map(|f| f.values["text"].as_str())
                        .collect::<Vec<_>>(),
                    ["Public A", "Public B", "Public tail"]
                );
                assert_eq!(
                    draft
                        .sections
                        .as_ref()
                        .unwrap()
                        .iter()
                        .map(|s| (s.start, s.count))
                        .collect::<Vec<_>>(),
                    [(0, 1), (1, 1), (2, 0)]
                );
                assert!(!runtime.0.borrow().iter().any(|r| matches!(
                    r.command,
                    Command::Save { .. } | Command::SaveRevision { .. }
                )));
                let rect = if kind == "url/v1" {
                    app.hits[&format!("value-{index}-url")]
                } else {
                    app.hits[&format!("location-{}-name", id.value())]
                };
                assert!(
                    app.bounds["record-viewport"].contains(rect.center()),
                    "{language} {width}: {rect:?} / {:?}",
                    app.bounds["record-viewport"]
                );
            }
            let footer = app.bounds["record-footer"];
            for button in [
                "add-field",
                "add-website",
                "add-location",
                "save",
                "cancel-edit",
            ] {
                assert!(footer.contains_rect(app.hits[button]));
            }
            assert!(app.hits["add-field"].bottom() <= app.hits["add-website"].top());
            assert!(app.hits["add-location"].bottom() <= app.hits["save"].top());
            click(&ctx, &mut app, width, "cancel-edit");
            assert!(!app.editing);
            assert!(!runtime.0.borrow().iter().any(|r| matches!(
                r.command,
                Command::Save { .. } | Command::SaveRevision { .. }
            )));
        }
    }
}

#[test]
fn quick_action_keyboard_activation_does_not_save_and_tag_errors_follow_all_actions() {
    let ctx = egui::Context::default();
    let runtime = RuntimeStub::default();
    let mut app = fixture(&ctx, runtime.clone());
    ctx.all_styles_mut(|style| style.animation_time = 0.);
    for _ in 0..3 {
        draw(&ctx, &mut app, 1180., vec![]);
    }
    ctx.memory_mut(|memory| memory.surrender_focus(memory.focused().unwrap_or(egui::Id::NULL)));
    let mut found = false;
    for _ in 0..100 {
        if ctx
            .memory(|m| m.focused())
            .and_then(|id| ctx.read_response(id))
            .is_some_and(|r| r.rect == app.hits["add-website"])
        {
            found = true;
            break;
        }
        key(&ctx, &mut app, 1180., egui::Key::Tab);
    }
    assert!(found);
    key(&ctx, &mut app, 1180., egui::Key::Enter);
    assert_eq!(
        app.draft.as_ref().unwrap().fields.last().unwrap().type_name,
        "url/v1"
    );
    assert!(app.editing);
    assert!(!runtime.0.borrow().iter().any(|r| matches!(
        r.command,
        Command::Save { .. } | Command::SaveRevision { .. }
    )));
    app.draft.as_mut().unwrap().tags = vec!["duplicate".into()];
    let tag_input = egui::Id::unique(("record-tag-input", app.draft.as_ref().unwrap().record));
    ctx.memory_mut(|memory| memory.request_focus(tag_input));
    draw(
        &ctx,
        &mut app,
        1180.,
        vec![egui::Event::Text("duplicate".into())],
    );
    for _ in 0..3 {
        draw(&ctx, &mut app, 1180., vec![]);
    }
    let bottom = ["add-field", "add-website", "add-location", "cancel-edit"]
        .map(|id| app.hits[id].bottom())
        .into_iter()
        .fold(0., f32::max);
    assert!(app.bounds["tag-error"].top() >= bottom);
    assert!(!app.hits.contains_key("save"));
}

#[test]
fn translated_quick_actions_keep_the_footer_inside_the_viewport() {
    for &(language, _) in Localizer::languages() {
        let ctx = egui::Context::default();
        let mut app = fixture(&ctx, RuntimeStub::default());
        app.locale = Localizer::new(language).unwrap();
        ctx.all_styles_mut(|style| style.animation_time = 0.);
        for width in [260., 390., 1180.] {
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let footer = app.bounds["record-footer"];
            assert!(
                ctx.content_rect().contains_rect(footer),
                "locale {language} width {width}: {footer:?}"
            );
            for button in [
                "add-field",
                "add-website",
                "add-location",
                "save",
                "cancel-edit",
            ] {
                assert!(
                    footer.contains_rect(app.hits[button]),
                    "locale {language} width {width}: {button}"
                );
            }
            assert!(app.hits["add-field"].bottom() <= app.hits["add-website"].top());
            assert!(app.hits["add-location"].bottom() <= app.hits["save"].top());
        }
    }
}

#[derive(Debug)]
struct UnreadDrop;
impl egui::DroppedFile for UnreadDrop {
    fn path(&self) -> &std::path::Path {
        std::path::Path::new("public-drop-fixture.bin")
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        panic!("The UI must use the bounded host reader");
    }
}
fn dropped() -> egui::DroppedFileHandle {
    std::sync::Arc::new(UnreadDrop)
}

#[test]
fn drops_use_the_bounded_import_path_and_stale_results_do_not_restore_a_draft() {
    for width in [390., 1180.] {
        for kind in ["file/v1", "photo/v1", "ssh/v1"] {
            let ctx = egui::Context::default();
            let mut app = fixture(&ctx, RuntimeStub::default());
            let draft = app.draft.as_mut().unwrap();
            draft.fields = vec![app::field(kind).unwrap()];
            draft.sections = Some(vec![]);
            let completion = Rc::new(RefCell::new(None));
            let captured = Rc::new(RefCell::new(None));
            let capture = captured.clone();
            let done = completion.clone();
            app.set_image_handler(move |request, callback| {
                if let crate::ImageRequest::Dropped { image, bytes, .. } = request {
                    *capture.borrow_mut() = Some((image, bytes));
                    *done.borrow_mut() = Some(callback);
                }
            });
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let pos = app.bounds["file-drop-0"].center();
            draw_files(
                &ctx,
                &mut app,
                width,
                vec![egui::Event::PointerMoved(egui::pos2(1., 1.))],
                vec![dropped()],
            );
            assert!(captured.borrow().is_none());
            draw_files(
                &ctx,
                &mut app,
                width,
                vec![egui::Event::PointerMoved(pos)],
                vec![dropped(), dropped()],
            );
            assert!(captured.borrow().is_none());
            assert_eq!(app.file_drop.error.unwrap().1, "field-drop-one");
            draw_files(
                &ctx,
                &mut app,
                width,
                vec![egui::Event::PointerMoved(pos)],
                vec![dropped()],
            );
            assert_eq!(
                *captured.borrow(),
                Some((
                    kind == "photo/v1",
                    if kind == "ssh/v1" {
                        app::ssh::MAX_KEY
                    } else {
                        crate::MAX_IMAGE_SOURCE_BYTES
                    }
                ))
            );
            assert!(app.file_drop.error.is_none());
            app.clear_private();
            completion.borrow_mut().take().unwrap()(crate::ImageReply::Opened(crate::ImageFile {
                name: "public-fixture.bin".into(),
                bytes: b"public fixture".to_vec().into(),
            }));
            app.poll_attachments();
            app.poll_ssh();
            assert!(app.draft.is_none());
        }
    }
}

#[test]
fn read_only_busy_and_covered_fields_do_not_accept_files() {
    for mode in 0..3 {
        let ctx = egui::Context::default();
        let mut app = fixture(&ctx, RuntimeStub::default());
        app.draft.as_mut().unwrap().fields = vec![app::field("file/v1").unwrap()];
        app.draft.as_mut().unwrap().sections = Some(vec![]);
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        let pos = app.bounds["file-drop-0"].center();
        match mode {
            0 => app.editing = false,
            1 => app.busy = true,
            _ => app.preferences.open = true,
        }
        let called = Rc::new(RefCell::new(false));
        let captured = called.clone();
        app.set_image_handler(move |request, _| {
            if matches!(request, crate::ImageRequest::Dropped { .. }) {
                *captured.borrow_mut() = true;
            }
        });
        draw_files(
            &ctx,
            &mut app,
            1180.,
            vec![egui::Event::PointerMoved(pos)],
            vec![dropped()],
        );
        assert!(!*called.borrow(), "mode {mode}");
        assert!(!app.bounds.contains_key("file-drop-0"));
    }
}

#[test]
fn field_menus_follow_each_button_and_scroll_without_changing_the_record() {
    for width in [390., 1180.] {
        for (button, prefix) in [("section-0-add", "section-0-add"), ("add-field", "add")] {
            let ctx = egui::Context::default();
            let mut app = fixture(&ctx, RuntimeStub::default());
            ctx.all_styles_mut(|style| style.animation_time = 0.);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let before = texts(&app);
            click(&ctx, &mut app, width, button);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let menu = app.bounds["field-menu"];
            let anchor = app.hits[button];
            assert!(
                (menu.left() - anchor.left()).abs() < 16.,
                "{menu:?} / {anchor:?}"
            );
            assert!((menu.width() - anchor.width()).abs() < 32.);
            assert!(menu.bottom() <= anchor.top() + 1. || menu.top() >= anchor.bottom() - 1.);
            assert!(menu.height() <= ctx.style_of(egui::Theme::Dark).spacing.combo_height + 1.);
            assert!(ctx.content_rect().contains_rect(menu));
            assert_eq!(texts(&app), before);
            key(&ctx, &mut app, width, egui::Key::Escape);
            assert!(!app.bounds.contains_key("field-menu"));
            click(&ctx, &mut app, width, button);
            let menu = app.bounds["field-menu"];
            for _ in 0..8 {
                draw(
                    &ctx,
                    &mut app,
                    width,
                    vec![
                        egui::Event::PointerMoved(menu.center()),
                        egui::Event::MouseWheel {
                            unit: egui::MouseWheelUnit::Point,
                            source: egui::MouseWheelSource::Unknown,
                            phase: egui::TouchPhase::Move,
                            delta: egui::vec2(0., -300.),
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
            let choice = format!("{prefix}-ssh/v1");
            assert!(
                app.bounds["field-menu"].contains(app.hits[&choice].center()),
                "{width} {button}: {:?} / {:?}",
                app.bounds["field-menu"],
                app.hits[&choice]
            );
            click(&ctx, &mut app, width, &choice);
            assert!(!app.bounds.contains_key("field-menu"));
            let draft = app.draft.as_ref().unwrap();
            let at = if button == "add-field" { 3 } else { 1 };
            assert_eq!(draft.fields.len(), 4);
            assert_eq!(draft.fields[at].type_name, "ssh/v1");
            let section = &draft.sections.as_ref().unwrap()[0];
            assert_eq!(section.count, if button == "add-field" { 1 } else { 2 });
        }
    }
}

#[test]
fn plain_notes_have_no_protection_toggle_and_protected_notes_keep_their_guard() {
    for width in [390., 1180.] {
        for (kind, protected) in [
            ("note/v1", false),
            ("secure-note/v1", true),
            ("note/v1", true),
        ] {
            let ctx = egui::Context::default();
            let host = RuntimeStub::default();
            let mut app = fixture(&ctx, host.clone());
            let mut field = app::field(kind).unwrap();
            field.name = "Notes".into();
            field.protected = protected;
            field
                .values
                .insert("text".into(), "Public note fixture".into());
            let draft = app.draft.as_mut().unwrap();
            draft.fields = vec![field];
            draft.sections = Some(vec![app::sections::Section::new("Section", 0, 1)]);
            for editing in [false, true] {
                app.editing = editing;
                app.revealed.clear();
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                assert_eq!(app.hits.contains_key("protected-0"), protected);
                assert_eq!(app.hits.contains_key("reveal-0-text"), protected);
                assert_eq!(app.draft.as_ref().unwrap().fields[0].type_name, kind);
                assert_eq!(app.draft.as_ref().unwrap().fields[0].protected, protected);
                if protected {
                    click(&ctx, &mut app, width, "reveal-0-text");
                    assert!(app.revealed.iter().any(|(_, key)| key == "text"));
                }
            }
            click(&ctx, &mut app, width, "save");
            let requests = host.0.borrow();
            let Command::Save { draft, .. } = &requests.last().unwrap().command else {
                panic!("save");
            };
            assert_eq!(draft.fields[0].type_name, kind);
            assert_eq!(draft.fields[0].protected, protected);
            assert_eq!(draft.fields[0].values["text"], "Public note fixture");
        }
    }
}

#[test]
fn an_unrendered_binary_field_keeps_its_preservation_caption() {
    let ctx = egui::Context::default();
    let mut app = fixture(&ctx, RuntimeStub::default());
    app.editing = false;
    let mut field = app::field("ssh/v1").unwrap();
    field.data = Some(b"Public binary sentinel".to_vec().into());
    app.draft.as_mut().unwrap().fields[0] = field;
    for _ in 0..3 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(390., 1100.),
            )),
            ..Default::default()
        },
        |ui| app.show(ui),
    );
    output.textures_delta.clear();
    let caption = app.locale.text("vault-opaque-fields");
    assert!(output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.job.text.contains(&caption))));
    assert!(!output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.job.text.contains("Public binary sentinel"))));
}

#[test]
fn an_invalid_section_name_stays_editable_until_corrected_or_ungrouped() {
    let ctx = egui::Context::default();
    let mut app = fixture(&ctx, RuntimeStub::default());
    app.draft.as_mut().unwrap().sections.as_mut().unwrap()[0].name = "я".repeat(2049);
    for _ in 0..3 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    assert!(app.hits.contains_key("section-0-name"));
    assert!(!app.hits.contains_key("save"));
    click(&ctx, &mut app, 390., "section-0-remove");
    assert!(app.hits.contains_key("save"));
    assert_eq!(texts(&app), ["Public A", "Public B", "Public tail"]);
}

#[test]
fn sections_keep_independent_fields_through_keyboard_add_ungroup_and_save() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let runtime = RuntimeStub::default();
        let mut app = fixture(&ctx, runtime.clone());
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        for index in 0..3 {
            let rect = app.bounds[&format!("section-{index}")];
            assert!(
                rect.left() >= 0. && rect.right() <= width,
                "{width} {rect:?}"
            );
        }
        click(&ctx, &mut app, width, "section-0-handle");
        key(&ctx, &mut app, width, egui::Key::ArrowDown);
        assert_eq!(texts(&app), ["Public B", "Public A", "Public tail"]);
        click(&ctx, &mut app, width, "field-handle-0");
        key(&ctx, &mut app, width, egui::Key::ArrowDown);
        assert_eq!(texts(&app), ["Public A", "Public B", "Public tail"]);
        assert_eq!(
            app.draft.as_ref().unwrap().sections.as_ref().unwrap()[0].count,
            0
        );
        click(&ctx, &mut app, width, "section-0-add");
        click(&ctx, &mut app, width, "section-0-add-text/v1");
        assert_eq!(texts(&app), ["", "Public A", "Public B", "Public tail"]);
        assert_eq!(
            app.draft.as_ref().unwrap().sections.as_ref().unwrap()[0].count,
            1
        );
        click(&ctx, &mut app, width, "section-0-remove");
        assert_eq!(texts(&app), ["", "Public A", "Public B", "Public tail"]);
        assert_eq!(
            app.draft.as_ref().unwrap().sections.as_ref().unwrap().len(),
            2
        );
        click(&ctx, &mut app, width, "save");
        let requests = runtime.0.borrow();
        let Command::Save { draft, .. } = &requests.last().unwrap().command else {
            panic!("save");
        };
        let sections = draft.sections.as_ref().unwrap();
        assert_eq!((sections[0].start, sections[0].count), (1, 2));
        assert_eq!((sections[1].start, sections[1].count), (3, 0));
        assert_eq!(draft.fields.len(), 4);
    }
}

#[test]
fn dragging_into_an_empty_section_retains_all_values() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let mut app = fixture(&ctx, RuntimeStub::default());
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        let start = app.hits["field-handle-0"].center();
        let end = app.hits["section-2-name"].center();
        drag(&ctx, &mut app, width, start, end);
        assert_eq!(texts(&app), ["Public B", "Public A", "Public tail"]);
        let draft = app.draft.as_ref().unwrap();
        let sections = draft.sections.as_ref().unwrap();
        assert_eq!(
            (sections[0].count, sections[2].start, sections[2].count),
            (0, 1, 1)
        );
        app::sections::validate(sections, draft.fields.len()).unwrap();
    }
}

#[test]
fn dragging_a_section_moves_all_its_children_together() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let mut app = fixture(&ctx, RuntimeStub::default());
        app.draft.as_mut().unwrap().sections = Some(vec![
            app::sections::Section::new("Same", 0, 2),
            app::sections::Section::new("Same", 2, 1),
        ]);
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        let start = app.hits["section-0-handle"].center();
        let target = app.bounds["section-1"];
        let end = egui::pos2(target.center().x, target.bottom() - 2.);
        drag(&ctx, &mut app, width, start, end);
        assert_eq!(texts(&app), ["Public tail", "Public A", "Public B"]);
        let draft = app.draft.as_ref().unwrap();
        let sections = draft.sections.as_ref().unwrap();
        assert_eq!(
            (sections[0].count, sections[1].start, sections[1].count),
            (1, 1, 2)
        );
    }
}

fn drag(ctx: &egui::Context, app: &mut VaultApp, width: f32, start: egui::Pos2, end: egui::Pos2) {
    draw(
        ctx,
        app,
        width,
        vec![
            egui::Event::PointerMoved(start),
            egui::Event::PointerButton {
                pos: start,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: Default::default(),
            },
        ],
    );
    for pos in [start + Vec2::new(0., 20.), end, end] {
        draw(ctx, app, width, vec![egui::Event::PointerMoved(pos)]);
    }
    draw(
        ctx,
        app,
        width,
        vec![egui::Event::PointerButton {
            pos: end,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: Default::default(),
        }],
    );
    draw(ctx, app, width, vec![]);
}
