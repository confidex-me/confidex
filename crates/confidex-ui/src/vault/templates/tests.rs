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
    draw(ctx, app, width, vec![]);
}

#[test]
fn grid_navigation_keeps_columns_across_featured_and_regular_rows() {
    let desktop = rows(6, 24, 800.);
    assert_eq!(next_row(&desktop, 0, true), 3);
    assert_eq!(next_row(&desktop, 3, true), 6);
    assert_eq!(next_row(&desktop, 5, true), 7);
    assert_eq!(next_row(&desktop, 7, false), 4);
    let mobile = rows(6, 24, 330.);
    assert_eq!(next_row(&mobile, 0, true), 1);
    assert_eq!(next_row(&mobile, 23, true), 0);
    assert_eq!(next_row(&mobile, 0, false), 23);
}

#[test]
fn every_catalogue_choice_creates_only_a_draft_and_localizes_its_fields_and_sections() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let host = Host::default();
        let mut app = VaultApp::new(&ctx, Box::new(host.clone())).unwrap();
        app.locale = Localizer::new(1).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        for template in app::templates::CATALOG {
            app.draft = None;
            app.editing = false;
            app.mobile_detail = false;
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "new-record");
            app.template_query = template.id.replace('-', " ");
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(
                app.bounds["template-body"]
                    .expand(1.)
                    .contains_rect(app.bounds["template-caption"])
            );
            assert!(
                app.hits.contains_key(&format!("template-{}", template.id)),
                "{}",
                template.id
            );
            key(&ctx, &mut app, width, egui::Key::Enter);
            let draft = app.draft.as_ref().expect(template.id);
            assert!(!app.templates.open && app.editing);
            let tag = template.name;
            assert_eq!(draft.tags, [tag]);
            assert_eq!(draft.fields.len(), template.fields.len());
            for (field, spec) in draft.fields.iter().zip(template.fields) {
                assert_eq!(field.type_name, spec.type_name);
                let label = name_key(spec.name);
                assert_ne!(app.locale.text(&label), label, "{} {label}", template.id);
                assert_eq!(field.name, app.locale.text(&label));
            }
            for section in draft.sections.as_ref().unwrap() {
                assert!(!section.name.starts_with("starter-"));
            }
            let names: Vec<_> = draft
                .fields
                .iter()
                .map(|field| field.name.clone())
                .collect();
            let sections: Vec<_> = draft
                .sections
                .as_ref()
                .unwrap()
                .iter()
                .map(|section| section.name.clone())
                .collect();
            app.locale = Localizer::new(0).unwrap();
            draw(&ctx, &mut app, width, vec![]);
            let draft = app.draft.as_ref().unwrap();
            assert_eq!(draft.tags, [tag]);
            assert_eq!(
                draft
                    .fields
                    .iter()
                    .map(|field| field.name.clone())
                    .collect::<Vec<_>>(),
                names
            );
            assert_eq!(
                draft
                    .sections
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|section| section.name.clone())
                    .collect::<Vec<_>>(),
                sections
            );
            assert!(!host.0.borrow().iter().any(|request| matches!(
                &request.command,
                Command::Save { .. } | Command::SaveRevision { .. }
            )));
            app.locale = Localizer::new(1).unwrap();
        }
    }
}

#[test]
fn new_template_focus_reveals_the_title_after_a_scrolled_record() {
    let ctx = egui::Context::default();
    ctx.all_styles_mut(|style| style.animation_time = 0.);
    let mut app = VaultApp::new(&ctx, Box::new(Host::default())).unwrap();
    app.screen = Screen::Open;
    app.busy = false;
    app.mobile_detail = true;
    app.editing = true;
    let mut draft = app::new_record().unwrap();
    draft.title = "Long record".into();
    draft.fields = (0..30).map(|_| app::field("text/v1").unwrap()).collect();
    app.draft = Some(draft);
    for _ in 0..3 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    let pointer = app.bounds["record-viewport"].center();
    draw(
        &ctx,
        &mut app,
        390.,
        vec![
            egui::Event::PointerMoved(pointer),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                source: egui::MouseWheelSource::Unknown,
                phase: egui::TouchPhase::Move,
                delta: egui::vec2(0., -2400.),
                modifiers: Default::default(),
            },
        ],
    );
    for _ in 0..30 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    assert!(app.hits["record-title"].bottom() < app.bounds["record-viewport"].top());
    click(&ctx, &mut app, 390., "cancel-edit");
    click(&ctx, &mut app, 390., "new-record");
    app.template_query = "email".into();
    for _ in 0..3 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    click(&ctx, &mut app, 390., "template-email");
    for _ in 0..30 {
        draw(&ctx, &mut app, 390., vec![]);
    }
    assert!(
        app.bounds["record-viewport"].contains_rect(app.hits["record-title"]),
        "title {:?}, viewport {:?}, focus {:?}",
        app.hits["record-title"],
        app.bounds["record-viewport"],
        ctx.memory(|memory| memory.focused())
    );
    assert_eq!(
        ctx.memory(|memory| memory.focused()),
        Some(egui::Id::unique("record-title"))
    );
    assert_eq!(app.draft.as_ref().unwrap().tags, ["Email"]);
}

#[test]
fn legacy_starters_also_use_english_tags_in_a_russian_interface() {
    let ctx = egui::Context::default();
    let mut app = VaultApp::new(&ctx, Box::new(Host::default())).unwrap();
    app.locale = Localizer::new(1).unwrap();
    app.screen = Screen::Open;
    app.busy = false;
    for (kind, tag) in [("wifi", "Wi-Fi network"), ("note", "Note")] {
        app.draft = None;
        app.editing = false;
        app.mobile_detail = false;
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        click(&ctx, &mut app, 1180., "new-record");
        app.template_query = kind.into();
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        click(&ctx, &mut app, 1180., &format!("template-{kind}"));
        assert_eq!(app.draft.as_ref().unwrap().tags, [tag]);
    }
}

#[test]
fn search_empty_state_keeps_empty_record_reachable_and_escape_does_not_write() {
    for width in [390., 1180.] {
        let ctx = egui::Context::default();
        let host = Host::default();
        let mut app = VaultApp::new(&ctx, Box::new(host.clone())).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        click(&ctx, &mut app, width, "new-record");
        app.template_query = "no such template".into();
        for _ in 0..3 {
            draw(&ctx, &mut app, width, vec![]);
        }
        assert!(!app.hits.contains_key("template-login"));
        assert!(app.hits.contains_key("template-empty"));
        key(&ctx, &mut app, width, egui::Key::Enter);
        assert!(app.draft.is_none());
        click(&ctx, &mut app, width, "template-empty");
        assert!(app.draft.as_ref().unwrap().fields.is_empty());
        assert!(app.draft.as_ref().unwrap().tags.is_empty());
        click(&ctx, &mut app, width, "cancel-edit");
        click(&ctx, &mut app, width, "new-record");
        key(&ctx, &mut app, width, egui::Key::Escape);
        assert!(app.draft.is_none() && !app.templates.open);
        assert!(
            !host
                .0
                .borrow()
                .iter()
                .any(|request| matches!(&request.command, Command::Save { .. }))
        );
    }
}
