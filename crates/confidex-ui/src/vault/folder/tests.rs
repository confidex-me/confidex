use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};
#[derive(Clone, Default)]
struct Host {
    requests: Rc<RefCell<Vec<Request>>>,
    replies: Rc<RefCell<VecDeque<Response>>>,
    canceled: Rc<Cell<usize>>,
    picker: Rc<RefCell<Option<FolderFileCompletion>>>,
}
impl Runtime for Host {
    fn sync_available(&self) -> bool {
        true
    }
    fn folder_available(&self) -> bool {
        true
    }
    fn cancel_folder(&mut self) {
        self.canceled.set(self.canceled.get() + 1);
    }
    fn pick_folder(&mut self, done: FolderFileCompletion) {
        *self.picker.borrow_mut() = Some(done);
    }
    fn send(&mut self, request: Request) -> Result<(), Error> {
        self.requests.borrow_mut().push(request);
        Ok(())
    }
    fn receive(&mut self) -> Option<Response> {
        self.replies.borrow_mut().pop_front()
    }
}
fn fixture() -> (VaultApp, Host) {
    let host = Host::default();
    let mut app = VaultApp::new(&egui::Context::default(), Box::new(host.clone())).unwrap();
    host.requests.borrow_mut().clear();
    app.busy = false;
    app.screen = Screen::Open;
    app.active = Some(VaultInfo {
        id: [1; 16],
        name: "Public folder fixture".into(),
    });
    app.folder.path = Some("/public/shared-folder".into());
    app.sync_server = "https://public.example.test/".into();
    (app, host)
}
fn reply(app: &mut VaultApp, host: &Host, result: Result<Output, Error>) {
    host.replies.borrow_mut().push_back(Response {
        generation: app.generation,
        result,
    });
    app.poll();
}
fn synced(app: &mut VaultApp, host: &Host, pending: usize) {
    reply(
        app,
        host,
        Ok(Output::Folder(Ok(Reply::Synced {
            vault: [1; 16],
            report: app::local_sync::Report {
                downloaded: 1,
                uploaded: 1,
                pending,
            },
        }))),
    );
}
fn rows(app: &mut VaultApp, host: &Host) {
    reply(
        app,
        host,
        Ok(Output::Rows {
            rows: vec![],
            more: false,
            next: None,
        }),
    );
}
#[test]
fn unlock_loads_folder_before_scheduling_and_bridges_both_transports() {
    let (mut app, host) = fixture();
    app.folder.path = None;
    reply(
        &mut app,
        &host,
        Ok(Output::Opened {
            info: VaultInfo {
                id: [1; 16],
                name: "Public folder fixture".into(),
            },
            remembered: false,
            server: Some("https://public.example.test/".into()),
            device_unlock_verified_at: None,
        }),
    );
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::Folder(FolderCommand::Status)
    ));
    reply(
        &mut app,
        &host,
        Ok(Output::Folder(Ok(Reply::State {
            vault: [1; 16],
            path: Some("/public/shared-folder".into()),
        }))),
    );
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::Search { .. }
    ));
    rows(&mut app, &host);
    assert!(app.sync_automatic && app.syncing && app.folder.phase == Phase::BeforeHttp);
    synced(&mut app, &host, 2);
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::CheckSync { .. }
    ));
    reply(
        &mut app,
        &host,
        Ok(Output::Synced(app::sync::Report {
            server: Some("https://public.example.test/".into()),
            more: true,
            ..Default::default()
        })),
    );
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::Sync { .. }
    ));
    reply(
        &mut app,
        &host,
        Ok(Output::Synced(app::sync::Report {
            server: Some("https://public.example.test/".into()),
            ..Default::default()
        })),
    );
    assert!(app.syncing && app.sync_automatic && app.folder.phase == Phase::AfterHttp);
    synced(&mut app, &host, 3);
    rows(&mut app, &host);
    assert_eq!(app.folder.pending, 3);
    assert!(app.folder.phase == Phase::Idle && !app.busy && !app.syncing && !app.sync_automatic);
    assert_eq!(app.sync_schedule.failures, 0);
}
#[test]
fn filesystem_only_uses_the_existing_timer_and_keeps_open_content() {
    let (mut app, host) = fixture();
    app.sync_enabled = false;
    let mut draft = app::new_record().unwrap();
    draft.title = "Private selected content".into();
    draft.revision = Some([2; 32]);
    app.draft = Some(draft.clone());
    app.latest_revision = draft.revision;
    app.edit_baseline = Some(draft.clone());
    let now = Instant::now();
    app.sync_schedule.due = Some(now);
    assert_eq!(app.tick_sync(now, true), Some(Duration::ZERO));
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::Folder(FolderCommand::Sync)
    ));
    synced(&mut app, &host, 0);
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::CheckRevision { .. }
    ));
    reply(
        &mut app,
        &host,
        Ok(Output::RecordHead {
            record: draft.record,
            revision: None,
        }),
    );
    rows(&mut app, &host);
    assert!(app.draft.as_ref() == Some(&draft) && app.edit_baseline.as_ref() == Some(&draft));
    assert!(app.latest_revision.is_none());
    assert!(!host.requests.borrow().iter().any(|request| matches!(
        request.command,
        Command::Sync { .. }
            | Command::CheckSync { .. }
            | Command::Open { .. }
            | Command::OpenRevision { .. }
    )));
}
#[test]
fn unavailable_transports_are_independent_and_automatic_errors_stay_quiet() {
    let (mut app, host) = fixture();
    app.sync_enabled = true;
    app.start_sync(true);
    reply(
        &mut app,
        &host,
        Ok(Output::Folder(Err(FolderError::Unavailable))),
    );
    assert!(app.folder.error.is_none() && app.sync_automatic);
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::CheckSync { .. }
    ));
    reply(&mut app, &host, Ok(Output::SyncUnchanged));
    rows(&mut app, &host);
    assert_eq!(app.sync_schedule.failures, 1);
    app.start_sync(true);
    synced(&mut app, &host, 0);
    reply(&mut app, &host, Err(Error::Network));
    assert!(app.folder.phase == Phase::AfterHttp && app.folder.error.is_none());
    synced(&mut app, &host, 0);
    rows(&mut app, &host);
    assert!(app.error.is_none() && app.folder.error.is_none());
    assert_eq!(app.sync_schedule.failures, 2);
    app.start_sync(false);
    reply(
        &mut app,
        &host,
        Ok(Output::Folder(Err(FolderError::Unavailable))),
    );
    assert_eq!(app.folder.error, Some(FolderError::Unavailable));
    reply(&mut app, &host, Ok(Output::SyncUnchanged));
    rows(&mut app, &host);
    assert_eq!(app.folder.error, Some(FolderError::Unavailable));
    app.start_sync(true);
    reply(
        &mut app,
        &host,
        Ok(Output::Folder(Err(FolderError::App(Error::Integrity)))),
    );
    reply(&mut app, &host, Ok(Output::SyncUnchanged));
    rows(&mut app, &host);
    assert_eq!(app.folder.error, Some(FolderError::App(Error::Integrity)));
    app.sync_schedule.due = Some(Instant::now());
    assert!(app.tick_sync(Instant::now(), true).is_none());
}
#[test]
fn picker_cancel_import_configuration_and_stale_replies_keep_their_scope() {
    let (mut app, host) = fixture();
    app.sync_enabled = true;
    app.pick_folder(false);
    host.picker.borrow_mut().take().unwrap()(FolderFileReply::Canceled);
    app.poll();
    assert_eq!(app.folder.path.as_deref(), Some("/public/shared-folder"));
    assert!(host.requests.borrow().is_empty());
    app.pick_folder(false);
    host.picker.borrow_mut().take().unwrap()(FolderFileReply::Selected("/public/other".into()));
    app.poll();
    assert!(
        matches!(&host.requests.borrow().last().unwrap().command, Command::Folder(FolderCommand::Configure { path:Some(path) }) if path == "/public/other")
    );
    reply(
        &mut app,
        &host,
        Ok(Output::Folder(Ok(Reply::State {
            vault: [1; 16],
            path: Some("/public/other".into()),
        }))),
    );
    assert!(app.sync_enabled);
    app.screen = Screen::Catalog;
    app.pick_folder(true);
    host.picker.borrow_mut().take().unwrap()(FolderFileReply::Selected("/public/bootstrap".into()));
    app.poll();
    assert!(app.screen == Screen::Import && app.remember);
    app.name = "New device".into();
    app.password = "public-password".into();
    app.key = "public-key".into();
    app.sync_server.clear();
    assert!(app.credentials_error().is_none());
    let old = app.generation;
    app.request(Command::Lock, true);
    assert!(host.canceled.get() > 0);
    assert!(
        app.folder.path.is_none()
            && app.folder.import_path.is_none()
            && app.password.is_empty()
            && app.key.is_empty()
    );
    host.replies.borrow_mut().push_back(Response {
        generation: old,
        result: Ok(Output::Folder(Ok(Reply::State {
            vault: [1; 16],
            path: Some("/stale".into()),
        }))),
    });
    app.poll();
    assert!(app.folder.path.is_none());
}

#[test]
fn failed_http_page_with_open_content_finishes_without_an_unplanned_retry() {
    let (mut app, host) = fixture();
    app.sync_enabled = true;
    let mut draft = app::new_record().unwrap();
    draft.revision = Some([2; 32]);
    let record = draft.record;
    app.draft = Some(draft);
    app.start_sync(true);
    synced(&mut app, &host, 0);
    reply(
        &mut app,
        &host,
        Ok(Output::Synced(app::sync::Report {
            server: Some("https://public.example.test/".into()),
            more: true,
            ..Default::default()
        })),
    );
    assert!(app.sync_automatic);
    reply(
        &mut app,
        &host,
        Ok(Output::RecordHead {
            record,
            revision: Some([2; 32]),
        }),
    );
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::Sync { .. }
    ));
    app.files.after_sync = true;
    reply(&mut app, &host, Err(Error::Network));
    assert!(app.sync_automatic && app.folder.error.is_none());
    synced(&mut app, &host, 0);
    reply(
        &mut app,
        &host,
        Ok(Output::RecordHead {
            record,
            revision: None,
        }),
    );
    assert!(matches!(
        host.requests.borrow().last().unwrap().command,
        Command::Search { .. }
    ));
    rows(&mut app, &host);
    assert!(!app.files.after_sync && !app.sync_automatic && !app.busy);
    assert_eq!(app.sync_schedule.failures, 1);
}

#[test]
fn long_paths_and_folder_actions_fit_the_shared_settings_rows() {
    for width in [340., 720.] {
        for index in 0..Localizer::languages().len() {
            let (mut app, _) = fixture();
            app.locale = Localizer::new(index).unwrap();
            app.folder.path = Some(format!(
                "/public/{}/Confidex shared vault",
                "very-long-directory-name".repeat(4)
            ));
            let ctx = app.context.clone();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 1200.),
                    )),
                    ..Default::default()
                },
                |ui| {
                    form::group(
                        ui,
                        THEMES[app.theme].colors,
                        "Public folder fixture",
                        |group| app.folder_setting(group),
                    );
                },
            );
            output.textures_delta.clear();
            let bounds = app.bounds["preferences-folder"];
            for id in ["folder-choose", "folder-disconnect"] {
                let button = app.hits[id];
                assert!(
                    bounds.contains_rect(button),
                    "{} {width} {id}: {bounds:?} {button:?}",
                    app.locale.id()
                );
                assert!(button.right() <= width, "{} {width} {id}", app.locale.id());
            }
            assert!(app.hits["folder-choose"].bottom() < app.hits["folder-disconnect"].top());
        }
    }
}
