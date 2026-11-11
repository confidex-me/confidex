use super::*;
use app::{export, export_flow as flow};
use design::exporter::{Event, Stage};
use std::sync::mpsc;
use zeroize::Zeroizing;

enum FileReply {
    Keyfile(ImportFileReply),
    Saved(ExportFileReply),
}
pub(super) struct Files {
    sender: mpsc::Sender<(u32, u32, FileReply)>,
    receiver: mpsc::Receiver<(u32, u32, FileReply)>,
    serial: u32,
    picking: bool,
    keyfile: Option<Zeroizing<Vec<u8>>>,
    transfer: Option<flow::Transfer>,
    artifact: Option<[u8; 16]>,
    chunk_offset: usize,
    pub pending: bool,
    after: Option<confidex_storage::Head>,
    pages: usize,
    deferred: Option<flow::Command>,
}
impl Default for Files {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            sender,
            receiver,
            serial: 0,
            picking: false,
            keyfile: None,
            transfer: None,
            artifact: None,
            chunk_offset: 0,
            pending: false,
            after: None,
            pages: 0,
            deferred: None,
        }
    }
}
impl Files {
    fn discard_file(&mut self) {
        self.serial = self
            .serial
            .checked_add(1)
            .expect("export file generation exhausted");
        self.picking = false;
        self.keyfile = None;
        if let Some(transfer) = self.transfer.take() {
            transfer.cancel();
        }
        self.artifact = None;
        self.chunk_offset = 0;
    }
    pub fn clear(&mut self) {
        self.discard_file();
        self.pending = false;
        self.after = None;
        self.pages = 0;
        self.deferred = None;
    }
}
impl VaultApp {
    fn export_request(&mut self, command: flow::Command) {
        if self.export_files.pending {
            self.export_files.deferred = Some(command);
            return;
        }
        self.export_files.pending = true;
        if let Err(error) = self.runtime.send(Request {
            generation: self.generation,
            command: Command::VendorExport(command),
        }) {
            self.export_files.pending = false;
            self.export_failed(flow::Error::App(error));
        }
    }
    fn export_failed(&mut self, error: flow::Error) {
        self.export_files.discard_file();
        self.exporter.password.zeroize();
        self.exporter.keyfile = None;
        self.exporter.csv = design::exporter::CsvState::default();
        self.exporter.stage = Stage::Failed;
        self.exporter.error = Some(error);
        self.export_files.deferred = Some(flow::Command::Cancel { token: None });
    }
    fn cancel_record_export(&mut self) {
        self.runtime.cancel_export(self.exporter.operation);
        self.export_files.discard_file();
        self.exporter.window.close(&self.context);
        self.exporter.clear();
        self.export_request(flow::Command::Cancel { token: None });
    }
    pub(super) fn export_action(&mut self, ui: &mut egui::Ui) -> bool {
        let enabled = !self.busy
            && !self.editing
            && !self.loading_more
            && !self.export_files.pending
            && !self.import_files.pending;
        let response = design::button(
            ui,
            THEMES[self.theme].colors,
            &self.locale.text("export-title"),
            ButtonRole::Secondary,
            ui.available_width(),
            enabled,
        );
        if enabled {
            self.hits.insert("export-records".into(), response.rect);
        }
        if response.clicked() {
            self.export_files.clear();
            self.exporter.clear();
            self.exporter.all = true;
            self.exporter.window.open(&response);
            self.export_request(flow::Command::Begin);
            return true;
        }
        false
    }
    fn list_export_records(&mut self) {
        let operation = self.exporter.next_operation();
        self.export_request(flow::Command::List {
            operation,
            after: self.export_files.after.clone(),
        });
    }
    fn export_rows(&mut self, page: flow::SelectionPage) {
        let flow::SelectionPage { rows, more, next } = page;
        if self.exporter.window.open {
            let previous = self.export_files.after.as_ref();
            if self.export_files.pages >= 100_000usize.div_ceil(confidex_storage::PAGE_SIZE)
                || rows.len() > confidex_storage::PAGE_SIZE
                || (more && next.is_none())
                || next
                    .as_ref()
                    .is_some_and(|next| previous.is_some_and(|previous| next <= previous))
                || self.exporter.rows.len() + rows.len() > export::Limits::default().records
                || rows.iter().enumerate().any(|(index, row)| {
                    row.index != index
                        || row.title.chars().count() > 128
                        || row.fields > confidex_vault::record::MAX_ENTRIES
                })
                || rows.windows(2).any(|p| p[0].head >= p[1].head)
                || rows
                    .first()
                    .is_some_and(|r| previous.is_some_and(|p| &r.head <= p))
                || rows
                    .last()
                    .is_some_and(|r| next.as_ref().is_none_or(|n| &r.head > n))
            {
                self.export_failed(flow::Error::App(Error::Integrity));
            } else {
                self.export_files.pages += 1;
                self.export_files.after = next;
                for mut row in rows {
                    row.index = self.exporter.rows.len();
                    self.exporter.rows.push(row);
                }
                if more {
                    self.list_export_records();
                } else {
                    self.exporter.stage = Stage::Setup;
                }
            }
        }
        self.flush_export_request();
    }
    fn flush_export_request(&mut self) {
        if !self.export_files.pending
            && let Some(command) = self.export_files.deferred.take()
        {
            self.export_request(command);
        }
    }
    pub(super) fn export_reply(&mut self, result: Result<flow::Reply, flow::Error>) {
        if matches!(&result, Ok(flow::Reply::Fields { operation, .. }) if *operation != self.exporter.operation)
        {
            return;
        }
        if !matches!(&result, Ok(flow::Reply::Progress { .. })) {
            self.export_files.pending = false;
        }
        if !self.exporter.window.open {
            if !matches!(&result, Ok(flow::Reply::Canceled | flow::Reply::Finished)) {
                self.export_files.deferred = Some(flow::Command::Cancel { token: None });
            }
            if let Ok(flow::Reply::Progress { operation, .. }) = result {
                self.runtime.cancel_export(operation);
            }
            self.flush_export_request();
            return;
        }
        let reply = match result {
            Ok(reply) => reply,
            Err(error) => {
                self.export_failed(error);
                self.flush_export_request();
                return;
            }
        };
        match reply {
            flow::Reply::Fields {
                operation,
                vault,
                head,
                start,
                fields,
            } => {
                if self.exporter.stage == Stage::Setup
                    && self.exporter.selected_format() == Some(export::Format::Csv)
                {
                    if self.active.as_ref().is_none_or(|active| active.id != vault) {
                        self.export_failed(flow::Error::App(Error::Integrity));
                    } else if !self.exporter.rows.iter().any(|row| {
                        row.head == head
                            && (self.exporter.all || self.exporter.selected.contains(&row.index))
                    }) {
                        self.exporter.csv.clear_sources();
                    } else if let Err(error) =
                        self.exporter.csv.accept(operation, head, start, fields)
                    {
                        self.export_failed(error);
                    }
                }
            }
            flow::Reply::Listed {
                operation,
                vault,
                after,
                page,
            } if operation == self.exporter.operation
                && self.active.as_ref().is_some_and(|v| v.id == vault)
                && after == self.export_files.after =>
            {
                self.export_rows(page)
            }

            flow::Reply::Begun { vault, formats }
                if self.active.as_ref().is_some_and(|v| v.id == vault) =>
            {
                self.exporter.formats = formats;
                self.exporter.format = 0;
                self.exporter.use_password = matches!(
                    self.exporter.selected_format(),
                    Some(export::Format::Kdbx | export::Format::BitwardenEncryptedJson)
                );
                if self.exporter.formats.is_empty() {
                    self.exporter.stage = Stage::Setup;
                } else {
                    self.list_export_records();
                }
            }
            flow::Reply::Progress {
                operation,
                progress,
            } if operation == self.exporter.operation => self.exporter.progress = Some(progress),
            flow::Reply::Reviewed { operation, review }
                if operation == self.exporter.operation
                    && self.active.as_ref().is_some_and(|v| v.id == review.vault) =>
            {
                if review.records > export::Limits::default().records
                    || review.losses.saturating_add(review.blocked)
                        > export::Limits::default().issues
                {
                    self.export_failed(flow::Error::App(Error::Integrity));
                } else {
                    let token = review.token;
                    self.exporter.review = Some(review);
                    self.exporter.issues.clear();
                    self.exporter.allow_losses = false;
                    self.exporter.plaintext_ack = false;
                    self.exporter.password.zeroize();
                    self.export_files.keyfile = None;
                    self.exporter.keyfile = None;
                    self.export_request(flow::Command::Issues { token, start: 0 });
                }
            }
            flow::Reply::Issues {
                token,
                start,
                issues,
            } if self
                .exporter
                .review
                .as_ref()
                .is_some_and(|r| r.token == token)
                && start == self.exporter.issues.len() =>
            {
                let review = self.exporter.review.as_ref().unwrap();
                let total = review.losses + review.blocked;
                let end = start.saturating_add(issues.items.len());
                if issues.items.len() > flow::PAGE_SIZE
                    || end > total
                    || issues.next != (end < total).then_some(end)
                    || (end < total && end == start)
                    || issues.items.iter().any(|row| {
                        row.issue.record >= review.records
                            || row
                                .issue
                                .field
                                .is_some_and(|field| field >= confidex_vault::record::MAX_ENTRIES)
                            || row.title.chars().count() > 128
                            || row
                                .field_name
                                .as_ref()
                                .is_some_and(|name| name.chars().count() > 128)
                    })
                {
                    self.export_failed(flow::Error::App(Error::Integrity));
                } else {
                    self.exporter.issues.extend(issues.items);
                    if let Some(start) = issues.next {
                        self.export_request(flow::Command::Issues { token, start });
                    } else {
                        let losses = self
                            .exporter
                            .issues
                            .iter()
                            .filter(|r| r.issue.severity == export::Severity::Loss)
                            .count();
                        if losses != review.losses
                            || self.exporter.issues.len() - losses != review.blocked
                        {
                            self.export_failed(flow::Error::App(Error::Integrity));
                        } else {
                            self.exporter.stage = Stage::Review;
                        }
                    }
                }
            }
            flow::Reply::Ready { operation, ready }
                if operation == self.exporter.operation
                    && self.exporter.stage == Stage::Generating =>
            {
                if self.exporter.review.as_ref().is_none_or(|r| {
                    r.file.name != ready.file.name
                        || r.file.media_type != ready.file.media_type
                        || r.file.encrypted != ready.file.encrypted
                }) {
                    self.export_failed(flow::Error::App(Error::Integrity));
                } else {
                    match flow::Transfer::new(&ready) {
                        Ok(transfer) => {
                            self.exporter.bytes = ready.bytes;
                            self.export_files.transfer = Some(transfer);
                            self.export_files.artifact = Some(ready.token);
                            self.export_files.chunk_offset = 0;
                            self.exporter.stage = Stage::Collecting;
                            self.export_request(flow::Command::Chunk {
                                token: ready.token,
                                offset: 0,
                            });
                        }
                        Err(_) => {
                            self.export_failed(flow::Error::Export(export::Error::Allocation))
                        }
                    }
                }
            }
            flow::Reply::Chunk { token, chunk }
                if self.export_files.artifact == Some(token)
                    && self.exporter.stage == Stage::Collecting =>
            {
                if chunk.offset != self.export_files.chunk_offset
                    || self
                        .export_files
                        .transfer
                        .as_ref()
                        .is_none_or(|t| t.append(chunk.offset, &chunk.bytes, chunk.next).is_err())
                {
                    self.export_failed(flow::Error::App(Error::Integrity));
                } else if let Some(offset) = chunk.next {
                    self.export_files.chunk_offset = offset;
                    self.export_request(flow::Command::Chunk { token, offset });
                } else {
                    self.export_request(flow::Command::Finish { token });
                }
            }
            flow::Reply::Finished
                if self.exporter.stage == Stage::Collecting
                    && self
                        .export_files
                        .transfer
                        .as_ref()
                        .is_some_and(flow::Transfer::available) =>
            {
                self.export_files.artifact = None;
                self.exporter.stage = Stage::Ready;
            }
            flow::Reply::Canceled => (),
            _ => self.export_failed(flow::Error::App(Error::Integrity)),
        }
        self.flush_export_request();
    }
    pub(super) fn poll_export_file(&mut self) {
        while let Ok((generation, serial, reply)) = self.export_files.receiver.try_recv() {
            if generation != self.generation
                || serial != self.export_files.serial
                || !self.exporter.window.open
            {
                continue;
            }
            self.export_files.picking = false;
            match reply {
                FileReply::Keyfile(ImportFileReply::Selected(mut file))
                    if file.bytes.len() <= export::MAX_KEYFILE_BYTES && file.name.len() <= 4096 =>
                {
                    self.exporter.keyfile = Some(app::import_flow::File {
                        name: std::mem::take(&mut file.name),
                        bytes: file.bytes.len(),
                    });
                    self.export_files.keyfile =
                        Some(Zeroizing::new(std::mem::take(&mut file.bytes)));
                }
                FileReply::Keyfile(ImportFileReply::Canceled) => (),
                FileReply::Keyfile(_) => {
                    self.exporter.notice = Some("export-file-error");
                }
                FileReply::Saved(reply) => {
                    self.export_files.discard_file();
                    self.exporter.stage = if matches!(
                        reply,
                        ExportFileReply::Saved | ExportFileReply::DownloadStarted
                    ) {
                        Stage::Complete
                    } else {
                        Stage::Failed
                    };
                    self.exporter.notice = Some(match reply {
                        ExportFileReply::Saved => "backup-saved",
                        ExportFileReply::DownloadStarted => "backup-download-started",
                        ExportFileReply::Canceled => "export-canceled",
                        ExportFileReply::Failed => "export-file-error",
                    });
                }
            }
        }
    }
    pub(super) fn export_window(&mut self, ui: &mut egui::Ui) {
        self.exporter.waiting = self.export_files.pending || self.export_files.picking;
        self.exporter
            .show_window(ui.ctx(), THEMES[self.theme].colors, &self.locale);
        self.hits.extend(self.exporter.hits.clone());
        self.bounds.extend(self.exporter.bounds.clone());
        for event in self.exporter.take_events() {
            match event {
                Event::Fields {
                    operation,
                    head,
                    start,
                } if !self.export_files.pending
                    && self.exporter.stage == Stage::Setup
                    && self.exporter.selected_format() == Some(export::Format::Csv) =>
                {
                    self.export_request(flow::Command::Fields {
                        operation,
                        head,
                        start,
                    });
                }
                Event::Cancel => self.cancel_record_export(),
                Event::Restart if !self.export_files.pending => {
                    let window = std::mem::take(&mut self.exporter.window);
                    self.export_files.clear();
                    self.exporter.clear();
                    self.exporter.window = window;
                    self.exporter.all = true;
                    self.export_request(flow::Command::Begin);
                }
                Event::Review if self.exporter.configured() && !self.export_files.pending => {
                    let Some(format) = self.exporter.selected_format() else {
                        continue;
                    };
                    let selection = self.exporter.selection();
                    let options = if format == export::Format::Csv {
                        match self.exporter.csv.take_config() {
                            Ok(config) => export::Options::Csv(config),
                            Err(error) => {
                                self.export_failed(error.into());
                                continue;
                            }
                        }
                    } else if format == export::Format::Kdbx {
                        export::Options::Password {
                            password: self
                                .exporter
                                .use_password
                                .then(|| std::mem::take(&mut *self.exporter.password)),
                            keyfile: if self.exporter.use_keyfile {
                                self.export_files
                                    .keyfile
                                    .take()
                                    .map(|mut bytes| std::mem::take(&mut *bytes))
                            } else {
                                None
                            },
                        }
                    } else if matches!(
                        format,
                        export::Format::BitwardenJson | export::Format::BitwardenEncryptedJson
                    ) {
                        export::Options::Bitwarden {
                            organization: self.exporter.organization,
                            password: (format == export::Format::BitwardenEncryptedJson)
                                .then(|| std::mem::take(&mut *self.exporter.password)),
                        }
                    } else {
                        export::Options::Plain
                    };
                    if let Err(error) = options.validate(format) {
                        self.export_failed(error.into());
                        continue;
                    }
                    let operation = self.exporter.next_operation();
                    self.exporter.stage = Stage::Loading;
                    self.exporter.error = None;
                    self.export_request(flow::Command::Prepare {
                        operation,
                        created_at: epoch() / 1000,
                        format,
                        options,
                        selection,
                    });
                }
                Event::Generate if self.exporter.can_generate() && !self.export_files.pending => {
                    let token = self.exporter.review.as_ref().unwrap().token;
                    let consent = if self.exporter.allow_losses {
                        export::Consent::AllowLosses
                    } else {
                        export::Consent::Lossless
                    };
                    let operation = self.exporter.next_operation();
                    self.exporter.stage = Stage::Generating;
                    self.exporter.progress = None;
                    self.export_request(flow::Command::Generate {
                        operation,
                        token,
                        consent,
                    });
                }
                Event::Save
                    if self.exporter.stage == Stage::Ready && !self.export_files.pending =>
                {
                    if let Some(transfer) = self.export_files.transfer.clone() {
                        self.exporter.stage = Stage::Saving;
                        let sender = self.export_files.sender.clone();
                        let generation = self.generation;
                        let serial = self.export_files.serial;
                        let ctx = ui.ctx().clone();
                        self.runtime.save_export(
                            transfer,
                            Box::new(move |reply| {
                                let _ = sender.send((generation, serial, FileReply::Saved(reply)));
                                ctx.request_repaint();
                            }),
                        );
                    }
                }
                Event::ChooseKeyfile if !self.export_files.picking => {
                    self.export_files.picking = true;
                    self.export_files.serial = self
                        .export_files
                        .serial
                        .checked_add(1)
                        .expect("export file generation exhausted");
                    let serial = self.export_files.serial;
                    let generation = self.generation;
                    let sender = self.export_files.sender.clone();
                    let ctx = ui.ctx().clone();
                    self.pick_import_file(
                        crate::ImportFileRequest::Keyfile,
                        Box::new(move |reply| {
                            let _ = sender.send((generation, serial, FileReply::Keyfile(reply)));
                            ctx.request_repaint();
                        }),
                    );
                }
                Event::ClearKeyfile => {
                    self.export_files.keyfile = None;
                    self.export_files.picking = false;
                    self.export_files.serial = self
                        .export_files
                        .serial
                        .checked_add(1)
                        .expect("export file generation exhausted");
                }
                _ => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[derive(Default)]
    struct HostState {
        requests: Vec<Request>,
        saved: Option<(flow::Transfer, ExportFileCompletion)>,
        canceled: Vec<u32>,
    }
    struct Host(Rc<RefCell<HostState>>);
    impl Runtime for Host {
        fn send(&mut self, request: Request) -> Result<(), Error> {
            self.0.borrow_mut().requests.push(request);
            Ok(())
        }
        fn receive(&mut self) -> Option<Response> {
            None
        }
        fn cancel_export(&mut self, operation: u32) {
            self.0.borrow_mut().canceled.push(operation);
        }
        fn save_export(&mut self, transfer: flow::Transfer, done: ExportFileCompletion) {
            self.0.borrow_mut().saved = Some((transfer, done));
        }
    }
    fn app() -> (VaultApp, Rc<RefCell<HostState>>, egui::Context) {
        let ctx = egui::Context::default();
        let host = Rc::new(RefCell::new(HostState::default()));
        let mut app = VaultApp::new(&ctx, Box::new(Host(host.clone()))).unwrap();
        app.active = Some(VaultInfo {
            id: [1; 16],
            name: "Public vault".into(),
        });
        app.busy = false;
        app.screen = Screen::Open;
        app.exporter.window.open = true;
        app.exporter.all = true;
        host.borrow_mut().requests.clear();
        app.export_request(flow::Command::Begin);
        app.export_reply(Ok(flow::Reply::Begun {
            vault: [1; 16],
            formats: vec![export::FormatInfo {
                format: export::Format::KeepassXml,
                label: "Public synthetic test".into(),
            }],
        }));
        assert!(matches!(
            host.borrow().requests.last().unwrap().command,
            Command::VendorExport(flow::Command::List { .. })
        ));
        app.export_reply(Ok(flow::Reply::Listed {
            operation: app.exporter.operation,
            vault: [1; 16],
            after: None,
            page: flow::SelectionPage {
                rows: vec![flow::Row {
                    index: 0,
                    head: confidex_storage::Head {
                        record: [2; 16],
                        revision: [3; 32],
                    },
                    title: "Public record".into(),
                    fields: 1,
                }],
                more: false,
                next: Some(confidex_storage::Head {
                    record: [2; 16],
                    revision: [3; 32],
                }),
            },
        }));
        (app, host, ctx)
    }
    #[test]
    fn export_selection_keeps_two_revisions_of_the_same_record() {
        let (mut app, _, _) = app();
        let second = confidex_storage::Head {
            record: [2; 16],
            revision: [4; 32],
        };
        app.export_rows(flow::SelectionPage {
            rows: vec![flow::Row {
                index: 0,
                head: second.clone(),
                title: "Public second branch".into(),
                fields: 1,
            }],
            more: false,
            next: Some(second.clone()),
        });
        assert_eq!(app.exporter.stage, Stage::Setup);
        assert_eq!(app.exporter.rows.len(), 2);
        app.exporter.all = false;
        app.exporter.selected.insert(1);
        let flow::Selection::Records(selected) = app.exporter.selection() else {
            panic!("selection")
        };
        assert_eq!(selected, vec![second]);
        app.exporter.selected.insert(0);
        let flow::Selection::Records(selected) = app.exporter.selection() else {
            panic!("selection")
        };
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].record, selected[1].record);
        assert_ne!(selected[0].revision, selected[1].revision);
    }
    fn frame(app: &mut VaultApp, ctx: &egui::Context, events: Vec<egui::Event>) {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(1320., 1000.),
                )),
                events,
                ..Default::default()
            },
            |ui| app.export_window(ui),
        );
        output.textures_delta.clear();
    }
    fn click(app: &mut VaultApp, ctx: &egui::Context, id: &str) {
        for _ in 0..3 {
            frame(app, ctx, vec![]);
        }
        let pos = app.exporter.hits[id].center();
        frame(
            app,
            ctx,
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
        frame(
            app,
            ctx,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
    }
    fn file() -> flow::File {
        flow::File {
            name: "public.json".into(),
            media_type: "application/json".into(),
            encrypted: false,
        }
    }
    fn reviewed(app: &mut VaultApp) {
        let operation = app.exporter.operation;
        app.export_reply(Ok(flow::Reply::Reviewed {
            operation,
            review: flow::Review {
                token: [4; 16],
                vault: [1; 16],
                format: export::Format::KeepassXml,
                file: file(),
                records: 1,
                losses: 0,
                blocked: 0,
            },
        }));
        app.export_reply(Ok(flow::Reply::Issues {
            token: [4; 16],
            start: 0,
            issues: flow::Issues {
                items: vec![],
                next: None,
            },
        }));
    }
    fn chunk(offset: usize, bytes: &[u8], next: Option<usize>) -> flow::Chunk {
        serde_json::from_value(serde_json::json!({"offset":offset,"bytes":bytes,"next":next}))
            .unwrap()
    }
    fn csv_fields(operation: u32, head: confidex_storage::Head, index: usize) -> flow::Reply {
        flow::Reply::Fields { operation, vault: [1;16], head, start: 0, fields: serde_json::from_value(serde_json::json!({"items":[{"index":index,"name":"Password","type_name":"password/v1","key":"password"}],"next":null})).unwrap() }
    }
    #[test]
    fn csv_setup_checks_selection_and_transfers_the_exact_configuration() {
        let (mut app, host, ctx) = app();
        app.exporter.formats[0].format = export::Format::Csv;
        app.exporter.formats[0].label = "CSV".into();
        app.exporter.csv.manual.delimiter = b';';
        app.exporter.csv.manual.header = false;
        app.exporter
            .csv
            .add("User header".into(), export::Source::Title)
            .unwrap();
        let head = app.exporter.rows[0].head.clone();
        app.exporter.all = false;
        assert!(!app.exporter.request_csv_fields(head.clone(), 0));
        app.exporter.selected.insert(0);
        assert!(app.exporter.request_csv_fields(head.clone(), 0));
        let operation = app.exporter.operation;
        frame(&mut app, &ctx, vec![]);
        assert!(
            matches!(&host.borrow().requests.last().unwrap().command,Command::VendorExport(flow::Command::Fields {operation: actual,head: actual_head,start:0}) if *actual==operation && *actual_head==head)
        );
        assert!(app.export_files.pending);
        app.export_reply(Ok(csv_fields(operation - 1, head.clone(), 0)));
        assert!(app.export_files.pending && app.exporter.csv.sources().is_empty());
        app.export_reply(Ok(csv_fields(operation, head, 0)));
        assert!(!app.export_files.pending);
        assert_eq!(app.exporter.csv.sources().len(), 1);
        click(&mut app, &ctx, "export-review");
        let requests = host.borrow();
        let Command::VendorExport(flow::Command::Prepare {
            format: export::Format::Csv,
            options: export::Options::Csv(config),
            selection: flow::Selection::Records(selection),
            ..
        }) = &requests.requests.last().unwrap().command
        else {
            panic!("CSV review");
        };
        assert!(config.profile.is_none() && !config.header && config.delimiter == b';');
        assert_eq!(selection.len(), 1);
        assert_eq!(config.columns.len(), 1);
        assert_eq!(config.columns[0].heading, "User header");
        assert!(matches!(config.columns[0].source, export::Source::Title));
        assert!(
            app.exporter.csv.sources().is_empty() && app.exporter.csv.manual.columns.is_empty()
        );
    }
    #[test]
    fn csv_metadata_cannot_restore_setup_after_cancel_lock_or_failure() {
        for action in 0..3 {
            let (mut app, _, ctx) = app();
            app.exporter.formats[0].format = export::Format::Csv;
            app.exporter
                .csv
                .add("Private heading".into(), export::Source::Title)
                .unwrap();
            let head = app.exporter.rows[0].head.clone();
            assert!(app.exporter.request_csv_fields(head.clone(), 0));
            let operation = app.exporter.operation;
            frame(&mut app, &ctx, vec![]);
            match action {
                0 => app.cancel_record_export(),
                1 => app.request(Command::Lock, true),
                _ => {}
            }
            app.export_reply(Ok(csv_fields(
                operation,
                head,
                if action == 2 { 1 } else { 0 },
            )));
            assert!(
                app.exporter.csv.sources().is_empty() && app.exporter.csv.manual.columns.is_empty()
            );
            if action == 2 {
                assert_eq!(app.exporter.stage, Stage::Failed);
            } else {
                assert!(!app.exporter.window.open);
            }
        }
    }
    #[test]
    fn bitwarden_profile_reaches_the_same_review_request() {
        for organization in [false, true] {
            let (mut app, host, ctx) = app();
            app.exporter.formats[0].format = export::Format::BitwardenJson;
            app.exporter.formats[0].label = "Bitwarden JSON".into();
            app.exporter.organization = organization;
            click(&mut app, &ctx, "export-review");
            assert!(matches!(
                &host.borrow().requests.last().unwrap().command,
                Command::VendorExport(flow::Command::Prepare {
                    format: export::Format::BitwardenJson,
                    options: export::Options::Bitwarden { organization: actual, password: None }, ..
                }) if *actual == organization
            ));
            assert_eq!(app.exporter.stage, Stage::Loading);
            assert!(app.exporter.review.is_none());
        }
    }
    #[test]
    fn encrypted_bitwarden_profile_and_password_use_the_same_request() {
        for organization in [false, true] {
            let (mut app, host, ctx) = app();
            app.exporter.formats[0].format = export::Format::BitwardenEncryptedJson;
            app.exporter.organization = organization;
            app.exporter.use_password = true;
            assert!(!app.exporter.configured());
            *app.exporter.password = "x".repeat(export::MAX_PASSWORD_BYTES + 1);
            assert!(!app.exporter.configured());
            *app.exporter.password = " Public export 密码 é e\u{301} ".into();
            assert!(app.exporter.configured());
            app.exporter.use_password = false;
            assert!(!app.exporter.configured());
            app.exporter.use_password = true;
            click(&mut app, &ctx, "export-review");
            assert!(matches!(
                &host.borrow().requests.last().unwrap().command,
                Command::VendorExport(flow::Command::Prepare {
                    format: export::Format::BitwardenEncryptedJson,
                    options: export::Options::Bitwarden { organization: actual, password: Some(password) }, ..
                }) if *actual == organization && password == " Public export 密码 é e\u{301} "
            ));
            assert!(app.exporter.password.is_empty());
            assert_eq!(app.exporter.stage, Stage::Loading);
        }
    }
    #[test]
    fn explicit_review_generate_and_save_then_lock_clears_host_owned_plaintext() {
        let (mut app, host, ctx) = app();
        click(&mut app, &ctx, "export-review");
        assert_eq!(app.exporter.operation, 2);
        assert!(matches!(
            host.borrow().requests.last().unwrap().command,
            Command::VendorExport(flow::Command::Prepare { operation: 2, .. })
        ));
        reviewed(&mut app);
        assert!(!app.exporter.can_generate());
        click(&mut app, &ctx, "export-plaintext-ack");
        click(&mut app, &ctx, "export-generate");
        assert_eq!(app.exporter.operation, 3);
        app.export_reply(Ok(flow::Reply::Ready {
            operation: 3,
            ready: flow::Ready {
                token: [5; 16],
                file: file(),
                bytes: 3,
            },
        }));
        app.export_reply(Ok(flow::Reply::Chunk {
            token: [5; 16],
            chunk: chunk(0, b"key", None),
        }));
        assert!(matches!(
            host.borrow().requests.last().unwrap().command,
            Command::VendorExport(flow::Command::Finish { .. })
        ));
        app.export_reply(Ok(flow::Reply::Finished));
        assert_eq!(app.exporter.stage, Stage::Ready);
        assert!(host.borrow().saved.is_none());
        click(&mut app, &ctx, "export-save");
        let (transfer, done) = host.borrow_mut().saved.take().unwrap();
        assert!(transfer.available());
        app.request(Command::Lock, true);
        assert!(!transfer.available());
        assert!(
            transfer
                .publish::<()>(|_| panic!("published after lock"))
                .is_err()
        );
        done(ExportFileReply::Saved);
        app.poll_export_file();
        assert!(!app.exporter.window.open);
        assert!(app.exporter.notice.is_none());
        assert!(app.export_files.transfer.is_none());
    }
    #[test]
    fn late_metadata_after_close_is_discarded_and_cancel_is_serialized() {
        let (mut app, host, _) = app();
        app.list_export_records();
        app.cancel_record_export();
        assert!(app.export_files.pending);
        app.export_reply(Ok(flow::Reply::Listed {
            operation: app.exporter.operation,
            vault: [1; 16],
            after: Some(confidex_storage::Head {
                record: [2; 16],
                revision: [3; 32],
            }),
            page: flow::SelectionPage {
                rows: vec![flow::Row {
                    index: 0,
                    head: confidex_storage::Head {
                        record: [7; 16],
                        revision: [8; 32],
                    },
                    title: "Late public title".into(),
                    fields: 1,
                }],
                more: false,
                next: Some(confidex_storage::Head {
                    record: [7; 16],
                    revision: [8; 32],
                }),
            },
        }));
        assert!(app.exporter.rows.is_empty());
        assert!(matches!(
            host.borrow().requests.last().unwrap().command,
            Command::VendorExport(flow::Command::Cancel { token: None })
        ));
        let previous = app.exporter.next_operation();
        app.exporter.clear();
        assert_eq!(app.exporter.next_operation(), previous + 1);
    }
    #[test]
    fn malformed_file_continuation_is_not_saveable() {
        let (mut app, host, _) = app();
        app.exporter.operation = 2;
        reviewed(&mut app);
        app.exporter.stage = Stage::Generating;
        app.export_reply(Ok(flow::Reply::Ready {
            operation: 2,
            ready: flow::Ready {
                token: [5; 16],
                file: file(),
                bytes: 3,
            },
        }));
        app.export_reply(Ok(flow::Reply::Chunk {
            token: [5; 16],
            chunk: chunk(0, b"ke", None),
        }));
        assert_eq!(app.exporter.stage, Stage::Failed);
        assert!(app.export_files.transfer.is_none());
        assert!(host.borrow().saved.is_none());
        assert!(matches!(
            host.borrow().requests.last().unwrap().command,
            Command::VendorExport(flow::Command::Cancel { .. })
        ));
    }
    #[test]
    fn a_closed_keyfile_picker_cannot_restore_key_bytes() {
        let (mut app, _, _) = app();
        let sender = app.export_files.sender.clone();
        let generation = app.generation;
        let serial = app.export_files.serial;
        app.cancel_record_export();
        sender
            .send((
                generation,
                serial,
                FileReply::Keyfile(ImportFileReply::Selected(ImportFile {
                    name: "public.key".into(),
                    bytes: b"public-key".to_vec(),
                })),
            ))
            .ok()
            .unwrap();
        app.poll_export_file();
        assert!(app.export_files.keyfile.is_none());
        assert!(app.exporter.keyfile.is_none());
    }
}
