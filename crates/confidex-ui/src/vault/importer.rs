use super::*;
use app::import_flow as flow;
use design::importer::{Event, FileRequest as ImportFileRequest};
use std::sync::mpsc;
use zeroize::Zeroizing;

pub struct ImportFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

impl Drop for ImportFile {
    fn drop(&mut self) {
        self.name.zeroize();
        self.bytes.zeroize();
    }
}
pub enum ImportFileReply {
    Selected(ImportFile),
    Canceled,
    Failed,
    TooLarge,
}
pub type ImportFileCompletion = Box<dyn FnOnce(ImportFileReply) + Send>;
type Handler = Box<dyn FnMut(ImportFileRequest, ImportFileCompletion)>;
pub(super) struct Files {
    handler: Option<Handler>,
    sender: mpsc::Sender<(u32, u32, ImportFileRequest, ImportFileReply)>,
    receiver: mpsc::Receiver<(u32, u32, ImportFileRequest, ImportFileReply)>,
    bytes: Option<Zeroizing<Vec<u8>>>,
    serial: u32,
    picking: Option<ImportFileRequest>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
    pub pending: bool,
    deferred: Option<flow::Command>,
}
impl Default for Files {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            handler: None,
            sender,
            receiver,
            bytes: None,
            serial: 0,
            picking: None,
            keyfile: None,
            pending: false,
            deferred: None,
        }
    }
}
impl Files {
    pub fn clear(&mut self) {
        self.bytes = None;
        self.serial = self
            .serial
            .checked_add(1)
            .expect("file generation exhausted");
        self.picking = None;
        self.keyfile = None;
        self.pending = false;
        self.deferred = None;
    }
}
impl VaultApp {
    pub fn set_import_file_handler(
        &mut self,
        handler: impl FnMut(ImportFileRequest, ImportFileCompletion) + 'static,
    ) {
        self.import_files.handler = Some(Box::new(handler));
    }
    pub(super) fn pick_import_file(&mut self, kind: ImportFileRequest, done: ImportFileCompletion) {
        if let Some(handler) = &mut self.import_files.handler {
            handler(kind, done);
        } else {
            done(ImportFileReply::Failed);
        }
    }
    fn import_request(&mut self, command: flow::Command) {
        if self.import_files.pending {
            self.import_files.deferred = Some(command);
            return;
        }
        self.import_files.pending = true;
        if let Err(error) = self.runtime.send(Request {
            generation: self.generation,
            command: Command::VendorImport(command),
        }) {
            self.import_files.pending = false;
            self.importer.accept(Err(flow::Error::App(error)));
        }
    }
    pub(super) fn import_reply(&mut self, result: Result<flow::Reply, flow::Error>) {
        if !matches!(&result, Ok(flow::Reply::Progress { .. })) {
            self.import_files.pending = false;
        }
        let applied = matches!(&result, Ok(flow::Reply::Applied { .. }));
        if self.importer.window.open {
            self.importer.accept(result);
        }
        if !self.import_files.pending && self.importer.stage != design::importer::Stage::Unlock {
            self.import_files.keyfile = None;
        }
        if applied {
            self.request_list(None);
        }
        if !self.import_files.pending
            && let Some(command) = self.import_files.deferred.take()
        {
            self.import_request(command);
        }
    }
    pub(super) fn import_action(&mut self, ui: &mut egui::Ui) -> bool {
        let enabled = !self.busy && !self.editing && !self.import_files.pending;
        let button = design::button(
            ui,
            THEMES[self.theme].colors,
            &self.locale.text("import-title"),
            ButtonRole::Secondary,
            ui.available_width(),
            enabled,
        );
        if enabled {
            self.hits.insert("import-records".into(), button.rect);
        }
        if button.clicked() {
            self.start_record_import(&button);
            return true;
        }
        false
    }
    pub(super) fn start_record_import(&mut self, opener: &egui::Response) {
        self.import_files.clear();
        let name = self
            .active
            .as_ref()
            .map(|info| info.name.clone())
            .unwrap_or_default();
        self.importer.open(opener, name);
        self.import_request(flow::Command::Begin);
    }
    fn choose_import_file(&mut self, ctx: &egui::Context, kind: ImportFileRequest) {
        if self.import_files.picking.is_some() {
            return;
        }
        match kind {
            ImportFileRequest::Records => {
                self.import_files.bytes = None;
                self.importer.file = None;
            }
            ImportFileRequest::Keyfile => {
                self.import_files.keyfile = None;
                self.importer.keyfile = None;
            }
        }
        self.importer.error = None;
        self.import_files.picking = Some(kind);
        self.import_files.serial = self
            .import_files
            .serial
            .checked_add(1)
            .expect("file generation exhausted");
        let serial = self.import_files.serial;
        let generation = self.generation;
        let sender = self.import_files.sender.clone();
        let ctx = ctx.clone();
        let done = Box::new(move |reply| {
            let _ = sender.send((generation, serial, kind, reply));
            ctx.request_repaint();
        });
        self.pick_import_file(kind, done);
    }
    pub(super) fn poll_import_file(&mut self) {
        while let Ok((generation, serial, kind, reply)) = self.import_files.receiver.try_recv() {
            if generation != self.generation
                || serial != self.import_files.serial
                || !self.importer.window.open
            {
                continue;
            }
            self.import_files.picking = None;
            match reply {
                ImportFileReply::Selected(mut file)
                    if file.bytes.len() <= kind.limit() && file.name.len() <= 4096 =>
                {
                    let metadata = flow::File {
                        name: std::mem::take(&mut file.name),
                        bytes: file.bytes.len(),
                    };
                    let bytes = Some(Zeroizing::new(std::mem::take(&mut file.bytes)));
                    match kind {
                        ImportFileRequest::Records => {
                            self.importer.file_selected(metadata);
                            self.import_files.bytes = bytes;
                        }
                        ImportFileRequest::Keyfile => {
                            self.importer.keyfile_selected(metadata);
                            self.import_files.keyfile = bytes;
                        }
                    }
                }
                ImportFileReply::Canceled => (),
                ImportFileReply::TooLarge | ImportFileReply::Selected(_) => {
                    self.importer.error =
                        Some(flow::Error::Parse(app::import::ErrorKind::Limit.into()))
                }
                ImportFileReply::Failed => {
                    self.importer.error = Some(flow::Error::App(Error::Input))
                }
            }
        }
    }
    pub(super) fn import_window(&mut self, ui: &mut egui::Ui) {
        self.importer.waiting = self.import_files.pending || self.import_files.picking.is_some();
        self.importer
            .show_window(ui.ctx(), THEMES[self.theme].colors, &self.locale, &|id| {
                self.clipboard.state(id)
            });
        self.hits.extend(self.importer.hits.clone());
        self.bounds.extend(self.importer.bounds.clone());
        for event in self.importer.take_events() {
            match event {
                Event::ChooseFile => self.choose_import_file(ui.ctx(), ImportFileRequest::Records),
                Event::ChooseKeyfile => {
                    self.choose_import_file(ui.ctx(), ImportFileRequest::Keyfile)
                }
                Event::ClearKeyfile => {
                    self.import_files.keyfile = None;
                    if self.import_files.picking == Some(ImportFileRequest::Keyfile) {
                        self.import_files.picking = None;
                        self.import_files.serial = self
                            .import_files
                            .serial
                            .checked_add(1)
                            .expect("file generation exhausted");
                    }
                }
                Event::Review => {
                    if self.import_files.pending || self.import_files.picking.is_some() {
                        continue;
                    }
                    if let (Some(mut bytes), Some(file)) =
                        (self.import_files.bytes.take(), &self.importer.file)
                    {
                        let file_name = file.name.clone();
                        let operation = self
                            .importer
                            .operation
                            .checked_add(1)
                            .expect("import operation exhausted");
                        let mut options = app::import::Options::default();
                        options.source_instance = Some(self.importer.source.trim().to_owned());
                        self.importer.preparing(operation);
                        self.import_request(flow::Command::Prepare {
                            operation,
                            file_name,
                            format: self.importer.format,
                            options,
                            bytes: std::mem::take(&mut *bytes),
                        });
                    }
                }
                Event::Unlock => {
                    if self.import_files.pending {
                        continue;
                    }
                    if let Some(token) = self.importer.token() {
                        let operation = self
                            .importer
                            .operation
                            .checked_add(1)
                            .expect("import operation exhausted");
                        let command = if self.importer.format == Some(app::import::Format::Kdbx) {
                            if !self.importer.credentials_ready()
                                || (self.importer.use_keyfile
                                    && self.import_files.keyfile.is_none())
                            {
                                continue;
                            }
                            flow::Command::UnlockKdbx {
                                operation,
                                token,
                                password: self
                                    .importer
                                    .use_password
                                    .then(|| self.importer.password.to_string()),
                                keyfile: if self.importer.use_keyfile {
                                    self.import_files
                                        .keyfile
                                        .as_ref()
                                        .map(|bytes| bytes.to_vec())
                                } else {
                                    None
                                },
                            }
                        } else {
                            flow::Command::Unlock {
                                operation,
                                token,
                                password: self.importer.password.to_string(),
                            }
                        };
                        self.importer.unlocking(operation);
                        self.import_request(command);
                    }
                }
                Event::Request(mut command) => {
                    if let flow::Command::Apply {
                        operation,
                        epoch: time,
                        ..
                    } = &mut command
                    {
                        self.importer.operation = self
                            .importer
                            .operation
                            .checked_add(1)
                            .expect("import operation exhausted");
                        *operation = self.importer.operation;
                        *time = epoch();
                    }
                    self.import_request(command);
                }
                Event::Copy { id, mut value } => {
                    self.clipboard
                        .request(ui.ctx(), id, std::mem::take(&mut *value))
                }
                Event::Cancel => {
                    self.runtime.cancel_import(self.importer.operation);
                    self.import_request(flow::Command::Cancel {
                        token: self.importer.token(),
                    });
                    self.import_files.bytes = None;
                    self.import_files.keyfile = None;
                    self.import_files.picking = None;
                    self.import_files.serial = self
                        .import_files
                        .serial
                        .checked_add(1)
                        .expect("file generation exhausted");
                    if !self.importer.window.open {
                        self.importer.clear();
                    }
                }
                Event::Done => {
                    self.importer.window.close(ui.ctx());
                    self.importer.clear();
                    self.import_files.clear();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
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
    #[test]
    fn preview_requests_coalesce_and_lock_discards_late_plaintext_files() {
        let ctx = egui::Context::default();
        let requests = Rc::new(RefCell::new(Vec::new()));
        let mut app = VaultApp::new(&ctx, Box::new(Host(requests.clone()))).unwrap();
        requests.borrow_mut().clear();
        app.busy = false;
        app.importer.window.open = true;
        app.import_request(flow::Command::Begin);
        for index in 0..100 {
            app.import_request(flow::Command::Preview {
                token: [1; 16],
                index,
            });
        }
        assert_eq!(requests.borrow().len(), 1);
        app.import_reply(Ok(flow::Reply::Begun {
            vault: [2; 16],
            formats: vec![],
        }));
        assert_eq!(requests.borrow().len(), 2);
        assert!(matches!(
            &requests.borrow()[1].command,
            Command::VendorImport(flow::Command::Preview { index: 99, .. })
        ));
        let serial = app.import_files.serial;
        app.clear_private();
        app.import_files
            .sender
            .send((
                app.generation,
                serial,
                ImportFileRequest::Records,
                ImportFileReply::Selected(ImportFile {
                    name: "public.json".into(),
                    bytes: b"public plaintext".to_vec(),
                }),
            ))
            .unwrap();
        app.poll_import_file();
        assert!(app.import_files.bytes.is_none());
        assert!(app.importer.file.is_none());
        assert!(!app.importer.window.open);
    }
    #[test]
    fn choosing_another_file_discards_the_previous_selection_and_blocks_review() {
        let ctx = egui::Context::default();
        let requests = Rc::new(RefCell::new(Vec::new()));
        let mut app = VaultApp::new(&ctx, Box::new(Host(requests))).unwrap();
        app.importer.window.open = true;
        app.importer.source = "public-account".into();
        app.importer.file = Some(flow::File {
            name: "old.json".into(),
            bytes: 3,
        });
        app.import_files.bytes = Some(Zeroizing::new(b"old".to_vec()));
        app.set_import_file_handler(|_, _| {});
        app.choose_import_file(&ctx, ImportFileRequest::Records);
        assert!(app.importer.file.is_none());
        assert!(app.import_files.bytes.is_none());
        for _ in 0..3 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(1320., 900.),
                    )),
                    ..Default::default()
                },
                |ui| app.import_window(ui),
            );
            output.textures_delta.clear();
        }
        assert!(!app.hits.contains_key("import-review"));
        assert!(!app.hits.contains_key("import-choose-file"));
    }
}
