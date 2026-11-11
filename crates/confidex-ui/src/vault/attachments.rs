use super::*;
use crate::{
    ImageCompletion, ImageFile, ImageHost, ImageJobReply, ImageReply, ImageRequest,
    ImageWorkCompletion,
};
use design::image_viewer;
use std::sync::mpsc;

enum Event {
    Host(ImageReply),
    Job(Result<ImageJobReply, String>),
}
type Worker = Box<dyn FnMut(Vec<u8>, ImageWorkCompletion)>;
#[derive(Clone, Copy)]
enum Phase {
    Pick,
    Probe,
    Apply,
    Preview,
    Export,
}
pub(super) struct Attachments {
    handler: Option<Box<dyn FnMut(ImageRequest, ImageCompletion)>>,
    worker: Option<Worker>,
    sender: mpsc::Sender<(u64, Event)>,
    receiver: mpsc::Receiver<(u64, Event)>,
    operation: u64,
    context: Option<egui::Context>,
    target: Option<(RecordId, u64)>,
    phase: Phase,
    file_mode: bool,
    readonly_key: Option<String>,
    pub busy: bool,
    pub pending: Option<(u64, app::Field)>,
    pub checking: bool,
    pub window: window::State,
    pub viewer: image_viewer::State,
    source: Option<ImageFile>,
    candidate: Option<ImageFile>,
    quality: u8,
    has_exif: bool,
    keep_exif: bool,
    pub notice: Option<&'static str>,
    compressed: Option<usize>,
    view: Option<ImageFile>,
    texture: Option<egui::TextureHandle>,
    natural: [u32; 2],
}
impl Default for Attachments {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            handler: None,
            worker: None,
            sender,
            receiver,
            operation: 0,
            context: None,
            target: None,
            phase: Phase::Pick,
            file_mode: false,
            readonly_key: None,
            busy: false,
            pending: None,
            checking: false,
            window: Default::default(),
            viewer: Default::default(),
            source: None,
            candidate: None,
            quality: 101,
            has_exif: false,
            keep_exif: false,
            notice: None,
            compressed: None,
            view: None,
            texture: None,
            natural: [0; 2],
        }
    }
}
impl Attachments {
    pub fn invalidate_size(&mut self) {
        self.compressed = None;
    }
    pub fn clear(&mut self) {
        self.operation += 1;
        if let Some(handler) = &mut self.handler {
            handler(ImageRequest::Discard { source: true }, Box::new(|_| {}));
        }
        self.target = None;
        self.file_mode = false;
        self.readonly_key = None;
        self.busy = false;
        self.pending = None;
        self.window.clear();
        self.viewer = Default::default();
        self.source = None;
        self.candidate = None;
        self.view = None;
        self.texture = None;
        self.notice = None;
        self.compressed = None;
    }
}
impl ImageHost for VaultApp {
    fn set_image_handler(&mut self, handler: impl FnMut(ImageRequest, ImageCompletion) + 'static) {
        self.attachments.handler = Some(Box::new(handler));
    }
    fn set_image_worker(&mut self, worker: impl FnMut(Vec<u8>, ImageWorkCompletion) + 'static) {
        self.attachments.worker = Some(Box::new(worker));
    }
}
impl VaultApp {
    pub(super) fn host_file_request(&mut self, request: ImageRequest, done: ImageCompletion) {
        if let Some(handler) = &mut self.attachments.handler {
            handler(request, done);
        } else {
            done(ImageReply::Failed);
        }
    }
    pub(super) fn file_readonly(&mut self, ui: &mut egui::Ui, id: &str, field: &app::Field) {
        let name = field
            .values
            .get("filename")
            .map(String::as_str)
            .filter(|v| !v.is_empty())
            .unwrap_or("attachment.bin");
        ui.label(name);
        if let Some(data) = &field.data {
            if self.button(
                ui,
                id,
                "gallery-file-save",
                !self.busy && !self.attachments.busy,
            ) {
                self.attachments.clear();
                self.attachments.file_mode = true;
                self.attachments.readonly_key = Some(id.into());
                self.attachment_request(
                    ui.ctx(),
                    ImageRequest::Save(ImageFile {
                        name: name.into(),
                        bytes: data.to_vec().into(),
                    }),
                );
            }
            self.file_size(ui, data.len());
        }
        if self.attachments.readonly_key.as_deref() == Some(id)
            && let Some(message) = self.attachments.notice
        {
            ui.label(self.locale.text(message));
        }
    }
    fn file_size(&self, ui: &mut egui::Ui, bytes: usize) {
        let mut args = fluent_bundle::FluentArgs::new();
        args.set("value", bytes as i64);
        design::muted(
            ui,
            THEMES[self.theme].colors,
            self.locale.format("gallery-file-size", &args),
        );
    }
    pub(super) fn file_field(
        &mut self,
        ui: &mut egui::Ui,
        record: RecordId,
        key: u64,
        data: Option<&app::Bytes>,
        values: &BTreeMap<String, String>,
        editing: bool,
    ) {
        let name = values.get("filename").map(String::as_str).unwrap_or("");
        let ready = data.is_some() && !name.is_empty();
        if ready {
            ui.label(name);
        }
        layout::grid(
            ui,
            &format!("file-actions-{key}"),
            usize::from(editing) + usize::from(ready),
            140.,
            2,
            Metrics::SM,
            |ui, index| {
                if editing && index == 0 {
                    if self.button(
                        ui,
                        &format!("file-{key}-choose"),
                        "gallery-file-choose",
                        !self.busy && !self.attachments.busy,
                    ) {
                        self.attachment_open(ui.ctx(), record, key, ImageRequest::OpenFile);
                    }
                } else if self.button(
                    ui,
                    &format!("file-{key}-save"),
                    "gallery-file-save",
                    !self.busy && !self.attachments.busy,
                ) {
                    self.attachments.clear();
                    self.attachments.file_mode = true;
                    self.attachments.target = Some((record, key));
                    self.attachment_request(
                        ui.ctx(),
                        ImageRequest::Save(ImageFile {
                            name: name.into(),
                            bytes: data.unwrap().to_vec().into(),
                        }),
                    );
                }
            },
        );
        if ready {
            self.file_size(ui, data.unwrap().len());
        } else {
            design::muted(
                ui,
                THEMES[self.theme].colors,
                self.locale.text("gallery-file-empty"),
            );
        }
        if self.attachments.target == Some((record, key)) {
            if self.attachments.busy {
                design::spinner(
                    ui,
                    THEMES[self.theme].colors,
                    Metrics::ICON,
                    &self.locale.text("vault-working"),
                );
            }
            if let Some(message) = self.attachments.notice {
                ui.label(self.locale.text(message));
            }
            if let Some(value) = self.attachments.compressed {
                let mut args = fluent_bundle::FluentArgs::new();
                args.set("value", value as i64);
                design::muted(
                    ui,
                    THEMES[self.theme].colors,
                    self.locale.format("gallery-image-record-size", &args),
                );
            }
        }
    }
    pub(super) fn photo_readonly(&mut self, ui: &mut egui::Ui, id: &str, field: &app::Field) {
        let name = field
            .values
            .get("filename")
            .map(String::as_str)
            .filter(|v| !v.is_empty())
            .unwrap_or("image.webp");
        if field.data.as_ref().is_some_and(|data| !data.is_empty()) {
            self.photo_preview(ui, id, name, field.data.as_ref().unwrap());
        } else {
            design::muted(
                ui,
                THEMES[self.theme].colors,
                self.locale.text("gallery-photo-empty"),
            );
        }
    }
    fn photo_preview(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        name: &str,
        data: &app::Bytes,
    ) -> bool {
        let response = design::button(
            ui,
            THEMES[self.theme].colors,
            &self.locale.text("gallery-image-view"),
            ButtonRole::Secondary,
            ui.available_width(),
            !self.busy && !self.attachments.busy,
        );
        self.hits.insert(id.into(), response.rect);
        if response.clicked() {
            self.attachments.clear();
            let file = ImageFile {
                name: name.into(),
                bytes: data.to_vec().into(),
            };
            self.attachments.view = Some(file.clone());
            self.attachments.viewer.open(&response);
            self.attachment_job(ui.ctx(), 2, file, Phase::Preview);
        }
        response.clicked()
    }
    fn attachment_request(&mut self, ctx: &egui::Context, request: ImageRequest) {
        self.attachments.context = Some(ctx.clone());
        self.attachments.operation += 1;
        let operation = self.attachments.operation;
        self.attachments.busy = true;
        self.attachments.notice = None;
        let sender = self.attachments.sender.clone();
        let ctx = ctx.clone();
        let done = Box::new(move |reply| {
            let _ = sender.send((operation, Event::Host(reply)));
            ctx.request_repaint();
        });
        if let Some(handler) = &mut self.attachments.handler {
            handler(request, done);
        } else {
            done(ImageReply::Failed);
        }
    }
    fn attachment_job(&mut self, ctx: &egui::Context, kind: u64, file: ImageFile, phase: Phase) {
        self.attachments.context = Some(ctx.clone());
        self.attachments.operation += 1;
        let operation = self.attachments.operation;
        self.attachments.phase = phase;
        self.attachments.busy = true;
        let quality = self.attachments.quality;
        let keep_exif = self.attachments.keep_exif;
        let sender = self.attachments.sender.clone();
        let ctx = ctx.clone();
        if let Some(worker) = &mut self.attachments.worker {
            let done = Box::new(move |result: Result<Vec<u8>, String>| {
                let result = result
                    .and_then(|bytes| crate::image_job_reply(&zeroize::Zeroizing::new(bytes)));
                let _ = sender.send((operation, Event::Job(result)));
                ctx.request_repaint();
            });
            match crate::image_job_request(kind, file, quality, keep_exif) {
                Ok(bytes) => worker(bytes, done),
                Err(error) => done(Err(error)),
            }
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            std::thread::spawn(move || {
                let result = crate::run_image_job(kind, file, quality, keep_exif);
                let _ = sender.send((operation, Event::Job(result)));
                ctx.request_repaint();
            });
            #[cfg(target_arch = "wasm32")]
            {
                let _ = (kind, file, quality, keep_exif);
                let _ = sender.send((operation, Event::Job(Err("worker unavailable".into()))));
                ctx.request_repaint();
            }
        }
    }
    pub(super) fn attachment_open(
        &mut self,
        ctx: &egui::Context,
        record: RecordId,
        key: u64,
        request: ImageRequest,
    ) {
        self.attachments.clear();
        self.attachments.target = Some((record, key));
        self.attachments.phase = Phase::Pick;
        self.attachments.file_mode = !matches!(
            request,
            ImageRequest::Open | ImageRequest::Dropped { image: true, .. }
        );
        self.file_drop.error = None;
        self.attachment_request(ctx, request);
    }
    fn attachment_candidate(&mut self, mut file: ImageFile) {
        let Some((record, key)) = self.attachments.target else {
            return;
        };
        let Some(mut draft) = self.draft.as_ref().filter(|d| d.record == record).cloned() else {
            return;
        };
        let Some(index) = self.field_ids.iter().position(|id| *id == key) else {
            return;
        };
        let field = &mut draft.fields[index];
        field.data = Some(std::mem::take(&mut *file.bytes).into());
        field.values.insert(
            "mime".into(),
            if self.attachments.file_mode {
                "application/octet-stream"
            } else {
                "image/webp"
            }
            .into(),
        );
        if file.name.is_empty() {
            file.name = "attachment.bin".into();
        }
        field.values.insert("filename".into(), file.name);
        self.attachments.pending = Some((key, field.clone()));
        self.attachments.checking = true;
        self.attachments.busy = true;
        self.request(Command::CheckDraft { draft }, false);
    }
    pub(super) fn attachment_checked(&mut self, compressed: usize) {
        if self.attachments.pending.is_none() {
            return;
        }
        if let Some((key, field)) = self.attachments.pending.take()
            && let Some(index) = self.field_ids.iter().position(|id| *id == key)
            && let Some(draft) = &mut self.draft
        {
            draft.fields[index] = field;
        }
        self.attachments.busy = false;
        self.attachments.compressed = Some(compressed);
        self.attachments.window.clear();
        self.attachments.source = None;
        self.attachments.candidate = None;
        self.attachments.notice = Some(if self.attachments.file_mode {
            "gallery-file-added"
        } else {
            "gallery-image-added"
        });
        if let Some(handler) = &mut self.attachments.handler {
            handler(ImageRequest::Discard { source: true }, Box::new(|_| {}));
        }
    }
    pub(super) fn poll_attachments(&mut self) {
        let Some(ctx) = self.attachments.context.clone() else {
            return;
        };
        while let Ok((operation, event)) = self.attachments.receiver.try_recv() {
            if operation != self.attachments.operation {
                continue;
            }
            if let Some((record, key)) = self.attachments.target
                && (self.draft.as_ref().is_none_or(|d| d.record != record)
                    || !self.field_ids.contains(&key))
            {
                self.attachments.clear();
                continue;
            }
            self.attachments.busy = false;
            match event {
                Event::Host(ImageReply::Opened(file)) => {
                    if self.attachments.file_mode {
                        self.attachment_candidate(file);
                        continue;
                    }
                    self.attachments.source = Some(file.clone());
                    self.attachments.window.open = true;
                    self.attachments.quality = 101;
                    self.attachments.keep_exif = false;
                    self.attachments.has_exif =
                        crate::image_metadata(&file.bytes).is_ok_and(|info| !info.exif.is_empty());
                    self.attachment_job(&ctx, 0, file, Phase::Probe);
                }
                Event::Host(ImageReply::Large {
                    name,
                    has_exif,
                    webp,
                }) => {
                    self.attachments.source = Some(ImageFile {
                        name,
                        bytes: Vec::new().into(),
                    });
                    self.attachments.window.open = true;
                    self.attachments.quality = if webp && !has_exif { 101 } else { 60 };
                    self.attachments.has_exif = has_exif;
                    self.attachments.keep_exif = false;
                    self.attachments.notice = Some("gallery-image-large");
                }
                Event::Host(reply) => {
                    self.attachments.notice = Some(match reply {
                        ImageReply::Saved => "gallery-image-saved",
                        ImageReply::DownloadStarted => "gallery-image-download",
                        ImageReply::TooLarge => {
                            if self.attachments.file_mode {
                                "gallery-file-resource"
                            } else {
                                "gallery-image-resource"
                            }
                        }
                        ImageReply::Cancelled => "gallery-image-cancelled",
                        _ => "gallery-image-save-error",
                    })
                }
                Event::Job(Ok(ImageJobReply::Imported(file))) => {
                    if matches!(self.attachments.phase, Phase::Probe) {
                        self.attachments.candidate = Some(file);
                        self.attachments.notice = Some("gallery-image-ready");
                    } else {
                        self.attachment_candidate(file);
                    }
                }
                Event::Job(Ok(ImageJobReply::Quality(file))) => {
                    self.attachments.source = Some(file);
                    self.attachments.quality = 60;
                    self.attachments.notice = Some("gallery-image-large");
                }
                Event::Job(Ok(ImageJobReply::Error(message, _))) => {
                    self.attachments.notice = Some(message);
                    if matches!(self.attachments.phase, Phase::Probe) {
                        self.attachments.quality = 60;
                    }
                }
                Event::Job(Ok(ImageJobReply::Preview(image, natural))) => {
                    if self.attachments.viewer.is_open() {
                        let rgba = image.to_rgba8();
                        self.attachments.texture = Some(ctx.load_texture(
                            "vault-photo",
                            egui::ColorImage::from_rgba_unmultiplied(
                                [rgba.width() as usize, rgba.height() as usize],
                                rgba.as_raw(),
                            ),
                            Default::default(),
                        ));
                        self.attachments.natural = natural;
                    }
                }
                Event::Job(Ok(ImageJobReply::Exported(file))) => {
                    self.attachment_request(&ctx, ImageRequest::Save(file))
                }
                Event::Job(Ok(ImageJobReply::DownloadReady)) => {
                    self.attachment_request(&ctx, ImageRequest::Download)
                }
                Event::Job(Err(_)) => {
                    self.attachments.notice = Some("gallery-image-processing-error")
                }
            }
        }
    }
    pub(super) fn photo_field(
        &mut self,
        ui: &mut egui::Ui,
        record: RecordId,
        key: u64,
        data: Option<&app::Bytes>,
        values: &BTreeMap<String, String>,
        editing: bool,
    ) {
        let p = THEMES[self.theme].colors;
        let name = values
            .get("filename")
            .map(String::as_str)
            .filter(|n| !n.is_empty())
            .unwrap_or("image.webp");
        if let Some(data) = data
            && !data.is_empty()
        {
            ui.label(name);
        }
        let has_data = data.is_some_and(|data| !data.is_empty());
        let mut open = false;
        layout::grid(
            ui,
            &format!("photo-actions-{key}"),
            usize::from(editing) + usize::from(has_data),
            140.,
            2,
            Metrics::SM,
            |ui, index| {
                if editing && index == 0 {
                    open = self.button(
                        ui,
                        &format!("photo-{key}-choose"),
                        "gallery-image-import",
                        !self.busy && !self.attachments.busy,
                    );
                } else {
                    if self.photo_preview(ui, &format!("photo-{key}-reveal"), name, data.unwrap()) {
                        self.attachments.target = Some((record, key));
                    }
                }
            },
        );
        if open {
            self.attachment_open(ui.ctx(), record, key, ImageRequest::Open);
        }
        if !has_data {
            design::muted(ui, p, self.locale.text("gallery-photo-empty"));
        }
        if self.attachments.target == Some((record, key)) {
            if self.attachments.busy {
                design::spinner(
                    ui,
                    p,
                    Metrics::ICON,
                    &self.locale.text("gallery-image-working"),
                );
            }
            if let Some(message) = self.attachments.notice {
                design::muted(ui, p, self.locale.text(message));
            }
            if let Some(value) = self.attachments.compressed {
                let mut args = fluent_bundle::FluentArgs::new();
                args.set("value", value as i64);
                design::muted(
                    ui,
                    p,
                    self.locale.format("gallery-image-record-size", &args),
                );
            }
        }
    }
    pub(super) fn attachment_windows(&mut self, ctx: &egui::Context) {
        let p = THEMES[self.theme].colors;
        let mut window = std::mem::take(&mut self.attachments.window);
        let was_open = window.open;
        self.attachments.window.open = was_open;
        if let Some(output) = window.show(
            ctx,
            p,
            window::Window {
                id: egui::Id::unique("photo-preparation"),
                title: &self.locale.text("gallery-image-compress"),
                close_label: &self.locale.text("window-close"),
                size: Vec2::new(620., 460.),
            },
            |ui| {
                dialog::Form {
                    id: "photo-preparation-form",
                    actions: 2,
                    min_action_width: 150.,
                }
                .show(
                    ui,
                    self,
                    |app, ui| {
                        if let Some(file) = &app.attachments.source {
                            ui.label(&file.name);
                        }
                        let mut lossless = app.attachments.quality == 101;
                        if design::checkbox(
                            ui,
                            &mut lossless,
                            app.locale.text("gallery-image-lossless"),
                        )
                        .changed()
                        {
                            app.attachments.quality = if lossless { 101 } else { 75 };
                        }
                        if !lossless {
                            ui.add(
                                egui::Slider::new(&mut app.attachments.quality, 1..=100)
                                    .text(app.locale.text("gallery-image-quality")),
                            );
                        }
                        ui.add_enabled_ui(app.attachments.has_exif, |ui| {
                            design::checkbox(
                                ui,
                                &mut app.attachments.keep_exif,
                                app.locale.text("gallery-image-exif"),
                            );
                        });
                    },
                    |app, ui, index| {
                        let id = if index == 0 {
                            "photo-apply"
                        } else {
                            "photo-cancel"
                        };
                        let clicked = app.action(
                            ui,
                            id,
                            if index == 0 {
                                "gallery-image-add"
                            } else {
                                "vault-cancel"
                            },
                            index == 1 || (!app.busy && !app.attachments.busy),
                            if index == 0 {
                                ButtonRole::Primary
                            } else {
                                ButtonRole::Secondary
                            },
                        );
                        if clicked && index == 0 {
                            if app.attachments.quality == 101
                                && !app.attachments.keep_exif
                                && app.attachments.candidate.is_some()
                            {
                                let file = app.attachments.candidate.take().unwrap();
                                app.attachment_candidate(file);
                            } else if let Some(file) = app.attachments.source.clone() {
                                app.attachment_job(ui.ctx(), 1, file, Phase::Apply);
                            }
                        } else if clicked {
                            app.attachments.window.clear();
                        }
                    },
                    |app, ui| {
                        if app.attachments.busy {
                            design::spinner(
                                ui,
                                p,
                                Metrics::ICON,
                                &app.locale.text("gallery-image-working"),
                            );
                        }
                        if let Some(message) = app.attachments.notice {
                            ui.label(app.locale.text(message));
                        }
                        design::muted(ui, p, app.locale.text("gallery-image-compress-help"));
                    },
                );
            },
        ) {
            self.bounds.insert("photo-preparation".into(), output.rect);
        }
        if was_open && !self.attachments.window.open {
            window.clear();
        }
        self.attachments.window = window;
        if was_open && !self.attachments.window.open {
            self.attachments.clear();
        }
        let labels = [
            "window-close",
            "gallery-image-prev",
            "gallery-image-next",
            "gallery-image-export",
            "gallery-image-original",
            "gallery-image-png",
            "gallery-image-jpeg",
            "gallery-image-minus",
            "gallery-image-fit",
            "gallery-image-plus",
            "gallery-image-actual",
            "gallery-image-canvas",
            "gallery-image-gestures",
        ]
        .map(|key| self.locale.text(key));
        if let Some(file) = &self.attachments.view {
            let output = self.attachments.viewer.show(
                ctx,
                p,
                image_viewer::Image {
                    id: egui::Id::unique(("vault-photo", self.attachments.target)),
                    name: &file.name,
                    source: "",
                    texture: self.attachments.texture.as_ref(),
                    natural_size: Vec2::new(
                        self.attachments.natural[0] as f32,
                        self.attachments.natural[1] as f32,
                    ),
                    index: 0,
                    count: 1,
                    busy: self.attachments.busy,
                    status: &self
                        .locale
                        .text(self.attachments.notice.unwrap_or("gallery-image-working")),
                },
                image_viewer::Labels {
                    close: &labels[0],
                    previous: &labels[1],
                    next: &labels[2],
                    export: &labels[3],
                    webp: &labels[4],
                    png: &labels[5],
                    jpeg: &labels[6],
                    minus: &labels[7],
                    fit: &labels[8],
                    plus: &labels[9],
                    actual: &labels[10],
                    canvas: &labels[11],
                    help: &labels[12],
                },
            );
            if let Some(output) = output {
                self.bounds.insert("photo-viewer".into(), output.rect);
                for (name, response) in output.controls {
                    self.hits
                        .insert(format!("photo-viewer-{name}"), response.rect);
                }
                if let Some(action) = output.action {
                    let file = self.attachments.view.clone().unwrap();
                    match action {
                        image_viewer::Action::Webp => {
                            self.attachment_request(ctx, ImageRequest::Save(file))
                        }
                        image_viewer::Action::Png => {
                            self.attachment_job(ctx, 3, file, Phase::Export)
                        }
                        image_viewer::Action::Jpeg => {
                            self.attachment_job(ctx, 4, file, Phase::Export)
                        }
                        _ => (),
                    }
                }
            }
            if !self.attachments.viewer.is_open() {
                self.attachments.clear();
            }
        }
    }
}
