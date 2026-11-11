use crate::browser_store::{self, BrowserKeys, BrowserStore};
use confidex_app::{Command, Engine, Error, Output, Request, Response, import_flow as flow};
use confidex_ui::{Runtime, VaultApp};
use eframe::egui;
use js_sys::{Array, Uint8Array};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::mpsc,
};
use wasm_bindgen::{JsCast, prelude::*};
use web_sys::{ErrorEvent, MessageEvent, Worker, WorkerOptions, WorkerType};
use zeroize::Zeroizing;

#[wasm_bindgen(module = "/web/fonts.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = loadFonts)]
    async fn load_fonts(names: Array) -> Result<Array, JsValue>;
}

async fn browser_fonts() -> Result<egui::FontDefinitions, JsValue> {
    use confidex_ui::ui_kit::fonts;
    let names = fonts::FILES
        .into_iter()
        .map(JsValue::from_str)
        .collect::<Array>();
    let faces = load_fonts(names)
        .await?
        .iter()
        .map(|value| {
            let bytes = value.dyn_into::<Uint8Array>()?;
            Ok(egui::FontData::from_owned(bytes.to_vec()))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    let faces = faces
        .try_into()
        .map_err(|_| JsValue::from_str("Incorrect font file count"))?;
    Ok(fonts::definitions(faces))
}

#[wasm_bindgen(module = "/web/import.js")]
extern "C" {
    #[wasm_bindgen(js_name=isImportCanceled)]
    fn is_import_canceled(operation: u32) -> bool;
    #[wasm_bindgen(js_name=importProgress)]
    fn import_progress(bytes: Uint8Array);
    #[wasm_bindgen(js_name=importYield)]
    async fn import_yield();
    #[wasm_bindgen(js_name=isExportCanceled)]
    fn is_export_canceled(operation: u32) -> bool;
}
struct ExportControl {
    operation: u32,
    generation: u32,
    last: f64,
    yielded: f64,
    phase: Option<confidex_app::export::Phase>,
}
impl ExportControl {
    fn progress(&mut self, progress: confidex_app::export::Progress) -> bool {
        if is_export_canceled(self.operation) {
            return false;
        }
        let now = js_sys::Date::now();
        if self.phase != Some(progress.phase) || now - self.last >= 40. {
            self.phase = Some(progress.phase);
            self.last = now;
            let response = Response {
                generation: self.generation,
                result: Ok(Output::VendorExport(Ok(
                    confidex_app::export_flow::Reply::Progress {
                        operation: self.operation,
                        progress,
                    },
                ))),
            };
            let Ok(bytes) = crate::browser_wire::encode_response(response) else {
                return false;
            };
            let bytes = Zeroizing::new(bytes);
            import_progress(Uint8Array::from(bytes.as_slice()));
        }
        true
    }
}
impl confidex_app::export_flow::Control for ExportControl {
    async fn checkpoint(&mut self, progress: confidex_app::export::Progress) -> bool {
        let now = js_sys::Date::now();
        if progress.current == 0 || progress.current == progress.total || now - self.yielded >= 16.
        {
            import_yield().await;
            self.yielded = js_sys::Date::now();
        }
        self.progress(progress)
    }
    fn computing(&mut self, progress: confidex_app::export::Progress) -> bool {
        self.progress(progress)
    }
}
struct ImportControl {
    operation: u32,
    generation: u32,
    last: f64,
    yielded: f64,
    phase: Option<flow::Phase>,
}
impl ImportControl {
    fn progress(&mut self, progress: flow::Progress) -> bool {
        if is_import_canceled(self.operation) {
            return false;
        }
        let now = js_sys::Date::now();
        if self.phase != Some(progress.phase) || now - self.last >= 40. {
            self.last = now;
            self.phase = Some(progress.phase);
            let response = Response {
                generation: self.generation,
                result: Ok(Output::VendorImport(Ok(flow::Reply::Progress {
                    operation: self.operation,
                    progress,
                }))),
            };
            let Ok(bytes) = crate::browser_wire::encode_response(response) else {
                return false;
            };
            let bytes = Zeroizing::new(bytes);
            import_progress(Uint8Array::from(bytes.as_slice()));
        }
        true
    }
}
impl confidex_app::import_apply::Control for ImportControl {
    async fn checkpoint(&mut self, value: confidex_app::import_apply::Progress) -> bool {
        let now = js_sys::Date::now();
        if value.current == 0
            || value.phase == confidex_app::import_apply::Phase::Commit
            || now - self.yielded >= 16.
        {
            // The parser is synchronous. Read queued cancellation before any write.
            import_yield().await;
            self.yielded = js_sys::Date::now();
        }
        self.progress(value.into())
    }
}
impl flow::Control for ImportControl {
    fn parsing(&mut self, value: confidex_app::import::Progress) -> bool {
        self.progress(value.into())
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub struct WorkerService {
    engine: Engine,
    #[cfg(feature = "sync")]
    transport: crate::sync_transport::Net,
}
#[wasm_bindgen]
impl WorkerService {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn execute(&mut self, input: Vec<u8>) -> Result<Uint8Array, JsValue> {
        let input = Zeroizing::new(input);
        if input.len() > crate::browser_wire::MAX_PACKET {
            let _ = self.engine.cancel_export(None);
            return Err(JsValue::from_str("request limit"));
        }
        let mut request: Request = match crate::browser_wire::decode_request(&input) {
            Ok(request) => request,
            Err(_) => {
                let _ = self.engine.cancel_export(None);
                return Err(JsValue::from_str("invalid request"));
            }
        };
        drop(input);
        #[cfg(not(feature = "sync"))]
        let mut transport = confidex_app::sync::Offline;
        #[cfg(not(feature = "sync"))]
        let transport = &mut transport;
        #[cfg(feature = "sync")]
        let transport = &mut self.transport;
        let response = if let Command::VendorImport(command) = &mut request.command {
            let mut control = ImportControl {
                operation: command.operation().unwrap_or(0),
                generation: request.generation,
                last: 0.,
                yielded: 0.,
                phase: None,
            };
            import_yield().await;
            Response {
                generation: request.generation,
                result: Ok(Output::VendorImport(
                    self.engine
                        .execute_import(&mut BrowserStore, command, &mut control)
                        .await,
                )),
            }
        } else if let Command::VendorExport(command) = &mut request.command {
            let mut control = ExportControl {
                operation: command.operation().unwrap_or(0),
                generation: request.generation,
                last: 0.,
                yielded: 0.,
                phase: None,
            };
            import_yield().await;
            Response {
                generation: request.generation,
                result: Ok(Output::VendorExport(
                    self.engine
                        .execute_export(&mut BrowserStore, command, &mut control)
                        .await,
                )),
            }
        } else {
            self.engine
                .execute_with_transport(
                    &mut BrowserStore,
                    &mut BrowserKeys::default(),
                    transport,
                    &mut request,
                )
                .await
        };
        let bytes = Zeroizing::new(
            crate::browser_wire::encode_response(response)
                .map_err(|_| JsValue::from_str("response encoding"))?,
        );
        Ok(Uint8Array::from(bytes.as_slice()))
    }
}
struct BrowserRuntime {
    worker: Worker,
    ready: Rc<Cell<bool>>,
    pending: Rc<RefCell<Vec<Zeroizing<Vec<u8>>>>>,
    generation: Rc<Cell<u32>>,
    device_unlock_minutes: Rc<Cell<u16>>,
    replies: mpsc::Receiver<Response>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(ErrorEvent)>,
}
fn post(worker: &Worker, bytes: &[u8]) -> Result<(), JsValue> {
    let data = Uint8Array::from(bytes);
    let transfer = Array::new();
    transfer.push(&data.buffer());
    worker.post_message_with_transfer(&data, &transfer)
}
impl BrowserRuntime {
    fn new(ctx: eframe::egui::Context) -> Result<Self, JsValue> {
        let options = WorkerOptions::new();
        options.set_type(WorkerType::Module);
        let worker = Worker::new_with_options("/worker.js", &options)?;
        confidex_device_secrets::platform::attach_passkey_host(worker.as_ref());
        browser_store::attach_key_fallback(&worker);
        let (sender, replies) = mpsc::channel();
        let ready = Rc::new(Cell::new(false));
        let generation = Rc::new(Cell::new(0));
        let device_unlock_minutes =
            Rc::new(Cell::new(confidex_app::device_unlock::DEFAULT_MINUTES));
        let minutes = device_unlock_minutes.clone();
        let pending = Rc::new(RefCell::new(Vec::<Zeroizing<Vec<u8>>>::new()));
        let (target, flag, queue, output, repaint, current) = (
            worker.clone(),
            ready.clone(),
            pending.clone(),
            sender.clone(),
            ctx.clone(),
            generation.clone(),
        );
        let message = Closure::new(move |event: MessageEvent| {
            if event.data().as_string().as_deref() == Some("ready") {
                flag.set(true);
                let _ = target.post_message(&u32::from(minutes.get()).into());
                for bytes in queue.borrow_mut().drain(..) {
                    if post(&target, &bytes).is_err() {
                        let _ = output.send(Response {
                            generation: current.get(),
                            result: Err(Error::Storage(confidex_storage::Error::Storage)),
                        });
                    }
                }
            } else {
                let data = event
                    .data()
                    .dyn_into::<Uint8Array>()
                    .unwrap_or_else(|_| Uint8Array::new_with_length(0));
                let response = if data.length() as usize <= crate::browser_wire::MAX_PACKET {
                    let bytes = Zeroizing::new(data.to_vec());
                    data.fill(0, 0, data.length());
                    crate::browser_wire::decode_response(&bytes).ok()
                } else {
                    None
                };
                let _ = output.send(response.unwrap_or(Response {
                    generation: current.get(),
                    result: Err(Error::Storage(confidex_storage::Error::Storage)),
                }));
            }
            repaint.request_repaint();
        });
        let error_generation = generation.clone();
        let error = Closure::new(move |_: ErrorEvent| {
            let _ = sender.send(Response {
                generation: error_generation.get(),
                result: Err(Error::Storage(confidex_storage::Error::Storage)),
            });
            ctx.request_repaint();
        });
        worker.set_onmessage(Some(message.as_ref().unchecked_ref()));
        worker.set_onerror(Some(error.as_ref().unchecked_ref()));
        Ok(Self {
            worker,
            ready,
            pending,
            generation,
            device_unlock_minutes,
            replies,
            _message: message,
            _error: error,
        })
    }
}
impl Runtime for BrowserRuntime {
    fn save_export(
        &mut self,
        transfer: confidex_app::export_flow::Transfer,
        done: confidex_ui::ExportFileCompletion,
    ) {
        crate::export_files::save(transfer, done);
    }
    fn cancel_export(&mut self, operation: u32) {
        if operation != 0 {
            let message = js_sys::Object::new();
            if js_sys::Reflect::set(&message, &"cancelExport".into(), &operation.into()).is_ok() {
                let _ = self.worker.post_message(&message);
            }
        }
    }
    fn cancel_import(&mut self, operation: u32) {
        if operation != 0 {
            let message = js_sys::Object::new();
            if js_sys::Reflect::set(&message, &"cancelImport".into(), &operation.into()).is_ok() {
                let _ = self.worker.post_message(&message);
            }
        }
    }
    fn sync_available(&self) -> bool {
        cfg!(feature = "sync")
    }
    fn default_sync_server(&self) -> Option<String> {
        cfg!(feature = "sync").then(|| crate::sync_defaults::DEFAULT_SYNC_SERVER.to_owned())
    }
    fn device_unlock_label(&self) -> Option<&'static str> {
        Some("vault-device-unlock")
    }
    fn set_device_unlock_minutes(&mut self, minutes: u16) {
        self.device_unlock_minutes.set(minutes);
        if self.ready.get() {
            let _ = self.worker.post_message(&u32::from(minutes).into());
        }
    }
    fn set_key_storage_warning(&mut self, message: &str) {
        browser_store::set_key_storage_warning(&self.worker, message);
    }
    fn send(&mut self, request: Request) -> Result<(), Error> {
        if matches!(
            &request.command,
            Command::Create { .. } | Command::RestoreBackup { .. }
        ) {
            browser_store::request_persistence();
        }
        self.generation.set(request.generation);
        let bytes = Zeroizing::new(crate::browser_wire::encode_request(request)?);
        if self.ready.get() {
            post(&self.worker, &bytes).map_err(|_| Error::Storage(confidex_storage::Error::Storage))
        } else if self.pending.borrow().len() < 4 {
            self.pending.borrow_mut().push(bytes);
            Ok(())
        } else {
            Err(Error::Storage(confidex_storage::Error::Storage))
        }
    }
    fn receive(&mut self) -> Option<Response> {
        self.replies.try_recv().ok()
    }
    fn offline_launch(&self) -> Option<bool> {
        match browser_store::offline_shell() {
            1 => Some(true),
            -1 => Some(false),
            _ => None,
        }
    }
}
impl Drop for BrowserRuntime {
    fn drop(&mut self) {
        self.worker.set_onmessage(None);
        self.worker.set_onerror(None);
        self.worker.terminate();
    }
}

#[wasm_bindgen]
pub struct WebHandle {
    runner: eframe::WebRunner,
}
impl Default for WebHandle {
    fn default() -> Self {
        Self {
            runner: eframe::WebRunner::new(),
        }
    }
}
#[wasm_bindgen]
impl WebHandle {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn start(&self, canvas: web_sys::HtmlCanvasElement) -> Result<(), JsValue> {
        let fonts = browser_fonts().await?;
        let input_id = format!("{}-text-input", canvas.id());
        let plugin_input_id = input_id.clone();
        self.runner
            .start(
                canvas.clone(),
                eframe::WebOptions::default(),
                Box::new(move |cc| {
                    cc.egui_ctx.set_fonts(fonts);
                    let runtime =
                        BrowserRuntime::new(cc.egui_ctx.clone()).map_err(|_| "worker startup")?;
                    let mut app = VaultApp::new(&cc.egui_ctx, Box::new(runtime))?;
                    app.restore_sync_defaults(cc.storage);
                    app.restore_device_unlock_settings(cc.storage);
                    app.restore_auto_lock_settings(cc.storage);
                    app.restore_generator_preferences(cc.storage);
                    cc.egui_ctx
                        .add_plugin(crate::browser_input::TextInput::new(plugin_input_id));
                    crate::motion::install(&cc.egui_ctx);
                    crate::backup_files::install(&mut app);
                    crate::import_files::install(&mut app);
                    crate::image_files::install(&mut app);
                    crate::passwords::install(app.password_evaluator());
                    let languages: Vec<String> = web_sys::window()
                        .map(|w| w.navigator().languages())
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|language| language.as_string())
                        .collect();
                    app.locale = confidex_ui::i18n::Localizer::from_preferences(languages)?;
                    app.set_clipboard_handler(|text, done| {
                        let clipboard = web_sys::window().and_then(|w| {
                            js_sys::Reflect::get(&w.navigator(), &"clipboard".into())
                                .ok()
                                .and_then(|c| c.dyn_into::<web_sys::Clipboard>().ok())
                        });
                        if let Some(clipboard) = clipboard {
                            let promise = clipboard.write_text(&text);
                            wasm_bindgen_futures::spawn_local(async move {
                                done(wasm_bindgen_futures::JsFuture::from(promise).await.is_ok());
                            });
                        } else {
                            done(false);
                        }
                    });
                    Ok(Box::new(app))
                }),
            )
            .await?;
        crate::browser_input::install(&self.runner, &canvas, &input_id)
    }
    #[cfg(feature = "export-ui-check")]
    pub async fn start_folder_check(
        &self,
        canvas: web_sys::HtmlCanvasElement,
        language: String,
    ) -> Result<(), JsValue> {
        let fonts = browser_fonts().await?;
        self.runner
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(move |cc| {
                    cc.egui_ctx.set_fonts(fonts);
                    let mut app = VaultApp::folder_fixture(&cc.egui_ctx)?;
                    app.locale =
                        confidex_ui::i18n::Localizer::from_preferences([language.as_str()])?;
                    Ok(Box::new(app))
                }),
            )
            .await
    }
    pub fn destroy(&self) {
        self.runner.destroy();
    }
    pub fn has_unsaved_changes(&self) -> bool {
        self.runner
            .app_mut::<VaultApp>()
            .is_some_and(|app| app.has_unsaved_changes())
    }
    pub fn file_drag(&self, x: f32, y: f32) {
        if let Some(mut app) = self.runner.app_mut::<VaultApp>() {
            let zoom = app.zoom_factor;
            app.set_file_drop_position(Some(eframe::egui::pos2(x / zoom, y / zoom)));
        }
    }
    pub fn file_drag_end(&self) {
        if let Some(mut app) = self.runner.app_mut::<VaultApp>() {
            app.set_file_drop_position(None);
        }
    }
    pub fn snapshot(&self) -> Result<JsValue, JsValue> {
        let app = self
            .runner
            .app_mut::<VaultApp>()
            .ok_or(JsValue::from_str("not ready"))?;
        let (screen, busy, vaults, rows) = app.status();
        let value = js_sys::Object::new();
        js_sys::Reflect::set(
            &value,
            &"error".into(),
            &app.error_code()
                .map(JsValue::from_str)
                .unwrap_or(JsValue::NULL),
        )?;
        for (name, data) in [
            ("screen", screen.into()),
            ("busy", busy.into()),
            ("vaults", (vaults as u32).into()),
            ("rows", (rows as u32).into()),
        ] {
            js_sys::Reflect::set(&value, &name.into(), &data)?;
        }
        #[cfg(feature = "export-ui-check")]
        {
            let (path, pending, running, failed) = app.folder_fixture_status();
            for (name, data) in [
                (
                    "folderPath",
                    path.map(JsValue::from_str).unwrap_or(JsValue::NULL),
                ),
                ("folderPending", (pending as u32).into()),
                ("folderRunning", running.into()),
                ("folderFailed", failed.into()),
            ] {
                js_sys::Reflect::set(&value, &name.into(), &data)?;
            }
        }
        let zoom = app.zoom_factor;
        let (editing, theme, locale, copied, failed) = app.view_info();
        for (name, data) in [
            ("zoom", zoom.into()),
            ("editing", editing.into()),
            ("theme", (theme as u32).into()),
            ("locale", locale.into()),
            ("copied", copied.into()),
            ("copyFailed", failed.into()),
        ] {
            js_sys::Reflect::set(&value, &name.into(), &data)?;
        }
        let bounds = js_sys::Object::new();
        for (id, rect) in &app.bounds {
            let coords = Array::new();
            for n in [rect.left(), rect.top(), rect.right(), rect.bottom()] {
                coords.push(&(n * zoom).into());
            }
            js_sys::Reflect::set(&bounds, &id.as_str().into(), &coords)?;
        }
        js_sys::Reflect::set(&value, &"bounds".into(), &bounds)?;
        js_sys::Reflect::set(
            &value,
            &"defaultSyncServer".into(),
            &app.default_sync_server()
                .map(|url| JsValue::from_str(&url))
                .unwrap_or(JsValue::NULL),
        )?;
        let hits = js_sys::Object::new();
        for (id, rect) in &app.hits {
            let point = Array::new();
            point.push(&(rect.center().x * zoom).into());
            point.push(&(rect.center().y * zoom).into());
            js_sys::Reflect::set(&hits, &id.as_str().into(), &point)?;
        }
        js_sys::Reflect::set(&value, &"hits".into(), &hits)?;
        Ok(value.into())
    }
}
