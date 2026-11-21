use crate::protocol::{
    Action, Credentials, MAX_RESPONSE, Reply, Request, Response, SyncStatus, VERSION,
};
use confidex_app::{
    Error,
    browser_logins::{
        Change, Cursor, EditLogin, Issues, Login, MAX_LOGIN_TEXT, NewLogin, Selection,
    },
    new_record, templates,
};
use confidex_storage::RecordId;
use confidex_ui::{
    browser_input,
    i18n::Localizer,
    theme::{self, Palette},
    ui_kit::{self, ButtonRole, Icon, Metrics, record, tags},
};
use eframe::egui;
use js_sys::Uint8Array;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

#[wasm_bindgen(module = "/web/session-host.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn exchange(input: Uint8Array) -> Result<Uint8Array, JsValue>;

    #[wasm_bindgen(js_name = observeSession)]
    fn observe_session(callback: &js_sys::Function);

    #[wasm_bindgen(js_name = disposeSession)]
    fn dispose_session();

    #[wasm_bindgen(js_name = cancelSession)]
    fn cancel_session();

    #[wasm_bindgen(js_name = sessionRevision)]
    fn session_revision() -> u32;

    #[wasm_bindgen(js_name = syncStatusRevision)]
    fn sync_status_revision() -> u32;
}

#[wasm_bindgen]
pub struct WebHandle {
    runner: eframe::WebRunner,
    repaint: RefCell<Option<Closure<dyn FnMut()>>>,
}

#[wasm_bindgen]
impl WebHandle {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            runner: eframe::WebRunner::new(),
            repaint: RefCell::default(),
        }
    }

    pub fn destroy(&self) {
        dispose_session();
        self.repaint.borrow_mut().take();
        self.runner.destroy();
    }

    pub async fn start(&self, canvas: web_sys::HtmlCanvasElement) -> Result<(), JsValue> {
        let fonts = ui_kit::fonts::load_browser().await?;
        let languages = web_sys::window()
            .map(|window| window.navigator().languages())
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.as_string())
            .collect::<Vec<_>>();
        let locale = Localizer::from_preferences(languages)?;
        let input_id = format!("{}-text-input", canvas.id());
        let plugin_input_id = input_id.clone();
        let repaint = Rc::new(RefCell::new(None));
        let app_repaint = repaint.clone();
        self.runner
            .start(
                canvas.clone(),
                eframe::WebOptions::default(),
                Box::new(move |cc| {
                    cc.egui_ctx.set_fonts(fonts);
                    ui_kit::setup(&cc.egui_ctx);
                    cc.egui_ctx
                        .add_plugin(browser_input::TextInput::new(plugin_input_id));
                    let dark = cc.egui_ctx.theme() == egui::Theme::Dark;
                    let theme = theme::THEMES
                        .iter()
                        .find(|theme| theme.dark == dark)
                        .unwrap_or(&theme::THEMES[0]);
                    theme.apply(&cc.egui_ctx);
                    let ctx = cc.egui_ctx.clone();
                    *app_repaint.borrow_mut() = Some(Closure::<dyn FnMut()>::new(move || {
                        ctx.request_repaint();
                    }));
                    let mut app = App {
                        locale,
                        colors: theme.colors,
                        name: String::new(),
                        credentials: Credentials {
                            password: String::new(),
                            key: String::new(),
                        },
                        server: confidex_browser::DEFAULT_SYNC_SERVER.to_owned(),
                        page: Page::Starting,
                        revision: session_revision(),
                        pending: None,
                        sync_revision: sync_status_revision(),
                        sync: SyncStatus::Disabled,
                        issues: Issues::default(),
                        editor: None,
                        rows: Vec::new(),
                        next: None,
                        status: None,
                    };
                    app.request(&cc.egui_ctx, Action::Status);
                    Ok(Box::new(app))
                }),
            )
            .await?;
        browser_input::install(&self.runner, &canvas, &input_id)?;
        if let Some(callback) = repaint.borrow_mut().take() {
            observe_session(callback.as_ref().unchecked_ref());
            *self.repaint.borrow_mut() = Some(callback);
        }
        Ok(())
    }
}

enum Page {
    Starting,
    Disconnected,
    Locked(String),
    Opened(String),
}

type Pending = Rc<RefCell<Option<Response>>>;

struct Editor {
    record: RecordId,
    original: Option<(Selection, EditLogin)>,
    form: NewLogin,
    focus_title: bool,
    tag_editor: tags::Editor,
}

impl Editor {
    fn can_save(&self) -> bool {
        let Some((_, original)) = &self.original else {
            return self.form.has_valid_lengths();
        };
        let form = &self.form;
        let title_changed = form.title != original.title;
        let url_changed = differs(&form.url, original.url.as_deref());
        let username_changed = differs(&form.username, original.username.as_deref());
        let notes_changed = differs(&form.notes, original.notes.as_deref());
        (title_changed
            || url_changed
            || username_changed
            || notes_changed
            || form.tags != original.tags
            || self.tag_editor.has_pending_tag()
            || !form.password.is_empty())
            && (!title_changed
                || !form.title.trim().is_empty() && form.title.len() <= MAX_LOGIN_TEXT)
            && (!url_changed || !form.url.trim().is_empty() && form.url.len() <= MAX_LOGIN_TEXT)
            && (!username_changed || form.username.len() <= MAX_LOGIN_TEXT)
            && (!notes_changed || form.notes.len() <= MAX_LOGIN_TEXT)
            && form.password.len() <= MAX_LOGIN_TEXT
    }

    fn save_action(&self) -> Action {
        let form = &self.form;
        if let Some((target, original)) = &self.original {
            Action::UpdateLogin {
                target: target.clone(),
                change: Change {
                    title: changed_text(&form.title, Some(&original.title)),
                    username: changed_text(&form.username, original.username.as_deref()),
                    password: (!form.password.is_empty()).then(|| form.password.clone()),
                    url: changed_text(&form.url, original.url.as_deref()),
                    notes: changed_text(&form.notes, original.notes.as_deref()),
                    tags: (form.tags != original.tags).then(|| form.tags.clone()),
                },
            }
        } else {
            Action::CreateLogin {
                record: self.record,
                login: NewLogin {
                    title: form.title.clone(),
                    url: form.url.clone(),
                    username: form.username.clone(),
                    password: form.password.clone(),
                    notes: form.notes.clone(),
                    tags: form.tags.clone(),
                },
            }
        }
    }
}

fn differs(current: &str, original: Option<&str>) -> bool {
    original.is_some_and(|value| value != current)
}

fn changed_text(current: &str, original: Option<&str>) -> Option<String> {
    differs(current, original).then(|| current.to_owned())
}

struct App {
    locale: Localizer,
    colors: Palette,
    name: String,
    credentials: Credentials,
    server: String,
    page: Page,
    revision: u32,
    pending: Option<Pending>,
    rows: Vec<Login>,
    next: Option<Cursor>,
    sync_revision: u32,
    sync: SyncStatus,
    issues: Issues,
    editor: Option<Editor>,
    status: Option<(&'static str, bool)>,
}

impl App {
    fn request(&mut self, ctx: &egui::Context, action: Action) {
        if matches!(action, Action::Logins { after: None }) {
            self.issues = Issues::default();
        }
        let pending = Pending::default();
        self.pending = Some(pending.clone());
        let ctx = ctx.clone();
        wasm_bindgen_futures::spawn_local(async move {
            *pending.borrow_mut() = Some(send(action).await);
            ctx.request_repaint();
        });
    }

    fn receive(&mut self, ctx: &egui::Context, response: Response) {
        match response {
            Err(error) => {
                self.status = Some((error_label(error), true));
                match error {
                    Error::Locked => {
                        self.page = Page::Starting;
                        self.rows.clear();
                        self.next = None;
                        self.editor = None;
                    }
                    Error::Storage(confidex_storage::Error::Conflict) => {
                        self.editor = None;
                        self.request(ctx, Action::Logins { after: None });
                    }
                    _ => {}
                }
            }
            Ok(Reply::Disconnected) => {
                self.page = Page::Disconnected;
                self.rows.clear();
                self.next = None;
            }
            Ok(Reply::Locked { name }) => {
                self.page = Page::Locked(name);
                self.rows.clear();
                self.next = None;
                self.editor = None;
            }
            Ok(Reply::Opened { name, sync }) => {
                self.page = Page::Opened(name);
                self.sync = sync;
                self.request(ctx, Action::Logins { after: None });
            }
            Ok(Reply::Synced { sync, .. }) => {
                self.sync = sync;
                self.request(ctx, Action::Logins { after: None });
            }
            Ok(Reply::Logins { page, sync }) => {
                self.sync = sync;
                self.rows = page.rows;
                self.next = page.next;
                self.issues.ambiguous |= page.issues.ambiguous;
                self.issues.conflicts |= page.issues.conflicts;
            }
            Ok(Reply::LoginEditor { target, fields }) => {
                self.editor = Some(Editor {
                    record: target.head.record,
                    form: NewLogin {
                        title: fields.title.clone(),
                        username: fields.username.clone().unwrap_or_default(),
                        url: fields.url.clone().unwrap_or_default(),
                        password: String::new(),
                        notes: fields.notes.clone().unwrap_or_default(),
                        tags: fields.tags.clone(),
                    },
                    original: Some((target, fields)),
                    focus_title: true,
                    tag_editor: tags::Editor::default(),
                });
            }
            Ok(Reply::Saved(_)) => {
                self.editor = None;
                self.status = Some(("extension-saved-local", false));
                self.request(ctx, Action::Logins { after: None });
            }
        }
    }

    fn show_editor(&mut self, ui: &mut egui::Ui) {
        let Some(editor) = &mut self.editor else {
            return;
        };
        let original = editor.original.as_ref().map(|(_, fields)| fields);
        record::toolbar(
            ui,
            self.colors,
            &self.locale.text(if original.is_some() {
                "vault-record"
            } else {
                "vault-unsaved"
            }),
            |_| {},
        );
        let title = record::heading(
            ui,
            &mut editor.form.title,
            true,
            &self.locale.text("vault-record-title"),
        );
        if std::mem::take(&mut editor.focus_title) {
            title.request_focus();
            title.scroll_to_me(Some(egui::Align::TOP));
        }

        ui.add_space(Metrics::LG);
        let template = templates::get("login").expect("login template");
        let list = ui.make_persistent_id(editor.record);
        for spec in template.fields {
            let (value, secret, multiline, enabled) = match spec.type_name {
                "username/v1" => (
                    &mut editor.form.username,
                    false,
                    false,
                    original.is_none_or(|f| f.username.is_some()),
                ),
                "password/v1" => (&mut editor.form.password, true, false, true),
                "url/v1" => (
                    &mut editor.form.url,
                    false,
                    false,
                    original.is_none_or(|f| f.url.is_some()),
                ),
                "note/v1" => (
                    &mut editor.form.notes,
                    false,
                    true,
                    original.is_none_or(|f| f.notes.is_some()),
                ),
                _ => continue,
            };
            let id = list.with(spec.type_name);
            let card = ui_kit::field::Field {
                id,
                list,
                name: &mut self.locale.starter_name(spec.name),
                kind: &ui_kit::field::kind_label(&self.locale, spec.type_name),
                editing: false,
                move_label: "",
                remove_label: "",
            };
            let response = card.show(ui, self.colors, |ui| {
                let response =
                    ui_kit::field_with_id(ui, id.with("value"), value, secret, multiline, enabled);
                if secret && original.is_some() {
                    ui_kit::muted(
                        ui,
                        self.colors,
                        self.locale.text("extension-password-replacement-hint"),
                    );
                } else if !enabled {
                    ui_kit::muted(ui, self.colors, self.locale.text("vault-opaque-fields"));
                }
                response
            });
            let value = response.inner.labelled_by(response.name.id);
            if value.gained_focus() {
                value.scroll_to_me(None);
            }
        }

        editor.tag_editor.show(
            ui,
            self.colors,
            &self.locale,
            editor.record,
            &mut editor.form.tags,
        );
        let tag_problem = editor.tag_editor.problem(&editor.form.tags);
        let ready = tag_problem.is_none() && editor.can_save();

        ui.add_space(Metrics::LG);
        let (submit, cancel) = ui
            .horizontal_wrapped(|ui| {
                let submit = ui_kit::button(
                    ui,
                    self.colors,
                    &self.locale.text("vault-save"),
                    ButtonRole::Primary,
                    0.,
                    ready,
                )
                .clicked();
                let cancel = ui_kit::button(
                    ui,
                    self.colors,
                    &self.locale.text("vault-cancel"),
                    ButtonRole::Secondary,
                    0.,
                    true,
                )
                .clicked();
                (submit, cancel)
            })
            .inner;
        if let Some(key) = tag_problem {
            ui.colored_label(self.colors.error, self.locale.text(key));
        }
        if cancel {
            self.editor = None;
            self.status = None;
        } else if ready
            && (submit
                || ui.memory(|memory| memory.focused().is_none())
                    && ui.input_mut(|input| {
                        input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                    }))
        {
            if !editor.tag_editor.apply(&mut editor.form.tags) {
                return;
            }
            let action = editor.save_action();
            self.status = None;
            self.request(ui.ctx(), action);
        }
    }

    fn show_sync(&self, ui: &mut egui::Ui) {
        let (message, error) = match self.sync {
            SyncStatus::Disabled => ("sync-disabled", false),
            SyncStatus::Pending => ("extension-sync-pending", false),
            SyncStatus::Current => ("remove-vault-synced", false),
            SyncStatus::Offline => ("sync-error-network", true),
            SyncStatus::Failed(error) => (error_label(error), true),
        };
        let color = if error {
            self.colors.error
        } else {
            self.colors.text_muted
        };
        ui.colored_label(color, self.locale.text(message));
        if self.issues.conflicts {
            ui.colored_label(
                self.colors.error,
                self.locale.text("extension-login-conflicts"),
            );
        }
        if self.issues.ambiguous {
            ui.colored_label(
                self.colors.error,
                self.locale.text("extension-login-ambiguous"),
            );
        }
    }

    fn show_credentials(&mut self, ui: &mut egui::Ui) -> bool {
        let connecting = matches!(self.page, Page::Disconnected);
        if connecting {
            field(ui, self.locale.text("vault-name"), &mut self.name, false);
            field(ui, self.locale.text("sync-server"), &mut self.server, false);
        }
        field(
            ui,
            self.locale.text("vault-secret-key"),
            &mut self.credentials.key,
            true,
        );
        let password = field(
            ui,
            self.locale.text("vault-password"),
            &mut self.credentials.password,
            true,
        );
        let ready = !self.credentials.key.is_empty()
            && !self.credentials.password.is_empty()
            && (!connecting || !self.name.trim().is_empty());
        let action = if connecting {
            "sync-import"
        } else {
            "vault-unlock"
        };
        let pressed = ui_kit::button(
            ui,
            self.colors,
            &self.locale.text(action),
            ButtonRole::Primary,
            0.,
            ready,
        )
        .clicked();
        ready
            && (pressed
                || (password.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))))
    }

    fn show(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width().min(480.);
        ui.set_width(width);
        ui.horizontal(|ui| {
            ui_kit::badge(ui, Icon::Vault, self.colors, 36., true);
            ui.heading(self.locale.text("vault-window-title"));
        });
        ui.add_space(Metrics::SM);
        ui_kit::muted(ui, self.colors, self.locale.text("extension-session-hint"));
        ui.add_space(Metrics::LG);
        if let Some((message, error)) = self.status {
            let color = if error {
                self.colors.error
            } else {
                self.colors.text_muted
            };
            ui.colored_label(color, self.locale.text(message));
        }
        if self.pending.is_some() {
            ui_kit::spinner(ui, self.colors, 20., &self.locale.text("vault-working"));
            let action = if matches!(self.page, Page::Opened(_)) {
                "vault-lock"
            } else {
                "vault-cancel"
            };
            if ui_kit::button(
                ui,
                self.colors,
                &self.locale.text(action),
                ButtonRole::Secondary,
                0.,
                true,
            )
            .clicked()
            {
                cancel_session();
            }
            return;
        }

        match &self.page {
            Page::Starting => {
                if ui.button(self.locale.text("vault-refresh")).clicked() {
                    self.status = None;
                    self.request(ui.ctx(), Action::Status);
                }
            }
            Page::Disconnected | Page::Locked(_) => {
                if let Page::Locked(name) = &self.page {
                    ui.heading(name);
                }
                if self.show_credentials(ui) {
                    let credentials = Credentials {
                        password: std::mem::take(&mut self.credentials.password),
                        key: std::mem::take(&mut self.credentials.key),
                    };
                    let action = if matches!(self.page, Page::Disconnected) {
                        Action::Connect {
                            name: self.name.clone(),
                            server: self.server.clone(),
                            credentials,
                        }
                    } else {
                        Action::Unlock(credentials)
                    };
                    self.status = None;
                    self.request(ui.ctx(), action);
                }
            }
            Page::Opened(name) => {
                ui.heading(name);
                self.show_sync(ui);
                let mut selected = None;
                ui.horizontal_wrapped(|ui| {
                    if ui_kit::button(
                        ui,
                        self.colors,
                        &self.locale.text("vault-lock"),
                        ButtonRole::Secondary,
                        0.,
                        true,
                    )
                    .clicked()
                    {
                        cancel_session();
                        self.rows.clear();
                        self.next = None;
                        self.editor = None;
                    }
                    if ui_kit::button(
                        ui,
                        self.colors,
                        &self.locale.text("sync-now"),
                        ButtonRole::Secondary,
                        0.,
                        self.sync != SyncStatus::Disabled,
                    )
                    .clicked()
                    {
                        selected = Some(Action::Sync);
                    }
                    if ui_kit::button(
                        ui,
                        self.colors,
                        &self.locale.text("extension-new-login"),
                        ButtonRole::Quiet,
                        0.,
                        self.editor.is_none(),
                    )
                    .clicked()
                    {
                        self.status = None;
                        match new_record() {
                            Ok(draft) => {
                                self.editor = Some(Editor {
                                    record: draft.record,
                                    original: None,
                                    form: NewLogin::default(),
                                    focus_title: true,
                                    tag_editor: tags::Editor::default(),
                                })
                            }
                            Err(error) => self.status = Some((error_label(error), true)),
                        }
                    }
                });
                ui.separator();
                if self.editor.is_some() {
                    self.show_editor(ui);
                    if let Some(action) = selected {
                        self.request(ui.ctx(), action);
                    }
                    return;
                }
                if self.rows.is_empty() {
                    ui_kit::muted(ui, self.colors, self.locale.text("vault-no-results"));
                }
                for login in &self.rows {
                    ui.group(|ui| {
                        ui.strong(&login.title);
                        ui.label(&login.username);
                        if ui.button(self.locale.text("vault-edit")).clicked() {
                            self.status = None;
                            selected = Some(Action::LoginEditor {
                                target: login.target.clone(),
                            });
                        }
                    });
                }
                if self.next.is_some() && ui.button(self.locale.text("vault-more")).clicked() {
                    selected = Some(Action::Logins {
                        after: self.next.clone(),
                    });
                }
                if let Some(action) = selected {
                    self.status = None;
                    self.request(ui.ctx(), action);
                }
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        let revision = session_revision();
        if revision != self.revision {
            self.revision = revision;
            self.rows.clear();
            self.next = None;
            self.credentials.key.zeroize();
            self.credentials.password.zeroize();
            self.status = None;
            self.sync = SyncStatus::Disabled;
            self.issues = Issues::default();
            self.editor = None;
            let pending = self.pending.take().is_some();
            self.page = match std::mem::replace(&mut self.page, Page::Starting) {
                Page::Opened(name) => Page::Locked(name),
                Page::Disconnected if pending => Page::Starting,
                page => page,
            };
        }
        let response = self
            .pending
            .as_ref()
            .and_then(|pending| pending.borrow_mut().take());
        if let Some(response) = response {
            self.pending = None;
            self.receive(ctx, response);
        }
        let sync_revision = sync_status_revision();
        if self.pending.is_none() && sync_revision != self.sync_revision {
            self.sync_revision = sync_revision;
            if matches!(self.page, Page::Opened(_)) {
                self.request(ctx, Action::Logins { after: None });
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(Metrics::XXL);
                    let width = ui.available_width().min(480.);
                    ui.allocate_ui_with_layout(
                        egui::vec2(width, 0.),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| self.show(ui),
                    );
                });
            });
        });
    }
}

fn field(ui: &mut egui::Ui, label: String, value: &mut String, secret: bool) -> egui::Response {
    let label = ui.label(label);
    ui_kit::field(ui, value, secret, false, true).labelled_by(label.id)
}

async fn send(action: Action) -> Response {
    let bytes = Zeroizing::new(
        serde_json::to_vec(&Request {
            version: VERSION,
            action,
        })
        .map_err(|_| Error::Input)?,
    );
    let input = Uint8Array::from(bytes.as_slice());
    drop(bytes);
    let output = exchange(input).await.map_err(|_| Error::Locked)?;
    if output.length() as usize > MAX_RESPONSE {
        output.fill(0, 0, output.length());
        return Err(Error::Integrity);
    }
    let bytes = Zeroizing::new(output.to_vec());
    output.fill(0, 0, output.length());
    serde_json::from_slice(&bytes).map_err(|_| Error::Integrity)?
}

fn error_label(error: Error) -> &'static str {
    match error {
        Error::Auth => "vault-error-auth",
        Error::Key => "vault-error-key",
        Error::Network => "sync-error-network",
        Error::Server(_) | Error::Credentials => "sync-error-server",
        Error::Input | Error::PasswordRequired => "vault-error-input",
        Error::Locked => "vault-error-locked",
        Error::SyncDisabled => "sync-disabled",
        Error::Integrity => "vault-error-integrity",
        Error::Storage(confidex_storage::Error::Conflict) => "extension-login-changed",
        _ => "vault-error-storage",
    }
}
