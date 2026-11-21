use crate::protocol::{
    Action, Credentials, Login, LoginCursor, MAX_RESPONSE, Reply, Request, Response, VERSION,
};
use confidex_app::Error;
use confidex_ui::{
    browser_input,
    i18n::Localizer,
    theme::{self, Palette},
    ui_kit::{self, ButtonRole, Icon, Metrics},
};
use eframe::egui;
use js_sys::Uint8Array;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen(module = "/web/session-host.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn exchange(input: Uint8Array) -> Result<Uint8Array, JsValue>;
}

#[wasm_bindgen]
pub struct WebHandle {
    runner: eframe::WebRunner,
}

#[wasm_bindgen]
impl WebHandle {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            runner: eframe::WebRunner::new(),
        }
    }

    pub fn destroy(&self) {
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
                        pending: None,
                        rows: Vec::new(),
                        next: None,
                        status: None,
                    };
                    app.request(&cc.egui_ctx, Action::Status);
                    Ok(Box::new(app))
                }),
            )
            .await?;
        browser_input::install(&self.runner, &canvas, &input_id)
    }
}

enum Page {
    Starting,
    Disconnected,
    Locked(String),
    Opened { name: String, can_sync: bool },
}

type Pending = Rc<RefCell<Option<(Response, bool)>>>;

struct App {
    locale: Localizer,
    colors: Palette,
    name: String,
    credentials: Credentials,
    server: String,
    page: Page,
    pending: Option<Pending>,
    rows: Vec<Login>,
    next: Option<LoginCursor>,
    status: Option<(&'static str, bool)>,
}

impl App {
    fn request(&mut self, ctx: &egui::Context, action: Action) {
        let pending = Pending::default();
        self.pending = Some(pending.clone());
        let ctx = ctx.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let sync = matches!(action, Action::Sync);
            *pending.borrow_mut() = Some((send(action).await, sync));
            ctx.request_repaint();
        });
    }

    fn receive(&mut self, ctx: &egui::Context, response: Response, sync: bool) {
        match response {
            Err(error) => {
                self.status = Some((error_label(error), true));
                if error == Error::Locked {
                    self.page = Page::Starting;
                    self.rows.clear();
                    self.next = None;
                } else if sync {
                    self.request(ctx, Action::Logins { after: None });
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
            }
            Ok(Reply::Opened { name, can_sync }) => {
                self.page = Page::Opened { name, can_sync };
                if can_sync {
                    self.request(ctx, Action::Sync);
                } else {
                    self.request(ctx, Action::Logins { after: None });
                }
            }
            Ok(Reply::Synced { conflicts, more }) => {
                if more && !conflicts {
                    self.request(ctx, Action::Sync);
                } else {
                    if conflicts {
                        self.status = Some(("sync-conflicts", true));
                    }
                    self.request(ctx, Action::Logins { after: None });
                }
            }
            Ok(Reply::Logins { rows, next }) => {
                self.rows = rows;
                self.next = next;
            }
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
            Page::Opened { name, can_sync } => {
                ui.heading(name);
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
                        self.rows.clear();
                        self.next = None;
                        selected = Some(Action::Lock);
                    }
                    if ui_kit::button(
                        ui,
                        self.colors,
                        &self.locale.text("sync-now"),
                        ButtonRole::Secondary,
                        0.,
                        *can_sync,
                    )
                    .clicked()
                    {
                        selected = Some(Action::Sync);
                    }
                    if ui_kit::button(
                        ui,
                        self.colors,
                        &self.locale.text("vault-refresh"),
                        ButtonRole::Quiet,
                        0.,
                        true,
                    )
                    .clicked()
                    {
                        selected = Some(Action::Logins { after: None });
                    }
                });
                ui.separator();
                if self.rows.is_empty() {
                    ui_kit::muted(ui, self.colors, self.locale.text("vault-no-results"));
                }
                for login in &self.rows {
                    ui.group(|ui| {
                        ui.strong(&login.title);
                        ui.label(&login.username);
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
        let response = self
            .pending
            .as_ref()
            .and_then(|pending| pending.borrow_mut().take());
        if let Some((response, sync)) = response {
            self.pending = None;
            self.receive(ctx, response, sync);
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
        _ => "vault-error-storage",
    }
}
