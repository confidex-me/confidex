use crate::{
    autofill::{PopupAction, PopupReply, PopupRequest},
    autosave::SitePolicy,
    protocol::{MAX_RESPONSE, SyncStatus},
    save_ui::SavePanel,
};
use confidex_app::browser_logins::Page;
use confidex_extension_content::Choice;
use confidex_ui::{
    i18n::Localizer,
    theme::{self, Palette},
    ui_kit::{self, ButtonRole, Metrics},
};
use eframe::egui;
use std::{cell::RefCell, rc::Rc, time::Duration};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen(module = "/web/popup-channel.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = popupCall)]
    async fn popup_call(input: String) -> Result<String, JsValue>;
}

pub(crate) async fn request_popup(action: PopupAction) -> PopupReply {
    let request = PopupRequest { version: 1, action };
    let reply = match serde_json::to_string(&request) {
        Ok(request) => popup_call(request).await.ok().and_then(|text| {
            let text = Zeroizing::new(text);
            if text.len() > MAX_RESPONSE {
                return None;
            }
            serde_json::from_str::<PopupReply>(&text).ok()
        }),
        Err(_) => None,
    };
    reply.unwrap_or(PopupReply::Error)
}

#[wasm_bindgen]
pub struct PopupHandle(eframe::WebRunner);

#[wasm_bindgen]
impl PopupHandle {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(eframe::WebRunner::new())
    }

    pub fn destroy(&self) {
        self.0.destroy();
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
        self.0
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(move |cc| {
                    cc.egui_ctx.set_fonts(fonts);
                    ui_kit::setup(&cc.egui_ctx);
                    let dark = cc.egui_ctx.theme() == egui::Theme::Dark;
                    let theme = theme::THEMES
                        .iter()
                        .find(|theme| theme.dark == dark)
                        .unwrap_or(&theme::THEMES[0]);
                    theme.apply(&cc.egui_ctx);
                    let mut popup = Popup {
                        locale,
                        colors: theme.colors,
                        state: PopupReply::Locked,
                        pending: None,
                        form: None,
                        account: None,
                        check_at: 0.,
                        saves: SavePanel::default(),
                    };
                    popup.request(&cc.egui_ctx, PopupAction::Discover { after: None });
                    Ok(Box::new(popup))
                }),
            )
            .await
    }
}

struct Pending {
    reply: Rc<RefCell<Option<PopupReply>>>,
    quiet: bool,
}

struct Popup {
    locale: Localizer,
    colors: Palette,
    state: PopupReply,
    pending: Option<Pending>,
    form: Option<usize>,
    account: Option<usize>,
    check_at: f64,
    saves: SavePanel,
}

impl Popup {
    fn request(&mut self, ctx: &egui::Context, action: PopupAction) {
        let reply_slot = Rc::new(RefCell::new(None));
        self.pending = Some(Pending {
            quiet: matches!(action, PopupAction::Check { .. }),
            reply: reply_slot.clone(),
        });
        let ctx = ctx.clone();
        wasm_bindgen_futures::spawn_local(async move {
            *reply_slot.borrow_mut() = Some(request_popup(action).await);
            ctx.request_repaint();
        });
    }

    fn show(&mut self, ui: &mut egui::Ui) -> Option<PopupAction> {
        let busy = self.pending.as_ref().is_some_and(|request| !request.quiet);
        ui.heading("Confidex");
        self.saves.show(ui, &self.locale, self.colors);
        if busy {
            ui_kit::spinner(ui, self.colors, 20., &self.locale.text("vault-working"));
        }
        match &self.state {
            PopupReply::Site {
                operation,
                origin,
                forms,
                matches,
                sync,
                policy,
                ..
            } => {
                ui.label(origin);
                if matches.issues.conflicts {
                    ui.colored_label(
                        self.colors.error,
                        self.locale.text("extension-login-conflicts"),
                    );
                }
                if matches.issues.ambiguous {
                    ui.colored_label(
                        self.colors.error,
                        self.locale.text("extension-login-ambiguous"),
                    );
                }
                match sync {
                    SyncStatus::Offline => {
                        ui.label(self.locale.text("sync-error-network"));
                    }
                    SyncStatus::Failed(error) => {
                        ui.label(self.locale.text(crate::ui::error_label(*error)));
                    }
                    _ => {}
                }
                if forms.is_empty() {
                    ui.label(self.locale.text("extension-no-form"));
                } else {
                    ui.add_enabled_ui(!busy, |ui| {
                        show_choices(
                            ui,
                            &self.locale,
                            self.colors,
                            forms,
                            matches,
                            &mut self.form,
                            &mut self.account,
                        );
                    });
                    let selection = self
                        .form
                        .zip(self.account)
                        .and_then(|(form, account)| {
                            Some((forms.get(form)?, matches.rows.get(account)?))
                        })
                        .filter(|(form, login)| {
                            form.target.password.is_some() || !login.username.is_empty()
                        });
                    if let Some(action) = ui
                        .add_enabled_ui(!busy, |ui| {
                            let clicked = ui_kit::button(
                                ui,
                                self.colors,
                                &self.locale.text("extension-fill"),
                                ButtonRole::Primary,
                                ui.available_width(),
                                selection.is_some(),
                            )
                            .clicked();
                            selection
                                .filter(|_| clicked)
                                .map(|(form, login)| PopupAction::Fill {
                                    operation: operation.clone(),
                                    form: form.target.form,
                                    target: login.target.clone(),
                                })
                        })
                        .inner
                    {
                        return Some(action);
                    }
                    if let Some(after) = &matches.next
                        && ui
                            .add_enabled(!busy, egui::Button::new(self.locale.text("vault-more")))
                            .clicked()
                    {
                        return Some(PopupAction::Discover {
                            after: Some(after.clone()),
                        });
                    }
                }
                if let Some(action) = ui
                    .add_enabled_ui(!busy, |ui| self.site_settings(ui, origin, *policy))
                    .inner
                {
                    return Some(action);
                }
            }
            PopupReply::SiteDisabled { origin } => {
                ui.label(origin);
                ui.label(self.locale.text("extension-site-disabled"));
                if let Some(action) = ui
                    .add_enabled_ui(!busy, |ui| {
                        self.site_settings(ui, origin, SitePolicy::Disabled)
                    })
                    .inner
                {
                    return Some(action);
                }
            }
            state => {
                let key = match state {
                    PopupReply::Locked | PopupReply::Live => "vault-error-locked",
                    PopupReply::Unavailable => "extension-site-no-access",
                    PopupReply::Changed => "extension-form-changed",
                    PopupReply::Busy | PopupReply::PolicyChanged => "vault-working",
                    PopupReply::Error => "vault-error-storage",
                    PopupReply::Filled => "extension-filled",
                    PopupReply::Save(_)
                    | PopupReply::Site { .. }
                    | PopupReply::SiteDisabled { .. } => unreachable!(),
                };
                if !busy {
                    ui.label(self.locale.text(key));
                }
            }
        }
        ui.add_space(Metrics::SM);
        ui.separator();
        let mut action = None;
        ui.add_enabled_ui(!busy, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui_kit::button(
                    ui,
                    self.colors,
                    &self.locale.text("extension-session-open"),
                    ButtonRole::Quiet,
                    0.,
                    true,
                )
                .clicked()
                {
                    action = Some(PopupAction::OpenSession);
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
                    action = Some(PopupAction::Discover { after: None });
                }
            });
        });
        action
    }

    fn site_settings(
        &self,
        ui: &mut egui::Ui,
        origin: &str,
        current: SitePolicy,
    ) -> Option<PopupAction> {
        let (saving, toggle) = match current {
            SitePolicy::Allow => (
                Some(("extension-save-never", SitePolicy::NoSave)),
                ("extension-site-disable", SitePolicy::Disabled),
            ),
            SitePolicy::NoSave => (
                Some(("extension-saving-enable", SitePolicy::Allow)),
                ("extension-site-disable", SitePolicy::Disabled),
            ),
            SitePolicy::Disabled => (None, ("extension-site-enable", SitePolicy::Allow)),
        };
        let mut change = None;
        ui.horizontal_wrapped(|ui| {
            for (label, policy) in saving.into_iter().chain([toggle]) {
                if ui.button(self.locale.text(label)).clicked() {
                    change = Some(PopupAction::SetPolicy {
                        origin: origin.to_owned(),
                        policy,
                    });
                }
            }
        });
        change
    }
}

fn show_choices(
    ui: &mut egui::Ui,
    locale: &Localizer,
    colors: Palette,
    forms: &[Choice],
    matches: &Page,
    form: &mut Option<usize>,
    account: &mut Option<usize>,
) {
    if matches.rows.is_empty() {
        ui.label(locale.text("vault-no-results"));
        return;
    }
    if forms.len() > 1 {
        let label = locale.text("extension-form-choice");
        ui.label(&label);
        for (index, choice) in forms.iter().enumerate() {
            let text = if choice.label.is_empty() {
                format!("{} {}", label, index + 1)
            } else {
                format!("{} · {}", index + 1, choice.label)
            };
            if ui_kit::navigation_item(ui, colors, &text, *form == Some(index)).clicked() {
                *form = Some(index);
            }
        }
        ui.separator();
    }
    for (index, login) in matches.rows.iter().enumerate() {
        let title = if login.title.is_empty() {
            locale.text("vault-untitled")
        } else {
            login.title.clone()
        };
        let text = if login.username.is_empty() {
            title
        } else {
            format!("{}\n{}", title, login.username)
        };
        if ui
            .add(
                egui::Button::new(text)
                    .wrap()
                    .selected(*account == Some(index)),
            )
            .clicked()
        {
            *account = Some(index);
        }
    }
}

impl eframe::App for Popup {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let now = js_sys::Date::now();
        let response = self
            .pending
            .as_ref()
            .and_then(|p| p.reply.borrow_mut().take());
        if let Some(response) = response {
            self.pending = None;
            self.check_at = now + 1500.;
            if matches!(response, PopupReply::PolicyChanged) {
                self.request(ui.ctx(), PopupAction::Discover { after: None });
            }
            if !matches!(response, PopupReply::Live) {
                self.form = None;
                self.account = None;
                if let PopupReply::Site {
                    forms,
                    matches,
                    preferred,
                    ..
                } = &response
                {
                    if forms.len() == 1 {
                        self.form = Some(0);
                        let prefer = preferred
                            .as_ref()
                            .filter(|_| forms[0].target.username.is_none());
                        self.account = if matches.rows.len() == 1 {
                            Some(0)
                        } else {
                            prefer.and_then(|target| {
                                matches.rows.iter().position(|row| &row.target == target)
                            })
                        };
                    }
                }
                self.state = response;
            }
        }
        let mut action = None;
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                action = self.show(ui);
            });
        });
        if self.pending.is_none()
            && action.is_none()
            && let PopupReply::Site {
                operation, forms, ..
            } = &self.state
        {
            if now >= self.check_at {
                action = Some(if forms.is_empty() {
                    PopupAction::Discover { after: None }
                } else {
                    PopupAction::Check {
                        operation: operation.clone(),
                    }
                });
            } else {
                ui.ctx()
                    .request_repaint_after(Duration::from_millis((self.check_at - now) as u64));
            }
        }
        if let Some(action) = action {
            self.request(ui.ctx(), action);
        }
    }
}
