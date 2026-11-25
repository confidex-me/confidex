use crate::{
    autofill::{PopupAction, PopupReply, PopupRequest},
    autosave::SitePolicy,
    protocol::{MAX_RESPONSE, SyncStatus},
    save_ui::SavePanel,
};
use confidex_app::browser_logins::{Page, Selection};
use confidex_extension_content::Choice;
use confidex_ui::{
    i18n::Localizer,
    theme::Palette,
    ui_kit::{self, Metrics},
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

struct Pending {
    reply: Rc<RefCell<Option<PopupReply>>>,
    quiet: bool,
}

pub(crate) struct Popup {
    locale: Rc<Localizer>,
    colors: Palette,
    state: PopupReply,
    pending: Option<Pending>,
    form: Option<usize>,
    check_at: f64,
    saves: SavePanel,
}

impl Popup {
    pub(crate) fn new(
        ctx: &egui::Context,
        locale: Rc<Localizer>,
        colors: Palette,
        initial: PopupAction,
    ) -> Self {
        let mut popup = Self {
            locale,
            colors,
            state: PopupReply::Locked,
            pending: None,
            form: None,
            check_at: 0.,
            saves: SavePanel::default(),
        };
        popup.request(ctx, initial);
        popup
    }

    fn request(&mut self, ctx: &egui::Context, action: PopupAction) {
        let reply_slot = Rc::new(RefCell::new(None));
        self.pending = Some(Pending {
            quiet: matches!(
                action,
                PopupAction::Discover {
                    previous: Some(_),
                    ..
                }
            ),
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
                let clicked = ui
                    .add_enabled_ui(!busy, |ui| {
                        show_choices(
                            ui,
                            &self.locale,
                            self.colors,
                            forms,
                            matches,
                            &mut self.form,
                        )
                    })
                    .inner;
                if let Some((form, target)) = clicked {
                    return Some(PopupAction::Fill {
                        operation: operation.clone(),
                        form,
                        target,
                    });
                }
                if forms.is_empty() {
                    ui_kit::muted(ui, self.colors, self.locale.text("extension-no-form"));
                }
                if let Some(after) = &matches.next
                    && ui
                        .add_enabled(!busy, egui::Button::new(self.locale.text("vault-more")))
                        .clicked()
                {
                    return Some(PopupAction::Discover {
                        after: Some(after.clone()),
                        previous: None,
                    });
                }
            }
            PopupReply::SiteDisabled { origin } => {
                ui.label(origin);
                ui.label(self.locale.text("extension-site-disabled"));
            }
            state => {
                let key = match state {
                    PopupReply::Locked | PopupReply::Live => "vault-error-locked",
                    PopupReply::Unavailable => "extension-no-form",
                    PopupReply::Changed => "vault-working",
                    PopupReply::Busy | PopupReply::PolicyChanged => "vault-working",
                    PopupReply::Error => "extension-load-error",
                    PopupReply::Filled => "extension-filled",
                    PopupReply::CurrentSite { .. }
                    | PopupReply::Save(_)
                    | PopupReply::Site { .. }
                    | PopupReply::SiteDisabled { .. } => unreachable!(),
                };
                if !busy {
                    ui.label(self.locale.text(key));
                }
            }
        }
        if !busy
            && matches!(self.state, PopupReply::Error)
            && ui.button(self.locale.text("extension-retry")).clicked()
        {
            return Some(PopupAction::Discover {
                after: None,
                previous: None,
            });
        }
        None
    }

    fn site_settings(
        &self,
        ui: &mut egui::Ui,
        origin: &str,
        current: SitePolicy,
    ) -> Option<PopupAction> {
        let (saving, toggle) = match current {
            SitePolicy::Allow => (None, ("extension-site-disable", SitePolicy::Disabled)),
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
) -> Option<(u32, Selection)> {
    if matches.rows.is_empty() {
        ui.label(locale.text("vault-no-results"));
        return None;
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
    ui.add_space(Metrics::SM);
    ui.strong(locale.text("extension-saved-logins"));
    let selected_form = form.and_then(|index| forms.get(index));
    for login in &matches.rows {
        let title = if login.title.is_empty() {
            locale.text("vault-untitled")
        } else {
            login.title.clone()
        };
        let eligible = selected_form
            .filter(|choice| choice.target.password.is_some() || !login.username.is_empty());
        let row = egui::Frame::new()
            .fill(colors.surface)
            .stroke(egui::Stroke::new(1., colors.border))
            .corner_radius(Metrics::FIELD_RADIUS)
            .show(ui, |ui| {
                ui_kit::record_row(
                    ui,
                    colors,
                    &title,
                    &login.username,
                    false,
                    eligible.is_some(),
                )
            })
            .inner;
        if row.clicked()
            && let Some(choice) = eligible
        {
            return Some((choice.target.form, login.target.clone()));
        }
    }
    None
}

impl Popup {
    pub(crate) fn panel(&mut self, ui: &mut egui::Ui, settings: bool) {
        let now = js_sys::Date::now();
        let response = self
            .pending
            .as_ref()
            .and_then(|p| p.reply.borrow_mut().take());
        if let Some(mut response) = response {
            let quiet = self.pending.as_ref().is_some_and(|pending| pending.quiet);
            self.pending = None;
            self.check_at = now + 1500.;
            if matches!(response, PopupReply::PolicyChanged) {
                self.request(ui.ctx(), PopupAction::CurrentSite);
            }
            if !matches!(response, PopupReply::Live)
                && !(quiet && matches!(response, PopupReply::Busy))
            {
                self.form = None;
                if let PopupReply::Site {
                    forms,
                    matches,
                    preferred,
                    ..
                } = &mut response
                    && let [choice] = forms.as_slice()
                {
                    self.form = Some(0);
                    if choice.target.username.is_none()
                        && let Some(index) = matches
                            .rows
                            .iter()
                            .position(|row| preferred.as_ref() == Some(&row.target))
                    {
                        matches.rows[..=index].rotate_right(1);
                    }
                }
                self.state = response;
            }
        }
        if settings {
            if let PopupReply::CurrentSite { origin, policy } = &self.state {
                ui.add_space(Metrics::MD);
                ui.separator();
                ui.heading(self.locale.text("extension-current-site"));
                ui.label(origin);
                if let Some(action) = ui
                    .add_enabled_ui(self.pending.is_none(), |ui| {
                        self.site_settings(ui, origin, *policy)
                    })
                    .inner
                {
                    self.request(ui.ctx(), action);
                }
            } else if matches!(self.state, PopupReply::Error) {
                ui.label(self.locale.text("extension-load-error"));
                if ui
                    .add_enabled(
                        self.pending.is_none(),
                        egui::Button::new(self.locale.text("extension-retry")),
                    )
                    .clicked()
                {
                    self.request(ui.ctx(), PopupAction::CurrentSite);
                }
            }
            return;
        }
        let mut action = self.show(ui);
        if self.pending.is_none()
            && action.is_none()
            && matches!(
                self.state,
                PopupReply::Site { .. } | PopupReply::Changed | PopupReply::Busy
            )
        {
            if now >= self.check_at {
                let previous = match &self.state {
                    PopupReply::Site { operation, .. } => Some(operation.clone()),
                    _ => None,
                };
                action = Some(PopupAction::Discover {
                    after: None,
                    previous,
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
