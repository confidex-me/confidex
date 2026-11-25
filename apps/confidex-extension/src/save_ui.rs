use crate::{
    autofill::{PopupAction, PopupReply},
    autosave::{Offer, OfferKind, SaveAction, SaveReply, SitePolicy},
    popup::request_popup,
    protocol::SyncStatus,
};
use confidex_app::browser_logins::Selection;
use confidex_ui::{
    i18n::Localizer,
    theme::Palette,
    ui_kit::{self, ButtonRole, Metrics},
};
use eframe::egui;
use std::{cell::RefCell, rc::Rc, time::Duration};

type Pending = Rc<RefCell<Option<PopupReply>>>;

#[derive(Default)]
pub struct SavePanel {
    all_tabs: bool,
    offers: Vec<(Offer, f64)>,
    selected: Option<(String, Selection)>,
    pending: Option<Pending>,
    polling: bool,
    refresh_at: f64,
    status: Option<&'static str>,
    saved: Option<SyncStatus>,
}

impl SavePanel {
    pub fn all_tabs() -> Self {
        Self {
            all_tabs: true,
            ..Self::default()
        }
    }

    fn request(&mut self, ctx: &egui::Context, action: PopupAction, polling: bool) {
        let action = match action {
            PopupAction::Save(save) if self.all_tabs => PopupAction::VaultSave(save),
            other => other,
        };
        let reply = Pending::default();
        self.pending = Some(reply.clone());
        self.polling = polling;
        let ctx = ctx.clone();
        wasm_bindgen_futures::spawn_local(async move {
            *reply.borrow_mut() = Some(request_popup(action).await);
            ctx.request_repaint();
        });
    }

    pub fn show(&mut self, ui: &mut egui::Ui, locale: &Localizer, colors: Palette) {
        let now = js_sys::Date::now();
        let reply = self
            .pending
            .as_ref()
            .and_then(|pending| pending.borrow_mut().take());
        if let Some(reply) = reply {
            self.pending = None;
            self.refresh_at = now + 1500.;
            match reply {
                PopupReply::Save(SaveReply::Offers { offers, sync }) => {
                    if self.saved.is_some() {
                        self.saved = Some(sync);
                    }
                    self.offers = offers
                        .into_iter()
                        .map(|offer| {
                            let deadline = now + f64::from(offer.remaining);
                            (offer, deadline)
                        })
                        .collect();
                    if self.selected.as_ref().is_some_and(|(id, target)| {
                        !self.offers.iter().any(|(offer, _)| {
                            &offer.id == id
                                && matches!(&offer.kind, OfferKind::Update(rows)
                                if rows.iter().any(|row| &row.target == target))
                        })
                    }) {
                        self.selected = None;
                    }
                }
                PopupReply::Locked | PopupReply::Save(SaveReply::Locked) => {
                    self.offers.clear();
                    self.selected = None;
                    self.saved = None;
                    self.status = None;
                }
                PopupReply::Save(SaveReply::Saved(sync)) => {
                    self.saved = Some(sync);
                    self.offers.clear();
                    self.refresh_at = now;
                }
                PopupReply::PolicyChanged | PopupReply::Save(SaveReply::Dismissed) => {
                    self.offers.clear();
                    self.refresh_at = now;
                }
                PopupReply::Save(SaveReply::Changed | SaveReply::Duplicate) => {
                    self.offers.clear();
                    self.selected = None;
                    self.status =
                        Some(if matches!(reply, PopupReply::Save(SaveReply::Duplicate)) {
                            "extension-save-duplicate"
                        } else {
                            "extension-save-changed"
                        });
                    self.refresh_at = now;
                }
                _ if !self.polling => {
                    self.status = Some(if matches!(reply, PopupReply::Save(SaveReply::Busy)) {
                        "vault-working"
                    } else {
                        "vault-error-storage"
                    });
                }
                _ => (),
            }
        }
        self.offers.retain(|(_, deadline)| now < *deadline);
        let mut action = None;
        if let Some(message) = self.status {
            ui.label(locale.text(message));
        }
        if let Some(sync) = self.saved {
            ui.label(locale.text("extension-saved-local"));
            let message = match sync {
                SyncStatus::Disabled => "sync-disabled",
                SyncStatus::Pending => "extension-sync-pending",
                SyncStatus::Current => "remove-vault-synced",
                SyncStatus::Offline => "sync-error-network",
                SyncStatus::Failed(error) => crate::ui::error_label(error),
            };
            ui.label(locale.text(message));
        }
        let busy = self.pending.is_some();
        for (offer, _) in &self.offers {
            ui.push_id(&offer.id, |ui| {
                ui.add_enabled_ui(!busy || self.polling, |ui| {
                    if let Some(next) = show_offer(ui, locale, colors, offer, &mut self.selected) {
                        action = Some(next);
                    }
                });
                ui.add_space(Metrics::SM);
                ui.separator();
            });
        }
        // An explicit decision can supersede a quiet status poll.
        if let Some(action) = action {
            self.status = None;
            self.saved = None;
            self.request(ui.ctx(), action, false);
        } else if !busy {
            if now >= self.refresh_at {
                self.request(ui.ctx(), PopupAction::Save(SaveAction::List), true);
            } else {
                ui.ctx()
                    .request_repaint_after(Duration::from_millis((self.refresh_at - now) as u64));
            }
        }
    }
}

fn show_offer(
    ui: &mut egui::Ui,
    locale: &Localizer,
    colors: Palette,
    offer: &Offer,
    selected: &mut Option<(String, Selection)>,
) -> Option<PopupAction> {
    match &offer.kind {
        OfferKind::New { username } => {
            ui.strong(locale.text("extension-save-offer"));
            ui.label(&offer.origin);
            if !username.is_empty() {
                ui.label(username);
            }
            if ui_kit::button(
                ui,
                colors,
                &locale.text("vault-save"),
                ButtonRole::Primary,
                0.,
                true,
            )
            .clicked()
            {
                return Some(PopupAction::Save(SaveAction::Confirm {
                    id: offer.id.clone(),
                    target: None,
                }));
            }
        }
        OfferKind::Update(rows) => {
            ui.strong(locale.text("extension-update-offer"));
            ui.label(&offer.origin);
            for row in rows {
                let title = if row.title.is_empty() {
                    locale.text("vault-untitled")
                } else {
                    row.title.clone()
                };
                let label = if row.username.is_empty() {
                    title
                } else {
                    format!("{title}\n{}", row.username)
                };
                let current = selected
                    .as_ref()
                    .is_some_and(|(id, target)| id == &offer.id && target == &row.target);
                if ui
                    .add(egui::Button::new(label).wrap().selected(current))
                    .clicked()
                {
                    *selected = Some((offer.id.clone(), row.target.clone()));
                }
            }
            let target = selected
                .as_ref()
                .filter(|(id, _)| id == &offer.id)
                .map(|(_, target)| target);
            if ui_kit::button(
                ui,
                colors,
                &locale.text("extension-update-password"),
                ButtonRole::Primary,
                0.,
                target.is_some(),
            )
            .clicked()
            {
                return Some(PopupAction::Save(SaveAction::Confirm {
                    id: offer.id.clone(),
                    target: target.cloned(),
                }));
            }
        }
        OfferKind::Blocked(issues) => {
            ui.label(&offer.origin);
            if issues.conflicts {
                ui.colored_label(colors.error, locale.text("extension-login-conflicts"));
            }
            if issues.ambiguous {
                ui.colored_label(colors.error, locale.text("extension-login-ambiguous"));
            }
        }
    }
    ui.horizontal_wrapped(|ui| {
        if ui.button(locale.text("extension-save-dismiss")).clicked() {
            Some(PopupAction::Save(SaveAction::Dismiss {
                id: offer.id.clone(),
            }))
        } else {
            ui.menu_button(locale.text("extension-offer-more"), |ui| {
                if !ui.button(locale.text("extension-save-never")).clicked() {
                    return None;
                }
                ui.close();
                Some(PopupAction::SetPolicy {
                    origin: offer.origin.clone(),
                    policy: SitePolicy::NoSave,
                })
            })
            .inner
            .flatten()
        }
    })
    .inner
}
