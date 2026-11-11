use super::*;

const AUTO_LOCK_MINUTES: [u16; 4] = [5, 10, 15, 60];

#[derive(Default)]
pub(super) struct AutoLock {
    minutes: BTreeMap<VaultId, u16>,
    pub last_activity: Option<(VaultId, u64)>,
}

#[derive(Default)]
pub(super) struct DeviceUnlockForm {
    enabling: bool,
    pub pending: bool,
    pub password: String,
    pub error: Option<Error>,
}

impl Drop for DeviceUnlockForm {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

fn user_activity(ctx: &egui::Context) -> bool {
    ctx.input(|input| {
        input.events.iter().any(|event| {
            matches!(
                event,
                egui::Event::Key { .. }
                    | egui::Event::Text(_)
                    | egui::Event::Paste(_)
                    | egui::Event::Cut
                    | egui::Event::PointerMoved(_)
                    | egui::Event::PointerButton { .. }
                    | egui::Event::MouseWheel { .. }
                    | egui::Event::Touch { .. }
                    | egui::Event::Ime(_)
            )
        })
    })
}

impl VaultApp {
    pub fn restore_auto_lock_settings(&mut self, storage: Option<&dyn eframe::Storage>) {
        if let Some(entries) = storage.and_then(|storage| {
            eframe::get_value::<BTreeMap<VaultId, u16>>(storage, "vault-auto-lock-minutes")
        }) {
            self.auto_lock.minutes = entries
                .into_iter()
                .filter(|(_, minutes)| AUTO_LOCK_MINUTES.contains(minutes))
                .collect();
        }
    }

    pub(super) fn save_auto_lock_settings(&self, storage: &mut dyn eframe::Storage) {
        if !self.auto_lock.minutes.is_empty() {
            eframe::set_value(storage, "vault-auto-lock-minutes", &self.auto_lock.minutes);
        }
    }

    fn auto_lock_minutes(&self, vault: VaultId) -> u16 {
        self.auto_lock.minutes.get(&vault).copied().unwrap_or(5)
    }

    pub(super) fn record_auto_lock_activity(&mut self, ctx: &egui::Context, now: u64) {
        if user_activity(ctx)
            && let Some(vault) = &self.active
        {
            self.auto_lock.last_activity = Some((vault.id, now));
        }
    }

    pub(super) fn tick_auto_lock(&mut self, ctx: &egui::Context, now: u64) {
        let unlocked = matches!(
            self.screen,
            Screen::Open | Screen::Conflicts | Screen::Backup
        ) || self.screen == Screen::Key && self.auto_lock.last_activity.is_some();
        if !unlocked {
            self.auto_lock.last_activity = None;
            return;
        }
        let Some(vault) = self.active.as_ref().map(|vault| vault.id) else {
            return;
        };
        let timeout = u64::from(self.auto_lock_minutes(vault)) * 60_000;
        let (previous, last) = self.auto_lock.last_activity.get_or_insert((vault, now));
        if *previous != vault {
            (*previous, *last) = (vault, now);
        }
        // A clock rollback must not extend an unlocked session.
        let elapsed = now.checked_sub(*last).unwrap_or(timeout);
        if elapsed >= timeout && !self.editing && !self.has_unsaved_changes() {
            self.preferences.close(ctx);
            self.screen = Screen::Locking;
            self.request(Command::Lock, true);
            return;
        }
        self.record_auto_lock_activity(ctx, now);
        ctx.request_repaint_after(Duration::from_millis(
            timeout.saturating_sub(elapsed).max(1000),
        ));
    }

    pub(super) fn vault_security_settings(&mut self, ui: &mut egui::Ui, vault: VaultId) {
        let p = THEMES[self.theme].colors;
        form::group(ui, p, "", |group| {
            group.row(
                form::Row {
                    title: &self.locale.text("settings-auto-lock"),
                    description: &self.locale.text("settings-auto-lock-hint"),
                    control_width: 160.,
                },
                |ui, label| {
                    let mut minutes = self.auto_lock_minutes(vault);
                    let duration = |minutes: u16| {
                        let mut args = fluent_bundle::FluentArgs::new();
                        args.set("value", minutes);
                        self.locale.format("settings-device-unlock-minutes", &args)
                    };
                    let response = design::Select::from_id_salt(("auto-lock", vault))
                        .selected_text(duration(minutes))
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            for option in AUTO_LOCK_MINUTES {
                                let response =
                                    ui.selectable_value(&mut minutes, option, duration(option));
                                if ui.clip_rect().contains(response.rect.center()) {
                                    self.hits
                                        .insert(format!("auto-lock-{option}"), response.rect);
                                }
                            }
                        })
                        .response
                        .labelled_by(label);
                    self.hits.insert("auto-lock".into(), response.rect);
                    if minutes != self.auto_lock_minutes(vault) {
                        self.auto_lock.minutes.insert(vault, minutes);
                        self.defaults_changed = true;
                    }
                },
            );
        });
        let Some(label) = self.runtime.device_unlock_label() else {
            return;
        };
        ui.add_space(Metrics::MD);
        let enabled = self.device_unlock_verified_at.is_some();
        let mut selected = enabled || self.device_unlock_form.enabling;
        let response = ui
            .add_enabled_ui(!self.busy && !self.editing, |ui| {
                design::checkbox(ui, &mut selected, self.locale.text(label))
            })
            .inner;
        self.hits
            .insert("vault-device-unlock".into(), response.rect);
        if response.changed() {
            self.device_unlock_form = Default::default();
            if selected {
                self.device_unlock_form.enabling = true;
            } else if enabled {
                self.set_device_unlock(false);
            }
        }
        if self.device_unlock_form.enabling {
            ui.add_space(Metrics::SM);
            ui.label(self.locale.text("vault-password"));
            let response = design::field_with_id(
                ui,
                egui::Id::unique("device-unlock-password"),
                &mut self.device_unlock_form.password,
                true,
                false,
                !self.busy,
            );
            self.hits
                .insert("device-unlock-password".into(), response.rect);
            ui.horizontal_wrapped(|ui| {
                if self.button(
                    ui,
                    "device-unlock-apply",
                    "vault-save",
                    !self.busy && !self.device_unlock_form.password.is_empty(),
                ) {
                    self.set_device_unlock(true);
                }
                if self.button(ui, "device-unlock-cancel", "vault-cancel", !self.busy) {
                    self.device_unlock_form = Default::default();
                }
            });
        }
        if let Some(error) = self.device_unlock_form.error {
            ui.colored_label(
                p.error,
                self.locale.text(if error == Error::Credentials {
                    "settings-device-unlock-error"
                } else {
                    error_key(error)
                }),
            );
        }
    }

    fn set_device_unlock(&mut self, enabled: bool) {
        let Some(vault) = self.active.as_ref().map(|vault| vault.id) else {
            return;
        };
        self.device_unlock_form.pending = true;
        self.device_unlock_form.error = None;
        let password = std::mem::take(&mut self.device_unlock_form.password);
        self.request(
            Command::SetDeviceUnlock {
                vault,
                enabled,
                password,
            },
            false,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone, Default)]
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
    fn opened(ctx: &egui::Context, host: Host) -> VaultApp {
        let mut app = VaultApp::new(ctx, Box::new(host)).unwrap();
        app.screen = Screen::Open;
        app.active = Some(VaultInfo {
            id: [1; 16],
            name: "Public vault A".into(),
        });
        app.busy = false;
        app
    }

    #[test]
    fn auto_lock_uses_each_vaults_timeout_and_clears_the_session() {
        let ctx = egui::Context::default();
        let host = Host::default();
        let mut app = opened(&ctx, host.clone());
        let start = 1_000_000;
        app.auto_lock.minutes.insert([1; 16], 5);
        app.auto_lock.minutes.insert([2; 16], 60);
        app.tick_auto_lock(&ctx, start);
        app.tick_auto_lock(&ctx, start + 299_000);
        assert!(app.screen == Screen::Open);
        app.active.as_mut().unwrap().id = [2; 16];
        app.tick_auto_lock(&ctx, start + 300_000);
        app.tick_auto_lock(&ctx, start + 600_000);
        assert!(app.screen == Screen::Open);
        let generation = app.generation;
        app.tick_auto_lock(&ctx, start + 3_900_000);
        assert!(app.screen == Screen::Locking);
        assert!(app.generation > generation);
        assert!(app.draft.is_none() && app.auto_lock.last_activity.is_none());
        assert!(matches!(
            host.0.borrow().last().unwrap().command,
            Command::Lock
        ));
    }

    #[test]
    fn auto_lock_waits_for_editing_and_only_user_input_resets_the_timer() {
        let ctx = egui::Context::default();
        let mut app = opened(&ctx, Host::default());
        let start = 1_000_000;
        app.tick_auto_lock(&ctx, start);
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.tick_auto_lock(ui.ctx(), start + 100_000);
        });
        output.drop_without_applying_deltas();
        assert_eq!(app.auto_lock.last_activity.unwrap().1, start);
        let output = ctx.run_ui(
            egui::RawInput {
                events: vec![egui::Event::Text("Public activity".into())],
                ..Default::default()
            },
            |ui| app.tick_auto_lock(ui.ctx(), start + 200_000),
        );
        output.drop_without_applying_deltas();
        assert_eq!(app.auto_lock.last_activity.unwrap().1, start + 200_000);
        app.editing = true;
        app.draft = Some(app::new_record().unwrap());
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.tick_auto_lock(ui.ctx(), start + 500_000);
        });
        output.drop_without_applying_deltas();
        assert!(app.screen == Screen::Open && app.draft.is_some());
        app.editing = false;
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.tick_auto_lock(ui.ctx(), start + 501_000);
        });
        output.drop_without_applying_deltas();
        assert!(app.screen == Screen::Locking && app.draft.is_none());
    }

    #[test]
    fn auto_lock_settings_survive_restart_and_ignore_invalid_values() {
        #[derive(Default)]
        struct Storage(BTreeMap<String, String>);
        impl eframe::Storage for Storage {
            fn get_string(&self, key: &str) -> Option<String> {
                self.0.get(key).cloned()
            }
            fn set_string(&mut self, key: &str, value: String) {
                self.0.insert(key.into(), value);
            }
            fn remove_string(&mut self, key: &str) {
                self.0.remove(key);
            }
            fn flush(&mut self) {}
        }
        let ctx = egui::Context::default();
        let mut app = opened(&ctx, Host::default());
        app.auto_lock.minutes.insert([1; 16], 15);
        app.auto_lock.minutes.insert([2; 16], 60);
        app.auto_lock.minutes.insert([3; 16], 0);
        let mut storage = Storage::default();
        app.save_auto_lock_settings(&mut storage);
        let mut restored = opened(&ctx, Host::default());
        restored.restore_auto_lock_settings(Some(&storage));
        assert_eq!(restored.auto_lock_minutes([1; 16]), 15);
        assert_eq!(restored.auto_lock_minutes([2; 16]), 60);
        assert_eq!(restored.auto_lock_minutes([3; 16]), 5);
        assert_eq!(restored.auto_lock_minutes([4; 16]), 5);
    }

    #[test]
    fn clock_rollback_locks_but_a_new_vault_key_can_be_saved_first() {
        let ctx = egui::Context::default();
        let mut app = opened(&ctx, Host::default());
        app.tick_auto_lock(&ctx, 1_000_000);
        app.screen = Screen::Key;
        app.tick_auto_lock(&ctx, 999_999);
        assert!(app.screen == Screen::Locking);
        app.screen = Screen::Key;
        app.auto_lock.last_activity = None;
        app.tick_auto_lock(&ctx, 2_000_000);
        assert!(app.screen == Screen::Key);
    }
}
