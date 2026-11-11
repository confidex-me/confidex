use crate::{
    clipboard::Clipboard,
    i18n::Localizer,
    theme::THEMES,
    ui_kit::{
        self as design, ButtonRole, Icon, Metrics, dialog, fonts::Weight, large_type, layout,
        record, settings as form, value, window,
    },
};
use confidex_app::{self as app, Command, Draft, Error, Output, Request, Response};
use confidex_storage::{RecordId, VaultId, VaultInfo};
use confidex_vault::transfer_code;
use eframe::egui::{self, RichText, Vec2};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use web_time::Instant;
use zeroize::Zeroize;
mod attachments;
mod backup;
mod card;
mod dates;
mod exit;
mod exporter;
mod file_drop;
mod folder;
mod history;
mod importer;
mod locations;
mod passwords;
mod record_fields;
mod removal;
mod rename;
mod security;
mod ssh;
mod tags;
mod templates;
mod totp;
mod trash;
mod validation;
mod wifi;
pub use backup::{BackupFileCompletion, BackupFileReply, BackupFileRequest};
pub use folder::{FolderFileCompletion, FolderFileReply};
pub use importer::{ImportFile, ImportFileCompletion, ImportFileReply};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFileReply {
    Saved,
    DownloadStarted,
    Canceled,
    Failed,
}
pub type ExportFileCompletion = Box<dyn FnOnce(ExportFileReply) + Send>;

pub trait Runtime {
    fn folder_available(&self) -> bool {
        false
    }
    fn cancel_folder(&mut self) {}
    fn pick_folder(&mut self, done: FolderFileCompletion) {
        done(FolderFileReply::Failed);
    }
    fn cancel_import(&mut self, _operation: u32) {}
    fn cancel_export(&mut self, _operation: u32) {}
    fn save_export(&mut self, transfer: app::export_flow::Transfer, done: ExportFileCompletion) {
        transfer.cancel();
        done(ExportFileReply::Failed);
    }
    fn set_key_storage_warning(&mut self, _: &str) {}
    fn device_unlock_label(&self) -> Option<&'static str> {
        None
    }
    fn set_device_unlock_minutes(&mut self, _: u16) {}
    fn send(&mut self, request: Request) -> Result<(), Error>;
    fn receive(&mut self) -> Option<Response>;
    fn default_sync_server(&self) -> Option<String> {
        None
    }
    fn sync_available(&self) -> bool {
        self.default_sync_server().is_some()
    }
    fn offline_launch(&self) -> Option<bool> {
        Some(true)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Catalog,
    Create,
    Unlock,
    Key,
    Open,
    Locking,
    Import,
    Conflicts,
    Backup,
}

#[derive(Default)]
struct SyncSchedule {
    due: Option<Instant>,
    focused: Option<bool>,
    failures: u8,
    after_save: bool,
}
impl SyncSchedule {
    fn wait(&mut self, now: Instant, focused: bool, jitter: u64) -> Duration {
        if self.focused == Some(false) && focused {
            self.due = Some(now);
        } else if self.focused == Some(true) && !focused && !self.after_save {
            self.due = None;
        }
        self.focused = Some(focused);
        let seconds =
            ((if focused { 60u64 } else { 300 }) * (1 << self.failures.min(4))).min(900) + jitter;
        let due = self.due.get_or_insert(now + Duration::from_secs(seconds));
        due.saturating_duration_since(now)
    }
    fn finish(&mut self, failed: bool) {
        self.due = None;
        self.after_save = false;
        self.failures = if failed {
            self.failures.saturating_add(1)
        } else {
            0
        };
    }
    fn saved(&mut self) {
        self.due = Some(Instant::now() + Duration::from_secs(2));
        self.after_save = true;
    }
}

pub struct VaultApp {
    context: egui::Context,
    importer: design::importer::State,
    import_files: importer::Files,
    exporter: design::exporter::State,
    export_files: exporter::Files,
    files: backup::Files,
    history: history::State,
    removal: removal::State,
    rename: rename::State,
    runtime: Box<dyn Runtime>,
    generation: u32,
    screen: Screen,
    busy: bool,
    pub locale: Localizer,
    pub theme: usize,
    catalog: Vec<VaultInfo>,
    active: Option<VaultInfo>,
    remembered: bool,
    device_unlock_verified_at: Option<u64>,
    use_device_unlock: bool,
    device_unlock_minutes: u16,
    auto_lock: security::AutoLock,
    device_unlock_form: security::DeviceUnlockForm,
    rows: Vec<app::Summary>,
    trash: Option<trash::View>,
    next: Option<confidex_storage::Head>,
    more: bool,
    loading_more: bool,
    pending_open: Option<confidex_storage::Head>,
    draft: Option<Draft>,
    edit_baseline: Option<Draft>,
    exit: Option<exit::Action>,
    latest_revision: Option<confidex_storage::RevisionId>,
    editing: bool,
    mobile_detail: bool,
    deleting: bool,
    confirm_delete: bool,
    revealed: BTreeSet<(u64, String)>,
    field_ids: Vec<u64>,
    ssh: ssh::State,
    section_ids: Vec<u64>,
    wifi_fields: BTreeMap<u64, design::wifi_qr::State>,
    card_fields: BTreeMap<u64, design::card::State>,
    date_fields: BTreeMap<u64, design::date::Editor>,
    totp_fields: BTreeMap<u64, design::totp::Editor>,
    pending_totp: BTreeSet<u64>,
    totp_times: BTreeMap<u64, (u64, u64)>,
    attachments: attachments::Attachments,
    file_drop: file_drop::State,
    tag_editor: tags::State,
    next_field: u64,
    clipboard: Clipboard,
    pub zoom_factor: f32,
    pub bounds: BTreeMap<String, egui::Rect>,
    created: Option<app::Created>,
    saved_key: bool,
    import_after_create: bool,
    create_sync: bool,
    create_server: String,
    new_vault_sync: bool,
    new_vault_server: String,
    defaults_changed: bool,
    name: String,
    password: String,
    repeated: String,
    key: String,
    search: String,
    listed_search: String,
    listed_tag: Option<String>,
    remember: bool,
    show_password: bool,
    preferences: window::State,
    templates: window::State,
    template_query: String,
    template_selection: usize,
    template_focus: bool,
    preferences_section: usize,
    preferences_vault: Option<VaultInfo>,
    sync_server_draft: String,
    pending_focus: Option<egui::Id>,
    pending_field_focus: Option<(egui::Id, egui::Id)>,
    shortcuts_blocked: bool,
    large_type: large_type::State,
    folder: folder::State,
    sync_after_list: Option<bool>,
    sync_schedule: SyncSchedule,
    passwords: design::password::Evaluator,
    generator_preferences: design::password::GeneratorPreferences,
    sync_automatic: bool,
    syncing: bool,
    sync_server: String,
    sync_enabled: bool,
    sync_report: Option<app::sync::Report>,
    comparison: Option<(RecordId, [Option<Draft>; 2])>,
    sync_choices: BTreeMap<RecordId, bool>,
    resolve_queue: Vec<(RecordId, [u8; 32], [u8; 32], bool)>,
    error: Option<Error>,
    pub hits: BTreeMap<String, egui::Rect>,
}

impl VaultApp {
    pub fn password_evaluator(&mut self) -> &mut design::password::Evaluator {
        &mut self.passwords
    }

    pub fn new(ctx: &egui::Context, runtime: Box<dyn Runtime>) -> Result<Self, String> {
        let locale = Localizer::new(0)?;
        THEMES[0].apply(ctx);
        design::setup(ctx);
        let sync_server = runtime.default_sync_server().unwrap_or_default();
        let create_sync = runtime.sync_available();
        let mut app = Self {
            context: ctx.clone(),
            importer: design::importer::State::default(),
            import_files: importer::Files::default(),
            exporter: design::exporter::State::default(),
            export_files: exporter::Files::default(),
            files: backup::Files::default(),
            history: history::State::default(),
            removal: removal::State::default(),
            rename: rename::State::default(),
            runtime,
            generation: 0,
            screen: Screen::Catalog,
            busy: false,
            locale,
            theme: 0,
            catalog: vec![],
            active: None,
            remembered: false,
            device_unlock_verified_at: None,
            use_device_unlock: false,
            device_unlock_minutes: app::device_unlock::DEFAULT_MINUTES,
            auto_lock: Default::default(),
            device_unlock_form: Default::default(),
            rows: vec![],
            trash: None,
            next: None,
            more: false,
            loading_more: false,
            pending_open: None,
            draft: None,
            edit_baseline: None,
            exit: None,
            latest_revision: None,
            editing: false,
            mobile_detail: false,
            deleting: false,
            confirm_delete: false,
            revealed: BTreeSet::new(),
            field_ids: vec![],
            ssh: Default::default(),
            section_ids: vec![],
            wifi_fields: BTreeMap::new(),
            card_fields: BTreeMap::new(),
            date_fields: BTreeMap::new(),
            totp_fields: BTreeMap::new(),
            pending_totp: BTreeSet::new(),
            totp_times: BTreeMap::new(),
            attachments: Default::default(),
            file_drop: Default::default(),
            tag_editor: Default::default(),
            next_field: 0,
            clipboard: Clipboard::default(),
            zoom_factor: 1.,
            bounds: BTreeMap::new(),
            created: None,
            saved_key: false,
            import_after_create: false,
            create_sync,
            create_server: sync_server.clone(),
            new_vault_sync: true,
            new_vault_server: sync_server.clone(),
            defaults_changed: false,
            name: String::new(),
            password: String::new(),
            repeated: String::new(),
            key: String::new(),
            search: String::new(),
            listed_search: String::new(),
            listed_tag: None,
            remember: true,
            show_password: false,
            preferences: window::State::default(),
            templates: window::State::default(),
            template_query: String::new(),
            template_selection: 0,
            template_focus: false,
            preferences_section: 0,
            preferences_vault: None,
            sync_server_draft: String::new(),
            pending_focus: None,
            pending_field_focus: None,
            shortcuts_blocked: false,
            large_type: large_type::State::default(),
            folder: folder::State::default(),
            sync_after_list: None,
            sync_schedule: SyncSchedule::default(),
            passwords: design::password::Evaluator::default(),
            generator_preferences: Default::default(),
            sync_automatic: false,
            syncing: false,
            sync_server,
            sync_enabled: false,
            sync_report: None,
            comparison: None,
            sync_choices: BTreeMap::new(),
            resolve_queue: vec![],
            error: None,
            hits: BTreeMap::new(),
        };
        app.request(Command::Catalog, true);
        Ok(app)
    }
    pub fn restore_sync_defaults(&mut self, storage: Option<&dyn eframe::Storage>) {
        if let Some(storage) = storage {
            self.new_vault_sync =
                storage.get_string("new-vault-sync-enabled").as_deref() != Some("false");
            if let Some(server) = storage.get_string("new-vault-sync-server")
                && let Ok(server) = app::sync::server_url(&server)
            {
                self.new_vault_server = server;
            }
        }
    }
    pub fn restore_device_unlock_settings(&mut self, storage: Option<&dyn eframe::Storage>) {
        if let Some(minutes) = storage
            .and_then(|storage| storage.get_string("device-unlock-minutes"))
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|minutes| app::device_unlock::MINUTE_OPTIONS.contains(minutes))
        {
            self.device_unlock_minutes = minutes;
        }
        self.runtime
            .set_device_unlock_minutes(self.device_unlock_minutes);
    }
    fn clear_private(&mut self) {
        self.auto_lock.last_activity = None;
        self.device_unlock_form = Default::default();
        self.runtime.cancel_folder();
        self.folder = folder::State::default();
        self.file_drop = file_drop::State::default();
        egui::Popup::close_all(&self.context);
        design::password::finish(&self.context);
        self.runtime.cancel_import(self.importer.operation);
        self.importer.clear();
        self.importer.window.clear();
        self.import_files.clear();
        self.runtime.cancel_export(self.exporter.operation);
        self.export_files.clear();
        self.exporter.clear();
        self.removal.clear();
        self.rename = rename::State::default();
        self.preferences_vault = None;
        self.files.clear();
        self.history = history::State::default();
        self.large_type.clear();
        self.sync_report = None;
        self.comparison = None;
        self.sync_choices.clear();
        self.resolve_queue.clear();
        self.sync_enabled = false;
        self.sync_after_list = None;
        self.sync_schedule = SyncSchedule::default();
        self.syncing = false;
        self.sync_automatic = false;
        self.rows.clear();
        self.trash = None;
        self.draft = None;
        self.edit_baseline = None;
        self.exit = None;
        self.tag_editor.clear();
        self.latest_revision = None;
        self.created = None;
        self.import_after_create = false;
        self.create_sync = false;
        self.create_server.clear();
        self.pending_open = None;
        self.clear_credentials();
        self.search.zeroize();
        self.listed_search.zeroize();
        if let Some(mut tag) = self.listed_tag.take() {
            tag.zeroize();
        }
        self.revealed.clear();
        self.field_ids.clear();
        self.ssh.clear();
        self.section_ids.clear();
        self.wifi_fields.clear();
        self.card_fields.clear();
        self.totp_fields.clear();
        self.pending_totp.clear();
        self.date_fields.clear();
        self.totp_times.clear();
        self.attachments.clear();
        self.attachments.checking = false;
        self.clipboard.clear();
        self.editing = false;
        self.mobile_detail = false;
        self.confirm_delete = false;
        self.preferences.clear();
        self.templates.clear();
        self.template_query.zeroize();
        self.sync_server_draft.clear();
        self.pending_focus = None;
        self.pending_field_focus = None;
        self.next = None;
        self.more = false;
        self.deleting = false;
        self.loading_more = false;
    }
    fn clear_credentials(&mut self) {
        self.passwords.clear();
        self.password.zeroize();
        self.repeated.zeroize();
        self.key.zeroize();
        self.show_password = false;
        self.use_device_unlock = false;
    }
    fn can_use_device_unlock(&self) -> bool {
        self.remembered
            && self.device_unlock_verified_at.is_some_and(|verified_at| {
                app::device_unlock::password_is_current(
                    verified_at,
                    epoch(),
                    self.device_unlock_minutes,
                )
            })
    }
    fn credentials_error(&self) -> Option<(&'static str, &'static str)> {
        if matches!(self.screen, Screen::Create | Screen::Import) {
            if self.name.trim().is_empty() {
                return Some(("name", "vault-error-name-empty"));
            }
            if self.name.len() > 128 {
                return Some(("name", "vault-error-name-long"));
            }
        }
        if self.password.is_empty()
            && !(self.screen == Screen::Unlock && self.can_use_device_unlock())
        {
            return Some(("password", "vault-error-password-empty"));
        }
        if self.password.len() > 4096 {
            return Some(("password", "vault-error-password-long"));
        }
        if self.screen == Screen::Create && self.password != self.repeated {
            return Some(("repeat", "vault-error-repeat"));
        }
        if (self.screen == Screen::Import || !self.remembered && self.screen == Screen::Unlock)
            && self.key.trim().is_empty()
        {
            return Some(("secret-key", "vault-error-key"));
        }
        if self.screen == Screen::Create
            && self.create_sync
            && self.runtime.sync_available()
            && app::sync::server_url(&self.create_server).is_err()
        {
            return Some(("sync-server", "vault-error-server"));
        }
        if self.screen == Screen::Import
            && !self.files.importing
            && self.folder.import_path.is_none()
            && self.sync_server.trim().is_empty()
        {
            return Some(("sync-server", "vault-error-server"));
        }
        None
    }
    fn validate_credentials(&mut self) -> bool {
        if let Some((id, _)) = self.credentials_error() {
            self.error = Some(Error::Input);
            let target = egui::Id::unique(("vault-input", id));
            self.pending_focus = Some(if self.screen == Screen::Create && id == "password" {
                target.with("input")
            } else {
                target
            });
            false
        } else {
            true
        }
    }
    fn request_failed(&mut self, error: Error) {
        if self.device_unlock_form.pending {
            self.device_unlock_form.pending = false;
            self.device_unlock_form.error = Some(error);
            self.device_unlock_form.password.zeroize();
            self.busy = false;
            return;
        }
        self.folder.after_config = false;
        if self.folder.phase == folder::Phase::Http {
            self.folder_http_failed(error);
            return;
        }
        if self.attachments.pending.take().is_some() {
            self.attachments.checking = false;
            self.attachments.busy = false;
            self.attachments.notice = Some(if error == Error::RecordLimit {
                "gallery-image-full"
            } else {
                "gallery-image-processing-error"
            });
            self.busy = false;
            return;
        }
        if self.rename.pending {
            self.rename.pending = false;
            self.rename.error = Some(error);
            self.busy = false;
            return;
        }
        if self.removal.pending {
            self.removal_failed(error);
            return;
        }
        self.syncing = false;
        if self.history.loading {
            self.history.loading = false;
            self.history.error = Some(error);
            self.busy = false;
            return;
        }
        self.files.after_sync = false;
        let quiet = self.sync_automatic
            && matches!(error, Error::Network | Error::Server(408 | 429 | 500..=599));
        if self.sync_automatic {
            self.sync_schedule.finish(true);
        }
        self.sync_automatic = false;
        self.error = if quiet { None } else { Some(error) };
        self.busy = false;
        self.deleting = false;
        self.loading_more = false;
        self.resolve_queue.clear();
        if self.screen == Screen::Locking {
            self.screen = if self.active.is_some() {
                Screen::Unlock
            } else {
                Screen::Catalog
            };
        }
        if self.screen == Screen::Unlock {
            match error {
                Error::Key => {
                    self.remembered = false;
                    self.device_unlock_verified_at = None;
                    self.pending_focus = Some(egui::Id::unique(("vault-input", "secret-key")));
                }
                Error::PasswordRequired => {
                    self.device_unlock_verified_at = Some(0);
                    self.pending_focus = Some(egui::Id::unique(("vault-input", "password")));
                }
                _ => (),
            }
        }
        if matches!(self.screen, Screen::Unlock | Screen::Import) && error == Error::Auth {
            self.pending_focus = Some(egui::Id::unique(("vault-input", "password")));
        }
    }
    fn request(&mut self, command: Command, invalidate: bool) {
        if invalidate {
            self.generation = self
                .generation
                .checked_add(1)
                .expect("session generation exhausted");
            self.clear_private();
        }
        if !matches!(
            command,
            Command::Sync { .. }
                | Command::CheckSync { .. }
                | Command::Folder(app::local_sync::Command::Sync)
        ) && self.folder.phase == folder::Phase::Idle
        {
            self.sync_automatic = false;
        }
        self.syncing |= matches!(
            command,
            Command::Sync { .. }
                | Command::CheckSync { .. }
                | Command::SyncConfig { .. }
                | Command::Folder(app::local_sync::Command::Sync)
        );
        self.error = None;
        #[cfg(target_arch = "wasm32")]
        if matches!(
            command,
            Command::Create { remember: true, .. }
                | Command::Unlock { remember: true, .. }
                | Command::RestoreBackup { remember: true, .. }
                | Command::Import { remember: true, .. }
                | Command::SetDeviceUnlock { enabled: false, .. }
        ) {
            let warning = if matches!(
                command,
                Command::Import {
                    use_device_unlock: Some(false),
                    ..
                } | Command::SetDeviceUnlock { enabled: false, .. }
            ) {
                "vault-remember-browser-unprotected"
            } else {
                "vault-remember-browser-warning"
            };
            self.runtime.set_key_storage_warning(&format!(
                "{}\n\n{}",
                self.locale.text("vault-remember-browser-key"),
                self.locale.text(warning),
            ));
        }
        match self.runtime.send(Request {
            generation: self.generation,
            command,
        }) {
            Ok(()) => self.busy = true,
            Err(error) => self.request_failed(error),
        }
    }
    fn poll(&mut self) {
        self.poll_folder();
        self.poll_attachments();
        self.poll_backup();
        self.poll_import_file();
        self.poll_export_file();
        while let Some(mut response) = self.runtime.receive() {
            if response.generation != self.generation {
                continue;
            }
            response.result = match response.result {
                Ok(Output::Folder(Ok(app::local_sync::Reply::Opened {
                    info,
                    remembered,
                    server,
                }))) => Ok(Output::Opened {
                    info,
                    remembered,
                    server,
                    device_unlock_verified_at: None,
                }),
                other => other,
            };
            if let Ok(Output::Ssh { token, result }) = response.result {
                self.ssh_reply(token, result);
                continue;
            }
            if self.ssh.checking {
                let result = match &response.result {
                    Ok(Output::Checked { .. }) => Some(Ok(())),
                    Err(error) => Some(Err(*error)),
                    _ => None,
                };
                if let Some(result) = result {
                    self.ssh_checked(result);
                    continue;
                }
            }
            if self.attachments.checking {
                self.attachments.checking = false;
                if self.attachments.pending.is_none() {
                    self.busy = false;
                    continue;
                }
            }
            if let Err(error) = response.result
                && self.import_files.pending
            {
                self.import_reply(Err(app::import_flow::Error::App(error)));
                if self.busy {
                    self.request_failed(error);
                }
                continue;
            }
            if let Ok(Output::VendorImport(result)) = response.result {
                self.import_reply(result);
                continue;
            }
            if let Err(error) = response.result
                && self.export_files.pending
            {
                self.export_reply(Err(app::export_flow::Error::App(error)));
                continue;
            }
            if let Ok(Output::VendorExport(result)) = response.result {
                self.export_reply(result);
                continue;
            }
            self.busy = false;
            match response.result {
                Err(error) => self.request_failed(error),
                Ok(output) => match output {
                    Output::Folder(result) => self.folder_reply(result),
                    Output::VendorImport(_) => unreachable!(),
                    Output::VendorExport(_) => unreachable!(),
                    Output::Ssh { .. } => unreachable!(),
                    Output::Checked { compressed } => self.attachment_checked(compressed),
                    Output::Renamed(info) => self.renamed(info, false),
                    Output::RenameConflict(info) => self.renamed(info, true),
                    Output::Removed { vault, result } => self.removed(vault, result),
                    Output::RemovalPrepared { created, report } => {
                        self.removal_prepared(created, report)
                    }
                    Output::BackupReady => {
                        self.folder.import_path = None;
                        self.files.importing = true;
                        self.name = self.locale.text("backup-restored-name");
                        self.screen = Screen::Import;
                        self.remember = true;
                        self.pending_focus = Some(egui::Id::unique(("vault-input", "secret-key")));
                    }
                    Output::Backup(bytes) => {
                        self.files.bytes = Some(bytes);
                        self.screen = Screen::Backup;
                    }
                    Output::Catalog(vaults) => {
                        self.catalog = vaults;
                        self.screen = Screen::Catalog;
                        self.active = None;
                        self.device_unlock_verified_at = None;
                    }
                    Output::Selected {
                        info,
                        remembered,
                        device_unlock_verified_at,
                    } => {
                        self.active = Some(info);
                        self.remembered = remembered;
                        self.device_unlock_verified_at = device_unlock_verified_at;
                        self.use_device_unlock = false;
                        self.remember = true;
                        self.screen = Screen::Unlock;
                        self.pending_focus = (!self.can_use_device_unlock()).then(|| {
                            egui::Id::unique((
                                "vault-input",
                                if remembered { "password" } else { "secret-key" },
                            ))
                        });
                    }
                    Output::Created(created) => {
                        if self.screen != Screen::Open
                            || self
                                .active
                                .as_ref()
                                .is_none_or(|vault| vault.id != created.info.id)
                        {
                            self.device_unlock_verified_at = None;
                        }
                        self.create_sync &= self.screen == Screen::Create;
                        self.clear_credentials();
                        if !self.catalog.iter().any(|v| v.id == created.info.id) {
                            self.catalog.push(created.info.clone());
                        }
                        self.active = Some(created.info.clone());
                        self.remembered = created.remembered;
                        self.created = Some(created);
                        self.saved_key = false;
                        self.screen = Screen::Key;
                    }
                    Output::Opened {
                        info,
                        remembered,
                        server,
                        device_unlock_verified_at,
                    } => {
                        self.clear_credentials();
                        self.folder.import_path = None;
                        self.files.clear();
                        if !self.catalog.iter().any(|v| v.id == info.id) {
                            self.catalog.push(info.clone());
                        }
                        self.active = Some(info);
                        self.remembered = remembered;
                        self.device_unlock_verified_at = device_unlock_verified_at;
                        let automatic = self.screen != Screen::Import;
                        self.screen = Screen::Open;
                        self.sync_enabled = server.is_some();
                        if let Some(server) = server {
                            self.sync_server = server;
                        }
                        if self.runtime.folder_available() {
                            self.folder.loading = Some(automatic);
                            self.request(Command::Folder(app::local_sync::Command::Status), false);
                        } else {
                            self.sync_after_list = self.sync_enabled.then_some(automatic);
                            self.request_list(None);
                        }
                    }
                    Output::DeviceUnlockChanged { verified_at } => {
                        self.device_unlock_verified_at = verified_at;
                        self.remembered = true;
                        self.device_unlock_form = Default::default();
                    }
                    Output::Compared {
                        record,
                        mut local,
                        mut remote,
                    } => {
                        for draft in [&mut local, &mut remote].into_iter().flatten() {
                            localize_legacy_fields(&self.locale, draft);
                        }
                        self.comparison = Some((record, [local, remote]));
                        self.revealed.clear();
                        self.clipboard.clear();
                    }
                    Output::SyncUnchanged => {
                        if !self.finish_http_folder() {
                            self.sync_automatic = false;
                            self.sync_schedule.finish(false);
                        }
                    }
                    Output::Synced(mut report) => {
                        if std::mem::take(&mut self.folder.after_config) {
                            self.sync_enabled = report.server.is_some();
                            if let Some(server) = report.server {
                                self.sync_server = server;
                            }
                            self.start_sync(false);
                            continue;
                        }
                        self.sync_enabled = report.server.is_some();
                        if let Some(server) = &report.server {
                            self.sync_server = server.clone();
                        }
                        if let Some(previous) = &self.sync_report {
                            report.downloaded += previous.downloaded;
                            report.uploaded += previous.uploaded;
                            report.duplicates += previous.duplicates;
                        }
                        let more = report.more;
                        let conflicts = !report.conflicts.is_empty();
                        if (!more || conflicts) && self.folder.phase != folder::Phase::Http {
                            self.sync_automatic = false;
                            self.sync_schedule.finish(false);
                        }
                        self.sync_report = Some(report);
                        if !self.resolve_queue.is_empty() {
                            self.resolve_next();
                        } else if conflicts {
                            self.sync_choices = self
                                .sync_report
                                .as_ref()
                                .unwrap()
                                .conflicts
                                .iter()
                                .filter(|c| c.local.epoch != c.remote.epoch)
                                .map(|c| (c.record, c.local.epoch > c.remote.epoch))
                                .collect();
                            if self.draft.is_none() {
                                self.screen = Screen::Conflicts;
                            } else if let Some(draft) = &self.draft {
                                self.request(
                                    Command::CheckRevision {
                                        record: draft.record,
                                        revision: draft.revision,
                                    },
                                    false,
                                );
                            }
                        } else if more && self.sync_enabled {
                            if let Some(draft) = &self.draft {
                                self.request(
                                    Command::CheckRevision {
                                        record: draft.record,
                                        revision: draft.revision,
                                    },
                                    false,
                                );
                            } else {
                                self.request(
                                    Command::Sync {
                                        server: self.sync_server.clone(),
                                    },
                                    false,
                                );
                            }
                        } else if self.finish_http_folder() {
                            continue;
                        } else if self.files.after_sync {
                            self.files.after_sync = false;
                            self.request(Command::ExportBackup, false);
                        } else {
                            self.screen = Screen::Open;
                            if let Some(draft) = &self.draft {
                                self.request(
                                    Command::CheckRevision {
                                        record: draft.record,
                                        revision: draft.revision,
                                    },
                                    false,
                                );
                            } else {
                                self.request_list(None);
                            }
                        }
                    }
                    Output::Locked => {
                        self.screen = if self.active.is_some() {
                            Screen::Unlock
                        } else {
                            Screen::Catalog
                        };
                        if self.screen == Screen::Unlock && !self.can_use_device_unlock() {
                            self.pending_focus =
                                Some(egui::Id::unique(("vault-input", "password")));
                        }
                    }
                    Output::Indexing => {
                        self.request_list(if self.loading_more {
                            self.next.clone()
                        } else {
                            None
                        });
                    }
                    Output::Rows {
                        mut rows,
                        more,
                        next,
                    } => {
                        if self.loading_more {
                            self.rows.append(&mut rows);
                        } else {
                            self.rows = rows;
                        }
                        self.loading_more = false;
                        self.more = more;
                        self.next = next;
                        if let Some(head) = self.pending_open.take() {
                            self.request(
                                Command::OpenRevision {
                                    record: head.record,
                                    revision: head.revision,
                                },
                                false,
                            );
                        } else if let Some(automatic) = self.sync_after_list.take() {
                            if automatic && !self.sync_configured() {
                                continue;
                            }
                            self.start_sync(automatic);
                        }
                    }
                    Output::TrashPage { rows, next } => {
                        if let Some(view) = &mut self.trash {
                            let empty = rows.is_empty();
                            view.rows.extend(rows);
                            view.next = next.clone();
                            if empty && next.is_some() {
                                self.request_trash(next);
                            }
                        }
                    }
                    Output::Restored => {
                        self.sync_schedule.saved();
                        self.request_list(None);
                    }
                    Output::RecordHead { record, revision } => {
                        if self.draft.as_ref().is_some_and(|d| d.record == record) {
                            self.latest_revision = revision;
                            if self.history.record == Some(record) && self.history.head != revision
                            {
                                self.history.invalidate();
                            }
                        }
                        self.loading_more = false;
                        if self.sync_enabled
                            && self
                                .sync_report
                                .as_ref()
                                .is_some_and(|r| r.more && r.conflicts.is_empty())
                        {
                            self.request(
                                Command::Sync {
                                    server: self.sync_server.clone(),
                                },
                                false,
                            );
                        } else {
                            self.request_list(None);
                        }
                    }
                    Output::History(page) => {
                        if self.history.record == Some(page.record) {
                            if self.history.head != Some(page.head) {
                                self.history.revisions.clear();
                            }
                            self.history.head = Some(page.head);
                            self.history.revisions.extend(page.revisions);
                            self.history.next = page.next;
                            self.history.loading = false;
                            self.history.loaded = true;
                            self.history.error = None;
                        }
                    }
                    Output::Historical {
                        record,
                        revision,
                        epoch,
                        mut draft,
                    } => {
                        if self.history.record == Some(record)
                            && self.history.selected.is_some_and(|(id, _)| id == revision)
                        {
                            if let Some(draft) = &mut draft {
                                localize_legacy_fields(&self.locale, draft);
                            }
                            if self.history.window.open {
                                self.history.preview = draft;
                                self.history.selected = Some((revision, epoch));
                            } else {
                                self.history.selected = None;
                            }
                            self.history.loading = false;
                            self.history.error = None;
                        }
                    }
                    Output::Draft(mut draft) => {
                        self.edit_baseline = None;
                        self.tag_editor.clear();
                        localize_legacy_fields(&self.locale, &mut draft);
                        self.history = history::State::default();
                        self.reset_field_ids(draft.fields.len());
                        self.clipboard.clear();
                        self.latest_revision = draft.revision;
                        self.draft = Some(draft);
                        self.editing = false;
                        self.mobile_detail = true;
                        self.revealed.clear();
                    }
                    Output::Saved(head) => {
                        self.edit_baseline = None;
                        self.sync_schedule.saved();
                        if self.deleting {
                            self.draft = None;
                            self.mobile_detail = false;
                            self.deleting = false;
                        } else {
                            self.pending_open = Some(head);
                        }
                        self.editing = false;
                        self.loading_more = false;
                        self.request_list(None);
                    }
                },
            }
        }
        self.syncing &= self.busy;
    }
    fn schedule_sync(&mut self, ctx: &egui::Context) {
        if self.ssh.active() {
            return;
        }
        if let Some(wait) = self.tick_sync(Instant::now(), ctx.input(|i| i.focused)) {
            ctx.request_repaint_after(wait.max(Duration::from_secs(1)));
        }
    }
    fn tick_sync(&mut self, now: Instant, focused: bool) -> Option<Duration> {
        if self.screen != Screen::Open || !self.sync_configured() {
            return None;
        }
        let jitter = self
            .active
            .as_ref()
            .map(|v| u64::from(v.id[0]) % 11)
            .unwrap_or(0);
        let wait = self.sync_schedule.wait(now, focused, jitter);
        if self.busy
            || self.importer.window.open
            || self.exporter.window.open
            || self.export_files.pending
            || self.import_files.pending
            || self.editing
            || self.confirm_delete
            || self.preferences.open
            || self.templates.open
            || self.history.window.open
            || self.large_type.is_open()
            || self.folder.error.is_some_and(|error| {
                !matches!(
                    error,
                    app::local_sync::Error::Unavailable
                        | app::local_sync::Error::Canceled
                        | app::local_sync::Error::App(
                            Error::Network | Error::Server(408 | 429 | 500..=599)
                        )
                )
            })
            || self.error.is_some_and(|error| {
                !matches!(error, Error::Network | Error::Server(408 | 429 | 500..=599))
            })
        {
            return None;
        }
        if wait.is_zero() {
            self.sync_schedule.due = None;
            self.sync_schedule.after_save = false;
            self.start_sync(true);
        }
        Some(wait)
    }
    fn action(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        message: &str,
        enabled: bool,
        role: ButtonRole,
    ) -> bool {
        let width = if matches!(
            id,
            "submit"
                | "continue"
                | "create"
                | "import-new"
                | "sync-now"
                | "export-key"
                | "backup-export"
                | "sync-conflicts"
                | "import"
                | "backup-import"
                | "folder-open"
                | "backup-save"
                | "backup-sync"
                | "backup-offline"
                | "backup-cancel"
                | "vaults"
        ) || self.screen == Screen::Import && id == "cancel"
            || id.starts_with("photo-")
            || id.starts_with("file-")
            || id.starts_with("ssh-")
            || id == "first-problem"
        {
            ui.available_size_before_wrap().x
        } else {
            0.
        };
        if matches!(
            id,
            "sync-now" | "sync-conflicts" | "backup-export" | "export-key"
        ) {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        }
        let response = design::button(
            ui,
            THEMES[self.theme].colors,
            &self.locale.text(message),
            role,
            width,
            enabled,
        );
        if enabled {
            self.hits.insert(id.into(), response.rect);
        }
        response.clicked()
    }
    fn button(&mut self, ui: &mut egui::Ui, id: &str, message: &str, enabled: bool) -> bool {
        self.action(ui, id, message, enabled, ButtonRole::Secondary)
    }
    fn primary(&mut self, ui: &mut egui::Ui, id: &str, message: &str, enabled: bool) -> bool {
        self.action(ui, id, message, enabled, ButtonRole::Primary)
            || (matches!(
                self.screen,
                Screen::Create | Screen::Unlock | Screen::Key | Screen::Import
            ) && matches!(id, "submit" | "continue")
                && enabled
                && ui.is_enabled()
                && !self.busy
                && !self.preferences.open
                && !egui::Popup::is_any_open(ui.ctx())
                && ui.memory(|memory| memory.focused().is_none())
                && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)))
    }
    fn icon_button(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        label: &str,
        icon: Icon,
        enabled: bool,
    ) -> bool {
        let response = design::icon_button(
            ui,
            THEMES[self.theme].colors,
            &self.locale.text(label),
            icon,
            enabled,
        );
        if enabled {
            self.hits.insert(id.into(), response.rect);
        }
        response.clicked()
    }
    pub fn set_clipboard_handler(
        &mut self,
        handler: impl FnMut(String, crate::CopyCompletion) + 'static,
    ) {
        self.clipboard.set_handler(handler);
    }
    fn reset_field_ids(&mut self, count: usize) {
        self.ssh.clear();
        self.section_ids.clear();
        egui::Popup::close_all(&self.context);
        design::password::finish(&self.context);
        self.wifi_fields.clear();
        self.card_fields.clear();
        self.totp_fields.clear();
        self.pending_totp.clear();
        self.date_fields.clear();
        self.totp_times.clear();
        self.attachments.clear();
        self.field_ids = (self.next_field..self.next_field + count as u64).collect();
        self.next_field += count as u64;
    }
    fn settings_content(&mut self, ui: &mut egui::Ui) -> bool {
        self.record_auto_lock_activity(ui.ctx(), epoch());
        let p = THEMES[self.theme].colors;
        if self.preferences_section == 0 {
            form::group(ui, p, &self.locale.text("settings-appearance"), |group| {
                for (index, (key, hint)) in [
                    ("vault-theme", "settings-theme-hint"),
                    ("vault-scale", "settings-scale-hint"),
                    ("vault-language", "settings-language-hint"),
                ]
                .into_iter()
                .enumerate()
                {
                    let title = self.locale.text(key);
                    group.row(
                        form::Row {
                            title: &title,
                            description: &self.locale.text(hint),
                            control_width: 200.,
                        },
                        |ui, _| match index {
                            0 => self.theme_setting(ui),
                            1 => self.scale_setting(ui),
                            _ => self.language_setting(ui),
                        },
                    );
                }
            });
            if let Some(label) = self.runtime.device_unlock_label() {
                ui.add_space(Metrics::LG);
                form::group(ui, p, &self.locale.text(label), |group| {
                    group.row(
                        form::Row {
                            title: &self.locale.text("settings-device-unlock-delay"),
                            description: "",
                            control_width: 160.,
                        },
                        |ui, label| self.device_unlock_setting(ui, label),
                    );
                });
            }
            if self.runtime.sync_available() {
                ui.add_space(Metrics::LG);
                form::group(ui, p, &self.locale.text("sync-new-vaults"), |group| {
                    let title = self.locale.text("sync-enabled");
                    group.row(
                        form::Row {
                            title: &title,
                            description: &self.locale.text("settings-new-sync-hint"),
                            control_width: Metrics::SWITCH_WIDTH,
                        },
                        |ui, _| {
                            let r = form::switch(ui, p, &mut self.new_vault_sync, &title, true);
                            self.defaults_changed |= r.changed();
                            self.hits.insert("default-sync-enabled".into(), r.rect);
                        },
                    );
                    let title = self.locale.text("sync-server");
                    group.row(
                        form::Row {
                            title: &title,
                            description: &self.locale.text("settings-new-server-hint"),
                            control_width: 360.,
                        },
                        |ui, label| {
                            let r = design::field_with_id(
                                ui,
                                egui::Id::unique("default-sync-server"),
                                &mut self.new_vault_server,
                                false,
                                false,
                                true,
                            )
                            .labelled_by(label);
                            self.defaults_changed |= r.changed();
                            self.hits.insert("default-sync-server".into(), r.rect);
                        },
                    );
                });
                ui.add_space(Metrics::SM);
                design::muted(ui, p, self.locale.text("sync-new-vaults-hint"));
                if app::sync::server_url(&self.new_vault_server).is_err() {
                    ui.colored_label(p.error, self.locale.text("vault-error-server"));
                }
            }
            return false;
        }
        let mut close = false;
        if let Some(target) = self.preferences_vault.clone()
            && (self.screen != Screen::Open
                || self.active.as_ref().is_none_or(|v| v.id != target.id))
        {
            ui.label(RichText::new(&target.name).font(design::fonts::semibold(Metrics::HEADING)));
            if self.button(
                ui,
                "preferences-unlock",
                "vault-unlock",
                !self.busy && !self.editing,
            ) {
                self.request(Command::Select { vault: target.id }, true);
                close = true;
            }
            self.rename_setting(ui, &target);
            self.removal_action(ui, &target);
            return close;
        }
        if self.screen == Screen::Open {
            if let Some(target) = self.active.clone() {
                self.rename_setting(ui, &target);
                ui.add_space(Metrics::LG);
            }
            let button_font = design::fonts::medium(design::density(ui).body);
            let button_width = |message| {
                ui.fonts_mut(|fonts| {
                    fonts
                        .layout_no_wrap(self.locale.text(message), button_font.clone(), p.text)
                        .size()
                        .x
                }) + 2. * ui.spacing().button_padding.x
            };
            let action_width = [
                "sync-now",
                "vault-working",
                "sync-conflicts",
                "backup-export",
                "vault-save-key",
            ]
            .into_iter()
            .map(button_width)
            .fold(200., f32::max);
            let name = self
                .active
                .as_ref()
                .map(|info| info.name.clone())
                .unwrap_or_else(|| self.locale.text("vault-local"));
            let title = format!("{} · {name}", self.locale.text("settings-vault"));
            form::group(ui, p, &title, |group| {
                if self.runtime.sync_available() {
                    let title = self.locale.text("sync-server");
                    group.row(
                        form::Row {
                            title: &title,
                            description: &self.locale.text("settings-sync-server-hint"),
                            control_width: 360.,
                        },
                        |ui, label| {
                            let r = design::field(
                                ui,
                                &mut self.sync_server_draft,
                                false,
                                false,
                                !self.busy && !self.editing,
                            )
                            .labelled_by(label);
                            self.hits.insert("sync-server".into(), r.rect);
                        },
                    );
                    let title = self.locale.text("sync-enabled");
                    let mut enabled = self.sync_enabled;
                    group.row(
                        form::Row {
                            title: &title,
                            description: &self.locale.text("settings-sync-enabled-hint"),
                            control_width: Metrics::SWITCH_WIDTH,
                        },
                        |ui, _| {
                            let r = form::switch(
                                ui,
                                p,
                                &mut enabled,
                                &title,
                                !self.busy && !self.editing,
                            );
                            self.hits.insert("sync-enabled".into(), r.rect);
                        },
                    );
                    if enabled != self.sync_enabled {
                        self.request(
                            Command::SyncConfig {
                                server: enabled.then(|| self.sync_server_draft.clone()),
                            },
                            false,
                        );
                    }
                    let status = self
                        .sync_report
                        .as_ref()
                        .map(|r| {
                            format!("↓ {}  ↑ {}  ≡ {}", r.downloaded, r.uploaded, r.duplicates)
                        })
                        .unwrap_or_else(|| self.locale.text("sync-now"));
                    let action = group.row(
                        form::Row {
                            title: &status,
                            description: &self.locale.text("settings-sync-now-hint"),
                            control_width: action_width,
                        },
                        |ui, _| {
                            if self.button(
                                ui,
                                "sync-now",
                                "sync-now",
                                self.sync_enabled && !self.busy && !self.editing,
                            ) {
                                self.sync_report = None;
                                self.folder.after_config = self.folder.path.is_some();
                                self.request(
                                    Command::SyncConfig {
                                        server: Some(self.sync_server_draft.clone()),
                                    },
                                    false,
                                );
                            }
                        },
                    );
                    self.bounds
                        .insert("preferences-sync-actions".into(), action.row);
                    if self
                        .sync_report
                        .as_ref()
                        .is_some_and(|r| !r.conflicts.is_empty())
                    {
                        let title = self.locale.text("sync-conflicts");
                        group.row(
                            form::Row {
                                title: &title,
                                description: &self.locale.text("settings-sync-conflicts-hint"),
                                control_width: action_width,
                            },
                            |ui, _| {
                                if self.button(
                                    ui,
                                    "sync-conflicts",
                                    "sync-conflicts",
                                    !self.busy && !self.editing,
                                ) {
                                    self.screen = Screen::Conflicts;
                                    close = true;
                                }
                            },
                        );
                    }
                }
                self.folder_setting(group);
                let title = self.locale.text("vault-secret-key");
                let import_title = self.locale.text("import-title");
                group.row(
                    form::Row {
                        title: &import_title,
                        description: &self.locale.text("import-settings-hint"),
                        control_width: action_width,
                    },
                    |ui, _| {
                        if self.import_action(ui) {
                            close = true;
                        }
                    },
                );
                let backup_title = self.locale.text("backup-export");
                let export_title = self.locale.text("export-title");
                group.row(
                    form::Row {
                        title: &export_title,
                        description: &self.locale.text("export-settings-hint"),
                        control_width: action_width,
                    },
                    |ui, _| {
                        if self.export_action(ui) {
                            close = true;
                        }
                    },
                );
                group.row(
                    form::Row {
                        title: &backup_title,
                        description: &self.locale.text("settings-backup-hint"),
                        control_width: action_width,
                    },
                    |ui, _| {
                        if self.button(
                            ui,
                            "backup-export",
                            "backup-export",
                            !self.busy && !self.editing,
                        ) {
                            self.files.clear();
                            self.screen = Screen::Backup;
                            close = true;
                        }
                    },
                );
                group.row(
                    form::Row {
                        title: &title,
                        description: &self.locale.text("settings-secret-key-hint"),
                        control_width: action_width,
                    },
                    |ui, _| {
                        if self.button(
                            ui,
                            "export-key",
                            "vault-save-key",
                            !self.busy && !self.editing,
                        ) {
                            self.request(Command::ExportKey, false);
                            close = true;
                        }
                    },
                );
            });
            if let Some(target) = self.active.clone() {
                ui.add_space(Metrics::LG);
                self.vault_security_settings(ui, target.id);
            }
        }
        if let Some(target) = self.active.clone() {
            self.removal_action(ui, &target);
        }
        close
    }
    fn device_unlock_setting(&mut self, ui: &mut egui::Ui, label: egui::Id) {
        let duration = |minutes: u16| {
            let mut args = fluent_bundle::FluentArgs::new();
            let (message, value) = if minutes < 60 {
                ("settings-device-unlock-minutes", minutes)
            } else {
                ("settings-device-unlock-hours", minutes / 60)
            };
            args.set("value", value);
            self.locale.format(message, &args)
        };
        let mut minutes = self.device_unlock_minutes;
        let response = design::Select::from_id_salt("device-unlock-delay")
            .selected_text(duration(minutes))
            .width(ui.available_width())
            .height(280.)
            .show_ui(ui, |ui| {
                for option in app::device_unlock::MINUTE_OPTIONS {
                    let response = ui.selectable_value(&mut minutes, option, duration(option));
                    if ui.clip_rect().contains(response.rect.center()) {
                        self.hits
                            .insert(format!("device-unlock-delay-{option}"), response.rect);
                    }
                }
            })
            .response
            .labelled_by(label);
        self.hits
            .insert("device-unlock-delay".into(), response.rect);
        if minutes != self.device_unlock_minutes {
            self.device_unlock_minutes = minutes;
            self.runtime.set_device_unlock_minutes(minutes);
            self.defaults_changed = true;
        }
    }
    fn theme_setting(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width();
        let theme = self.theme;
        let selected = self.locale.text(THEMES[theme].label);
        let response = design::Select::from_id_salt("vault-theme")
            .selected_text(selected)
            .width(width)
            .height(280.)
            .show_ui(ui, |ui| {
                for (i, theme) in THEMES.iter().enumerate() {
                    let label = self.locale.text(theme.label);
                    let r = ui.selectable_value(&mut self.theme, i, label);
                    if ui.clip_rect().contains(r.rect.center()) {
                        self.hits.insert(format!("theme-{i}"), r.rect);
                    }
                }
            });
        self.hits.insert("theme".into(), response.response.rect);
        if theme != self.theme {
            THEMES[self.theme].apply(ui.ctx());
        }
    }
    fn scale_setting(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width();
        let mut percent = (self.zoom_factor * 100.).round() as u16;
        let response = design::Select::from_id_salt("vault-scale")
            .selected_text(format!("{percent}%"))
            .height(400.)
            .width(width)
            .show_ui(ui, |ui| {
                for value in [75, 90, 100, 110, 125, 150, 175, 200] {
                    let r = ui.selectable_value(&mut percent, value, format!("{value}%"));
                    if ui.clip_rect().contains(r.rect.center()) {
                        self.hits.insert(format!("scale-{value}"), r.rect);
                    }
                }
            });
        self.hits.insert("scale".into(), response.response.rect);
        if percent != (self.zoom_factor * 100.).round() as u16 {
            ui.ctx().set_zoom_factor(f32::from(percent) / 100.);
        }
    }
    fn language_setting(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width();
        let mut selected = self.locale.index;
        let response = design::Select::from_id_salt("vault-language")
            .selected_text(self.locale.text("language-name"))
            .width(width)
            .height(280.)
            .show_ui(ui, |ui| {
                self.hits.insert(
                    "language-menu".into(),
                    egui::Rect::from_x_y_ranges(ui.max_rect().x_range(), ui.clip_rect().y_range()),
                );
                for (index, name) in Localizer::languages() {
                    let response = ui.selectable_value(&mut selected, *index, name);
                    if ui.clip_rect().contains(response.rect.center()) {
                        self.hits.insert(format!("language-{index}"), response.rect);
                    }
                }
            });
        self.hits.insert("language".into(), response.response.rect);
        if selected != self.locale.index {
            match Localizer::new(selected) {
                Ok(locale) => self.locale = locale,
                Err(_) => self.error = Some(Error::Input),
            }
        }
    }
    fn preferences(&mut self, ui: &mut egui::Ui, labeled: bool) {
        let p = THEMES[self.theme].colors;
        let button = if labeled {
            design::navigation_action(ui, p, &self.locale.text("vault-settings"), Icon::Settings)
        } else {
            design::icon_button(
                ui,
                p,
                &self.locale.text("vault-settings"),
                Icon::Settings,
                true,
            )
        };
        self.hits.insert("settings".into(), button.rect);
        if button.clicked() {
            self.sync_server_draft.clone_from(&self.sync_server);
            if self.preferences_section == 1 {
                self.preferences_vault = self.active.clone();
            }
            self.preferences.open(&button);
        }
    }
    fn sync_action(&mut self, ui: &mut egui::Ui, labeled: bool) {
        if !self.transports_available() {
            return;
        }
        let p = THEMES[self.theme].colors;
        let enabled = self.screen == Screen::Open && !self.busy && !self.editing;
        let label = self.locale.text("sync-now");
        let icon = if self.syncing {
            Icon::Spinner
        } else {
            Icon::Refresh
        };
        let response = if labeled {
            ui.add_enabled_ui(enabled, |ui| design::navigation_action(ui, p, &label, icon))
                .inner
        } else {
            design::icon_button(ui, p, &label, icon, enabled)
        };
        let response = if !self.sync_configured() {
            response.on_hover_text(self.locale.text("sync-disabled"))
        } else {
            response
        };
        self.bounds.insert("sync-action".into(), response.rect);
        if enabled {
            self.hits.insert("sync".into(), response.rect);
        }
        if response.clicked() {
            if self.sync_configured() {
                self.start_sync(false);
            } else {
                self.preferences_section = 1;
                self.preferences_vault = self.active.clone();
                self.sync_server_draft.clone_from(&self.sync_server);
                self.preferences.open(&response);
            }
        }
    }
    fn settings_navigation(&mut self, ui: &mut egui::Ui) {
        let p = THEMES[self.theme].colors;
        let inset = egui::Margin {
            left: Metrics::SM as i8,
            ..Default::default()
        };
        let heading = ui.label(
            RichText::new(self.locale.text("settings-app"))
                .font(design::fonts::semibold(Metrics::LABEL))
                .color(p.text_muted),
        );
        self.bounds
            .insert("preferences-app-heading".into(), heading.rect);
        ui.add_space(Metrics::XS);
        egui::Frame::new().inner_margin(inset).show(ui, |ui| {
            let r = design::navigation_item_icon(
                ui,
                p,
                &self.locale.text("settings-appearance"),
                Icon::Sun,
                self.preferences_section == 0,
            );
            self.hits.insert("preferences-section-0".into(), r.rect);
            if r.clicked() {
                self.preferences_section = 0;
                egui::Popup::close_all(ui.ctx());
            }
        });
        let mut vaults = self.catalog.clone();
        if let Some(active) = &self.active
            && !vaults.iter().any(|vault| vault.id == active.id)
        {
            vaults.push(active.clone());
        }
        if !vaults.is_empty() {
            ui.add_space(Metrics::XL);
            let heading = ui.label(
                RichText::new(self.locale.text("settings-vaults"))
                    .font(design::fonts::semibold(Metrics::LABEL))
                    .color(p.text_muted),
            );
            self.bounds
                .insert("preferences-vaults-heading".into(), heading.rect);
            ui.add_space(Metrics::XS);
            egui::Frame::new().inner_margin(inset).show(ui, |ui| {
                for (index, vault) in vaults.iter().enumerate() {
                    let open = self.screen == Screen::Open
                        && self
                            .active
                            .as_ref()
                            .is_some_and(|active| active.id == vault.id);
                    let enabled = !self.busy
                        && matches!(self.screen, Screen::Open | Screen::Catalog | Screen::Unlock);
                    let r = ui
                        .add_enabled_ui(enabled, |ui| {
                            design::navigation_item_icon(
                                ui,
                                p,
                                &vault.name,
                                if open { Icon::Vault } else { Icon::Lock },
                                self.preferences_section == 1
                                    && self
                                        .preferences_vault
                                        .as_ref()
                                        .map_or(open, |v| v.id == vault.id),
                            )
                        })
                        .inner;
                    if enabled {
                        self.hits.insert(
                            if open {
                                "preferences-section-1".into()
                            } else {
                                format!("preferences-vault-{index}")
                            },
                            r.rect,
                        );
                    }
                    if r.clicked() {
                        egui::Popup::close_all(ui.ctx());
                        self.preferences_section = 1;
                        self.preferences_vault = Some(vault.clone());
                    }
                }
            });
        }
    }
    fn preferences_window(&mut self, ui: &mut egui::Ui) {
        if !self.preferences.open {
            return;
        }
        let mut window = std::mem::take(&mut self.preferences);
        let p = THEMES[self.theme].colors;
        let title = self.locale.text("vault-settings");
        let close_label = self.locale.text("window-close");
        let mut close = false;
        let mut lock = false;
        let response = window.show(
            ui.ctx(),
            p,
            window::Window {
                id: egui::Id::unique("preferences-window"),
                title: &title,
                close_label: &close_label,
                size: Vec2::new(880., 520.),
            },
            |ui| {
                lock |= lock_shortcut(ui.ctx())
                    && matches!(
                        self.screen,
                        Screen::Open | Screen::Conflicts | Screen::Backup
                    );
                let mut panel =
                    layout::sidebar_panel(ui, p, "preferences-layout", ui.available_height());
                if self.screen != Screen::Open && self.preferences_vault.is_none() {
                    self.preferences_section = 0;
                }
                if let Some(nav) = panel.sidebar.as_mut() {
                    layout::scroll(nav, "preferences-navigation", false, |ui| {
                        self.settings_navigation(ui);
                    });
                } else {
                    let label = if self.preferences_section == 0 {
                        self.locale.text("settings-appearance")
                    } else {
                        format!(
                            "{} · {}",
                            self.locale.text("settings-vault"),
                            self.preferences_vault
                                .as_ref()
                                .or(self.active.as_ref())
                                .map(|v| v.name.as_str())
                                .unwrap_or_default()
                        )
                    };
                    let response = design::Select::from_id_salt("preferences-section")
                        .selected_text(label)
                        .width(panel.content.available_width())
                        .height(320.)
                        .show_ui(&mut panel.content, |ui| {
                            self.settings_navigation(ui);
                        });
                    self.hits
                        .insert("preferences-sections".into(), response.response.rect);
                    panel.content.add_space(Metrics::LG);
                }
                let scroll_id = format!("preferences-content-{}", self.preferences_section);
                let area = layout::scroll(&mut panel.content, &scroll_id, false, |ui| {
                    close |= self.settings_content(ui);
                    if self.error.is_some() || self.folder.error.is_some() {
                        ui.add_space(Metrics::MD);
                        self.feedback(ui);
                    }
                });
                self.bounds
                    .insert("preferences-viewport".into(), area.inner_rect);
                self.removal_dialog(ui.ctx());
            },
        );
        if close {
            window.close(ui.ctx());
        }
        if let Some(response) = response {
            self.bounds
                .insert("preferences-popup".into(), response.rect);
            self.bounds
                .insert("preferences-window".into(), response.rect);
            if response.header.is_positive() {
                self.bounds
                    .insert("preferences-header".into(), response.header);
            }
            self.bounds.insert("preferences-body".into(), response.body);
            if let Some(close) = response.close {
                self.hits.insert("preferences-close".into(), close.rect);
            }
        }
        if !window.open && self.removal.target.is_some() {
            self.close_removal();
        }
        if !window.open && !self.device_unlock_form.pending {
            self.device_unlock_form = Default::default();
        }
        self.preferences = window;
        if lock && !self.removal.removing {
            self.request_lock();
        }
    }
    fn lock_hint(&self) -> String {
        let mut args = fluent_bundle::FluentArgs::new();
        args.set(
            "shortcut",
            if cfg!(target_arch = "wasm32") {
                "Ctrl + Shift + L"
            } else {
                "⌘ / Ctrl + L"
            },
        );
        self.locale.format("vault-lock-shortcut", &args)
    }
    fn lock_action(&mut self, ui: &mut egui::Ui) {
        if self.icon_button(ui, "lock", "vault-lock", Icon::Lock, true) {
            self.request_lock();
        }
    }
    fn feedback(&mut self, ui: &mut egui::Ui) {
        self.folder_feedback(ui);
        let p = THEMES[self.theme].colors;
        if let Some(error) = self.error {
            let error = egui::Frame::new()
                .fill(p.surface)
                .stroke(egui::Stroke::new(1., p.error))
                .corner_radius(8)
                .inner_margin(12.)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let message = if self.files.importing
                        && error == Error::Storage(confidex_storage::Error::Conflict)
                    {
                        "backup-exists"
                    } else if matches!(self.screen, Screen::Backup | Screen::Import)
                        && error == Error::Storage(confidex_storage::Error::Limit)
                    {
                        "backup-limit"
                    } else if error == Error::Input
                        && matches!(
                            self.screen,
                            Screen::Create | Screen::Unlock | Screen::Import
                        )
                    {
                        self.credentials_error()
                            .map(|(_, message)| message)
                            .unwrap_or_else(|| error_key(error))
                    } else {
                        error_key(error)
                    };
                    ui.label(RichText::new(self.locale.text(message)).color(p.error));
                });
            self.bounds.insert("form-error".into(), error.response.rect);
            ui.add_space(Metrics::SM);
        }
        if self.busy
            && !self.sync_automatic
            && !matches!(self.screen, Screen::Open | Screen::Locking)
        {
            ui.horizontal(|ui| {
                design::spinner(ui, p, 16., &self.locale.text("vault-working"));
                design::muted(ui, p, self.locale.text("vault-working"));
            });
        }
        match self.runtime.offline_launch() {
            None => {
                design::muted(ui, p, self.locale.text("vault-offline-preparing"));
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(500));
            }
            Some(false) => {
                design::muted(ui, p, self.locale.text("vault-offline-unavailable"));
            }
            Some(true) => (),
        }
    }
    pub fn show(&mut self, ui: &mut egui::Ui) {
        self.tick_auto_lock(ui.ctx(), epoch());
        self.passwords.begin_frame(ui.ctx());
        self.large_type.begin_frame();
        self.poll();
        self.check_close(ui.ctx());
        self.poll_ssh();
        self.schedule_sync(ui.ctx());
        self.shortcuts_blocked = self.preferences.open
            || self.importer.window.open
            || self.exporter.window.open
            || self.history.window.open
            || self.templates.open
            || self.confirm_delete
            || self.exit.is_some()
            || self.large_type.is_open()
            || self.attachments.window.open
            || self.attachments.viewer.is_open()
            || egui::Popup::is_any_open(ui.ctx());
        self.hits.clear();
        self.bounds.clear();
        self.zoom_factor = ui.ctx().zoom_factor();
        self.clipboard.poll(ui.ctx());
        design::apply_density(ui.ctx(), false);
        if matches!(
            self.screen,
            Screen::Create | Screen::Unlock | Screen::Import
        ) && !self.busy
            && !self.preferences.open
            && !egui::Popup::is_any_open(ui.ctx())
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.request(Command::Catalog, true);
        }
        if !self.removal.removing
            && lock_shortcut(ui.ctx())
            && matches!(
                self.screen,
                Screen::Open | Screen::Conflicts | Screen::Backup
            )
        {
            self.request_lock();
        }
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Title(
            self.locale.text("vault-window-title"),
        ));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(THEMES[self.theme].colors.background))
            .show(ui, |ui| {
                if self.screen == Screen::Open {
                    ui.add_enabled_ui(
                        !self.history.window.open
                            && !self.importer.window.open
                            && !self.exporter.window.open
                            && !self.attachments.window.open
                            && !self.attachments.viewer.is_open(),
                        |ui| self.open_layout(ui),
                    );
                    return;
                }
                let p = THEMES[self.theme].colors;
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(20, 10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            design::badge(ui, Icon::Vault, p, 30., true);
                            if ui.available_width() >= 140. {
                                ui.label(
                                    RichText::new("Confidex").size(Metrics::HEADING).semibold(),
                                );
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    self.preferences(ui, false);
                                    if matches!(
                                        self.screen,
                                        Screen::Key | Screen::Conflicts | Screen::Backup
                                    ) {
                                        self.lock_action(ui);
                                    }
                                },
                            );
                        });
                    });
                match self.screen {
                    Screen::Catalog => self.catalogue(ui),
                    Screen::Create => self.create(ui),
                    Screen::Unlock => self.unlock(ui),
                    Screen::Key => self.save_key(ui),
                    Screen::Locking => self.form(ui, 460., 160., |app, ui| {
                        design::spinner(ui, p, 16., &app.locale.text("vault-locking"));
                        ui.label(app.locale.text("vault-locking"));
                    }),
                    Screen::Open => (),
                    Screen::Import => self.import(ui),
                    Screen::Backup => self.backup_screen(ui),
                    Screen::Conflicts => self.conflicts(ui),
                }
            });
        if !self.preferences.open
            && !self.importer.window.open
            && !self.exporter.window.open
            && !self.templates.open
            && !self.history.window.open
            && !self.confirm_delete
            && self.exit.is_none()
            && !egui::Popup::is_any_open(ui.ctx())
            && let Some(id) = self.pending_focus.take()
        {
            ui.memory_mut(|memory| memory.request_focus(id));
        }
        if self.confirm_delete {
            let response = dialog::Confirmation {
                title: &self.locale.text("vault-delete"),
                body: &self.locale.text("vault-delete-explanation"),
                confirm: &self.locale.text("vault-confirm-delete"),
                cancel: &self.locale.text("vault-cancel"),
                role: ButtonRole::Danger,
            }
            .show(
                ui.ctx(),
                THEMES[self.theme].colors,
                egui::Id::unique("delete-record"),
            );
            self.hits
                .insert("cancel-delete".into(), response.cancel.rect);
            self.hits
                .insert("confirm-delete".into(), response.confirm.rect);
            match response.action {
                Some(dialog::Action::Cancel) => self.confirm_delete = false,
                Some(dialog::Action::Confirm) => {
                    self.confirm_delete = false;
                    if let Some(draft) = &self.draft {
                        self.deleting = true;
                        self.request(
                            Command::Delete {
                                record: draft.record,
                                expected: draft.revision.unwrap_or([0; 32]),
                                epoch: epoch(),
                            },
                            false,
                        );
                    }
                }
                None => (),
            }
        }
        self.preferences_window(ui);
        self.attachment_windows(ui.ctx());
        self.template_picker(ui);
        self.history_window(ui);
        self.import_window(ui);
        self.export_window(ui);
        self.large_type.end_frame();
        self.passwords.end_frame();
        design::password::finish(ui.ctx());
        self.exit_dialog(ui.ctx());
        if ui
            .input(|input| input.raw.hovered_files.is_empty() && input.raw.dropped_files.is_empty())
        {
            self.file_drop.position = None;
        }
    }
    fn form(
        &mut self,
        ui: &mut egui::Ui,
        width: f32,
        height: f32,
        contents: impl FnOnce(&mut Self, &mut egui::Ui),
    ) {
        let p = THEMES[self.theme].colors;
        let narrow = ui.available_width() < 600.;
        layout::scroll(ui, "vault-form", false, |ui| {
            ui.add_space(if narrow {
                20.
            } else {
                ((ui.available_height() - height) / 2.).max(28.)
            });
            let outer = ui.available_width();
            ui.horizontal(|ui| {
                ui.add_space(((outer - width) / 2.).max(12.));
                let actual = (outer - 24.).min(width);
                let frame = ui
                    .allocate_ui_with_layout(
                        Vec2::new(actual, 0.),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(actual);
                            design::card(p)
                                .inner_margin(if narrow { 16. } else { 24. })
                                .show(ui, |ui| {
                                    let feedback = !matches!(
                                        self.screen,
                                        Screen::Create
                                            | Screen::Import
                                            | Screen::Backup
                                            | Screen::Unlock
                                    );
                                    ui.add_enabled_ui(!self.busy, |ui| contents(self, ui));
                                    if feedback {
                                        self.feedback(ui);
                                    }
                                })
                        },
                    )
                    .inner;
                self.bounds.insert("form-card".into(), frame.response.rect);
            });
            ui.add_space(Metrics::XL);
        });
    }
    fn steps(&self, ui: &mut egui::Ui, key: bool) {
        let p = THEMES[self.theme].colors;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(self.locale.text(if key {
                    "vault-step-done"
                } else {
                    "vault-step-vault"
                }))
                .color(if key { p.text_muted } else { p.accent }),
            );
            let available = ui.available_width();
            ui.add_space((available - 130.).max(8.));
            ui.label(
                RichText::new(self.locale.text("vault-step-key")).color(if key {
                    p.accent
                } else {
                    p.text_muted
                }),
            );
        });
        ui.add_space(Metrics::MD);
    }
    fn catalogue(&mut self, ui: &mut egui::Ui) {
        self.form(ui, 560., 440., |app, ui| {
            let p = THEMES[app.theme].colors;
            design::badge(ui, Icon::Vault, p, 48., true);
            ui.add_space(Metrics::MD);
            ui.heading(app.locale.text("vault-your-vaults"));
            design::muted(
                ui,
                p,
                app.locale.text(if app.catalog.is_empty() && !app.busy {
                    "vault-empty-catalogue"
                } else {
                    "vault-catalogue-intro"
                }),
            );
            ui.add_space(Metrics::XL);
            let mut selected = None;
            for (index, vault) in app.catalog.iter().enumerate() {
                let response = design::record_row(
                    ui,
                    p,
                    &vault.name,
                    &app.locale.text("vault-local"),
                    false,
                    !app.busy,
                );
                app.hits.insert(format!("vault-{index}"), response.rect);
                if response.clicked() {
                    selected = Some(vault.id);
                }
            }
            if let Some(vault) = selected {
                app.request(Command::Select { vault }, true);
            }
            ui.add_space(Metrics::LG);
            if app.primary(ui, "create", "vault-create", !app.busy) {
                app.begin_create(false);
            }
            if app.button(ui, "import-new", "vault-import-new", !app.busy) {
                app.begin_create(true);
            }
            let server = app.runtime.sync_available();
            let font = design::fonts::medium(design::density(ui).body);
            let min = ["sync-import", "backup-import"]
                .into_iter()
                .map(|key| {
                    ui.fonts_mut(|fonts| {
                        fonts
                            .layout_no_wrap(app.locale.text(key), font.clone(), p.text)
                            .size()
                            .x
                    }) + 2. * ui.spacing().button_padding.x
                })
                .fold(0., f32::max);
            layout::grid(
                ui,
                "vault-import-actions",
                if server { 2 } else { 1 },
                min,
                2,
                Metrics::SM,
                |ui, index| {
                    if server && index == 0 {
                        if app.button(ui, "import", "sync-import", !app.busy) {
                            app.files.importing = false;
                            app.folder.import_path = None;
                            app.use_device_unlock = false;
                            app.name.clear();
                            app.screen = Screen::Import;
                            app.pending_focus = Some(egui::Id::unique(("vault-input", "name")));
                            app.remember = true;
                        }
                    } else if app.button(
                        ui,
                        "backup-import",
                        "backup-import",
                        !app.busy && !app.files.busy,
                    ) {
                        app.backup_file(ui.ctx(), BackupFileRequest::Open);
                    }
                },
            );
            if app.runtime.folder_available()
                && app.button(ui, "folder-open", "folder-open", !app.busy)
            {
                app.pick_folder(true);
            }
            app.folder_feedback(ui);
            if let Some(message) = app.files.notice {
                ui.label(app.locale.text(message));
            }
            ui.add_space(Metrics::LG);
            design::muted(ui, p, app.locale.text("vault-local-only"));
        });
    }
    fn device_unlock_checkbox(&mut self, ui: &mut egui::Ui) {
        if let Some(label) = self.runtime.device_unlock_label() {
            ui.add_space(Metrics::SM);
            let response =
                design::checkbox(ui, &mut self.use_device_unlock, self.locale.text(label));
            self.hits.insert("device-unlock".into(), response.rect);
        }
    }
    fn import(&mut self, ui: &mut egui::Ui) {
        self.form(ui, Metrics::CREATE_WIDTH, 620., |app, ui| {
            dialog::Form {
                id: "vault-import",
                actions: 2,
                min_action_width: 200.,
            }
            .show(
                ui,
                app,
                |app, ui| {
                    ui.heading(app.locale.text(if app.files.importing {
                        "backup-import"
                    } else if app.folder.import_path.is_some() {
                        "folder-open"
                    } else {
                        "sync-import"
                    }));
                    if let Some(path) = &app.folder.import_path {
                        ui.add(egui::Label::new(path).wrap());
                        if app.button(ui, "folder-choose", "folder-choose", !app.busy) {
                            app.pick_folder(true);
                        }
                    }
                    for (id, label, value, secret) in [
                        ("name", "vault-name", &mut app.name, false),
                        ("sync-server", "sync-server", &mut app.sync_server, false),
                        ("secret-key", "vault-secret-key", &mut app.key, false),
                        (
                            "password",
                            "vault-password",
                            &mut app.password,
                            !app.show_password,
                        ),
                    ] {
                        if id == "sync-server"
                            && (app.files.importing || app.folder.import_path.is_some())
                        {
                            continue;
                        }
                        ui.add_space(Metrics::MD);
                        edit(ui, &app.locale, &mut app.hits, id, label, value, secret);
                    }
                    ui.add_space(Metrics::MD);
                    design::checkbox(
                        ui,
                        &mut app.show_password,
                        app.locale.text("vault-show-password"),
                    );
                    if !app.files.importing && app.folder.import_path.is_none() {
                        app.device_unlock_checkbox(ui);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        ui.add_space(Metrics::SM);
                        design::checkbox(
                            ui,
                            &mut app.remember,
                            app.locale.text("vault-remember-key"),
                        );
                    }
                },
                |app, ui, index| {
                    if index == 0 {
                        if app.primary(
                            ui,
                            "submit",
                            if app.files.importing {
                                "backup-import"
                            } else if app.folder.import_path.is_some() {
                                "folder-open"
                            } else {
                                "sync-import"
                            },
                            !app.busy,
                        ) && app.validate_credentials()
                        {
                            let command = if app.files.importing {
                                Command::RestoreBackup {
                                    name: app.name.clone(),
                                    key: app.key.clone(),
                                    password: app.password.clone(),
                                    remember: app.remember,
                                }
                            } else if let Some(path) = &app.folder.import_path {
                                Command::Folder(app::local_sync::Command::Import {
                                    name: app.name.clone(),
                                    path: path.clone(),
                                    key: app.key.clone(),
                                    password: app.password.clone(),
                                    remember: app.remember,
                                })
                            } else {
                                Command::Import {
                                    name: app.name.clone(),
                                    server: app.sync_server.clone(),
                                    key: app.key.clone(),
                                    password: app.password.clone(),
                                    remember: app.remember,
                                    use_device_unlock: if app.use_device_unlock {
                                        Some(true)
                                    } else {
                                        cfg!(target_arch = "wasm32").then_some(false)
                                    },
                                }
                            };
                            app.request(command, false);
                        }
                    } else if app.button(
                        ui,
                        "cancel",
                        "vault-cancel",
                        !app.busy || app.folder.import_path.is_some(),
                    ) {
                        app.request(Command::Catalog, true);
                    }
                },
                |app, ui| {
                    app.feedback(ui);
                    design::muted(
                        ui,
                        THEMES[app.theme].colors,
                        app.locale.text(if app.files.importing {
                            "backup-import-hint"
                        } else if app.folder.import_path.is_some() {
                            "folder-open-hint"
                        } else {
                            "sync-import-hint"
                        }),
                    );
                },
            );
        });
    }
    fn resolve_next(&mut self) {
        if let Some((record, local, remote, keep_local)) = self.resolve_queue.pop() {
            self.request(
                Command::Resolve {
                    record,
                    local,
                    remote,
                    keep_local,
                    epoch: epoch(),
                },
                false,
            );
        }
    }
    fn conflicts(&mut self, ui: &mut egui::Ui) {
        if self.comparison.is_some() {
            self.compare_versions(ui);
            return;
        }
        let mut compare = None;
        self.form(ui, 920., 720., |app, ui| {
            let p = THEMES[app.theme].colors;
            ui.heading(app.locale.text("sync-conflicts"));
            design::muted(ui, p, app.locale.text("sync-conflicts-hint"));
            ui.add_space(Metrics::LG);
            let mut can_apply = false;
            if let Some(report) = &app.sync_report {
                for (index, conflict) in report.conflicts.iter().enumerate() {
                    design::card(p).show(ui, |ui| {
                        let title = if conflict.local.title.is_empty() {
                            &conflict.remote.title
                        } else {
                            &conflict.local.title
                        };
                        ui.label(RichText::new(title).semibold());
                        ui.add_space(Metrics::MD);
                        layout::grid(
                            ui,
                            &format!("conflict-{index}"),
                            2,
                            260.,
                            2,
                            Metrics::MD,
                            |ui, side| {
                                let local = side == 0;
                                let version = if local {
                                    &conflict.local
                                } else {
                                    &conflict.remote
                                };
                                let selected =
                                    app.sync_choices.get(&conflict.record) == Some(&local);
                                let label = app.locale.text(if local {
                                    "sync-local"
                                } else {
                                    "sync-remote"
                                });
                                let frame = design::card(p)
                                    .fill(if selected {
                                        p.accent.gamma_multiply(0.12)
                                    } else {
                                        p.background
                                    })
                                    .stroke(egui::Stroke::new(
                                        1.,
                                        if selected { p.accent } else { p.border },
                                    ))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            let (rect, _) = ui.allocate_exact_size(
                                                Vec2::splat(16.),
                                                egui::Sense::hover(),
                                            );
                                            ui.painter().circle_stroke(
                                                rect.center(),
                                                7.,
                                                egui::Stroke::new(
                                                    1.,
                                                    if selected { p.accent } else { p.text_muted },
                                                ),
                                            );
                                            if selected {
                                                ui.painter().circle_filled(
                                                    rect.center(),
                                                    3.5,
                                                    p.accent,
                                                );
                                            }
                                            ui.label(&label);
                                        });
                                        if version.deleted {
                                            ui.label(
                                                RichText::new(app.locale.text("sync-deleted"))
                                                    .color(p.error),
                                            );
                                        }
                                        let date = time::OffsetDateTime::from_unix_timestamp_nanos(
                                            i128::from(version.epoch) * 1_000_000,
                                        )
                                        .map(|d| d.to_string())
                                        .unwrap_or_default();
                                        design::muted(ui, p, date);
                                        let other = if local {
                                            conflict.remote.epoch
                                        } else {
                                            conflict.local.epoch
                                        };
                                        if version.epoch > other {
                                            record::tag(
                                                ui,
                                                p,
                                                &app.locale.text("sync-newer"),
                                                record::TagRole::Accent,
                                            );
                                        }
                                    });
                                let response = ui.interact(
                                    frame.response.rect,
                                    ui.scope_id().with((index, side, "choice")),
                                    if app.busy {
                                        egui::Sense::hover()
                                    } else {
                                        egui::Sense::click()
                                    },
                                );
                                response.widget_info(|| {
                                    egui::WidgetInfo::selected(
                                        egui::Role::RadioButton,
                                        !app.busy,
                                        selected,
                                        &label,
                                    )
                                });
                                app.hits
                                    .insert(format!("conflict-{index}-{local}"), response.rect);
                                if response.clicked() {
                                    app.sync_choices.insert(conflict.record, local);
                                }
                            },
                        );
                        let response = design::button(
                            ui,
                            p,
                            &app.locale.text("sync-compare"),
                            ButtonRole::Quiet,
                            0.,
                            !app.busy,
                        );
                        app.hits.insert(format!("compare-{index}"), response.rect);
                        if response.clicked() {
                            compare = Some((
                                conflict.record,
                                conflict.local.revision,
                                conflict.remote.revision,
                            ));
                        }
                    });
                    ui.add_space(Metrics::MD);
                }
                can_apply = app.sync_choices.len() == report.conflicts.len()
                    && !report.conflicts.is_empty();
                if report.duplicates > 0 {
                    let mut args = fluent_bundle::FluentArgs::new();
                    args.set("count", report.duplicates as i64);
                    design::muted(ui, p, app.locale.format("sync-duplicates", &args));
                }
            }
            ui.add_space(Metrics::MD);
            if app.primary(ui, "sync-apply", "sync-apply", can_apply && !app.busy)
                && let Some(report) = &app.sync_report
            {
                app.resolve_queue = report
                    .conflicts
                    .iter()
                    .rev()
                    .map(|c| {
                        (
                            c.record,
                            c.local.revision,
                            c.remote.revision,
                            app.sync_choices[&c.record],
                        )
                    })
                    .collect();
                app.resolve_next();
            }
            design::muted(ui, p, app.locale.text("sync-later-hint"));
            if app.button(ui, "sync-later", "sync-later", !app.busy) {
                app.files.after_sync = false;
                app.screen = Screen::Open;
                app.request(Command::SyncConfig { server: None }, false);
            }
        });
        if let Some((record, local, remote)) = compare {
            self.request(
                Command::Compare {
                    record,
                    local,
                    remote,
                },
                false,
            );
        }
    }
    fn compare_versions(&mut self, ui: &mut egui::Ui) {
        self.form(ui, 920., 720., |app, ui| {
            let p = THEMES[app.theme].colors;
            ui.heading(app.locale.text("sync-compare"));
            let mut comparison = app.comparison.take().unwrap();
            layout::grid(ui, "comparison", 2, 280., 2, Metrics::LG, |ui, side| {
                ui.heading(app.locale.text(if side == 0 {
                    "sync-local"
                } else {
                    "sync-remote"
                }));
                let Some(draft) = &mut comparison.1[side] else {
                    ui.label(RichText::new(app.locale.text("sync-deleted")).color(p.error));
                    return;
                };
                ui.label(RichText::new(&draft.title).semibold());
                if !draft.tags.is_empty() {
                    layout::flow(ui, Metrics::SM, |ui| {
                        for tag in &draft.tags {
                            record::tag(ui, p, tag, record::TagRole::Neutral);
                        }
                    });
                }
                let sources = draft.fields.clone();
                let keys: Vec<_> = (0..sources.len() as u64).collect();
                for (index, field) in draft.fields.iter_mut().enumerate() {
                    if !field_visible(field) {
                        continue;
                    }
                    ui.add_space(Metrics::MD);
                    design::card(p).show(ui, |ui| {
                        let kind = field_label(&app.locale, &field.type_name);
                        ui.label(
                            RichText::new(if field.name.is_empty() {
                                &kind
                            } else {
                                &field.name
                            })
                            .semibold(),
                        );
                        if !field.name.is_empty() && field.name != kind {
                            record::tag(ui, p, &kind, record::TagRole::Type);
                        }
                        if field.type_name == "wifi-qr/v1" {
                            app.wifi_field(
                                ui,
                                egui::Id::unique(("comparison-wifi", comparison.0, side, index)),
                                &mut field.values,
                                &sources,
                                &keys,
                                false,
                            );
                            return;
                        }
                        if field.type_name == "photo/v1" {
                            app.photo_readonly(
                                ui,
                                &format!("comparison-photo-{side}-{index}"),
                                field,
                            );
                            return;
                        }
                        if field.type_name == "card/v1" {
                            app.card_field(
                                ui,
                                egui::Id::unique(("comparison-card", comparison.0, side, index)),
                                &sources[index],
                                &mut field.values,
                                false,
                            );
                            return;
                        }
                        if field.type_name == "totp/v1" {
                            app.totp_field(
                                ui,
                                egui::Id::unique(("comparison-totp", comparison.0, side, index)),
                                &sources[index],
                                None,
                            );
                            return;
                        }
                        if field.type_name == "file/v1" {
                            app.file_readonly(
                                ui,
                                &format!("comparison-file-{side}-{index}"),
                                field,
                            );
                            return;
                        }
                        let multiple = field.values.len() > 1;
                        for (key, text) in &mut field.values {
                            if text.is_empty() {
                                continue;
                            }
                            if multiple {
                                design::muted(ui, p, value_label(&app.locale, key));
                            }
                            let field_id = ((side as u64) << 32) | index as u64;
                            let mut revealed = app.revealed.contains(&(field_id, key.clone()));
                            let id = egui::Id::unique((
                                "comparison",
                                comparison.0,
                                side,
                                index,
                                key.as_str(),
                            ));
                            let labels = [
                                "vault-copy-value",
                                "vault-copy-pending",
                                "vault-copied",
                                "vault-copy-failed",
                                "vault-reveal",
                                "vault-hide",
                                "vault-large-type",
                                "vault-empty-value",
                            ]
                            .map(|id| app.locale.text(id));
                            let kind = field_kind(&field.type_name, key);
                            let response = value::ValueField {
                                id,
                                value: text,
                                kind,
                                protected: value_protected(&field.type_name, field.protected, key),
                                editing: false,
                                enabled: !app.busy,
                                revealed: &mut revealed,
                                feedback: app.clipboard.state(id),
                                labels: value::Labels {
                                    copy: &labels[0],
                                    pending: &labels[1],
                                    copied: &labels[2],
                                    failed: &labels[3],
                                    show: &labels[4],
                                    hide: &labels[5],
                                    large: &labels[6],
                                    empty: &labels[7],
                                },
                            }
                            .show(ui, p);
                            if revealed {
                                app.revealed.insert((field_id, key.clone()));
                            } else {
                                app.revealed.remove(&(field_id, key.clone()));
                            }
                            app.large_value(
                                ui,
                                large_type::Value {
                                    id,
                                    title: &draft.title,
                                    field: &value_label(&app.locale, key),
                                    text,
                                },
                                &response,
                            );
                            if let Some(large) = &response.large {
                                app.hits.insert(
                                    format!("compare-large-{side}-{index}-{key}"),
                                    large.rect,
                                );
                            }
                            if response.copy.clicked() {
                                app.clipboard.request(ui.ctx(), id, text.clone());
                            }
                        }
                        if field.opaque > 0 {
                            design::muted(ui, p, app.locale.text("vault-opaque-fields"));
                        }
                    });
                }
            });
            app.comparison = Some(comparison);
            ui.add_space(Metrics::LG);
            if app.button(ui, "compare-back", "vault-back", !app.busy) {
                app.comparison = None;
                app.attachments.clear();
                app.revealed.clear();
                app.clipboard.clear();
            }
        });
    }
    fn begin_create(&mut self, importing: bool) {
        self.name.clear();
        self.import_after_create = importing;
        self.create_sync = self.new_vault_sync && self.runtime.sync_available();
        self.create_server.clone_from(&self.new_vault_server);
        self.screen = Screen::Create;
        self.pending_focus = Some(egui::Id::unique(("vault-input", "name")));
        self.remember = true;
    }
    fn create(&mut self, ui: &mut egui::Ui) {
        self.form(ui, Metrics::CREATE_WIDTH, 620., |app, ui| {
            dialog::Form {
                id: "create-vault",
                actions: 2,
                min_action_width: 180.,
            }
            .show(
                ui,
                app,
                |app, ui| {
                    let p = THEMES[app.theme].colors;
                    app.steps(ui, false);
                    ui.heading(app.locale.text(if app.import_after_create {
                        "vault-import-new"
                    } else {
                        "vault-create-heading"
                    }));
                    ui.add_space(Metrics::XL);
                    edit(
                        ui,
                        &app.locale,
                        &mut app.hits,
                        "name",
                        "vault-name",
                        &mut app.name,
                        false,
                    );
                    ui.add_space(Metrics::MD);
                    app.new_master_password(ui);
                    ui.add_space(Metrics::SM);
                    edit(
                        ui,
                        &app.locale,
                        &mut app.hits,
                        "repeat",
                        "vault-repeat-password",
                        &mut app.repeated,
                        !app.show_password,
                    );
                    ui.add_space(Metrics::SM);
                    design::checkbox(
                        ui,
                        &mut app.show_password,
                        app.locale.text("vault-show-password"),
                    );
                    ui.add_space(Metrics::SM);
                    ui.add_space(Metrics::LG);
                    if app.runtime.sync_available() {
                        let title = app.locale.text("sync-enabled");
                        ui.horizontal(|ui| {
                            ui.label(&title);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let r = form::switch(
                                        ui,
                                        p,
                                        &mut app.create_sync,
                                        &title,
                                        !app.busy,
                                    );
                                    app.hits.insert("create-sync".into(), r.rect);
                                },
                            );
                        });
                    }
                    if app.create_sync && app.runtime.sync_available() {
                        let invalid = app.error == Some(Error::Input)
                            && app
                                .credentials_error()
                                .is_some_and(|(id, _)| id == "sync-server");
                        let mut field = None;
                        let collapse = egui::CollapsingHeader::new(app.locale.text("sync-server"))
                            .id_salt("create-sync-server")
                            .open(invalid.then_some(true))
                            .show(ui, |ui| {
                                let response = design::field_with_id(
                                    ui,
                                    egui::Id::unique(("vault-input", "sync-server")),
                                    &mut app.create_server,
                                    false,
                                    false,
                                    true,
                                );
                                app.hits.insert("sync-server".into(), response.rect);
                                field = Some(response);
                            });
                        if let Some(field) = field {
                            field.labelled_by(collapse.header_response.id);
                        }
                        app.hits
                            .insert("create-sync-server".into(), collapse.header_response.rect);
                    }
                },
                |app, ui, index| {
                    if index == 0 {
                        if app.primary(ui, "submit", "vault-create", !app.busy)
                            && app.validate_credentials()
                        {
                            let command = Command::Create {
                                name: app.name.clone(),
                                password: app.password.clone(),
                                remember: true,
                            };
                            app.request(command, false);
                        }
                    } else {
                        let cancel = design::button(
                            ui,
                            THEMES[app.theme].colors,
                            &app.locale.text("vault-cancel"),
                            ButtonRole::Secondary,
                            ui.available_width(),
                            !app.busy,
                        );
                        app.hits.insert("cancel".into(), cancel.rect);
                        if cancel.clicked() {
                            app.request(Command::Catalog, true);
                        }
                    }
                },
                |app, ui| {
                    app.feedback(ui);
                    if app
                        .passwords
                        .report(egui::Id::unique(("vault-input", "password")))
                        .is_some_and(|report| report.score <= 1)
                    {
                        let warning = ui.colored_label(
                            THEMES[app.theme].colors.error,
                            app.locale.text("vault-password-strength-weak-warning"),
                        );
                        app.bounds
                            .insert("master-password-warning".into(), warning.rect);
                    }
                    design::muted(
                        ui,
                        THEMES[app.theme].colors,
                        app.locale.text("vault-create-intro"),
                    );
                    if !app.create_sync || !app.runtime.sync_available() {
                        design::muted(
                            ui,
                            THEMES[app.theme].colors,
                            app.locale.text("vault-local-intro"),
                        );
                    }
                },
            );
        });
    }
    fn unlock(&mut self, ui: &mut egui::Ui) {
        self.form(
            ui,
            480.,
            if self.remembered { 420. } else { 560. },
            |app, ui| {
                dialog::Form {
                    id: "unlock-vault",
                    actions: 2,
                    min_action_width: 180.,
                }
                .show(
                    ui,
                    app,
                    |app, ui| {
                        let p = THEMES[app.theme].colors;
                        ui.vertical_centered(|ui| {
                            design::badge(ui, Icon::Lock, p, 40., true);
                            ui.add_space(Metrics::LG);
                            ui.heading(app.locale.text("vault-unlock"));
                            if let Some(info) = &app.active {
                                ui.label(
                                    RichText::new(&info.name)
                                        .size(Metrics::HEADING)
                                        .color(p.accent),
                                );
                            }
                        });
                        ui.add_space(Metrics::XL);
                        if !app.remembered {
                            edit(
                                ui,
                                &app.locale,
                                &mut app.hits,
                                "secret-key",
                                "vault-secret-key",
                                &mut app.key,
                                false,
                            );
                            ui.add_space(Metrics::SM);
                            design::muted(ui, p, app.locale.text("vault-key-input-hint"));
                            ui.add_space(Metrics::MD);
                        }
                        if !app.can_use_device_unlock() {
                            edit(
                                ui,
                                &app.locale,
                                &mut app.hits,
                                "password",
                                "vault-password",
                                &mut app.password,
                                !app.show_password,
                            );
                            ui.add_space(Metrics::SM);
                            design::checkbox(
                                ui,
                                &mut app.show_password,
                                app.locale.text("vault-show-password"),
                            );
                        }
                        if app.device_unlock_verified_at.is_none() && cfg!(target_os = "macos") {
                            app.device_unlock_checkbox(ui);
                        }
                        if !app.remembered
                            && !cfg!(target_arch = "wasm32")
                            && !app.use_device_unlock
                        {
                            design::checkbox(
                                ui,
                                &mut app.remember,
                                app.locale.text("vault-remember-key"),
                            );
                        }
                    },
                    |app, ui, index| {
                        if index == 0 {
                            if app.primary(
                                ui,
                                "submit",
                                if app.can_use_device_unlock() {
                                    app.runtime.device_unlock_label().unwrap_or("vault-unlock")
                                } else {
                                    "vault-unlock"
                                },
                                !app.busy,
                            ) && app.validate_credentials()
                                && let Some(info) = &app.active
                            {
                                let command = if app.use_device_unlock {
                                    Command::EnrollDeviceUnlock {
                                        vault: info.id,
                                        password: app.password.clone(),
                                        key: app.key.clone(),
                                        remember: app.remember,
                                    }
                                } else {
                                    Command::Unlock {
                                        vault: info.id,
                                        password: app.password.clone(),
                                        key: app.key.clone(),
                                        remember: app.remember,
                                    }
                                };
                                app.request(command, false);
                            }
                        } else if app.action(
                            ui,
                            "vaults",
                            "vault-switch",
                            !app.busy,
                            ButtonRole::Quiet,
                        ) {
                            app.request(Command::Catalog, true);
                        }
                    },
                    |app, ui| {
                        app.feedback(ui);
                        if !app.can_use_device_unlock() {
                            design::muted(
                                ui,
                                THEMES[app.theme].colors,
                                app.locale.text("vault-unlock-intro"),
                            );
                        }
                    },
                );
            },
        );
    }
    fn save_key(&mut self, ui: &mut egui::Ui) {
        self.form(ui, Metrics::KEY_WIDTH, 680., |app, ui| {
            let p = THEMES[app.theme].colors;
            app.steps(ui, true);
            ui.heading(app.locale.text("vault-save-key"));
            design::muted(ui, p, app.locale.text("vault-key-explanation"));
            ui.add_space(Metrics::XL);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(app.locale.text("vault-password")).semibold());
                ui.label(RichText::new("+").color(p.text_muted));
                ui.label(
                    RichText::new(app.locale.text("vault-secret-key"))
                        .color(p.accent)
                        .semibold(),
                );
                ui.label(RichText::new("=").color(p.text_muted));
                ui.label(RichText::new(app.locale.text("vault-opens")).color(p.success));
            });
            ui.add_space(Metrics::MD);
            for (icon, heading, body) in [
                (Icon::Key, "vault-key-required", "vault-key-required-body"),
                (
                    Icon::Lock,
                    "vault-key-keep-safe",
                    "vault-key-keep-safe-body",
                ),
            ] {
                ui.horizontal_top(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(24.), egui::Sense::hover());
                    icon.paint(ui, rect, p.accent);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(app.locale.text(heading)).semibold());
                        design::muted(ui, p, app.locale.text(body));
                    });
                });
                ui.add_space(Metrics::SM);
            }
            ui.add_space(Metrics::SM);
            design::card(p)
                .fill(p.background)
                .inner_margin(18.)
                .show(ui, |ui| {
                    if let Some(created) = &app.created {
                        let font = egui::FontId::monospace(design::density(ui).body + 2.);
                        layout::flow(ui, Metrics::SM, |ui| {
                            for (index, group) in created.key.split('-').enumerate() {
                                let response = ui.add(
                                    egui::Label::new(RichText::new(group).font(font.clone()))
                                        .wrap_mode(egui::TextWrapMode::Extend),
                                );
                                app.bounds
                                    .insert(format!("key-group-{index}"), response.rect);
                            }
                        });
                    }
                });
            ui.add_space(Metrics::MD);
            let copy_id = egui::Id::unique("vault-secret-key");
            let message = match app.clipboard.state(copy_id) {
                value::CopyState::Copied => "vault-copied",
                value::CopyState::Failed => "vault-copy-failed",
                value::CopyState::Pending => "vault-copy-pending",
                value::CopyState::Idle => "vault-copy-key",
            };
            if app.button(
                ui,
                "copy-key",
                message,
                app.clipboard.state(copy_id) != value::CopyState::Pending,
            ) && let Some(created) = &app.created
            {
                app.clipboard
                    .request(ui.ctx(), copy_id, created.key.clone());
            }
            if !app.remembered {
                ui.add_space(Metrics::SM);
                ui.label(
                    RichText::new(app.locale.text("vault-key-not-remembered")).color(p.warning),
                );
            }
            let saved_key = app.saved_key;
            let enter = ui.input(|input| input.key_pressed(egui::Key::Enter));
            let response =
                design::checkbox(ui, &mut app.saved_key, app.locale.text("vault-key-saved"));
            if enter && response.has_focus() {
                app.saved_key = saved_key;
                response.surrender_focus();
            }
            app.hits.insert("key-saved".into(), response.rect);
            if app.primary(ui, "continue", "vault-continue", app.saved_key && !app.busy) {
                app.created = None;
                app.screen = Screen::Open;
                if std::mem::take(&mut app.create_sync) && app.runtime.sync_available() {
                    app.sync_server.clone_from(&app.create_server);
                    app.request(
                        Command::SyncConfig {
                            server: Some(app.create_server.clone()),
                        },
                        false,
                    );
                    app.sync_automatic = app.busy;
                } else {
                    app.request_list(None);
                }
                if std::mem::take(&mut app.import_after_create) {
                    app.start_record_import(&ui.response());
                }
            }
        });
    }
    fn open_layout(&mut self, ui: &mut egui::Ui) {
        let p = THEMES[self.theme].colors;
        let area = ui.available_rect_before_wrap();
        if let Some(layout) = design::Workspace::desktop(area) {
            let rail = layout.sidebar;
            let list = layout.records;
            let detail = layout.detail;
            ui.painter().rect_filled(rail, 0., p.background);
            ui.painter().rect_filled(list, 0., p.surface);
            for x in [rail.right(), list.right()] {
                ui.painter()
                    .vline(x, area.y_range(), egui::Stroke::new(1., p.border));
            }
            let mut child = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(rail.shrink(Metrics::LG))
                    .layout(egui::Layout::top_down(egui::Align::Min)),
            );
            child.set_clip_rect(rail.intersect(ui.clip_rect()));
            self.navigation(&mut child);
            let mut child = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(list.shrink2(Vec2::new(Metrics::MD, Metrics::LG)))
                    .layout(egui::Layout::top_down(egui::Align::Min)),
            );
            child.set_clip_rect(list.intersect(ui.clip_rect()));
            self.list(&mut child);
            let mut child = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(detail.shrink(Metrics::LG))
                    .layout(egui::Layout::top_down(egui::Align::Min)),
            );
            child.set_clip_rect(detail.intersect(ui.clip_rect()));
            self.feedback(&mut child);
            self.record(&mut child);
        } else {
            egui::Frame::new()
                .inner_margin(egui::Margin::symmetric(16, 12))
                .show(ui, |ui| {
                    self.mobile_header(ui);
                    ui.add_space(Metrics::LG);
                    self.feedback(ui);
                    if self.mobile_detail && self.draft.is_some() {
                        self.record(ui);
                    } else {
                        self.list(ui);
                    }
                });
        }
    }
    fn mobile_header(&mut self, ui: &mut egui::Ui) {
        let p = THEMES[self.theme].colors;
        let compact = ui.available_width() < 240.;
        ui.horizontal_wrapped(|ui| {
            if compact {
                ui.spacing_mut().item_spacing.x = Metrics::XS;
            }
            if self.mobile_detail && self.draft.is_some() {
                if self.icon_button(
                    ui,
                    "back",
                    "vault-back",
                    Icon::Back,
                    !self.editing && !self.busy,
                ) {
                    self.mobile_detail = false;
                }
            } else {
                design::badge(ui, Icon::Vault, p, 40., true);
            }
            if !compact {
                let actions_width = if self.transports_available() {
                    184.
                } else {
                    140.
                };
                let width = (ui.available_width() - actions_width).max(36.);
                ui.allocate_ui_with_layout(
                    Vec2::new(width, 42.),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_min_width(width);
                        if let Some(info) = &self.active {
                            let response = ui.add_enabled(
                                !self.busy && !self.editing,
                                egui::Button::new(
                                    RichText::new(&info.name).size(Metrics::HEADING).semibold(),
                                )
                                .frame(false)
                                .wrap_mode(egui::TextWrapMode::Truncate)
                                .min_size(Vec2::new(width, 26.)),
                            );
                            if !self.busy && !self.editing {
                                self.hits.insert("vaults".into(), response.rect);
                            }
                            if response.clicked() {
                                self.request(Command::Catalog, true);
                            }
                        }
                        ui.label(
                            RichText::new(self.locale.text("vault-local"))
                                .small()
                                .color(p.text_muted),
                        );
                    },
                );
            }
            self.lock_action(ui);
            ui.horizontal(|ui| {
                self.sync_action(ui, false);
                self.preferences(ui, false);
            });
        });
    }
    fn navigation(&mut self, ui: &mut egui::Ui) {
        let p = THEMES[self.theme].colors;
        let name = self
            .active
            .as_ref()
            .map(|i| i.name.clone())
            .unwrap_or_default();
        let response = design::record_row(
            ui,
            p,
            &name,
            &self.locale.text("vault-local"),
            false,
            !self.busy && !self.editing,
        );
        self.hits.insert("vaults".into(), response.rect);
        if response.clicked() {
            self.request(Command::Catalog, true);
        }
        ui.add_space(Metrics::XL);
        let response = ui
            .add_enabled_ui(!self.busy && !self.editing, |ui| {
                design::navigation_item(
                    ui,
                    p,
                    &self.locale.text("vault-all-items"),
                    self.trash.is_none(),
                )
            })
            .inner;
        self.hits.insert("all-items".into(), response.rect);
        if response.clicked() {
            self.show_records();
        }
        let height = ui.available_height();
        let count = if self.transports_available() { 3. } else { 2. };
        let footer_height = count * (design::density(ui).control + Metrics::SM) + 2. * Metrics::SM;
        ui.add_space((height - footer_height).max(Metrics::MD));
        ui.separator();
        let lock = design::navigation_action(ui, p, &self.locale.text("vault-lock"), Icon::Lock)
            .on_hover_text(self.lock_hint());
        self.hits.insert("lock".into(), lock.rect);
        if lock.clicked() {
            self.request_lock();
        }
        self.sync_action(ui, true);
        self.preferences(ui, true);
    }
    fn search_tag(&self) -> Option<String> {
        self.search
            .strip_prefix('#')
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
    }
    fn request_list(&mut self, after: Option<confidex_storage::Head>) {
        if self.trash.is_some() && self.sync_after_list.is_none() {
            self.request_trash(after);
        } else {
            self.request_search(after, false);
        }
    }
    fn request_search(&mut self, after: Option<confidex_storage::Head>, refresh: bool) {
        let tag = self.search_tag();
        if let Some(mut old) = self.listed_tag.take() {
            old.zeroize();
        }
        self.listed_tag = tag.clone();
        self.listed_search.zeroize();
        self.listed_search = self.search.clone();
        let query = if tag.is_some() {
            String::new()
        } else {
            self.search.trim().to_owned()
        };
        self.request(
            Command::Search {
                after,
                tag,
                query,
                refresh,
            },
            false,
        );
    }
    fn list(&mut self, ui: &mut egui::Ui) {
        if self.trash.is_some() {
            self.trash_list(ui);
            return;
        }
        let p = THEMES[self.theme].colors;
        ui.horizontal(|ui| {
            let height = design::density(ui).input;
            let width = (ui.available_width() - height - Metrics::SM).max(80.);
            let response = ui
                .allocate_ui_with_layout(
                    Vec2::new(width, design::density(ui).input),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        design::search_field(
                            ui,
                            p,
                            &mut self.search,
                            &self.locale.text("vault-search-placeholder"),
                        )
                    },
                )
                .inner;
            self.hits.insert("search".into(), response.rect);
            let response = ui
                .add_enabled(
                    !self.busy && !self.editing,
                    egui::Button::new("")
                        .min_size(Vec2::splat(height))
                        .fill(p.accent)
                        .stroke(egui::Stroke::NONE),
                )
                .on_hover_text(self.locale.text("vault-new-record"));
            Icon::Plus.paint(ui, response.rect, p.on_accent);
            response.widget_info(|| {
                egui::WidgetInfo::labeled(
                    egui::Role::Button,
                    !self.busy && !self.editing,
                    self.locale.text("vault-new-record"),
                )
            });
            if !self.busy && !self.editing {
                self.hits.insert("new-record".into(), response.rect);
            }
            if response.clicked() {
                self.template_query.zeroize();
                self.template_selection = 0;
                self.template_focus = true;
                self.templates.open(&response);
            }
        });
        if !self.busy && !self.editing && self.search != self.listed_search {
            self.rows.clear();
            self.next = None;
            self.more = false;
            self.loading_more = false;
            self.request_list(None);
        }
        ui.add_space(Metrics::SM);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(self.locale.text("vault-all-items"))
                    .semibold()
                    .color(p.text_muted),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.icon_button(
                    ui,
                    "trash",
                    "vault-trash",
                    Icon::Trash,
                    !self.busy && !self.editing,
                ) {
                    self.show_trash();
                }
                if self.icon_button(
                    ui,
                    "refresh",
                    "vault-refresh",
                    Icon::Refresh,
                    !self.busy && !self.editing,
                ) {
                    self.loading_more = false;
                    self.request_search(None, true);
                }
            });
        });
        ui.add_space(Metrics::SM);
        let area = layout::scroll(ui, "records", false, |ui| {
            if self.rows.is_empty() && !self.busy {
                ui.add_space(Metrics::XXL);
                ui.vertical_centered(|ui| {
                    design::badge(ui, Icon::Note, p, 44., false);
                    ui.add_space(Metrics::MD);
                    design::muted(
                        ui,
                        p,
                        self.locale.text(if self.search.trim().is_empty() {
                            "vault-empty-records"
                        } else {
                            "vault-no-results"
                        }),
                    );
                });
            }
            let mut selected = None;
            for (index, row) in self.rows.iter().enumerate() {
                let title = if row.title.is_empty() {
                    self.locale.text("vault-untitled")
                } else {
                    row.title.clone()
                };
                let mut args = fluent_bundle::FluentArgs::new();
                args.set("count", row.fields as i64);
                let current = self.draft.as_ref().is_some_and(|d| {
                    d.record == row.head.record && d.revision == Some(row.head.revision)
                });
                let response = ui
                    .push_id((row.head.record, row.head.revision), |ui| {
                        design::record_row(
                            ui,
                            p,
                            &title,
                            &self.locale.format("vault-field-count", &args),
                            current,
                            !self.busy && !self.editing,
                        )
                    })
                    .inner;
                self.hits.insert(format!("record-{index}"), response.rect);
                if response.clicked() {
                    selected = Some(row.head.clone());
                }
            }
            if let Some(head) = selected {
                self.request(
                    Command::OpenRevision {
                        record: head.record,
                        revision: head.revision,
                    },
                    false,
                );
            }
            if self.more && self.button(ui, "more", "vault-more", !self.busy && !self.editing) {
                self.loading_more = true;
                self.request_list(self.next.clone());
            }
        });
        self.bounds.insert("list-viewport".into(), area.inner_rect);
    }
    fn large_value(&mut self, ui: &egui::Ui, value: large_type::Value<'_>, output: &value::Output) {
        let id = value.id;
        let text = value.text;
        if let Some(modal) = self.large_type.show(
            ui,
            THEMES[self.theme].colors,
            value,
            output.large.as_ref(),
            &self.locale,
            self.clipboard.state(id),
        ) {
            self.hits.insert("large-copy".into(), modal.copy.rect);
            if let Some(close) = modal.close {
                self.hits.insert("large-close".into(), close.rect);
            }
            self.bounds.insert("large-dialog".into(), modal.rect);
            self.bounds.insert("large-viewport".into(), modal.viewport);
            if modal.copy.clicked() {
                self.clipboard.request(ui.ctx(), id, text.to_owned());
            }
        }
    }
    fn record(&mut self, ui: &mut egui::Ui) {
        layout::content_column(ui, |ui| self.record_content(ui));
    }
    fn record_content(&mut self, ui: &mut egui::Ui) {
        self.bounds.insert("record-column".into(), ui.max_rect());
        let p = THEMES[self.theme].colors;
        let popup_open = self.shortcuts_blocked
            || self.preferences.open
            || self.confirm_delete
            || egui::Popup::is_any_open(ui.ctx());
        let Some(mut draft) = self.draft.take() else {
            ui.add_space(ui.available_height() * 0.3);
            ui.vertical_centered(|ui| {
                design::badge(ui, Icon::Note, p, 48., false);
                ui.add_space(Metrics::LG);
                ui.heading(self.locale.text("vault-detail-empty"));
                design::muted(ui, p, self.locale.text("vault-select-record"));
            });
            return;
        };
        if self.field_ids.len() != draft.fields.len() {
            self.reset_field_ids(draft.fields.len());
        }
        let mut save = false;
        let mut cancel = false;
        if self.editing && !self.busy && !popup_open {
            cancel =
                ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
            if cancel && self.ssh.is_open() {
                self.ssh.clear();
                cancel = false;
            }
        }
        let context = self.locale.text(if draft.revision.is_none() {
            "vault-unsaved"
        } else {
            "vault-record"
        });
        let conflict = self
            .sync_report
            .as_ref()
            .is_some_and(|report| report.conflicts.iter().any(|c| c.record == draft.record));
        if conflict || (draft.revision.is_some() && self.latest_revision != draft.revision) {
            design::card(p).show(ui, |ui| {
                ui.label(self.locale.text("vault-record-updated"));
                if conflict && self.button(ui, "record-conflicts", "sync-conflicts", !self.busy) {
                    self.screen = Screen::Conflicts;
                }
            });
            ui.add_space(Metrics::SM);
        }
        let valid_fields = self.record_valid(&draft);
        record::toolbar(ui, p, &context, |ui| {
            if !self.editing {
                if self.icon_button(ui, "delete", "vault-delete", Icon::Trash, !self.busy) {
                    self.confirm_delete = true;
                }
                if self.button(ui, "edit", "vault-edit", !self.busy) {
                    self.edit_baseline = Some(draft.clone());
                    self.editing = true;
                    self.revealed.clear();
                    self.clipboard.clear();
                }
            }
        });
        ui.add_space(Metrics::SM);
        let editing = self.editing;
        let enabled = !self.busy;
        let mut added = None;
        let mut added_section = false;
        let can_group = draft
            .sections
            .as_ref()
            .is_some_and(|sections| sections.len() < app::sections::MAX_SECTIONS);
        let mut footer_hits = Vec::new();
        let before_ids = self.field_ids.clone();
        let add_label = self.locale.text("vault-add-field");
        let section_label = self.locale.text("field-section");
        let save_label = self.locale.text("vault-save");
        let cancel_label = self.locale.text("vault-cancel");
        let quick_labels = [
            self.locale.text("vault-add-website"),
            self.locale.text("vault-add-location"),
        ];
        let button_font = design::fonts::medium(design::density(ui).body);
        let quick_width = quick_labels
            .iter()
            .map(|label| {
                ui.fonts_mut(|fonts| {
                    fonts.layout_no_wrap(label.clone(), button_font.clone(), p.text)
                })
                .size()
                .x + 2. * Metrics::LG
            })
            .fold(160., f32::max);
        let quick_columns = layout::columns(ui.available_width(), quick_width, Metrics::SM, 2);
        let action_columns = layout::columns(ui.available_width(), 120., Metrics::SM, 2);
        let footer_rows = 1 + 2_usize.div_ceil(quick_columns) + 2_usize.div_ceil(action_columns);
        let caption_font = design::fonts::regular(design::density(ui).body);
        let caption_width = ui.available_width();
        let record_problem = self
            .tag_editor
            .problem(&draft.tags)
            .map(|key| ("tag-error", key))
            .or_else(|| {
                draft
                    .title
                    .trim()
                    .is_empty()
                    .then_some(("title-error", "vault-title-required"))
            });
        let record_error = record_problem.map(|(id, key)| {
            let text = self.locale.text(key);
            (
                id,
                ui.fonts_mut(|fonts| fonts.layout(text, caption_font, p.error, caption_width)),
            )
        });
        let mut footer_bounds = Vec::new();
        let footer_height = design::density(ui).control * footer_rows as f32
            + Metrics::SM * (footer_rows - 1) as f32
            + record_error
                .as_ref()
                .map_or(0., |(_, text)| text.size().y + Metrics::SM);
        let kinds: Vec<_> = app::FIELD_KINDS
            .iter()
            .map(|kind| (*kind, field_label(&self.locale, kind)))
            .collect();
        let geometry = record::contents(
            ui,
            "record-values",
            ui.available_height().max(1.),
            footer_height,
            |ui| {
                let title = if editing {
                    record::heading(
                        ui,
                        &mut draft.title,
                        true,
                        &self.locale.text("vault-record-title"),
                    )
                } else {
                    let mut title = if draft.title.is_empty() {
                        self.locale.text("vault-untitled")
                    } else {
                        draft.title.clone()
                    };
                    record::heading(ui, &mut title, false, "")
                };
                self.hits.insert("record-title".into(), title.rect);
                if editing && (title.gained_focus() || self.pending_focus == Some(title.id)) {
                    title.scroll_to_me(Some(egui::Align::TOP));
                }
                if title.changed() {
                    self.attachments.invalidate_size();
                }
                if !editing && !draft.tags.is_empty() {
                    layout::flow(ui, Metrics::SM, |ui| {
                        for tag in &draft.tags {
                            record::tag(ui, p, tag, record::TagRole::Neutral);
                        }
                    });
                }
                if !draft.fields.is_empty() {
                    ui.add_space(Metrics::LG);
                }
                let focus = editing
                    .then(|| self.validation_summary(ui, &draft))
                    .flatten();
                self.record_fields(ui, &mut draft, focus);
                if editing {
                    self.record_tags(ui, &mut draft);
                }
                self.history_list(ui, &draft);
            },
            editing.then_some(|ui: &mut egui::Ui| {
                ui.add_enabled_ui(enabled, |ui| {
                    layout::grid(
                        ui,
                        "record-add-actions",
                        1,
                        160.,
                        1,
                        Metrics::SM,
                        |ui, _| {
                            let response = record::add_field(ui, p, &add_label, |ui| {
                                footer_bounds.push((
                                    "field-menu".into(),
                                    egui::Rect::from_x_y_ranges(
                                        ui.max_rect().x_range(),
                                        ui.clip_rect().y_range(),
                                    ),
                                ));
                                for (kind, label) in &kinds {
                                    let response = ui.button(label);
                                    footer_hits.push((format!("add-{kind}"), response.rect));
                                    if response.clicked() {
                                        added = Some(*kind);
                                        ui.close();
                                    }
                                }
                                if can_group {
                                    ui.separator();
                                    let response = ui.button(&section_label);
                                    footer_hits.push(("add-section".into(), response.rect));
                                    if response.clicked() {
                                        added_section = true;
                                        ui.close();
                                    }
                                }
                            });
                            footer_hits.push(("add-field".into(), response.rect));
                        },
                    );
                    layout::grid(
                        ui,
                        "record-quick-actions",
                        2,
                        quick_width,
                        2,
                        Metrics::SM,
                        |ui, index| {
                            let (id, kind) = if index == 0 {
                                ("add-website", "url/v1")
                            } else {
                                ("add-location", "location/v1")
                            };
                            let response = design::button(
                                ui,
                                p,
                                &quick_labels[index],
                                ButtonRole::Secondary,
                                ui.available_width(),
                                true,
                            );
                            footer_hits.push((id.into(), response.rect));
                            if response.clicked() {
                                added = Some(kind);
                            }
                        },
                    );
                    layout::grid(
                        ui,
                        "record-save-actions",
                        2,
                        120.,
                        2,
                        Metrics::SM,
                        |ui, index| {
                            let (label, role, id, active) = if index == 0 {
                                (&save_label, ButtonRole::Primary, "save", valid_fields)
                            } else {
                                (&cancel_label, ButtonRole::Secondary, "cancel-edit", true)
                            };
                            let response =
                                design::button(ui, p, label, role, ui.available_width(), active);
                            footer_bounds.push((id.into(), response.rect));
                            if active {
                                footer_hits.push((id.into(), response.rect));
                            }
                            if index == 0 {
                                save |= response.clicked();
                            } else {
                                cancel |= response.clicked();
                            }
                        },
                    );
                    if let Some((id, error)) = record_error {
                        let response = ui.label(error);
                        footer_bounds.push((id.into(), response.rect));
                    }
                });
            }),
        );
        self.hits.extend(footer_hits);
        self.bounds.extend(footer_bounds);
        self.bounds
            .insert("record-viewport".into(), geometry.content);
        self.bounds.insert("record-footer".into(), geometry.footer);
        if let Some(kind) = added {
            let at = draft.fields.len();
            self.insert_record_field(&mut draft, kind, at, None);
        }
        if added_section && let Some(sections) = &mut draft.sections {
            sections.push(app::sections::Section::new("", draft.fields.len(), 0));
            self.section_ids.push(self.next_field);
            self.next_field += 1;
            self.attachments.invalidate_size();
        }
        let positions: Vec<_> = before_ids
            .iter()
            .map(|key| self.field_ids.iter().position(|id| id == key))
            .collect();
        app::wifi::remap(&mut draft.fields, &positions);
        save |= editing
            && enabled
            && !cancel
            && !popup_open
            && !egui::Popup::is_any_open(ui.ctx())
            && ui.memory(|memory| memory.focused().is_none())
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Enter));
        save &= self.record_valid(&draft);
        if save && self.apply_pending_tag(&mut draft) {
            self.request(
                Command::Save {
                    draft: draft.clone(),
                    epoch: epoch(),
                },
                false,
            );
            self.revealed.clear();
            self.clipboard.clear();
        }
        if cancel {
            self.tag_editor.clear();
            self.ssh.clear();
            self.totp_fields.clear();
            self.pending_totp.clear();
            self.date_fields.clear();
            self.totp_times.clear();
            self.revealed.clear();
            self.clipboard.clear();
            if let Some(baseline) = self.edit_baseline.take() {
                draft = baseline;
                self.reset_field_ids(draft.fields.len());
                self.editing = false;
            } else if let Some(revision) = draft.revision {
                self.request(
                    Command::OpenRevision {
                        record: draft.record,
                        revision,
                    },
                    false,
                );
            } else {
                self.mobile_detail = false;
                self.editing = false;
                return;
            }
        }
        self.draft = Some(draft);
    }
    pub fn status(&self) -> (&'static str, bool, usize, usize) {
        (
            match self.screen {
                Screen::Catalog => "catalog",
                Screen::Create => "create",
                Screen::Unlock => "unlock",
                Screen::Key => "key",
                Screen::Open => "open",
                Screen::Locking => "locking",
                Screen::Import => "import",
                Screen::Backup => "backup",
                Screen::Conflicts => "conflicts",
            },
            self.busy,
            self.catalog.len(),
            self.rows.len(),
        )
    }
    pub fn default_sync_server(&self) -> Option<String> {
        self.runtime.default_sync_server()
    }
    pub fn view_info(&self) -> (bool, usize, &'static str, u32, u32) {
        (
            self.editing,
            self.theme,
            self.locale.id(),
            self.clipboard.completed,
            self.clipboard.failed,
        )
    }
    pub fn error_code(&self) -> Option<&'static str> {
        self.error.map(error_key)
    }
}
impl Drop for VaultApp {
    fn drop(&mut self) {
        self.clear_private();
    }
}
impl eframe::App for VaultApp {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll();
        self.check_close(ctx);
        self.schedule_sync(ctx);
    }
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.show(ui);
        if std::mem::take(&mut self.defaults_changed)
            && let Some(storage) = frame.storage_mut()
        {
            self.save(storage);
            storage.flush();
        }
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.save_auto_lock_settings(storage);
        self.generator_preferences.save(storage);
        #[cfg(any(target_arch = "wasm32", target_os = "macos"))]
        storage.set_string(
            "device-unlock-minutes",
            self.device_unlock_minutes.to_string(),
        );
        storage.set_string("new-vault-sync-enabled", self.new_vault_sync.to_string());
        if let Ok(server) = app::sync::server_url(&self.new_vault_server) {
            storage.set_string("new-vault-sync-server", server);
        }
    }
    fn persist_egui_memory(&self) -> bool {
        false
    }
    #[cfg(target_arch = "wasm32")]
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}
fn lock_shortcut(ctx: &egui::Context) -> bool {
    let modifiers = if cfg!(target_arch = "wasm32") {
        egui::Modifiers::CTRL | egui::Modifiers::SHIFT
    } else {
        egui::Modifiers::COMMAND
    };
    ctx.input_mut(|input| input.consume_key(modifiers, egui::Key::L))
}

fn edit(
    ui: &mut egui::Ui,
    locale: &Localizer,
    hits: &mut BTreeMap<String, egui::Rect>,
    id: &str,
    label: &str,
    value: &mut String,
    secret: bool,
) {
    if id == "secret-key" {
        secret_key_field(ui, locale, hits, id, value, secret, true);
        return;
    }
    let label = ui.label(locale.text(label));
    let response = design::field_with_id(
        ui,
        egui::Id::unique(("vault-input", id)),
        value,
        secret,
        false,
        true,
    )
    .labelled_by(label.id);
    hits.insert(id.into(), response.rect);
}
fn key_symbol(character: char) -> bool {
    character != '-' && !character.is_ascii_whitespace()
}

fn format_secret_key(input: &str) -> String {
    let mut formatted = String::with_capacity(input.len());
    for (index, character) in input.chars().filter(|&c| key_symbol(c)).enumerate() {
        if index != 0 && index.is_multiple_of(7) {
            formatted.push('-');
        }
        formatted.push(character.to_ascii_uppercase());
    }
    formatted
}

fn key_cursor(input: &str, index: usize) -> usize {
    let symbols = input.chars().take(index).filter(|&c| key_symbol(c)).count();
    symbols + symbols.saturating_sub(1) / 7
}

fn secret_key_invalid(input: &str) -> bool {
    input
        .chars()
        .filter(|&c| key_symbol(c))
        .take(transfer_code::SYMBOLS)
        .count()
        == transfer_code::SYMBOLS
        && transfer_code::decode(input).is_err()
}

fn secret_key_field(
    ui: &mut egui::Ui,
    locale: &Localizer,
    hits: &mut BTreeMap<String, egui::Rect>,
    id: &str,
    value: &mut String,
    masked: bool,
    enabled: bool,
) {
    let label = ui.label(locale.text("vault-secret-key"));
    let widget = egui::Id::unique(("vault-input", id));
    let response =
        design::field_with_id(ui, widget, value, masked, false, enabled).labelled_by(label.id);
    hits.insert(id.into(), response.rect);
    if response.changed() {
        let mut formatted = zeroize::Zeroizing::new(format_secret_key(value));
        if *formatted != *value {
            if let Some(mut state) = egui::text_edit::TextEditState::load(ui.ctx(), widget)
                && let Some(mut range) = state.cursor.char_range()
            {
                for cursor in [&mut range.primary, &mut range.secondary] {
                    cursor.index = egui::text::CharIndex(key_cursor(value, cursor.index.0));
                }
                state.cursor.set_char_range(Some(range));
                state.store(ui.ctx(), widget);
            }
            value.zeroize();
            *value = std::mem::take(&mut *formatted);
            ui.ctx().request_repaint();
        }
    }
    if secret_key_invalid(value) {
        let error = ui.visuals().error_fg_color;
        ui.painter().rect_stroke(
            response.rect.expand(2.),
            Metrics::RADIUS,
            egui::Stroke::new(1., error),
            egui::StrokeKind::Inside,
        );
        let message = ui.add(
            egui::Label::new(RichText::new(locale.text("vault-error-key")).color(error)).wrap(),
        );
        hits.insert(format!("{id}-error"), message.rect);
    }
}
fn epoch() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|v| v.as_millis() as u64)
        .unwrap_or(0)
}
fn error_key(error: Error) -> &'static str {
    match error {
        Error::Auth => "vault-error-auth",
        Error::Key => "vault-error-key",
        Error::PasswordRequired => "vault-error-password-empty",
        Error::Input => "vault-error-input",
        Error::RecordLimit => "gallery-image-full",
        Error::Integrity => "vault-error-integrity",
        Error::Locked => "vault-error-locked",
        Error::Credentials => "vault-error-key",
        Error::Storage(confidex_storage::Error::Removing) => "remove-vault-cleanup-error",
        Error::Network => "sync-error-network",
        Error::Server(_) => "sync-error-server",
        Error::SyncDisabled => "sync-disabled",
        Error::Storage(confidex_storage::Error::Conflict) => "vault-error-conflict",
        Error::Storage(confidex_storage::Error::Quota) => "vault-error-quota",
        Error::Storage(_) => "vault-error-storage",
    }
}

fn field_visible(field: &app::Field) -> bool {
    if field.type_name == "ssh/v1" {
        return field.opaque > 0
            || field.data.as_ref().is_some_and(|data| !data.is_empty())
            || field.values.values().any(|text| !text.is_empty());
    }
    if matches!(field.type_name.as_str(), "photo/v1" | "file/v1") {
        return field.opaque > 0
            || field.data.as_ref().is_some_and(|data| {
                !data.is_empty()
                    || field
                        .values
                        .get("filename")
                        .is_some_and(|name| !name.is_empty())
            });
    }
    field.opaque > 0
        || !app::FIELD_KINDS.contains(&field.type_name.as_str())
        || field.values.values().any(|value| !value.is_empty())
}
fn field_label(locale: &Localizer, kind: &str) -> String {
    locale.text(match kind {
        "text/v1" => "vault-text",
        "username/v1" => "vault-username",
        "url/v1" => "vault-url",
        "secret/v1" => "vault-secret",
        "password/v1" => "vault-password",
        "note/v1" => "vault-note",
        "secure-note/v1" => "vault-secure-note",
        "wifi-qr/v1" => "gallery-field-kind-6",
        "photo/v1" => "gallery-field-kind-4",
        "file/v1" => "gallery-file",
        "card/v1" => "gallery-card",
        "totp/v1" => "gallery-totp",
        "ssh/v1" => "field-ssh-key",
        "date/v1" => "field-date",
        "month-year/v1" => "field-month-year",
        "location/v1" => "field-location-type",
        _ => return kind.to_owned(),
    })
}
fn value_protected(kind: &str, protected: bool, key: &str) -> bool {
    if kind == "ssh/v1" {
        key == "private_key"
    } else {
        protected
    }
}
fn field_kind(kind: &str, key: &str) -> value::Kind {
    if kind == "ssh/v1" && key == "private_key" {
        return value::Kind::Password;
    }
    match kind {
        "password/v1" | "secret/v1" => value::Kind::Password,
        "note/v1" | "secure-note/v1" => value::Kind::Multiline,
        _ => value::Kind::Text,
    }
}
fn template_label(locale: &Localizer, kind: &str) -> String {
    locale.text(&format!("template-{kind}"))
}
fn template_field_label(
    locale: &Localizer,
    kind: &str,
    index: usize,
    field: &app::Field,
) -> String {
    if let Some(template) = app::templates::get(kind)
        && let Some(spec) = template.fields.get(index)
    {
        return locale.text(&templates::name_key(spec.name));
    }
    if kind == "wifi" && index == 0 {
        return "SSID".into();
    }
    field_label(locale, &field.type_name)
}
fn localize_legacy_fields(locale: &Localizer, draft: &mut Draft) {
    for field in &mut draft.fields {
        if field.name.is_empty()
            && let Some(key) = &field.source_key
        {
            field.name = value_label(locale, key);
        }
    }
}

fn value_label(locale: &Localizer, key: &str) -> String {
    locale.text(match key {
        "username" => "vault-username",
        "password" => "vault-password",
        "secret" => "vault-secret",
        "url" => "vault-url",
        "text" => "vault-note",
        "date" => "field-date",
        "name" => "field-location",
        "latitude" => "field-latitude",
        "longitude" => "field-longitude",
        "public_key" => "ssh-public",
        "fingerprint" => "ssh-fingerprint",
        "private_key" => "ssh-private",
        "key_type" => "ssh-type",
        _ => return key.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn transfer_code_input_formats_and_checks_complete_keys() {
        let code = transfer_code::encode(&[1; 32], &[2; 32]);
        let expected = std::str::from_utf8(&*code).unwrap();
        let raw = expected.to_ascii_lowercase().replace('-', " ");
        assert_eq!(format_secret_key(&raw), expected);
        assert_eq!(format_secret_key("abcd efg hi"), "ABCDEFG-HI");
        assert_eq!(key_cursor("abcd efg hi", 9), 7);
        assert_eq!(key_cursor("abcd efg hi", 10), 9);
        assert!(!secret_key_invalid(expected));
        assert!(!secret_key_invalid(&expected[..expected.len() - 1]));
        let mut invalid = expected.to_owned();
        invalid.replace_range(..1, "B");
        assert!(secret_key_invalid(&invalid));
    }

    use super::*;
    #[derive(Clone, Default)]
    struct OnboardingRuntime {
        requests: std::rc::Rc<std::cell::RefCell<Vec<Request>>>,
        replies: std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<Response>>>,
    }
    impl Runtime for OnboardingRuntime {
        fn send(&mut self, request: Request) -> Result<(), Error> {
            self.requests.borrow_mut().push(request);
            Ok(())
        }
        fn receive(&mut self) -> Option<Response> {
            self.replies.borrow_mut().pop_front()
        }
        fn default_sync_server(&self) -> Option<String> {
            Some("https://sync.confidex.me/".into())
        }
    }
    fn onboarding_reply(
        runtime: &OnboardingRuntime,
        app: &mut VaultApp,
        output: Result<Output, Error>,
    ) {
        runtime.replies.borrow_mut().push_back(Response {
            generation: app.generation,
            result: output,
        });
        app.poll();
    }
    fn created_fixture() -> Output {
        Output::Created(app::Created {
            info: VaultInfo {
                id: [1; 16],
                name: "Public fixture".into(),
            },
            key: ["AAAAAAA"; 11].join("-"),
            remembered: true,
        })
    }
    #[test]
    fn home_import_creates_a_separate_destination_and_starts_after_key_confirmation() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            let original = VaultInfo {
                id: [2; 16],
                name: "Existing public vault".into(),
            };
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Catalog(vec![original.clone()])),
            );
            click(&ctx, &mut app, width, "import-new");
            assert!(app.screen == Screen::Create && app.import_after_create);
            click(&ctx, &mut app, width, "cancel");
            assert!(!app.import_after_create);
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Catalog(vec![original.clone()])),
            );
            click(&ctx, &mut app, width, "create");
            assert!(!app.import_after_create);
            click(&ctx, &mut app, width, "cancel");
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Catalog(vec![original.clone()])),
            );
            click(&ctx, &mut app, width, "import-new");
            app.name = "Public destination".into();
            app.password = "Public destination password".into();
            app.repeated = app.password.clone();
            app.create_sync = false;
            runtime.requests.borrow_mut().clear();
            click(&ctx, &mut app, width, "submit");
            assert!(matches!(
                runtime.requests.borrow()[0].command,
                Command::Create { .. }
            ));
            onboarding_reply(&runtime, &mut app, Ok(created_fixture()));
            assert!(app.screen == Screen::Key && !app.importer.window.open);
            draw(&ctx, &mut app, width, vec![]);
            assert!(!app.hits.contains_key("continue"));
            assert!(!app.importer.window.open);
            click(&ctx, &mut app, width, "key-saved");
            click(&ctx, &mut app, width, "continue");
            assert!(app.screen == Screen::Open && app.importer.window.open);
            assert!(!app.import_after_create);
            assert_eq!(app.importer.target, "Public fixture");
            assert_eq!(app.active.as_ref().unwrap().id, [1; 16]);
            assert_eq!(app.catalog[0].id, original.id);
            assert_eq!(app.catalog[0].name, original.name);
            assert_eq!(
                runtime
                    .requests
                    .borrow()
                    .iter()
                    .filter(|request| matches!(
                        request.command,
                        Command::VendorImport(app::import_flow::Command::Begin)
                    ))
                    .count(),
                1
            );
            app.clear_private();
            assert!(!app.importer.window.open && !app.import_after_create);
        }
    }
    #[test]
    fn weak_master_warning_follows_actions_and_does_not_block_creation() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            onboarding_reply(&runtime, &mut app, Ok(Output::Catalog(vec![])));
            runtime.requests.borrow_mut().clear();
            app.passwords.set_worker(|_, done| {
                done(Ok(design::password::Report {
                    bits: 2.,
                    score: 0,
                    advice: Some(0),
                }))
            });
            app.screen = Screen::Create;
            app.name = "Public strength fixture".into();
            app.password = "password".into();
            app.repeated = app.password.clone();
            for _ in 0..5 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let warning = app.bounds["master-password-warning"];
            assert!((app.hits["submit"].width() - app.hits["cancel"].width()).abs() < 1.);
            assert!(warning.top() > app.hits["submit"].bottom().max(app.hits["cancel"].bottom()));
            click(&ctx, &mut app, width, "submit");
            assert!(
                app.busy
                    && matches!(&runtime.requests.borrow()[0].command, Command::Create { password, .. } if password == "password")
            );
        }
    }
    #[test]
    fn record_strength_is_available_in_edit_and_reveal_and_clears_on_lock() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        let mut draft = app::new_record().unwrap();
        draft.fields = app::template("login").unwrap();
        draft.fields[1]
            .values
            .insert("password".into(), "public test password".into());
        app.reset_field_ids(draft.fields.len());
        app.draft = Some(draft);
        app.editing = true;
        draw(&ctx, &mut app, 1180., vec![]);
        assert!(app.bounds.contains_key("strength-1-password"));
        app.editing = false;
        draw(&ctx, &mut app, 1180., vec![]);
        assert!(!app.bounds.contains_key("strength-1-password"));
        app.revealed.insert((app.field_ids[1], "password".into()));
        draw(&ctx, &mut app, 1180., vec![]);
        assert!(app.bounds.contains_key("strength-1-password"));
        app.request(Command::Lock, true);
        assert!(
            app.draft.is_none()
                && app
                    .passwords
                    .report(egui::Id::unique(("vault-input", "password")))
                    .is_none()
        );
    }
    #[test]
    fn backup_actions_use_a_responsive_grid_and_keep_the_authentication_step() {
        for width in [320., 390., 1180.] {
            let runtime = OnboardingRuntime::default();
            let ctx = egui::Context::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            onboarding_reply(&runtime, &mut app, Ok(Output::Catalog(vec![])));
            draw(&ctx, &mut app, width, vec![]);
            let open = app.hits["import"];
            let import = app.hits["backup-import"];
            assert!((open.width() - import.width()).abs() < 1.);
            if width > 1000. {
                assert!((open.top() - import.top()).abs() < 1.);
            } else {
                assert!(import.top() >= open.bottom());
            }
            let pending = std::rc::Rc::new(std::cell::RefCell::new(None));
            let captured = pending.clone();
            app.set_backup_file_handler(move |request, done| {
                assert!(matches!(request, BackupFileRequest::Open));
                *captured.borrow_mut() = Some(done);
            });
            runtime.requests.borrow_mut().clear();
            click(&ctx, &mut app, width, "backup-import");
            assert!(app.busy && runtime.requests.borrow().is_empty());
            pending.borrow_mut().take().unwrap()(BackupFileReply::Opened(vec![1, 2, 3]));
            app.poll();
            assert!(
                matches!(&runtime.requests.borrow().last().unwrap().command, Command::InspectBackup { archive } if archive == &[1,2,3])
            );
            onboarding_reply(&runtime, &mut app, Ok(Output::BackupReady));
            draw(&ctx, &mut app, width, vec![]);
            assert!(app.files.importing && app.screen == Screen::Import);
            assert!(!app.hits.contains_key("sync-server"));
            app.error = Some(Error::Storage(confidex_storage::Error::Conflict));
            draw(&ctx, &mut app, width, vec![]);
            let submit = app.hits["submit"];
            let cancel = app.hits["cancel"];
            assert!((submit.width() - cancel.width()).abs() < 1.);
            if width > 1000. {
                assert!((submit.top() - cancel.top()).abs() < 1.);
            }
            assert!(app.bounds["form-error"].top() > submit.bottom().max(cancel.bottom()));
            app.key = "public-transfer-code-fixture".into();
            app.password = "public-password-fixture".into();
            app.sync_server.clear();
            click(&ctx, &mut app, width, "submit");
            assert!(
                matches!(&runtime.requests.borrow().last().unwrap().command, Command::RestoreBackup { password, key, .. } if password == "public-password-fixture" && key == "public-transfer-code-fixture")
            );
            app.files.clear();
            app.screen = Screen::Backup;
            app.busy = false;
            app.files.bytes = Some(vec![1, 2, 3]);
            app.files.notice = Some("backup-download-started");
            app.error = Some(Error::Network);
            draw(&ctx, &mut app, width, vec![]);
            let save = app.hits["backup-save"];
            let cancel = app.hits["backup-cancel"];
            assert!((save.width() - cancel.width()).abs() < 1.);
            if width > 1000. {
                assert!((save.top() - cancel.top()).abs() < 1.);
            }
            assert!(app.bounds["form-error"].top() > save.bottom().max(cancel.bottom()));
            app.request(Command::Lock, true);
            assert!(!app.files.importing && app.files.bytes.is_none());
        }
    }
    #[test]
    fn backup_waits_for_all_sync_pages_and_supports_an_offline_retry() {
        let runtime = OnboardingRuntime::default();
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
        app.screen = Screen::Backup;
        app.busy = false;
        app.sync_enabled = true;
        draw(&ctx, &mut app, 1180., vec![]);
        click(&ctx, &mut app, 1180., "backup-sync");
        assert!(app.files.after_sync);
        for more in [true, true, false] {
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Synced(app::sync::Report {
                    server: Some("https://sync.confidex.me/".into()),
                    more,
                    ..Default::default()
                })),
            );
            assert_eq!(
                matches!(
                    runtime.requests.borrow().last().unwrap().command,
                    Command::ExportBackup
                ),
                !more
            );
        }
        onboarding_reply(&runtime, &mut app, Err(Error::Network));
        assert!(!app.files.after_sync);
        draw(&ctx, &mut app, 1180., vec![]);
        click(&ctx, &mut app, 1180., "backup-offline");
        assert!(matches!(
            runtime.requests.borrow().last().unwrap().command,
            Command::ExportBackup
        ));
        onboarding_reply(&runtime, &mut app, Ok(Output::Backup(vec![3, 2, 1])));
        let saved = std::rc::Rc::new(std::cell::Cell::new(false));
        let captured = saved.clone();
        app.set_backup_file_handler(move |request, done| {
            assert!(matches!(request, BackupFileRequest::Save(bytes) if bytes == [3,2,1]));
            captured.set(true);
            done(BackupFileReply::Cancelled);
        });
        draw(&ctx, &mut app, 1180., vec![]);
        click(&ctx, &mut app, 1180., "backup-save");
        app.poll();
        assert!(saved.get() && app.files.bytes.is_some());
        assert!(app.files.notice.is_none());
    }
    #[test]
    fn creation_defaults_validate_server_and_always_remember_the_new_key() {
        for width in [390., 1180.] {
            let runtime = OnboardingRuntime::default();
            let ctx = egui::Context::default();
            ctx.all_styles_mut(|style| style.animation_time = 0.);
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.busy = false;
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "create");
            assert!(app.create_sync);
            assert_eq!(app.create_server, "https://sync.confidex.me/");
            assert!(app.hits.contains_key("create-sync-server"));
            click(&ctx, &mut app, width, "create-sync");
            assert!(!app.create_sync && !app.hits.contains_key("create-sync-server"));
            click(&ctx, &mut app, width, "create-sync");
            app.name = "Public fixture".into();
            app.password = "Public password".into();
            app.repeated = app.password.clone();
            app.create_server = "https://user:password@example.test/".into();
            runtime.requests.borrow_mut().clear();
            click(&ctx, &mut app, width, "submit");
            assert!(runtime.requests.borrow().is_empty());
            assert_eq!(app.error, Some(Error::Input));
            draw(&ctx, &mut app, width, vec![]);
            assert!(app.hits.contains_key("sync-server"));
            assert!(ctx.memory(|memory| {
                memory.has_focus(egui::Id::unique(("vault-input", "sync-server")))
            }));
            app.create_server = "http://sync.example.test/".into();
            app.remember = false;
            click(&ctx, &mut app, width, "submit");
            assert!(matches!(
                &runtime.requests.borrow()[0].command,
                Command::Create { remember: true, .. }
            ));
            assert_eq!(runtime.requests.borrow().len(), 1);
        }
    }
    #[test]
    fn creation_configures_sync_only_after_key_confirmation_and_offline_is_quiet() {
        for enabled in [false, true] {
            let runtime = OnboardingRuntime::default();
            let ctx = egui::Context::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.screen = Screen::Create;
            app.create_sync = enabled;
            app.create_server = "https://new-vault.example.test/".into();
            onboarding_reply(&runtime, &mut app, Ok(created_fixture()));
            runtime.requests.borrow_mut().clear();
            draw(&ctx, &mut app, 1180., vec![]);
            assert!(!app.hits.contains_key("continue"));
            assert!(runtime.requests.borrow().is_empty());
            app.saved_key = true;
            draw(&ctx, &mut app, 1180., vec![]);
            click(&ctx, &mut app, 1180., "continue");
            assert!(app.screen == Screen::Open);
            if enabled {
                assert!(
                    matches!(&runtime.requests.borrow()[0].command, Command::SyncConfig { server: Some(url) } if url == "https://new-vault.example.test/")
                );
                onboarding_reply(
                    &runtime,
                    &mut app,
                    Ok(Output::Synced(app::sync::Report {
                        server: Some("https://new-vault.example.test/".into()),
                        more: true,
                        ..Default::default()
                    })),
                );
                assert!(matches!(
                    &runtime.requests.borrow().last().unwrap().command,
                    Command::Sync { .. }
                ));
                onboarding_reply(&runtime, &mut app, Err(Error::Network));
                assert!(app.error.is_none() && app.sync_enabled && !app.busy);
            } else {
                assert!(matches!(
                    &runtime.requests.borrow()[0].command,
                    Command::List { .. } | Command::Search { .. }
                ));
            }
        }
    }
    #[test]
    fn exporting_an_existing_key_does_not_apply_creation_sync_defaults() {
        let runtime = OnboardingRuntime::default();
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
        app.screen = Screen::Open;
        app.create_sync = true;
        app.sync_enabled = true;
        app.sync_server = "https://existing.example.test/".into();
        onboarding_reply(&runtime, &mut app, Ok(created_fixture()));
        assert!(!app.create_sync);
        app.saved_key = true;
        runtime.requests.borrow_mut().clear();
        draw(&ctx, &mut app, 1180., vec![]);
        click(&ctx, &mut app, 1180., "continue");
        assert_eq!(app.sync_server, "https://existing.example.test/");
        assert!(
            !runtime
                .requests
                .borrow()
                .iter()
                .any(|r| matches!(&r.command, Command::SyncConfig { .. }))
        );
    }
    #[test]
    fn new_vault_preferences_persist_only_public_defaults_and_do_not_change_existing_vaults() {
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
        let mut app = VaultApp::new(&ctx, Box::new(OnboardingRuntime::default())).unwrap();
        app.password = "Public password sentinel".into();
        app.key = "Public secret-key sentinel".into();
        app.generator_preferences.length = 41;
        app.device_unlock_minutes = 30;
        app.sync_enabled = true;
        app.sync_server = "https://existing.example.test/".into();
        app.new_vault_sync = false;
        app.new_vault_server = "http://new.example.test".into();
        let mut storage = Storage::default();
        eframe::App::save(&mut app, &mut storage);
        let has_device_unlock_settings = cfg!(any(target_arch = "wasm32", target_os = "macos"));
        assert_eq!(storage.0.len(), 3 + usize::from(has_device_unlock_settings));
        assert!(
            storage
                .0
                .values()
                .all(|value| !value.contains("Public password sentinel")
                    && !value.contains("Public secret-key sentinel"))
        );
        assert!(!eframe::App::persist_egui_memory(&app));
        assert!(app.sync_enabled);
        assert_eq!(app.sync_server, "https://existing.example.test/");
        let mut restored = VaultApp::new(&ctx, Box::new(OnboardingRuntime::default())).unwrap();
        restored.restore_sync_defaults(Some(&storage));
        restored.restore_generator_preferences(Some(&storage));
        restored.restore_device_unlock_settings(Some(&storage));
        assert_eq!(
            restored.device_unlock_minutes,
            if has_device_unlock_settings {
                30
            } else {
                app::device_unlock::DEFAULT_MINUTES
            }
        );
        assert_eq!(restored.generator_preferences.length, 41);
        assert!(!restored.new_vault_sync);
        assert_eq!(restored.new_vault_server, "http://new.example.test/");
        restored.busy = false;
        draw(&ctx, &mut restored, 1180., vec![]);
        click(&ctx, &mut restored, 1180., "create");
        assert!(!restored.create_sync);
        assert_eq!(restored.create_server, "http://new.example.test/");
        storage.0.insert(
            "new-vault-sync-server".into(),
            "https://user:secret@example.test/".into(),
        );
        let mut clean = VaultApp::new(&ctx, Box::new(OnboardingRuntime::default())).unwrap();
        clean.restore_sync_defaults(Some(&storage));
        assert_eq!(clean.new_vault_server, "https://sync.confidex.me/");
    }
    struct Idle;
    impl Runtime for Idle {
        fn send(&mut self, _: Request) -> Result<(), Error> {
            Ok(())
        }
        fn receive(&mut self) -> Option<Response> {
            None
        }
    }
    #[test]
    fn wifi_can_be_added_selected_saved_and_shown_inline() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            let mut draft = app::new_record().unwrap();
            draft.title = "Public fixture".into();
            draft.fields = ["text/v1", "password/v1"]
                .map(app::field)
                .into_iter()
                .collect::<Result<_, _>>()
                .unwrap();
            draft.fields[0].name = "Same".into();
            draft.fields[1].name = "Same".into();
            draft.fields[0]
                .values
                .insert("text".into(), "Guest; café".into());
            draft.fields[1]
                .values
                .insert("password".into(), "public-password".into());
            let record = draft.record;
            app.draft = Some(draft);
            app.editing = true;
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "add-field");
            click(&ctx, &mut app, width, "add-wifi-qr/v1");
            let id = egui::Id::unique(("record-fields", record)).with(app.field_ids[2]);
            let prefix = format!("wifi-{}", id.value());
            for (name, index) in [("ssid", 0), ("password", 1)] {
                click(&ctx, &mut app, width, &format!("{prefix}-{name}"));
                let key = app.field_ids[index];
                click(&ctx, &mut app, width, &format!("{prefix}-{name}-{key}"));
            }
            click(&ctx, &mut app, width, "save");
            let requests = runtime.requests.borrow();
            let Command::Save { draft, .. } = &requests.last().unwrap().command else {
                panic!("save");
            };
            assert_eq!(draft.fields[2].values["ssid"], "0");
            assert_eq!(draft.fields[2].values["password"], "1");
            let saved = draft.clone();
            drop(requests);
            onboarding_reply(&runtime, &mut app, Ok(Output::Draft(saved)));
            draw(&ctx, &mut app, width, vec![]);
            let id = egui::Id::unique(("record-fields", record)).with(app.field_ids[2]);
            assert!(
                app.bounds
                    .contains_key(&format!("wifi-{}-code", id.value()))
            );
            app.clear_private();
            assert!(app.wifi_fields.is_empty());
        }
    }
    #[test]
    fn photo_picker_preparation_and_check_keep_the_draft_unchanged_until_apply() {
        use crate::{ImageCompletion, ImageFile, ImageReply, ImageRequest};
        use std::{cell::RefCell, rc::Rc};
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            let picker = Rc::new(RefCell::new(None::<ImageCompletion>));
            let capture = picker.clone();
            crate::ImageHost::set_image_handler(&mut app, move |request, done| {
                if matches!(request, ImageRequest::Open) {
                    *capture.borrow_mut() = Some(done);
                } else {
                    done(ImageReply::Cancelled);
                }
            });
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            draft.fields.push(app::field("photo/v1").unwrap());
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let key = app.field_ids[0];
            click(&ctx, &mut app, width, &format!("photo-{key}-choose"));
            let mut bytes = std::io::Cursor::new(Vec::new());
            image::DynamicImage::new_rgb8(2, 2)
                .write_to(&mut bytes, image::ImageFormat::Png)
                .unwrap();
            picker.borrow_mut().take().unwrap()(ImageReply::Opened(ImageFile {
                name: "public.png".into(),
                bytes: bytes.into_inner().into(),
            }));
            for _ in 0..100 {
                draw(&ctx, &mut app, width, vec![]);
                if !app.attachments.busy {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(app.attachments.window.open && !app.attachments.busy);
            assert!(
                app.draft.as_ref().unwrap().fields[0]
                    .data
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
            click(&ctx, &mut app, width, "photo-apply");
            assert!(app.attachments.pending.is_some());
            assert!(
                app.draft.as_ref().unwrap().fields[0]
                    .data
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
            let requests = runtime.requests.borrow();
            let Command::CheckDraft { draft } = &requests.last().unwrap().command else {
                panic!("preflight");
            };
            assert_eq!(draft.fields[0].values["mime"], "image/webp");
            assert_eq!(draft.fields[0].values["filename"], "public.webp");
            assert!(draft.fields[0].data.as_ref().unwrap().starts_with(b"RIFF"));
            drop(requests);
            onboarding_reply(&runtime, &mut app, Ok(Output::Checked { compressed: 100 }));
            draw(&ctx, &mut app, width, vec![]);
            assert!(!app.attachments.window.open);
            let choose = app.hits[&format!("photo-{key}-choose")];
            let reveal = app.hits[&format!("photo-{key}-reveal")];
            assert!((choose.width() - reveal.width()).abs() < 1.);
            assert!(
                !app.draft.as_ref().unwrap().fields[0]
                    .data
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
            click(&ctx, &mut app, width, &format!("photo-{key}-choose"));
            let late = picker.borrow_mut().take().unwrap();
            app.clear_private();
            late(ImageReply::Opened(ImageFile {
                name: "late.png".into(),
                bytes: vec![1, 2].into(),
            }));
            app.poll();
            assert!(
                app.draft.is_none()
                    && !app.attachments.window.open
                    && app.attachments.pending.is_none()
            );
        }
    }
    #[test]
    fn cancelling_a_record_check_discards_its_late_success_or_error() {
        for result in [
            Ok(Output::Checked { compressed: 42 }),
            Err(Error::RecordLimit),
        ] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.screen = Screen::Open;
            app.busy = true;
            let mut draft = app::new_record().unwrap();
            draft.fields.push(app::field("photo/v1").unwrap());
            app.reset_field_ids(1);
            let mut candidate = draft.fields[0].clone();
            candidate.data = Some(vec![1, 2, 3].into());
            app.draft = Some(draft);
            app.attachments.checking = true;
            app.attachments.pending = Some((app.field_ids[0], candidate));
            app.attachments.clear();
            onboarding_reply(&runtime, &mut app, result);
            assert!(!app.busy && app.error.is_none() && app.attachments.pending.is_none());
            assert!(
                app.draft.as_ref().unwrap().fields[0]
                    .data
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
        }
    }
    #[test]
    fn arbitrary_file_picker_checks_the_record_and_exports_exact_bytes() {
        use crate::{ImageCompletion, ImageFile, ImageReply, ImageRequest};
        use std::{cell::RefCell, rc::Rc};
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            let picker = Rc::new(RefCell::new(None::<ImageCompletion>));
            let capture = picker.clone();
            let saved = Rc::new(RefCell::new(None::<ImageFile>));
            let save = saved.clone();
            crate::ImageHost::set_image_handler(&mut app, move |request, done| match request {
                ImageRequest::OpenFile => *capture.borrow_mut() = Some(done),
                ImageRequest::Save(file) => {
                    *save.borrow_mut() = Some(file);
                    done(ImageReply::Saved);
                }
                _ => done(ImageReply::Cancelled),
            });
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            draft.fields.push(app::field("file/v1").unwrap());
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let key = app.field_ids[0];
            let bytes = if width == 390. {
                vec![0, 255, 128, 12]
            } else {
                vec![]
            };
            for accepted in [false, true] {
                draw(&ctx, &mut app, width, vec![]);
                click(&ctx, &mut app, width, &format!("file-{key}-choose"));
                picker.borrow_mut().take().unwrap()(ImageReply::Opened(ImageFile {
                    name: "product.license".into(),
                    bytes: bytes.clone().into(),
                }));
                app.poll();
                assert!(app.attachments.pending.is_some());
                let requests = runtime.requests.borrow();
                let Command::CheckDraft { draft } = &requests.last().unwrap().command else {
                    panic!("preflight");
                };
                assert_eq!(&**draft.fields[0].data.as_ref().unwrap(), bytes.as_slice());
                drop(requests);
                if accepted {
                    onboarding_reply(&runtime, &mut app, Ok(Output::Checked { compressed: 100 }));
                } else {
                    onboarding_reply(&runtime, &mut app, Err(Error::RecordLimit));
                    assert_eq!(app.draft.as_ref().unwrap().fields[0].values["filename"], "");
                    assert!(
                        app.draft.as_ref().unwrap().fields[0]
                            .data
                            .as_ref()
                            .unwrap()
                            .is_empty()
                    );
                }
            }
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let choose = app.hits[&format!("file-{key}-choose")];
            let save = app.hits[&format!("file-{key}-save")];
            assert!((choose.width() - save.width()).abs() < 1.);
            click(&ctx, &mut app, width, &format!("file-{key}-save"));
            app.poll();
            let saved = saved.borrow();
            let file = saved.as_ref().unwrap();
            assert_eq!(file.name, "product.license");
            assert_eq!(file.bytes.as_slice(), bytes.as_slice());
            assert_eq!(
                app.draft.as_ref().unwrap().fields[0].values["mime"],
                "application/octet-stream"
            );
        }
    }
    #[test]
    fn production_generators_apply_only_on_use_and_close_on_lock() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            let mut field = app::field("password/v1").unwrap();
            field
                .values
                .insert("password".into(), "Public original".into());
            draft.fields.push(field);
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "password-0-generate");
            assert!(app.bounds.contains_key("password-0-generator"));
            assert_eq!(
                app.draft.as_ref().unwrap().fields[0].values["password"],
                "Public original"
            );
            click(&ctx, &mut app, width, "password-0-generate");
            assert_eq!(
                app.draft.as_ref().unwrap().fields[0].values["password"],
                "Public original"
            );
            click(&ctx, &mut app, width, "password-0-generate");
            click(&ctx, &mut app, width, "password-0-generator-use");
            assert_ne!(
                app.draft.as_ref().unwrap().fields[0].values["password"],
                "Public original"
            );
            assert!(
                !runtime
                    .requests
                    .borrow()
                    .iter()
                    .any(|request| matches!(&request.command, Command::Save { .. }))
            );
            click(&ctx, &mut app, width, "password-0-generate");
            app.request(Command::Lock, true);
            assert!(app.draft.is_none() && !egui::Popup::is_any_open(&ctx));

            app.screen = Screen::Create;
            app.busy = false;
            app.name = "Public generated vault".into();
            app.password = "Public old master".into();
            app.repeated = app.password.clone();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "master-generate");
            assert_eq!(app.password, "Public old master");
            click(&ctx, &mut app, width, "master-generator-use");
            assert_ne!(app.password, "Public old master");
            assert_eq!(app.password, app.repeated);
        }
    }
    #[test]
    fn production_locations_validate_manual_input_and_preserve_copy() {
        use std::{cell::RefCell, rc::Rc};
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            let copied = Rc::new(RefCell::new(String::new()));
            let capture = copied.clone();
            app.set_clipboard_handler(move |text, done| {
                *capture.borrow_mut() = text;
                done(true);
            });
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            draft.title = "Public fixture".into();
            let record = draft.record;
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "add-field");
            click(&ctx, &mut app, width, "add-location/v1");
            assert_eq!(
                app.draft.as_ref().unwrap().fields[0].type_name,
                "location/v1"
            );
            let id = egui::Id::unique(("record-fields", record)).with(app.field_ids[0]);
            let prefix = format!("location-{}", id.value());
            let edit = |app: &mut VaultApp, key: &str, text: &str| {
                click(&ctx, app, width, &format!("{prefix}-{key}"));
                draw(
                    &ctx,
                    app,
                    width,
                    vec![
                        egui::Event::Key {
                            key: egui::Key::A,
                            physical_key: None,
                            pressed: true,
                            repeat: false,
                            modifiers: egui::Modifiers::COMMAND,
                        },
                        egui::Event::Text(text.into()),
                        egui::Event::Key {
                            key: egui::Key::A,
                            physical_key: None,
                            pressed: false,
                            repeat: false,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
                draw(&ctx, app, width, vec![]);
            };
            edit(&mut app, "name", "Public place");
            assert_eq!(
                app.draft.as_ref().unwrap().fields[0].name,
                app.locale.text("field-location-type")
            );
            edit(&mut app, "latitude", "91");
            assert!(!app.hits.contains_key("save"));
            edit(&mut app, "longitude", "4.90");
            assert!(!app.hits.contains_key("save"));
            edit(&mut app, "latitude", "52,37");
            assert!(app.hits.contains_key("save"));
            click(&ctx, &mut app, width, "save");
            let saved = {
                let requests = runtime.requests.borrow();
                let Command::Save { draft, .. } = &requests.last().unwrap().command else {
                    panic!("save");
                };
                assert_eq!(draft.fields[0].values["latitude"], "52,37");
                app::field_record(&draft.fields[0]).unwrap().entries[0]
                    .validate_value()
                    .unwrap();
                draft.clone()
            };
            onboarding_reply(&runtime, &mut app, Ok(Output::Draft(saved)));
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "copy-0-name");
            assert_eq!(copied.borrow().as_str(), "Public place");
            app.request(Command::Lock, true);
            assert!(app.draft.is_none());
        }
    }
    #[test]
    fn protected_dates_keep_reveal_and_hide_controls() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        app.mobile_detail = true;
        app.editing = true;
        let mut draft = app::new_record().unwrap();
        let record = draft.record;
        let mut field = app::field("date/v1").unwrap();
        field.protected = true;
        field.values.insert("date".into(), "29/02/2024".into());
        draft.fields.push(field);
        app.draft = Some(draft);
        for _ in 0..3 {
            draw(&ctx, &mut app, 390., vec![]);
        }
        let id = egui::Id::unique(("record-fields", record)).with(app.field_ids[0]);
        let prefix = format!("date-{}", id.value());
        assert!(!app.hits.contains_key(&format!("{prefix}-picker")));
        click(&ctx, &mut app, 390., "reveal-0-date");
        assert!(app.hits.contains_key(&format!("{prefix}-picker")));
        click(&ctx, &mut app, 390., &format!("{prefix}-hide"));
        assert!(!app.hits.contains_key(&format!("{prefix}-picker")));
        assert!(app.hits.contains_key("reveal-0-date"));
    }
    #[test]
    fn every_record_field_uses_the_common_header_and_type_slot() {
        for width in [390., 760., 1180.] {
            for kind in app::FIELD_KINDS {
                let ctx = egui::Context::default();
                let mut app = VaultApp::new(&ctx, Box::new(OnboardingRuntime::default())).unwrap();
                app.screen = Screen::Open;
                app.busy = false;
                app.mobile_detail = true;
                app.editing = true;
                let mut draft = app::new_record().unwrap();
                let mut field = app::field(kind).unwrap();
                field.name = "A field name".into();
                draft.fields.push(field);
                app.draft = Some(draft);
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                let name = app.hits["field-name-0"];
                let kind_slot = app.bounds["field-type-0"];
                let remove = app.hits["remove-0"];
                assert!(kind_slot.left() >= name.right(), "{kind} at {width}");
                assert!(kind_slot.right() < remove.left(), "{kind} at {width}");
                assert!(
                    (kind_slot.center().y - remove.center().y).abs() < 1.,
                    "{kind} at {width}"
                );
                assert!(app.bounds["field-0"].contains_rect(kind_slot));
                assert_eq!(app.draft.as_ref().unwrap().fields[0].name, "A field name");
            }
        }
    }
    #[test]
    fn production_dates_validate_pick_copy_and_clear_on_lock() {
        use std::{cell::RefCell, rc::Rc};
        for width in [390., 1180.] {
            for (kind, invalid, valid, pick, expected) in [
                ("date/v1", "29/02/2023", "29/02/2024", "day-1", "01/02/2024"),
                ("month-year/v1", "13/2024", "02/2024", "month-12", "12/2024"),
            ] {
                let ctx = egui::Context::default();
                let runtime = OnboardingRuntime::default();
                let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
                let copied = Rc::new(RefCell::new(String::new()));
                let capture = copied.clone();
                app.set_clipboard_handler(move |text, done| {
                    *capture.borrow_mut() = text;
                    done(true);
                });
                app.screen = Screen::Open;
                app.busy = false;
                app.mobile_detail = true;
                app.editing = true;
                let mut draft = app::new_record().unwrap();
                draft.title = "Public fixture".into();
                let record = draft.record;
                app.draft = Some(draft);
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                click(&ctx, &mut app, width, "add-field");
                click(&ctx, &mut app, width, &format!("add-{kind}"));
                assert_eq!(app.draft.as_ref().unwrap().fields[0].type_name, kind);
                let id = egui::Id::unique(("record-fields", record)).with(app.field_ids[0]);
                let prefix = format!("date-{}", id.value());
                click(&ctx, &mut app, width, &format!("{prefix}-input"));
                draw(
                    &ctx,
                    &mut app,
                    width,
                    vec![egui::Event::Text(invalid.into())],
                );
                draw(&ctx, &mut app, width, vec![]);
                assert!(!app.hits.contains_key("save"));
                assert_eq!(
                    app.draft.as_ref().unwrap().fields[0].values["date"],
                    invalid
                );
                click(&ctx, &mut app, width, &format!("{prefix}-input"));
                draw(
                    &ctx,
                    &mut app,
                    width,
                    vec![
                        egui::Event::Key {
                            key: egui::Key::A,
                            physical_key: None,
                            pressed: true,
                            repeat: false,
                            modifiers: egui::Modifiers::COMMAND,
                        },
                        egui::Event::Key {
                            key: egui::Key::A,
                            physical_key: None,
                            pressed: false,
                            repeat: false,
                            modifiers: egui::Modifiers::NONE,
                        },
                        egui::Event::Key {
                            key: egui::Key::Backspace,
                            physical_key: None,
                            pressed: true,
                            repeat: false,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
                draw(&ctx, &mut app, width, vec![]);
                assert_eq!(app.draft.as_ref().unwrap().fields[0].values["date"], "");
                click(&ctx, &mut app, width, &format!("{prefix}-input"));
                draw(&ctx, &mut app, width, vec![egui::Event::Text(valid.into())]);
                draw(&ctx, &mut app, width, vec![]);
                click(&ctx, &mut app, width, &format!("{prefix}-picker"));
                click(&ctx, &mut app, width, &format!("{prefix}-{pick}"));
                assert_eq!(
                    app.draft.as_ref().unwrap().fields[0].values["date"],
                    expected
                );
                click(&ctx, &mut app, width, "save");
                let saved = {
                    let requests = runtime.requests.borrow();
                    let Command::Save { draft, .. } = &requests.last().unwrap().command else {
                        panic!("save");
                    };
                    assert_eq!(draft.fields[0].values["date"], expected);
                    app::field_record(&draft.fields[0]).unwrap().entries[0]
                        .validate_value()
                        .unwrap();
                    draft.clone()
                };
                onboarding_reply(&runtime, &mut app, Ok(Output::Draft(saved)));
                draw(&ctx, &mut app, width, vec![]);
                click(&ctx, &mut app, width, "copy-0-date");
                assert_eq!(copied.borrow().as_str(), expected);
                app.locale = Localizer::new(1).unwrap();
                draw(&ctx, &mut app, width, vec![]);
                assert_eq!(
                    app.draft.as_ref().unwrap().fields[0].values["date"],
                    expected
                );
                app.request(Command::Lock, true);
                assert!(app.date_fields.is_empty() && app.draft.is_none());
            }
        }
    }
    #[test]
    fn production_card_uses_typed_controls_and_allows_a_bad_checksum() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            draft.title = "Public fixture".into();
            let mut field = app::field("card/v1").unwrap();
            field
                .values
                .insert("number".into(), "4111 1111 1111 1112".into());
            field.values.insert("cvv".into(), "123".into());
            draft.fields.push(field);
            let record = draft.record;
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let id = egui::Id::unique(("record-fields", record)).with(app.field_ids[0]);
            assert!(
                app.hits
                    .contains_key(&format!("card-{}-number", id.value()))
            );
            assert!(
                app.hits
                    .contains_key(&format!("card-{}-cvv-copy", id.value()))
            );
            click(&ctx, &mut app, width, "save");
            let requests = runtime.requests.borrow();
            let Command::Save { draft, .. } = &requests.last().unwrap().command else {
                panic!("save");
            };
            assert_eq!(draft.fields[0].values["number"], "4111 1111 1111 1112");
            drop(requests);
            app.clear_private();
            assert!(app.card_fields.is_empty());
        }
    }
    #[test]
    fn production_totp_editor_writes_binary_seed_and_blocks_invalid_parameters() {
        use std::{cell::RefCell, rc::Rc};
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            let copied = Rc::new(RefCell::new(String::new()));
            let capture = copied.clone();
            app.set_clipboard_handler(move |text, done| {
                *capture.borrow_mut() = text;
                done(true);
            });
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            draft.title = "Public fixture".into();
            draft.fields.push(app::field("totp/v1").unwrap());
            let record = draft.record;
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(!app.hits.contains_key("save"));
            let id = egui::Id::unique(("record-fields", record)).with(app.field_ids[0]);
            click(
                &ctx,
                &mut app,
                width,
                &format!("totp-{}-secret", id.value()),
            );
            draw(
                &ctx,
                &mut app,
                width,
                vec![egui::Event::Text("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into())],
            );
            draw(&ctx, &mut app, width, vec![]);
            assert_eq!(
                &**app.draft.as_ref().unwrap().fields[0].data.as_ref().unwrap(),
                b"12345678901234567890"
            );
            assert!(app.hits.contains_key("save"));
            let code = app.bounds[&format!("totp-{}-code", id.value())];
            let timer = app.bounds[&format!("totp-{}-timer", id.value())];
            assert!(code.right() <= timer.left());
            assert!(timer.right() <= app.hits[&format!("totp-{}-copy", id.value())].left());
            click(&ctx, &mut app, width, &format!("totp-{}-copy", id.value()));
            assert!(
                copied.borrow().len() == 6
                    && copied.borrow().bytes().all(|byte| byte.is_ascii_digit())
            );
            app.totp_times.insert(id.value(), (0, 0));
            draw(&ctx, &mut app, width, vec![]);
            assert!(app.clipboard.state(id.with("code")) == value::CopyState::Idle);
            app.totp_fields.get_mut(&id.value()).unwrap().period = "0".into();
            draw(&ctx, &mut app, width, vec![]);
            assert!(!app.hits.contains_key("save"));
            app.request(Command::Lock, true);
            assert!(app.totp_fields.is_empty() && app.totp_times.is_empty() && app.draft.is_none());
        }
    }
    #[test]
    fn record_view_uses_footer_space_but_editor_keeps_add_field() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            let mut draft = app::new_record().unwrap();
            draft.fields = (0..30).map(|_| app::field("text/v1").unwrap()).collect();
            for field in &mut draft.fields {
                field.values.insert("text".into(), "Public fixture".into());
            }
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let viewport = app.bounds["record-viewport"];
            assert_eq!(app.bounds["record-footer"], egui::Rect::NOTHING);
            assert!(!app.hits.contains_key("add-field"));
            assert!((viewport.bottom() - app.bounds["record-column"].bottom()).abs() < 2.);
            app.editing = true;
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(app.bounds["record-viewport"].height() < viewport.height() - Metrics::LG);
            assert!(app.bounds["record-footer"].contains_rect(app.hits["add-field"]));
            assert!(ctx.content_rect().contains_rect(app.hits["add-field"]));
        }
    }
    fn draw(ctx: &egui::Context, app: &mut VaultApp, width: f32, events: Vec<egui::Event>) {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(width, 1100.),
                )),
                events,
                ..Default::default()
            },
            |ui| app.show(ui),
        );
        output.textures_delta.clear();
    }
    fn click(ctx: &egui::Context, app: &mut VaultApp, width: f32, id: &str) {
        for _ in 0..30 {
            draw(ctx, app, width, vec![]);
        }
        if id.starts_with("add-") && id.ends_with("/v1") {
            for _ in 0..20 {
                let menu = app.bounds["field-menu"];
                let pos = app.hits[id].center();
                if menu.contains(pos) {
                    break;
                }
                draw(
                    ctx,
                    app,
                    width,
                    vec![
                        egui::Event::PointerMoved(egui::pos2(menu.left() + 4., menu.center().y)),
                        egui::Event::MouseWheel {
                            unit: egui::MouseWheelUnit::Point,
                            source: egui::MouseWheelSource::Unknown,
                            phase: egui::TouchPhase::Move,
                            delta: Vec2::new(0., if pos.y < menu.top() { 120. } else { -120. }),
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
                for _ in 0..15 {
                    draw(ctx, app, width, vec![]);
                }
            }
            assert!(
                app.bounds["field-menu"].contains(app.hits[id].center()),
                "{id}"
            );
        }
        let pos = app.hits[id].center();
        for pressed in [true, false] {
            draw(
                ctx,
                app,
                width,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        draw(ctx, app, width, vec![]);
    }
    #[test]
    fn template_picker_supports_keyboard_and_cancels_without_a_record() {
        for width in [390., 1320.] {
            let ctx = egui::Context::default();
            let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "new-record");
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(app.templates.open && app.draft.is_none());
            click(&ctx, &mut app, width, "template-close");
            assert!(!app.templates.open && app.draft.is_none());
            click(&ctx, &mut app, width, "new-record");
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "template-search");
            draw(&ctx, &mut app, width, vec![egui::Event::Text("API".into())]);
            for pressed in [true, false] {
                draw(
                    &ctx,
                    &mut app,
                    width,
                    vec![egui::Event::Key {
                        key: egui::Key::Enter,
                        physical_key: None,
                        pressed,
                        repeat: false,
                        modifiers: Default::default(),
                    }],
                );
            }
            let draft = app.draft.as_ref().unwrap();
            assert!(app.editing && !app.templates.open);
            assert_eq!(
                draft
                    .fields
                    .iter()
                    .map(|f| f.type_name.as_str())
                    .collect::<Vec<_>>(),
                [
                    "username/v1",
                    "secret/v1",
                    "text/v1",
                    "text/v1",
                    "date/v1",
                    "date/v1",
                    "text/v1",
                    "note/v1"
                ]
            );
            assert!(draft.fields.iter().all(|f| f.source.is_none()));
            click(&ctx, &mut app, width, "cancel-edit");
            assert!(app.draft.is_none() && !app.editing);
        }
    }
    #[test]
    fn identity_and_card_picker_preserve_role_names_and_independent_widgets() {
        for width in [390., 1320.] {
            for kind in ["identity", "credit-card"] {
                let ctx = egui::Context::default();
                let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
                app.screen = Screen::Open;
                app.busy = false;
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                click(&ctx, &mut app, width, "new-record");
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                click(&ctx, &mut app, width, "template-search");
                let label = template_label(&app.locale, kind);
                draw(&ctx, &mut app, width, vec![egui::Event::Text(label)]);
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                click(&ctx, &mut app, width, &format!("template-{kind}"));
                let draft = app.draft.as_ref().unwrap();
                assert_eq!(draft.fields.len(), 6);
                for (index, field) in draft.fields.iter().enumerate() {
                    assert_eq!(
                        field.name,
                        template_field_label(&app.locale, kind, index, field)
                    );
                }
                assert_ne!(draft.fields[0].name, draft.fields[1].name);
                assert!(app.editing && !app.templates.open);
                assert!(
                    !app.hits
                        .keys()
                        .any(|key| key.starts_with("password-") && key.ends_with("-generate"))
                );
                click(&ctx, &mut app, width, "cancel-edit");
                assert!(app.draft.is_none());
            }
        }
    }
    #[test]
    fn parallel_rows_open_and_reopen_only_the_acknowledged_revision() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            let head = |revision| confidex_storage::Head {
                record: [8; 16],
                revision: [revision; 32],
            };
            let row = |revision| app::Summary {
                head: head(revision),
                title: "Same public title".into(),
                fields: 0,
                tags: vec![],
            };
            app.rows = vec![row(1), row(2)];
            let mut draft = app::new_record().unwrap();
            draft.record = [8; 16];
            draft.revision = Some([1; 32]);
            draft.title = "Same public title".into();
            app.latest_revision = draft.revision;
            app.draft = Some(draft.clone());
            click(&ctx, &mut app, width, "record-1");
            assert!(matches!(
                runtime.requests.borrow().last().unwrap().command,
                Command::OpenRevision {
                    record: [8, ..],
                    revision: [2, ..]
                }
            ));
            draft.revision = Some([2; 32]);
            onboarding_reply(&runtime, &mut app, Ok(Output::Draft(draft)));
            assert_eq!(app.draft.as_ref().unwrap().revision, Some([2; 32]));
            onboarding_reply(&runtime, &mut app, Ok(Output::Saved(head(3))));
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Rows {
                    rows: vec![row(1), row(3)],
                    more: false,
                    next: None,
                }),
            );
            assert!(matches!(
                runtime.requests.borrow().last().unwrap().command,
                Command::OpenRevision {
                    record: [8, ..],
                    revision: [3, ..]
                }
            ));
        }
    }
    #[test]
    fn tag_search_restarts_pagination_and_clears_private_query_on_lock() {
        use std::{cell::RefCell, rc::Rc};
        struct Capture(Rc<RefCell<Vec<Request>>>);
        impl Runtime for Capture {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.0.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
        }
        let ctx = egui::Context::default();
        let requests = Rc::new(RefCell::new(vec![]));
        let mut app = VaultApp::new(&ctx, Box::new(Capture(requests.clone()))).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        app.search = "#work".into();
        app.next = Some(confidex_storage::Head {
            record: [4; 16],
            revision: [4; 32],
        });
        draw(&ctx, &mut app, 1180., vec![]);
        assert!(matches!(&requests.borrow().last().unwrap().command,
            Command::Search { after: None, tag: Some(tag), .. } if tag == "work"));
        assert!(app.next.is_none());
        app.request_list(Some(confidex_storage::Head {
            record: [5; 16],
            revision: [6; 32],
        }));
        assert!(matches!(&requests.borrow().last().unwrap().command,
            Command::Search { after: Some(id), tag: Some(tag), .. } if id.record == [5;16] && id.revision == [6;32] && tag == "work"));
        app.clear_private();
        assert!(app.search.is_empty() && app.listed_search.is_empty() && app.listed_tag.is_none());
    }
    #[test]
    fn full_search_waits_for_complete_index_and_discards_old_session_progress() {
        use std::{cell::RefCell, collections::VecDeque, rc::Rc};
        struct Queued(Rc<RefCell<VecDeque<Response>>>, Rc<RefCell<Vec<Request>>>);
        impl Runtime for Queued {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.1.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                self.0.borrow_mut().pop_front()
            }
        }
        let ctx = egui::Context::default();
        let replies = Rc::new(RefCell::new(VecDeque::new()));
        let sent = Rc::new(RefCell::new(vec![]));
        let mut app = VaultApp::new(&ctx, Box::new(Queued(replies.clone(), sent.clone()))).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        app.search = "note prefix".into();
        draw(&ctx, &mut app, 1180., vec![]);
        assert!(matches!(&sent.borrow().last().unwrap().command,
            Command::Search { query, after: None, refresh: false, .. } if query == "note prefix"));
        app.search = "latest query".into();
        replies.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Ok(Output::Indexing),
        });
        app.poll();
        assert!(app.busy && app.rows.is_empty());
        assert!(matches!(&sent.borrow().last().unwrap().command,
            Command::Search { query, .. } if query == "latest query"));
        let old_generation = app.generation;
        app.request(Command::Lock, true);
        let count = sent.borrow().len();
        replies.borrow_mut().push_back(Response {
            generation: old_generation,
            result: Ok(Output::Indexing),
        });
        app.poll();
        assert_eq!(sent.borrow().len(), count);
        assert!(app.search.is_empty() && app.listed_search.is_empty());
    }
    #[test]
    fn unlock_lists_local_records_before_trying_a_disconnected_server() {
        use std::{cell::RefCell, collections::VecDeque, rc::Rc};
        struct Queued(
            Rc<RefCell<VecDeque<Response>>>,
            Rc<RefCell<Vec<&'static str>>>,
        );
        impl Runtime for Queued {
            fn sync_available(&self) -> bool {
                true
            }
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.1.borrow_mut().push(match request.command {
                    Command::Search { .. } => "list",
                    Command::CheckSync { .. } => "check",
                    _ => "other",
                });
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                self.0.borrow_mut().pop_front()
            }
        }
        let ctx = egui::Context::default();
        let responses = Rc::new(RefCell::new(VecDeque::new()));
        let sent = Rc::new(RefCell::new(vec![]));
        let mut app =
            VaultApp::new(&ctx, Box::new(Queued(responses.clone(), sent.clone()))).unwrap();
        responses.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Ok(Output::Opened {
                info: VaultInfo {
                    id: [1; 16],
                    name: "Public offline fixture".into(),
                },
                remembered: true,
                server: Some("https://sync.example.test/".into()),
                device_unlock_verified_at: None,
            }),
        });
        app.poll();
        assert_eq!(sent.borrow().last(), Some(&"list"));
        responses.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Ok(Output::Rows {
                rows: vec![],
                more: false,
                next: None,
            }),
        });
        app.poll();
        assert_eq!(sent.borrow().last(), Some(&"check"));
        responses.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Err(Error::Network),
        });
        app.poll();
        assert!(app.screen == Screen::Open && !app.busy && app.sync_enabled);
        assert_eq!(app.error, None);
        assert!(app.sync_after_list.is_none());
    }
    #[test]
    fn sync_schedule_uses_foreground_background_focus_and_backoff() {
        let now = Instant::now();
        let mut timer = SyncSchedule::default();
        assert_eq!(timer.wait(now, true, 0), Duration::from_secs(60));
        assert_eq!(
            timer.wait(now + Duration::from_secs(59), true, 0),
            Duration::from_secs(1)
        );
        assert_eq!(
            timer.wait(now + Duration::from_secs(60), true, 0),
            Duration::ZERO
        );
        timer.finish(false);
        assert_eq!(timer.wait(now, false, 0), Duration::from_secs(300));
        assert_eq!(
            timer.wait(now + Duration::from_secs(1), true, 0),
            Duration::ZERO
        );
        timer.finish(true);
        assert_eq!(timer.wait(now, true, 0), Duration::from_secs(120));
        timer.finish(true);
        assert_eq!(timer.wait(now, true, 0), Duration::from_secs(240));
        for _ in 0..10 {
            timer.finish(true);
        }
        assert_eq!(timer.wait(now, true, 0), Duration::from_secs(900));
        timer.finish(false);
        assert_eq!(timer.wait(now, true, 7), Duration::from_secs(67));
        timer.saved();
        let saved = timer.due.unwrap();
        timer.wait(now, false, 0);
        assert_eq!(timer.due, Some(saved));
    }
    #[test]
    fn automatic_sync_suppresses_only_transient_errors() {
        struct Failing(Error);
        impl Runtime for Failing {
            fn send(&mut self, _: Request) -> Result<(), Error> {
                Err(self.0)
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
        }
        for automatic in [true, false] {
            for error in [
                Error::Network,
                Error::Server(503),
                Error::Server(429),
                Error::Integrity,
                Error::Server(403),
                Error::Storage(confidex_storage::Error::Quota),
            ] {
                let ctx = egui::Context::default();
                let mut app = VaultApp::new(&ctx, Box::new(Failing(error))).unwrap();
                app.screen = Screen::Open;
                app.sync_automatic = automatic;
                app.request(
                    Command::CheckSync {
                        server: "https://sync.example.test/".into(),
                    },
                    false,
                );
                let quiet = automatic && matches!(error, Error::Network | Error::Server(503 | 429));
                assert_eq!(app.error, if quiet { None } else { Some(error) });
                assert!(!app.busy && !app.sync_automatic);
            }
        }
    }
    #[test]
    fn automatic_checks_do_not_overlap_or_discard_the_open_record() {
        use std::{cell::RefCell, collections::VecDeque, rc::Rc};
        struct Queued(Rc<RefCell<VecDeque<Response>>>, Rc<RefCell<Vec<Request>>>);
        impl Runtime for Queued {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.1.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                self.0.borrow_mut().pop_front()
            }
            fn sync_available(&self) -> bool {
                true
            }
        }
        let ctx = egui::Context::default();
        let replies = Rc::new(RefCell::new(VecDeque::new()));
        let sent = Rc::new(RefCell::new(vec![]));
        let mut app = VaultApp::new(&ctx, Box::new(Queued(replies.clone(), sent.clone()))).unwrap();
        app.screen = Screen::Open;
        app.sync_enabled = true;
        app.busy = false;
        app.sync_server = "https://sync.example.test/".into();
        let now = Instant::now();
        app.sync_schedule.due = Some(now);
        app.editing = true;
        app.tick_sync(now, true);
        assert_eq!(sent.borrow().len(), 1);
        app.editing = false;
        let mut draft = app::new_record().unwrap();
        draft.title = "Public viewed record".into();
        app.draft = Some(draft);
        app.tick_sync(now, true);
        assert_eq!(sent.borrow().len(), 2);
        assert!(matches!(
            sent.borrow().last().unwrap().command,
            Command::CheckSync { .. }
        ));
        app.tick_sync(now + Duration::from_secs(1000), true);
        assert_eq!(sent.borrow().len(), 2);
        replies.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Ok(Output::SyncUnchanged),
        });
        app.poll();
        assert_eq!(app.draft.as_ref().unwrap().title, "Public viewed record");
        assert!(!app.busy);
        app.request(Command::Lock, true);
        app.tick_sync(now + Duration::from_secs(2000), true);
        assert_eq!(sent.borrow().len(), 3);
        assert!(app.sync_schedule.due.is_none());
    }
    #[test]
    fn equal_date_conflicts_require_a_choice_before_any_resolution() {
        use std::{cell::RefCell, collections::VecDeque, rc::Rc};
        struct Queued {
            responses: Rc<RefCell<VecDeque<Response>>>,
            sent: Rc<RefCell<Vec<Request>>>,
        }
        impl Runtime for Queued {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.sent.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                self.responses.borrow_mut().pop_front()
            }
        }
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let responses = Rc::new(RefCell::new(VecDeque::new()));
            let sent = Rc::new(RefCell::new(vec![]));
            let mut app = VaultApp::new(
                &ctx,
                Box::new(Queued {
                    responses: responses.clone(),
                    sent: sent.clone(),
                }),
            )
            .unwrap();
            responses.borrow_mut().push_back(Response {
                generation: app.generation,
                result: Ok(Output::Synced(app::sync::Report {
                    server: Some("https://sync.example.test/".into()),
                    conflicts: vec![app::sync::Conflict {
                        record: [1; 16],
                        local: app::sync::Version {
                            revision: [2; 32],
                            title: "Public local".into(),
                            epoch: 100,
                            deleted: false,
                        },
                        remote: app::sync::Version {
                            revision: [3; 32],
                            title: "Public remote".into(),
                            epoch: 100,
                            deleted: true,
                        },
                    }],
                    ..Default::default()
                })),
            });
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(app.screen == Screen::Conflicts);
            assert!(app.sync_choices.is_empty());
            assert!(!app.hits.contains_key("sync-apply"));
            click(&ctx, &mut app, width, "conflict-0-false");
            assert_eq!(app.sync_choices.get(&[1; 16]), Some(&false));
            click(&ctx, &mut app, width, "sync-apply");
            assert!(matches!(&sent.borrow().last().unwrap().command,
                Command::Resolve {record,local,remote,keep_local:false,..}
                if *record == [1;16] && *local == [2;32] && *remote == [3;32]));
            app.request(Command::Lock, true);
            assert!(app.sync_report.is_none() && app.comparison.is_none());
            assert!(app.sync_choices.is_empty() && app.resolve_queue.is_empty());
        }
    }
    #[test]
    fn lock_shortcut_uses_key_event_modifiers_after_a_fast_release() {
        let ctx = egui::Context::default();
        let mut output = ctx.run_ui(
            egui::RawInput {
                events: vec![
                    egui::Event::Key {
                        key: egui::Key::L,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers: egui::Modifiers::COMMAND,
                    },
                    egui::Event::Key {
                        key: egui::Key::L,
                        physical_key: None,
                        pressed: false,
                        repeat: false,
                        modifiers: Default::default(),
                    },
                ],
                ..Default::default()
            },
            |ui| {
                assert!(lock_shortcut(ui.ctx()));
                assert!(!lock_shortcut(ui.ctx()));
            },
        );
        output.textures_delta.clear();
    }
    #[test]
    fn locking_closes_large_type_and_removes_its_plaintext() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.busy = false;
        app.screen = Screen::Open;
        app.editing = true;
        let secret = "Public large-type sentinel";
        let mut draft = app::new_record().unwrap();
        let mut field = app::field("password/v1").unwrap();
        field.values.insert("password".into(), secret.into());
        draft.fields.push(field);
        app.reset_field_ids(1);
        app.draft = Some(draft);
        for _ in 0..3 {
            draw(&ctx, &mut app, 1320., vec![]);
        }
        click(&ctx, &mut app, 1320., "large-0-password");
        assert!(app.large_type.is_open());
        let modifiers = egui::Modifiers {
            command: true,
            ctrl: true,
            ..Default::default()
        };
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(1320., 1100.),
                )),
                events: vec![egui::Event::Key {
                    key: egui::Key::L,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers,
                }],
                ..Default::default()
            },
            |ui| app.show(ui),
        );
        output.textures_delta.clear();
        assert!(app.exit == Some(exit::Action::Lock) && app.draft.is_some());
        for _ in 0..3 {
            draw(&ctx, &mut app, 1320., vec![]);
        }
        click(&ctx, &mut app, 1320., "exit-confirm");
        assert!(!app.large_type.is_open() && app.draft.is_none());
        assert!(app.screen == Screen::Locking);
    }
    #[test]
    fn comparison_reveals_only_the_selected_side_after_many_fields() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.screen = Screen::Conflicts;
        app.busy = false;
        let mut local = app::new_record().unwrap();
        for _ in 0..129 {
            let mut field = app::field("password/v1").unwrap();
            field.values.clear();
            field
                .values
                .insert("password".into(), "Public local sentinel".into());
            local.fields.push(field);
        }
        let mut remote = app::new_record().unwrap();
        let mut field = app::field("password/v1").unwrap();
        field.values.clear();
        field
            .values
            .insert("password".into(), "Public remote sentinel".into());
        remote.fields.push(field);
        app.comparison = Some(([1; 16], [Some(local), Some(remote)]));
        app.revealed.insert((128, "password".into()));
        for frame in 0..3 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(1320., 100_000.),
                    )),
                    ..Default::default()
                },
                |ui| app.show(ui),
            );
            output.textures_delta.clear();
            if frame == 2 {
                let paints = |sentinel: &str| {
                    output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(t) if t.galley.job.text == sentinel))
                };
                assert!(paints("Public local sentinel"));
                assert!(!paints("Public remote sentinel"));
            }
        }
    }
    #[test]
    fn cancelling_a_stale_edit_restores_the_open_version_without_reloading() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            let mut draft = app::new_record().unwrap();
            draft.record = [8; 16];
            draft.revision = Some([1; 32]);
            draft.title = "Public original title".into();
            draft.fields.push(app::field("password/v1").unwrap());
            app.latest_revision = draft.revision;
            app.draft = Some(draft);
            click(&ctx, &mut app, width, "edit");
            assert!(app.editing && app.edit_baseline.is_some());
            app.draft.as_mut().unwrap().title = "Public unsaved title".into();
            app.latest_revision = None;
            runtime.requests.borrow_mut().clear();
            click(&ctx, &mut app, width, "cancel-edit");
            assert!(!app.editing && app.edit_baseline.is_none());
            assert_eq!(app.draft.as_ref().unwrap().title, "Public original title");
            assert_eq!(app.draft.as_ref().unwrap().revision, Some([1; 32]));
            assert!(app.latest_revision.is_none());
            assert!(runtime.requests.borrow().is_empty());
        }
    }
    #[test]
    fn synchronization_keeps_the_open_record_and_draft_and_reports_new_revisions() {
        for width in [390., 1180.] {
            for editing in [false, true] {
                for (base, head) in [
                    (Some([1; 32]), Some([1; 32])),
                    (Some([1; 32]), Some([2; 32])),
                    (Some([1; 32]), None),
                    (None, None),
                ] {
                    let ctx = egui::Context::default();
                    let runtime = OnboardingRuntime::default();
                    let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
                    app.busy = false;
                    app.screen = Screen::Open;
                    let mut draft = app::new_record().unwrap();
                    draft.record = [8; 16];
                    draft.revision = base;
                    draft.title = "Public unsaved title".into();
                    draft.tags = vec!["Public unsaved tag".into()];
                    let mut field = app::field("password/v1").unwrap();
                    field
                        .values
                        .insert("password".into(), "Public unsaved value".into());
                    draft.fields.push(field);
                    app.draft = Some(draft);
                    app.latest_revision = base;
                    app.field_ids = vec![44];
                    app.revealed.insert((44, "password".into()));
                    app.editing = editing;
                    app.mobile_detail = true;
                    runtime.requests.borrow_mut().clear();
                    onboarding_reply(&runtime, &mut app, Ok(Output::SyncUnchanged));
                    assert!(app.draft.is_some() && app.mobile_detail && app.editing == editing);
                    if head != base {
                        onboarding_reply(
                            &runtime,
                            &mut app,
                            Ok(Output::Synced(app::sync::Report {
                                server: Some("https://example.test/".into()),
                                more: true,
                                ..Default::default()
                            })),
                        );
                        onboarding_reply(
                            &runtime,
                            &mut app,
                            Ok(Output::RecordHead {
                                record: [8; 16],
                                revision: head,
                            }),
                        );
                        assert!(matches!(
                            runtime.requests.borrow().last().unwrap().command,
                            Command::Sync { .. }
                        ));
                        onboarding_reply(&runtime, &mut app, Err(Error::Network));
                        assert_eq!(app.latest_revision, head);
                        assert!(app.draft.is_some() && app.editing == editing && app.mobile_detail);
                    }
                    onboarding_reply(
                        &runtime,
                        &mut app,
                        Ok(Output::Synced(app::sync::Report {
                            server: Some("https://example.test/".into()),
                            downloaded: usize::from(head != base),
                            ..Default::default()
                        })),
                    );
                    assert!(matches!(
                        runtime.requests.borrow().last().unwrap().command,
                        Command::CheckRevision { record, .. } if record == [8; 16]
                    ));
                    onboarding_reply(
                        &runtime,
                        &mut app,
                        Ok(Output::RecordHead {
                            record: [8; 16],
                            revision: head,
                        }),
                    );
                    // The selected record can be absent from a filtered or paginated list.
                    onboarding_reply(
                        &runtime,
                        &mut app,
                        Ok(Output::Rows {
                            rows: vec![],
                            more: false,
                            next: None,
                        }),
                    );
                    for _ in 0..3 {
                        draw(&ctx, &mut app, width, vec![]);
                    }
                    let draft = app.draft.as_ref().unwrap();
                    assert_eq!(draft.title, "Public unsaved title");
                    assert_eq!(draft.tags, ["Public unsaved tag"]);
                    assert_eq!(draft.fields[0].values["password"], "Public unsaved value");
                    assert_eq!(draft.revision, base);
                    assert_eq!(app.latest_revision, head);
                    assert_eq!(app.field_ids, [44]);
                    assert!(app.revealed.contains(&(44, "password".into())));
                    assert!(
                        app.screen == Screen::Open && app.editing == editing && app.mobile_detail
                    );
                    assert!(runtime.requests.borrow().iter().all(|r| !matches!(
                        r.command,
                        Command::Open { .. } | Command::OpenRevision { .. }
                    )));
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(width, 1100.),
                            )),
                            ..Default::default()
                        },
                        |ui| app.show(ui),
                    );
                    let notice = app.locale.text("vault-record-updated");
                    assert_eq!(output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(t) if t.galley.job.text == notice)), head != base);
                    output.textures_delta.clear();
                    if editing {
                        click(&ctx, &mut app, width, "save");
                        let requests = runtime.requests.borrow();
                        let saved = &requests.last().unwrap().command;
                        assert!(
                            matches!(saved, Command::Save { draft, .. } if draft.revision == base)
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn synchronization_conflicts_do_not_replace_the_open_editor() {
        let ctx = egui::Context::default();
        let runtime = OnboardingRuntime::default();
        let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
        let mut draft = app::new_record().unwrap();
        draft.record = [8; 16];
        draft.revision = Some([1; 32]);
        draft.title = "Public unsaved title".into();
        app.draft = Some(draft);
        app.editing = true;
        app.mobile_detail = true;
        app.screen = Screen::Open;
        onboarding_reply(
            &runtime,
            &mut app,
            Ok(Output::Synced(app::sync::Report {
                server: Some("https://example.test/".into()),
                conflicts: vec![app::sync::Conflict {
                    record: [8; 16],
                    local: app::sync::Version {
                        revision: [1; 32],
                        title: "Local".into(),
                        epoch: 1,
                        deleted: false,
                    },
                    remote: app::sync::Version {
                        revision: [2; 32],
                        title: "Remote".into(),
                        epoch: 2,
                        deleted: true,
                    },
                }],
                ..Default::default()
            })),
        );
        onboarding_reply(
            &runtime,
            &mut app,
            Ok(Output::RecordHead {
                record: [8; 16],
                revision: Some([1; 32]),
            }),
        );
        onboarding_reply(
            &runtime,
            &mut app,
            Ok(Output::Rows {
                rows: vec![],
                more: false,
                next: None,
            }),
        );
        for _ in 0..3 {
            draw(&ctx, &mut app, 390., vec![]);
        }
        assert!(app.screen == Screen::Open && app.editing && app.mobile_detail);
        assert_eq!(app.draft.as_ref().unwrap().title, "Public unsaved title");
        assert!(app.hits.contains_key("record-conflicts"));
        onboarding_reply(&runtime, &mut app, Err(Error::Network));
        assert!(app.draft.is_some() && app.editing && app.mobile_detail);
        for has_draft in [true, false] {
            if !has_draft {
                app.draft = None;
            }
            app.screen = Screen::Conflicts;
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Synced(app::sync::Report {
                    server: Some("https://example.test/".into()),
                    ..Default::default()
                })),
            );
            assert!(app.screen == Screen::Open);
            assert_eq!(app.draft.is_some(), has_draft);
        }
    }
    #[test]
    fn sync_toggle_keeps_settings_geometry_while_busy_and_after_completion() {
        use std::{cell::RefCell, collections::VecDeque, rc::Rc};
        struct Queued(Rc<RefCell<VecDeque<Response>>>);
        impl Runtime for Queued {
            fn send(&mut self, _: Request) -> Result<(), Error> {
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                self.0.borrow_mut().pop_front()
            }
            fn sync_available(&self) -> bool {
                true
            }
        }
        for (width, locale) in [390., 1180.]
            .into_iter()
            .flat_map(|width| [0, 1, 7, 8].map(|locale| (width, locale)))
        {
            let ctx = egui::Context::default();
            let replies = Rc::new(RefCell::new(VecDeque::new()));
            let mut app = VaultApp::new(&ctx, Box::new(Queued(replies.clone()))).unwrap();
            ctx.all_styles_mut(|style| style.animation_time = 0.);
            app.locale = Localizer::new(locale).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            app.active = Some(VaultInfo {
                id: [1; 16],
                name: "Public fixture".into(),
            });
            app.sync_server = "https://example.test/".into();
            app.preferences_section = 1;
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "settings");
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let geometry = |app: &VaultApp| {
                [
                    app.bounds["preferences-window"],
                    app.hits["sync-server"],
                    app.hits["sync-enabled"],
                    app.bounds["preferences-sync-actions"],
                ]
            };
            let initial = geometry(&app);
            let backup = app.hits["backup-export"];
            let export = app.hits["export-key"];
            assert!(
                (backup.width() - export.width()).abs() < 1.,
                "{width}, {locale}: {backup:?} {export:?}"
            );
            assert!((backup.right() - export.right()).abs() < 1.);
            for enabled in [true, false] {
                click(&ctx, &mut app, width, "sync-enabled");
                assert!(app.busy);
                assert_eq!(geometry(&app), initial, "busy: {width}, {enabled}");
                replies.borrow_mut().extend([
                    Response {
                        generation: app.generation,
                        result: Ok(Output::Synced(app::sync::Report {
                            server: enabled.then(|| "https://example.test/".into()),
                            ..Default::default()
                        })),
                    },
                    Response {
                        generation: app.generation,
                        result: Ok(Output::Rows {
                            rows: vec![],
                            more: false,
                            next: None,
                        }),
                    },
                ]);
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                assert!(!app.busy && app.sync_enabled == enabled);
                assert_eq!(geometry(&app), initial, "complete: {width}, {enabled}");
                if enabled {
                    let sync = app.hits["sync-now"];
                    assert!((sync.width() - backup.width()).abs() < 1.);
                    assert!((sync.right() - backup.right()).abs() < 1.);
                }
            }
        }
    }
    #[test]
    fn renaming_current_and_locked_vaults_keeps_the_record_draft_and_handles_conflicts() {
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.catalog = vec![
                VaultInfo {
                    id: [1; 16],
                    name: "Current".into(),
                },
                VaultInfo {
                    id: [2; 16],
                    name: "Other".into(),
                },
            ];
            app.active = Some(app.catalog[0].clone());
            app.screen = Screen::Open;
            app.busy = false;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            draft.title = "Unsaved record".into();
            app.draft = Some(draft);
            app.preferences.open = true;
            app.preferences_section = 1;
            app.preferences_vault = Some(app.catalog[1].clone());
            runtime.requests.borrow_mut().clear();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            app.rename.name = "Local B".into();
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "rename-save");
            assert!(matches!(&runtime.requests.borrow().last().unwrap().command,
                Command::RenameVault { vault, expected, name } if *vault == [2;16] && expected == "Other" && name == "Local B"));
            onboarding_reply(
                &runtime,
                &mut app,
                Err(Error::Storage(confidex_storage::Error::Storage)),
            );
            assert_eq!(app.catalog[1].name, "Other");
            assert_eq!(app.rename.name, "Local B");
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "rename-save");
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::RenameConflict(VaultInfo {
                    id: [2; 16],
                    name: "Changed elsewhere".into(),
                })),
            );
            assert_eq!(app.catalog[1].name, "Changed elsewhere");
            assert_eq!(app.rename.name, "Local B");
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "rename-save");
            assert!(matches!(&runtime.requests.borrow().last().unwrap().command,
                Command::RenameVault { expected, .. } if expected == "Changed elsewhere"));
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Renamed(VaultInfo {
                    id: [2; 16],
                    name: "Local B".into(),
                })),
            );
            assert_eq!(app.catalog[1].name, "Local B");
            assert_eq!(app.preferences_vault.as_ref().unwrap().name, "Local B");
            assert_eq!(app.active.as_ref().unwrap().name, "Current");
            app.rename.name = "Cancelled".into();
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "rename-cancel");
            assert_eq!(app.rename.name, "Local B");
            app.preferences_vault = app.active.clone();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let before = runtime.requests.borrow().len();
            for name in [" ".to_owned(), "雪".repeat(43)] {
                app.rename.name = name;
                draw(&ctx, &mut app, width, vec![]);
                click(&ctx, &mut app, width, "rename-save");
                assert_eq!(runtime.requests.borrow().len(), before);
            }
            app.rename.name = "New A".into();
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "rename-save");
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Renamed(VaultInfo {
                    id: [1; 16],
                    name: "New A".into(),
                })),
            );
            assert_eq!(app.catalog[0].name, "New A");
            assert_eq!(app.active.as_ref().unwrap().name, "New A");
            app.rename.name = "Same name".into();
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "rename-save");
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::RenameConflict(VaultInfo {
                    id: [1; 16],
                    name: "Same name".into(),
                })),
            );
            assert!(app.rename.error.is_none() && !app.rename.pending);
            assert_eq!(app.active.as_ref().unwrap().name, "Same name");
            assert_eq!(app.draft.as_ref().unwrap().title, "Unsaved record");
            assert!(app.editing && app.screen == Screen::Open && app.preferences.open);
        }
    }
    #[test]
    fn vault_removal_keeps_other_drafts_and_handles_failures_and_current_cleanup() {
        use std::{cell::RefCell, rc::Rc};
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let runtime = OnboardingRuntime::default();
            let mut app = VaultApp::new(&ctx, Box::new(runtime.clone())).unwrap();
            app.catalog = (1..=2)
                .map(|id| VaultInfo {
                    id: [id; 16],
                    name: format!("Public vault {id}"),
                })
                .collect();
            app.active = Some(app.catalog[0].clone());
            app.screen = Screen::Open;
            app.busy = false;
            app.editing = true;
            let mut draft = app::new_record().unwrap();
            draft.title = "Unsaved public fixture".into();
            app.draft = Some(draft);
            app.preferences.open = true;
            app.preferences_section = 1;
            app.preferences_vault = Some(app.catalog[1].clone());
            runtime.requests.borrow_mut().clear();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let confirm = |app: &mut VaultApp| {
                let before = runtime.requests.borrow().len();
                for step in [1, 2] {
                    click(&ctx, app, width, "remove-confirm");
                    assert_eq!(app.removal.confirmation, step);
                    assert_eq!(runtime.requests.borrow().len(), before);
                    assert!(!app.busy && !app.removal.removing);
                }
                click(&ctx, app, width, "remove-confirm");
                assert_eq!(runtime.requests.borrow().len(), before + 1);
                assert!(app.busy && app.removal.removing);
            };
            click(&ctx, &mut app, width, "remove-vault");
            click(&ctx, &mut app, width, "remove-confirm");
            click(&ctx, &mut app, width, "remove-confirm");
            assert!(runtime.requests.borrow().is_empty());
            click(&ctx, &mut app, width, "remove-cancel");
            assert_eq!(app.removal.confirmation, 0);
            assert!(!app.removal.open && app.editing);
            click(&ctx, &mut app, width, "remove-vault");
            assert_eq!(app.removal.confirmation, 0);
            assert!(app.removal.open);
            for rect in [
                app.bounds["remove-dialog"],
                app.hits["remove-confirm"],
                app.hits["remove-cancel"],
            ] {
                assert!(
                    ctx.content_rect().expand(1.).contains_rect(rect),
                    "{width}: {rect:?}"
                );
            }
            confirm(&mut app);
            assert!(
                matches!(runtime.requests.borrow().last().unwrap().command, Command::RemoveVault {vault} if vault==[2;16])
            );
            onboarding_reply(
                &runtime,
                &mut app,
                Err(Error::Storage(confidex_storage::Error::Storage)),
            );
            assert!(app.removal.open && app.editing);
            assert_eq!(app.catalog.len(), 2);
            assert_eq!(app.draft.as_ref().unwrap().title, "Unsaved public fixture");
            draw(&ctx, &mut app, width, vec![]);
            confirm(&mut app);
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Removed {
                    vault: [2; 16],
                    result: Ok(()),
                }),
            );
            assert_eq!(app.catalog.len(), 1);
            assert_eq!(app.active.as_ref().unwrap().id, [1; 16]);
            assert!(app.editing && app.draft.is_some() && app.screen == Screen::Open);
            app.preferences_section = 1;
            app.preferences_vault = app.active.clone();
            app.removal.open = true;
            app.removal.target = app.active.clone();
            let copied = Rc::new(RefCell::new(Vec::new()));
            let captured = copied.clone();
            app.set_clipboard_handler(move |text, done| {
                captured.borrow_mut().push(text);
                done(true);
            });
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "remove-copy-key");
            assert!(
                matches!(&runtime.requests.borrow().last().unwrap().command, Command::PrepareRemoval {vault,synchronize:false,..} if *vault==[1;16])
            );
            let created = || app::Created {
                info: VaultInfo {
                    id: [1; 16],
                    name: "Public vault 1".into(),
                },
                key: "private-key-fixture-not-for-rendering".into(),
                remembered: true,
            };
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::RemovalPrepared {
                    created: created(),
                    report: None,
                }),
            );
            draw(&ctx, &mut app, width, vec![]);
            assert_eq!(
                copied.borrow().as_slice(),
                ["private-key-fixture-not-for-rendering"]
            );
            assert!(app.editing && app.draft.is_some());
            click(&ctx, &mut app, width, "remove-cancel");
            assert!(!app.removal.open && app.preferences.open && app.editing);
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::RemovalPrepared {
                    created: created(),
                    report: None,
                }),
            );
            assert!(app.created.is_none() && !app.removal.open && app.screen == Screen::Open);
            app.removal.open = true;
            app.removal.target = app.active.clone();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            confirm(&mut app);
            assert!(
                matches!(runtime.requests.borrow().last().unwrap().command, Command::RemoveVault {vault} if vault==[1;16])
            );
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Removed {
                    vault: [1; 16],
                    result: Err(Error::Credentials),
                }),
            );
            assert!(app.active.is_none() && app.draft.is_none() && !app.editing);
            assert_eq!(app.catalog.len(), 1);
            assert!(app.removal.open && app.preferences.open);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            confirm(&mut app);
            onboarding_reply(
                &runtime,
                &mut app,
                Ok(Output::Removed {
                    vault: [1; 16],
                    result: Ok(()),
                }),
            );
            assert!(app.catalog.is_empty() && app.active.is_none() && app.draft.is_none());
            assert!(
                app.screen == Screen::Catalog
                    && !app.editing
                    && !app.preferences.open
                    && !app.removal.open
            );
        }
    }
    #[test]
    fn settings_groups_all_vaults_and_switching_requires_unlock() {
        use std::{cell::RefCell, rc::Rc};
        struct Recording(Rc<RefCell<Vec<Request>>>);
        impl Runtime for Recording {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.0.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
        }
        for width in [390., 1180.] {
            let ctx = egui::Context::default();
            let requests = Rc::new(RefCell::new(Vec::new()));
            let mut app = VaultApp::new(&ctx, Box::new(Recording(requests.clone()))).unwrap();
            app.catalog = (1..=3)
                .map(|id| VaultInfo {
                    id: [id; 16],
                    name: format!("Public vault {id}"),
                })
                .collect();
            app.active = Some(app.catalog[0].clone());
            app.screen = Screen::Open;
            app.busy = false;
            app.draft = Some(app::new_record().unwrap());
            requests.borrow_mut().clear();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            click(&ctx, &mut app, width, "settings");
            if app.hits.contains_key("preferences-sections") {
                click(&ctx, &mut app, width, "preferences-sections");
            }
            assert!(app.hits.contains_key("preferences-section-1"));
            assert!(app.hits.contains_key("preferences-vault-1"));
            assert!(app.hits.contains_key("preferences-vault-2"));
            let group = app.bounds["preferences-vaults-heading"];
            let child = app.hits["preferences-section-1"];
            assert!(child.left() > group.left() && child.top() > group.bottom());
            app.editing = true;
            draw(&ctx, &mut app, width, vec![]);
            assert!(app.hits.contains_key("preferences-vault-1"));
            click(&ctx, &mut app, width, "preferences-vault-1");
            assert!(requests.borrow().is_empty());
            assert!(app.preferences.open && app.draft.is_some() && app.editing);
            assert_eq!(app.preferences_vault.as_ref().unwrap().id, [2; 16]);
            assert!(app.hits.contains_key("remove-vault"));
            app.editing = false;
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "preferences-unlock");
            assert_eq!(requests.borrow().len(), 1, "{width}: {:?}", app.hits);
            assert!(
                matches!(requests.borrow()[0].command, Command::Select { vault } if vault == [2;16])
            );
            assert!(!app.preferences.open && app.draft.is_none() && app.busy);
        }
    }
    #[test]
    fn quick_sync_opens_setup_or_uses_saved_server_without_duplicate_requests() {
        use std::{cell::RefCell, rc::Rc};
        struct Recording(Rc<RefCell<Vec<Request>>>);
        impl Runtime for Recording {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.0.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
            fn sync_available(&self) -> bool {
                true
            }
        }
        for width in [195., 320., 390., 1180., 1920.] {
            let ctx = egui::Context::default();
            let requests = Rc::new(RefCell::new(Vec::new()));
            let mut app = VaultApp::new(&ctx, Box::new(Recording(requests.clone()))).unwrap();
            requests.borrow_mut().clear();
            app.screen = Screen::Open;
            app.busy = false;
            app.sync_server = "https://saved.example.test/".into();
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let sync = app.hits["sync"];
            let settings = app.hits["settings"];
            assert!(sync.left() >= 0. && settings.right() <= width, "{width}");
            assert!(sync.center().distance(settings.center()) < 60., "{width}");
            click(&ctx, &mut app, width, "sync");
            assert!(app.preferences.open && !app.sync_enabled);
            assert!(requests.borrow().is_empty());
            assert_eq!(app.sync_server_draft, app.sync_server);
            assert!(app.hits.contains_key("sync-server") && !app.hits.contains_key("theme"));
            app.sync_server_draft = "https://unsaved.example.test/".into();
            if app.hits.contains_key("preferences-sections") {
                click(&ctx, &mut app, width, "preferences-sections");
            }
            click(&ctx, &mut app, width, "preferences-section-0");
            assert!(app.hits.contains_key("theme") && !app.hits.contains_key("sync-server"));
            click(&ctx, &mut app, width, "preferences-close");
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            app.sync_enabled = true;
            click(&ctx, &mut app, width, "sync");
            assert!(!app.preferences.open && app.busy && !app.sync_automatic);
            assert!(
                matches!(&requests.borrow()[0].command, Command::Sync { server }
                if server == "https://saved.example.test/")
            );
            assert!(!app.hits.contains_key("sync"));
            app.busy = false;
            app.editing = true;
            draw(&ctx, &mut app, width, vec![]);
            assert!(!app.hits.contains_key("sync"));
            assert_eq!(requests.borrow().len(), 1);
            app.editing = false;
            draw(&ctx, &mut app, width, vec![]);
            click(&ctx, &mut app, width, "settings");
            assert_eq!(app.sync_server_draft, "https://saved.example.test/");
        }
    }
    #[test]
    fn sync_spinner_stays_in_the_action_through_refresh_and_clears_on_completion() {
        struct WithSync(OnboardingRuntime);
        impl Runtime for WithSync {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.0.send(request)
            }
            fn receive(&mut self) -> Option<Response> {
                self.0.receive()
            }
            fn sync_available(&self) -> bool {
                true
            }
        }
        for width in [390., 1180.] {
            for automatic in [false, true] {
                let ctx = egui::Context::default();
                let runtime = OnboardingRuntime::default();
                let mut app = VaultApp::new(&ctx, Box::new(WithSync(runtime.clone()))).unwrap();
                onboarding_reply(&runtime, &mut app, Ok(Output::Catalog(vec![])));
                app.screen = Screen::Open;
                app.sync_enabled = true;
                app.sync_schedule.due = Some(Instant::now() + Duration::from_secs(3600));
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                let idle = app.bounds["sync-action"];
                app.sync_automatic = automatic;
                app.request(
                    if automatic {
                        Command::CheckSync {
                            server: "https://example.test/".into(),
                        }
                    } else {
                        Command::Sync {
                            server: "https://example.test/".into(),
                        }
                    },
                    false,
                );
                let render = |app: &mut VaultApp, spinner: bool| {
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(width, 1100.),
                            )),
                            time: Some(1.25),
                            ..Default::default()
                        },
                        |ui| app.show(ui),
                    );
                    output.textures_delta.clear();
                    assert_eq!(app.bounds["sync-action"], idle);
                    let paths = output.shapes.iter().filter(|shape| {
                        matches!(&shape.shape, egui::Shape::Path(path)
                            if path.stroke.width == 3. && path.points.iter().all(|point| idle.contains(*point)))
                    }).count();
                    assert_eq!(paths, usize::from(spinner));
                    assert!(
                        !output
                            .shapes
                            .iter()
                            .any(|shape| matches!(&shape.shape, egui::Shape::Text(text)
                        if text.galley.job.text == app.locale.text("vault-working")))
                    );
                };
                render(&mut app, true);
                assert!(app.syncing && app.busy && !app.hits.contains_key("sync"));
                onboarding_reply(
                    &runtime,
                    &mut app,
                    Ok(Output::Synced(app::sync::Report {
                        server: Some("https://example.test/".into()),
                        ..Default::default()
                    })),
                );
                assert!(app.syncing && app.busy);
                render(&mut app, true);
                onboarding_reply(
                    &runtime,
                    &mut app,
                    Ok(Output::Rows {
                        rows: vec![],
                        more: false,
                        next: None,
                    }),
                );
                assert!(!app.syncing && !app.busy);
                render(&mut app, false);
                app.request(
                    Command::CheckSync {
                        server: "https://example.test/".into(),
                    },
                    false,
                );
                onboarding_reply(&runtime, &mut app, Ok(Output::SyncUnchanged));
                assert!(!app.syncing && !app.busy);
                app.request(
                    Command::Sync {
                        server: "https://example.test/".into(),
                    },
                    false,
                );
                onboarding_reply(&runtime, &mut app, Err(Error::Network));
                assert!(!app.syncing && !app.busy && app.error == Some(Error::Network));
                app.error = None;
                app.request_list(None);
                render(&mut app, false);
            }
        }
    }
    #[test]
    fn preferences_fit_short_windows_at_large_interface_scales() {
        struct WithSync;
        impl Runtime for WithSync {
            fn send(&mut self, _: Request) -> Result<(), Error> {
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
            fn sync_available(&self) -> bool {
                true
            }
        }
        for zoom in [1., 1.5, 2.] {
            for size in [Vec2::new(390., 440.), Vec2::new(1320., 1000.)] {
                let ctx = egui::Context::default();
                let mut app = VaultApp::new(&ctx, Box::new(WithSync)).unwrap();
                ctx.set_zoom_factor(zoom);
                app.busy = false;
                app.preferences.open = true;
                for _ in 0..3 {
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                size / zoom,
                            )),
                            ..Default::default()
                        },
                        |ui| app.show(ui),
                    );
                    output.textures_delta.clear();
                }
                let popup = app.bounds["preferences-popup"];
                assert!(
                    ctx.content_rect().expand(1.).contains_rect(popup),
                    "{zoom}, {size:?}: {popup:?}"
                );
            }
        }
    }
    #[test]
    fn responses_clear_credentials_on_success_and_recover_missing_device_keys() {
        use std::{cell::RefCell, collections::VecDeque, rc::Rc};
        struct Queued(Rc<RefCell<VecDeque<Response>>>);
        impl Runtime for Queued {
            fn send(&mut self, _: Request) -> Result<(), Error> {
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                self.0.borrow_mut().pop_front()
            }
        }
        let responses = Rc::new(RefCell::new(VecDeque::new()));
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Queued(responses.clone()))).unwrap();
        app.screen = Screen::Unlock;
        app.remembered = true;
        app.password = "Public password".into();
        responses.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Err(Error::Key),
        });
        draw(&ctx, &mut app, 1180., vec![]);
        assert!(!app.remembered && app.hits.contains_key("secret-key"));
        assert_eq!(app.password, "Public password");

        for output in [
            Output::Created(app::Created {
                info: VaultInfo {
                    id: [1; 16],
                    name: "Public fixture".into(),
                },
                key: "Public transfer code".into(),
                remembered: true,
            }),
            Output::Opened {
                info: VaultInfo {
                    id: [1; 16],
                    name: "Public fixture".into(),
                },
                remembered: true,
                server: None,
                device_unlock_verified_at: None,
            },
        ] {
            app.password = "Public password".into();
            app.repeated = app.password.clone();
            app.key = "Public transfer code".into();
            app.show_password = true;
            responses.borrow_mut().push_back(Response {
                generation: app.generation,
                result: Ok(output),
            });
            app.poll();
            assert!(app.password.is_empty() && app.repeated.is_empty() && app.key.is_empty());
            assert!(!app.show_password);
        }
        app.screen = Screen::Locking;
        app.deleting = true;
        responses.borrow_mut().push_back(Response {
            generation: app.generation,
            result: Err(Error::Storage(confidex_storage::Error::Storage)),
        });
        app.poll();
        assert!(app.screen == Screen::Unlock && !app.deleting && !app.busy);
    }
    #[test]
    fn form_errors_follow_all_actions_and_fill_the_inner_width() {
        for width in [390., 1180.] {
            for (screen, action) in [
                (Screen::Create, "cancel"),
                (Screen::Import, "cancel"),
                (Screen::Unlock, "vaults"),
                (Screen::Key, "continue"),
                (Screen::Catalog, "backup-import"),
            ] {
                let ctx = egui::Context::default();
                let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
                app.screen = screen;
                app.busy = false;
                app.remembered = true;
                app.saved_key = true;
                app.error = Some(Error::Auth);
                for _ in 0..3 {
                    draw(&ctx, &mut app, width, vec![]);
                }
                let error = app.bounds["form-error"];
                let button = app.hits[action];
                assert!(error.top() > button.bottom(), "{action} at {width}");
                let card = app.bounds["form-card"];
                let inset = if width < 600. { 17. } else { 25. };
                assert!((error.left() - card.left() - inset).abs() < 1.);
                assert!((card.right() - error.right() - inset).abs() < 1.);
                if screen == Screen::Unlock {
                    assert!((app.hits["submit"].width() - button.width()).abs() < 1.);
                    assert!(error.top() > app.hits["submit"].bottom());
                }
            }
        }
    }
    #[test]
    fn form_focus_survives_reflow_and_validation_points_to_the_invalid_field() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.busy = false;
        app.screen = Screen::Create;
        app.name = "Public fixture".into();
        app.password = "Public password".into();
        app.repeated = "Public password".into();
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        click(&ctx, &mut app, 1180., "password");
        draw(
            &ctx,
            &mut app,
            1180.,
            vec![egui::Event::Key {
                key: egui::Key::End,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
        for width in [390., 1180.] {
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert_eq!(
                ctx.memory(|m| m.focused()),
                Some(egui::Id::unique(("vault-input", "password")).with("input"))
            );
            draw(&ctx, &mut app, width, vec![egui::Event::Text("x".into())]);
        }
        assert_eq!(app.password, "Public passwordxx");
        assert_eq!(app.repeated, "Public password");
        app.name = "  ".into();
        click(&ctx, &mut app, 1180., "submit");
        draw(&ctx, &mut app, 1180., vec![]);
        assert_eq!(app.error, Some(Error::Input));
        assert_eq!(
            ctx.memory(|m| m.focused()),
            Some(egui::Id::unique(("vault-input", "name")))
        );
    }
    #[test]
    fn escape_closes_the_add_menu_before_cancelling_the_record() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.busy = false;
        app.screen = Screen::Open;
        app.editing = true;
        app.mobile_detail = true;
        app.draft = Some(app::new_record().unwrap());
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        click(&ctx, &mut app, 1180., "add-field");
        assert!(egui::Popup::is_any_open(&ctx));
        for expected_editor in [true, false] {
            for pressed in [true, false] {
                draw(
                    &ctx,
                    &mut app,
                    1180.,
                    vec![egui::Event::Key {
                        key: egui::Key::Escape,
                        physical_key: None,
                        pressed,
                        repeat: false,
                        modifiers: Default::default(),
                    }],
                );
            }
            assert_eq!(app.editing, expected_editor);
        }
        assert!(app.draft.is_none());
    }
    #[test]
    fn failed_forms_keep_input_for_retry_and_navigation_hides_passwords() {
        struct Failing(Error);
        impl Runtime for Failing {
            fn send(&mut self, _: Request) -> Result<(), Error> {
                Err(self.0)
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
        }
        for (screen, error) in [
            (
                Screen::Create,
                Error::Storage(confidex_storage::Error::Quota),
            ),
            (Screen::Unlock, Error::Auth),
            (Screen::Import, Error::Network),
        ] {
            let ctx = egui::Context::default();
            let mut app = VaultApp::new(&ctx, Box::new(Failing(error))).unwrap();
            app.screen = screen;
            app.active = Some(VaultInfo {
                id: [1; 16],
                name: "Public fixture".into(),
            });
            app.name = "Public fixture".into();
            app.sync_server = "https://example.test/".into();
            app.password = "Public password".into();
            app.repeated = app.password.clone();
            app.key = "Public transfer-code fixture".into();
            app.show_password = true;
            for _ in 0..3 {
                draw(&ctx, &mut app, 1180., vec![]);
            }
            click(&ctx, &mut app, 1180., "submit");
            assert_eq!(app.error, Some(error));
            assert_eq!(
                app.password, "Public password",
                "failed form lost its password"
            );
            if screen == Screen::Create {
                assert_eq!(app.repeated, "Public password");
            } else {
                assert_eq!(
                    app.key, "Public transfer-code fixture",
                    "retry needs the transfer code"
                );
            }
            app.clear_private();
            assert!(app.password.is_empty() && app.repeated.is_empty() && app.key.is_empty());
            assert!(!app.show_password, "a new screen must conceal passwords");
        }
    }
    #[test]
    fn failed_lock_and_delete_leave_a_recoverable_screen() {
        struct Failing;
        impl Runtime for Failing {
            fn send(&mut self, _: Request) -> Result<(), Error> {
                Err(Error::Storage(confidex_storage::Error::Storage))
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
        }
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Failing)).unwrap();
        app.screen = Screen::Locking;
        app.active = Some(VaultInfo {
            id: [1; 16],
            name: "Public fixture".into(),
        });
        app.request(Command::Lock, true);
        assert!(
            app.screen == Screen::Unlock,
            "failed lock left a permanent spinner"
        );
        app.deleting = true;
        app.request_list(None);
        assert!(
            !app.deleting,
            "failed deletion must not classify a later save as deletion"
        );
    }
    #[test]
    fn enter_submits_forms_once_and_keeps_validation_and_disabled_guards() {
        use std::{cell::RefCell, rc::Rc};
        struct Capture(Rc<RefCell<Vec<Request>>>);
        impl Runtime for Capture {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.0.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
        }
        fn enter(ctx: &egui::Context, app: &mut VaultApp) {
            for pressed in [true, false] {
                draw(
                    ctx,
                    app,
                    1180.,
                    vec![egui::Event::Key {
                        key: egui::Key::Enter,
                        physical_key: None,
                        pressed,
                        repeat: false,
                        modifiers: Default::default(),
                    }],
                );
            }
        }
        let requests = Rc::new(RefCell::new(Vec::new()));
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Capture(requests.clone()))).unwrap();
        app.screen = Screen::Create;
        app.busy = false;
        app.name = "Public fixture".into();
        app.password = "Public password".into();
        app.repeated = "Mismatch".into();
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        requests.borrow_mut().clear();
        click(&ctx, &mut app, 1180., "repeat");
        enter(&ctx, &mut app);
        assert_eq!(app.error, Some(Error::Input));
        assert_eq!(app.password, "Public password");
        assert!(requests.borrow().is_empty());
        app.repeated = app.password.clone();
        click(&ctx, &mut app, 1180., "repeat");
        enter(&ctx, &mut app);
        assert!(matches!(
            requests.borrow()[0].command,
            Command::Create { .. }
        ));
        enter(&ctx, &mut app);
        assert_eq!(requests.borrow().len(), 1);

        app.screen = Screen::Unlock;
        app.busy = false;
        app.remembered = true;
        app.active = Some(VaultInfo {
            id: [1; 16],
            name: "Public fixture".into(),
        });
        app.password = "Public password".into();
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        requests.borrow_mut().clear();
        click(&ctx, &mut app, 1180., "password");
        enter(&ctx, &mut app);
        assert!(matches!(
            requests.borrow()[0].command,
            Command::Unlock { .. }
        ));
        enter(&ctx, &mut app);
        assert_eq!(requests.borrow().len(), 1);

        app.screen = Screen::Open;
        app.busy = false;
        app.editing = true;
        app.mobile_detail = true;
        let mut draft = app::new_record().unwrap();
        draft.title = "Public fixture".into();
        let mut note = app::field("note/v1").unwrap();
        note.values.insert("text".into(), "Public note".into());
        draft.fields.push(note);
        app.draft = Some(draft);
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        requests.borrow_mut().clear();
        click(&ctx, &mut app, 1180., "value-0-text");
        enter(&ctx, &mut app);
        assert!(app.draft.as_ref().unwrap().fields[0].values["text"].contains('\n'));
        assert!(requests.borrow().is_empty());
        click(&ctx, &mut app, 1180., "record-title");
        enter(&ctx, &mut app);
        assert!(matches!(requests.borrow()[0].command, Command::Save { .. }));
        enter(&ctx, &mut app);
        assert_eq!(requests.borrow().len(), 1);

        app.screen = Screen::Key;
        app.busy = false;
        app.saved_key = false;
        requests.borrow_mut().clear();
        draw(&ctx, &mut app, 1180., vec![]);
        enter(&ctx, &mut app);
        assert!(requests.borrow().is_empty());
        app.saved_key = true;
        app.preferences.open = true;
        enter(&ctx, &mut app);
        assert!(requests.borrow().is_empty());
        app.preferences.open = false;
        egui::Popup::close_all(&ctx);
        click(&ctx, &mut app, 1180., "key-saved");
        app.saved_key = true;
        enter(&ctx, &mut app);
        assert!(matches!(
            requests.borrow()[0].command,
            Command::Search { .. }
        ));
        enter(&ctx, &mut app);
        assert_eq!(requests.borrow().len(), 1);
    }
    #[test]
    fn entry_screens_fit_each_width_and_locking_has_one_status() {
        for locale in [0, 1] {
            let ctx = egui::Context::default();
            let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
            app.locale = Localizer::new(locale).unwrap();
            app.active = Some(VaultInfo {
                id: [1; 16],
                name: "Public fixture".into(),
            });
            app.created = Some(app::Created {
                info: app.active.clone().unwrap(),
                key: "AAAAAA-AAAAAAA-AAAAAA-AAAAAAA-AAAAAA-AAAAAAA-AAAAAA-AAAAAAA".into(),
                remembered: true,
            });
            app.remembered = false;
            app.sync_server = "https://example.test/".into();
            app.sync_report = Some(app::sync::Report {
                conflicts: vec![app::sync::Conflict {
                    record: [2; 16],
                    local: app::sync::Version {
                        revision: [3; 32],
                        title: "Public local fixture".into(),
                        epoch: 1,
                        deleted: false,
                    },
                    remote: app::sync::Version {
                        revision: [4; 32],
                        title: "Public remote fixture".into(),
                        epoch: 2,
                        deleted: true,
                    },
                }],
                ..Default::default()
            });
            for screen in [
                Screen::Catalog,
                Screen::Create,
                Screen::Key,
                Screen::Unlock,
                Screen::Locking,
                Screen::Import,
                Screen::Conflicts,
            ] {
                app.screen = screen;
                app.busy = screen == Screen::Locking;
                for width in [320., 600., 960., 1920.] {
                    for frame in 0..3 {
                        let mut output = ctx.run_ui(
                            egui::RawInput {
                                screen_rect: Some(egui::Rect::from_min_size(
                                    egui::Pos2::ZERO,
                                    Vec2::new(width, 1100.),
                                )),
                                ..Default::default()
                            },
                            |ui| app.show(ui),
                        );
                        output.textures_delta.clear();
                        if frame == 2 {
                            let card = app.bounds["form-card"];
                            assert!(card.left() >= 0. && card.right() <= width);
                            if screen == Screen::Locking {
                                let count = output.shapes.iter().filter(|shape| matches!(&shape.shape, egui::Shape::Text(t) if t.galley.job.text == app.locale.text("vault-locking"))).count();
                                assert_eq!(count, 1);
                                assert!(!output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(t) if t.galley.job.text == app.locale.text("vault-working"))));
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn viewing_hides_empty_values_and_editing_keeps_all_source_fields() {
        for width in [1180., 390.] {
            let ctx = egui::Context::default();
            let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
            app.screen = Screen::Open;
            app.busy = false;
            app.mobile_detail = true;
            let mut draft = app::new_record().unwrap();
            let mut login = app::template("login").unwrap();
            login[1].values.insert("password".into(), "  ".into());
            let mut note = app::field("note/v1").unwrap();
            note.protected = true;
            let mut opaque = note.clone();
            opaque.opaque = 1;
            let mut unknown = note.clone();
            unknown.type_name = "future/v7".into();
            let note_index = login.len();
            draft.fields = login;
            draft.fields.extend([note, opaque, unknown]);
            let expected = draft.clone();
            app.draft = Some(draft);
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            assert!(app.hits.contains_key("value-1-password"));
            assert!(!app.hits.contains_key("value-0-username"));
            assert!(!app.hits.contains_key("value-2-url"));
            assert!(!app.bounds.contains_key("field-0"));
            assert!(!app.bounds.contains_key("field-2"));
            assert!(!app.bounds.contains_key("field-3"));
            assert!(!app.bounds.contains_key(&format!("field-{note_index}")));
            assert!(
                app.bounds
                    .contains_key(&format!("field-{}", note_index + 1))
            );
            assert!(
                app.bounds
                    .contains_key(&format!("field-{}", note_index + 2))
            );
            app.editing = true;
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            for key in [
                "value-1-password",
                "value-0-username",
                "value-2-url",
                "value-3-text",
            ] {
                assert!(app.hits.contains_key(key), "{width}: {key}");
            }
            assert!(app.hits.contains_key(&format!("value-{note_index}-text")));
            let actual = app.draft.as_ref().unwrap();
            assert_eq!(
                (
                    &actual.record,
                    &actual.revision,
                    &actual.title,
                    &actual.tags
                ),
                (
                    &expected.record,
                    &expected.revision,
                    &expected.title,
                    &expected.tags
                )
            );
            assert_eq!(actual.fields.len(), expected.fields.len());
            for (actual, expected) in actual.fields.iter().zip(&expected.fields) {
                assert_eq!(
                    (
                        &actual.source,
                        &actual.source_key,
                        &actual.name,
                        &actual.type_name,
                        &actual.values,
                        actual.opaque,
                        actual.protected
                    ),
                    (
                        &expected.source,
                        &expected.source_key,
                        &expected.name,
                        &expected.type_name,
                        &expected.values,
                        expected.opaque,
                        expected.protected
                    )
                );
            }
        }
    }
    #[test]
    fn reordered_protected_notes_keep_their_source_and_save_the_same_values() {
        use std::{cell::RefCell, rc::Rc};
        struct Capture(Rc<RefCell<Vec<Request>>>);
        impl Runtime for Capture {
            fn send(&mut self, request: Request) -> Result<(), Error> {
                self.0.borrow_mut().push(request);
                Ok(())
            }
            fn receive(&mut self) -> Option<Response> {
                None
            }
        }
        let requests = Rc::new(RefCell::new(vec![]));
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Capture(requests.clone()))).unwrap();
        app.screen = Screen::Open;
        app.busy = false;
        app.editing = true;
        app.mobile_detail = true;
        let mut draft = app::new_record().unwrap();
        draft.title = "Public fixture".into();
        let mut login = app::field("username/v1").unwrap();
        login.source = Some(2);
        login.name = "same".into();
        login.values.insert("username".into(), "public-user".into());
        let mut note = app::field("note/v1").unwrap();
        note.source = Some(8);
        note.name = "same".into();
        note.protected = true;
        note.values.insert("text".into(), "public-note".into());
        draft.fields = vec![login, note];
        app.draft = Some(draft);
        for _ in 0..3 {
            draw(&ctx, &mut app, 1180., vec![]);
        }
        click(&ctx, &mut app, 1180., "field-handle-1");
        draw(
            &ctx,
            &mut app,
            1180.,
            vec![egui::Event::Key {
                key: egui::Key::ArrowUp,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
        assert_eq!(app.draft.as_ref().unwrap().fields[0].source, Some(8));
        for width in [390., 1180.] {
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let area = app.bounds["record-viewport"];
            assert!(
                app.bounds["record-footer"].top() > area.bottom(),
                "{width}: {:?} vs {area:?}",
                app.bounds["record-footer"]
            );
            assert!(ctx.content_rect().contains_rect(app.hits["save"]));
        }
        click(&ctx, &mut app, 1180., "save");
        let requests = requests.borrow();
        let Command::Save { draft, .. } = &requests.last().unwrap().command else {
            panic!("save")
        };
        assert_eq!(
            draft.fields.iter().map(|f| f.source).collect::<Vec<_>>(),
            [Some(8), Some(2)]
        );
        assert!(draft.fields[0].protected);
        assert_eq!(draft.fields[0].type_name, "note/v1");
        assert_eq!(draft.fields[0].values["text"], "public-note");
        assert_eq!(draft.fields[1].values["username"], "public-user");
    }
    #[test]
    fn secret_key_groups_flow_in_order_and_confirmation_stays_compact() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.busy = false;
        app.screen = Screen::Key;
        app.remembered = true;
        app.created = Some(app::Created {
            info: VaultInfo {
                id: [1; 16],
                name: "Fixture".into(),
            },
            key: ["AAAAAAA"; 11].join("-"),
            remembered: true,
        });
        for width in [1180., 720., 390., 320.] {
            for _ in 0..3 {
                draw(&ctx, &mut app, width, vec![]);
            }
            let groups: Vec<_> = (0..11)
                .map(|i| app.bounds[&format!("key-group-{i}")])
                .collect();
            for pair in groups.windows(2) {
                if (pair[0].top() - pair[1].top()).abs() < 1. {
                    assert!(pair[1].left() >= pair[0].right());
                } else {
                    assert!(pair[1].top() >= pair[0].bottom());
                }
            }
            assert!(
                groups
                    .iter()
                    .all(|r| app.bounds["form-card"].contains_rect(*r))
            );
            if width < 720. {
                assert!(groups[10].top() > groups[0].top());
            }
            let checkbox = app.hits["key-saved"];
            assert!(checkbox.top() - app.hits["copy-key"].bottom() <= Metrics::SM + 1.);
            assert!(checkbox.height() <= if width < 600. { 44. } else { 24. });
        }
    }
    #[test]
    fn forms_fit_and_resizing_preserves_the_editor() {
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Idle)).unwrap();
        app.busy = false;
        app.screen = Screen::Create;
        for width in [1180., 600., 390., 320.] {
            draw(&ctx, &mut app, width, vec![]);
            draw(&ctx, &mut app, width, vec![]);
            for id in ["name", "password", "repeat", "submit"] {
                let rect = app.hits[id];
                assert!(
                    rect.left() >= 0. && rect.right() <= width && rect.bottom() <= 1100.,
                    "{width} {id}: {rect:?}"
                );
            }
            assert!(app.hits["password"].top() > app.hits["name"].bottom());
            let card = app.bounds["form-card"];
            assert!(card.width() <= Metrics::CREATE_WIDTH + 2.);
            assert!((card.center().x - width / 2.).abs() <= 10.);
        }
        app.screen = Screen::Open;
        app.active = Some(VaultInfo {
            id: [1; 16],
            name: "Long vault name that must not overlap the controls".into(),
        });
        let mut draft = app::new_record().unwrap();
        draft.title = "Unsaved draft".into();
        draft.fields.push(app::field("note/v1").unwrap());
        draft.fields[0]
            .values
            .insert("text".into(), "Keep this text through every layout".into());
        app.draft = Some(draft);
        app.editing = true;
        app.mobile_detail = true;
        for width in [1180., 960., 720., 390., 320., 1180.] {
            draw(&ctx, &mut app, width, vec![]);
            draw(&ctx, &mut app, width, vec![]);
            for id in ["save", "cancel-edit", "lock", "settings"] {
                let rect = app.hits[id];
                assert!(
                    rect.left() >= 0. && rect.right() <= width && rect.bottom() <= 1100.,
                    "{width} {id}: {rect:?}"
                );
            }
            let before = app.theme;
            let target = if before == 0 { "theme-1" } else { "theme-0" };
            for id in ["settings", "theme", target] {
                let pos = app
                    .hits
                    .get(id)
                    .unwrap_or_else(|| panic!("{width} missing {id}: {:?}", app.hits.keys()))
                    .center();
                for pressed in [true, false] {
                    draw(
                        &ctx,
                        &mut app,
                        width,
                        vec![
                            egui::Event::PointerMoved(pos),
                            egui::Event::PointerButton {
                                pos,
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: Default::default(),
                            },
                        ],
                    );
                }
                draw(&ctx, &mut app, width, vec![]);
            }
            assert_ne!(app.theme, before);
            draw(
                &ctx,
                &mut app,
                width,
                vec![egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: Default::default(),
                }],
            );
            app.locale = app.locale.next().unwrap();
            assert_eq!(app.draft.as_ref().unwrap().title, "Unsaved draft");
            assert_eq!(
                app.draft.as_ref().unwrap().fields[0].values["text"],
                "Keep this text through every layout"
            );
        }
    }
}
