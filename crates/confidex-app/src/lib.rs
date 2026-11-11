//! Vault operations shared by GUI, browser workers, and future CLI hosts.
use confidex_storage::{Head, RecordId, RevisionId, Store, StoredVault, VaultId, VaultInfo};
pub use confidex_vault::BUILD_VERSION;
use confidex_vault::{
    entropy,
    envelope::{self, EventKind, Options},
    kdf, lock,
    record::{Entry, Record, Value},
    resources::MAX_OPEN_MEMORY,
    revisions::Graph,
    transfer_code,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};
pub mod backup;
mod blob;
pub mod device_unlock;
pub mod export;
pub mod export_flow;
pub use blob::Bytes;
mod fields;
pub mod history;
pub mod import;
pub mod import_apply;
pub mod import_flow;
pub mod local_sync;
mod search;
pub mod sections;
pub mod ssh;
pub mod sync;
pub mod templates;
mod trash;
pub mod wifi;
pub use fields::{FIELD_KINDS, data_key, field, field_record, template};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Error {
    Storage(confidex_storage::Error),
    Auth,
    Key,
    PasswordRequired,
    Input,
    RecordLimit,
    Integrity,
    Locked,
    Credentials,
    Network,
    SyncDisabled,
    Server(u16),
}
impl From<confidex_storage::Error> for Error {
    fn from(error: confidex_storage::Error) -> Self {
        Self::Storage(error)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub source: Option<usize>,
    #[serde(default)]
    pub source_key: Option<String>,
    pub name: String,
    pub type_name: String,
    pub values: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    pub opaque: usize,
    #[serde(default)]
    pub protected: bool,
}
impl Drop for Field {
    fn drop(&mut self) {
        self.name.zeroize();
        self.type_name.zeroize();
        self.source_key.zeroize();
        for (mut key, mut value) in std::mem::take(&mut self.values) {
            key.zeroize();
            value.zeroize();
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    pub record: RecordId,
    pub revision: Option<RevisionId>,
    pub title: String,
    pub fields: Vec<Field>,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sections: Option<Vec<sections::Section>>,
}
impl Drop for Draft {
    fn drop(&mut self) {
        self.title.zeroize();
        self.tags.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Summary {
    pub head: Head,
    pub title: String,
    pub fields: usize,
    pub tags: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct DeletedVersion {
    pub head: Head,
    pub title: String,
    pub source: RevisionId,
    pub epoch: u64,
}
impl Drop for DeletedVersion {
    fn drop(&mut self) {
        self.title.zeroize();
    }
}
impl Drop for Summary {
    fn drop(&mut self) {
        self.title.zeroize();
        self.tags.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub enum Command {
    Folder(local_sync::Command),
    VendorExport(export_flow::Command),
    ImportSsh {
        token: u64,
        data: Vec<u8>,
        password: Option<String>,
    },
    VendorImport(import_flow::Command),
    RenameVault {
        vault: VaultId,
        expected: String,
        name: String,
    },
    Catalog,
    Select {
        vault: VaultId,
    },
    Create {
        name: String,
        password: String,
        remember: bool,
    },
    Unlock {
        vault: VaultId,
        password: String,
        key: String,
        remember: bool,
    },
    EnrollDeviceUnlock {
        vault: VaultId,
        password: String,
        key: String,
        remember: bool,
    },
    Lock,
    ExportKey,
    PrepareRemoval {
        vault: VaultId,
        password: String,
        key: String,
        synchronize: bool,
    },
    RemoveVault {
        vault: VaultId,
    },
    InspectBackup {
        archive: Vec<u8>,
    },
    ExportBackup,
    RestoreBackup {
        name: String,
        password: String,
        key: String,
        remember: bool,
    },
    Sync {
        server: String,
    },
    CheckSync {
        server: String,
    },
    SyncConfig {
        server: Option<String>,
    },
    Import {
        name: String,
        password: String,
        key: String,
        server: String,
        remember: bool,
        #[serde(default)]
        use_device_unlock: Option<bool>,
    },
    Resolve {
        record: RecordId,
        local: RevisionId,
        remote: RevisionId,
        keep_local: bool,
        epoch: u64,
    },
    Compare {
        record: RecordId,
        local: RevisionId,
        remote: RevisionId,
    },
    List {
        after: Option<Head>,
        #[serde(default)]
        tag: Option<String>,
    },
    Search {
        query: String,
        after: Option<Head>,
        tag: Option<String>,
        #[serde(default)]
        refresh: bool,
    },
    Open {
        record: RecordId,
    },
    OpenRevision {
        record: RecordId,
        revision: RevisionId,
    },
    Save {
        draft: Draft,
        epoch: u64,
    },
    CheckDraft {
        draft: Draft,
    },
    SaveRevision {
        draft: Draft,
        parent: RevisionId,
        epoch: u64,
    },
    RecordHead {
        record: RecordId,
    },
    CheckRevision {
        record: RecordId,
        revision: Option<RevisionId>,
    },
    History {
        record: RecordId,
        cursor: Option<history::Cursor>,
    },
    Historical {
        record: RecordId,
        revision: RevisionId,
    },
    Delete {
        record: RecordId,
        expected: RevisionId,
        epoch: u64,
    },
    Trash {
        after: Option<Head>,
    },
    PreviewDeleted {
        head: Head,
        source: RevisionId,
    },
    RestoreDeleted {
        head: Head,
        source: RevisionId,
        epoch: u64,
    },
    SetDeviceUnlock {
        vault: VaultId,
        enabled: bool,
        password: String,
    },
}
impl Drop for Command {
    fn drop(&mut self) {
        match self {
            Self::ImportSsh { data, password, .. } => {
                data.zeroize();
                password.zeroize();
            }
            Self::List { tag, .. } => tag.zeroize(),
            Self::Search { query, tag, .. } => {
                query.zeroize();
                tag.zeroize();
            }
            Self::Create { password, .. } => password.zeroize(),
            Self::SetDeviceUnlock { password, .. } => password.zeroize(),
            Self::Unlock { password, key, .. }
            | Self::EnrollDeviceUnlock { password, key, .. }
            | Self::Import { password, key, .. }
            | Self::RestoreBackup { password, key, .. }
            | Self::PrepareRemoval { password, key, .. } => {
                password.zeroize();
                key.zeroize();
            }
            _ => (),
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Created {
    pub info: VaultInfo,
    pub key: String,
    pub remembered: bool,
}
impl Drop for Created {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub enum Output {
    Folder(Result<local_sync::Reply, local_sync::Error>),
    VendorExport(Result<export_flow::Reply, export_flow::Error>),
    Ssh {
        token: u64,
        result: Result<Field, ssh::Error>,
    },
    VendorImport(Result<import_flow::Reply, import_flow::Error>),
    Renamed(VaultInfo),
    RenameConflict(VaultInfo),
    RemovalPrepared {
        created: Created,
        report: Option<sync::Report>,
    },
    Removed {
        vault: VaultId,
        result: Result<(), Error>,
    },
    BackupReady,
    Backup(Vec<u8>),
    Catalog(Vec<VaultInfo>),
    Selected {
        info: VaultInfo,
        remembered: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_unlock_verified_at: Option<u64>,
    },
    Created(Created),
    Opened {
        info: VaultInfo,
        remembered: bool,
        server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_unlock_verified_at: Option<u64>,
    },
    Synced(sync::Report),
    SyncUnchanged,
    Compared {
        record: RecordId,
        local: Option<Draft>,
        remote: Option<Draft>,
    },
    Locked,
    Indexing,
    Rows {
        rows: Vec<Summary>,
        more: bool,
        next: Option<Head>,
    },
    Draft(Draft),
    History(history::Page),
    Historical {
        record: RecordId,
        revision: RevisionId,
        epoch: u64,
        draft: Option<Draft>,
    },
    RecordHead {
        record: RecordId,
        revision: Option<RevisionId>,
    },
    Saved(Head),
    Checked {
        compressed: usize,
    },
    TrashPage {
        rows: Vec<DeletedVersion>,
        next: Option<Head>,
    },
    Restored,
    DeviceUnlockChanged {
        verified_at: Option<u64>,
    },
}
#[derive(Serialize, Deserialize)]
pub struct Response {
    pub generation: u32,
    pub result: Result<Output, Error>,
}
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub generation: u32,
    pub command: Command,
}

#[allow(async_fn_in_trait)]
pub trait DeviceKeys {
    async fn remove(&mut self, vault: VaultId) -> bool;
    async fn load(&mut self, vault: VaultId) -> Option<String>;
    async fn save(&mut self, vault: VaultId, key: &str) -> bool;
    async fn has_saved_key(&mut self, vault: VaultId) -> bool {
        self.load(vault).await.map(Zeroizing::new).is_some()
    }
    async fn save_unprotected(&mut self, _: VaultId, _: &str) -> bool {
        false
    }
    fn device_unlock_minutes(&self) -> u16 {
        device_unlock::DEFAULT_MINUTES
    }
    fn now_ms(&self) -> Option<u64> {
        None
    }
    async fn device_unlock_verified_at(&mut self, _: VaultId) -> Option<u64> {
        None
    }
    async fn load_device_unlock(&mut self, _: VaultId) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    async fn save_device_unlock(&mut self, _: VaultId, _: u64, _: &[u8]) -> bool {
        false
    }
    async fn disable_device_unlock(&mut self, _: VaultId, _: &str) -> bool {
        false
    }
}

#[derive(Default)]
pub struct Engine {
    vault: Option<lock::OpenedVault>,
    search: Option<search::Index>,
    backup: Option<Vec<u8>>,
    history: Option<history::Session>,
    import_session: Option<import_apply::Session>,
    import_input: Option<import_flow::Input>,
    export_session: Option<export_flow::Session>,
}
impl Engine {
    pub async fn execute<S: Store, K: DeviceKeys>(
        &mut self,
        store: &mut S,
        keys: &mut K,
        request: &mut Request,
    ) -> Response {
        self.execute_with_transport(store, keys, &mut sync::Offline, request)
            .await
    }
    pub async fn execute_with_transport<S: Store, K: DeviceKeys, T: sync::Transport>(
        &mut self,
        store: &mut S,
        keys: &mut K,
        transport: &mut T,
        request: &mut Request,
    ) -> Response {
        Response {
            generation: request.generation,
            result: self.run(store, keys, transport, &mut request.command).await,
        }
    }
    async fn run<S: Store, K: DeviceKeys, T: sync::Transport>(
        &mut self,
        store: &mut S,
        keys: &mut K,
        transport: &mut T,
        command: &mut Command,
    ) -> Result<Output, Error> {
        if matches!(
            command,
            Command::Save { .. }
                | Command::SaveRevision { .. }
                | Command::Delete { .. }
                | Command::RestoreDeleted { .. }
                | Command::Sync { .. }
                | Command::Resolve { .. }
                | Command::ExportBackup
        ) {
            self.export_session = None;
        }
        if matches!(
            command,
            Command::Catalog
                | Command::Select { .. }
                | Command::Create { .. }
                | Command::Import { .. }
                | Command::Unlock { .. }
                | Command::EnrollDeviceUnlock { .. }
                | Command::Lock
        ) {
            self.backup = None;
        }
        match command {
            Command::Catalog
            | Command::Select { .. }
            | Command::Create { .. }
            | Command::Import { .. }
            | Command::RestoreBackup { .. }
            | Command::PrepareRemoval { .. }
            | Command::RemoveVault { .. }
            | Command::Unlock { .. }
            | Command::EnrollDeviceUnlock { .. }
            | Command::Lock => {
                self.search = None;
                self.history = None;
                self.import_session = None;
                self.import_input = None;
                self.export_session = None;
            }
            Command::Sync { .. } | Command::Resolve { .. } => {
                if let Some(index) = &mut self.search {
                    index.invalidate();
                }
            }
            _ => (),
        }
        let enroll_device_unlock = matches!(command, Command::EnrollDeviceUnlock { .. });
        match command {
            Command::SetDeviceUnlock {
                vault: target,
                enabled,
                password,
            } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let id = vault.vault_id();
                if id != *target {
                    return Err(Error::Locked);
                }
                let verified_at = if *enabled {
                    if password.is_empty() || password.len() > 4096 {
                        return Err(Error::PasswordRequired);
                    }
                    let stored = store.vault(id).await?;
                    let secret = Zeroizing::new(vault.keys().secret_key());
                    let (opened, unlock_key) = lock::open_with_unlock_key(
                        &stored.lock,
                        password.as_bytes(),
                        &secret,
                        kdf::REQUIRED_MEMORY,
                    )
                    .map_err(|_| Error::Auth)?;
                    if opened.vault_id() != id {
                        return Err(Error::Integrity);
                    }
                    Some(
                        device_unlock::remember(keys, id, &stored.lock, &secret, &unlock_key)
                            .await
                            .ok_or(Error::Credentials)?,
                    )
                } else {
                    let code = transfer_code::encode(
                        &vault.keys().secret_key(),
                        vault.keys().signing_key().verifying_key().as_bytes(),
                    );
                    let code =
                        Zeroizing::new(String::from_utf8(code.to_vec()).map_err(|_| Error::Key)?);
                    if !keys.disable_device_unlock(id, &code).await {
                        return Err(Error::Credentials);
                    }
                    None
                };
                Ok(Output::DeviceUnlockChanged { verified_at })
            }
            Command::Folder(command) => {
                #[cfg(not(target_arch = "wasm32"))]
                let result = self
                    .execute_folder(store, keys, command, &mut || true)
                    .await;
                #[cfg(target_arch = "wasm32")]
                let result = {
                    let _ = command;
                    Err(local_sync::Error::App(Error::SyncDisabled))
                };
                Ok(Output::Folder(result))
            }
            Command::VendorExport(command) => Ok(Output::VendorExport(
                self.execute_export(store, command, &mut |_| true).await,
            )),
            Command::ImportSsh {
                token,
                data,
                password,
            } => {
                if self.vault.is_none() {
                    return Err(Error::Locked);
                }
                Ok(Output::Ssh {
                    token: *token,
                    result: ssh::import(data, password.as_deref()),
                })
            }
            Command::VendorImport(command) => Ok(Output::VendorImport(
                self.execute_import(store, command, &mut import_flow::Quiet)
                    .await,
            )),
            Command::InspectBackup { archive } => {
                self.export_session = None;
                self.import_session = None;
                self.import_input = None;
                self.vault = None;
                self.search = None;
                self.history = None;
                self.backup = None;
                backup::inspect(archive)?;
                self.backup = Some(std::mem::take(archive));
                Ok(Output::BackupReady)
            }
            Command::ExportBackup => Ok(Output::Backup(
                backup::export(store, self.vault.as_ref().ok_or(Error::Locked)?).await?,
            )),
            Command::RestoreBackup {
                name,
                password,
                key,
                remember,
            } => {
                self.vault = None;
                let (snapshot, opened) = backup::restore(
                    self.backup.as_ref().ok_or(Error::Input)?,
                    name,
                    password,
                    key,
                )?;
                store.restore(&snapshot).await?;
                let remembered = *remember && keys.save(snapshot.vault.info.id, key).await;
                self.backup = None;
                self.vault = Some(opened);
                Ok(Output::Opened {
                    info: snapshot.vault.info,
                    remembered,
                    server: None,
                    device_unlock_verified_at: None,
                })
            }
            Command::Search {
                query,
                after,
                tag,
                refresh,
            } => {
                search::query_terms(query)?;
                if tag.as_ref().is_some_and(|tag| tag.len() > 256) {
                    return Err(Error::Input);
                }
                let result = self
                    .search(store, query, after.clone(), tag.as_deref(), *refresh)
                    .await;
                if result.is_err() {
                    self.search = None;
                }
                result
            }
            Command::Compare {
                record,
                local,
                remote,
            } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                sync::check_conflict(store, vault, *record, *local, *remote).await?;
                Ok(Output::Compared {
                    record: *record,
                    local: read_draft(store, vault, *record, *local).await?,
                    remote: read_draft(store, vault, *record, *remote).await?,
                })
            }
            Command::CheckSync { server } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let result = sync::check(store, transport, vault, server).await;
                if !matches!(&result, Ok(None))
                    && let Some(index) = &mut self.search
                {
                    index.invalidate();
                }
                Ok(match result? {
                    Some(report) => Output::Synced(report),
                    None => Output::SyncUnchanged,
                })
            }
            Command::Sync { server } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                Ok(Output::Synced(
                    sync::step(store, transport, vault, server).await?,
                ))
            }
            Command::SyncConfig { server } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let mut report = sync::configure(store, vault, server.as_deref()).await?;
                report.more = server.is_some();
                Ok(Output::Synced(report))
            }
            Command::Resolve {
                record,
                local,
                remote,
                keep_local,
                epoch,
            } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                sync::resolve(store, vault, *record, *local, *remote, *keep_local, *epoch).await?;
                Ok(Output::Synced(sync::Report {
                    server: sync::configured_server(store, vault.vault_id()).await?,
                    more: true,
                    ..sync::Report::default()
                }))
            }
            Command::Import {
                name,
                password,
                key,
                server,
                remember,
                use_device_unlock,
            } => {
                self.vault = None;
                if name.is_empty()
                    || name.len() > 128
                    || password.is_empty()
                    || password.len() > 4096
                {
                    return Err(Error::Input);
                }
                let code = transfer_code::decode(key).map_err(|_| Error::Key)?;
                let server = sync::server_url(server)?;
                let wire = sync::fetch_lock(transport, &server, code.id).await?;
                let (opened, unlock_key) = lock::open_with_unlock_key(
                    &wire,
                    password.as_bytes(),
                    &code.secret,
                    kdf::REQUIRED_MEMORY,
                )
                .map_err(|_| Error::Auth)?;
                if confidex_vault::sync::id(opened.keys().signing_key().verifying_key().as_bytes())
                    != code.id
                {
                    return Err(Error::Integrity);
                }
                let info = VaultInfo {
                    id: opened.vault_id(),
                    name: name.clone(),
                };
                let stored_lock_matches = match store.vault(info.id).await {
                    Ok(existing) => {
                        let header = lock::inspect(&existing.lock).map_err(|_| Error::Integrity)?;
                        if header.public_key != opened.anchor().public_key() {
                            return Err(Error::Integrity);
                        }
                        existing.lock == wire
                    }
                    Err(confidex_storage::Error::NotFound) => {
                        store
                            .create(&StoredVault {
                                info: info.clone(),
                                lock: wire.clone(),
                            })
                            .await?;
                        true
                    }
                    Err(error) => return Err(error.into()),
                };
                sync::configure(store, &opened, Some(&server)).await?;
                let device_unlock_verified_at = if *use_device_unlock == Some(true)
                    && stored_lock_matches
                {
                    device_unlock::remember(keys, info.id, &wire, &code.secret, &unlock_key).await
                } else {
                    None
                };
                let remembered = match use_device_unlock {
                    Some(true) => device_unlock_verified_at.is_some(),
                    Some(false) => *remember && keys.save_unprotected(info.id, key).await,
                    None => *remember && keys.save(info.id, key).await,
                };
                self.vault = Some(opened);
                Ok(Output::Opened {
                    info,
                    remembered,
                    server: Some(server),
                    device_unlock_verified_at,
                })
            }
            Command::RenameVault {
                vault,
                expected,
                name,
            } => {
                let name = name.trim();
                if name.is_empty() || name.len() > 128 || expected.len() > 128 {
                    return Err(Error::Input);
                }
                match store.rename(*vault, expected, name).await {
                    Ok(()) => Ok(Output::Renamed(VaultInfo {
                        id: *vault,
                        name: name.to_owned(),
                    })),
                    Err(confidex_storage::Error::Conflict) => {
                        Ok(Output::RenameConflict(store.vault(*vault).await?.info))
                    }
                    Err(error) => Err(error.into()),
                }
            }
            Command::Catalog => {
                self.vault = None;
                Ok(Output::Catalog(store.vaults().await?))
            }
            Command::Select { vault } => {
                self.vault = None;
                let info = store.vault(*vault).await?.info;
                let device_unlock_verified_at = keys.device_unlock_verified_at(*vault).await;
                let remembered =
                    device_unlock_verified_at.is_some() || keys.has_saved_key(*vault).await;
                Ok(Output::Selected {
                    info,
                    remembered,
                    device_unlock_verified_at,
                })
            }
            Command::Create {
                name,
                password,
                remember,
            } => {
                self.vault = None;
                if name.is_empty()
                    || name.len() > 128
                    || password.is_empty()
                    || password.len() > 4096
                {
                    return Err(Error::Input);
                }
                let created = lock::create(password.as_bytes(), kdf::REQUIRED_MEMORY)
                    .map_err(|_| Error::Auth)?;
                let info = VaultInfo {
                    id: created.vault.vault_id(),
                    name: name.clone(),
                };
                let text = transfer_code::encode(
                    &created.vault.keys().secret_key(),
                    created
                        .vault
                        .keys()
                        .signing_key()
                        .verifying_key()
                        .as_bytes(),
                );
                let mut key =
                    Zeroizing::new(String::from_utf8(text.to_vec()).map_err(|_| Error::Key)?);
                store
                    .create(&StoredVault {
                        info: info.clone(),
                        lock: created.lock,
                    })
                    .await?;
                let remembered = *remember && keys.save(info.id, &key).await;
                self.vault = Some(created.vault);
                Ok(Output::Created(Created {
                    info,
                    key: std::mem::take(&mut *key),
                    remembered,
                }))
            }
            Command::Unlock {
                vault,
                password,
                key,
                remember,
            }
            | Command::EnrollDeviceUnlock {
                vault,
                password,
                key,
                remember,
            } => {
                self.vault = None;
                if enroll_device_unlock && password.is_empty() {
                    return Err(Error::PasswordRequired);
                }
                let stored = store.vault(*vault).await?;
                let device_unlock_verified_at = keys.device_unlock_verified_at(*vault).await;
                if device_unlock_verified_at.is_some() && key.is_empty() {
                    let (opened, device_unlock_verified_at) =
                        device_unlock::open(store, keys, &stored, password).await?;
                    self.vault = Some(opened);
                    return Ok(Output::Opened {
                        info: stored.info,
                        remembered: true,
                        server: sync::configured_server(store, *vault).await?,
                        device_unlock_verified_at,
                    });
                }
                let cached;
                let text = if key.is_empty() {
                    cached = Zeroizing::new(keys.load(*vault).await.ok_or(Error::Key)?);
                    cached.as_str()
                } else {
                    key.as_str()
                };
                let (opened, unlock_key, code) = open_stored_with_key(&stored, password, text)?;
                audit(store, &opened).await?;
                let had_device_unlock = enroll_device_unlock || device_unlock_verified_at.is_some();
                let device_unlock_verified_at = if had_device_unlock {
                    device_unlock::remember(keys, *vault, &stored.lock, &code.secret, &unlock_key)
                        .await
                } else {
                    None
                };
                let remembered = if device_unlock_verified_at.is_some() || key.is_empty() {
                    true
                } else if had_device_unlock {
                    false
                } else {
                    *remember && keys.save(*vault, text).await
                };
                self.vault = Some(opened);
                Ok(Output::Opened {
                    info: stored.info,
                    remembered,
                    server: sync::configured_server(store, *vault).await?,
                    device_unlock_verified_at,
                })
            }
            Command::Lock => {
                self.vault = None;
                Ok(Output::Locked)
            }
            Command::RemoveVault { vault } => {
                store.clear_records(*vault).await?;
                self.backup = None;
                if self.vault.as_ref().is_some_and(|v| v.vault_id() == *vault) {
                    self.vault = None;
                    self.search = None;
                    self.history = None;
                }
                let result = if keys.remove(*vault).await {
                    store.remove(*vault).await.map_err(Error::from)
                } else {
                    Err(Error::Credentials)
                };
                Ok(Output::Removed {
                    vault: *vault,
                    result,
                })
            }
            Command::PrepareRemoval {
                vault,
                password,
                key,
                synchronize,
            } => {
                let stored = store.vault(*vault).await?;
                let temporary;
                let cached;
                let opened =
                    if let Some(opened) = self.vault.as_ref().filter(|v| v.vault_id() == *vault) {
                        opened
                    } else {
                        let text = if key.is_empty() {
                            cached = Zeroizing::new(keys.load(*vault).await.ok_or(Error::Key)?);
                            cached.as_str()
                        } else {
                            key.as_str()
                        };
                        temporary = open_stored(&stored, password, text)?;
                        audit(store, &temporary).await?;
                        &temporary
                    };
                let report = if *synchronize {
                    let server = sync::configured_server(store, *vault)
                        .await?
                        .ok_or(Error::SyncDisabled)?;
                    if let Some(index) = self.search.as_mut() {
                        index.invalidate();
                    }
                    Some(sync::step(store, transport, opened, &server).await?)
                } else {
                    None
                };
                let text = transfer_code::encode(
                    &opened.keys().secret_key(),
                    opened.keys().signing_key().verifying_key().as_bytes(),
                );
                Ok(Output::RemovalPrepared {
                    created: Created {
                        info: stored.info,
                        key: String::from_utf8(text.to_vec()).map_err(|_| Error::Key)?,
                        remembered: keys.has_saved_key(*vault).await,
                    },
                    report,
                })
            }
            Command::ExportKey => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let info = store.vault(vault.vault_id()).await?.info;
                let text = transfer_code::encode(
                    &vault.keys().secret_key(),
                    vault.keys().signing_key().verifying_key().as_bytes(),
                );
                Ok(Output::Created(Created {
                    remembered: keys.has_saved_key(info.id).await,
                    info,
                    key: String::from_utf8(text.to_vec()).map_err(|_| Error::Key)?,
                }))
            }
            Command::List { after, tag } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let heads = store
                    .branch_heads(vault.vault_id(), after.as_ref(), tag.as_deref())
                    .await?;
                let more = heads.len() == confidex_storage::PAGE_SIZE;
                let next = heads.last().cloned();
                let mut rows = Vec::new();
                for head in heads {
                    let wire = store.object(vault.vault_id(), head.revision).await?;
                    let verified = envelope::verify(
                        &wire,
                        vault.anchor(),
                        Some(&head.revision),
                        MAX_OPEN_MEMORY,
                    )
                    .map_err(|_| Error::Integrity)?;
                    if verified.header().record_id != head.record {
                        return Err(Error::Integrity);
                    }
                    if verified.header().kind == EventKind::Deletion {
                        continue;
                    }
                    let record = verified
                        .open(vault.keys(), MAX_OPEN_MEMORY)
                        .map_err(|_| Error::Integrity)?;
                    if tag.as_ref().is_some_and(|tag| !record.tags.contains(tag)) {
                        return Err(Error::Integrity);
                    }
                    rows.push(Summary {
                        head,
                        title: title(&record)?,
                        fields: fields::count(&record),
                        tags: record.tags.clone(),
                    });
                }
                Ok(Output::Rows { rows, more, next })
            }
            Command::Trash { after } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                trash::page(store, vault, after.as_ref()).await
            }
            Command::PreviewDeleted { head, source } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let epoch = trash::source_epoch(store, vault, head, *source).await?;
                let draft = read_draft(store, vault, head.record, *source)
                    .await?
                    .ok_or(Error::Integrity)?;
                Ok(Output::Historical {
                    record: head.record,
                    revision: *source,
                    epoch,
                    draft: Some(draft),
                })
            }
            Command::RestoreDeleted {
                head,
                source,
                epoch,
            } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                trash::restore(store, vault, head, *source, *epoch).await?;
                self.history = None;
                if let Some(index) = &mut self.search {
                    index.invalidate();
                }
                Ok(Output::Restored)
            }
            Command::OpenRevision { record, revision } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                if !record_heads(store, vault.vault_id(), *record)
                    .await?
                    .iter()
                    .any(|h| h.revision == *revision)
                {
                    return Err(confidex_storage::Error::Conflict.into());
                }
                Ok(Output::Draft(
                    read_draft(store, vault, *record, *revision)
                        .await?
                        .ok_or(Error::Input)?,
                ))
            }
            Command::Open { record } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let head = record_head(store, vault.vault_id(), *record)
                    .await?
                    .ok_or(Error::Input)?;
                Ok(Output::Draft(
                    read_draft(store, vault, *record, head.revision)
                        .await?
                        .ok_or(Error::Integrity)?,
                ))
            }
            Command::History { record, cursor } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let head = if let Some(cursor) = cursor {
                    cursor.head
                } else {
                    record_head(store, vault.vault_id(), *record)
                        .await?
                        .ok_or(Error::Input)?
                        .revision
                };
                if self
                    .history
                    .as_ref()
                    .is_none_or(|h| h.record != *record || h.head != head)
                {
                    self.history = Some(history::Session::load(store, vault, *record, head).await?);
                }
                Ok(Output::History(
                    self.history
                        .as_ref()
                        .unwrap()
                        .page(store, vault, cursor.map_or(0, |c| c.offset))
                        .await?,
                ))
            }
            Command::Historical { record, revision } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                if self.history.as_ref().is_none_or(|h| h.record != *record) {
                    let head = record_head(store, vault.vault_id(), *record)
                        .await?
                        .ok_or(Error::Input)?
                        .revision;
                    self.history = Some(history::Session::load(store, vault, *record, head).await?);
                }
                self.history
                    .as_ref()
                    .unwrap()
                    .revision(store, vault, *revision)
                    .await
            }
            Command::CheckRevision { record, revision } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let heads = record_heads(store, vault.vault_id(), *record).await?;
                let current = if heads.iter().any(|h| Some(h.revision) == *revision) {
                    *revision
                } else if heads.len() == 1 {
                    Some(heads[0].revision)
                } else {
                    None
                };
                Ok(Output::RecordHead {
                    record: *record,
                    revision: current,
                })
            }
            Command::RecordHead { record } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                Ok(Output::RecordHead {
                    record: *record,
                    revision: record_head(store, vault.vault_id(), *record)
                        .await?
                        .map(|h| h.revision),
                })
            }
            Command::Save { .. } | Command::SaveRevision { .. } | Command::CheckDraft { .. } => {
                let checking = matches!(command, Command::CheckDraft { .. });
                let require_current = matches!(command, Command::SaveRevision { .. });
                let (draft, epoch, parent) = match command {
                    Command::Save { draft, epoch } => (&*draft, *epoch, draft.revision),
                    Command::CheckDraft { draft } => (&*draft, 0, draft.revision),
                    Command::SaveRevision {
                        draft,
                        parent,
                        epoch,
                    } => {
                        if draft.revision.is_none() {
                            return Err(Error::Input);
                        }
                        (&*draft, *epoch, Some(*parent))
                    }
                    _ => unreachable!(),
                };
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                if draft.title.len() > 4096 || draft.fields.len() > fields::MAX_FIELDS {
                    return Err(Error::Input);
                }
                let mut record = if let Some(revision) = draft.revision {
                    let wire = store.object(vault.vault_id(), revision).await?;
                    let opened = envelope::open(
                        &wire,
                        vault.keys(),
                        vault.anchor(),
                        Some(&revision),
                        MAX_OPEN_MEMORY,
                    )
                    .map_err(|_| Error::Integrity)?;
                    if opened.revision.header().record_id != draft.record
                        || opened.revision.header().kind == EventKind::Deletion
                    {
                        return Err(Error::Integrity);
                    }
                    opened.record
                } else {
                    Record::default()
                };
                sections::apply(&mut record, draft.sections.as_deref(), draft.fields.len())?;
                fields::apply(&mut record, &draft.fields)?;
                let mut retired = Record::default();
                if let Some(old) = record
                    .extra
                    .insert(TITLE_KEY.into(), Value::from(draft.title.as_str()))
                {
                    retired.extra.insert(retired.extra.len().to_string(), old);
                }
                record.tags.zeroize();
                record.tags = draft.tags.clone();
                record.tags.sort_unstable();
                if checking {
                    return envelope::compressed_size(&record, MAX_OPEN_MEMORY)
                        .map(|compressed| Output::Checked { compressed })
                        .map_err(|_| Error::RecordLimit);
                }
                let mut parents: Vec<_> = parent.into_iter().collect();
                if let Some(source) = draft.revision
                    && !parents.contains(&source)
                {
                    parents.push(source);
                }
                let revision = append(
                    store,
                    vault,
                    &record,
                    Options {
                        vault_id: vault.vault_id(),
                        record_id: draft.record,
                        parents: &parents,
                        epoch,
                        kind: EventKind::Content,
                    },
                    require_current,
                )
                .await?;
                if let Some(index) = &mut self.search
                    && index
                        .changed(
                            Head {
                                record: draft.record,
                                revision,
                            },
                            Some(&record),
                            &parents,
                        )
                        .is_err()
                {
                    self.search = None;
                }
                Ok(Output::Saved(Head {
                    record: draft.record,
                    revision,
                }))
            }
            Command::Delete {
                record,
                expected,
                epoch,
            } => {
                let vault = self.vault.as_ref().ok_or(Error::Locked)?;
                let wire = store.object(vault.vault_id(), *expected).await?;
                let mut opened = envelope::open(
                    &wire,
                    vault.keys(),
                    vault.anchor(),
                    Some(expected),
                    MAX_OPEN_MEMORY,
                )
                .map_err(|_| Error::Integrity)?;
                if opened.revision.header().record_id != *record {
                    return Err(Error::Integrity);
                }
                let mut deleted = Record::default();
                deleted.tags = opened.record.tags.clone();
                if let Some(origin) = opened.record.extra.remove(import_apply::ORIGIN_KEY) {
                    deleted
                        .extra
                        .insert(import_apply::ORIGIN_KEY.into(), origin);
                }
                let revision = append(
                    store,
                    vault,
                    &deleted,
                    Options {
                        vault_id: vault.vault_id(),
                        record_id: *record,
                        parents: &[*expected],
                        epoch: *epoch,
                        kind: EventKind::Deletion,
                    },
                    true,
                )
                .await?;
                if let Some(index) = &mut self.search
                    && index
                        .changed(
                            Head {
                                record: *record,
                                revision,
                            },
                            None,
                            &[*expected],
                        )
                        .is_err()
                {
                    self.search = None;
                }
                Ok(Output::Saved(Head {
                    record: *record,
                    revision,
                }))
            }
        }
    }
    async fn search(
        &mut self,
        store: &mut impl Store,
        query: &str,
        after: Option<Head>,
        tag: Option<&str>,
        refresh: bool,
    ) -> Result<Output, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        if self.search.is_none() {
            self.search = Some(search::Index::new()?);
        }
        let index = self.search.as_mut().unwrap();
        if refresh {
            index.invalidate();
        }
        if !index.step(store, vault).await? {
            return Ok(Output::Indexing);
        }
        let (rows, more, next) = index.rows(query, after, tag)?;
        Ok(Output::Rows { rows, more, next })
    }
}
const TITLE_KEY: &str = "confidex.title";
fn title(record: &Record) -> Result<String, Error> {
    let text = record
        .extra
        .get(TITLE_KEY)
        .and_then(Value::as_str)
        .unwrap_or("");
    if text.len() > 4096 {
        return Err(Error::Input);
    }
    Ok(text.to_owned())
}
fn field_protected(entry: &Entry) -> bool {
    if entry.type_name == "secure-note/v1" {
        return true;
    }
    let Some(metadata) = entry.extra.get("metadata") else {
        return false;
    };
    let Some(items) = metadata.as_map() else {
        return true;
    };
    let mut markers = items
        .iter()
        .filter(|(key, _)| key.as_str() == Some("protected"));
    let Some((_, value)) = markers.next() else {
        return false;
    };
    markers.next().is_some() || value.as_bool() != Some(false)
}

pub fn new_record() -> Result<Draft, Error> {
    let mut record = [0; 16];
    entropy::fill_random(&mut record).map_err(|_| Error::Input)?;
    Ok(Draft {
        record,
        revision: None,
        title: String::new(),
        fields: vec![],
        tags: vec![],
        sections: Some(vec![]),
    })
}

async fn append<S: Store>(
    store: &mut S,
    vault: &lock::OpenedVault,
    record: &Record,
    options: Options<'_>,
    require_current: bool,
) -> Result<RevisionId, Error> {
    let Options {
        record_id,
        parents,
        kind,
        ..
    } = options;
    let expected = parents.first().copied();
    let wire = envelope::seal(record, vault.keys(), options, MAX_OPEN_MEMORY).map_err(|error| {
        if matches!(error, envelope::Error::Limit) {
            Error::RecordLimit
        } else {
            Error::Input
        }
    })?;
    let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
        .map_err(|_| Error::Integrity)?
        .id();
    let mut tags = if kind == EventKind::Deletion {
        Vec::new()
    } else {
        record.tags.clone()
    };
    tags.sort_unstable();
    let head = Head {
        record: record_id,
        revision,
    };
    for _ in 0..4 {
        let current = record_heads(store, vault.vault_id(), record_id).await?;
        if expected.map_or(!current.is_empty(), |revision| {
            require_current && !current.iter().any(|h| h.revision == revision)
        }) {
            return Err(confidex_storage::Error::Conflict.into());
        }
        let mut changes: Vec<_> = current
            .iter()
            .filter(|h| parents.contains(&h.revision))
            .map(|h| confidex_storage::HeadChange {
                head: head.clone(),
                expected: Some(h.revision),
            })
            .collect();
        if changes.is_empty() {
            changes.push(confidex_storage::HeadChange {
                head: head.clone(),
                expected: None,
            });
        }
        match sync::publish_local(
            store,
            vault.vault_id(),
            vec![confidex_storage::StoredObject {
                head: head.clone(),
                wire: wire.clone(),
                tags: tags.clone(),
            }],
            changes,
        )
        .await
        {
            Ok(()) => return Ok(revision),
            Err(Error::Storage(confidex_storage::Error::Conflict)) => (),
            Err(error) => return Err(error),
        }
    }
    Err(confidex_storage::Error::Conflict.into())
}

async fn record_head(
    store: &mut impl Store,
    vault: VaultId,
    record: RecordId,
) -> Result<Option<Head>, Error> {
    let mut heads = record_heads(store, vault, record).await?;
    if heads.len() > 1 {
        return Err(confidex_storage::Error::Conflict.into());
    }
    Ok(heads.pop())
}

async fn record_heads(
    store: &mut impl Store,
    vault: VaultId,
    record: RecordId,
) -> Result<Vec<Head>, Error> {
    let mut previous = record;
    let mut after = None;
    for index in (0..previous.len()).rev() {
        if previous[index] == 0 {
            previous[index] = 255;
        } else {
            previous[index] -= 1;
            after = Some(Head {
                record: previous,
                revision: [255; 32],
            });
            break;
        }
    }
    let mut result = Vec::new();
    loop {
        let page = store.branch_heads(vault, after.as_ref(), None).await?;
        if page.is_empty() {
            return Ok(result);
        }
        after = page.last().cloned();
        for head in page {
            if head.record > record {
                return Ok(result);
            }
            if head.record != record {
                return Err(Error::Integrity);
            }
            result.push(head);
            if result.len() > 100_000 {
                return Err(Error::Input);
            }
        }
    }
}

async fn read_draft(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    record: RecordId,
    revision: RevisionId,
) -> Result<Option<Draft>, Error> {
    let wire = store.object(vault.vault_id(), revision).await?;
    let opened = envelope::open(
        &wire,
        vault.keys(),
        vault.anchor(),
        Some(&revision),
        MAX_OPEN_MEMORY,
    )
    .map_err(|_| Error::Integrity)?;
    if opened.revision.header().record_id != record {
        return Err(Error::Integrity);
    }
    if opened.revision.header().kind == EventKind::Deletion {
        return Ok(None);
    }
    let fields = fields::read(&opened.record)?;
    Ok(Some(Draft {
        record,
        revision: Some(revision),
        title: title(&opened.record)?,
        sections: sections::read(&opened.record, &fields),
        fields,
        tags: opened.record.tags.clone(),
    }))
}

async fn audit<S: Store>(store: &mut S, vault: &lock::OpenedVault) -> Result<(), Error> {
    let mut heads = Vec::new();
    loop {
        let page = store
            .branch_heads(vault.vault_id(), heads.last(), None)
            .await?;
        if page.is_empty() {
            break;
        }
        heads.extend(page);
        if heads.len() > 100_000 {
            return Err(Error::Input);
        }
    }
    let graph = sync::graph(store, vault, &heads).await?;
    let expected: Vec<_> = heads.iter().map(|h| (h.record, h.revision)).collect();
    if graph.report().heads != expected {
        return Err(Error::Integrity);
    }
    Ok(())
}

fn open_stored(
    stored: &StoredVault,
    password: &str,
    text: &str,
) -> Result<lock::OpenedVault, Error> {
    open_stored_with_key(stored, password, text).map(|(opened, _, _)| opened)
}

fn open_stored_with_key(
    stored: &StoredVault,
    password: &str,
    text: &str,
) -> Result<(lock::OpenedVault, Zeroizing<[u8; 32]>, transfer_code::Code), Error> {
    if password.is_empty() || password.len() > 4096 || text.len() > 4096 {
        return Err(Error::Input);
    }
    let code = transfer_code::decode(text).map_err(|_| Error::Key)?;
    let header = lock::inspect(&stored.lock).map_err(|_| Error::Integrity)?;
    if confidex_vault::sync::id(&header.public_key) != code.id {
        return Err(Error::Key);
    }
    let (opened, unlock_key) = lock::open_with_unlock_key(
        &stored.lock,
        password.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .map_err(|_| Error::Auth)?;
    if opened.vault_id() != stored.info.id
        || confidex_vault::sync::id(opened.keys().signing_key().verifying_key().as_bytes())
            != code.id
    {
        return Err(Error::Integrity);
    }
    Ok((opened, unlock_key, code))
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    #[test]
    fn encrypted_titles_use_the_current_metadata_key() {
        assert_eq!(TITLE_KEY, "confidex.title");
        let mut record = Record::default();
        assert_eq!(title(&record).unwrap(), "");
        record
            .extra
            .insert(TITLE_KEY.into(), Value::from("record title"));
        assert_eq!(title(&record).unwrap(), "record title");
    }
}
