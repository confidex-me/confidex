//! Application storage of opaque encrypted objects. Callers authenticate wire data.
use serde::{Deserialize, Serialize};

pub type VaultId = [u8; 16];
pub type RecordId = [u8; 16];
pub type RevisionId = [u8; 32];
pub const MAX_OBJECT: usize = 4_065_668;
pub const PAGE_SIZE: usize = 128;
pub const MAX_SYNC_STATE: usize = 8_000_000;
// shortcut: Backups use memory; add streaming for larger vaults.
pub const MAX_BACKUP_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_BACKUP_OBJECTS: usize = 10_000;

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: VaultId,
    pub name: String,
}
#[derive(Serialize, Deserialize)]
pub struct StoredVault {
    pub info: VaultInfo,
    pub lock: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Head {
    pub record: RecordId,
    pub revision: RevisionId,
}
#[derive(Serialize, Deserialize)]
pub struct StoredObject {
    pub head: Head,
    pub wire: Vec<u8>,
    pub tags: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub vault: StoredVault,
    pub objects: Vec<StoredObject>,
    pub heads: Vec<Head>,
}
impl Snapshot {
    pub fn validate(&self) -> Result<(), Error> {
        if self.vault.info.name.is_empty()
            || self.vault.info.name.len() > 128
            || self.vault.lock.len() > 344
            || self.objects.len() > MAX_BACKUP_OBJECTS
            || self.heads.len() > MAX_BACKUP_OBJECTS
            || self
                .objects
                .iter()
                .any(|o| o.wire.is_empty() || o.wire.len() > MAX_OBJECT || !valid_tags(&o.tags))
            || self.objects.iter().map(|o| o.wire.len()).sum::<usize>() > MAX_BACKUP_BYTES * 3 / 4
        {
            return Err(Error::Limit);
        }
        let objects: std::collections::BTreeMap<_, _> = self
            .objects
            .iter()
            .map(|o| (o.head.revision, o.head.record))
            .collect();
        let records: std::collections::BTreeSet<_> =
            self.heads.iter().map(|h| (h.record, h.revision)).collect();
        if objects.len() != self.objects.len()
            || records.len() != self.heads.len()
            || self
                .heads
                .iter()
                .any(|h| objects.get(&h.revision) != Some(&h.record))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
pub struct HeadChange {
    pub head: Head,
    pub expected: Option<RevisionId>,
}
#[derive(Serialize, Deserialize)]
pub struct SyncCommit {
    pub previous: Option<Vec<u8>>,
    pub current: Vec<u8>,
    pub objects: Vec<StoredObject>,
    pub heads: Vec<HeadChange>,
}
impl SyncCommit {
    pub fn validate(&self) -> Result<(), Error> {
        if self.current.len() > MAX_SYNC_STATE
            || self
                .previous
                .as_ref()
                .is_some_and(|b| b.len() > MAX_SYNC_STATE)
            || self.objects.len() > 256
            || self.heads.len() > 256
            || self
                .objects
                .iter()
                .any(|o| o.wire.is_empty() || o.wire.len() > MAX_OBJECT || !valid_tags(&o.tags))
            || self.objects.iter().map(|o| o.wire.len()).sum::<usize>() > 8_000_000
        {
            return Err(Error::Limit);
        }
        let mut targets = std::collections::BTreeSet::new();
        let mut consumed = std::collections::BTreeSet::new();
        if self.heads.iter().any(|h| {
            !targets.insert((h.head.record, h.head.revision, h.expected))
                || h.expected
                    .is_some_and(|id| !consumed.insert((h.head.record, id)))
        }) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub const MAX_BATCH_OBJECTS: usize = 10_000;
pub const MAX_BATCH_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_BATCH_BASE_HEADS: usize = 100_000;

/// Publish a bounded group without changing the sync checkpoint.
#[derive(Serialize, Deserialize)]
pub struct BatchCommit {
    // Compare all heads to detect concurrent creation of new records.
    pub previous: Vec<Head>,
    pub objects: Vec<StoredObject>,
    pub heads: Vec<HeadChange>,
}
impl BatchCommit {
    pub fn validate(&self) -> Result<(), Error> {
        if self.previous.len() > MAX_BATCH_BASE_HEADS
            || self.objects.len() > MAX_BATCH_OBJECTS
            || self.heads.len() > MAX_BATCH_OBJECTS
        {
            return Err(Error::Limit);
        }
        if self.objects.len() != self.heads.len()
            || !self
                .previous
                .windows(2)
                .all(|pair| (pair[0].record, pair[0].revision) < (pair[1].record, pair[1].revision))
        {
            return Err(Error::Invalid);
        }
        let mut bytes = 0usize;
        let mut objects = std::collections::BTreeMap::new();
        for object in &self.objects {
            bytes = bytes.checked_add(object.wire.len()).ok_or(Error::Limit)?;
            if object.wire.is_empty()
                || object.wire.len() > MAX_OBJECT
                || bytes > MAX_BATCH_BYTES
                || !valid_tags(&object.tags)
            {
                return Err(Error::Limit);
            }
            if objects
                .insert(object.head.revision, object.head.record)
                .is_some()
            {
                return Err(Error::Invalid);
            }
        }
        let mut consumed = std::collections::BTreeSet::new();
        let mut targets = std::collections::BTreeSet::new();
        for change in &self.heads {
            let exists = match change.expected {
                Some(expected) => self
                    .previous
                    .binary_search_by_key(&(change.head.record, expected), |h| {
                        (h.record, h.revision)
                    })
                    .is_ok(),
                None => self
                    .previous
                    .binary_search_by_key(&change.head.record, |h| h.record)
                    .is_err(),
            };
            if !consumed.insert((change.head.record, change.expected))
                || !targets.insert((change.head.record, change.head.revision))
                || !exists
                || objects.get(&change.head.revision) != Some(&change.head.record)
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}

pub fn valid_tags(tags: &[String]) -> bool {
    tags.len() <= 256
        && tags.iter().all(|tag| tag.len() <= 256)
        && tags.windows(2).all(|pair| pair[0] < pair[1])
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    Storage,
    Conflict,
    NotFound,
    Removing,
    Invalid,
    Limit,
    Quota,
    Version,
}

// Browser transactions need local futures; the host chooses the executor.
#[allow(async_fn_in_trait)]
pub trait Store {
    async fn rename(&mut self, vault: VaultId, expected: &str, name: &str) -> Result<(), Error>;
    // Keep the lock until the host removes the device key.
    async fn clear_records(&mut self, vault: VaultId) -> Result<(), Error>;
    async fn remove(&mut self, vault: VaultId) -> Result<(), Error>;
    async fn snapshot(&mut self, vault: VaultId) -> Result<Snapshot, Error>;
    async fn restore(&mut self, snapshot: &Snapshot) -> Result<(), Error>;
    async fn vaults(&mut self) -> Result<Vec<VaultInfo>, Error>;
    async fn vault(&mut self, id: VaultId) -> Result<StoredVault, Error>;
    async fn create(&mut self, vault: &StoredVault) -> Result<(), Error>;
    async fn branch_heads(
        &mut self,
        vault: VaultId,
        after: Option<&Head>,
        tag: Option<&str>,
    ) -> Result<Vec<Head>, Error>;
    async fn publish_branches(&mut self, vault: VaultId, commit: &SyncCommit) -> Result<(), Error>;
    async fn heads(&mut self, vault: VaultId, after: Option<RecordId>) -> Result<Vec<Head>, Error>;
    async fn tagged_heads(
        &mut self,
        vault: VaultId,
        tag: &str,
        after: Option<RecordId>,
    ) -> Result<Vec<Head>, Error>;
    async fn head(&mut self, vault: VaultId, record: RecordId) -> Result<Option<Head>, Error>;
    async fn object(&mut self, vault: VaultId, revision: RevisionId) -> Result<Vec<u8>, Error>;
    async fn append(
        &mut self,
        vault: VaultId,
        head: &Head,
        expected: Option<RevisionId>,
        wire: &[u8],
        tags: &[String],
    ) -> Result<(), Error>;
    async fn batch_commit(&mut self, vault: VaultId, commit: &BatchCommit) -> Result<(), Error>;
    async fn sync_state(&mut self, vault: VaultId) -> Result<Option<Vec<u8>>, Error>;
    async fn sync_commit(&mut self, vault: VaultId, commit: &SyncCommit) -> Result<(), Error>;
}

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
mod sqlite;
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub use sqlite::SqliteStore;
