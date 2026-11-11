//! Review a vendor plan, then publish its explicitly selected records atomically.
use crate::{Engine, Error as AppError, import};
use confidex_storage::{BatchCommit, Head, HeadChange, RecordId, Store, StoredObject, VaultId};
use confidex_vault::{
    entropy,
    envelope::{self, EventKind, Options},
    lock,
    record::Record,
    resources::MAX_OPEN_MEMORY,
};
use import::{Plan, Reservation, Status};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroize;
mod matching;
pub(crate) mod memory;
mod origin;
pub(super) const ORIGIN_KEY: &str = origin::KEY;
pub use matching::{Candidate, Match};
use matching::{Catalog, Existing, Repeated};
use memory::Owned;
use origin::Origin;

const MAX_CATALOG: usize = 100_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    App(AppError),
    Plan(import::Error),
    Limit,
    InvalidSession,
    InvalidChoice,
    InvalidProvenance,
    NoCarrier,
    Canceled,
}
impl From<AppError> for Error {
    fn from(error: AppError) -> Self {
        Self::App(error)
    }
}
impl From<confidex_storage::Error> for Error {
    fn from(error: confidex_storage::Error) -> Self {
        Self::App(error.into())
    }
}
impl From<import::Error> for Error {
    fn from(error: import::Error) -> Self {
        Self::Plan(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Catalog,
    Review,
    Seal,
    Commit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub phase: Phase,
    pub current: usize,
    pub total: usize,
}
#[allow(async_fn_in_trait)]
pub trait Control {
    async fn checkpoint(&mut self, progress: Progress) -> bool;
}
impl<F: FnMut(Progress) -> bool> Control for F {
    async fn checkpoint(&mut self, progress: Progress) -> bool {
        self(progress)
    }
}
async fn checkpoint(
    callback: &mut impl Control,
    phase: Phase,
    current: usize,
    total: usize,
) -> Result<(), Error> {
    if callback
        .checkpoint(Progress {
            phase,
            current,
            total,
        })
        .await
    {
        Ok(())
    } else {
        Err(Error::Canceled)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub status: Status,
    pub matching: Match,
    pub duplicate: Option<Head>,
    pub candidates: usize,
}
#[derive(Serialize, Deserialize)]
pub struct Review {
    pub token: [u8; 16],
    pub vault: VaultId,
    pub items: Vec<Item>,
    pub container_status: Status,
    pub container_diagnostics: Vec<import::Diagnostic>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Skip,
    Create,
    Copy,
    Update(Head),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    pub action: Action,
    pub reviewed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub choices: Vec<Choice>,
    pub container_reviewed: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
}
#[derive(Serialize, Deserialize)]
pub struct Candidates {
    pub items: Vec<Candidate>,
    pub next: Option<usize>,
}

pub(super) struct Session {
    token: [u8; 16],
    vault: VaultId,
    plan: Plan,
    previous: Vec<Head>,
    catalog: Catalog,
    incoming: Vec<Origin>,
    items: Vec<Item>,
    catalog_memory: Vec<Reservation>,
    contexts: BTreeSet<(RecordId, [u8; 32], origin::Fingerprint)>,
    container_digest: Option<origin::Fingerprint>,
    _metadata_memory: Reservation,
    _heads_memory: Reservation,
}
struct Staged(BatchCommit);
impl Drop for Staged {
    fn drop(&mut self) {
        for object in &mut self.0.objects {
            object.tags.zeroize();
        }
    }
}
impl Engine {
    /// Release the previous plan and derived caches before the host parses a new file.
    pub fn begin_import(&mut self) -> Result<VaultId, Error> {
        self.export_session = None;
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?.vault_id();
        self.import_session = None;
        self.import_input = None;
        self.search = None;
        self.history = None;
        Ok(vault)
    }
    pub fn cancel_import(&mut self, token: [u8; 16]) -> Result<(), Error> {
        self.import_session
            .as_ref()
            .filter(|s| s.token == token)
            .ok_or(Error::InvalidSession)?;
        self.import_session = None;
        Ok(())
    }
    pub fn import_plan(&self, token: [u8; 16]) -> Result<&Plan, Error> {
        Ok(&self
            .import_session
            .as_ref()
            .filter(|s| s.token == token)
            .ok_or(Error::InvalidSession)?
            .plan)
    }
    pub fn import_candidates(
        &self,
        token: [u8; 16],
        item: usize,
        after: usize,
    ) -> Result<Candidates, Error> {
        let session = self
            .import_session
            .as_ref()
            .filter(|s| s.token == token)
            .ok_or(Error::InvalidSession)?;
        let incoming = session.incoming.get(item).ok_or(Error::InvalidChoice)?;
        let indices = session.catalog.indices(incoming);
        if after > indices.len() {
            return Err(Error::InvalidChoice);
        }
        let end = indices.len().min(after.saturating_add(64));
        Ok(Candidates {
            items: indices[after..end]
                .iter()
                .map(|&i| session.catalog.candidate(i, incoming))
                .collect(),
            next: (end < indices.len()).then_some(end),
        })
    }

    /// Release the input buffer and parser options before this call.
    pub async fn review_import(
        &mut self,
        store: &mut impl Store,
        target: VaultId,
        plan: Plan,
        callback: &mut impl Control,
    ) -> Result<Review, Error> {
        self.export_session = None;
        self.import_session = None;
        self.import_input = None;
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?;
        if vault.vault_id() != target {
            return Err(Error::InvalidSession);
        }
        self.search = None;
        self.history = None;
        let memory = plan.memory().clone();
        let heads_memory = memory.reserve(MAX_CATALOG * std::mem::size_of::<Head>())?;
        let mut previous = Vec::new();
        previous
            .try_reserve_exact(MAX_CATALOG)
            .map_err(|_| Error::Limit)?;
        loop {
            checkpoint(callback, Phase::Catalog, previous.len(), MAX_CATALOG).await?;
            let page = store.branch_heads(target, previous.last(), None).await?;
            if page.is_empty() {
                break;
            }
            if page.len() > confidex_storage::PAGE_SIZE || previous.len() + page.len() > MAX_CATALOG
            {
                return Err(Error::Limit);
            }
            for head in page {
                if previous
                    .last()
                    .is_some_and(|h: &Head| (h.record, h.revision) >= (head.record, head.revision))
                {
                    return Err(AppError::Integrity.into());
                }
                previous.push(head);
            }
        }
        let metadata_memory = memory.reserve(
            plan.items
                .len()
                .checked_mul(1024)
                .and_then(|n| n.checked_add(64 << 10))
                .ok_or(Error::Limit)?,
        )?;
        let container_digest = plan
            .container_attributes_bytes()
            .map(origin::container_digest);
        let mut session = Session {
            token: [0; 16],
            vault: target,
            previous,
            plan,
            catalog: Catalog::default(),
            incoming: Vec::new(),
            items: Vec::new(),
            catalog_memory: Vec::new(),
            contexts: BTreeSet::new(),
            container_digest,
            _metadata_memory: metadata_memory,
            _heads_memory: heads_memory,
        };
        let mut ancestry = 0usize;
        for index in 0..session.previous.len() {
            let head = session.previous[index].clone();
            checkpoint(
                callback,
                Phase::Catalog,
                session.catalog.records.len(),
                session.previous.len(),
            )
            .await?;
            session
                .load_existing(store, vault, &head, &mut ancestry, callback)
                .await?;
        }
        session
            .incoming
            .try_reserve_exact(session.plan.items.len())
            .map_err(|_| Error::Limit)?;
        session
            .items
            .try_reserve_exact(session.plan.items.len())
            .map_err(|_| Error::Limit)?;
        let mut repeated = Repeated::default();
        for (index, item) in session.plan.items.iter().enumerate() {
            checkpoint(callback, Phase::Review, index, session.plan.items.len()).await?;
            let incoming = Origin {
                source: origin::source_key(session.plan.format, &item.source),
                original: origin::source_digest(
                    item.record_bytes(),
                    item.source_attributes_bytes(),
                    session.container_digest.as_ref(),
                ),
                content: origin::encoded_content_digest(item.record_bytes()),
            };
            let (matching, duplicate) = if let Some(matching) = repeated.check(&incoming, index) {
                (matching, None)
            } else {
                session.catalog.classify(&incoming)
            };
            session.items.push(Item {
                status: item.status,
                matching,
                duplicate,
                candidates: session.catalog.indices(&incoming).len(),
            });
            session.incoming.push(incoming);
        }
        entropy::fill_random(&mut session.token).map_err(|_| Error::Limit)?;
        let review = Review {
            token: session.token,
            vault: target,
            items: session.items.clone(),
            container_status: session.plan.container_status,
            container_diagnostics: session.plan.container_diagnostics.clone(),
        };
        self.import_session = Some(session);
        Ok(review)
    }

    /// Cancellation stops at the Commit checkpoint. The storage transaction then runs to completion.
    pub async fn apply_import(
        &mut self,
        store: &mut impl Store,
        token: [u8; 16],
        selection: &Selection,
        epoch: u64,
        callback: &mut impl Control,
    ) -> Result<Report, Error> {
        self.import_session
            .as_ref()
            .filter(|s| s.token == token)
            .ok_or(Error::InvalidSession)?;
        let session = self.import_session.take().ok_or(Error::InvalidSession)?;
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?;
        if session.vault != vault.vault_id() {
            return Err(Error::InvalidSession);
        }
        let report = session
            .apply(store, vault, selection, epoch, callback)
            .await?;
        // A committed import succeeds even when the derived search index must be rebuilt.
        self.search = None;
        self.history = None;
        Ok(report)
    }
}

impl Session {
    async fn apply(
        self,
        store: &mut impl Store,
        vault: &lock::OpenedVault,
        selection: &Selection,
        epoch: u64,
        callback: &mut impl Control,
    ) -> Result<Report, Error> {
        if matches!(
            self.plan.container_status,
            Status::Blocked | Status::Excluded
        ) || (self.plan.container_status == Status::Review && !selection.container_reviewed)
        {
            return Err(Error::InvalidChoice);
        }
        let choices = &selection.choices;
        if choices.len() != self.items.len() {
            return Err(Error::InvalidChoice);
        }
        let memory = self.plan.memory().clone();
        let mut report = Report::default();
        let mut targets = BTreeSet::new();
        let mut selected = Vec::new();
        for (index, ((choice, item), incoming)) in choices
            .iter()
            .zip(&self.items)
            .zip(&self.incoming)
            .enumerate()
        {
            checkpoint(callback, Phase::Review, index, choices.len()).await?;
            if choice.action == Action::Skip {
                report.skipped += 1;
                continue;
            }
            if matches!(item.status, Status::Blocked | Status::Excluded)
                || ((item.status == Status::Review
                    || item.matching != Match::New
                    || choice.action != Action::Create)
                    && !choice.reviewed)
            {
                return Err(Error::InvalidChoice);
            }
            let (record, expected) = match &choice.action {
                Action::Skip => unreachable!(),
                Action::Create if item.matching == Match::New => (random_record()?, None),
                Action::Copy => (random_record()?, None),
                Action::Update(head)
                    if !matches!(
                        item.matching,
                        Match::RepeatedSource { .. } | Match::RepeatedContent { .. }
                    ) && self.catalog.contains(incoming, head) =>
                {
                    (head.record, Some(head.revision))
                }
                _ => return Err(Error::InvalidChoice),
            };
            if !targets.insert((record, expected))
                || (expected.is_none()
                    && self
                        .previous
                        .binary_search_by_key(&record, |h| h.record)
                        .is_ok())
            {
                return Err(Error::InvalidChoice);
            }
            selected.push((index, record, expected));
        }
        let Session {
            plan,
            previous,
            incoming,
            catalog,
            catalog_memory,
            _metadata_memory,
            _heads_memory,
            container_digest,
            ..
        } = self;
        drop(catalog);
        drop(catalog_memory);
        if selected.is_empty() {
            if plan.items.is_empty() {
                let container = Owned::new(
                    Record {
                        entries: Vec::new(),
                        tags: Vec::new(),
                        extra: plan.container_attributes(memory.available())?,
                    },
                    &memory,
                )?;
                if !container.record.extra.is_empty() {
                    return Err(Error::NoCarrier);
                }
            }
            return Ok(report);
        }
        let _host_memory = memory.reserve(
            previous
                .len()
                .checked_mul(1024)
                .and_then(|n| {
                    selected
                        .len()
                        .checked_mul(1024)
                        .and_then(|s| n.checked_add(s))
                })
                .ok_or(Error::Limit)?,
        )?;
        let mut staged = Staged(BatchCommit {
            previous,
            objects: Vec::new(),
            heads: Vec::new(),
        });
        let commit = &mut staged.0;
        commit
            .objects
            .try_reserve_exact(selected.len())
            .map_err(|_| Error::Limit)?;
        commit
            .heads
            .try_reserve_exact(selected.len())
            .map_err(|_| Error::Limit)?;
        let mut staging = Vec::new();
        let mut wire_bytes = 0usize;
        let mut carrier = None;
        for (position, (index, record_id, expected)) in selected.iter().copied().enumerate() {
            checkpoint(callback, Phase::Seal, position, selected.len()).await?;
            let item = &plan.items[index];
            let mut content = Owned::new(item.record(memory.available())?, &memory)?;
            if content.record.extra.contains_key(origin::KEY) {
                return Err(Error::InvalidProvenance);
            }
            let mut attributes = Owned::new(
                Record {
                    extra: item.source_attributes(memory.available())?,
                    entries: Vec::new(),
                    tags: Vec::new(),
                },
                &memory,
            )?;
            let mut context = if let Some(digest) = &container_digest {
                if let Some((record, revision)) = carrier {
                    Owned::new(origin::reference(record, revision, digest), &memory)?
                } else {
                    let mut decoded = Owned::new(
                        Record {
                            extra: plan.container_attributes(memory.available())?,
                            entries: Vec::new(),
                            tags: Vec::new(),
                        },
                        &memory,
                    )?;
                    let value = origin::carrier(std::mem::take(&mut decoded.record), digest);
                    decoded.record = value;
                    decoded
                }
            } else {
                Owned::new(Record::default(), &memory)?
            };
            let _origin_memory = memory.reserve(64 << 10)?;
            origin::attach(
                &mut content.record,
                plan.format,
                &item.source,
                &incoming[index],
                std::mem::take(&mut attributes.record),
                std::mem::take(&mut context.record),
            )
            .map_err(|_| Error::InvalidProvenance)?;
            let parents: Vec<_> = expected.into_iter().collect();
            let wire = envelope::seal(
                &content.record,
                vault.keys(),
                Options {
                    vault_id: vault.vault_id(),
                    record_id,
                    parents: &parents,
                    epoch,
                    kind: EventKind::Content,
                },
                memory.available().min(MAX_OPEN_MEMORY),
            )
            .map_err(core_error)?;
            wire_bytes = wire_bytes
                .checked_add(wire.len())
                .filter(|n| *n <= confidex_storage::MAX_BATCH_BYTES)
                .ok_or(Error::Limit)?;
            staging.push(memory.reserve(wire.capacity().checked_mul(3).ok_or(Error::Limit)?)?);
            let revision = envelope::verify(
                &wire,
                vault.anchor(),
                None,
                memory.available().min(MAX_OPEN_MEMORY),
            )
            .map_err(core_error)?
            .id();
            let tag_bytes = content
                .record
                .tags
                .iter()
                .try_fold(
                    content.record.tags.len() * std::mem::size_of::<String>(),
                    |n, s| n.checked_add(s.len()),
                )
                .and_then(|n| n.checked_mul(6))
                .ok_or(Error::Limit)?;
            staging.push(memory.reserve(tag_bytes)?);
            let mut tags = content.record.tags.clone();
            tags.sort_unstable();
            let head = Head {
                record: record_id,
                revision,
            };
            if carrier.is_none() {
                carrier = Some((record_id, revision));
            }
            commit.heads.push(HeadChange {
                head: head.clone(),
                expected,
            });
            commit.objects.push(StoredObject { head, wire, tags });
            if expected.is_some() {
                report.updated += 1;
            } else {
                report.added += 1;
            }
        }
        checkpoint(callback, Phase::Commit, selected.len(), selected.len()).await?;
        store.batch_commit(vault.vault_id(), commit).await?;
        Ok(report)
    }
}
fn random_record() -> Result<RecordId, Error> {
    let mut id = [0; 16];
    entropy::fill_random(&mut id).map_err(|_| Error::Limit)?;
    Ok(id)
}
fn core_error(error: envelope::Error) -> Error {
    match error {
        envelope::Error::Limit
        | envelope::Error::Allocation
        | envelope::Error::Content(
            confidex_vault::record::Error::Limit | confidex_vault::record::Error::Allocation,
        ) => Error::Limit,
        _ => Error::App(AppError::Integrity),
    }
}

impl Session {
    async fn load_existing(
        &mut self,
        store: &mut impl Store,
        vault: &lock::OpenedVault,
        head: &Head,
        visits: &mut usize,
        callback: &mut impl Control,
    ) -> Result<(), Error> {
        let memory = self.plan.memory().clone();
        let mut pending = vec![head.revision];
        let mut seen = BTreeSet::new();
        let mut walk_memory = Vec::new();
        while let Some(revision) = pending.pop() {
            if seen.contains(&revision) {
                continue;
            }
            *visits += 1;
            if *visits > MAX_CATALOG {
                return Err(Error::Limit);
            }
            walk_memory.push(memory.reserve(256)?);
            seen.insert(revision);
            checkpoint(callback, Phase::Catalog, *visits, MAX_CATALOG).await?;
            let _wire_memory = memory.reserve(confidex_storage::MAX_OBJECT * 3 + (128 << 10))?;
            let wire = store.object(vault.vault_id(), revision).await?;
            let opened = envelope::open(
                &wire,
                vault.keys(),
                vault.anchor(),
                Some(&revision),
                memory.available().min(MAX_OPEN_MEMORY),
            )
            .map_err(core_error)?;
            if opened.revision.header().record_id != head.record {
                return Err(AppError::Integrity.into());
            }
            let deleted = opened.revision.header().kind == EventKind::Deletion;
            let parents = opened.revision.header().parents.clone();
            let mut record = Owned::new(opened.record, &memory)?;
            let origin = origin::read(&record.record).map_err(|_| Error::InvalidProvenance)?;
            if deleted && origin.is_none() {
                if pending.len() + parents.len() > MAX_CATALOG {
                    return Err(Error::Limit);
                }
                walk_memory.push(memory.reserve(parents.len() * 128)?);
                pending.extend(parents);
                continue;
            }
            if self.catalog.records.len() >= MAX_CATALOG {
                return Err(Error::Limit);
            }
            let current = if deleted {
                origin
                    .as_ref()
                    .ok_or(Error::InvalidProvenance)?
                    .content
                    .clone()
            } else {
                origin::content_digest(&mut record.record, memory.available())
                    .map_err(|_| Error::Limit)?
            };
            self.verify_context(store, vault, head.record, revision, record, callback)
                .await?;
            self.catalog_memory.push(memory.reserve(1024)?);
            self.catalog
                .records
                .try_reserve(1)
                .map_err(|_| Error::Limit)?;
            self.catalog.push(Existing {
                head: head.clone(),
                deleted: deleted || revision != head.revision,
                current,
                origin,
            });
        }
        Ok(())
    }

    async fn verify_context(
        &mut self,
        store: &mut impl Store,
        vault: &lock::OpenedVault,
        record_id: RecordId,
        revision: [u8; 32],
        mut content: Owned,
        callback: &mut impl Control,
    ) -> Result<(), Error> {
        let memory = self.plan.memory().clone();
        let context =
            origin::take_container(&mut content.record).map_err(|_| Error::InvalidProvenance)?;
        let (payload, digest, key) = match context {
            origin::Container::None => return Ok(()),
            origin::Container::Carrier { payload, digest } => {
                let key = (record_id, revision, digest.clone());
                (payload, digest, key)
            }
            origin::Container::Reference {
                record,
                revision,
                digest,
            } => {
                drop(content);
                let key = (record, revision, digest.clone());
                if self.contexts.contains(&key) {
                    return Ok(());
                }
                checkpoint(
                    callback,
                    Phase::Catalog,
                    self.catalog.records.len(),
                    MAX_CATALOG,
                )
                .await?;
                let _wire = memory.reserve(confidex_storage::MAX_OBJECT * 3)?;
                let wire = store
                    .object(vault.vault_id(), revision)
                    .await
                    .map_err(|error| {
                        if error == confidex_storage::Error::NotFound {
                            Error::InvalidProvenance
                        } else {
                            error.into()
                        }
                    })?;
                let opened = envelope::open(
                    &wire,
                    vault.keys(),
                    vault.anchor(),
                    Some(&revision),
                    memory.available().min(MAX_OPEN_MEMORY),
                )
                .map_err(core_error)?;
                if opened.revision.header().record_id != record
                    || opened.revision.header().kind != EventKind::Content
                {
                    return Err(Error::InvalidProvenance);
                }
                content = Owned::new(opened.record, &memory)?;
                origin::read(&content.record)
                    .map_err(|_| Error::InvalidProvenance)?
                    .ok_or(Error::InvalidProvenance)?;
                let origin::Container::Carrier {
                    payload,
                    digest: actual,
                } = origin::take_container(&mut content.record)
                    .map_err(|_| Error::InvalidProvenance)?
                else {
                    return Err(Error::InvalidProvenance);
                };
                if actual != digest {
                    return Err(Error::InvalidProvenance);
                }
                (payload, digest, key)
            }
        };
        content.record = payload;
        let encoded = content
            .record
            .encode_content(memory.available())
            .map_err(|_| Error::Limit)?;
        if origin::container_digest(&encoded.bytes) != digest {
            return Err(Error::InvalidProvenance);
        }
        if !self.contexts.contains(&key) {
            if self.contexts.len() >= MAX_CATALOG {
                return Err(Error::Limit);
            }
            self.catalog_memory.push(memory.reserve(256)?);
            self.contexts.insert(key);
        }
        Ok(())
    }
}
