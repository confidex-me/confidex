//! Authenticated export sessions. File publication remains an explicit host action.
use crate::{Bytes, Engine, Error as AppError, export};
use confidex_storage::{Head, Store, VaultId};
use confidex_vault::{entropy, envelope, record::Value};
use export::{Consent, Issue, Phase, Progress, Severity};
use serde::{Deserialize, Serialize};
use std::mem::size_of;
use zeroize::{Zeroize, Zeroizing};
mod fields;
mod protocol;
mod transfer;
pub use fields::{FieldSource, FieldSources, SOURCE_PAGE_SIZE};
pub use protocol::{Command, Reply};
pub use transfer::Transfer;

pub const PAGE_SIZE: usize = 64;
pub const CHUNK_BYTES: usize = 256 << 10;
const MAX_HEADS: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    App(AppError),
    Export(export::Error),
    InvalidSession,
    InvalidSelection,
    Changed,
    Entropy,
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
impl From<export::Error> for Error {
    fn from(error: export::Error) -> Self {
        Self::Export(error)
    }
}

#[derive(Serialize, Deserialize)]
pub enum Selection {
    All,
    Records(Vec<Head>),
}
#[allow(async_fn_in_trait)]
pub trait Control {
    async fn checkpoint(&mut self, progress: Progress) -> bool;
    fn computing(&mut self, progress: Progress) -> bool;
}
impl<F: FnMut(Progress) -> bool> Control for F {
    async fn checkpoint(&mut self, progress: Progress) -> bool {
        self(progress)
    }
    fn computing(&mut self, progress: Progress) -> bool {
        self(progress)
    }
}
async fn checkpoint(
    control: &mut impl Control,
    phase: Phase,
    current: usize,
    total: usize,
) -> Result<(), Error> {
    if control
        .checkpoint(Progress {
            phase,
            current,
            total,
        })
        .await
    {
        Ok(())
    } else {
        Err(export::Error::Canceled.into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct File {
    pub name: String,
    pub media_type: String,
    pub encrypted: bool,
}
impl From<export::File> for File {
    fn from(file: export::File) -> Self {
        Self {
            name: file.name.into(),
            media_type: file.media_type.into(),
            encrypted: file.encrypted,
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Review {
    pub token: [u8; 16],
    pub vault: VaultId,
    pub format: export::Format,
    pub file: File,
    pub records: usize,
    pub losses: usize,
    pub blocked: usize,
}
#[derive(Serialize, Deserialize)]
pub struct Row {
    pub index: usize,
    pub head: Head,
    pub title: String,
    pub fields: usize,
}
impl Drop for Row {
    fn drop(&mut self) {
        self.title.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub struct Rows {
    pub items: Vec<Row>,
    pub next: Option<usize>,
}
#[derive(Serialize, Deserialize)]
pub struct SelectionPage {
    pub rows: Vec<Row>,
    pub more: bool,
    pub next: Option<Head>,
}
#[derive(Serialize, Deserialize)]
pub struct IssueRow {
    pub issue: Issue,
    pub title: String,
    pub field_name: Option<String>,
}
impl Drop for IssueRow {
    fn drop(&mut self) {
        self.title.zeroize();
        self.field_name.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub struct Issues {
    pub items: Vec<IssueRow>,
    pub next: Option<usize>,
}
#[derive(Serialize, Deserialize)]
pub struct Ready {
    pub token: [u8; 16],
    pub file: File,
    pub bytes: usize,
}
#[derive(Serialize, Deserialize)]
pub struct Chunk {
    pub offset: usize,
    pub bytes: Bytes,
    pub next: Option<usize>,
    #[serde(skip)]
    _memory: Option<crate::import::Reservation>,
}

enum Stage {
    Preview(export::Plan),
    Ready(export::Artifact),
}
pub(super) struct Session {
    token: [u8; 16],
    vault: VaultId,
    all: bool,
    previous: Vec<Head>,
    active: Vec<Head>,
    stage: Stage,
    _heads_memory: crate::import::Reservation,
}
impl Session {
    fn plan(&self) -> Result<&export::Plan, Error> {
        match &self.stage {
            Stage::Preview(plan) => Ok(plan),
            _ => Err(Error::InvalidSession),
        }
    }
}
fn token() -> Result<[u8; 16], Error> {
    let mut token = [0; 16];
    entropy::fill_random(&mut token).map_err(|_| Error::Entropy)?;
    Ok(token)
}
fn envelope_error(error: envelope::Error) -> Error {
    match error {
        envelope::Error::Allocation => export::Error::Allocation.into(),
        envelope::Error::Limit
        | envelope::Error::Content(confidex_vault::record::Error::Limit)
        | envelope::Error::Compression(confidex_vault::resources::ResourceError::Limit) => {
            export::Error::Limit.into()
        }
        _ => AppError::Integrity.into(),
    }
}
fn label(text: &str) -> String {
    text.chars().take(128).collect()
}
fn title(record: &confidex_vault::record::Record) -> String {
    record
        .extra
        .get(crate::TITLE_KEY)
        .and_then(Value::as_str)
        .map(label)
        .unwrap_or_default()
}
async fn page(
    store: &mut impl Store,
    vault: VaultId,
    after: Option<&Head>,
) -> Result<Vec<Head>, Error> {
    let page = store.branch_heads(vault, after, None).await?;
    if page.len() > confidex_storage::PAGE_SIZE
        || page
            .first()
            .is_some_and(|head| after.is_some_and(|after| head <= after))
        || page.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AppError::Integrity.into());
    }
    Ok(page)
}
async fn check_heads(
    store: &mut impl Store,
    vault: VaultId,
    all: bool,
    previous: &[Head],
    control: &mut impl Control,
) -> Result<(), Error> {
    checkpoint(control, Phase::Check, 0, previous.len()).await?;
    if all {
        let mut offset = 0;
        let mut after = None;
        loop {
            let page = page(store, vault, after.as_ref()).await?;
            if page.is_empty() {
                break;
            }
            let end = offset + page.len();
            if previous.get(offset..end) != Some(page.as_slice()) {
                return Err(Error::Changed);
            }
            after = page.last().cloned();
            offset = end;
            checkpoint(control, Phase::Check, offset, previous.len()).await?;
        }
        if offset != previous.len() {
            return Err(Error::Changed);
        }
    } else {
        let mut current = Vec::new();
        for (index, head) in previous.iter().enumerate() {
            if current
                .first()
                .is_none_or(|h: &Head| h.record != head.record)
            {
                current = crate::record_heads(store, vault, head.record).await?;
            }
            if !current.contains(head) {
                return Err(Error::Changed);
            }
            checkpoint(control, Phase::Check, index + 1, previous.len()).await?;
        }
    }
    Ok(())
}
impl Engine {
    pub async fn export_selection(
        &self,
        store: &mut impl Store,
        after: Option<Head>,
        control: &mut impl Control,
    ) -> Result<SelectionPage, Error> {
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?;
        let heads = page(store, vault.vault_id(), after.as_ref()).await?;
        let memory = crate::import::Memory::new(export::Limits::default().memory_bytes);
        let _labels = memory.reserve(1 << 20).map_err(|_| export::Error::Limit)?;
        let mut rows = Vec::new();
        for (index, head) in heads.iter().enumerate() {
            checkpoint(control, Phase::Read, index, heads.len()).await?;
            let _wire = memory
                .reserve(confidex_storage::MAX_OBJECT)
                .map_err(|_| export::Error::Limit)?;
            let wire = store.object(vault.vault_id(), head.revision).await?;
            if wire.len() > confidex_storage::MAX_OBJECT {
                return Err(export::Error::Limit.into());
            }
            let verified = envelope::verify(
                &wire,
                vault.anchor(),
                Some(&head.revision),
                memory.available(),
            )
            .map_err(envelope_error)?;
            if verified.header().record_id != head.record {
                return Err(AppError::Integrity.into());
            }
            if verified.header().kind == envelope::EventKind::Deletion {
                continue;
            }
            let record = verified
                .open(vault.keys(), memory.available())
                .map_err(envelope_error)?;
            rows.push(Row {
                index: rows.len(),
                head: head.clone(),
                title: title(&record),
                fields: record.entries.len(),
            });
        }
        checkpoint(control, Phase::Read, heads.len(), heads.len()).await?;
        Ok(SelectionPage {
            rows,
            more: heads.len() == confidex_storage::PAGE_SIZE,
            next: heads.last().cloned(),
        })
    }
    pub fn begin_export(&mut self) -> Result<VaultId, Error> {
        self.export_session = None;
        self.import_session = None;
        self.import_input = None;
        self.search = None;
        self.history = None;
        self.vault
            .as_ref()
            .map(|vault| vault.vault_id())
            .ok_or(AppError::Locked.into())
    }
    fn export_session(&self, token: [u8; 16]) -> Result<&Session, Error> {
        self.export_session
            .as_ref()
            .filter(|session| {
                session.token == token
                    && self
                        .vault
                        .as_ref()
                        .is_some_and(|vault| vault.vault_id() == session.vault)
            })
            .ok_or(Error::InvalidSession)
    }
    pub fn cancel_export(&mut self, token: Option<[u8; 16]>) -> Result<(), Error> {
        if let Some(token) = token {
            self.export_session(token)?;
        }
        self.export_session = None;
        Ok(())
    }
    pub async fn prepare_export(
        &mut self,
        store: &mut impl Store,
        selection: &Selection,
        writer: Box<dyn export::Writer>,
        limits: export::Limits,
        control: &mut impl Control,
    ) -> Result<Review, Error> {
        self.begin_export()?;
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?;
        let records_limit = limits.records;
        let mut records = export::Records::new(limits)?;
        let memory = records.memory().clone();
        let heads_memory = memory
            .reserve((MAX_HEADS + records_limit + confidex_storage::PAGE_SIZE) * size_of::<Head>())
            .map_err(|_| export::Error::Limit)?;
        let all = matches!(selection, Selection::All);
        let capacity = if all { MAX_HEADS } else { records_limit };
        let mut previous: Vec<Head> = Vec::new();
        previous
            .try_reserve_exact(capacity)
            .map_err(|_| export::Error::Allocation)?;
        checkpoint(control, Phase::Read, 0, 0).await?;
        match selection {
            Selection::All => loop {
                let page = page(store, vault.vault_id(), previous.last()).await?;
                if page.is_empty() {
                    break;
                }
                if previous.len() + page.len() > MAX_HEADS {
                    return Err(export::Error::Limit.into());
                }
                previous.extend(page);
                checkpoint(control, Phase::Read, 0, previous.len()).await?;
            },
            Selection::Records(heads) => {
                if heads.len() > records_limit {
                    return Err(export::Error::Limit.into());
                }
                previous.extend_from_slice(heads);
                previous.sort_unstable();
                if previous.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(Error::InvalidSelection);
                }
                check_heads(store, vault.vault_id(), false, &previous, control).await?;
            }
        }
        let mut active = Vec::new();
        active
            .try_reserve_exact(records_limit)
            .map_err(|_| export::Error::Allocation)?;
        for (index, head) in previous.iter().enumerate() {
            checkpoint(control, Phase::Read, index, previous.len()).await?;
            let wire_memory = memory
                .reserve(confidex_storage::MAX_OBJECT)
                .map_err(|_| export::Error::Limit)?;
            let wire = store.object(vault.vault_id(), head.revision).await?;
            if wire.len() > confidex_storage::MAX_OBJECT {
                return Err(export::Error::Limit.into());
            }
            let verified = envelope::verify(
                &wire,
                vault.anchor(),
                Some(&head.revision),
                memory.available(),
            )
            .map_err(envelope_error)?;
            if verified.header().record_id != head.record {
                return Err(AppError::Integrity.into());
            }
            if verified.header().kind == envelope::EventKind::Deletion {
                if !all {
                    return Err(Error::InvalidSelection);
                }
                continue;
            }
            let record = verified
                .open(vault.keys(), memory.available())
                .map_err(envelope_error)?;
            drop(verified);
            drop(wire);
            drop(wire_memory);
            records.push(record)?;
            active.push(head.clone());
        }
        check_heads(store, vault.vault_id(), all, &previous, control).await?;
        let plan = export::prepare(records, writer, &mut |progress| control.computing(progress))?;
        checkpoint(control, Phase::Review, plan.records(), plan.records()).await?;
        let token = token()?;
        let review = Review {
            token,
            vault: vault.vault_id(),
            format: plan.format(),
            file: plan.file().into(),
            records: plan.records(),
            losses: plan
                .issues()
                .iter()
                .filter(|issue| issue.severity == Severity::Loss)
                .count(),
            blocked: plan
                .issues()
                .iter()
                .filter(|issue| issue.severity == Severity::Blocked)
                .count(),
        };
        self.export_session = Some(Session {
            token,
            vault: review.vault,
            all,
            previous,
            active,
            stage: Stage::Preview(plan),
            _heads_memory: heads_memory,
        });
        Ok(review)
    }
    pub fn export_rows(&self, token: [u8; 16], start: usize) -> Result<Rows, Error> {
        let session = self.export_session(token)?;
        let plan = session.plan()?;
        let _memory = plan
            .memory()
            .reserve(1 << 20)
            .map_err(|_| export::Error::Limit)?;
        if start > plan.records() {
            return Err(Error::InvalidSelection);
        }
        let end = plan.records().min(start.saturating_add(PAGE_SIZE));
        let items = (start..end)
            .map(|index| {
                let record = plan.record(index).unwrap();
                Row {
                    index,
                    head: session.active[index].clone(),
                    title: title(record),
                    fields: record.entries.len(),
                }
            })
            .collect();
        Ok(Rows {
            items,
            next: (end < plan.records()).then_some(end),
        })
    }
    pub fn export_issues(&self, token: [u8; 16], start: usize) -> Result<Issues, Error> {
        let session = self.export_session(token)?;
        let plan = session.plan()?;
        let _memory = plan
            .memory()
            .reserve(1 << 20)
            .map_err(|_| export::Error::Limit)?;
        if start > plan.issues().len() {
            return Err(Error::InvalidSelection);
        }
        let end = plan.issues().len().min(start.saturating_add(PAGE_SIZE));
        let items = plan.issues()[start..end]
            .iter()
            .map(|&issue| {
                let record = plan.record(issue.record).unwrap();
                IssueRow {
                    issue,
                    title: title(record),
                    field_name: issue.field.map(|field| label(&record.entries[field].name)),
                }
            })
            .collect();
        Ok(Issues {
            items,
            next: (end < plan.issues().len()).then_some(end),
        })
    }
    pub async fn generate_export(
        &mut self,
        store: &mut impl Store,
        token_value: [u8; 16],
        consent: Consent,
        control: &mut impl Control,
    ) -> Result<Ready, Error> {
        let session = self.export_session(token_value)?;
        session.plan()?.check_consent(consent)?;
        let Session {
            vault,
            all,
            previous,
            active,
            stage,
            _heads_memory,
            ..
        } = self.export_session.take().unwrap();
        let Stage::Preview(plan) = stage else {
            unreachable!()
        };
        check_heads(store, vault, all, &previous, control).await?;
        let artifact = plan.write(consent, &mut |progress| control.computing(progress))?;
        check_heads(store, vault, all, &previous, control).await?;
        // Read queued cancellation after synchronous serialization and before release.
        checkpoint(control, Phase::Write, active.len(), active.len()).await?;
        let token = token()?;
        let ready = Ready {
            token,
            file: artifact.file.into(),
            bytes: artifact.bytes().len(),
        };
        self.export_session = Some(Session {
            token,
            vault,
            all,
            previous,
            active,
            stage: Stage::Ready(artifact),
            _heads_memory,
        });
        Ok(ready)
    }
    pub fn export_chunk(&self, token: [u8; 16], offset: usize) -> Result<Chunk, Error> {
        let session = self.export_session(token)?;
        let Stage::Ready(artifact) = &session.stage else {
            return Err(Error::InvalidSession);
        };
        if offset > artifact.bytes().len() {
            return Err(Error::InvalidSelection);
        }
        let end = artifact
            .bytes()
            .len()
            .min(offset.saturating_add(CHUNK_BYTES));
        let memory = artifact
            .memory()
            .reserve(end - offset + 1024)
            .map_err(|_| export::Error::Limit)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(end - offset)
            .map_err(|_| export::Error::Allocation)?;
        bytes.extend_from_slice(&artifact.bytes()[offset..end]);
        Ok(Chunk {
            offset,
            bytes: std::mem::take(&mut *bytes).into(),
            next: (end < artifact.bytes().len()).then_some(end),
            _memory: Some(memory),
        })
    }
    pub fn finish_export(&mut self, token: [u8; 16]) -> Result<(), Error> {
        if !matches!(self.export_session(token)?.stage, Stage::Ready(_)) {
            return Err(Error::InvalidSession);
        }
        self.export_session = None;
        Ok(())
    }
}
