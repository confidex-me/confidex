//! Bounded import messages shared by native and browser hosts.
use crate::{Draft, Engine, Error as AppError, import, import_apply};
use confidex_storage::{Store, VaultId};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
mod credentials;
mod csv;
pub use csv::{Profile as CsvProfile, Setup as CsvSetup};

pub const PAGE_SIZE: usize = 64;
pub const MAX_FILE_BYTES: usize = 64 << 20;
pub const MAX_KEYFILE_BYTES: usize = 1 << 20;
pub const FORMATS: &[import::Format] = &[
    import::Format::BitwardenJson,
    import::Format::Onepassword1pux,
    import::Format::KeepassXml,
    import::Format::BitwardenZip,
    import::Format::BitwardenEncryptedJson,
    import::Format::Csv,
    import::Format::Kdbx,
];

pub(super) struct Input {
    token: [u8; 16],
    vault: VaultId,
    file: File,
    bytes: Zeroizing<Vec<u8>>,
    options: import::Options,
    format: import::Format,
    memory: Option<import::Reservation>,
}

#[derive(Serialize, Deserialize)]
pub enum Command {
    Begin,
    Prepare {
        operation: u32,
        file_name: String,
        format: Option<import::Format>,
        options: import::Options,
        bytes: Vec<u8>,
    },
    Unlock {
        operation: u32,
        token: [u8; 16],
        password: String,
    },
    UnlockKdbx {
        operation: u32,
        token: [u8; 16],
        password: Option<String>,
        keyfile: Option<Vec<u8>>,
    },
    ConfigureCsv {
        operation: u32,
        token: [u8; 16],
        delimiter: u8,
        header: bool,
    },
    PreviewCsv {
        operation: u32,
        token: [u8; 16],
        mapping: import::CsvMapping,
    },
    Rows {
        token: [u8; 16],
        start: usize,
    },
    Preview {
        token: [u8; 16],
        index: usize,
    },
    Candidates {
        token: [u8; 16],
        index: usize,
        after: usize,
    },
    Apply {
        operation: u32,
        token: [u8; 16],
        selection: import_apply::Selection,
        epoch: u64,
    },
    Cancel {
        token: Option<[u8; 16]>,
    },
}
impl Drop for Command {
    fn drop(&mut self) {
        if let Self::Prepare {
            file_name, bytes, ..
        } = self
        {
            file_name.zeroize();
            bytes.zeroize();
        }
        if let Self::Unlock { password, .. } = self {
            password.zeroize();
        }
        if let Self::UnlockKdbx {
            password, keyfile, ..
        } = self
        {
            password.zeroize();
            keyfile.zeroize();
        }
    }
}
impl Command {
    pub fn operation(&self) -> Option<u32> {
        match self {
            Self::Prepare { operation, .. }
            | Self::Unlock { operation, .. }
            | Self::UnlockKdbx { operation, .. }
            | Self::ConfigureCsv { operation, .. }
            | Self::PreviewCsv { operation, .. }
            | Self::Apply { operation, .. } => Some(*operation),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    App(AppError),
    Parse(import::Error),
    Apply(import_apply::Error),
    Unsupported,
    InvalidOptions,
    Authentication,
    AccountRestricted,
}
impl From<AppError> for Error {
    fn from(value: AppError) -> Self {
        Self::App(value)
    }
}
impl From<import::Error> for Error {
    fn from(value: import::Error) -> Self {
        Self::Parse(value)
    }
}
impl From<import_apply::Error> for Error {
    fn from(value: import_apply::Error) -> Self {
        Self::Apply(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Inspect,
    Parse,
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
impl From<import::Progress> for Progress {
    fn from(value: import::Progress) -> Self {
        Self {
            phase: if value.phase == import::Phase::Inspect {
                Phase::Inspect
            } else {
                Phase::Parse
            },
            current: value.current,
            // Parser totals can specify resource limits.
            total: 0,
        }
    }
}
impl From<import_apply::Progress> for Progress {
    fn from(value: import_apply::Progress) -> Self {
        Self {
            phase: match value.phase {
                import_apply::Phase::Catalog | import_apply::Phase::Review => Phase::Review,
                import_apply::Phase::Seal => Phase::Seal,
                import_apply::Phase::Commit => Phase::Commit,
            },
            current: value.current,
            total: if value.phase == import_apply::Phase::Catalog {
                0
            } else {
                value.total
            },
        }
    }
}
#[allow(async_fn_in_trait)]
pub trait Control: import_apply::Control {
    fn parsing(&mut self, progress: import::Progress) -> bool;
}
pub struct Quiet;
impl import_apply::Control for Quiet {
    async fn checkpoint(&mut self, _: import_apply::Progress) -> bool {
        true
    }
}
impl Control for Quiet {
    fn parsing(&mut self, _: import::Progress) -> bool {
        true
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct File {
    pub name: String,
    pub bytes: usize,
}
impl Drop for File {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Row {
    pub index: usize,
    pub title: String,
    pub source_vault: Option<String>,
    pub source_account: Option<String>,
    pub fields: usize,
    pub diagnostics: Vec<import::Diagnostic>,
}
impl Drop for Row {
    fn drop(&mut self) {
        self.title.zeroize();
        self.source_vault.zeroize();
        self.source_account.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub struct Candidate {
    pub state: import_apply::Candidate,
    pub title: String,
}
impl Drop for Candidate {
    fn drop(&mut self) {
        self.title.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub struct Candidates {
    pub items: Vec<Candidate>,
    pub next: Option<usize>,
}
#[derive(Serialize, Deserialize)]
pub enum Reply {
    CsvRequired {
        operation: u32,
        setup: CsvSetup,
    },
    Begun {
        vault: VaultId,
        formats: Vec<import::Format>,
    },
    KdbxRequired {
        operation: u32,
        token: [u8; 16],
        file: File,
    },
    PasswordRequired {
        operation: u32,
        token: [u8; 16],
        file: File,
    },
    Reviewed {
        operation: u32,
        file: File,
        review: import_apply::Review,
    },
    Rows {
        token: [u8; 16],
        start: usize,
        rows: Vec<Row>,
        next: Option<usize>,
    },
    Preview {
        token: [u8; 16],
        index: usize,
        draft: Draft,
    },
    Candidates {
        token: [u8; 16],
        index: usize,
        after: usize,
        candidates: Candidates,
    },
    Progress {
        operation: u32,
        progress: Progress,
    },
    Applied {
        operation: u32,
        report: import_apply::Report,
    },
    Canceled,
}

impl Engine {
    pub async fn execute_import(
        &mut self,
        store: &mut impl Store,
        command: &mut Command,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        match command {
            Command::Begin => Ok(Reply::Begun {
                vault: self.begin_import()?,
                formats: FORMATS.to_vec(),
            }),
            Command::Prepare {
                operation,
                file_name,
                format,
                options,
                bytes,
            } => {
                let vault = self.begin_import()?;
                let input = Zeroizing::new(std::mem::take(bytes));
                if input.len() > MAX_FILE_BYTES {
                    return Err(import::Error::from(import::ErrorKind::Limit).into());
                }
                if file_name.len() > 4096
                    || options.password.len() > 65536
                    || options
                        .source_instance
                        .as_ref()
                        .is_none_or(|scope| scope.trim().is_empty() || scope.len() > 4096)
                {
                    return Err(Error::InvalidOptions);
                }
                // CSV has no signature: its bounded reader validates an explicit selection.
                if *format == Some(import::Format::Csv) {
                    return self
                        .begin_csv(
                            vault,
                            *operation,
                            File {
                                name: std::mem::take(file_name),
                                bytes: input.len(),
                            },
                            input,
                            std::mem::take(options),
                            control,
                        )
                        .await;
                }
                let inspection =
                    import::inspect(&input, import::Limits::default(), &mut |progress| {
                        control.parsing(progress)
                    })?;
                if !inspection
                    .candidates
                    .iter()
                    .any(|format| FORMATS.contains(format))
                {
                    return Err(Error::Unsupported);
                }
                let selected = match *format {
                    Some(format) if inspection.candidates.contains(&format) => format,
                    None if inspection.candidates.len() == 1
                        && !inspection.confirmation_required =>
                    {
                        inspection.candidates[0]
                    }
                    _ => return Err(Error::InvalidOptions),
                };
                if selected == import::Format::Kdbx {
                    return self
                        .begin_unlock(
                            *operation,
                            selected,
                            File {
                                name: std::mem::take(file_name),
                                bytes: input.len(),
                            },
                            input,
                            std::mem::take(options),
                            control,
                        )
                        .await;
                }
                let parser: import::Parser = match selected {
                    import::Format::BitwardenJson => import::formats::bitwarden_json::parse,
                    import::Format::Onepassword1pux => import::formats::onepassword_1pux::parse,
                    import::Format::KeepassXml => import::formats::keepass_xml::parse,
                    import::Format::BitwardenZip => import::formats::bitwarden_zip::parse,
                    import::Format::BitwardenEncryptedJson => {
                        import::formats::bitwarden_encrypted_json::parse
                    }
                    _ => return Err(Error::Unsupported),
                };
                if selected == import::Format::BitwardenEncryptedJson && options.password.is_empty()
                {
                    match import::prepare(
                        selected,
                        &input,
                        options,
                        import::Limits::default(),
                        &mut |progress| control.parsing(progress),
                        parser,
                    ) {
                        Err(error) if error.kind == import::ErrorKind::InvalidOptions => (),
                        Err(error) if error.kind == import::ErrorKind::UnsupportedFormat => {
                            return Err(Error::AccountRestricted);
                        }
                        Err(error) => return Err(error.into()),
                        Ok(_) => return Err(Error::InvalidOptions),
                    }
                    return self
                        .begin_unlock(
                            *operation,
                            selected,
                            File {
                                name: std::mem::take(file_name),
                                bytes: input.len(),
                            },
                            input,
                            std::mem::take(options),
                            control,
                        )
                        .await;
                }
                let parsed = import::prepare(
                    selected,
                    &input,
                    options,
                    import::Limits::default(),
                    &mut |progress| control.parsing(progress),
                    parser,
                )?;
                let size = input.len();
                drop(input);
                *options = import::Options::default();
                self.review_source(
                    store,
                    vault,
                    *operation,
                    File {
                        name: std::mem::take(file_name),
                        bytes: size,
                    },
                    parsed,
                    control,
                )
                .await
            }
            command @ (Command::Unlock { .. } | Command::UnlockKdbx { .. }) => {
                self.unlock_source(store, command, control).await
            }
            Command::ConfigureCsv {
                operation,
                token,
                delimiter,
                header,
            } => self.configure_csv(*operation, *token, *delimiter, *header, control),
            Command::PreviewCsv {
                operation,
                token,
                mapping,
            } => {
                self.preview_csv(store, *operation, *token, mapping, control)
                    .await
            }
            Command::Rows { token, start } => {
                let plan = self.import_plan(*token)?;
                if *start > plan.items.len() {
                    return Err(Error::InvalidOptions);
                }
                let _output = plan.memory().reserve(8 << 20)?;
                let mut rows = Vec::new();
                let mut estimated = 0usize;
                for index in *start..plan.items.len().min(start.saturating_add(PAGE_SIZE)) {
                    let item = &plan.items[index];
                    let record = crate::import_apply::memory::Owned::new(
                        item.record(plan.memory().available())?,
                        plan.memory(),
                    )?;
                    let bytes = item.source.vault.as_ref().map_or(0, String::len)
                        + item.source.account.as_ref().map_or(0, String::len)
                        + record
                            .record
                            .extra
                            .get("confidex.title")
                            .and_then(confidex_vault::record::Value::as_str)
                            .map_or(0, str::len);
                    let cost = bytes
                        .checked_mul(6)
                        .and_then(|size| size.checked_add(item.diagnostics.len() * 160 + 1024))
                        .ok_or(Error::InvalidOptions)?;
                    if cost > 4 << 20 {
                        return Err(import::Error::from(import::ErrorKind::Limit).into());
                    }
                    if !rows.is_empty() && estimated + cost > 4 << 20 {
                        break;
                    }
                    estimated += cost;
                    rows.push(Row {
                        index,
                        title: crate::title(&record.record)?,
                        source_vault: item.source.vault.clone(),
                        source_account: item.source.account.clone(),
                        fields: record.record.entries.len(),
                        diagnostics: item.diagnostics.clone(),
                    });
                }
                let end = *start + rows.len();
                Ok(Reply::Rows {
                    token: *token,
                    start: *start,
                    rows,
                    next: (end < plan.items.len()).then_some(end),
                })
            }
            Command::Preview { token, index } => {
                let plan = self.import_plan(*token)?;
                let item = plan.items.get(*index).ok_or(Error::InvalidOptions)?;
                let _output = plan.memory().reserve(16 << 20)?;
                let record = crate::import_apply::memory::Owned::new(
                    item.record(plan.memory().available())?,
                    plan.memory(),
                )?;
                let fields = crate::fields::read(&record.record)?;
                let draft = Draft {
                    record: [0; 16],
                    revision: None,
                    title: crate::title(&record.record)?,
                    sections: crate::sections::read(&record.record, &fields),
                    fields,
                    tags: record.record.tags.clone(),
                };
                Ok(Reply::Preview {
                    token: *token,
                    index: *index,
                    draft,
                })
            }
            Command::Candidates {
                token,
                index,
                after,
            } => {
                let candidates = self.import_candidates(*token, *index, *after)?;
                let _memory = self.import_plan(*token)?.memory().reserve(32 << 20)?;
                let vault = self.vault.as_ref().ok_or(AppError::Locked)?;
                let mut items = Vec::with_capacity(candidates.items.len());
                for state in candidates.items {
                    let mut draft =
                        crate::read_draft(store, vault, state.head.record, state.head.revision)
                            .await?;
                    let title = draft
                        .as_mut()
                        .map(|draft| std::mem::take(&mut draft.title))
                        .unwrap_or_default();
                    items.push(Candidate { state, title });
                }
                Ok(Reply::Candidates {
                    token: *token,
                    index: *index,
                    after: *after,
                    candidates: Candidates {
                        items,
                        next: candidates.next,
                    },
                })
            }
            Command::Apply {
                operation,
                token,
                selection,
                epoch,
            } => {
                let report = self
                    .apply_import(store, *token, selection, *epoch, control)
                    .await?;
                self.import_input = None;
                Ok(Reply::Applied {
                    operation: *operation,
                    report,
                })
            }
            Command::Cancel { token } => {
                if let Some(token) = token {
                    if self.import_input.is_some() || self.import_session.is_some() {
                        if !self
                            .import_input
                            .as_ref()
                            .is_some_and(|source| source.token == *token)
                            && self.import_plan(*token).is_err()
                        {
                            return Err(import_apply::Error::InvalidSession.into());
                        }
                        self.import_input = None;
                        self.import_session = None;
                    }
                } else {
                    self.begin_import()?;
                }
                Ok(Reply::Canceled)
            }
        }
    }
    async fn review_source(
        &mut self,
        store: &mut impl Store,
        vault: VaultId,
        operation: u32,
        file: File,
        parsed: import::Plan,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        {
            let _preview_memory = parsed.memory().reserve(8 << 20)?;
            for (index, item) in parsed.items.iter().enumerate() {
                if !control
                    .checkpoint(import_apply::Progress {
                        phase: import_apply::Phase::Review,
                        current: index,
                        total: parsed.items.len(),
                    })
                    .await
                {
                    return Err(import_apply::Error::Canceled.into());
                }
                let record = crate::import_apply::memory::Owned::new(
                    item.record(parsed.memory().available())?,
                    parsed.memory(),
                )?;
                // Do not save records that the client cannot open afterwards.
                crate::fields::read(&record.record)
                    .map_err(|_| import::Error::from(import::ErrorKind::Limit))?;
                // Leave room for escaped fields in the worker response.
                let title = Zeroizing::new(crate::title(&record.record)?);
                let metadata = record.record.tags.iter().fold(title.len(), |bytes, tag| {
                    bytes.saturating_add(tag.len()).saturating_add(32)
                });
                if metadata > 512 << 10 {
                    return Err(import::Error::from(import::ErrorKind::Limit).into());
                }
            }
        }
        let review = self.review_import(store, vault, parsed, control).await?;
        Ok(Reply::Reviewed {
            operation,
            file,
            review,
        })
    }
}
