//! Review immutable current records before writing an external file.
use crate::{
    import::{Memory, Reservation},
    import_apply::memory::Owned,
};
use confidex_vault::record::Record;
use serde::{Deserialize, Serialize};
use std::mem::size_of;
mod options;
mod output;
mod registry;
pub(crate) mod totp;
pub use crate::import::Format;
pub use options::{Column, Csv, Options, Source};
pub use options::{MAX_KEYFILE as MAX_KEYFILE_BYTES, MAX_PASSWORD as MAX_PASSWORD_BYTES};
pub(crate) use output::Sink;
pub use output::{Artifact, Output};
pub use registry::{FormatInfo, catalog, writer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    Limit,
    Allocation,
    InvalidRecord,
    InvalidWriter,
    InvalidOptions,
    UnsupportedFormat,
    Losses,
    Blocked,
    Canceled,
    Writer,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::FileTooLarge => Self::Limit,
            std::io::ErrorKind::ConnectionAborted => Self::Canceled,
            _ => Self::Writer,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub records: usize,
    pub snapshot_bytes: usize,
    pub output_bytes: usize,
    pub issues: usize,
    pub memory_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            records: 10_000,
            snapshot_bytes: 64 << 20,
            output_bytes: 64 << 20,
            issues: 100_000,
            memory_bytes: confidex_vault::resources::MAX_OPEN_MEMORY,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<Self, Error> {
        let max = Self::default();
        if [
            (self.records, max.records),
            (self.snapshot_bytes, max.snapshot_bytes),
            (self.output_bytes, max.output_bytes),
            (self.issues, max.issues),
            (self.memory_bytes, max.memory_bytes),
        ]
        .iter()
        .any(|&(value, limit)| value == 0 || value > limit)
        {
            return Err(Error::Limit);
        }
        Ok(self)
    }
}

/// The host authenticates current revisions before adding their full CoreRecords.
pub struct Records {
    items: Vec<Owned>,
    encoded_bytes: usize,
    limits: Limits,
    memory: Memory,
    _headers: Reservation,
}
impl Records {
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let memory = Memory::new(limits.memory_bytes);
        let headers = memory
            .reserve(limits.records * size_of::<Owned>())
            .map_err(|_| Error::Limit)?;
        let mut items = Vec::new();
        items
            .try_reserve_exact(limits.records)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            items,
            encoded_bytes: 0,
            limits,
            memory,
            _headers: headers,
        })
    }
    pub fn push(&mut self, record: Record) -> Result<(), Error> {
        if self.items.len() == self.limits.records {
            return Err(Error::Limit);
        }
        let item = Owned::new(record, &self.memory).map_err(|_| Error::Limit)?;
        let content = item
            .record
            .encode_content(self.memory.available())
            .map_err(|error| match error {
                confidex_vault::record::Error::Limit => Error::Limit,
                confidex_vault::record::Error::Allocation => Error::Allocation,
                _ => Error::InvalidRecord,
            })?;
        let bytes = self
            .encoded_bytes
            .checked_add(content.bytes.len())
            .filter(|&bytes| bytes <= self.limits.snapshot_bytes)
            .ok_or(Error::Limit)?;
        self.items.push(item);
        self.encoded_bytes = bytes;
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<&Record> {
        self.items.get(index).map(|item| &item.record)
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Record> {
        self.items.iter().map(|item| &item.record)
    }
    pub fn memory(&self) -> &Memory {
        &self.memory
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Read,
    Check,
    Review,
    Write,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub phase: Phase,
    pub current: usize,
    pub total: usize,
}
pub(super) struct Control<'a> {
    callback: &'a mut dyn FnMut(Progress) -> bool,
    canceled: bool,
}
impl Control<'_> {
    fn checkpoint(&mut self, progress: Progress) -> Result<(), Error> {
        if self.canceled || !(self.callback)(progress) {
            self.canceled = true;
            return Err(Error::Canceled);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Code {
    UnsupportedField,
    UnknownValue,
    UnknownMetadata,
    Protection,
    FieldOrder,
    FieldNames,
    MultipleUrls,
    TotpParameters,
    Attachments,
    Tags,
    Sections,
    SourceContext,
    History,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Loss,
    Blocked,
}
/// Locations and codes contain no field names, values, or source snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub record: usize,
    pub field: Option<usize>,
    pub severity: Severity,
    pub code: Code,
}
pub struct Review<'a> {
    memory: &'a Memory,
    record: usize,
    fields: usize,
    issues: &'a mut Vec<Issue>,
    limit: usize,
    covered: [u64; confidex_vault::record::MAX_ENTRIES / 64],
    tags: bool,
    metadata: bool,
    error: Option<Error>,
}
impl Review<'_> {
    /// Charge review scratch space before you allocate it.
    pub fn reserve(&self, bytes: usize) -> Result<Reservation, Error> {
        self.memory.reserve(bytes).map_err(|_| Error::Limit)
    }
    /// Check the field name, value, order, protection and extra metadata first.
    pub fn preserved(&mut self, field: usize) -> Result<(), Error> {
        if field >= self.fields {
            self.error = Some(Error::InvalidWriter);
            return Err(Error::InvalidWriter);
        }
        self.covered[field / 64] |= 1 << (field % 64);
        Ok(())
    }
    /// Acknowledge tags after reporting any loss of their values or grouping.
    pub fn tags(&mut self) {
        self.tags = true;
    }
    /// Inspect all Record.extra values, including source context and unknown keys.
    pub fn metadata(&mut self) {
        self.metadata = true;
    }
    pub fn issue(
        &mut self,
        field: Option<usize>,
        severity: Severity,
        code: Code,
    ) -> Result<(), Error> {
        if let Some(field) = field {
            self.preserved(field)?;
        }
        if self.issues.len() == self.limit {
            self.error = Some(Error::Limit);
            return Err(Error::Limit);
        }
        self.issues.push(Issue {
            record: self.record,
            field,
            severity,
            code,
        });
        Ok(())
    }
    fn finish(self) -> Result<(), Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if !self.tags
            || !self.metadata
            || (0..self.fields).any(|field| self.covered[field / 64] & (1 << (field % 64)) == 0)
        {
            return Err(Error::InvalidWriter);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct File {
    pub name: &'static str,
    pub media_type: &'static str,
    pub encrypted: bool,
}
impl File {
    fn validate(self) -> Result<(), Error> {
        if self.name.is_empty()
            || self.name.len() > 128
            || self.name.starts_with('.')
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.media_type.is_empty()
            || self.media_type.len() > 128
            || !self.media_type.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::InvalidWriter);
        }
        Ok(())
    }
}
/// Keep options in the writer. Review and write must use the same configuration.
/// Report every unrepresented field, value, protection flag, tag and metadata item.
/// Current record values are authoritative; source metadata must not restore old values.
pub trait Writer: Send {
    fn format(&self) -> Format;
    fn file(&self) -> File;
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error>;
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Consent {
    #[default]
    Lossless,
    AllowLosses,
}
pub struct Plan {
    records: Records,
    writer: Box<dyn Writer>,
    file: File,
    format: Format,
    issues: Vec<Issue>,
    _issues_memory: Reservation,
}
pub fn prepare(
    records: Records,
    writer: Box<dyn Writer>,
    callback: &mut dyn FnMut(Progress) -> bool,
) -> Result<Plan, Error> {
    let file = writer.file();
    let format = writer.format();
    file.validate()?;
    let mut control = Control {
        callback,
        canceled: false,
    };
    let reservation = records
        .memory
        .reserve(records.limits.issues * size_of::<Issue>())
        .map_err(|_| Error::Limit)?;
    let mut issues = Vec::new();
    issues
        .try_reserve_exact(records.limits.issues)
        .map_err(|_| Error::Allocation)?;
    for (index, record) in records.iter().enumerate() {
        control.checkpoint(Progress {
            phase: Phase::Review,
            current: index,
            total: records.len(),
        })?;
        let mut review = Review {
            memory: &records.memory,
            record: index,
            fields: record.entries.len(),
            issues: &mut issues,
            limit: records.limits.issues,
            covered: [0; confidex_vault::record::MAX_ENTRIES / 64],
            tags: record.tags.is_empty(),
            metadata: record.extra.is_empty(),
            error: None,
        };
        writer.review(record, &mut review)?;
        review.finish()?;
    }
    control.checkpoint(Progress {
        phase: Phase::Review,
        current: records.len(),
        total: records.len(),
    })?;
    Ok(Plan {
        records,
        writer,
        file,
        format,
        issues,
        _issues_memory: reservation,
    })
}
impl Plan {
    pub(crate) fn record(&self, index: usize) -> Option<&Record> {
        self.records.get(index)
    }
    pub(crate) fn memory(&self) -> &Memory {
        self.records.memory()
    }
    pub fn format(&self) -> Format {
        self.format
    }
    pub fn file(&self) -> File {
        self.file
    }
    pub fn records(&self) -> usize {
        self.records.len()
    }
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }
    pub fn check_consent(&self, consent: Consent) -> Result<(), Error> {
        if self
            .issues
            .iter()
            .any(|issue| issue.severity == Severity::Blocked)
        {
            return Err(Error::Blocked);
        }
        if !self.issues.is_empty() && consent != Consent::AllowLosses {
            return Err(Error::Losses);
        }
        Ok(())
    }
    pub fn write(
        self,
        consent: Consent,
        callback: &mut dyn FnMut(Progress) -> bool,
    ) -> Result<Artifact, Error> {
        self.check_consent(consent)?;
        let mut output = Output::new(&self.records, callback)?;
        output.checkpoint(0, self.records.len())?;
        let result = self.writer.write(&self.records, &mut output);
        output.status()?;
        result?;
        output.checkpoint(self.records.len(), self.records.len())?;
        Ok(output.finish(self.file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_names_and_media_types_cannot_contain_paths_or_header_controls() {
        let file = File {
            name: "confidex-export.json",
            media_type: "application/json",
            encrypted: false,
        };
        assert_eq!(file.validate(), Ok(()));
        for name in [
            "",
            ".hidden",
            "../escape.json",
            "a/b.json",
            "a\\b.json",
            "a\n.json",
        ] {
            assert_eq!(File { name, ..file }.validate(), Err(Error::InvalidWriter));
        }
        for media_type in ["", "text/plain\r\nX-Header: value", "text/plain\0"] {
            assert_eq!(
                File { media_type, ..file }.validate(),
                Err(Error::InvalidWriter)
            );
        }
    }
}
