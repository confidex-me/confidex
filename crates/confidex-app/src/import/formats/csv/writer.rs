//! Stream current values with an explicit positional mapping or a verified profile.
use super::{Profile, mapping};
use crate::export::{self, Code, Csv, Error, Output, Records, Review, Severity, Source, totp};
use confidex_vault::record::{Entry, MAX_ENTRIES, Record, Value};
use std::{
    collections::BTreeSet,
    io::{self, Write},
};

pub struct Writer {
    config: Csv,
    profile: Option<Profile>,
}
#[derive(Clone, Copy)]
enum Binding<'a> {
    Title,
    Tags,
    Field(usize, &'a Entry, &'a str, &'a str),
    Empty,
    Invalid,
}
fn same(a: &Source, b: &Source) -> bool {
    match (a, b) {
        (Source::Title, Source::Title) | (Source::Tags, Source::Tags) => true,
        (
            Source::Field {
                index: a,
                type_name: at,
                key: ak,
            },
            Source::Field {
                index: b,
                type_name: bt,
                key: bk,
            },
        ) => a == b && at == bt && ak == bk,
        _ => false,
    }
}
fn private(kind: &str) -> bool {
    matches!(
        kind,
        "password/v1" | "secret/v1" | "secure-note/v1" | "totp/v1"
    )
}
fn hidden(entry: &Entry) -> bool {
    private(&entry.type_name) || crate::field_protected(entry)
}
fn is_otp(entry: &Entry, key: &str) -> bool {
    entry.type_name == "totp/v1" && key == "secret"
}
fn member<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let mut fields = value
        .as_map()?
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key));
    let value = &fields.next()?.1;
    fields.next().is_none().then_some(value)
}
fn origin(record: &Record) -> Option<&Value> {
    let origin = record.extra.get("confidex.import.origin")?;
    (member(origin, "version")?.as_u64() == Some(1)
        && member(origin, "format")?.as_str() == Some("csv"))
    .then_some(origin)
}
fn source_profile(record: &Record, profile: Profile) -> bool {
    let check = || {
        let container = member(origin(record)?, "container")?;
        if member(container, "source_format")?.as_str() != Some("generic-csv")
            || member(container, "header")?.as_bool() != Some(true)
            || member(container, "delimiter")?.as_u64() != Some(u64::from(b','))
        {
            return None;
        }
        let columns = member(container, "columns")?.as_array()?;
        (columns.len() == profile.headings().len()
            && columns.iter().enumerate().all(|(index, column)| {
                member(column, "index").and_then(Value::as_u64) == Some(index as u64)
                    && member(column, "source_name").and_then(Value::as_str)
                        == Some(profile.headings()[index])
                    && member(column, "target").and_then(Value::as_str)
                        == Some(profile.target(index))
            }))
        .then_some(())
    };
    check().is_some()
}
fn source_null(record: &Record, column: usize) -> bool {
    let check = || {
        let attributes = member(origin(record)?, "attributes")?;
        let empty = member(attributes, "empty_cells")?.as_array()?;
        if empty.len() > MAX_ENTRIES {
            return None;
        }
        let mut cells = empty
            .iter()
            .filter_map(|value| value.as_array())
            .filter(|cell| cell.len() == 2 && cell[0].as_u64() == Some(column as u64));
        let cell = cells.next()?;
        (cell[1].as_bool() == Some(false) && cells.next().is_none()).then_some(())
    };
    check().is_some()
}
impl Writer {
    pub fn new(config: Csv) -> Result<Self, Error> {
        config.validate()?;
        let profile = match config.profile.as_deref() {
            None => None,
            Some("chromium") => Some(Profile::Chromium),
            Some("firefox") => Some(Profile::Firefox),
            Some("apple-passwords") => Some(Profile::ApplePasswords),
            Some(_) => return Err(Error::InvalidOptions),
        };
        if profile.is_some() && (config.delimiter != b',' || !config.header)
            || config.columns.iter().any(|c| c.heading.contains('\0'))
            || config.columns.iter().enumerate().any(|(n, column)| {
                config.columns[..n]
                    .iter()
                    .any(|other| same(&column.source, &other.source))
            })
        {
            return Err(Error::InvalidOptions);
        }
        Ok(Self { config, profile })
    }
    fn width(&self) -> usize {
        self.profile
            .map_or(self.config.columns.len(), |p| p.headings().len())
    }
    fn heading(&self, column: usize) -> &str {
        self.profile.map_or_else(
            || self.config.columns[column].heading.as_str(),
            |p| p.headings()[column],
        )
    }
    fn binding<'a>(&'a self, record: &'a Record, column: usize) -> Binding<'a> {
        if let Some(profile) = self.profile {
            let target = profile.target(column);
            if target == "title" {
                return Binding::Title;
            }
            if source_profile(record, profile) {
                let mut fields = record.entries.iter().enumerate().filter(|(_, entry)| {
                    entry
                        .extra
                        .get("confidex.import.csv.column")
                        .and_then(Value::as_u64)
                        == Some(column as u64)
                });
                let Some((index, entry)) = fields.next() else {
                    return Binding::Empty;
                };
                if fields.next().is_some() || entry.type_name != target {
                    return Binding::Invalid;
                }
                return Binding::Field(index, entry, mapping::key(target).unwrap(), target);
            }
            // CSV source-only realms, IDs and timestamps are not inferred from text labels.
            if profile == Profile::Firefox && column >= 3 {
                return Binding::Empty;
            }
            let selected = record.entries.iter().enumerate().find(|(_, entry)| {
                entry.type_name == target
                    || target == "secure-note/v1" && entry.type_name == "note/v1"
            });
            return selected.map_or(Binding::Empty, |(index, entry)| {
                Binding::Field(
                    index,
                    entry,
                    mapping::key(&entry.type_name).unwrap(),
                    target,
                )
            });
        }
        match &self.config.columns[column].source {
            Source::Title => Binding::Title,
            Source::Tags => Binding::Tags,
            Source::Field {
                index,
                type_name,
                key,
            } => record
                .entries
                .get(*index)
                .filter(|e| e.type_name == *type_name)
                .map_or(Binding::Invalid, |entry| {
                    Binding::Field(*index, entry, key, type_name)
                }),
        }
    }
    fn cell(&self, record: &Record, column: usize, output: &mut Output<'_>) -> Result<(), Error> {
        let binding = self.binding(record, column);
        if matches!(binding, Binding::Invalid) {
            return Err(Error::Blocked);
        }
        if self.profile == Some(Profile::Firefox) {
            if column >= 3 && matches!(binding, Binding::Empty) {
                return Ok(());
            }
            if let Binding::Field(_, entry, key, _) = binding
                && entry.value.get(key).and_then(Value::as_str) == Some("")
                && source_profile(record, Profile::Firefox)
                && source_null(record, column)
            {
                return Ok(());
            }
        }
        output.write_all(b"\"")?;
        match binding {
            Binding::Title => Quote(output).write_all(
                record
                    .extra
                    .get("confidex.title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            )?,
            Binding::Tags => {
                serde_json::to_writer(Quote(output), &record.tags).map_err(|_| Error::Writer)?
            }
            Binding::Field(_, entry, key, _) if is_otp(entry, key) => {
                if totp::valid_totp(entry) {
                    let _memory = totp::otp_raw(entry)
                        .map(|raw| totp::otp_scratch(raw).and_then(|n| output.reserve(n)))
                        .transpose()?;
                    let raw = totp::matching_otp(entry).filter(|s| !s.contains('\0'));
                    if let Some(raw) = raw {
                        Quote(output).write_all(raw.as_bytes())?;
                    } else {
                        write!(Quote(output), "{}", totp::Otp(entry, None))?;
                    }
                }
            }
            Binding::Field(_, entry, key, _) => {
                let value = entry.value.get(key).ok_or(Error::Blocked)?;
                if let Some(text) = value.as_str() {
                    Quote(output).write_all(text.as_bytes())?;
                }
            }
            Binding::Empty => {}
            Binding::Invalid => unreachable!(),
        }
        output.write_all(b"\"")?;
        Ok(())
    }
}

impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::Csv
    }
    fn file(&self) -> export::File {
        export::File {
            name: match self.profile {
                None => "confidex.csv",
                Some(Profile::Chromium) => "chromium.csv",
                Some(Profile::Firefox) => "firefox.csv",
                Some(Profile::ApplePasswords) => "apple-passwords.csv",
            },
            media_type: "text/csv",
            encrypted: false,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        let _scratch = review.reserve(self.width() * 128 + 8192)?;
        let mut keys = BTreeSet::new();
        let mut first = [usize::MAX; MAX_ENTRIES];
        let mut count = [0u16; MAX_ENTRIES];
        let mut title = false;
        let mut tags = false;
        for column in 0..self.width() {
            match self.binding(record, column) {
                Binding::Invalid => review.issue(None, Severity::Blocked, Code::SourceContext)?,
                Binding::Title => {
                    title = true;
                    match record.extra.get("confidex.title").and_then(Value::as_str) {
                        Some(text) if text.contains('\0') => {
                            review.issue(None, Severity::Blocked, Code::UnknownValue)?
                        }
                        None => review.issue(None, Severity::Loss, Code::UnknownValue)?,
                        _ => {}
                    }
                }
                Binding::Tags => tags = true,
                Binding::Empty => {
                    if self.profile.is_none_or(|p| p.target(column) != "totp/v1") {
                        review.issue(None, Severity::Loss, Code::UnknownValue)?;
                    }
                }
                Binding::Field(index, entry, key, target) => {
                    first[index] = first[index].min(column);
                    count[index] += 1;
                    keys.insert((index, key));
                    let mut issue = |severity, code| review.issue(Some(index), severity, code);
                    if entry.name != self.heading(column) {
                        issue(Severity::Loss, Code::FieldNames)?;
                    }
                    if entry.type_name != target || mapping::key(target) != Some(key) {
                        issue(Severity::Loss, Code::UnsupportedField)?;
                    }
                    let target_private = private(target)
                        && !(self.profile.is_some() && target == "secure-note/v1")
                        && !(self.profile == Some(Profile::Firefox) && column >= 3);
                    if hidden(entry) && !target_private {
                        issue(Severity::Loss, Code::Protection)?;
                    }
                    if is_otp(entry, key) {
                        if !totp::valid_totp(entry) {
                            issue(Severity::Loss, Code::TotpParameters)?;
                        }
                    } else {
                        match entry.value.get(key) {
                            Some(value)
                                if value.as_str().is_some_and(|text| text.contains('\0')) =>
                            {
                                issue(Severity::Blocked, Code::UnknownValue)?
                            }
                            Some(value) if value.as_str().is_none() => {
                                issue(Severity::Loss, Code::UnknownValue)?
                            }
                            None => issue(Severity::Blocked, Code::UnknownValue)?,
                            _ => {}
                        }
                    }
                }
            }
        }
        let mut previous = 0;
        for (index, entry) in record.entries.iter().enumerate() {
            let mut loss = |code| review.issue(Some(index), Severity::Loss, code);
            if count[index] == 0 {
                loss(match entry.type_name.as_str() {
                    "file/v1" | "photo/v1" => Code::Attachments,
                    "url/v1" => Code::MultipleUrls,
                    "totp/v1" => Code::TotpParameters,
                    _ => Code::UnsupportedField,
                })?;
                continue;
            }
            if count[index] > 1 {
                loss(Code::UnsupportedField)?;
            }
            if matches!(entry.type_name.as_str(), "file/v1" | "photo/v1") {
                loss(Code::Attachments)?;
            }
            if first[index] < previous {
                loss(Code::FieldOrder)?;
            }
            previous = previous.max(first[index]);
            let otp = keys.contains(&(index, "secret")) && entry.type_name == "totp/v1";
            if entry.value.keys().any(|key| {
                !keys.contains(&(index, key.as_str()))
                    && !(otp && matches!(key.as_str(), "algorithm" | "digits" | "period" | "t0"))
            }) {
                loss(Code::UnknownValue)?;
            }
            let _memory = if otp {
                totp::otp_raw(entry)
                    .map(|raw| totp::otp_scratch(raw).and_then(|n| review.reserve(n)))
                    .transpose()?
            } else {
                None
            };
            let otp_preserved =
                otp && totp::matching_otp(entry).is_some_and(|raw| !raw.contains('\0'));
            for (key, value) in &entry.extra {
                let recognized = key == "metadata"
                    && value.as_map().is_some_and(|m| {
                        m.len() == 1
                            && m[0].0.as_str() == Some("protected")
                            && m[0].1.as_bool().is_some()
                    })
                    || key == "confidex.import.csv.column"
                        && count[index] == 1
                        && value.as_u64() == Some(first[index] as u64)
                    || key == "confidex.import.totp" && otp_preserved;
                if !recognized {
                    review.issue(
                        Some(index),
                        Severity::Loss,
                        if key.starts_with("confidex.import.") {
                            Code::SourceContext
                        } else {
                            Code::UnknownMetadata
                        },
                    )?;
                }
            }
            review.preserved(index)?;
        }
        if tags || !record.tags.is_empty() {
            review.issue(None, Severity::Loss, Code::Tags)?;
        }
        review.tags();
        for (key, value) in &record.extra {
            if key == "confidex.title" && title && value.as_str().is_some() {
                continue;
            }
            review.issue(
                None,
                Severity::Loss,
                match key.as_str() {
                    "confidex.title" => Code::FieldNames,
                    "confidex.import.origin" => Code::SourceContext,
                    "confidex.sections" => Code::Sections,
                    _ => Code::UnknownMetadata,
                },
            )?;
        }
        review.metadata();
        Ok(())
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        if self.config.header {
            for column in 0..self.width() {
                if column > 0 {
                    output.write_all(&[self.config.delimiter])?;
                }
                output.write_all(b"\"")?;
                Quote(output).write_all(self.heading(column).as_bytes())?;
                output.write_all(b"\"")?;
            }
            output.write_all(b"\r\n")?;
        }
        for (index, record) in records.iter().enumerate() {
            output.checkpoint(index, records.len())?;
            for column in 0..self.width() {
                if column > 0 {
                    output.write_all(&[self.config.delimiter])?;
                }
                self.cell(record, column, output)?;
            }
            output.write_all(b"\r\n")?;
        }
        Ok(())
    }
}

/// Quoting changes CSV syntax only; it never prefixes or trims cell values.
struct Quote<'a, 'callback>(&'a mut Output<'callback>);
impl Write for Quote<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for chunk in bytes.chunks(65_536) {
            let mut start = 0;
            for (index, byte) in chunk.iter().enumerate() {
                if *byte == b'"' {
                    self.0.write_all(&chunk[start..index])?;
                    self.0.write_all(b"\"\"")?;
                    start = index + 1;
                }
            }
            self.0.write_all(&chunk[start..])?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
