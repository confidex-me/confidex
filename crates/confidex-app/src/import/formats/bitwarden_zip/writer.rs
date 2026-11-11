//! Individual name-folder ZIPs reuse the JSON mapping and reject ambiguous owners.
use super::{NameIndex, sanitized};
use crate::{
    export::{self, Code, Error, Output, Records, Review, Severity, Sink},
    import::formats::bitwarden_json::{self, Profile},
};
use confidex_vault::{
    entropy,
    record::{Entry, Record},
};
use std::{cell::RefCell, collections::BTreeSet, io::Write};

pub struct Writer {
    namespace: [u8; 16],
}
impl Writer {
    pub fn new() -> Result<Self, Error> {
        let mut namespace = [0; 16];
        entropy::fill_random(&mut namespace).map_err(|_| Error::Writer)?;
        namespace[6] = namespace[6] & 0x0f | 0x40;
        namespace[8] = namespace[8] & 0x3f | 0x80;
        Ok(Self { namespace })
    }
    fn id(&self, index: usize) -> String {
        let mut bytes = self.namespace;
        for (byte, counter) in bytes[12..].iter_mut().zip((index as u32).to_be_bytes()) {
            *byte ^= counter;
        }
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
            u64::from_be_bytes([
                0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ])
        )
    }
}
fn is_file(entry: &Entry) -> bool {
    matches!(entry.type_name.as_str(), "file/v1" | "photo/v1")
}
fn blob(entry: &Entry) -> Option<(&str, &[u8])> {
    is_file(entry).then_some(())?;
    Some((
        entry.value.get("filename")?.as_str()?,
        entry.value.get("data")?.as_slice()?,
    ))
}
fn part(name: &str) -> bool {
    !name.is_empty()
        && !matches!(name, "." | "..")
        && !name.contains(['/', '\\', ':'])
        && !name.chars().any(char::is_control)
}
fn path_len(folder: &str, name: &str) -> usize {
    "attachments/".len() + folder.len() + 1 + name.len()
}

impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::BitwardenZip
    }
    fn file(&self) -> export::File {
        export::File {
            name: "bitwarden-personal.zip",
            media_type: "application/zip",
            encrypted: false,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        let _scratch = review.reserve(record.entries.len() * 128 + 4096)?;
        let name = bitwarden_json::writer::name(record);
        let folder = sanitized(name);
        if name.len() > crate::import::Limits::default().name_bytes {
            review.issue(None, Severity::Blocked, Code::FieldNames)?;
        }
        if record.entries.iter().any(is_file) && !part(&folder) {
            review.issue(None, Severity::Blocked, Code::FieldNames)?;
        }
        let mut names = BTreeSet::new();
        bitwarden_json::Writer::new(Profile::Personal).review_with(
            record,
            review,
            &mut |index, entry, review| {
                if !is_file(entry) {
                    return Ok(false);
                }
                let Some((filename, _)) = blob(entry) else {
                    review.issue(Some(index), Severity::Blocked, Code::Attachments)?;
                    return Ok(true);
                };
                if !part(filename)
                    || path_len(&folder, filename) > crate::import::Limits::default().name_bytes
                    || !names.insert(filename)
                {
                    review.issue(Some(index), Severity::Blocked, Code::FieldNames)?;
                }
                if crate::field_protected(entry) {
                    review.issue(Some(index), Severity::Blocked, Code::Protection)?;
                }
                if entry.name != filename {
                    review.issue(Some(index), Severity::Loss, Code::FieldNames)?;
                }
                if entry.type_name == "photo/v1" {
                    review.issue(Some(index), Severity::Loss, Code::UnsupportedField)?;
                }
                if record.entries[index + 1..].iter().any(|e| !is_file(e)) {
                    review.issue(Some(index), Severity::Loss, Code::FieldOrder)?;
                }
                if entry.value.keys().any(|key| {
                    !matches!(key.as_str(), "data" | "filename" | "mime")
                        || key == "mime"
                            && entry.value["mime"].as_str() != Some("application/octet-stream")
                }) {
                    review.issue(Some(index), Severity::Loss, Code::UnknownValue)?;
                }
                for (key, value) in &entry.extra {
                    if key == "metadata"
                        && value.as_map().is_some_and(|m| {
                            m.len() == 1
                                && m[0].0.as_str() == Some("protected")
                                && m[0].1.as_bool().is_some()
                        })
                    {
                        continue;
                    }
                    review.issue(
                        Some(index),
                        Severity::Loss,
                        if key.starts_with("confidex.import.") || key == "bitwarden.zip.path" {
                            Code::SourceContext
                        } else {
                            Code::UnknownMetadata
                        },
                    )?;
                }
                review.preserved(index)?;
                Ok(true)
            },
        )
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        let total = records.len() * 2;
        let mut directory = 8192usize;
        let mut count = 2usize;
        let mut metadata = 22 + 46 * 2 + "data.json".len() + "attachments/".len();
        for record in records.iter() {
            output.checkpoint(0, total)?;
            let name = bitwarden_json::writer::name(record);
            if name.len() > crate::import::Limits::default().name_bytes {
                return Err(Error::Blocked);
            }
            let mut has_files = false;
            for entry in &record.entries {
                if let Some((filename, _)) = blob(entry) {
                    let length = "attachments/".len() + name.len() + 1 + filename.len();
                    directory = directory
                        .checked_add(4096 + length * 4)
                        .ok_or(Error::Limit)?;
                    metadata = metadata.checked_add(46 + length).ok_or(Error::Limit)?;
                    count += 1;
                    has_files = true;
                }
            }
            if has_files {
                count += 1;
                metadata = metadata
                    .checked_add(46 + "attachments/".len() + name.len() + 1)
                    .ok_or(Error::Limit)?;
            }
        }
        if count > crate::import::Limits::default().zip_entries
            || metadata > crate::import::Limits::default().zip_metadata_bytes
        {
            return Err(Error::Limit);
        }
        let _headers = output.reserve(records.len() * 1024 + 4096)?;
        let mut index = NameIndex::default();
        let mut ids = Vec::new();
        ids.try_reserve_exact(records.len())
            .map_err(|_| Error::Allocation)?;
        for (owner, record) in records.iter().enumerate() {
            output.checkpoint(0, total)?;
            index.add(owner, bitwarden_json::writer::name(record));
            ids.push(self.id(owner));
        }
        let owners = index.finish();
        // Check the same suffix/collision rules as the importer before emitting bytes.
        for (owner, record) in records.iter().enumerate() {
            output.checkpoint(0, total)?;
            if record.entries.iter().any(is_file)
                && owners.owner(&sanitized(bitwarden_json::writer::name(record))) != Ok(Some(owner))
            {
                return Err(Error::Blocked);
            }
        }
        let _directory = output.reserve(directory)?;
        let context = RefCell::new(output);
        let mut zip = zip::ZipWriter::new(Sink(&context));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o600);
        zip.start_file("data.json", options)
            .map_err(|_| Error::Writer)?;
        bitwarden_json::Writer::new(Profile::Personal)
            .write_to(records, &context, &mut zip, &ids, total)?;
        zip.add_directory("attachments/", options)
            .map_err(|_| Error::Writer)?;
        for (owner, record) in records.iter().enumerate() {
            context
                .borrow_mut()
                .checkpoint(records.len() + owner, total)?;
            let folder = sanitized(bitwarden_json::writer::name(record));
            let folder = folder.as_str();
            if !record.entries.iter().any(is_file) {
                continue;
            }
            zip.add_directory(format!("attachments/{folder}/"), options)
                .map_err(|_| Error::Writer)?;
            for entry in &record.entries {
                if let Some((name, bytes)) = blob(entry) {
                    zip.start_file(format!("attachments/{folder}/{name}"), options)
                        .map_err(|_| Error::Writer)?;
                    for chunk in bytes.chunks(256 << 10) {
                        zip.write_all(chunk)?;
                    }
                }
            }
        }
        zip.finish().map_err(|_| Error::Writer)?;
        context.borrow_mut().checkpoint(total, total)?;
        Ok(())
    }
}
