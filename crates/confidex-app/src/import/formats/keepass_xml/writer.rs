//! Shared KeePass XML semantics; the caller owns protected-value encryption.
use crate::export::{self, Code, Error, Output, Records, Review, Severity, Sink, totp};
use crate::import::Reservation;
use base64::{Engine as _, display::Base64Display, engine::general_purpose::STANDARD};
use confidex_vault::{
    entropy,
    record::{Entry, Record, Value},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Write,
};
use zeroize::Zeroizing;

pub struct Writer {
    namespace: [u8; 16],
    created_at: u64,
}
impl Writer {
    /// New external items use the supplied Unix time, not Confidex revision times.
    pub fn new(created_at: u64) -> Result<Self, Error> {
        if created_at > 253_402_300_799 {
            return Err(Error::InvalidOptions);
        }
        let mut namespace = [0; 16];
        entropy::fill_random(&mut namespace).map_err(|_| Error::Writer)?;
        namespace[0] |= 1; // Keep every generated KeePass UUID nonzero.
        Ok(Self {
            namespace,
            created_at,
        })
    }
    fn uuid(&self, counter: u32, output: &mut dyn Write) -> Result<(), Error> {
        let mut bytes = self.namespace;
        for (byte, counter) in bytes[12..].iter_mut().zip(counter.to_be_bytes()) {
            *byte ^= counter;
        }
        write!(
            output,
            "<UUID>{}</UUID>",
            Base64Display::new(&bytes, &STANDARD)
        )?;
        Ok(())
    }
    fn times(&self, output: &mut dyn Write) -> Result<(), Error> {
        // KeePass binary timestamps count seconds since 0001-01-01 UTC.
        let seconds = (self.created_at + 62_135_596_800).to_le_bytes();
        output.write_all(b"<Times>")?;
        for name in [
            "CreationTime",
            "LastModificationTime",
            "LastAccessTime",
            "ExpiryTime",
        ] {
            write!(
                output,
                "<{name}>{}</{name}>",
                Base64Display::new(&seconds, &STANDARD)
            )?;
        }
        output.write_all(b"<Expires>False</Expires><UsageCount>0</UsageCount></Times>")?;
        Ok(())
    }
}
fn xml_valid(value: &str) -> bool {
    value.chars().all(|c| matches!(c, '\t' | '\r' | '\n' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'))
}
fn escaped(output: &mut (impl Write + ?Sized), value: &str) -> std::io::Result<()> {
    let mut start = 0;
    for (at, character) in value.char_indices() {
        let escaped: &[u8] = match character {
            '&' => b"&amp;",
            '<' => b"&lt;",
            '>' => b"&gt;",
            '\r' => b"&#13;",
            _ => continue,
        };
        output.write_all(&value.as_bytes()[start..at])?;
        output.write_all(escaped)?;
        start = at + character.len_utf8();
    }
    output.write_all(&value.as_bytes()[start..])
}
struct Text<'a> {
    writer: &'a mut dyn Write,
    error: Option<Error>,
}
impl fmt::Write for Text<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        escaped(self.writer, value).map_err(|error| {
            self.error = Some(error.into());
            fmt::Error
        })
    }
}
pub(in crate::import::formats) type Protect<'a> =
    dyn FnMut(&mut dyn Write, fmt::Arguments<'_>, usize) -> Result<(), Error> + 'a;
struct Stream<'a> {
    writer: &'a mut dyn Write,
    checkpoint: &'a mut dyn FnMut(usize, usize) -> Result<(), Error>,
    reserve: &'a dyn Fn(usize) -> Result<Reservation, Error>,
    protect: Option<&'a mut Protect<'a>>,
}
impl Write for Stream<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writer.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
impl Stream<'_> {
    fn reserve(&self, bytes: usize) -> Result<Reservation, Error> {
        (self.reserve)(bytes)
    }
    fn checkpoint(&mut self, current: usize, total: usize) -> Result<(), Error> {
        (self.checkpoint)(current, total)
    }
    fn value(
        &mut self,
        hidden: bool,
        text: fmt::Arguments<'_>,
        maximum: usize,
    ) -> Result<(), Error> {
        self.writer.write_all(if hidden && self.protect.is_some() {
            b"<Value Protected=\"True\">"
        } else if hidden {
            b"<Value ProtectInMemory=\"True\">"
        } else {
            b"<Value>"
        })?;
        if hidden && let Some(protect) = self.protect.as_mut() {
            protect(self.writer, text, maximum)?;
        } else {
            let mut destination = Text {
                writer: self.writer,
                error: None,
            };
            fmt::write(&mut destination, text)
                .map_err(|_| destination.error.unwrap_or(Error::Writer))?;
        }
        self.writer.write_all(b"</Value>")?;
        Ok(())
    }
}

fn hidden(entry: &Entry) -> bool {
    matches!(
        entry.type_name.as_str(),
        "password/v1" | "secret/v1" | "secure-note/v1" | "totp/v1"
    ) || crate::field_protected(entry)
}
fn text(entry: &Entry) -> Option<&str> {
    entry
        .value
        .get(crate::fields::key(&entry.type_name)?)
        .and_then(Value::as_str)
}
pub(in crate::import::formats) fn blob(entry: &Entry) -> Option<(&str, &[u8])> {
    if !matches!(entry.type_name.as_str(), "file/v1" | "photo/v1") {
        return None;
    }
    Some((
        entry.value.get("filename")?.as_str()?,
        entry.value.get("data")?.as_slice()?,
    ))
}
pub(in crate::import::formats) fn base64(
    output: &mut dyn Write,
    bytes: &[u8],
) -> Result<(), Error> {
    let mut buffer = Zeroizing::new([0; 4096]);
    for chunk in bytes.chunks(3072) {
        let length = STANDARD
            .encode_slice(chunk, &mut *buffer)
            .map_err(|_| Error::Writer)?;
        output.write_all(&buffer[..length])?;
    }
    Ok(())
}
fn supported(entry: &Entry) -> bool {
    match entry.type_name.as_str() {
        "text/v1" | "username/v1" | "password/v1" | "url/v1" | "secret/v1" | "note/v1"
        | "secure-note/v1" => text(entry).is_some(),
        "totp/v1" => totp::valid_totp(entry),
        "file/v1" | "photo/v1" => blob(entry).is_some(),
        _ => false,
    }
}
fn member<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let mut matches = value
        .as_map()?
        .iter()
        .filter(|(k, _)| k.as_str() == Some(key));
    let value = &matches.next()?.1;
    matches.next().is_none().then_some(value)
}
fn title(record: &Record) -> &str {
    record
        .extra
        .get("confidex.title")
        .and_then(Value::as_str)
        .unwrap_or("")
}
fn tag(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.contains([',', ';', '\t'])
        && xml_valid(value)
}
struct Item<'a> {
    record: &'a Record,
    slots: [Option<usize>; 5],
}
impl<'a> Item<'a> {
    fn new(record: &'a Record) -> Self {
        let first = |kind| {
            record
                .entries
                .iter()
                .position(|e| e.type_name == kind && supported(e))
        };
        Self {
            record,
            slots: [
                first("username/v1"),
                first("password/v1"),
                first("url/v1"),
                record.entries.iter().position(|e| {
                    matches!(e.type_name.as_str(), "note/v1" | "secure-note/v1") && supported(e)
                }),
                first("totp/v1"),
            ],
        }
    }
    fn key(&self, index: usize) -> Option<&'a str> {
        let entry = &self.record.entries[index];
        if !supported(entry) {
            return None;
        }
        if let Some((name, _)) = blob(entry) {
            return Some(name);
        }
        for (slot, name) in self
            .slots
            .iter()
            .zip(["UserName", "Password", "URL", "Notes", "otp"])
        {
            if *slot == Some(index) {
                return Some(name);
            }
        }
        Some(&entry.name)
    }
    fn native_type(&self, index: usize, key: &str) -> &'static str {
        if blob(&self.record.entries[index]).is_some() {
            return "file/v1";
        }
        match key {
            "UserName" => "username/v1",
            "Password" => "password/v1",
            "URL" => "url/v1",
            "Notes" => "secure-note/v1",
            "otp" if self.slots[4] == Some(index) => "totp/v1",
            _ if hidden(&self.record.entries[index]) => "secret/v1",
            _ => "text/v1",
        }
    }
}

// Native provenance is a group hint only; it never supplies field values.
struct Path<'a> {
    names: &'a [Value],
    ids: Option<&'a [Value]>,
    scope: [Option<&'a str>; 4],
}
fn path(record: &Record) -> Option<Path<'_>> {
    let origin = record.extra.get("confidex.import.origin")?;
    if member(origin, "version")?.as_u64()? != 1 {
        return None;
    }
    let format = member(origin, "format")?.as_str()?;
    if !matches!(format, "keepass-xml" | "kdbx") {
        return None;
    }
    let attributes = member(origin, "attributes")?;
    let names = member(attributes, "group_path")?.as_array()?;
    // Root/Group plus Entry/String/Value must still fit the shared XML depth cap.
    if names.len() > 26
        || names
            .iter()
            .any(|v| v.as_str().is_none_or(|s| s.len() > 4096 || !xml_valid(s)))
    {
        return None;
    }
    let ids = member(attributes, "group_ids")
        .and_then(Value::as_array)
        .filter(|ids| {
            ids.len() == names.len()
                && ids
                    .iter()
                    .all(|v| v.as_str().is_some_and(|s| super::entry::uuid(s).is_ok()))
        });
    let source = member(origin, "source");
    Some(Path {
        names,
        ids: ids.map(Vec::as_slice),
        scope: [
            Some(format),
            source
                .and_then(|s| member(s, "instance"))
                .and_then(Value::as_str),
            source
                .and_then(|s| member(s, "account"))
                .and_then(Value::as_str),
            source
                .and_then(|s| member(s, "vault"))
                .and_then(Value::as_str),
        ],
    })
}
struct Group<'a> {
    name: &'a str,
    children: Vec<usize>,
    records: Vec<usize>,
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey<'a> {
    parent: usize,
    scope: [Option<&'a str>; 4],
    id: Option<&'a str>,
    name: &'a str,
    unscoped: usize,
}

impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::KeepassXml
    }
    fn file(&self) -> export::File {
        export::File {
            name: "confidex.xml",
            media_type: "application/xml",
            encrypted: false,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        self.review_with(record, review, false)
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        let context = RefCell::new(output);
        self.write_to(
            records,
            &mut Sink(&context),
            &mut |current, total| context.borrow_mut().checkpoint(current, total),
            &|bytes| context.borrow().reserve(bytes),
            None,
        )
    }
}
impl Writer {
    pub(in crate::import::formats) fn review_with(
        &self,
        record: &Record,
        review: &mut Review<'_>,
        native: bool,
    ) -> Result<(), Error> {
        let item = Item::new(record);
        let _headers = review.reserve(record.entries.len() * 128)?;
        let mut keys = BTreeSet::from(["Title"]);
        let mut files = BTreeSet::new();
        let mut previous: Option<(bool, &str)> = None;
        let mut order_loss = false;
        if !xml_valid(title(record)) || super::mapping::dynamic(title(record)) {
            review.issue(None, Severity::Blocked, Code::SourceContext)?;
        }
        if title(record).contains('\r') {
            review.issue(None, Severity::Loss, Code::UnknownValue)?;
        }
        if path(record).is_some_and(|p| {
            p.names.iter().any(|v| v.as_str().unwrap().contains('\r'))
                || p.ids.is_none()
                || p.scope[1].is_none_or(|s| s.trim().is_empty())
        }) {
            review.issue(None, Severity::Loss, Code::Sections)?;
        }
        for (index, entry) in record.entries.iter().enumerate() {
            let Some(key) = item.key(index) else {
                review.issue(
                    Some(index),
                    Severity::Loss,
                    if matches!(entry.type_name.as_str(), "file/v1" | "photo/v1") {
                        Code::Attachments
                    } else if entry.type_name == "totp/v1" {
                        Code::TotpParameters
                    } else {
                        Code::UnsupportedField
                    },
                )?;
                continue;
            };
            let file = blob(entry).is_some();
            // KeePassXC stores strings by key, separate from attachment keys.
            if let Some((prior_file, prior)) = previous
                && !order_loss
                && (prior_file && !file
                    || prior_file == file && prior.encode_utf16().cmp(key.encode_utf16()).is_gt())
            {
                review.issue(None, Severity::Loss, Code::FieldOrder)?;
                order_loss = true;
            }
            previous = Some((file, key));
            // CR-normalized keys can collide in KeePassXC.
            if !xml_valid(key)
                || key.contains('\r')
                || if file {
                    key.is_empty() || !files.insert(key)
                } else {
                    !keys.insert(key)
                }
            {
                review.issue(Some(index), Severity::Blocked, Code::FieldNames)?;
            }
            if !file
                && (key == "otp" && item.slots[4] != Some(index)
                    || key.starts_with("TimeOtp-")
                    || key.starts_with("HmacOtp-")
                    || key.starts_with("TOTP "))
            {
                review.issue(Some(index), Severity::Blocked, Code::TotpParameters)?;
            }
            if let Some(value) = text(entry)
                && (!xml_valid(value) || super::mapping::dynamic(value))
            {
                review.issue(Some(index), Severity::Blocked, Code::SourceContext)?;
            }
            if key != entry.name {
                review.issue(Some(index), Severity::Loss, Code::FieldNames)?;
            }
            if item.native_type(index, key) != entry.type_name {
                review.issue(Some(index), Severity::Loss, Code::UnsupportedField)?;
            }
            if file && crate::field_protected(entry) && !native {
                review.issue(Some(index), Severity::Blocked, Code::Protection)?;
            }
            if entry.type_name == "totp/v1" && item.slots[4] != Some(index) {
                review.issue(Some(index), Severity::Loss, Code::TotpParameters)?;
            }
            let source = if let Some(raw) = totp::otp_raw(entry) {
                let _scratch = review.reserve(totp::otp_scratch(raw)?)?;
                totp::matching_otp(entry)
                    .filter(|raw| xml_valid(raw) && !super::mapping::dynamic(raw))
            } else {
                None
            };
            if !hidden(entry) && text(entry).is_some_and(|value| value.contains('\r'))
                || entry.value.keys().any(|key| {
                    if entry.type_name == "totp/v1" {
                        !matches!(
                            key.as_str(),
                            "secret" | "algorithm" | "digits" | "period" | "t0"
                        )
                    } else if file {
                        !matches!(key.as_str(), "filename" | "data" | "mime")
                            || key == "mime"
                                && entry.value["mime"].as_str() != Some("application/octet-stream")
                    } else {
                        Some(key.as_str()) != crate::fields::key(&entry.type_name)
                    }
                })
            {
                review.issue(Some(index), Severity::Loss, Code::UnknownValue)?;
            }
            for (name, value) in &entry.extra {
                let known = name == "confidex.import.totp" && source.is_some()
                    || name == "metadata"
                        && value.as_map().is_some_and(|m| {
                            m.len() == 1
                                && m[0].0.as_str() == Some("protected")
                                && m[0].1.as_bool().is_some()
                        })
                    || name == "confidex.import.field"
                        && value.as_map().is_some_and(|m| m.len() == 2)
                        && member(value, "key").and_then(Value::as_str) == Some(key)
                        && member(value, "protect_in_memory").and_then(Value::as_bool)
                            == Some(hidden(entry));
                if !known {
                    review.issue(
                        Some(index),
                        Severity::Loss,
                        if name.starts_with("confidex.import.") {
                            Code::SourceContext
                        } else {
                            Code::UnknownMetadata
                        },
                    )?;
                }
            }
            review.preserved(index)?;
        }
        if record.tags.iter().any(|s| !tag(s) || s.contains('\r')) {
            review.issue(None, Severity::Loss, Code::Tags)?;
        }
        review.tags();
        for (key, value) in &record.extra {
            if key == "confidex.title" && value.as_str().is_some() {
                continue;
            }
            review.issue(
                None,
                Severity::Loss,
                if key == crate::sections::KEY {
                    Code::Sections
                } else if key.starts_with("confidex.import.") {
                    Code::SourceContext
                } else {
                    Code::UnknownMetadata
                },
            )?;
            if key == "confidex.import.origin"
                && member(value, "attributes")
                    .and_then(|v| member(v, "group_path"))
                    .is_some()
                && path(record).is_none()
            {
                review.issue(None, Severity::Loss, Code::Sections)?;
            }
        }
        review.metadata();
        Ok(())
    }
    pub(in crate::import::formats) fn write_to<'a>(
        &self,
        records: &Records,
        writer: &'a mut dyn Write,
        checkpoint: &'a mut dyn FnMut(usize, usize) -> Result<(), Error>,
        reserve: &'a dyn Fn(usize) -> Result<Reservation, Error>,
        protect: Option<&'a mut Protect<'a>>,
    ) -> Result<(), Error> {
        let native = protect.is_some();
        let output = &mut Stream {
            writer,
            checkpoint,
            reserve,
            protect,
        };
        let capacity = records.iter().try_fold(1usize, |n, record| {
            n.checked_add(path(record).map_or(0, |p| p.names.len()))
                .ok_or(Error::Limit)
        })?;
        let bytes = capacity
            .checked_mul(512)
            .and_then(|n| n.checked_add(records.len() * 64))
            .ok_or(Error::Limit)?;
        let _headers = output.reserve(bytes)?;
        let mut bases = Vec::new();
        bases
            .try_reserve_exact(records.len())
            .map_err(|_| Error::Allocation)?;
        let mut files = 0;
        for record in records.iter() {
            output.checkpoint(0, records.len())?;
            bases.push(files);
            files += record.entries.iter().filter(|e| blob(e).is_some()).count();
        }
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        groups.push(Group {
            name: "Confidex",
            children: Vec::new(),
            records: Vec::new(),
        });
        let mut keys = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            output.checkpoint(0, records.len())?;
            let mut parent = 0;
            if let Some(path) = path(record) {
                for (position, name) in path.names.iter().enumerate() {
                    let name = name.as_str().unwrap();
                    let key = GroupKey {
                        parent,
                        scope: path.scope,
                        id: path.ids.map(|ids| ids[position].as_str().unwrap()),
                        name,
                        unscoped: if path.ids.is_none()
                            || path.scope[1].is_none_or(|s| s.trim().is_empty())
                        {
                            index + 1
                        } else {
                            0
                        },
                    };
                    parent = if let Some(&found) = keys.get(&key) {
                        found
                    } else {
                        let next = groups.len();
                        groups.push(Group {
                            name,
                            children: Vec::new(),
                            records: Vec::new(),
                        });
                        groups[parent].children.push(next);
                        keys.insert(key, next);
                        next
                    };
                }
            }
            groups[parent].records.push(index);
        }
        output.write_all(b"<?xml version=\"1.0\" encoding=\"utf-8\"?><KeePassFile><Meta><Generator>Confidex</Generator>")?;
        if !native {
            output.write_all(b"<Binaries>")?;
            let mut file = 0;
            for record in records.iter() {
                output.checkpoint(0, records.len())?;
                for entry in &record.entries {
                    if let Some((_, bytes)) = blob(entry) {
                        write!(output, "<Binary ID=\"{file}\" Compressed=\"False\">")?;
                        base64(output, bytes)?;
                        output.write_all(b"</Binary>")?;
                        file += 1;
                    }
                }
            }
            output.write_all(b"</Binaries>")?;
        }
        output.write_all(b"</Meta><Root>")?;
        let mut current = 0;
        let root = if groups[0].records.is_empty() && groups[0].children.len() == 1 {
            groups[0].children[0]
        } else {
            0
        };
        self.group(root, &groups, records, &bases, output, &mut current)?;
        output.write_all(b"</Root></KeePassFile>")?;
        output.checkpoint(records.len(), records.len())?;
        Ok(())
    }
    fn group(
        &self,
        index: usize,
        groups: &[Group<'_>],
        records: &Records,
        bases: &[usize],
        output: &mut Stream<'_>,
        current: &mut usize,
    ) -> Result<(), Error> {
        output.write_all(b"<Group>")?;
        self.uuid(index as u32, output)?;
        output.write_all(b"<Name>")?;
        escaped(output, groups[index].name)?;
        output.write_all(b"</Name>")?;
        self.times(output)?;
        for &record in &groups[index].records {
            output.checkpoint(*current, records.len())?;
            self.item(record, records.get(record).unwrap(), bases[record], output)?;
            *current += 1;
        }
        for &child in &groups[index].children {
            self.group(child, groups, records, bases, output, current)?;
        }
        output.write_all(b"</Group>")?;
        Ok(())
    }
    fn item(
        &self,
        index: usize,
        record: &Record,
        mut file: usize,
        output: &mut Stream<'_>,
    ) -> Result<(), Error> {
        output.write_all(b"<Entry>")?;
        self.uuid(0x8000_0000 + index as u32, output)?;
        self.times(output)?;
        output.write_all(b"<String><Key>Title</Key><Value>")?;
        escaped(output, title(record))?;
        output.write_all(b"</Value></String><Tags>")?;
        for (index, tag) in record.tags.iter().filter(|s| tag(s)).enumerate() {
            if index != 0 {
                output.write_all(b";")?;
            }
            escaped(output, tag)?;
        }
        output.write_all(b"</Tags>")?;
        let item = Item::new(record);
        for (index, entry) in record.entries.iter().enumerate() {
            let Some(key) = item.key(index) else {
                continue;
            };
            if blob(entry).is_some() {
                output.write_all(b"<Binary><Key>")?;
                escaped(output, key)?;
                write!(output, "</Key><Value Ref=\"{file}\"/></Binary>")?;
                file += 1;
                continue;
            }
            output.write_all(b"<String><Key>")?;
            escaped(output, key)?;
            output.write_all(b"</Key>")?;
            if entry.type_name == "totp/v1" {
                let source = if let Some(raw) = totp::otp_raw(entry) {
                    let _scratch = output.reserve(totp::otp_scratch(raw)?)?;
                    totp::matching_otp(entry)
                        .filter(|raw| xml_valid(raw) && !super::mapping::dynamic(raw))
                } else {
                    None
                };
                if let Some(raw) = source {
                    output.value(hidden(entry), format_args!("{raw}"), raw.len())?;
                } else {
                    let maximum = entry.value["secret"]
                        .as_slice()
                        .unwrap()
                        .len()
                        .checked_mul(8)
                        .map(|n| n.div_ceil(5))
                        .and_then(|n| n.checked_add(256))
                        .ok_or(Error::Limit)?;
                    output.value(
                        hidden(entry),
                        format_args!("{}", totp::Otp(entry, None)),
                        maximum,
                    )?;
                }
            } else {
                let text = text(entry).unwrap();
                output.value(hidden(entry), format_args!("{text}"), text.len())?;
            }
            output.write_all(b"</String>")?;
        }
        output.write_all(b"</Entry>")?;
        Ok(())
    }
}
