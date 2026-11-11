//! Write current fields and file bytes without replaying source snapshots.
use crate::export::{self, Code, Error, Output, Records, Review, Severity, Sink, totp};
use confidex_vault::{
    entropy,
    record::{Entry, MAX_ENTRIES, Record, Value},
};
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use std::{cell::RefCell, collections::BTreeSet, fmt, io::Write, mem::size_of};

pub struct Writer {
    created_at: u64,
    namespace: [u8; 16],
}
impl Writer {
    /// Supply the export time in Unix seconds. No record history is inferred.
    pub fn new(created_at: u64) -> Result<Self, Error> {
        if created_at > 8_640_000_000_000 {
            return Err(Error::InvalidOptions);
        }
        let mut namespace = [0; 16];
        entropy::fill_random(&mut namespace).map_err(|_| Error::Writer)?;
        Ok(Self {
            created_at,
            namespace,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Login,
    Uri,
    Section,
    Omit,
}
impl Place {
    fn rank(self) -> u8 {
        match self {
            Self::Login => 0,
            Self::Uri => 1,
            Self::Section | Self::Omit => 2,
        }
    }
}
fn text(entry: &Entry) -> Option<&str> {
    entry
        .value
        .get(crate::fields::key(&entry.type_name)?)
        .and_then(Value::as_str)
}
fn hidden(entry: &Entry) -> bool {
    matches!(
        entry.type_name.as_str(),
        "password/v1" | "secret/v1" | "secure-note/v1"
    ) || crate::field_protected(entry)
}
fn filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= crate::import::Limits::default().name_bytes
        && !matches!(name, "." | "..")
        && !name.contains(['/', '\\', ':'])
        && !name.chars().any(char::is_control)
}
fn blob(entry: &Entry) -> Option<(&str, &[u8])> {
    if !matches!(entry.type_name.as_str(), "file/v1" | "photo/v1") {
        return None;
    }
    let name = entry.value.get("filename")?.as_str()?;
    filename(name).then_some(())?;
    Some((name, entry.value.get("data")?.as_slice()?))
}
fn member<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let mut fields = value
        .as_map()?
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key));
    let value = &fields.next()?.1;
    fields.next().is_none().then_some(value)
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Group<'a> {
    name: Option<&'a str>,
    title: Option<&'a str>,
    native: Option<usize>,
}
struct Context<'a> {
    group: Group<'a>,
    id: Option<&'a str>,
}
fn context(entry: &Entry) -> Option<Context<'_>> {
    let value = entry.extra.get("confidex.import.section")?;
    if value.as_map()?.len() != 3 {
        return None;
    }
    let optional = |key| match member(value, key)? {
        Value::Nil => Some(None),
        value => value.as_str().filter(|text| text.len() <= 4096).map(Some),
    };
    Some(Context {
        group: Group {
            name: optional("name")?,
            title: optional("title")?,
            native: None,
        },
        id: optional("field_id")?,
    })
}

struct Item<'a> {
    writer: &'a Writer,
    record: &'a Record,
    index: usize,
    otp: &'a [Option<&'a str>],
    username: Option<usize>,
    password: Option<usize>,
    login: bool,
    preface: usize,
    sections: usize,
    canonical: bool,
    native: Option<crate::sections::Native<'a>>,
}
impl<'a> Item<'a> {
    fn new(
        writer: &'a Writer,
        record: &'a Record,
        index: usize,
        otp: &'a [Option<&'a str>],
    ) -> Self {
        let first = |kind| {
            record
                .entries
                .iter()
                .position(|e| e.type_name == kind && text(e).is_some())
        };
        let username = record
            .entries
            .iter()
            .position(|e| e.type_name == "username/v1" && text(e).is_some() && !hidden(e));
        let password = first("password/v1");
        let (canonical, native) = match crate::sections::native(record) {
            Ok(None) => (false, None),
            Ok(Some(layout)) => (true, Some(layout)),
            Err(_) => (true, None),
        };
        let login = username.is_some()
            || password.is_some()
            || record
                .entries
                .iter()
                .any(|e| e.type_name == "url/v1" && text(e).is_some() && !hidden(e));
        let mut item = Self {
            writer,
            record,
            index,
            otp,
            username,
            password,
            login,
            preface: record.entries.len(),
            sections: record.entries.len(),
            canonical,
            native,
        };
        let mut phase = 0;
        for (index, entry) in record.entries.iter().enumerate() {
            if (entry.type_name == "password/v1"
                || entry.type_name == "username/v1" && !hidden(entry))
                && text(entry).is_some()
            {
                continue;
            }
            if !supported(entry) {
                continue;
            }
            let grouped = if canonical {
                native.is_some_and(|layout| {
                    layout.iter().any(|s| index >= s.start && index < s.end())
                })
            } else {
                entry.extra.contains_key("confidex.import.section")
            };
            let plain = !grouped && !hidden(entry);
            if phase == 0 && login && entry.type_name == "text/v1" && plain {
                continue;
            }
            if phase <= 1 && entry.type_name == "url/v1" && plain {
                item.preface = item.preface.min(index);
                phase = 1;
                continue;
            }
            item.preface = item.preface.min(index);
            item.sections = index;
            break;
        }
        item
    }
    fn place(&self, index: usize) -> Place {
        let entry = &self.record.entries[index];
        if !supported(entry) {
            return Place::Omit;
        }
        match entry.type_name.as_str() {
            "username/v1" if hidden(entry) => Place::Section,
            "username/v1" | "password/v1" => Place::Login,
            "text/v1" if self.login && index < self.preface => Place::Login,
            "url/v1" if index < self.sections => Place::Uri,
            _ => Place::Section,
        }
    }
    fn group(&self, index: usize) -> Group<'a> {
        let fallback = Group {
            name: None,
            title: Some(""),
            native: None,
        };
        if self.canonical {
            return self
                .native
                .and_then(|layout| layout.iter().find(|s| index >= s.start && index < s.end()))
                .map_or(fallback, |s| Group {
                    name: None,
                    title: Some(s.name),
                    native: Some(s.source),
                });
        }
        context(&self.record.entries[index]).map_or(fallback, |c| c.group)
    }
    fn id(&self) -> Id {
        Id(self.writer.namespace, self.index as u32 + 2)
    }
    fn field_id(&self, index: usize) -> Id {
        Id(
            self.writer.namespace,
            0x4000_0000 + (self.index * MAX_ENTRIES + index) as u32,
        )
    }
    fn document_id(&self, index: usize) -> Id {
        Id(
            self.writer.namespace,
            0x8000_0000 + (self.index * MAX_ENTRIES + index) as u32,
        )
    }
    fn section_id(&self, index: usize) -> Id {
        Id(
            self.writer.namespace,
            0x2000_0000
                + (self.index * (MAX_ENTRIES + crate::sections::MAX_SECTIONS + 1) + index) as u32,
        )
    }
    fn visit_sections<E>(
        &self,
        mut visit: impl FnMut(usize, usize, Group<'a>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut emit = |first: usize, end: usize, group: Group<'a>, force| {
            if force || (first..end).any(|i| self.place(i) == Place::Section) {
                visit(first, end, group)?;
            }
            Ok::<_, E>(())
        };
        if let Some(layout) = self.native {
            let mut cursor = 0;
            for span in layout.iter() {
                emit(
                    cursor,
                    span.start,
                    Group {
                        name: None,
                        title: Some(""),
                        native: None,
                    },
                    false,
                )?;
                emit(
                    span.start,
                    span.end(),
                    Group {
                        name: None,
                        title: Some(span.name),
                        native: Some(span.source),
                    },
                    true,
                )?;
                cursor = span.end();
            }
            emit(
                cursor,
                self.record.entries.len(),
                Group {
                    name: None,
                    title: Some(""),
                    native: None,
                },
                false,
            )?;
            return Ok(());
        }
        let mut start = 0;
        while let Some(first) =
            (start..self.record.entries.len()).find(|&i| self.place(i) == Place::Section)
        {
            let group = self.group(first);
            let end = (first + 1..self.record.entries.len())
                .find(|&i| self.place(i) == Place::Section && self.group(i) != group)
                .unwrap_or(self.record.entries.len());
            emit(first, end, group, false)?;
            start = end;
        }
        Ok(())
    }
    fn check_sections(&self) -> Result<(), Error> {
        let mut count = 0;
        self.visit_sections(|_, _, _| {
            count += 1;
            if count > crate::sections::MAX_SECTIONS {
                return Err(Error::Limit);
            }
            Ok(())
        })
    }
}
fn supported(entry: &Entry) -> bool {
    match entry.type_name.as_str() {
        "text/v1" | "secret/v1" | "username/v1" | "password/v1" | "url/v1" | "note/v1"
        | "secure-note/v1" => text(entry).is_some(),
        "totp/v1" => totp::valid_totp(entry),
        "file/v1" | "photo/v1" => blob(entry).is_some(),
        _ => false,
    }
}
impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::Onepassword1pux
    }
    fn file(&self) -> export::File {
        export::File {
            name: "confidex.1pux",
            media_type: "application/zip",
            encrypted: false,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        let _scratch = review.reserve(record.entries.len() * 256)?;
        let item = Item::new(self, record, 0, &[]);
        item.check_sections()?;
        let mut rank = 0;
        let mut previous = None;
        let mut names = BTreeSet::new();
        for (index, entry) in record.entries.iter().enumerate() {
            let place = item.place(index);
            let source_otp = if let Some(raw) = totp::otp_raw(entry) {
                let _scratch = review.reserve(totp::otp_scratch(raw)?)?;
                totp::matching_otp(entry).is_some()
            } else {
                false
            };
            let mut loss = |code| review.issue(Some(index), Severity::Loss, code);
            if place == Place::Omit {
                let file = matches!(entry.type_name.as_str(), "file/v1" | "photo/v1");
                let unsafe_name = file
                    && entry
                        .value
                        .get("filename")
                        .and_then(Value::as_str)
                        .is_some_and(|name| !filename(name));
                review.issue(
                    Some(index),
                    if unsafe_name {
                        Severity::Blocked
                    } else {
                        Severity::Loss
                    },
                    if file {
                        Code::Attachments
                    } else if entry.type_name == "totp/v1" {
                        Code::TotpParameters
                    } else {
                        Code::UnsupportedField
                    },
                )?;
                continue;
            }
            if place.rank() < rank {
                loss(Code::FieldOrder)?;
            }
            rank = rank.max(place.rank());
            if entry.type_name == "username/v1" && item.username != Some(index)
                || hidden(entry) && matches!(entry.type_name.as_str(), "text/v1" | "url/v1")
                || matches!(entry.type_name.as_str(), "note/v1" | "photo/v1")
            {
                loss(Code::UnsupportedField)?;
            }
            if place == Place::Section {
                let group = item.group(index);
                if previous != Some(group) {
                    if group.name.is_some_and(|name| !names.insert(name)) {
                        loss(Code::Sections)?;
                    }
                    previous = Some(group);
                }
            }
            let known_value = entry
                .value
                .keys()
                .all(|key| match entry.type_name.as_str() {
                    "totp/v1" => matches!(
                        key.as_str(),
                        "secret" | "algorithm" | "digits" | "period" | "t0"
                    ),
                    "file/v1" | "photo/v1" => matches!(key.as_str(), "data" | "filename"),
                    _ => Some(key.as_str()) == crate::fields::key(&entry.type_name),
                });
            if !known_value {
                loss(Code::UnknownValue)?;
            }
            for (key, value) in &entry.extra {
                let recognized = if key == "confidex.import.section"
                    && place == Place::Section
                    && !item.canonical
                {
                    if let Some(context) = context(entry) {
                        if context.group.name.is_some() || context.id.is_some() {
                            loss(Code::SourceContext)?;
                        }
                        if context.group.title.is_none() {
                            loss(Code::Sections)?;
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    source_otp && key == "confidex.import.totp"
                        || key == "metadata"
                            && value.as_map().is_some_and(|m| {
                                m.len() == 1
                                    && m[0].0.as_str() == Some("protected")
                                    && m[0].1.as_bool().is_some()
                            })
                };
                if !recognized {
                    loss(if key.starts_with("confidex.import.") {
                        Code::SourceContext
                    } else {
                        Code::UnknownMetadata
                    })?;
                }
            }
            review.preserved(index)?;
        }
        review.tags();
        for (key, value) in &record.extra {
            if key == "confidex.title" && value.as_str().is_some() {
                continue;
            }
            if key == crate::sections::KEY {
                if let Some(layout) = item.native {
                    if layout.unknown() {
                        review.issue(None, Severity::Loss, Code::UnknownMetadata)?;
                    }
                    if layout.iter().any(|span| {
                        (span.start..span.end()).any(|i| item.place(i) != Place::Section)
                    }) || layout.iter().next().is_none()
                        && record
                            .entries
                            .iter()
                            .enumerate()
                            .any(|(i, _)| item.place(i) == Place::Section)
                    {
                        review.issue(None, Severity::Loss, Code::Sections)?;
                    }
                } else {
                    review.issue(None, Severity::Loss, Code::Sections)?;
                    review.issue(None, Severity::Loss, Code::UnknownMetadata)?;
                }
                continue;
            }
            review.issue(
                None,
                Severity::Loss,
                if key.starts_with("confidex.import.") {
                    Code::SourceContext
                } else {
                    Code::UnknownMetadata
                },
            )?;
        }
        review.metadata();
        Ok(())
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        let mut headers = 8192usize;
        let mut fields = 0usize;
        let steps = records.len() * 2;
        let mut has_source = false;
        for record in records.iter() {
            output.checkpoint(0, steps)?;
            Item::new(self, record, 0, &[]).check_sections()?;
            fields = fields
                .checked_add(record.entries.len())
                .ok_or(Error::Limit)?;
            for entry in &record.entries {
                has_source |= totp::otp_raw(entry).is_some();
                if let Some((name, _)) = blob(entry) {
                    headers = headers
                        .checked_add(2048 + 4 * (name.len() + 35))
                        .ok_or(Error::Limit)?;
                }
            }
        }
        let _directory = output.reserve(headers)?;
        let _otp_headers = output.reserve(if has_source {
            fields
                .checked_mul(size_of::<Option<&str>>())
                .ok_or(Error::Limit)?
        } else {
            0
        })?;
        let mut otp = Vec::new();
        if has_source {
            otp.try_reserve_exact(fields)
                .map_err(|_| Error::Allocation)?;
            for record in records.iter() {
                output.checkpoint(0, steps)?;
                for entry in &record.entries {
                    let source = if let Some(raw) = totp::otp_raw(entry) {
                        let _scratch = output.reserve(totp::otp_scratch(raw)?)?;
                        totp::matching_otp(entry)
                    } else {
                        None
                    };
                    otp.push(source);
                }
            }
        }
        // Keep progress access while ZipWriter owns its sink.
        let sink = RefCell::new(output);
        let mut zip = zip::ZipWriter::new(Sink(&sink));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o600);
        zip.start_file("export.attributes", options)
            .map_err(|_| Error::Writer)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Attributes {
            version: u8,
            description: &'static str,
            created_at: u64,
        }
        json(
            &mut zip,
            &Attributes {
                version: 3,
                description: "1Password Unencrypted Export",
                created_at: self.created_at,
            },
        )?;
        zip.start_file("export.data", options)
            .map_err(|_| Error::Writer)?;
        zip.write_all(b"{\"accounts\":[{\"attrs\":{\"uuid\":")?;
        json(&mut zip, &Id(self.namespace, 0))?;
        zip.write_all(b",\"accountName\":\"Confidex\",\"name\":\"Confidex\",\"avatar\":\"\",\"email\":\"\",\"domain\":\"\"},\"vaults\":[{\"attrs\":{\"uuid\":")?;
        json(&mut zip, &Id(self.namespace, 1))?;
        zip.write_all(
            b",\"name\":\"Confidex\",\"desc\":\"\",\"avatar\":\"\",\"type\":\"P\"},\"items\":[",
        )?;
        let mut offset = 0;
        for (index, record) in records.iter().enumerate() {
            sink.borrow_mut().checkpoint(index, steps)?;
            if index != 0 {
                zip.write_all(b",")?;
            }
            let end = offset + record.entries.len();
            json(
                &mut zip,
                &Item::new(
                    self,
                    record,
                    index,
                    if has_source { &otp[offset..end] } else { &[] },
                ),
            )?;
            offset = end;
        }
        zip.write_all(b"]}]}]}")?;
        for (index, record) in records.iter().enumerate() {
            sink.borrow_mut().checkpoint(records.len() + index, steps)?;
            let item = Item::new(self, record, index, &[]);
            for (field, entry) in record.entries.iter().enumerate() {
                if let Some((name, bytes)) = blob(entry) {
                    zip.start_file(
                        format!("files/{}___{name}", item.document_id(field)),
                        options,
                    )
                    .map_err(|_| Error::Writer)?;
                    for chunk in bytes.chunks(256 << 10) {
                        zip.write_all(chunk)?;
                    }
                }
            }
        }
        zip.finish().map_err(|_| Error::Writer)?;
        sink.borrow_mut().checkpoint(steps, steps)?;
        Ok(())
    }
}

fn json(output: &mut impl Write, value: &impl Serialize) -> Result<(), Error> {
    serde_json::to_writer(output, value).map_err(|_| Error::Writer)
}
#[derive(Clone, Copy)]
struct Id([u8; 16], u32);
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = self.0;
        for (byte, counter) in bytes[12..].iter_mut().zip(self.1.to_be_bytes()) {
            *byte ^= counter;
        }
        let value = u128::from_be_bytes(bytes);
        for index in (0..26).rev() {
            let code = ((value >> (index * 5)) & 31) as usize;
            f.write_str(
                std::str::from_utf8(&[b"abcdefghijklmnopqrstuvwxyz234567"[code]])
                    .map_err(|_| fmt::Error)?,
            )?;
        }
        Ok(())
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl Serialize for Item<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        map.serialize_entry("uuid", &self.id())?;
        map.serialize_entry("categoryUuid", if self.login { "001" } else { "003" })?;
        map.serialize_entry("createdAt", &self.writer.created_at)?;
        map.serialize_entry("updatedAt", &self.writer.created_at)?;
        map.serialize_entry("state", "active")?;
        map.serialize_entry("favIndex", &0)?;
        map.serialize_entry("overview", &Overview(self))?;
        map.serialize_entry("details", &Details(self))?;
        map.end()
    }
}
struct Overview<'a>(&'a Item<'a>);
#[derive(Serialize)]
struct Uri<'a> {
    label: &'a str,
    url: &'a str,
}
impl Serialize for Overview<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        map.serialize_entry(
            "title",
            self.0
                .record
                .extra
                .get("confidex.title")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )?;
        map.serialize_entry("tags", &self.0.record.tags)?;
        map.serialize_entry("urls", &Uris(self.0))?;
        if let Some((_, entry)) = self
            .0
            .record
            .entries
            .iter()
            .enumerate()
            .find(|(i, _)| self.0.place(*i) == Place::Uri)
        {
            map.serialize_entry("url", text(entry).unwrap())?;
        }
        map.end()
    }
}
struct Uris<'a>(&'a Item<'a>);
impl Serialize for Uris<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        for (i, entry) in self.0.record.entries.iter().enumerate() {
            if self.0.place(i) == Place::Uri {
                seq.serialize_element(&Uri {
                    label: &entry.name,
                    url: text(entry).unwrap(),
                })?;
            }
        }
        seq.end()
    }
}
struct Details<'a>(&'a Item<'a>);
impl Serialize for Details<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        map.serialize_entry("loginFields", &Login(self.0))?;
        map.serialize_entry("sections", &Sections(self.0))?;
        map.end()
    }
}
struct Login<'a>(&'a Item<'a>);
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginField<'a> {
    name: &'a str,
    value: &'a str,
    id: Id,
    field_type: &'static str,
    designation: Option<&'static str>,
    guarded: bool,
}
impl Serialize for Login<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        for (i, entry) in self.0.record.entries.iter().enumerate() {
            if self.0.place(i) != Place::Login {
                continue;
            }
            seq.serialize_element(&LoginField {
                name: &entry.name,
                value: text(entry).unwrap(),
                id: self.0.field_id(i),
                field_type: if entry.type_name == "password/v1" {
                    "P"
                } else {
                    "T"
                },
                designation: if self.0.username == Some(i) {
                    Some("username")
                } else if self.0.password == Some(i) {
                    Some("password")
                } else {
                    None
                },
                guarded: hidden(entry),
            })?;
        }
        seq.end()
    }
}
struct Sections<'a>(&'a Item<'a>);
impl Serialize for Sections<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        let mut ordinal = 0;
        self.0.visit_sections(|first, end, group| {
            seq.serialize_element(&Section {
                item: self.0,
                first,
                end,
                group,
                ordinal,
            })?;
            ordinal += 1;
            Ok::<_, S::Error>(())
        })?;
        seq.end()
    }
}

struct Section<'a> {
    item: &'a Item<'a>,
    first: usize,
    end: usize,
    group: Group<'a>,
    ordinal: usize,
}
impl Serialize for Section<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        map.serialize_entry("name", &self.item.section_id(self.ordinal))?;
        map.serialize_entry("title", self.group.title.unwrap_or(""))?;
        map.serialize_entry("fields", &Fields(self))?;
        map.end()
    }
}
struct Fields<'a>(&'a Section<'a>);
struct Field<'a> {
    item: &'a Item<'a>,
    index: usize,
}
impl Serialize for Fields<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        for index in self.0.first..self.0.end {
            if self.0.item.place(index) == Place::Section {
                seq.serialize_element(&Field {
                    item: self.0.item,
                    index,
                })?;
            }
        }
        seq.end()
    }
}
impl Serialize for Field<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let entry = &self.item.record.entries[self.index];
        let mut map = s.serialize_map(None)?;
        map.serialize_entry("title", &entry.name)?;
        map.serialize_entry("id", &self.item.field_id(self.index))?;
        map.serialize_entry("guarded", &hidden(entry))?;
        map.serialize_entry(
            "multiline",
            &matches!(entry.type_name.as_str(), "note/v1" | "secure-note/v1"),
        )?;
        map.serialize_entry("value", &FieldValue(self))?;
        map.serialize_entry("dontGenerate", &false)?;
        #[derive(Serialize)]
        struct Traits {
            keyboard: &'static str,
            correction: &'static str,
            capitalization: &'static str,
        }
        map.serialize_entry(
            "inputTraits",
            &Traits {
                keyboard: "default",
                correction: "default",
                capitalization: "default",
            },
        )?;
        map.end()
    }
}
struct FieldValue<'a>(&'a Field<'a>);
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Document<'a> {
    file_name: &'a str,
    document_id: Id,
    decrypted_size: usize,
}
impl Serialize for FieldValue<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let field = self.0;
        let entry = &field.item.record.entries[field.index];
        let mut map = s.serialize_map(Some(1))?;
        match entry.type_name.as_str() {
            "file/v1" | "photo/v1" => {
                let (name, data) = blob(entry).unwrap();
                map.serialize_entry(
                    "file",
                    &Document {
                        file_name: name,
                        document_id: field.item.document_id(field.index),
                        decrypted_size: data.len(),
                    },
                )?;
            }
            "totp/v1" => map.serialize_entry(
                "totp",
                &totp::Otp(entry, field.item.otp.get(field.index).copied().flatten()),
            )?,
            _ if hidden(entry) => map.serialize_entry("concealed", text(entry).unwrap())?,
            "url/v1" => map.serialize_entry("url", text(entry).unwrap())?,
            _ => map.serialize_entry("string", text(entry).unwrap())?,
        }
        map.end()
    }
}
