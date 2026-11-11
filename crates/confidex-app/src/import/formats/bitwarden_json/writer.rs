//! Write current values. Do not restore values from import snapshots.
use crate::export::totp::{Otp, matching_otp, otp_raw, otp_scratch, valid_totp};
use crate::export::{self, Code, Error, Output, Records, Review, Severity, Sink};
use confidex_vault::{
    record::{Entry, Record, Value},
    ssh,
};
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use std::{cell::RefCell, collections::BTreeMap, fmt, io::Write};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    #[default]
    Personal,
    Organization,
}
pub struct Writer {
    profile: Profile,
}
impl Writer {
    pub fn new(profile: Profile) -> Self {
        Self { profile }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Username,
    Password,
    Uri,
    Totp,
    Personal(usize),
    Ssh,
    Notes,
    Custom,
    CustomOtp,
    Omit,
}
impl Place {
    fn rank(self) -> u8 {
        match self {
            Self::Username => 0,
            Self::Password => 1,
            Self::Uri => 2,
            Self::Totp => 3,
            Self::Personal(slot) => slot as u8,
            Self::Ssh => 0,
            Self::Notes => 32,
            Self::Custom | Self::CustomOtp | Self::Omit => 33,
        }
    }
    fn name(self) -> Option<&'static str> {
        match self {
            Self::Username => Some("Username"),
            Self::Password => Some("Password"),
            Self::Uri => Some("URL"),
            Self::Totp => Some("One-time code"),
            Self::Notes => Some("Notes"),
            Self::Ssh => Some("SSH key"),
            _ => None,
        }
    }
}
struct Item<'a> {
    id: Option<&'a str>,
    record: &'a Record,
    profile: Profile,
    groups: Option<&'a BTreeMap<&'a str, usize>>,
    slots: [Option<usize>; 4],
    login: bool,
    personal_kind: u64,
    personal: [Option<usize>; 18],
    ssh: Option<usize>,
    ssh_text: Option<Ssh<'a>>,
    otp_source: &'a [Option<&'a str>],
}
pub(crate) fn name(record: &Record) -> &str {
    record
        .extra
        .get("confidex.title")
        .and_then(Value::as_str)
        .unwrap_or("--")
}

fn text(entry: &Entry) -> Option<&str> {
    entry
        .value
        .get(crate::fields::key(&entry.type_name)?)
        .and_then(Value::as_str)
}
// The pinned reader uses ECMAScript trim, which differs from Rust whitespace.
fn blank(text: &str) -> bool {
    text.chars().all(|c| matches!(c, '\u{9}'..='\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'))
}
fn hidden(entry: &Entry) -> bool {
    matches!(entry.type_name.as_str(), "password/v1" | "secret/v1") || crate::field_protected(entry)
}
fn custom_kind(entry: &Entry) -> u8 {
    if hidden(entry) {
        1
    } else if source_field(entry, "type").and_then(Value::as_u64) == Some(2)
        && matches!(text(entry), Some("true" | "false"))
    {
        2
    } else {
        0
    }
}
fn source_field<'a>(entry: &'a Entry, key: &str) -> Option<&'a Value> {
    member(entry.extra.get("confidex.import.field")?, key)
}
fn member<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let mut fields = value
        .as_map()?
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key));
    let value = &fields.next()?.1;
    fields.next().is_none().then_some(value)
}
fn original<'a>(record: &'a Record, key: &str) -> Option<&'a Value> {
    let origin = record.extra.get("confidex.import.origin")?;
    if member(origin, "version")?.as_u64()? != 1
        || !matches!(
            member(origin, "format")?.as_str()?,
            "bitwarden-json" | "bitwarden-zip" | "bitwarden-encrypted-json"
        )
    {
        return None;
    }
    member(member(origin, "attributes")?, key)
}
fn custom_source(entry: &Entry, value: &Value) -> bool {
    value.as_map().is_some_and(|fields| {
        fields.len() == 1 + usize::from(source_field(entry, "linkedId").is_some())
            && source_field(entry, "type").and_then(Value::as_u64)
                == Some(u64::from(custom_kind(entry)))
            && fields.iter().all(|(key, value)| {
                matches!(key.as_str(), Some("type"))
                    || (key.as_str() == Some("linkedId") && matches!(value, Value::Nil))
            })
    })
}
fn personal_slot(entry: &Entry, kind: u64) -> Option<usize> {
    text(entry)?;
    let (group, slots) = super::fields::personal_slots(kind)?;
    if source_field(entry, "group").and_then(Value::as_str) != Some(group) {
        return None;
    }
    let slot = source_field(entry, "slot")?.as_str()?;
    let index = slots.iter().position(|(key, _, _)| *key == slot)?;
    let kind = if slots[index].2 {
        "secret/v1"
    } else {
        "text/v1"
    };
    (entry.type_name == kind).then_some(index)
}
impl<'a> Item<'a> {
    fn new(record: &'a Record, profile: Profile) -> Self {
        let mut item = Self {
            id: None,
            record,
            profile,
            groups: None,
            slots: [None; 4],
            login: false,
            personal_kind: 0,
            personal: [None; 18],
            ssh: None,
            ssh_text: None,
            otp_source: &[],
        };
        for (index, entry) in record.entries.iter().enumerate() {
            let slot = match entry.type_name.as_str() {
                "username/v1" if text(entry).is_some() => Some(0),
                "password/v1" if text(entry).is_some() => Some(1),
                "totp/v1" if valid_totp(entry) => Some(2),
                "note/v1" | "secure-note/v1" if text(entry).is_some_and(|text| !blank(text)) => {
                    Some(3)
                }
                _ => None,
            };
            if let Some(slot) = slot {
                item.slots[slot].get_or_insert(index);
            }
            item.login |= matches!(
                entry.type_name.as_str(),
                "username/v1" | "password/v1" | "url/v1" | "totp/v1"
            );
        }
        if !item.login {
            item.personal_kind = record
                .entries
                .iter()
                .find_map(|entry| {
                    [3, 4]
                        .into_iter()
                        .find(|&kind| personal_slot(entry, kind).is_some())
                })
                .unwrap_or(0);
            for (index, entry) in record.entries.iter().enumerate() {
                if let Some(slot) = personal_slot(entry, item.personal_kind) {
                    item.personal[slot].get_or_insert(index);
                }
            }
        }
        if !item.login && item.personal_kind == 0 {
            item.ssh = record.entries.iter().position(|entry| entry.type_name == "ssh/v1"
                && matches!(entry.value.get("private_key"), Some(Value::Binary(bytes)) if !bytes.is_empty() && bytes.len() <= ssh::MAX_KEY));
        }
        item
    }
    fn place(&self, index: usize) -> Place {
        let entry = &self.record.entries[index];
        if self.ssh == Some(index) {
            return Place::Ssh;
        }
        if let Some(slot) = self.personal.iter().position(|&field| field == Some(index)) {
            return Place::Personal(slot);
        }
        match entry.type_name.as_str() {
            "username/v1" if self.slots[0] == Some(index) => Place::Username,
            "password/v1" if self.slots[1] == Some(index) => Place::Password,
            "url/v1" if text(entry).is_some() => Place::Uri,
            "totp/v1" if self.slots[2] == Some(index) => Place::Totp,
            "totp/v1" if valid_totp(entry) => Place::CustomOtp,
            "note/v1" | "secure-note/v1" if self.slots[3] == Some(index) => Place::Notes,
            _ if text(entry).is_some() => Place::Custom,
            _ => Place::Omit,
        }
    }
    fn uri_match(&self, entry: &Entry) -> (Option<u8>, bool) {
        let uris = match original(self.record, "login.uris") {
            None | Some(Value::Nil) => return (None, false),
            Some(value) => match value.as_array() {
                Some(uris) => uris,
                None => return (None, true),
            },
        };
        if uris.len() > confidex_vault::record::MAX_ENTRIES {
            return (None, true);
        }
        let mut selected = None;
        let current = text(entry);
        for uri in uris {
            if uri.as_map().is_none_or(|fields| fields.len() > 2) {
                return (None, true);
            }
            if member(uri, "uri").and_then(Value::as_str) != current {
                continue;
            }
            let Some(fields) = uri.as_map() else {
                return (None, true);
            };
            let policy = member(uri, "match");
            if fields.len() != 1 + usize::from(policy.is_some())
                || fields
                    .iter()
                    .any(|(k, _)| !matches!(k.as_str(), Some("uri" | "match")))
            {
                return (None, true);
            }
            let policy = match policy {
                None | Some(Value::Nil) => None,
                Some(value) => match value.as_u64().filter(|&n| n <= 5) {
                    Some(n) => Some(n as u8),
                    None => return (None, true),
                },
            };
            if selected.is_some_and(|previous| previous != policy) {
                return (None, true);
            }
            selected = Some(policy);
        }
        match selected {
            Some(policy) => (policy, false),
            None => (
                None,
                uris.iter().any(|uri| {
                    uri.as_map().is_none_or(|fields| {
                        fields
                            .iter()
                            .any(|(k, v)| k.as_str() == Some("match") && !matches!(v, Value::Nil))
                    })
                }),
            ),
        }
    }
}
impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::BitwardenJson
    }
    fn file(&self) -> export::File {
        export::File {
            name: if self.profile == Profile::Personal {
                "bitwarden-personal.json"
            } else {
                "bitwarden-organization.json"
            },
            media_type: "application/json",
            encrypted: false,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        self.review_with(record, review, &mut |_, _, _| Ok(false))
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        let context = RefCell::new(output);
        self.write_to(records, &context, &mut Sink(&context), &[], records.len())
    }
}
impl Writer {
    pub(crate) fn review_with<'a>(
        &self,
        record: &'a Record,
        review: &mut Review<'_>,
        extend: &mut impl FnMut(usize, &'a Entry, &mut Review<'_>) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let item = Item::new(record, self.profile);
        let mut previous = 0;
        for (index, entry) in record.entries.iter().enumerate() {
            if extend(index, entry, review)? {
                continue;
            }
            let place = item.place(index);
            if place == Place::Ssh {
                let _memory = review.reserve(ssh::REQUIRED_MEMORY)?;
                if ssh::Key::from_value(&entry.value, ssh::REQUIRED_MEMORY).is_err() {
                    review.issue(Some(index), Severity::Blocked, Code::UnknownValue)?;
                    continue;
                }
            }
            let otp_preserved = if let Some(raw) = otp_raw(entry) {
                let _memory = review.reserve(otp_scratch(raw)?)?;
                matching_otp(entry).is_some()
            } else {
                false
            };
            let mut loss = |code| review.issue(Some(index), Severity::Loss, code);
            if place == Place::Omit {
                loss(match entry.type_name.as_str() {
                    "file/v1" | "photo/v1" => Code::Attachments,
                    "totp/v1" => Code::TotpParameters,
                    _ => Code::UnsupportedField,
                })?;
            } else {
                let name = if let Place::Personal(slot) = place {
                    Some(super::fields::personal_slots(item.personal_kind).unwrap().1[slot].1)
                } else {
                    place.name()
                };
                if name.is_some_and(|name| name != entry.name) {
                    loss(Code::FieldNames)?;
                }
                if place.rank() < previous {
                    loss(Code::FieldOrder)?;
                }
                previous = previous.max(place.rank());
                if place == Place::CustomOtp
                    || (place == Place::Custom
                        && !matches!(entry.type_name.as_str(), "text/v1" | "secret/v1"))
                {
                    loss(Code::UnsupportedField)?;
                }
                if hidden(entry) && matches!(place, Place::Username | Place::Uri | Place::Notes) {
                    loss(Code::Protection)?;
                }
                if place == Place::Uri && item.uri_match(entry).1 {
                    loss(Code::SourceContext)?;
                    loss(Code::Protection)?;
                }
                if let Place::Personal(slot) = place {
                    let protected =
                        super::fields::personal_slots(item.personal_kind).unwrap().1[slot].2;
                    if hidden(entry) != protected {
                        loss(Code::Protection)?;
                    }
                }
                if !matches!(place, Place::Totp | Place::CustomOtp) && entry.value.len() != 1 {
                    loss(Code::UnknownValue)?;
                }
                if matches!(place, Place::Totp | Place::CustomOtp)
                    && entry.value.keys().any(|k| {
                        !matches!(
                            k.as_str(),
                            "secret" | "algorithm" | "digits" | "period" | "t0"
                        )
                    })
                {
                    loss(Code::UnknownValue)?;
                }
                for (key, value) in &entry.extra {
                    let recognized = (place == Place::Custom
                        && key == "confidex.import.field"
                        && custom_source(entry, value))
                        || (otp_preserved && key == "confidex.import.totp")
                        || (matches!(place, Place::Personal(_))
                            && key == "confidex.import.field"
                            && value.as_map().is_some_and(|fields| {
                                fields.len() == 2
                                    && fields.iter().all(|(key, _)| {
                                        matches!(key.as_str(), Some("group" | "slot"))
                                    })
                            }))
                        || key == "metadata"
                            && value.as_map().is_some_and(|m| {
                                m.len() == 1
                                    && m[0].0.as_str() == Some("protected")
                                    && m[0].1.as_bool().is_some()
                            });
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
        }
        if self.profile == Profile::Personal && record.tags.len() > 1 {
            review.issue(None, Severity::Loss, Code::Tags)?;
        }
        review.tags();
        if original(record, "reprompt")
            .is_some_and(|v| !matches!(v, Value::Nil) && !matches!(v.as_u64(), Some(0 | 1)))
        {
            review.issue(None, Severity::Loss, Code::Protection)?;
        }
        if record
            .extra
            .get("confidex.title")
            .and_then(Value::as_str)
            .is_some_and(blank)
        {
            review.issue(None, Severity::Loss, Code::UnknownValue)?;
        }
        for (key, value) in &record.extra {
            if key == "confidex.title" && value.as_str().is_some() {
                continue;
            }
            review.issue(
                None,
                Severity::Loss,
                if key == "confidex.import.origin" {
                    Code::SourceContext
                } else {
                    Code::UnknownMetadata
                },
            )?;
        }
        review.metadata();
        Ok(())
    }
    pub(crate) fn write_to(
        &self,
        records: &Records,
        context: &RefCell<&mut Output<'_>>,
        sink: &mut impl Write,
        ids: &[String],
        total: usize,
    ) -> Result<(), Error> {
        if !ids.is_empty() && ids.len() != records.len() {
            return Err(Error::InvalidOptions);
        }
        let mut group_memory = Vec::new();
        let mut groups = BTreeMap::new();
        for record in records.iter() {
            context.borrow_mut().checkpoint(0, total)?;
            let take = if self.profile == Profile::Personal {
                1
            } else {
                record.tags.len()
            };
            for tag in record.tags.iter().take(take) {
                let next = groups.len();
                if let std::collections::btree_map::Entry::Vacant(slot) = groups.entry(tag.as_str())
                {
                    // Include map nodes and the reservation vector in each charge.
                    let memory = context.borrow().reserve(512)?;
                    group_memory.try_reserve(1).map_err(|_| Error::Allocation)?;
                    group_memory.push(memory);
                    slot.insert(next);
                }
            }
        }
        sink.write_all(if self.profile == Profile::Personal {
            b"{\"encrypted\":false,\"folders\":["
        } else {
            b"{\"encrypted\":false,\"collections\":["
        })?;
        for (index, (name, id)) in groups.iter().enumerate() {
            if index != 0 {
                sink.write_all(b",")?;
            }
            json(
                sink,
                &Group {
                    name,
                    id: *id,
                    profile: self.profile,
                },
            )?;
        }
        sink.write_all(b"],\"items\":[")?;
        for (index, record) in records.iter().enumerate() {
            context.borrow_mut().checkpoint(index, total)?;
            if index != 0 {
                sink.write_all(b",")?;
            }
            let mut item = Item::new(record, self.profile);
            item.id = ids.get(index).map(String::as_str);
            item.groups = Some(&groups);
            let has_otp_source = record.entries.iter().any(|entry| otp_raw(entry).is_some());
            let _otp_headers = if has_otp_source {
                Some(
                    context
                        .borrow()
                        .reserve(record.entries.len() * std::mem::size_of::<Option<&str>>())?,
                )
            } else {
                None
            };
            let mut otp_sources = Vec::new();
            if has_otp_source {
                otp_sources
                    .try_reserve_exact(record.entries.len())
                    .map_err(|_| Error::Allocation)?;
                for entry in &record.entries {
                    let source = if let Some(raw) = otp_raw(entry) {
                        let _memory = context.borrow().reserve(otp_scratch(raw)?)?;
                        matching_otp(entry)
                    } else {
                        None
                    };
                    otp_sources.push(source);
                }
                item.otp_source = &otp_sources;
            }
            let _key_memory = item
                .ssh
                .map(|_| context.borrow().reserve(ssh::REQUIRED_MEMORY))
                .transpose()?;
            let key_text = item
                .ssh
                .map(|index| {
                    let key =
                        ssh::Key::from_value(&record.entries[index].value, ssh::REQUIRED_MEMORY)
                            .map_err(|_| Error::InvalidRecord)?;
                    Ok::<_, Error>((
                        key.private_text().map_err(|_| Error::InvalidRecord)?,
                        Zeroizing::new(key.public_text().map_err(|_| Error::InvalidRecord)?),
                        Zeroizing::new(key.fingerprint()),
                    ))
                })
                .transpose()?;
            if let Some((private, public, fingerprint)) = &key_text {
                item.ssh_text = Some(Ssh {
                    private_key: private,
                    public_key: public,
                    key_fingerprint: fingerprint,
                });
            }
            json(sink, &item)?;
        }
        sink.write_all(b"]}")?;
        Ok(())
    }
}
fn json(output: &mut impl Write, value: &impl Serialize) -> Result<(), Error> {
    serde_json::to_writer(output, value).map_err(|_| Error::Writer)
}
const ORGANIZATION: &str = "00000000-0000-4000-8000-ffffffffffff";
struct Id(usize);
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "00000000-0000-4000-8000-{:012x}", self.0)
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
struct Group<'a> {
    name: &'a str,
    id: usize,
    profile: Profile,
}
impl Serialize for Group<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        map.serialize_entry("id", &Id(self.id))?;
        map.serialize_entry("name", self.name)?;
        if self.profile == Profile::Organization {
            map.serialize_entry("organizationId", ORGANIZATION)?;
        }
        map.end()
    }
}
impl Serialize for Item<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        if let Some(id) = self.id {
            map.serialize_entry("id", id)?;
        }
        map.serialize_entry(
            "type",
            &if self.ssh.is_some() {
                5
            } else if self.personal_kind != 0 {
                self.personal_kind
            } else if self.login {
                1
            } else {
                2
            },
        )?;
        map.serialize_entry("name", name(self.record))?;
        map.serialize_entry(
            "favorite",
            &original(self.record, "favorite")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )?;
        map.serialize_entry(
            "reprompt",
            &u8::from(original(self.record, "reprompt").and_then(Value::as_u64) == Some(1)),
        )?;
        let groups = self.groups.expect("writer sets groups");
        if self.profile == Profile::Organization {
            map.serialize_entry("organizationId", ORGANIZATION)?;
            map.serialize_entry(
                "collectionIds",
                &Collections {
                    tags: &self.record.tags,
                    groups,
                },
            )?;
        } else if let Some(tag) = self.record.tags.first() {
            map.serialize_entry("folderId", &Id(groups[tag.as_str()]))?;
        }
        if let Some(index) = self.slots[3] {
            map.serialize_entry("notes", &text(&self.record.entries[index]))?;
        }
        if self.ssh.is_some() {
            map.serialize_entry(
                "sshKey",
                self.ssh_text.as_ref().expect("writer prepares key"),
            )?;
        } else if let Some((group, _)) = super::fields::personal_slots(self.personal_kind) {
            map.serialize_entry(group, &Personal(self))?;
        } else if self.login {
            map.serialize_entry("login", &Login(self))?;
        } else {
            map.serialize_entry("secureNote", &Note { r#type: 0 })?;
        }
        map.serialize_entry("fields", &Custom(self))?;
        map.end()
    }
}
#[derive(Serialize)]
struct Note {
    r#type: u8,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Ssh<'a> {
    private_key: &'a str,
    public_key: &'a str,
    key_fingerprint: &'a str,
}
struct Personal<'a>(&'a Item<'a>);
impl Serialize for Personal<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (_, slots) =
            super::fields::personal_slots(self.0.personal_kind).expect("personal category");
        let mut map = s.serialize_map(None)?;
        for (slot, (key, _, _)) in slots.iter().enumerate() {
            if let Some(index) = self.0.personal[slot] {
                map.serialize_entry(key, &text(&self.0.record.entries[index]))?;
            }
        }
        map.end()
    }
}
struct Collections<'a> {
    tags: &'a [String],
    groups: &'a BTreeMap<&'a str, usize>,
}
impl Serialize for Collections<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.tags.len()))?;
        for tag in self.tags {
            seq.serialize_element(&Id(self.groups[tag.as_str()]))?;
        }
        seq.end()
    }
}
struct Login<'a>(&'a Item<'a>);
impl Serialize for Login<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for (slot, key) in [(0, "username"), (1, "password")] {
            if let Some(index) = self.0.slots[slot] {
                map.serialize_entry(key, &text(&self.0.record.entries[index]))?;
            }
        }
        map.serialize_entry("uris", &Uris(self.0))?;
        if let Some(index) = self.0.slots[2] {
            map.serialize_entry(
                "totp",
                &Otp(
                    &self.0.record.entries[index],
                    self.0.otp_source.get(index).copied().flatten(),
                ),
            )?;
        }
        map.end()
    }
}
struct Uris<'a>(&'a Item<'a>);
#[derive(Serialize)]
struct Uri<'a> {
    uri: &'a str,
    r#match: Option<u8>,
}
impl Serialize for Uris<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        for (index, entry) in self.0.record.entries.iter().enumerate() {
            if self.0.place(index) == Place::Uri {
                seq.serialize_element(&Uri {
                    uri: text(entry).unwrap(),
                    r#match: self.0.uri_match(entry).0,
                })?;
            }
        }
        seq.end()
    }
}
struct Custom<'a>(&'a Item<'a>);
#[derive(Serialize)]
struct Field<'a, T> {
    name: &'a str,
    value: T,
    r#type: u8,
    #[serde(rename = "linkedId", skip_serializing_if = "Option::is_none")]
    linked_id: Option<()>,
}
impl Serialize for Custom<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        for (index, entry) in self.0.record.entries.iter().enumerate() {
            if self.0.place(index) == Place::Custom {
                seq.serialize_element(&Field {
                    name: &entry.name,
                    value: text(entry).unwrap(),
                    r#type: custom_kind(entry),
                    linked_id: matches!(source_field(entry, "linkedId"), Some(Value::Nil))
                        .then_some(()),
                })?;
            } else if self.0.place(index) == Place::CustomOtp {
                seq.serialize_element(&Field {
                    name: &entry.name,
                    value: Otp(entry, self.0.otp_source.get(index).copied().flatten()),
                    r#type: 1,
                    linked_id: None,
                })?;
            }
        }
        seq.end()
    }
}
