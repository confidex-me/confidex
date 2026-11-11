use crate::{
    encoding::{CONTENT_LIMITS, EncodingError, scan_messagepack},
    resources::MAX_OPEN_MEMORY,
};
pub use rmpv::Value;
use rmpv::ValueRef;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

mod encode;
mod value;

pub type Mapping = BTreeMap<String, Value>;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_TAGS: usize = 256;
pub const MAX_TAG_BYTES: usize = 256;

#[derive(Default)]
pub struct Record {
    pub entries: Vec<Entry>,
    pub tags: Vec<String>,
    pub extra: Mapping,
}
pub struct Entry {
    pub name: String,
    pub type_name: String,
    pub value: Mapping,
    pub extra: Mapping,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    EmptyType { index: usize },
    ReservedField { index: Option<usize> },
    InvalidStructure,
    InvalidEncoding,
    Limit,
    Allocation,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValueError {
    UnsupportedType,
    Missing(&'static str),
    WrongType(&'static str),
    InvalidValue(&'static str),
}

pub struct DecodedContent {
    pub record: Record,
    pub value_sizes: Vec<u64>,
}
pub struct EncodedContent {
    pub bytes: Zeroizing<Vec<u8>>,
    pub value_sizes: Vec<u64>,
}

fn admission(bytes: usize, nodes: usize, budget: usize) -> Result<(), Error> {
    let required = bytes
        .checked_mul(2)
        .and_then(|n| nodes.checked_mul(256).and_then(|m| n.checked_add(m)))
        .and_then(|n| n.checked_add(2 * 1024 * 1024))
        .ok_or(Error::Limit)?;
    if budget > MAX_OPEN_MEMORY || required > budget {
        return Err(Error::Limit);
    }
    Ok(())
}

impl Record {
    pub fn validate_structure(&self) -> Result<(), Error> {
        if self.entries.len() > MAX_ENTRIES
            || self.tags.len() > MAX_TAGS
            || self.tags.iter().any(|tag| tag.len() > MAX_TAG_BYTES)
        {
            return Err(Error::Limit);
        }
        if self.extra.contains_key("entries") || self.extra.contains_key("tags") {
            return Err(Error::ReservedField { index: None });
        }
        if self
            .tags
            .iter()
            .enumerate()
            .any(|(i, tag)| self.tags[..i].contains(tag))
        {
            return Err(Error::InvalidStructure);
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.type_name.is_empty() {
                return Err(Error::EmptyType { index });
            }
            if ["name", "type", "value"]
                .iter()
                .any(|key| entry.extra.contains_key(*key))
            {
                return Err(Error::ReservedField { index: Some(index) });
            }
        }
        Ok(())
    }

    pub fn decode_content(input: &[u8], budget: usize) -> Result<DecodedContent, Error> {
        admission(input.len(), 0, budget)?;
        let stats = scan_messagepack(input, CONTENT_LIMITS).map_err(|e| match e {
            EncodingError::Limit => Error::Limit,
            EncodingError::Allocation => Error::Allocation,
            EncodingError::Invalid => Error::InvalidEncoding,
        })?;
        admission(input.len(), stats.nodes, budget)?;
        let mut remaining = input;
        let root =
            rmpv::decode::read_value_ref(&mut remaining).map_err(|_| Error::InvalidEncoding)?;
        let entries = ref_field(&root, "entries")?
            .as_array()
            .ok_or(Error::InvalidStructure)?;
        if entries.len() > MAX_ENTRIES {
            return Err(Error::Limit);
        }
        let ValueRef::Map(fields) = &root else {
            unreachable!()
        };
        if let Some((_, tags)) = fields.iter().find(|(key, _)| text_ref(key) == Some("tags")) {
            let tags = tags.as_array().ok_or(Error::InvalidStructure)?;
            if tags.len() > MAX_TAGS {
                return Err(Error::Limit);
            }
            let mut previous = None;
            for tag in tags {
                let tag = text_ref(tag).ok_or(Error::InvalidStructure)?;
                if tag.len() > MAX_TAG_BYTES {
                    return Err(Error::Limit);
                }
                if previous.is_some_and(|p| p >= tag) {
                    return Err(Error::InvalidStructure);
                }
                previous = Some(tag);
            }
        }
        for (index, entry) in entries.iter().enumerate() {
            text_ref(ref_field(entry, "name")?).ok_or(Error::InvalidStructure)?;
            let ty = text_ref(ref_field(entry, "type")?).ok_or(Error::InvalidStructure)?;
            if ty.is_empty() {
                return Err(Error::EmptyType { index });
            }
            if !matches!(ref_field(entry, "value")?, ValueRef::Map(_)) {
                return Err(Error::InvalidStructure);
            }
        }
        let sizes = value_spans(input, entries.len())?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(entries.len())
            .map_err(|_| Error::Allocation)?;
        let root = value::owned(root)?;
        let mut extra = into_mapping(root.take());
        let tags = match extra.remove("tags") {
            Some(Value::Array(tags)) => tags.into_iter().map(into_text).collect(),
            None => Vec::new(),
            _ => unreachable!(),
        };
        let Value::Array(values) = extra.remove("entries").unwrap() else {
            unreachable!()
        };
        for value in values {
            let mut fields = into_mapping(value);
            output.push(Entry {
                name: into_text(fields.remove("name").unwrap()),
                type_name: into_text(fields.remove("type").unwrap()),
                value: into_mapping(fields.remove("value").unwrap()),
                extra: fields,
            });
        }
        Ok(DecodedContent {
            record: Self {
                entries: output,
                tags,
                extra,
            },
            value_sizes: sizes,
        })
    }

    pub fn encode_content(&self, budget: usize) -> Result<EncodedContent, Error> {
        admission(0, 0, budget)?;
        self.validate_structure()?;
        let mut count = encode::Encoder::new(None);
        count.record(self)?;
        admission(count.bytes(), count.nodes(), budget)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(count.bytes())
            .map_err(|_| Error::Allocation)?;
        let mut writer = encode::Encoder::new(Some(bytes));
        writer.record(self)?;
        Ok(writer.finish())
    }
}

impl Entry {
    pub fn validate_value(&self) -> Result<(), ValueError> {
        if self.type_name == "location/v1" {
            return crate::location::read(&self.value).map(|_| ());
        }
        if let Some(precision) = crate::date::Precision::from_type(&self.type_name) {
            return crate::date::read(&self.value, precision).map(|_| ());
        }
        if self.type_name == "ssh/v1" {
            let Value::Binary(data) = self
                .value
                .get("private_key")
                .ok_or(ValueError::Missing("private_key"))?
            else {
                return Err(ValueError::WrongType("private_key"));
            };
            return if data.len() > crate::ssh::MAX_KEY {
                Err(ValueError::InvalidValue("private_key"))
            } else {
                Ok(())
            };
        }
        if self.type_name == "wifi/v1" {
            return crate::wifi::Credentials::from_value(&self.value).map(|_| ());
        }
        if self.type_name == "wifi-qr/v1" {
            let auth = self
                .value
                .get("auth")
                .and_then(Value::as_str)
                .ok_or(ValueError::WrongType("auth"))?;
            if !matches!(auth, "nopass" | "WEP" | "WPA") {
                return Err(ValueError::InvalidValue("auth"));
            }
            for key in ["ssid", "password"] {
                if let Some(value) = self.value.get(key) {
                    let value = value.as_str().ok_or(ValueError::WrongType(key))?;
                    if !value.is_empty() && value.parse::<u64>().is_err() {
                        return Err(ValueError::InvalidValue(key));
                    }
                }
            }
            return Ok(());
        }
        if self.type_name == "totp/v1" {
            return crate::totp::Totp::from_value(&self.value).map(|_| ());
        }
        if matches!(self.type_name.as_str(), "photo/v1" | "file/v1") {
            if !matches!(
                self.value.get("data").ok_or(ValueError::Missing("data"))?,
                Value::Binary(_)
            ) {
                return Err(ValueError::WrongType("data"));
            }
            for &field in if self.type_name == "file/v1" {
                &["mime", "filename"][..]
            } else {
                &["mime"][..]
            } {
                if let Some(value) = self.value.get(field) {
                    value.as_str().ok_or(ValueError::WrongType(field))?;
                }
            }
            return Ok(());
        }
        let (required, optional): (&[&'static str], &[&'static str]) = match self.type_name.as_str()
        {
            "login/v1" => (&["username", "password"], &["url"]),
            "username/v1" => (&["username"], &[]),
            "text/v1" => (&["text"], &[]),
            "url/v1" => (&["url"], &[]),
            "secret/v1" => (&["secret"], &[]),
            "password/v1" => (&["password"], &[]),
            "api_key/v1" => (&["secret"], &["url"]),
            "note/v1" | "secure-note/v1" => (&["text"], &[]),
            "card/v1" => (&[], &["number", "holder", "expiry", "cvv", "pin", "brand"]),
            "person/v1" => (
                &[],
                &[
                    "name",
                    "birth_date",
                    "address",
                    "email",
                    "phone",
                    "identifier",
                ],
            ),
            "document/v1" => (
                &[],
                &[
                    "kind", "number", "holder", "issuer", "country", "issued", "expires",
                ],
            ),
            "passport/v1" => (
                &[],
                &[
                    "number",
                    "holder",
                    "issuer",
                    "country",
                    "nationality",
                    "issued",
                    "expires",
                ],
            ),
            _ => return Err(ValueError::UnsupportedType),
        };
        for &field in required {
            self.value
                .get(field)
                .ok_or(ValueError::Missing(field))?
                .as_str()
                .ok_or(ValueError::WrongType(field))?;
        }
        for &field in optional {
            if let Some(value) = self.value.get(field) {
                value.as_str().ok_or(ValueError::WrongType(field))?;
            }
        }
        Ok(())
    }
}

fn ref_field<'a, 'b>(value: &'b ValueRef<'a>, name: &str) -> Result<&'b ValueRef<'a>, Error> {
    let ValueRef::Map(rows) = value else {
        return Err(Error::InvalidStructure);
    };
    rows.iter()
        .find(|(k, _)| text_ref(k) == Some(name))
        .map(|(_, v)| v)
        .ok_or(Error::InvalidStructure)
}
fn text_ref<'a>(value: &'a ValueRef<'_>) -> Option<&'a str> {
    match value {
        ValueRef::String(s) => s.as_str(),
        _ => None,
    }
}
fn into_text(value: Value) -> String {
    let Value::String(s) = value else {
        unreachable!()
    };
    s.into_str().unwrap()
}
fn into_mapping(value: Value) -> Mapping {
    let Value::Map(rows) = value else {
        unreachable!()
    };
    rows.into_iter()
        .map(|(key, value)| (into_text(key), value))
        .collect()
}
fn value_spans(mut input: &[u8], count: usize) -> Result<Vec<u64>, Error> {
    let mut sizes = Vec::new();
    sizes
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    let fields = rmp::decode::read_map_len(&mut input).map_err(|_| Error::InvalidStructure)?;
    for _ in 0..fields {
        let key = rmpv::decode::read_value_ref(&mut input).map_err(|_| Error::InvalidEncoding)?;
        if text_ref(&key) != Some("entries") {
            rmpv::decode::read_value_ref(&mut input).map_err(|_| Error::InvalidEncoding)?;
            continue;
        }
        let count = rmp::decode::read_array_len(&mut input).map_err(|_| Error::InvalidStructure)?;
        for _ in 0..count {
            let fields =
                rmp::decode::read_map_len(&mut input).map_err(|_| Error::InvalidStructure)?;
            for _ in 0..fields {
                let key =
                    rmpv::decode::read_value_ref(&mut input).map_err(|_| Error::InvalidEncoding)?;
                let before = input.len();
                rmpv::decode::read_value_ref(&mut input).map_err(|_| Error::InvalidEncoding)?;
                if text_ref(&key) == Some("value") {
                    sizes.push((before - input.len()) as u64);
                }
            }
        }
    }
    Ok(sizes)
}
fn wipe_mapping(map: &mut Mapping) {
    for value in map.values_mut() {
        value::wipe(value);
    }
    for (mut key, _) in std::mem::take(map) {
        key.zeroize();
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.name.zeroize();
        self.type_name.zeroize();
        wipe_mapping(&mut self.value);
        wipe_mapping(&mut self.extra);
    }
}
impl Drop for Record {
    fn drop(&mut self) {
        self.entries.clear();
        for tag in &mut self.tags {
            tag.zeroize();
        }
        wipe_mapping(&mut self.extra);
    }
}
