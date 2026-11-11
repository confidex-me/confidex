//! Templates produce independent entries. Source bindings only describe an old revision.
use super::{Error, Field, field_protected};
use confidex_vault::date;
use confidex_vault::location;
use confidex_vault::record::{Entry, Mapping, Record, Value};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

pub(super) const MAX_FIELDS: usize = 512;
const MAX_DRAFT_TEXT: usize = 2 * 1024 * 1024;
pub const FIELD_KINDS: &[&str] = &[
    "note/v1",
    "secure-note/v1",
    "password/v1",
    "text/v1",
    "username/v1",
    "url/v1",
    "secret/v1",
    "wifi-qr/v1",
    "photo/v1",
    "file/v1",
    "card/v1",
    "totp/v1",
    "date/v1",
    "month-year/v1",
    "location/v1",
    "ssh/v1",
];

pub(super) fn key(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "text/v1" | "note/v1" | "secure-note/v1" => "text",
        "username/v1" => "username",
        "password/v1" => "password",
        "url/v1" => "url",
        "secret/v1" => "secret",
        "date/v1" | "month-year/v1" => "date",
        _ => return None,
    })
}
pub fn data_key(kind: &str) -> Option<&'static str> {
    match kind {
        "photo/v1" | "file/v1" => Some("data"),
        "totp/v1" => Some("secret"),
        "ssh/v1" => Some("private_key"),
        _ => None,
    }
}
pub fn field(kind: &str) -> Result<Field, Error> {
    let binary = data_key(kind).is_some();
    let values = if kind == "ssh/v1" {
        BTreeMap::new()
    } else if kind == "location/v1" {
        location::FIELDS
            .into_iter()
            .map(|key| (key.into(), String::new()))
            .collect()
    } else if kind == "totp/v1" {
        [
            ("algorithm", "SHA1"),
            ("digits", "6"),
            ("period", "30"),
            ("t0", "0"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect()
    } else if kind == "card/v1" {
        ["number", "holder", "expiry", "cvv", "pin", "brand"]
            .into_iter()
            .map(|key| (key.into(), String::new()))
            .collect()
    } else if binary {
        BTreeMap::from([
            (
                "mime".into(),
                if kind == "photo/v1" {
                    "image/webp"
                } else {
                    "application/octet-stream"
                }
                .into(),
            ),
            ("filename".into(), String::new()),
        ])
    } else if kind == "wifi-qr/v1" {
        BTreeMap::from([
            ("ssid".into(), String::new()),
            ("password".into(), String::new()),
            ("auth".into(), "WPA".into()),
        ])
    } else {
        BTreeMap::from([(key(kind).ok_or(Error::Input)?.into(), String::new())])
    };
    Ok(Field {
        source: None,
        source_key: None,
        name: String::new(),
        type_name: kind.into(),
        values,
        data: binary.then(|| Vec::new().into()),
        opaque: 0,
        protected: binary || kind == "secure-note/v1",
    })
}
pub fn field_record(field: &Field) -> Result<Record, Error> {
    let mut field = field.clone();
    field.source = None;
    field.source_key = None;
    let mut record = Record::default();
    apply(&mut record, &[field])?;
    Ok(record)
}
pub fn template(kind: &str) -> Result<Vec<Field>, Error> {
    if let Some(template) = crate::templates::get(kind) {
        return template.fields();
    }
    if kind == "wifi" {
        let mut fields = ["text/v1", "password/v1", "wifi-qr/v1"]
            .map(field)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        fields[0].name = "SSID".into();
        fields[2].values.insert("ssid".into(), "0".into());
        fields[2].values.insert("password".into(), "1".into());
        return Ok(fields);
    }
    let kinds: &[&str] = match kind {
        "note" => &["note/v1"],
        "empty" => &[],
        _ => return Err(Error::Input),
    };
    kinds.iter().map(|kind| field(kind)).collect()
}
fn parts(entry: &Entry) -> Option<&'static [(&'static str, &'static str)]> {
    let parts: &[(&str, &str)] = match entry.type_name.as_str() {
        "login/v1" => &[
            ("username", "username/v1"),
            ("password", "password/v1"),
            ("url", "url/v1"),
        ],
        "api_key/v1" => &[("secret", "secret/v1"), ("url", "url/v1")],
        _ => return None,
    };
    parts
        .iter()
        .all(|(key, _)| {
            entry
                .value
                .get(*key)
                .is_none_or(|value| value.as_str().is_some())
        })
        .then_some(parts)
}
pub(super) fn count(record: &Record) -> usize {
    record
        .entries
        .iter()
        .map(|entry| parts(entry).map_or(1, <[_]>::len))
        .sum()
}
pub(super) fn read(record: &Record) -> Result<Vec<Field>, Error> {
    let mut fields = Vec::new();
    let mut bytes = 0;
    for (index, entry) in record.entries.iter().enumerate() {
        if entry.name.len() > 4096 || entry.type_name.len() > 4096 || entry.value.len() > 128 {
            return Err(Error::Input);
        }
        let before = fields.len();
        if let Some(parts) = parts(entry) {
            for (position, &(source_key, kind)) in parts.iter().enumerate() {
                let mut output = field(kind)?;
                output.source = Some(index);
                output.protected = field_protected(entry);
                output.source_key = Some(source_key.into());
                output.name = entry.name.clone();
                if let Some(value) = entry.value.get(source_key).and_then(Value::as_str) {
                    if value.len() <= 65536 {
                        output.values.insert(source_key.into(), value.into());
                    } else {
                        output.values.clear();
                        output.opaque += 1;
                    }
                }
                if position == 0 {
                    output.opaque += entry
                        .value
                        .keys()
                        .filter(|key| !parts.iter().any(|(part, _)| *part == key.as_str()))
                        .count();
                }
                fields.push(output);
            }
        } else {
            let mut values = BTreeMap::new();
            let token = entry.type_name == "totp/v1";
            let ssh = entry.type_name == "ssh/v1";
            let precision = date::Precision::from_type(&entry.type_name);
            let location = entry.type_name == "location/v1";
            let data_key = data_key(&entry.type_name);
            let binary = data_key.is_some();
            let data = if let Some(data_key) = data_key {
                entry.value.get(data_key).and_then(|value| match value {
                    Value::Binary(bytes)
                        if (!token || bytes.len() <= confidex_vault::totp::MAX_SECRET)
                            && (!ssh || bytes.len() <= confidex_vault::ssh::MAX_KEY) =>
                    {
                        Some(super::Bytes::from(bytes.clone()))
                    }
                    _ => None,
                })
            } else {
                None
            };
            let keys: Vec<_> = if precision.is_some() || location || ssh {
                vec![]
            } else if token {
                vec!["algorithm", "digits", "period", "t0"]
            } else if entry.type_name == "card/v1" {
                vec!["number", "holder", "expiry", "cvv", "pin", "brand"]
            } else if binary {
                vec!["mime", "filename"]
            } else if entry.type_name == "wifi-qr/v1" {
                vec!["ssid", "password", "auth"]
            } else {
                key(&entry.type_name).into_iter().collect()
            };
            for key in keys {
                if let Some(value) = entry.value.get(key) {
                    if token && key != "algorithm" {
                        values.insert(
                            key.into(),
                            value.as_u64().map(|n| n.to_string()).unwrap_or_default(),
                        );
                        continue;
                    }
                    if let Some(value) = value.as_str().filter(|value| value.len() <= 65536) {
                        values.insert(key.into(), value.into());
                    } else if token {
                        values.insert(key.into(), String::new());
                    }
                } else {
                    values.insert(
                        key.into(),
                        if token {
                            match key {
                                "algorithm" => "SHA1",
                                "digits" => "6",
                                "period" => "30",
                                _ => "0",
                            }
                            .into()
                        } else {
                            String::new()
                        },
                    );
                }
            }
            if let Some(precision) = precision
                && let Ok(date) = date::read(&entry.value, precision)
            {
                values.insert(
                    "date".into(),
                    date.map(|date| date.text()).unwrap_or_default(),
                );
            }
            if location
                && entry
                    .value
                    .get("name")
                    .and_then(Value::as_str)
                    .is_none_or(|name| name.len() <= 65536)
                && let Ok(coordinates) = location::read(&entry.value)
            {
                values.insert(
                    "name".into(),
                    entry
                        .value
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .into(),
                );
                values.insert(
                    "latitude".into(),
                    coordinates
                        .map(|(latitude, _)| latitude.to_string())
                        .unwrap_or_default(),
                );
                values.insert(
                    "longitude".into(),
                    coordinates
                        .map(|(_, longitude)| longitude.to_string())
                        .unwrap_or_default(),
                );
            }
            if ssh && let Some(data) = data.as_ref().filter(|data| !data.is_empty()) {
                values = crate::ssh::read(data).unwrap_or_default();
            }
            let opaque = entry
                .value
                .keys()
                .filter(|key| {
                    if ssh {
                        !(key.as_str() == "private_key" && data.is_some())
                    } else if location {
                        !values.contains_key("name") || !location::FIELDS.contains(&key.as_str())
                    } else if let Some(precision) = precision {
                        !values.contains_key("date") || !precision.keys().contains(&key.as_str())
                    } else {
                        !values.contains_key(*key)
                            && !(Some(key.as_str()) == data_key && data.is_some())
                    }
                })
                .count()
                + usize::from(
                    ssh && values.is_empty() && data.as_ref().is_some_and(|data| !data.is_empty()),
                );
            fields.push(Field {
                source: Some(index),
                source_key: None,
                name: entry.name.clone(),
                type_name: if entry.type_name == "note/v1" && field_protected(entry) {
                    "secure-note/v1".into()
                } else {
                    entry.type_name.clone()
                },
                values,
                data,
                opaque,
                protected: ssh || field_protected(entry),
            });
        }
        if fields.len() > MAX_FIELDS {
            return Err(Error::Input);
        }
        for field in &fields[before..] {
            bytes += field.name.len()
                + field.type_name.len()
                + field
                    .values
                    .iter()
                    .map(|(key, value)| key.len() + value.len())
                    .sum::<usize>();
            if bytes > MAX_DRAFT_TEXT {
                return Err(Error::Input);
            }
        }
    }
    let positions: Vec<_> = (0..record.entries.len())
        .map(|index| {
            fields
                .iter()
                .position(|f| f.source == Some(index) && f.source_key.is_none())
        })
        .collect();
    super::wifi::remap(&mut fields, &positions);
    Ok(fields)
}

pub(super) fn apply(record: &mut Record, fields: &[Field]) -> Result<(), Error> {
    let bytes: usize = fields
        .iter()
        .map(|field| {
            field.name.len()
                + field.type_name.len()
                + field
                    .values
                    .iter()
                    .map(|(key, value)| key.len() + value.len())
                    .sum::<usize>()
        })
        .sum();
    if fields.len() > MAX_FIELDS || bytes > MAX_DRAFT_TEXT {
        return Err(Error::Input);
    }
    let data_bytes = fields
        .iter()
        .filter_map(|field| field.data.as_ref())
        .try_fold(0usize, |total, data| total.checked_add(data.len()))
        .ok_or(Error::RecordLimit)?;
    if data_bytes > confidex_vault::resources::MAX_DECOMPRESSED {
        return Err(Error::RecordLimit);
    }
    let mut retired = Record::default();
    retired.entries = std::mem::take(&mut record.entries);
    let mut used = BTreeSet::new();
    let mut split = BTreeMap::<usize, BTreeSet<String>>::new();
    let mut owners = BTreeMap::<usize, &str>::new();
    for field in fields {
        if let (Some(index), Some(key)) = (field.source, field.source_key.as_deref()) {
            let source = retired.entries.get(index).ok_or(Error::Input)?;
            let parts = parts(source).ok_or(Error::Input)?;
            let preferred = parts[0].0;
            let owner = owners.entry(index).or_insert(key);
            if key == preferred {
                *owner = key;
            }
        }
    }
    for field in fields {
        if field.name.len() > 4096
            || field.values.len() > 128
            || field
                .values
                .iter()
                .any(|(key, value)| key.len() > 4096 || value.len() > 65536)
        {
            return Err(Error::Input);
        }
        let entry = if let Some(index) = field.source {
            let source = retired.entries.get(index).ok_or(Error::Input)?;
            if let Some(source_key) = &field.source_key {
                let parts = parts(source).ok_or(Error::Input)?;
                if used.contains(&index)
                    || !parts
                        .iter()
                        .any(|(key, kind)| key == source_key && *kind == field.type_name)
                    || !split.entry(index).or_default().insert(source_key.clone())
                {
                    return Err(Error::Input);
                }
                let owner = owners.get(&index).is_some_and(|key| *key == source_key);
                let mut value = if owner {
                    source.value.clone()
                } else {
                    Mapping::new()
                };
                let original = source.value.get(source_key).cloned();
                if owner {
                    for &(key, _) in parts {
                        if let Some(old) = value.remove(key) {
                            retired.extra.insert(retired.extra.len().to_string(), old);
                        }
                    }
                }
                if let Some(original) = original {
                    value.insert(source_key.clone(), original);
                }
                Entry {
                    name: String::new(),
                    type_name: field.type_name.clone(),
                    value,
                    extra: if owner {
                        source.extra.clone()
                    } else {
                        Mapping::new()
                    },
                }
            } else {
                if split.contains_key(&index)
                    || !used.insert(index)
                    || (source.type_name != field.type_name
                        && !(matches!(source.type_name.as_str(), "note/v1" | "secure-note/v1")
                            && matches!(field.type_name.as_str(), "note/v1" | "secure-note/v1")))
                {
                    return Err(Error::Input);
                }
                Entry {
                    name: source.name.clone(),
                    type_name: field.type_name.clone(),
                    value: source.value.clone(),
                    extra: source.extra.clone(),
                }
            }
        } else {
            if field.source_key.is_some() {
                return Err(Error::Input);
            }
            Entry {
                name: String::new(),
                type_name: field.type_name.clone(),
                value: Mapping::new(),
                extra: Mapping::new(),
            }
        };
        // Keep discarded copies under Record so all error paths wipe their values.
        record.entries.push(entry);
        let entry = record.entries.last_mut().unwrap();
        if entry.type_name == "note/v1" && field.protected {
            entry.type_name = "secure-note/v1".into();
        }
        entry.name.zeroize();
        entry.name = field.name.clone();
        if entry.type_name == "ssh/v1" {
            if field
                .values
                .keys()
                .any(|key| !crate::ssh::ROWS.contains(&key.as_str()))
            {
                return Err(Error::Input);
            }
        } else if entry.type_name == "location/v1" {
            if !field.values.is_empty() {
                if field.values.len() != location::FIELDS.len()
                    || !location::FIELDS
                        .iter()
                        .all(|key| field.values.contains_key(*key))
                {
                    return Err(Error::Input);
                }
                let coordinates =
                    location::parse(&field.values["latitude"], &field.values["longitude"])
                        .map_err(|_| Error::Input)?;
                if entry.value.get("name").and_then(Value::as_str)
                    != Some(field.values["name"].as_str())
                    && let Some(old) = entry
                        .value
                        .insert("name".into(), Value::from(field.values["name"].as_str()))
                {
                    retired.extra.insert(retired.extra.len().to_string(), old);
                }
                for (key, next) in [
                    ("latitude", coordinates.map(|(latitude, _)| latitude)),
                    ("longitude", coordinates.map(|(_, longitude)| longitude)),
                ] {
                    if let Some(number) = next {
                        if entry.value.get(key).and_then(Value::as_f64) != Some(number)
                            && let Some(old) = entry.value.insert(key.into(), Value::F64(number))
                        {
                            retired.extra.insert(retired.extra.len().to_string(), old);
                        }
                    } else if let Some(old) = entry.value.remove(key) {
                        retired.extra.insert(retired.extra.len().to_string(), old);
                    }
                }
            } else if field.source.is_none() {
                return Err(Error::Input);
            }
        } else if let Some(precision) = date::Precision::from_type(&entry.type_name) {
            if let Some(text) = field.values.get("date") {
                if field.values.len() != 1 {
                    return Err(Error::Input);
                }
                let date = date::parse(text, precision).map_err(|_| Error::Input)?;
                for key in precision.keys() {
                    if let Some(old) = entry.value.remove(*key) {
                        retired.extra.insert(retired.extra.len().to_string(), old);
                    }
                }
                if let Some(date) = date {
                    entry.value.extend(date.value());
                }
            } else if field.source.is_none() || !field.values.is_empty() {
                return Err(Error::Input);
            }
        } else {
            for (key, value) in &field.values {
                let numeric = entry.type_name == "totp/v1"
                    && matches!(key.as_str(), "digits" | "period" | "t0");
                if entry
                    .value
                    .get(key)
                    .is_some_and(|value| value.as_str().is_none())
                    && !numeric
                {
                    return Err(Error::Input);
                }
                let next = if numeric {
                    Value::from(value.parse::<u64>().map_err(|_| Error::Input)?)
                } else {
                    Value::from(value.as_str())
                };
                if let Some(old) = entry.value.insert(key.clone(), next) {
                    retired.extra.insert(retired.extra.len().to_string(), old);
                }
            }
        }
        // Keep unsupported source keys when their bytes do not change.
        let changed_ssh = entry.type_name == "ssh/v1" && field.data.as_ref().is_some_and(|data| {
            !matches!(entry.value.get("private_key"), Some(Value::Binary(old)) if old.as_slice() == &**data)
        });
        if let Some(data) = &field.data {
            let key = data_key(&entry.type_name).ok_or(Error::Input)?;
            if let Some(old) = entry.value.insert(key.into(), Value::Binary(data.to_vec())) {
                retired.extra.insert(retired.extra.len().to_string(), old);
            }
        }
        if matches!(entry.type_name.as_str(), "wifi-qr/v1" | "totp/v1") {
            entry.validate_value().map_err(|_| Error::Input)?;
        }
        if entry.type_name == "ssh/v1" && (changed_ssh || field.source.is_none()) {
            entry.validate_value().map_err(|_| Error::Input)?;
            if field.data.as_ref().is_some_and(|data| !data.is_empty()) {
                confidex_vault::ssh::Key::from_value(
                    &entry.value,
                    confidex_vault::ssh::REQUIRED_MEMORY,
                )
                .map_err(|_| Error::Input)?;
            }
        }
        if field.protected != field_protected(entry) {
            let metadata = entry
                .extra
                .entry("metadata".into())
                .or_insert_with(|| Value::Map(vec![]));
            let Value::Map(items) = metadata else {
                return Err(Error::Input);
            };
            for index in (0..items.len()).rev() {
                if items[index].0.as_str() == Some("protected") {
                    let old = items.remove(index);
                    retired
                        .extra
                        .insert(retired.extra.len().to_string(), Value::Map(vec![old]));
                }
            }
            items.push((Value::from("protected"), Value::Boolean(field.protected)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ssh_value() -> Mapping {
        let private = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
            "public app fixture",
        )
        .unwrap();
        let pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
        confidex_vault::ssh::Key::import(pem.as_bytes(), None, confidex_vault::ssh::REQUIRED_MEMORY)
            .unwrap()
            .to_value()
            .unwrap()
    }
    #[test]
    fn ssh_binary_roundtrip_keeps_source_values_metadata_and_independent_order() {
        let mut value = ssh_value();
        value.insert("future-value".into(), Value::Ext(4, vec![7, 8]));
        let mut record = Record::default();
        record.entries.push(Entry {
            name: "Same".into(),
            type_name: "ssh/v1".into(),
            value: value.clone(),
            extra: Mapping::from_iter([("future-meta".into(), Value::from("keep"))]),
        });
        let mut fields = read(&record).unwrap();
        assert_eq!(fields[0].values["key_type"], "Ed25519");
        assert!(fields[0].values["public_key"].starts_with("ssh-ed25519 "));
        assert_eq!(fields[0].opaque, 1);
        assert!(
            matches!(&value["private_key"], Value::Binary(bytes) if bytes.as_slice() == &**fields[0].data.as_ref().unwrap())
        );
        fields[0].name = "Renamed".into();
        fields.insert(0, field("note/v1").unwrap());
        apply(&mut record, &fields).unwrap();
        let content = record
            .encode_content(confidex_vault::resources::MAX_OPEN_MEMORY)
            .unwrap();
        let reopened =
            Record::decode_content(&content.bytes, confidex_vault::resources::MAX_OPEN_MEMORY)
                .unwrap()
                .record;
        assert_eq!(reopened.entries[1].name, "Renamed");
        assert_eq!(reopened.entries[1].value, value);
        assert_eq!(
            reopened.entries[1].extra["future-meta"].as_str(),
            Some("keep")
        );
        assert_eq!(read(&reopened).unwrap()[1].opaque, 1);
    }
    #[test]
    fn ssh_new_or_replaced_bytes_are_checked_but_an_empty_optional_field_is_allowed() {
        let mut ssh = field("ssh/v1").unwrap();
        assert!(ssh.protected && ssh.data.as_ref().unwrap().is_empty() && ssh.values.is_empty());
        assert!(field_record(&ssh).is_ok());
        let mut value = ssh_value();
        let Value::Binary(bytes) = value.remove("private_key").unwrap() else {
            panic!("binary");
        };
        ssh.data = Some(bytes.into());
        let mut record = field_record(&ssh).unwrap();
        let mut fields = read(&record).unwrap();
        fields[0].data = Some(vec![1, 2, 3].into());
        assert_eq!(apply(&mut record, &fields), Err(Error::Input));
        for data in [
            Some(vec![0; confidex_vault::ssh::MAX_KEY + 1].into()),
            Some(vec![1].into()),
            None,
        ] {
            ssh.data = data;
            assert!(field_record(&ssh).is_err());
        }
    }
    #[test]
    fn ssh_unrecognized_stored_bytes_survive_unrelated_edits() {
        for value in [
            Value::from("future representation"),
            Value::Binary(vec![9; confidex_vault::ssh::MAX_KEY + 1]),
            Value::Binary(vec![1, 2, 3]),
        ] {
            let mut record = Record::default();
            record.entries.push(Entry {
                name: "Before".into(),
                type_name: "ssh/v1".into(),
                value: Mapping::from_iter([("private_key".into(), value.clone())]),
                extra: Mapping::new(),
            });
            let mut fields = read(&record).unwrap();
            fields[0].name = "After".into();
            apply(&mut record, &fields).unwrap();
            assert_eq!(record.entries[0].value["private_key"], value);
            assert_eq!(record.entries[0].name, "After");
        }
    }
    fn legacy() -> Record {
        let mut record = Record::default();
        record.entries.push(Entry {
            name: "Work".into(),
            type_name: "login/v1".into(),
            value: Mapping::from_iter([
                ("username".into(), Value::from("alice")),
                ("password".into(), Value::from("private-fixture")),
                ("url".into(), Value::from("https://example.test")),
                ("vendor".into(), Value::Binary(vec![3, 4, 5])),
            ]),
            extra: Mapping::from_iter([("vendor-meta".into(), Value::from("keep"))]),
        });
        record
            .extra
            .insert("record-extra".into(), Value::from("keep"));
        record
    }
    #[test]
    fn templates_only_create_independent_optional_entries() {
        for kind in crate::templates::ids() {
            let fields = template(kind).unwrap();
            for field in fields {
                assert_eq!(
                    field.values.len(),
                    if field.type_name == "wifi-qr/v1" {
                        3
                    } else if matches!(field.type_name.as_str(), "photo/v1" | "file/v1") {
                        2
                    } else if field.type_name == "ssh/v1" {
                        0
                    } else {
                        1
                    }
                );
                assert!(field.source.is_none() && field.source_key.is_none());
                if !matches!(
                    field.type_name.as_str(),
                    "wifi-qr/v1" | "photo/v1" | "file/v1"
                ) {
                    assert!(field.values.values().all(String::is_empty));
                }
                assert!(field.data.as_ref().is_none_or(|data| data.is_empty()));
                assert!(!matches!(
                    field.type_name.as_str(),
                    "login/v1" | "api_key/v1"
                ));
            }
        }
        assert_eq!(template("login").unwrap().len(), 4);
        assert_eq!(template("api-key").unwrap().len(), 8);
        assert!(field("login/v1").is_err());
        assert!(field("api_key/v1").is_err());
    }
    #[test]
    fn identity_and_card_templates_keep_names_and_independent_fields() {
        for kind in ["identity", "credit-card"] {
            let mut fields = template(kind).unwrap();
            assert_eq!(fields.len(), 6);
            let last = fields.pop().unwrap();
            fields.swap(0, 1);
            fields.push(last);
            let names: Vec<_> = fields.iter().map(|field| field.name.clone()).collect();
            let mut record = Record::default();
            apply(&mut record, &fields).unwrap();
            assert_eq!(record.entries.len(), 6);
            let restored = read(&record).unwrap();
            assert_eq!(
                restored.iter().map(|field| &field.name).collect::<Vec<_>>(),
                names.iter().collect::<Vec<_>>()
            );
            if kind == "identity" {
                assert_eq!(restored[5].type_name, "photo/v1");
                assert!(restored[5].protected);
            } else {
                for index in [1, 3, 4] {
                    assert_eq!(restored[index].type_name, "secret/v1");
                    assert!(field_protected(&record.entries[index]));
                }
            }
            fields.remove(0);
            fields.push(field("note/v1").unwrap());
            apply(&mut record, &fields).unwrap();
            assert_eq!(record.entries.last().unwrap().type_name, "note/v1");
        }
    }
    #[test]
    fn legacy_parts_rename_reorder_and_keep_unknown_data_once() {
        let mut record = legacy();
        let mut fields = read(&record).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(count(&record), 3);
        assert_eq!(fields[0].opaque, 1);
        fields[0].name = "Same".into();
        fields[1].name = "Same".into();
        fields.swap(0, 1);
        fields.remove(2);
        let mut note = field("note/v1").unwrap();
        note.protected = true;
        note.values.insert("text".into(), "fixture note".into());
        fields.push(note);
        apply(&mut record, &fields).unwrap();
        assert_eq!(record.entries.len(), 3);
        assert_eq!(record.entries[0].type_name, "password/v1");
        assert_eq!(record.entries[1].type_name, "username/v1");
        assert_eq!(record.entries[0].name, record.entries[1].name);
        assert!(!record.entries[0].value.contains_key("username"));
        assert_eq!(
            record.entries[1].value["vendor"],
            Value::Binary(vec![3, 4, 5])
        );
        assert_eq!(record.entries[1].extra["vendor-meta"], Value::from("keep"));
        assert!(field_protected(&record.entries[2]));
        assert_eq!(record.extra["record-extra"], Value::from("keep"));
        assert!(
            read(&record)
                .unwrap()
                .iter()
                .all(|field| field.source_key.is_none())
        );
        for entry in &record.entries {
            entry.validate_value().unwrap();
        }
    }
    #[test]
    fn secure_notes_require_an_explicit_type_change_to_become_public() {
        let mut record = Record::default();
        let mut note = field("secure-note/v1").unwrap();
        note.values
            .insert("text".into(), "private note fixture".into());
        note.protected = false;
        apply(&mut record, &[note]).unwrap();
        assert_eq!(record.entries[0].type_name, "secure-note/v1");
        assert!(field_protected(&record.entries[0]));
        let mut draft = read(&record).unwrap();
        assert!(draft[0].protected);
        draft[0].type_name = "note/v1".into();
        draft[0].protected = false;
        apply(&mut record, &draft).unwrap();
        assert_eq!(record.entries[0].type_name, "note/v1");
        assert!(!field_protected(&record.entries[0]));
        draft = read(&record).unwrap();
        draft[0].protected = true;
        apply(&mut record, &draft).unwrap();
        assert_eq!(record.entries[0].type_name, "secure-note/v1");
    }
    #[test]
    fn protected_legacy_parts_remain_protected_after_reorder_and_save() {
        let mut record = legacy();
        record.entries[0].extra.insert(
            "metadata".into(),
            Value::Map(vec![
                ("protected".into(), true.into()),
                ("future".into(), "keep".into()),
            ]),
        );
        let mut fields = read(&record).unwrap();
        assert!(fields.iter().all(|field| field.protected));
        fields.reverse();
        apply(&mut record, &fields).unwrap();
        assert!(record.entries.iter().all(field_protected));
        assert!(read(&record).unwrap().iter().all(|field| field.protected));
    }
    #[test]
    fn removal_does_not_leave_a_hidden_copy_of_a_legacy_password() {
        let mut record = legacy();
        let mut fields = read(&record).unwrap();
        fields.remove(1);
        apply(&mut record, &fields).unwrap();
        assert!(
            !record
                .entries
                .iter()
                .any(|entry| entry.value.contains_key("password"))
        );
        assert_eq!(
            record
                .entries
                .iter()
                .filter(|entry| entry.value.contains_key("vendor"))
                .count(),
            1
        );
    }
    #[test]
    fn opaque_values_survive_and_duplicate_source_bindings_fail() {
        let mut record = legacy();
        record.entries[0]
            .value
            .insert("password".into(), Value::from("x".repeat(65537)));
        let mut fields = read(&record).unwrap();
        assert!(fields[1].values.is_empty() && fields[1].opaque == 1);
        fields[0].name = "Renamed".into();
        apply(&mut record, &fields).unwrap();
        assert_eq!(
            record.entries[1].value["password"].as_str().unwrap().len(),
            65537
        );
        let mut bad = legacy();
        let mut fields = read(&bad).unwrap();
        fields.push(fields[0].clone());
        assert!(matches!(apply(&mut bad, &fields), Err(Error::Input)));
        let mut malformed = legacy();
        malformed.entries[0]
            .value
            .insert("password".into(), Value::Binary(vec![9]));
        let fields = read(&malformed).unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields[0].values.is_empty() && fields[0].opaque > 0);
        apply(&mut malformed, &fields).unwrap();
        assert_eq!(
            malformed.entries[0].value["password"],
            Value::Binary(vec![9])
        );
    }
    #[test]
    fn card_fields_keep_opaque_values_and_checksum_does_not_block_save() {
        let mut field = field("card/v1").unwrap();
        field
            .values
            .insert("number".into(), "4111 1111 1111 1112".into());
        field.values.insert("cvv".into(), "123".into());
        let mut record = field_record(&field).unwrap();
        record.entries[0].validate_value().unwrap();
        record.entries[0]
            .value
            .insert("future".into(), Value::Binary(vec![7, 4]));
        let mut fields = read(&record).unwrap();
        assert_eq!(fields[0].opaque, 1);
        fields[0]
            .values
            .insert("holder".into(), "Public cardholder".into());
        apply(&mut record, &fields).unwrap();
        assert_eq!(record.entries[0].value["future"], Value::Binary(vec![7, 4]));
        assert_eq!(
            record.entries[0].value["number"].as_str(),
            Some("4111 1111 1111 1112")
        );
        assert_eq!(
            record.entries[0].value["holder"].as_str(),
            Some("Public cardholder")
        );
    }
    #[test]
    fn totp_fields_preserve_binary_seed_numeric_parameters_and_unknown_values() {
        let mut field = field("totp/v1").unwrap();
        field.data = Some(b"12345678901234567890".to_vec().into());
        field.values.insert("digits".into(), "8".into());
        let mut record = field_record(&field).unwrap();
        record.entries[0]
            .value
            .insert("future".into(), Value::Binary(vec![4, 2]));
        let mut fields = read(&record).unwrap();
        assert_eq!(fields[0].opaque, 1);
        assert_eq!(fields[0].values["digits"], "8");
        fields[0].name = "Renamed token".into();
        apply(&mut record, &fields).unwrap();
        assert_eq!(record.entries[0].value["digits"].as_u64(), Some(8));
        assert_eq!(record.entries[0].value["future"], Value::Binary(vec![4, 2]));
        let code = confidex_vault::totp::Totp::from_value(&record.entries[0].value)
            .unwrap()
            .generate(59)
            .unwrap();
        assert_eq!(code.as_str(), "94287082");
        fields[0].values.insert("period".into(), "0".into());
        assert!(field_record(&fields[0]).is_err());
    }
    #[test]
    fn calendar_fields_round_trip_components_and_keep_unknown_values() {
        for (kind, text) in [("date/v1", "29/02/2024"), ("month-year/v1", "02/2024")] {
            let mut field = field(kind).unwrap();
            field.values.insert("date".into(), text.into());
            let mut record = field_record(&field).unwrap();
            let value = &record.entries[0].value;
            assert_eq!(value["year"].as_u64(), Some(2024));
            assert_eq!(value["month"].as_u64(), Some(2));
            assert_eq!(value.contains_key("day"), kind == "date/v1");
            record.entries[0].validate_value().unwrap();
            record.entries[0]
                .value
                .insert("future".into(), Value::Binary(vec![4, 2]));
            record.entries[0]
                .value
                .insert("date".into(), Value::Binary(vec![7]));
            record.entries[0]
                .extra
                .insert("future-metadata".into(), Value::from("kept"));
            let mut fields = read(&record).unwrap();
            assert_eq!(fields[0].values["date"], text);
            assert_eq!(fields[0].opaque, 2);
            fields[0].name = "Renamed date".into();
            apply(&mut record, &fields).unwrap();
            assert_eq!(read(&record).unwrap()[0].values["date"], text);
            fields[0].values.insert("date".into(), "partial".into());
            assert!(field_record(&fields[0]).is_err());
            assert_eq!(read(&record).unwrap()[0].values["date"], text);
            fields[0].values.insert("date".into(), String::new());
            apply(&mut record, &fields).unwrap();
            assert!(!record.entries[0].value.contains_key("year"));
            assert_eq!(record.entries[0].value["future"], Value::Binary(vec![4, 2]));
            assert_eq!(record.entries[0].value["date"], Value::Binary(vec![7]));
            assert_eq!(
                record.entries[0].extra["future-metadata"].as_str(),
                Some("kept")
            );
            record.entries[0].validate_value().unwrap();
            record.entries[0]
                .value
                .insert("year".into(), Value::Binary(vec![1]));
            let mut broken = read(&record).unwrap();
            assert!(broken[0].values.is_empty() && broken[0].opaque > 0);
            broken[0].name = "Opaque date".into();
            apply(&mut record, &broken).unwrap();
            assert_eq!(record.entries[0].value["year"], Value::Binary(vec![1]));
        }
    }
    #[test]
    fn locations_keep_numeric_pairs_unknown_values_and_opaque_input() {
        let mut field = field("location/v1").unwrap();
        field.values.insert("name".into(), "Public place".into());
        field.values.insert("latitude".into(), "52,37".into());
        field.values.insert("longitude".into(), "4.90".into());
        let mut record = field_record(&field).unwrap();
        assert_eq!(record.entries[0].value["latitude"].as_f64(), Some(52.37));
        record.entries[0].validate_value().unwrap();
        record.entries[0]
            .value
            .insert("future".into(), Value::Binary(vec![8, 5]));
        record.entries[0]
            .value
            .insert("latitude".into(), Value::from(90));
        record.entries[0]
            .value
            .insert("longitude".into(), Value::from(-180));
        let mut fields = read(&record).unwrap();
        assert_eq!(fields[0].opaque, 1);
        fields[0].name = "Renamed location".into();
        apply(&mut record, &fields).unwrap();
        assert_eq!(record.entries[0].value["latitude"], Value::from(90));
        fields[0].values.insert("latitude".into(), "91".into());
        assert!(field_record(&fields[0]).is_err());
        fields[0].values.insert("latitude".into(), String::new());
        assert!(field_record(&fields[0]).is_err());
        fields[0].values.insert("longitude".into(), String::new());
        apply(&mut record, &fields).unwrap();
        assert!(!record.entries[0].value.contains_key("latitude"));
        assert_eq!(
            record.entries[0].value["name"].as_str(),
            Some("Public place")
        );
        assert_eq!(record.entries[0].value["future"], Value::Binary(vec![8, 5]));
        record.entries[0]
            .value
            .insert("name".into(), Value::from("x".repeat(65537)));
        let large = read(&record).unwrap();
        assert!(large[0].values.is_empty());
        apply(&mut record, &large).unwrap();
        assert_eq!(
            record.entries[0].value["name"].as_str().unwrap().len(),
            65537
        );
        record.entries[0]
            .value
            .insert("latitude".into(), Value::Binary(vec![6]));
        let opaque = read(&record).unwrap();
        assert!(opaque[0].values.is_empty() && opaque[0].opaque > 0);
        apply(&mut record, &opaque).unwrap();
        assert_eq!(record.entries[0].value["latitude"], Value::Binary(vec![6]));
    }
}
