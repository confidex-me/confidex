use confidex_vault::record::{Entry, Mapping, Value};
use serde_json::Value as Json;

fn entry(name: &str, kind: &str, key: &str, value: &str, protected: bool) -> Entry {
    let extra = if protected {
        Mapping::from([(
            "metadata".into(),
            Value::Map(vec![("protected".into(), true.into())]),
        )])
    } else {
        Mapping::new()
    };
    Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), value.into())]),
        extra,
    }
}
fn guarded(field: &Json) -> Option<bool> {
    match field.get("guarded") {
        None => Some(false),
        Some(v) => v.as_bool(),
    }
}
pub(super) fn login(field: &Json) -> Option<Entry> {
    let object = field.as_object()?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "name" | "id" | "value" | "fieldType" | "type" | "designation" | "guarded"
        )
    }) {
        return None;
    }
    let value = field.get("value")?.as_str()?;
    let field_type = match (field.get("fieldType"), field.get("type")) {
        (Some(a), Some(b)) if a == b => a.as_str()?,
        (Some(a), None) | (None, Some(a)) => a.as_str()?,
        _ => return None,
    };
    let designation = match field.get("designation") {
        None | Some(Json::Null) => None,
        Some(v) => Some(v.as_str()?),
    };
    let protected = guarded(field)?;
    let (kind, key) = if field_type == "P" || designation == Some("password") {
        ("password/v1", "password")
    } else if designation == Some("username") {
        ("username/v1", "username")
    } else {
        match field_type {
            "T" | "E" | "N" | "TEL" | "C" => ("text/v1", "text"),
            "U" => ("url/v1", "url"),
            "A" => ("secure-note/v1", "text"),
            _ => return None,
        }
    };
    if designation.is_some_and(|v| !matches!(v, "username" | "password")) {
        return None;
    }
    let name = match field.get("name") {
        Some(Json::String(name)) => name,
        None | Some(Json::Null) => designation
            .or_else(|| {
                field
                    .get("id")
                    .and_then(Json::as_str)
                    .filter(|id| !id.is_empty())
            })
            .unwrap_or(match key {
                "password" => "password",
                "url" => "URL",
                _ => "Text",
            }),
        _ => return None,
    };
    Some(entry(name, kind, key, value, protected))
}
pub(super) fn url(value: &Json) -> Option<Entry> {
    let object = value.as_object()?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "label" | "url" | "guarded" | "mode"))
        || object
            .get("mode")
            .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return None;
    }
    Some(entry(
        match value.get("label") {
            None | Some(Json::Null) => "URL",
            Some(value) => value.as_str()?,
        },
        "url/v1",
        "url",
        value.get("url")?.as_str()?,
        guarded(value)?,
    ))
}
fn optional_text(value: &Json, key: &str) -> Option<Value> {
    match value.get(key) {
        None | Some(Json::Null) => Some(Value::Nil),
        Some(v) => Some(v.as_str()?.into()),
    }
}
pub(super) fn section(field: &Json, section: &Json) -> Option<Entry> {
    let object = field.as_object()?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "title"
                | "id"
                | "value"
                | "guarded"
                | "indexAtSource"
                | "multiline"
                | "dontGenerate"
                | "inputTraits"
                | "placeholder"
                | "clipboardFilter"
        )
    }) {
        return None;
    }
    if field.get("inputTraits").is_some_and(|v| {
        v.as_object().is_none_or(|o| {
            o.iter().any(|(k, v)| {
                !matches!(k.as_str(), "keyboard" | "correction" | "capitalization")
                    || !v.is_string()
            })
        })
    }) {
        return None;
    }
    if field
        .get("clipboardFilter")
        .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return None;
    }
    let name = field.get("title")?.as_str()?;
    let protected = guarded(field)?;
    let value = field.get("value")?.as_object()?;
    let mut active = value.iter().filter(|(_, value)| !value.is_null());
    let (kind, value) = active.next()?;
    if active.next().is_some() {
        return None;
    }
    let multiline = match field.get("multiline") {
        None => false,
        Some(v) => v.as_bool()?,
    };
    let mut result = if kind == "file" {
        let (filename, _, _) = document(value)?;
        let mut result = entry(name, "file/v1", "filename", filename, false);
        result
            .value
            .insert("data".into(), Value::Binary(Vec::new()));
        result
    } else if kind == "totp" {
        otp(name, value.as_str()?)?
    } else if matches!(
        kind.as_str(),
        "date" | "monthYear" | "email" | "address" | "sshKey"
    ) {
        typed(name, kind, value, protected)?
    } else {
        let text = value.as_str()?;
        let (target, key) = match kind.as_str() {
            "concealed" if multiline => ("secure-note/v1", "text"),
            "concealed" | "creditCardNumber" => ("secret/v1", "secret"),
            "url" => ("url/v1", "url"),
            "string" if multiline => ("secure-note/v1", "text"),
            "string" | "phone" | "menu" | "gender" | "creditCardType" => ("text/v1", "text"),
            _ => return None,
        };
        entry(
            name,
            target,
            key,
            text,
            protected || matches!(kind.as_str(), "concealed" | "creditCardNumber"),
        )
    };
    if protected {
        result.extra.insert(
            "metadata".into(),
            Value::Map(vec![("protected".into(), true.into())]),
        );
    }
    result.extra.insert(
        "confidex.import.section".into(),
        Value::Map(vec![
            ("name".into(), optional_text(section, "name")?),
            ("title".into(), optional_text(section, "title")?),
            ("field_id".into(), optional_text(field, "id")?),
        ]),
    );
    Some(result)
}

fn typed(name: &str, kind: &str, value: &Json, protected: bool) -> Option<Entry> {
    match kind {
        "date" | "monthYear" => {
            use confidex_vault::date::{Civil, Precision, read};
            let (civil, precision, type_name) = if kind == "date" {
                let date = time::OffsetDateTime::from_unix_timestamp(value.as_i64()?)
                    .ok()?
                    .date();
                (
                    Civil {
                        year: date.year().try_into().ok()?,
                        month: date.month() as u8,
                        day: Some(date.day()),
                    },
                    Precision::Day,
                    "date/v1",
                )
            } else {
                let number = value.as_u64()?;
                (
                    Civil {
                        year: (number / 100).try_into().ok()?,
                        month: (number % 100).try_into().ok()?,
                        day: None,
                    },
                    Precision::Month,
                    "month-year/v1",
                )
            };
            let mut result = entry(name, type_name, "", "", protected);
            result.value = civil.value();
            read(&result.value, precision).ok()?;
            Some(result)
        }
        "email" => {
            let object = value.as_object()?;
            if object
                .keys()
                .any(|k| !matches!(k.as_str(), "email_address" | "provider"))
                || object
                    .get("provider")
                    .is_some_and(|p| !p.is_null() && !p.is_string())
            {
                return None;
            }
            Some(entry(
                name,
                "text/v1",
                "text",
                object.get("email_address")?.as_str()?,
                protected,
            ))
        }
        "address" => {
            let keys = ["street", "city", "state", "zip", "country"];
            let object = value.as_object()?;
            if object
                .iter()
                .any(|(k, v)| !keys.contains(&k.as_str()) || !v.is_string())
            {
                return None;
            }
            let mut text = zeroize::Zeroizing::new(String::new());
            for key in keys {
                if let Some(value) = object
                    .get(key)
                    .and_then(Json::as_str)
                    .filter(|v| !v.is_empty())
                {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(key);
                    text.push_str(": ");
                    text.push_str(value);
                }
            }
            Some(entry(name, "note/v1", "text", &text, protected))
        }
        "sshKey" => {
            let object = value.as_object()?;
            if object
                .keys()
                .any(|k| !matches!(k.as_str(), "privateKey" | "metadata"))
            {
                return None;
            }
            let private = object.get("privateKey")?.as_str()?;
            let key = confidex_vault::ssh::Key::import(
                private.as_bytes(),
                None,
                confidex_vault::ssh::REQUIRED_MEMORY,
            )
            .ok()?;
            if let Some(metadata) = object.get("metadata").filter(|v| !v.is_null()) {
                let metadata = metadata.as_object()?;
                if metadata.iter().any(|(k, v)| {
                    !matches!(
                        k.as_str(),
                        "privateKey" | "publicKey" | "fingerprint" | "keyType"
                    ) || !v.is_string()
                }) {
                    return None;
                }
                if metadata
                    .get("privateKey")
                    .is_some_and(|v| v.as_str() != Some(private))
                {
                    return None;
                }
                if let Some(public) = metadata
                    .get("publicKey")
                    .and_then(Json::as_str)
                    .filter(|p| !p.is_empty())
                {
                    if public.split_whitespace().take(2).collect::<Vec<_>>()
                        != key
                            .public_text()
                            .ok()?
                            .split_whitespace()
                            .take(2)
                            .collect::<Vec<_>>()
                    {
                        return None;
                    }
                }
            }
            let mut result = entry(name, "ssh/v1", "", "", true);
            result.value = key.to_value().ok()?;
            Some(result)
        }
        _ => None,
    }
}
fn otp(name: &str, input: &str) -> Option<Entry> {
    let mut entry = crate::import::totp::entry(input)?;
    entry.name = name.into();
    Some(entry)
}

pub(super) fn document(value: &Json) -> Option<(&str, &str, u64)> {
    Some((
        value.get("fileName")?.as_str()?,
        value.get("documentId")?.as_str()?,
        value.get("decryptedSize")?.as_u64()?,
    ))
}
