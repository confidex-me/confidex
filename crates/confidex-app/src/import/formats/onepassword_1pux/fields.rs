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
    let name = field.get("name")?.as_str()?;
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
    Some(entry(name, kind, key, value, protected))
}
pub(super) fn url(value: &Json) -> Option<Entry> {
    let object = value.as_object()?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "label" | "url" | "guarded"))
    {
        return None;
    }
    Some(entry(
        value.get("label")?.as_str()?,
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
        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
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
