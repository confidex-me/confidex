//! Plain Bitwarden JSON mapping is shared by the JSON, ZIP and encrypted adapters.
use super::super::{
    Code, Context, Diagnostic, Error, ErrorKind, Item, Location, Phase, Reservation, Source,
    Status, json, protected_original,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use confidex_vault::{
    record::{Entry, Mapping, Record, Value},
    ssh,
};
use serde::Serialize;
use serde_json::{Value as Json, value::RawValue};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};
mod fields;
pub(crate) mod writer;
use crate::import::totp;
pub use writer::{Profile, Writer};

struct Group {
    name: Zeroizing<String>,
    organization: Option<Zeroizing<String>>,
    _memory: Reservation,
}
struct Groups(BTreeMap<String, Group>);
struct Seen(BTreeSet<[u8; 32]>);
impl Drop for Seen {
    fn drop(&mut self) {
        for mut digest in std::mem::take(&mut self.0) {
            digest.zeroize();
        }
    }
}
impl Drop for Groups {
    fn drop(&mut self) {
        for (mut key, _) in std::mem::take(&mut self.0) {
            key.zeroize();
        }
    }
}
#[derive(Serialize)]
#[serde(untagged)]
enum Fragment<'a> {
    Value(&'a Json),
    Matches(Vec<&'a Json>),
}

pub fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    parse_with(
        input,
        context,
        Mapping::new(),
        &mut |_, _, _| Ok(Vec::new()),
    )
}

/// ZIP adapters add files before validation and share the same JSON semantics.
/// Extra container attributes must not use the reserved Bitwarden document key.
/// Return file reservations so they remain charged until the item is encoded.
pub fn parse_with(
    input: &[u8],
    context: &mut Context<'_>,
    extra: Mapping,
    extend: &mut impl FnMut(&Json, &mut Item, &mut Context<'_>) -> Result<Vec<Reservation>, Error>,
) -> Result<(), Error> {
    let mut container = Record {
        entries: Vec::new(),
        tags: Vec::new(),
        extra,
    };
    if container.extra.contains_key("bitwarden.document.json") {
        return Err(ErrorKind::InvalidOptions.into());
    }
    let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
    let document = json::Document::parse(input, context)?;
    let root = json::object(document.raw(), context)?;
    match root.get("encrypted").map(RawValue::get) {
        Some("false") => (),
        Some("true") => return Err(ErrorKind::UnsupportedFormat.into()),
        _ => return Err(ErrorKind::Malformed.into()),
    }
    let organization = root.get("collections").is_some();
    if organization && root.get("folders").is_some() {
        return Err(ErrorKind::AmbiguousFormat.into());
    }
    let mut review_container = root
        .iter()
        .any(|(key, _)| !matches!(key, "encrypted" | "items" | "folders" | "collections"));
    let mut groups = Groups(BTreeMap::new());
    if let Some(raw) = root.get(if organization {
        "collections"
    } else {
        "folders"
    }) {
        for group in json::array(raw)? {
            if groups.0.len() >= context.limits.records {
                return Err(ErrorKind::Limit.into());
            }
            let raw = group?;
            let value = json::owned(raw, context)?;
            let object = value.as_object().ok_or(ErrorKind::Malformed)?;
            review_container |= object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "id" | "name" | "organizationId" | "externalId"
                )
            }) || object
                .get("externalId")
                .is_some_and(|value| !value.is_null());
            let id = identifier(&value, "id")?.ok_or(ErrorKind::Malformed)?;
            let name = value
                .get("name")
                .and_then(Json::as_str)
                .ok_or(ErrorKind::Malformed)?;
            if id.len() > context.limits.name_bytes || name.len() > context.limits.name_bytes {
                return Err(ErrorKind::Limit.into());
            }
            if groups.0.contains_key(id) {
                return Err(ErrorKind::AmbiguousFormat.into());
            }
            let org = identifier(&value, "organizationId")?;
            let memory = context
                .memory()
                .reserve(id.len() + name.len() + org.map_or(0, str::len) + 256)?;
            groups.0.insert(
                id.into(),
                Group {
                    name: Zeroizing::new(name.into()),
                    organization: org.map(|s| Zeroizing::new(s.into())),
                    _memory: memory,
                },
            );
        }
    }
    let members: BTreeMap<_, _> = root.iter().filter(|(key, _)| *key != "items").collect();
    let bytes = members
        .iter()
        .try_fold(2usize, |total, (key, raw)| {
            total
                .checked_add(raw.get().len())?
                .checked_add(key.len().checked_mul(6)?.checked_add(8)?)
        })
        .ok_or(ErrorKind::Limit)?;
    {
        let _memory = context.reserve_work(bytes, members.len())?;
        let mut text =
            Zeroizing::new(serde_json::to_string(&members).map_err(|_| ErrorKind::Malformed)?);
        container.extra.insert(
            "bitwarden.document.json".into(),
            std::mem::take(&mut *text).into(),
        );
        context.set_container_attributes(std::mem::take(&mut container.extra))?;
    }
    if review_container {
        context.container_diagnostic(
            Status::Review,
            Diagnostic {
                code: Code::SourceDataPreserved,
                location: Location::default(),
            },
        )?;
    }
    let items = root.get("items").ok_or(ErrorKind::Malformed)?;
    let _seen_memory = context.memory().reserve(context.limits.records * 96)?;
    let mut seen = Seen(BTreeSet::new());
    for (index, raw) in json::array(items)?.enumerate() {
        if index >= context.limits.records {
            return Err(ErrorKind::Limit.into());
        }
        context.checkpoint(Phase::Map, index, context.limits.records)?;
        let raw = raw?;
        let owned = json::owned(raw, context)?;
        let _memory = context.reserve_work(raw.get().len(), context.limits.fields)?;
        let mut item =
            mapped(raw, &owned, &groups, organization, index, context).map_err(|error| {
                error.at(Location {
                    item: Some(index),
                    ..error.location
                })
            })?;
        let _attachments = extend(&owned, &mut item, context)?;
        if let (Some(vault), Some(id)) = (&item.source.vault, &item.source.item) {
            let mut hash = Sha256::new();
            hash.update((vault.len() as u64).to_be_bytes());
            hash.update(vault.as_bytes());
            hash.update(id.as_bytes());
            if !seen.0.insert(hash.finalize().into()) {
                return Err(Error::from(ErrorKind::AmbiguousFormat).at(Location {
                    item: Some(index),
                    ..Location::default()
                }));
            }
        }
        context.push(item)?;
    }
    Ok(())
}

fn identifier<'a>(value: &'a Json, key: &str) -> Result<Option<&'a str>, Error> {
    match value.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(text)) if !text.is_empty() => Ok(Some(text)),
        _ => Err(ErrorKind::Malformed.into()),
    }
}
fn core(value: &Json) -> Value {
    match value {
        Json::Null => Value::Nil,
        Json::Bool(value) => (*value).into(),
        Json::String(value) => value.as_str().into(),
        Json::Number(value) => value
            .as_i64()
            .map(Value::from)
            .or_else(|| value.as_u64().map(Value::from))
            .unwrap_or_else(|| Value::F64(value.as_f64().unwrap())),
        Json::Array(values) => Value::Array(values.iter().map(core).collect()),
        Json::Object(values) => Value::Map(
            values
                .iter()
                .map(|(key, value)| (key.as_str().into(), core(value)))
                .collect(),
        ),
    }
}
fn scalar(name: &str, kind: &str, key: &str, text: &str) -> Entry {
    Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), text.into())]),
        extra: Mapping::new(),
    }
}
fn diagnostic(code: Code, index: usize) -> Diagnostic {
    Diagnostic {
        code,
        location: Location {
            item: Some(index),
            ..Location::default()
        },
    }
}

fn mapped(
    raw: &RawValue,
    input: &Json,
    groups: &Groups,
    organization: bool,
    index: usize,
    context: &mut Context<'_>,
) -> Result<Item, Error> {
    let object = input.as_object().ok_or(ErrorKind::Malformed)?;
    for key in ["id", "organizationId", "folderId"] {
        if identifier(input, key)?.is_some_and(|id| id.len() > context.limits.name_bytes) {
            return Err(ErrorKind::Limit.into());
        }
    }
    if let Some(ids) = input.get("collectionIds").and_then(Json::as_array)
        && (ids.len() > context.limits.fields
            || ids.iter().any(|id| {
                id.as_str()
                    .is_some_and(|id| id.len() > context.limits.name_bytes)
            }))
    {
        return Err(ErrorKind::Limit.into());
    }
    let org = identifier(input, "organizationId")?;
    if org.is_some() != organization {
        return Err(ErrorKind::AmbiguousFormat.into());
    }
    let mut source = Source::default();
    source.locator = index;
    source.vault = Some(org.unwrap_or("personal").into());
    source.item = identifier(input, "id")?.map(String::from);
    let mut item = Item {
        source,
        record: Record {
            entries: Vec::new(),
            tags: Vec::new(),
            extra: Mapping::new(),
        },
        source_attributes: Mapping::new(),
        status: Status::Ready,
        diagnostics: Vec::new(),
    };
    let kind = input.get("type").and_then(Json::as_u64);
    let name = input
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or("Imported item");
    item.record
        .extra
        .insert("confidex.title".into(), name.into());
    for key in [
        "id",
        "organizationId",
        "folderId",
        "collectionIds",
        "type",
        "name",
        "favorite",
        "reprompt",
        "creationDate",
        "revisionDate",
        "deletedDate",
        "archivedDate",
    ] {
        if let Some(value) = input.get(key) {
            item.source_attributes.insert(key.into(), core(value));
        }
    }
    let mut fallback = input.get("name").is_some_and(|v| !v.is_string());
    fallback |= [
        "creationDate",
        "revisionDate",
        "deletedDate",
        "archivedDate",
    ]
    .iter()
    .any(|key| {
        input
            .get(key)
            .is_some_and(|v| !v.is_null() && !v.is_string())
    });
    fallback |= input.get("favorite").is_some_and(|v| !v.is_boolean());
    fallback |= input.get("reprompt").is_some_and(|v| v.as_u64().is_none());
    for (expected, key) in [
        (1, "login"),
        (2, "secureNote"),
        (3, "card"),
        (4, "identity"),
        (5, "sshKey"),
    ] {
        if kind != Some(expected)
            && let Some(value) = input.get(key)
        {
            item.source_attributes.insert(key.into(), core(value));
            fallback |= !value.is_null();
        }
    }
    let mut remaining = BTreeMap::<&str, Fragment<'_>>::new();
    fallback |= object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "id" | "organizationId"
                | "folderId"
                | "collectionIds"
                | "type"
                | "name"
                | "favorite"
                | "reprompt"
                | "creationDate"
                | "revisionDate"
                | "deletedDate"
                | "archivedDate"
                | "login"
                | "secureNote"
                | "card"
                | "identity"
                | "sshKey"
                | "fields"
                | "notes"
                | "passwordHistory"
        )
    });
    if !matches!(kind, Some(1..=5)) {
        item.record
            .entries
            .push(protected_original("Original data", raw.get()));
        item.status = Status::Review;
        item.diagnostics
            .push(diagnostic(Code::UnknownItemPreserved, index));
        groups_for(input, org, groups, &mut item, index)?;
        excluded(input, &mut item, context, index);
        return Ok(item);
    }
    match kind.unwrap() {
        1 => login(
            input,
            &mut item,
            &mut remaining,
            &mut fallback,
            index,
            context,
        )?,
        2 => {
            if let Some(note) = input.get("secureNote") {
                item.source_attributes
                    .insert("secureNote".into(), core(note));
                fallback |= note.as_object().is_none_or(|o| {
                    o.len() != 1 || o.get("type").and_then(Json::as_u64) != Some(0)
                });
            }
        }
        3 | 4 => {
            let group = if kind == Some(3) { "card" } else { "identity" };
            if let Some(value) = input.get(group) {
                item.source_attributes.insert(group.into(), core(value));
                fallback |= !fields::personal(kind.unwrap(), value, &mut item.record.entries);
            }
        }
        5 => {
            if let Some(value) = input.get("sshKey") {
                let private = value.get("privateKey").and_then(Json::as_str);
                let budget = ssh::REQUIRED_MEMORY;
                let _memory = context.memory().reserve(ssh::REQUIRED_MEMORY)?;
                if let Some(key) =
                    private.and_then(|pem| ssh::Key::import(pem.as_bytes(), None, budget).ok())
                {
                    item.record.entries.push(Entry {
                        name: "SSH key".into(),
                        type_name: "ssh/v1".into(),
                        value: key.to_value().map_err(|_| ErrorKind::InvalidRecord)?,
                        extra: Mapping::new(),
                    });
                    for slot in ["publicKey", "keyFingerprint"] {
                        if let Some(value) = value.get(slot) {
                            item.source_attributes
                                .insert(format!("sshKey.{slot}"), core(value));
                            fallback |= value.as_str().is_none_or(|text| {
                                !text.is_empty()
                                    && if slot == "publicKey" {
                                        !public_matches(&key, text)
                                    } else {
                                        text != key.fingerprint()
                                    }
                            });
                        }
                    }
                    fallback |= value.as_object().is_none_or(|o| {
                        o.keys().any(|k| {
                            !matches!(k.as_str(), "privateKey" | "publicKey" | "keyFingerprint")
                        }) || o.values().any(|v| !v.is_string())
                    });
                } else {
                    fallback = true;
                }
            }
        }
        _ => unreachable!(),
    }
    if let Some(notes) = input.get("notes") {
        if let Some(text) = notes.as_str() {
            item.record.entries.push(protected_original("Notes", text));
            if kind != Some(2) {
                item.diagnostics
                    .push(diagnostic(Code::NotesProtectedByDefault, index));
            }
        } else if notes.is_null() {
            item.source_attributes.insert("notes".into(), Value::Nil);
        } else {
            fallback = true;
        }
    }
    if let Some(fields) = input.get("fields") {
        if let Some(fields) = fields.as_array() {
            if fields.len() > context.limits.fields {
                return Err(ErrorKind::Limit.into());
            }
            for (field, value) in fields.iter().enumerate() {
                context.checkpoint(Phase::Map, field, fields.len())?;
                if let Some(entry) = fields::custom(value) {
                    item.record.entries.push(entry);
                } else {
                    fallback = true;
                }
            }
        } else if fields.is_null() {
            item.source_attributes.insert("fields".into(), Value::Nil);
        } else {
            fallback = true;
        }
    }
    if let Some(history) = input.get("passwordHistory") {
        match history.as_array() {
            Some(values) if values.is_empty() => {
                item.source_attributes
                    .insert("passwordHistory".into(), Value::Array(Vec::new()));
            }
            Some(values) => {
                fallback |= values.iter().any(|v| {
                    v.as_object().is_none_or(|o| {
                        o.iter().any(|(k, v)| {
                            !matches!(k.as_str(), "password" | "lastUsedDate")
                                || !(v.is_null() || v.is_string())
                        })
                    })
                });
                remaining.insert("passwordHistory", Fragment::Value(history));
            }
            None if history.is_null() => {
                item.source_attributes
                    .insert("passwordHistory".into(), Value::Nil);
            }
            None => fallback = true,
        }
    }
    if input
        .get("favorite")
        .is_some_and(|value| value != &Json::Bool(false))
        || input
            .get("reprompt")
            .is_some_and(|value| value.as_u64() != Some(0))
    {
        for key in ["favorite", "reprompt"] {
            if let Some(value) = input.get(key) {
                remaining.insert(key, Fragment::Value(value));
            }
        }
    }
    groups_for(input, org, groups, &mut item, index)?;
    fallback |= item.status == Status::Blocked;
    if fallback || !remaining.is_empty() {
        let text = if fallback {
            Zeroizing::new(raw.get().to_owned())
        } else {
            Zeroizing::new(serde_json::to_string(&remaining).map_err(|_| ErrorKind::Malformed)?)
        };
        item.record
            .entries
            .push(protected_original("Original data", &text));
        if item.status == Status::Ready {
            item.status = Status::Review;
        }
        item.diagnostics
            .insert(0, diagnostic(Code::SourceDataPreserved, index));
    }
    excluded(input, &mut item, context, index);
    Ok(item)
}

fn public_matches(key: &ssh::Key, text: &str) -> bool {
    let Ok(blob) = key.public_blob() else {
        return false;
    };
    let Some(length) = blob
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
    else {
        return false;
    };
    let Some(algorithm) = blob
        .get(4..4 + length as usize)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return false;
    };
    let mut parts = text.split_whitespace();
    parts.next() == Some(algorithm) && parts.next() == Some(BASE64_STANDARD.encode(blob).as_str())
}

fn login<'a>(
    input: &'a Json,
    item: &mut Item,
    remaining: &mut BTreeMap<&'a str, Fragment<'a>>,
    fallback: &mut bool,
    index: usize,
    context: &mut Context<'_>,
) -> Result<(), Error> {
    let Some(login) = input.get("login") else {
        return Ok(());
    };
    let Some(object) = login.as_object() else {
        *fallback = true;
        return Ok(());
    };
    *fallback |= object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "username" | "password" | "uris" | "totp" | "fido2Credentials"
        )
    });
    for (key, label, kind) in [
        ("username", "Username", "username/v1"),
        ("password", "Password", "password/v1"),
    ] {
        if let Some(value) = login.get(key) {
            if let Some(text) = value.as_str() {
                item.record.entries.push(scalar(label, kind, key, text));
            } else if value.is_null() {
                item.source_attributes
                    .insert(format!("login.{key}"), Value::Nil);
            } else {
                *fallback = true;
            }
        }
    }
    if let Some(uris) = login.get("uris") {
        item.source_attributes
            .insert("login.uris".into(), core(uris));
        if let Some(uris) = uris.as_array() {
            if uris.len() > context.limits.fields {
                return Err(ErrorKind::Limit.into());
            }
            let mut matches = Vec::new();
            for (field, uri) in uris.iter().enumerate() {
                context.checkpoint(Phase::Map, field, uris.len())?;
                let Some(object) = uri.as_object() else {
                    *fallback = true;
                    continue;
                };
                *fallback |= object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "uri" | "match"));
                if let Some(value) = uri.get("uri") {
                    if let Some(text) = value.as_str() {
                        item.record
                            .entries
                            .push(scalar("URL", "url/v1", "url", text));
                    } else if !value.is_null() {
                        *fallback = true;
                    }
                }
                if uri
                    .get("match")
                    .is_some_and(|v| !v.is_null() && v.as_u64().is_none_or(|n| n > 5))
                {
                    *fallback = true;
                }
                matches.push(uri.get("match").unwrap_or(&Json::Null));
            }
            if matches.iter().any(|value| !value.is_null()) {
                remaining.insert("uriMatch", Fragment::Matches(matches));
            }
        } else if !uris.is_null() {
            *fallback = true;
        }
    }
    if let Some(value) = login.get("totp") {
        if let Some(text) = value.as_str().filter(|text| !text.is_empty()) {
            if let Some(entry) = totp::entry(text) {
                item.record.entries.push(entry);
            } else {
                *fallback = true;
            }
        } else if value.is_null() || value.as_str() == Some("") {
            item.source_attributes
                .insert("login.totp".into(), core(value));
        } else {
            *fallback = true;
        }
    }
    if let Some(value) = login.get("fido2Credentials") {
        if value.is_null() || value.as_array().is_some_and(Vec::is_empty) {
            item.source_attributes
                .insert("login.fido2Credentials".into(), core(value));
        } else {
            *fallback = true;
        }
    }
    let _ = index;
    Ok(())
}

fn groups_for(
    input: &Json,
    org: Option<&str>,
    groups: &Groups,
    item: &mut Item,
    index: usize,
) -> Result<(), Error> {
    let mut ids = Vec::new();
    if let Some(id) = identifier(input, "folderId")? {
        ids.push(id);
    }
    if let Some(value) = input.get("collectionIds").filter(|v| !v.is_null()) {
        let values = value.as_array().ok_or(ErrorKind::Malformed)?;
        for value in values {
            ids.push(
                value
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(ErrorKind::Malformed)?,
            );
        }
    }
    for id in ids {
        if let Some(group) = groups.0.get(id).filter(|g| {
            g.organization
                .as_deref()
                .map(String::as_str)
                .is_none_or(|id| Some(id) == org)
        }) {
            if !item
                .record
                .tags
                .iter()
                .any(|tag| tag == group.name.as_str())
            {
                item.record.tags.push(group.name.to_string());
            }
        } else {
            item.status = Status::Blocked;
            item.diagnostics
                .push(diagnostic(Code::UnresolvedFieldReference, index));
        }
    }
    Ok(())
}
fn excluded(input: &Json, item: &mut Item, context: &Context<'_>, index: usize) {
    for (key, include, code) in [
        (
            "deletedDate",
            context.options.include_deleted,
            Code::RecycleBinExcludedByDefault,
        ),
        (
            "archivedDate",
            context.options.include_archived,
            Code::ArchivedExcludedByDefault,
        ),
    ] {
        if !include
            && input
                .get(key)
                .and_then(Json::as_str)
                .is_some_and(|value| !value.is_empty())
        {
            item.status = Status::Excluded;
            item.diagnostics.push(diagnostic(code, index));
        }
    }
}
