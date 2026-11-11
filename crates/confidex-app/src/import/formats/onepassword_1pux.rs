//! 1PUX v3 data is mapped locally; source facts remain encrypted provenance.
use super::super::{
    Code, Context, Diagnostic, Error, ErrorKind, Item, Location, Phase, Reservation, Source,
    Status, archive::Archive, json, protected_original,
};
use confidex_vault::record::{Entry, Mapping, Record, Value};
use serde_json::{Value as Json, value::RawValue};
use zeroize::Zeroizing;
mod fields;
mod raw;
mod writer;
pub use writer::Writer;

pub fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    let mut archive = Archive::open(input, context)?;
    let attrs_index = archive
        .index("export.attributes")
        .ok_or(ErrorKind::UnsupportedFormat)?;
    let data_index = archive
        .index("export.data")
        .ok_or(ErrorKind::UnsupportedFormat)?;
    let attributes = archive.read(attrs_index, context)?;
    let attributes_doc = json::Document::parse(&attributes, context)?;
    let attrs = json::object(attributes_doc.raw(), context)?;
    let version = serde_json::from_str::<u64>(raw::required(&attrs, "version")?.get())
        .map_err(|_| ErrorKind::Malformed)?;
    if version != 3 {
        return Err(ErrorKind::UnsupportedVersion.into());
    }
    if attrs
        .iter()
        .any(|(key, _)| !matches!(key, "version" | "description" | "createdAt" | "timestamp"))
    {
        container_review(context, Code::SourceDataPreserved, None)?;
    }
    drop(attrs);
    let data = archive.read(data_index, context)?;
    let document = json::Document::parse(&data, context)?;
    let root = json::object(document.raw(), context)?;
    let accounts = raw::required(&root, "accounts")?;
    let mut container = Record::default();
    container.extra.insert("schema".into(), 1u64.into());
    container
        .extra
        .insert("export_attributes".into(), raw::value(attributes_doc.raw()));
    container.extra.insert(
        "export_data".into(),
        raw::without(document.raw(), "accounts", context)?,
    );
    container
        .extra
        .insert("accounts".into(), Value::Array(Vec::new()));
    if root.iter().any(|(key, _)| key != "accounts") {
        container_review(context, Code::SourceDataPreserved, None)?;
    }
    let _catalog = context.memory().reserve(
        archive.len() * (std::mem::size_of::<bool>() + std::mem::size_of::<Reservation>()),
    )?;
    let mut used = vec![false; archive.len()];
    used[attrs_index] = true;
    used[data_index] = true;
    let mut locator = 0;
    for account_raw in json::array(accounts)? {
        let account_raw = account_raw?;
        let account = json::object(account_raw, context)?;
        let account_attrs = json::object(raw::required(&account, "attrs")?, context)?;
        let account_id = raw::id(&account_attrs, "uuid", context)?;
        if account_attrs.iter().any(|(key, _)| {
            !matches!(
                key,
                "uuid" | "accountName" | "name" | "avatar" | "email" | "domain"
            )
        }) {
            container_review(context, Code::SourceDataPreserved, None)?;
        }
        drop(account_attrs);
        let mut account_meta = Record::default();
        account_meta.extra.insert(
            "source".into(),
            raw::without(account_raw, "vaults", context)?,
        );
        account_meta
            .extra
            .insert("vaults".into(), Value::Array(Vec::new()));
        if account
            .iter()
            .any(|(key, _)| !matches!(key, "attrs" | "vaults"))
        {
            container_review(context, Code::SourceDataPreserved, None)?;
        }
        for vault_raw in json::array(raw::required(&account, "vaults")?)? {
            let vault_raw = vault_raw?;
            let vault = json::object(vault_raw, context)?;
            let vault_attrs = json::object(raw::required(&vault, "attrs")?, context)?;
            let vault_id = raw::id(&vault_attrs, "uuid", context)?;
            if vault_attrs
                .iter()
                .any(|(key, _)| !matches!(key, "uuid" | "name" | "desc" | "avatar" | "type"))
            {
                container_review(context, Code::SourceDataPreserved, None)?;
            }
            drop(vault_attrs);
            if vault
                .iter()
                .any(|(key, _)| !matches!(key, "attrs" | "items"))
            {
                container_review(context, Code::SourceDataPreserved, None)?;
            }
            for item_raw in json::array(raw::required(&vault, "items")?)? {
                if locator >= context.limits.records {
                    return Err(ErrorKind::Limit.into());
                }
                context.checkpoint(Phase::Map, locator, context.limits.records)?;
                let item_raw = item_raw?;
                let owned = json::owned(item_raw, context)?;
                let mut source = Source::default();
                source.account = Some(account_id.to_string());
                source.vault = Some(vault_id.to_string());
                source.locator = locator;
                let (item, _mapping_memory) =
                    map_item(item_raw, &owned, source, &mut archive, &mut used, context)?;
                context.push(item)?;
                locator += 1;
            }
            push_array(
                &mut account_meta,
                "vaults",
                raw::without(vault_raw, "items", context)?,
            );
        }
        let account_value = Value::Map(
            std::mem::take(&mut account_meta.extra)
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        );
        push_array(&mut container, "accounts", account_value);
    }
    container
        .extra
        .insert("unmatched_files".into(), Value::Array(Vec::new()));
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(archive.len())
        .map_err(|_| ErrorKind::Allocation)?;
    for (index, was_used) in used.into_iter().enumerate() {
        if was_used {
            continue;
        }
        let name = archive.names().nth(index).unwrap();
        if name.ends_with('/') {
            continue;
        }
        let name = Zeroizing::new(name.to_owned());
        let (mut bytes, memory) = archive.read(index, context)?.into_parts();
        push_array(
            &mut container,
            "unmatched_files",
            Value::Map(vec![
                ("index".into(), (index as u64).into()),
                ("path".into(), Value::from(name.as_str())),
                ("data".into(), Value::Binary(std::mem::take(&mut *bytes))),
            ]),
        );
        retained.push(memory);
        container_review(context, Code::SourceDataPreserved, None)?;
    }
    context.set_container_attributes(std::mem::take(&mut container.extra))?;
    Ok(())
}
fn push_array(record: &mut Record, key: &str, value: Value) {
    let Value::Array(values) = record.extra.get_mut(key).unwrap() else {
        unreachable!()
    };
    values.push(value);
}
fn container_review(
    context: &mut Context<'_>,
    code: Code,
    field: Option<usize>,
) -> Result<(), Error> {
    context.container_diagnostic(
        Status::Review,
        Diagnostic {
            code,
            location: Location {
                field,
                ..Location::default()
            },
        },
    )
}
fn issue(item: &mut Item, code: Code, field: Option<usize>, blocked: bool) {
    let diagnostic = Diagnostic {
        code,
        location: Location {
            item: Some(item.source.locator),
            field,
            offset: None,
        },
    };
    if !item.diagnostics.contains(&diagnostic) {
        item.diagnostics.push(diagnostic);
    }
    if blocked {
        item.status = Status::Blocked;
    } else if item.status == Status::Ready {
        item.status = Status::Review;
    }
}
fn original(item: &mut Item, path: &str, fragment: &RawValue) -> usize {
    let field = item.record.entries.len();
    item.record.entries.push(raw::original(path, fragment));
    issue(item, Code::SourceDataPreserved, None, false);
    field
}
fn map_item(
    source_raw: &RawValue,
    input: &Json,
    source: Source,
    archive: &mut Archive<'_>,
    used: &mut [bool],
    context: &mut Context<'_>,
) -> Result<(Item, Vec<Reservation>), Error> {
    let sections = input
        .get("details")
        .and_then(|v| v.get("sections"))
        .and_then(Json::as_array);
    let file_count = sections
        .into_iter()
        .flatten()
        .filter_map(|s| s.get("fields").and_then(Json::as_array))
        .flatten()
        .filter(|f| {
            f.get("value")
                .and_then(|v| v.get("file"))
                .is_some_and(|v| !v.is_null())
        })
        .take(context.limits.fields.saturating_add(2))
        .count()
        + usize::from(
            input
                .get("details")
                .and_then(|v| v.get("documentAttributes"))
                .is_some_and(|v| !v.is_null()),
        );
    if file_count > context.limits.fields.saturating_add(1) {
        return Err(ErrorKind::Limit.into());
    }
    let layout = sections.filter(|s| s.len() <= crate::sections::MAX_SECTIONS);
    let layout_bytes = layout.filter(|s| !s.is_empty()).map_or(0, |sections| {
        256 + sections.len() * 512
            + sections
                .iter()
                .filter_map(|s| s.get("title").and_then(Json::as_str))
                .filter(|s| s.len() <= 4096)
                .map(|s| s.len() * 2)
                .sum::<usize>()
    });
    let mut mapped_sections = layout.map(|_| Vec::new());
    let mut memories = Vec::new();
    if file_count != 0 || layout_bytes != 0 {
        let capacity = file_count + usize::from(layout_bytes != 0) + 1;
        let memory = context
            .memory()
            .reserve(capacity * std::mem::size_of::<Reservation>())?;
        memories
            .try_reserve_exact(capacity)
            .map_err(|_| ErrorKind::Allocation)?;
        memories.push(memory);
    }
    if layout_bytes != 0 {
        memories.push(context.memory().reserve(layout_bytes)?);
    }
    if let Some(groups) = &mut mapped_sections {
        groups
            .try_reserve_exact(layout.unwrap().len())
            .map_err(|_| ErrorKind::Allocation)?;
    }
    let mut item = Item {
        source,
        record: Record::default(),
        source_attributes: raw::snapshot(source_raw),
        status: Status::Ready,
        diagnostics: Vec::new(),
    };
    let object = input.as_object().ok_or(ErrorKind::Malformed)?;
    match input.get("uuid") {
        None | Some(Json::Null) => issue(&mut item, Code::MissingSourceScope, None, false),
        Some(Json::String(id))
            if !id.trim().is_empty() && id.len() <= context.limits.name_bytes =>
        {
            item.source.item = Some(id.clone())
        }
        _ => return Err(ErrorKind::Malformed.into()),
    }
    let raw_item = json::object(source_raw, context)?;
    let raw_details = json::object(raw::required(&raw_item, "details")?, context)?;
    let raw_overview = json::object(raw::required(&raw_item, "overview")?, context)?;
    let overview = input
        .get("overview")
        .and_then(Json::as_object)
        .ok_or(ErrorKind::Malformed)?;
    let details = input
        .get("details")
        .and_then(Json::as_object)
        .ok_or(ErrorKind::Malformed)?;
    let known_item = [
        "uuid",
        "favIndex",
        "createdAt",
        "updatedAt",
        "state",
        "categoryUuid",
        "overview",
        "details",
        "file",
    ];
    let known_overview = [
        "title",
        "subtitle",
        "urls",
        "url",
        "tags",
        "ps",
        "pbe",
        "pgrng",
        "icons",
        "watchtowerExclusions",
    ];
    if object.keys().any(|k| !known_item.contains(&k.as_str()))
        || overview
            .keys()
            .any(|k| !known_overview.contains(&k.as_str()))
    {
        item.record
            .extra
            .insert("confidex.title".into(), "Imported item".into());
        original(&mut item, "", source_raw);
        issue(&mut item, Code::UnsupportedFeature, None, true);
        return Ok((item, memories));
    }
    let title = overview
        .get("title")
        .and_then(Json::as_str)
        .filter(|s| s.len() <= context.limits.name_bytes);
    item.record.extra.insert(
        "confidex.title".into(),
        title.unwrap_or("Imported item").into(),
    );
    if title.is_none()
        && let Some(raw) = raw_overview.get("title")
    {
        original(&mut item, "/overview/title", raw);
    }
    if let Some(tags) = overview.get("tags") {
        if let Some(tags) = tags.as_array() {
            for tag in tags {
                if let Some(tag) = tag.as_str() {
                    if !item.record.tags.iter().any(|t| t == tag) {
                        if item.record.tags.len() >= confidex_vault::record::MAX_TAGS {
                            return Err(ErrorKind::Limit.into());
                        }
                        item.record.tags.push(tag.into());
                    }
                } else {
                    original(
                        &mut item,
                        "/overview/tags",
                        raw::required(&raw_overview, "tags")?,
                    );
                    break;
                }
            }
        } else if !tags.is_null() {
            original(
                &mut item,
                "/overview/tags",
                raw::required(&raw_overview, "tags")?,
            );
        }
    }
    if let Some(login) = details.get("loginFields") {
        if let Some(login) = login.as_array() {
            if login.len() > context.limits.fields {
                return Err(ErrorKind::Limit.into());
            }
            for (index, (field, raw)) in login
                .iter()
                .zip(json::array(raw::required(&raw_details, "loginFields")?)?)
                .enumerate()
            {
                let raw = raw?;
                if let Some(entry) = fields::login(field) {
                    item.record.entries.push(entry);
                } else {
                    let field = original(&mut item, &format!("/details/loginFields/{index}"), raw);
                    issue(&mut item, Code::UnsupportedFeature, Some(field), false);
                }
            }
        } else if !login.is_null() {
            original(
                &mut item,
                "/details/loginFields",
                raw::required(&raw_details, "loginFields")?,
            );
        }
    }
    if let Some(password) = details.get("password") {
        if let Some(password) = password.as_str() {
            item.record.entries.push(Entry {
                name: "Password".into(),
                type_name: "password/v1".into(),
                value: Mapping::from([("password".into(), password.into())]),
                extra: Mapping::new(),
            });
        } else if !password.is_null() {
            original(
                &mut item,
                "/details/password",
                raw::required(&raw_details, "password")?,
            );
        }
    }
    let mut source_urls = Vec::new();
    if let Some(array) = overview.get("urls") {
        if let Some(array) = array.as_array() {
            if array.len() > context.limits.fields {
                return Err(ErrorKind::Limit.into());
            }
            for (index, (value, raw)) in array
                .iter()
                .zip(json::array(raw::required(&raw_overview, "urls")?)?)
                .enumerate()
            {
                let raw = raw?;
                if let Some(url) = value.get("url").and_then(Json::as_str) {
                    source_urls.push(url);
                }
                if let Some(entry) = fields::url(value) {
                    item.record.entries.push(entry);
                } else {
                    original(&mut item, &format!("/overview/urls/{index}"), raw);
                }
            }
        } else if !array.is_null() {
            original(
                &mut item,
                "/overview/urls",
                raw::required(&raw_overview, "urls")?,
            );
        }
    }
    if let Some(primary) = overview.get("url") {
        if let Some(primary) = primary.as_str() {
            if !primary.is_empty() && !source_urls.contains(&primary) {
                item.record.entries.push(Entry {
                    name: "URL".into(),
                    type_name: "url/v1".into(),
                    value: Mapping::from([("url".into(), primary.into())]),
                    extra: Mapping::new(),
                });
            }
        } else if !primary.is_null() {
            original(
                &mut item,
                "/overview/url",
                raw::required(&raw_overview, "url")?,
            );
        }
    }
    if let Some(notes) = details.get("notesPlain") {
        if let Some(notes) = notes.as_str() {
            item.record.entries.push(protected_original("Notes", notes));
        } else if !notes.is_null() {
            original(
                &mut item,
                "/details/notesPlain",
                raw::required(&raw_details, "notesPlain")?,
            );
        }
    }
    if let Some(sections) = details.get("sections") {
        if let Some(sections) = sections.as_array() {
            if mapped_sections.is_none() {
                issue(&mut item, Code::UnsupportedFeature, None, false);
            }
            let mut source_fields = 0usize;
            for (section_index, (section, raw)) in sections
                .iter()
                .zip(json::array(raw::required(&raw_details, "sections")?)?)
                .enumerate()
            {
                let raw = raw?;
                let path = format!("/details/sections/{section_index}");
                if section.as_object().is_none_or(|s| {
                    s.keys().any(|k| {
                        !matches!(
                            k.as_str(),
                            "name" | "title" | "fields" | "hideAddAnotherField"
                        )
                    })
                }) {
                    original(&mut item, &path, raw);
                    continue;
                }
                let raw_section = json::object(raw, context)?;
                let group_start = item.record.entries.len();
                if let Some(fields) = section.get("fields").and_then(Json::as_array) {
                    source_fields = source_fields
                        .checked_add(fields.len())
                        .filter(|n| *n <= context.limits.fields)
                        .ok_or(ErrorKind::Limit)?;
                    for (index, (field, raw)) in fields
                        .iter()
                        .zip(json::array(raw::required(&raw_section, "fields")?)?)
                        .enumerate()
                    {
                        let raw = raw?;
                        if let Some(mut entry) = fields::section(field, section) {
                            if entry.type_name == "file/v1" {
                                let location = Some(item.record.entries.len());
                                if let Some((mut file, memory)) = attach_file(
                                    &mut item,
                                    &field["value"]["file"],
                                    None,
                                    archive,
                                    used,
                                    context,
                                    location,
                                )? {
                                    file.name = std::mem::take(&mut entry.name);
                                    file.extra.extend(std::mem::take(&mut entry.extra));
                                    entry = file;
                                    memories.push(memory);
                                }
                            }
                            item.record.entries.push(entry);
                        } else {
                            let field_location =
                                original(&mut item, &format!("{path}/fields/{index}"), raw);
                            let reference = field
                                .get("value")
                                .and_then(|v| v.get("reference"))
                                .is_some_and(|v| !v.is_null() && v.as_str() != Some(""));
                            issue(
                                &mut item,
                                if reference {
                                    Code::UnresolvedFieldReference
                                } else {
                                    Code::UnsupportedFeature
                                },
                                Some(field_location),
                                reference,
                            );
                        }
                    }
                } else if section.get("fields").is_some_and(|v| !v.is_null()) {
                    original(
                        &mut item,
                        &format!("{path}/fields"),
                        raw::required(&raw_section, "fields")?,
                    );
                }
                if let Some(groups) = &mut mapped_sections {
                    let title = match section.get("title") {
                        None | Some(Json::Null) => Some(""),
                        Some(value) => value.as_str().filter(|s| s.len() <= 4096),
                    };
                    if let Some(title) = title {
                        groups.push(crate::sections::Section::new(
                            title,
                            group_start,
                            item.record.entries.len() - group_start,
                        ));
                    } else {
                        issue(&mut item, Code::SourceDataPreserved, None, false);
                    }
                }
            }
        } else if !sections.is_null() {
            original(
                &mut item,
                "/details/sections",
                raw::required(&raw_details, "sections")?,
            );
        }
    }
    if details
        .get("passwordHistory")
        .is_some_and(|h| !h.is_null() && h.as_array().is_none_or(|a| !a.is_empty()))
    {
        original(
            &mut item,
            "/details/passwordHistory",
            raw::required(&raw_details, "passwordHistory")?,
        );
    }
    if input
        .get("favIndex")
        .is_some_and(|f| f.as_u64().is_none_or(|n| n != 0))
    {
        original(
            &mut item,
            "/favIndex",
            raw::required(&raw_item, "favIndex")?,
        );
    }
    for (key, raw) in raw_details.iter() {
        if !matches!(
            key,
            "loginFields"
                | "password"
                | "notesPlain"
                | "sections"
                | "passwordHistory"
                | "documentAttributes"
        ) {
            let mut path = Zeroizing::new(String::from("/details/"));
            for c in key.chars() {
                match c {
                    '~' => path.push_str("~0"),
                    '/' => path.push_str("~1"),
                    c => path.push(c),
                }
            }
            original(&mut item, &path, raw);
        }
    }
    for key in ["icons", "watchtowerExclusions"] {
        if overview
            .get(key)
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
        {
            original(
                &mut item,
                &format!("/overview/{key}"),
                raw::required(&raw_overview, key)?,
            );
        }
    }
    if item
        .record
        .entries
        .iter()
        .any(|e| e.type_name == "secure-note/v1")
    {
        item.diagnostics.push(Diagnostic {
            code: Code::NotesProtectedByDefault,
            location: Location {
                item: Some(item.source.locator),
                ..Location::default()
            },
        });
    }
    match input.get("state") {
        Some(Json::String(state)) if state == "archived" && !context.options.include_archived => {
            if item.status != Status::Blocked {
                item.status = Status::Excluded;
            }
            item.diagnostics.push(Diagnostic {
                code: Code::ArchivedExcludedByDefault,
                location: Location {
                    item: Some(item.source.locator),
                    ..Location::default()
                },
            });
        }
        Some(Json::String(state)) if matches!(state.as_str(), "active" | "archived") => (),
        None => (),
        _ => {
            original(&mut item, "/state", raw::required(&raw_item, "state")?);
            issue(&mut item, Code::UnsupportedFeature, None, true);
        }
    }
    if let Some(memory) = attach(&mut item, input, archive, used, context)? {
        memories.push(memory);
    }
    if let Some(sections) = mapped_sections {
        let fields = item.record.entries.len();
        crate::sections::apply(&mut item.record, Some(&sections), fields)
            .map_err(|_| ErrorKind::Malformed)?;
    }
    Ok((item, memories))
}

fn attach(
    item: &mut Item,
    input: &Json,
    archive: &mut Archive<'_>,
    used: &mut [bool],
    context: &mut Context<'_>,
) -> Result<Option<Reservation>, Error> {
    if item.status == Status::Blocked {
        return Ok(None);
    }
    let Some(document) = input
        .get("details")
        .and_then(|d| d.get("documentAttributes"))
        .filter(|d| !d.is_null())
    else {
        if input.get("file").is_some_and(|f| !f.is_null()) {
            issue(item, Code::UnsupportedFeature, None, true);
        }
        if !item.record.entries.is_empty()
            && item
                .record
                .entries
                .iter()
                .all(|e| e.extra.contains_key("confidex.import.original"))
        {
            issue(item, Code::UnknownItemPreserved, None, false);
        }
        return Ok(None);
    };
    let Some((mut entry, memory)) = attach_file(
        item,
        document,
        input.get("file").filter(|v| !v.is_null()),
        archive,
        used,
        context,
        None,
    )?
    else {
        return Ok(None);
    };
    if let Some(path) = entry.extra.remove("confidex.import.file_path") {
        item.source_attributes.insert("document_path".into(), path);
    }
    item.record.entries.push(entry);
    Ok(Some(memory))
}

fn attach_file(
    item: &mut Item,
    document: &Json,
    explicit: Option<&Json>,
    archive: &mut Archive<'_>,
    used: &mut [bool],
    context: &mut Context<'_>,
    field: Option<usize>,
) -> Result<Option<(Entry, Reservation)>, Error> {
    let Some((filename, id, size)) = fields::document(document) else {
        issue(item, Code::UnsupportedFeature, field, true);
        return Ok(None);
    };
    if id.is_empty()
        || id.contains("__")
        || id.contains(['/', '\\'])
        || filename.is_empty()
        || filename.contains(['/', '\\'])
        || document.as_object().is_none_or(|o| {
            o.keys()
                .any(|k| !matches!(k.as_str(), "fileName" | "documentId" | "decryptedSize"))
        })
    {
        issue(item, Code::UnsupportedEncoding, field, true);
        return Ok(None);
    }
    if filename.len() > context.limits.name_bytes || id.len() > context.limits.name_bytes {
        return Err(ErrorKind::Limit.into());
    }
    let paths = [
        Zeroizing::new(format!("files/{id}___{filename}")),
        Zeroizing::new(format!("files/{id}__{filename}")),
    ];
    if explicit.is_some_and(|f| {
        f.as_object()
            .is_none_or(|o| o.keys().any(|k| !matches!(k.as_str(), "path" | "attrs")))
            || f.get("attrs")
                .is_some_and(|a| !a.is_null() && a != document)
    }) {
        issue(item, Code::UnsupportedFeature, field, true);
        return Ok(None);
    }

    let selected = if let Some(explicit) = explicit {
        let path = explicit.get("path").and_then(Json::as_str);
        paths
            .iter()
            .position(|candidate| Some(candidate.as_str()) == path)
            .and_then(|candidate| {
                archive
                    .index(&paths[candidate])
                    .map(|index| (candidate, index))
            })
    } else {
        match (archive.index(&paths[0]), archive.index(&paths[1])) {
            (Some(_), Some(_)) => {
                issue(item, Code::UnsupportedFeature, field, true);
                return Ok(None);
            }
            (Some(index), None) => Some((0, index)),
            (None, Some(index)) => Some((1, index)),
            _ => None,
        }
    };
    let Some((candidate, index)) = selected else {
        issue(item, Code::MissingAttachment, field, true);
        return Ok(None);
    };
    if archive.size(index).map(|n| n as u64) != Some(size) {
        return Err(Error::from(ErrorKind::SizeMismatch).at(Location {
            item: Some(item.source.locator),
            field: field.or(Some(index)),
            offset: None,
        }));
    }
    let (mut bytes, memory) = archive.read(index, context)?.into_parts();
    let entry = Entry {
        name: filename.into(),
        type_name: "file/v1".into(),
        value: Mapping::from([
            ("data".into(), Value::Binary(std::mem::take(&mut *bytes))),
            ("filename".into(), filename.into()),
        ]),
        extra: Mapping::from([(
            "confidex.import.file_path".into(),
            paths[candidate].as_str().into(),
        )]),
    };
    used[index] = true;
    Ok(Some((entry, memory)))
}
