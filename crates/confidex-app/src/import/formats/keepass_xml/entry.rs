//! Map one KeePass entry without executing source references or commands.
use super::{mapping, xml::Node};
use crate::import::{
    Code, Diagnostic, Error, ErrorKind, Item, Limits, Location, Options, Source, Status,
    protected_original,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use confidex_vault::record::{Entry, Mapping, Record, Value};
use zeroize::{Zeroize, Zeroizing};

pub(in crate::import::formats) struct Scope<'a> {
    pub index: usize,
    pub path: &'a [&'a str],
    pub group_ids: &'a [&'a str],
    pub deleted: bool,
}
pub(in crate::import::formats) struct Binary {
    pub bytes: Zeroizing<Vec<u8>>,
    pub protected: bool,
}
struct Field<'a> {
    node: &'a Node,
    key: &'a str,
    value: &'a str,
    protected: bool,
    encrypted: bool,
    hidden_name: bool,
}
fn malformed() -> Error {
    ErrorKind::Malformed.into()
}
fn field(node: &Node) -> Result<Field<'_>, Error> {
    let key_node = node
        .child("Key")
        .map_err(|_| malformed())?
        .ok_or_else(malformed)?;
    let key = key_node.leaf().map_err(|_| malformed())?;
    let value = node
        .child("Value")
        .map_err(|_| malformed())?
        .ok_or_else(malformed)?;
    Ok(Field {
        node,
        key,
        value: value.leaf().map_err(|_| malformed())?,
        protected: flag(value.attribute("ProtectInMemory"))?,
        encrypted: flag(value.attribute("Protected"))? || flag(key_node.attribute("Protected"))?,
        hidden_name: flag(key_node.attribute("ProtectInMemory"))?,
    })
}
pub(in crate::import::formats) fn flag(value: Option<&str>) -> Result<bool, Error> {
    match value {
        None => Ok(false),
        Some(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
        _ => Err(malformed()),
    }
}
pub(in crate::import::formats) fn uuid(value: &str) -> Result<(), Error> {
    let mut bytes = [0u8; 16];
    let length = STANDARD
        .decode_slice(value, &mut bytes)
        .map_err(|_| malformed())?;
    if length != bytes.len() {
        return Err(malformed());
    }
    Ok(())
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
fn raw<'a>(source: &'a str, node: &Node) -> &'a str {
    &source[node.span.clone()]
}
struct Retained<'a> {
    source: &'a str,
    text: Zeroizing<String>,
    ranges: std::collections::BTreeSet<(usize, usize)>,
    root: std::ops::Range<usize>,
}
impl<'a> Retained<'a> {
    fn new(source: &'a str, root: std::ops::Range<usize>) -> Self {
        Self {
            source,
            text: Zeroizing::new(String::new()),
            ranges: Default::default(),
            root,
        }
    }
    fn add(&mut self, node: &Node) {
        if self
            .ranges
            .iter()
            .any(|&(start, end)| start <= node.span.start && end >= node.span.end)
        {
            return;
        }
        if node.span == self.root {
            self.text.zeroize();
            self.ranges.clear();
        }
        if self.text.capacity() < self.source.len() {
            self.text = Zeroizing::new(String::with_capacity(self.source.len()));
        }
        self.ranges.insert((node.span.start, node.span.end));
        self.text.push_str(raw(self.source, node));
    }
}
fn retain(
    item: &mut Item,
    original: &mut Retained<'_>,
    _source: &str,
    node: &Node,
    field: Option<usize>,
) {
    original.add(node);
    issue(item, Code::SourceDataPreserved, field, false);
}
fn plain(field: &Field<'_>) -> Result<Entry, mapping::Issue> {
    mapping::text_field(field.key, field.value, field.protected)
}
fn native_otp(fields: &[Field<'_>], seed_index: usize) -> Result<Entry, mapping::Issue> {
    let value = |name| {
        fields
            .iter()
            .find(|field| field.key == name)
            .map_or("", |field| field.value)
    };
    let field = &fields[seed_index];
    let encoding = match field.key {
        "TimeOtp-Secret" => "Utf8",
        "TimeOtp-Secret-Hex" => "Hex",
        "TimeOtp-Secret-Base32" => "Base32",
        "TimeOtp-Secret-Base64" => "Base64",
        _ => unreachable!(),
    };
    mapping::otp_keepass(
        field.key,
        field.value,
        encoding,
        value("TimeOtp-Algorithm"),
        value("TimeOtp-Length"),
        value("TimeOtp-Period"),
    )
}
fn is_native_seed(key: &str) -> bool {
    matches!(
        key,
        "TimeOtp-Secret" | "TimeOtp-Secret-Hex" | "TimeOtp-Secret-Base32" | "TimeOtp-Secret-Base64"
    )
}
fn is_native_option(key: &str) -> bool {
    matches!(
        key,
        "TimeOtp-Algorithm" | "TimeOtp-Length" | "TimeOtp-Period"
    )
}

pub(in crate::import::formats) fn build(
    node: &Node,
    source: &str,
    scope: &Scope<'_>,
    options: &Options,
    limits: Limits,
    mut binary: impl FnMut(&Node) -> Result<Option<Binary>, Error>,
) -> Result<Item, Error> {
    let id = node
        .child("UUID")
        .map_err(|_| malformed())?
        .ok_or_else(malformed)?
        .leaf()
        .map_err(|_| malformed())?;
    uuid(id)?;
    for name in ["Times", "Tags"] {
        node.child(name).map_err(|_| ErrorKind::DuplicateKey)?;
    }
    let mut item = Item {
        source: Source {
            instance: None,
            account: None,
            vault: None,
            item: Some(id.into()),
            locator: scope.index,
        },
        record: Record::default(),
        source_attributes: Mapping::new(),
        status: Status::Ready,
        diagnostics: Vec::new(),
    };
    item.source_attributes.insert(
        "group_path".into(),
        Value::Array(scope.path.iter().map(|s| Value::from(*s)).collect()),
    );
    item.source_attributes.insert(
        "group_ids".into(),
        Value::Array(scope.group_ids.iter().map(|s| Value::from(*s)).collect()),
    );
    let mut original = Retained::new(source, node.span.clone());
    let mut entries = Vec::new();
    let mut fields = Vec::new();
    for child in &node.children {
        if child.name.as_str() == "String" {
            fields.push(field(child)?);
        }
    }
    let title_count = fields.iter().filter(|f| f.key == "Title").count();
    let title_header = title_count == 1
        && fields.iter().any(|f| {
            f.key == "Title"
                && !f.protected
                && !f.encrypted
                && !f.hidden_name
                && !mapping::dynamic(f.value)
        });
    if fields.len() - usize::from(title_header)
        + node
            .children
            .iter()
            .filter(|n| n.name.as_str() == "Binary")
            .count()
        > limits.fields
        || fields
            .iter()
            .any(|field| field.key.len() > limits.name_bytes)
    {
        return Err(ErrorKind::Limit.into());
    }
    let native_seeds = fields.iter().filter(|f| is_native_seed(f.key)).count();
    let legacy_seeds = fields.iter().filter(|f| f.key == "TOTP Seed").count();
    let native_ambiguous = fields.iter().any(|field| {
        field.key.starts_with("TimeOtp-")
            && !is_native_seed(field.key)
            && !is_native_option(field.key)
    }) || fields.iter().any(|field| {
        is_native_option(field.key)
            && fields.iter().filter(|prior| prior.key == field.key).count() > 1
    });
    let legacy_ambiguous = fields.iter().any(|field| {
        field.key.starts_with("TOTP ") && !matches!(field.key, "TOTP Seed" | "TOTP Settings")
    }) || fields
        .iter()
        .filter(|field| field.key == "TOTP Settings")
        .count()
        > 1;
    item.source_attributes
        .insert("title_present".into(), Value::Boolean(title_count > 0));
    let mut code_placeholders = Vec::new();
    let mut title = "Imported entry";
    for (index, field) in fields.iter().enumerate() {
        if !field.node.text.trim().is_empty()
            || !field.node.attributes.is_empty()
            || field
                .node
                .children
                .iter()
                .any(|c| !matches!(c.name.as_str(), "Key" | "Value"))
            || field.node.children.iter().any(|c| {
                c.attributes
                    .iter()
                    .any(|(key, _)| !matches!(key.as_str(), "ProtectInMemory" | "Protected"))
            })
        {
            retain(&mut item, &mut original, source, field.node, Some(index));
        }
        if fields[..index].iter().any(|prior| prior.key == field.key) {
            retain(&mut item, &mut original, source, field.node, Some(index));
            issue(&mut item, Code::UnsupportedFeature, Some(index), false);
        }
        if field.encrypted || field.hidden_name {
            retain(&mut item, &mut original, source, field.node, Some(index));
            issue(
                &mut item,
                if field.encrypted {
                    Code::UnsupportedEncoding
                } else {
                    Code::UnsupportedFeature
                },
                Some(index),
                true,
            );
            continue;
        }
        if field.key == "Password"
            && ["{TIMEOTP}", "{TOTP}"]
                .iter()
                .any(|token| field.value.eq_ignore_ascii_case(token))
        {
            retain(&mut item, &mut original, source, field.node, Some(index));
            code_placeholders.push(index);
            continue;
        }
        let entry = if field.key == "Title" {
            if mapping::dynamic(field.value) {
                retain(&mut item, &mut original, source, field.node, Some(index));
                issue(&mut item, Code::UnresolvedFieldReference, Some(index), true);
            } else if title_count != 1 || field.protected {
                retain(&mut item, &mut original, source, field.node, Some(index));
            } else {
                title = field.value;
            }
            continue;
        } else if field.key == "otp" && !field.value.is_empty() {
            if field.value.contains("://") {
                mapping::otp_uri(field.key, field.value)
            } else {
                mapping::otp_keeotp(field.key, field.value)
            }
        } else if is_native_seed(field.key) {
            if native_ambiguous
                || native_seeds != 1
                || fields
                    .iter()
                    .any(|f| (is_native_seed(f.key) || is_native_option(f.key)) && f.encrypted)
            {
                Err(mapping::Issue::UnsupportedOtp)
            } else {
                native_otp(&fields, index)
            }
        } else if field.key == "TOTP Seed" {
            let settings = fields.iter().find(|f| f.key == "TOTP Settings");
            if legacy_ambiguous || legacy_seeds != 1 || settings.is_some_and(|f| f.encrypted) {
                Err(mapping::Issue::UnsupportedOtp)
            } else {
                mapping::otp_legacy(field.key, field.value, settings.map_or("", |f| f.value))
            }
        } else if (is_native_option(field.key) && native_seeds > 0)
            || (field.key == "TOTP Settings" && legacy_seeds > 0)
        {
            retain(&mut item, &mut original, source, field.node, Some(index));
            continue;
        } else if field.key == "otp"
            || field.key.starts_with("TimeOtp-")
            || field.key.starts_with("HmacOtp-")
            || field.key.starts_with("TOTP ")
        {
            retain(&mut item, &mut original, source, field.node, Some(index));
            issue(&mut item, Code::UnsupportedFeature, Some(index), false);
            continue;
        } else {
            plain(field)
        };
        match entry {
            Ok(mut entry) => {
                if !field.protected && field.key == "Notes" {
                    issue(&mut item, Code::NotesProtectedByDefault, Some(index), false);
                }
                if field.protected && field.key == "URL" {
                    issue(&mut item, Code::ProtectedUrlNotIndexed, Some(index), false);
                }
                entry.extra.insert(
                    "confidex.import.field".into(),
                    Value::Map(vec![
                        ("key".into(), field.key.into()),
                        ("protect_in_memory".into(), field.protected.into()),
                    ]),
                );
                entries.push((field.node.span.start, entry));
            }
            Err(reason) => {
                retain(&mut item, &mut original, source, field.node, Some(index));
                issue(
                    &mut item,
                    if reason == mapping::Issue::UnresolvedReference {
                        Code::UnresolvedFieldReference
                    } else {
                        Code::UnsupportedFeature
                    },
                    Some(index),
                    reason != mapping::Issue::UnsupportedOtp,
                );
            }
        }
    }
    if !entries
        .iter()
        .any(|(_, entry)| entry.type_name == "totp/v1")
    {
        for index in code_placeholders {
            issue(&mut item, Code::UnresolvedFieldReference, Some(index), true);
        }
    }
    item.record
        .extra
        .insert("confidex.title".into(), title.into());
    for child in &node.children {
        match child.name.as_str() {
            "String" => {}
            "UUID" => {
                if !child.attributes.is_empty() {
                    retain(&mut item, &mut original, source, child, None);
                }
            }
            "Tags" => {
                if flag(child.attribute("Protected"))? || flag(child.attribute("ProtectInMemory"))?
                {
                    retain(&mut item, &mut original, source, child, None);
                    issue(&mut item, Code::UnsupportedFeature, None, true);
                    continue;
                }
                if !child.attributes.is_empty() {
                    retain(&mut item, &mut original, source, child, None);
                }
                let tags = child.leaf().map_err(|_| malformed())?;
                item.source_attributes.insert("tags".into(), tags.into());
                for tag in tags
                    .split([',', ';', '\t'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if !item.record.tags.iter().any(|t| t == tag) {
                        item.record.tags.push(tag.into());
                    }
                }
            }
            "Times" => {
                item.source_attributes
                    .insert("times".into(), raw(source, child).into());
            }
            "Binary" => {
                let key = child
                    .child("Key")
                    .map_err(|_| malformed())?
                    .ok_or_else(malformed)?;
                let name = key.leaf().map_err(|_| malformed())?;
                if name.len() > limits.name_bytes {
                    return Err(ErrorKind::Limit.into());
                }
                if flag(key.attribute("Protected"))? || flag(key.attribute("ProtectInMemory"))? {
                    retain(&mut item, &mut original, source, child, None);
                    issue(&mut item, Code::UnsupportedFeature, None, true);
                    continue;
                }
                let value = child
                    .child("Value")
                    .map_err(|_| malformed())?
                    .ok_or_else(malformed)?;
                if value.attribute("Ref").is_some()
                    && (!value.text.trim().is_empty() || !value.children.is_empty())
                {
                    retain(&mut item, &mut original, source, child, None);
                    issue(&mut item, Code::UnsupportedFeature, None, true);
                    continue;
                }
                let data = if flag(value.attribute("Protected"))? {
                    None
                } else {
                    binary(value)?
                };
                if let Some(mut data) = data {
                    let protected = data.protected || flag(value.attribute("ProtectInMemory"))?;
                    if !child.text.trim().is_empty()
                        || !child.attributes.is_empty()
                        || !key.attributes.is_empty()
                        || child
                            .children
                            .iter()
                            .any(|n| !matches!(n.name.as_str(), "Key" | "Value"))
                        || value.attributes.iter().any(|(key, _)| {
                            !matches!(key.as_str(), "Ref" | "Protected" | "ProtectInMemory")
                        })
                    {
                        retain(&mut item, &mut original, source, child, None);
                    }
                    entries.push((
                        child.span.start,
                        Entry {
                            name: name.into(),
                            type_name: "file/v1".into(),
                            value: Mapping::from([
                                ("filename".into(), name.into()),
                                ("mime".into(), "application/octet-stream".into()),
                                (
                                    "data".into(),
                                    Value::Binary(std::mem::take(&mut *data.bytes)),
                                ),
                            ]),
                            extra: if protected {
                                Mapping::from([(
                                    "metadata".into(),
                                    Value::Map(vec![("protected".into(), true.into())]),
                                )])
                            } else {
                                Mapping::new()
                            },
                        },
                    ));
                } else {
                    retain(&mut item, &mut original, source, child, None);
                    issue(&mut item, Code::MissingAttachment, None, true);
                }
            }
            _ => retain(&mut item, &mut original, source, child, None),
        }
    }
    fn encrypted(node: &Node) -> bool {
        node.attribute("Protected")
            .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1")
            || node.children.iter().any(encrypted)
    }
    if encrypted(node) {
        issue(&mut item, Code::UnsupportedEncoding, None, true);
    }
    if !node.attributes.is_empty() || !node.text.trim().is_empty() {
        retain(&mut item, &mut original, source, node, None);
    }
    entries.sort_by_key(|(position, _)| *position);
    item.record.entries = entries.into_iter().map(|(_, entry)| entry).collect();
    if !original.text.is_empty() {
        item.record
            .entries
            .push(protected_original("Original data", &original.text));
    }
    if scope.deleted && !options.include_deleted {
        item.status = Status::Excluded;
        issue(&mut item, Code::RecycleBinExcludedByDefault, None, false);
    }
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{Context, Format};
    use quick_xml::events::Event;
    const DATA: &str = include_str!("../../../../tests/import_fixtures/keepass_xml/database.xml");
    fn document(source: &str) -> Node {
        let mut xml =
            super::super::xml::Xml::new(source.as_bytes(), 32, 100_000, 16 << 20).unwrap();
        loop {
            if let Event::Start(start) = xml.next().unwrap() {
                return xml.element(start, false, &mut |_| true).unwrap();
            }
        }
    }
    fn record(source: &str) -> (Node, String) {
        let xml = format!("<Entry><UUID>EREREREREREREREREREREQ==</UUID>{source}</Entry>");
        (document(&xml), xml)
    }
    fn scope() -> Scope<'static> {
        Scope {
            index: 0,
            path: &[],
            group_ids: &[],
            deleted: false,
        }
    }
    #[test]
    fn a_real_plan_preserves_protection_and_source_behavior() {
        let root = document(DATA);
        let group = root
            .child("Root")
            .unwrap()
            .unwrap()
            .child("Group")
            .unwrap()
            .unwrap()
            .children
            .iter()
            .find(|n| n.name.as_str() == "Group")
            .unwrap();
        let source_entry = group
            .children
            .iter()
            .find(|n| n.name.as_str() == "Entry")
            .unwrap();
        let mut options = Options::default();
        options.source_instance = Some("public-fixture-source".into());
        let path = ["Public fixture", "Work/メール"];
        let group_ids = ["AAAAAAAAAAAAAAAAAAAAAA==", "AQEBAQEBAQEBAQEBAQEBAQ=="];
        let mut callback = |_| true;
        let mut context = Context::new(
            Format::KeepassXml,
            DATA.len(),
            &options,
            Limits::default(),
            &mut callback,
        )
        .unwrap();
        let item = build(
            source_entry,
            DATA,
            &Scope {
                index: 0,
                path: &path,
                group_ids: &group_ids,
                deleted: false,
            },
            &options,
            Limits::default(),
            |_| Ok(None),
        )
        .unwrap();
        assert_eq!(item.status, Status::Review);
        context.push(item).unwrap();
        let plan = context.finish().unwrap();
        assert_eq!(plan.items.len(), 1);
        let record = plan.items[0].record(96 << 20).unwrap();
        assert_eq!(
            record.extra["confidex.title"].as_str(),
            Some("Почта — 東京")
        );
        let url = record.entries.iter().find(|e| e.name == "URL").unwrap();
        assert_eq!(url.type_name, "url/v1");
        assert!(
            url.extra["metadata"]
                .as_map()
                .unwrap()
                .iter()
                .any(|(k, v)| k.as_str() == Some("protected") && v.as_bool() == Some(true))
        );
        let otp = record.entries.iter().find(|e| e.name == "otp").unwrap();
        assert_eq!(otp.type_name, "totp/v1");
        assert_eq!(otp.value["period"].as_u64(), Some(45));
        assert_eq!(otp.value["digits"].as_u64(), Some(8));
        let original = record
            .entries
            .iter()
            .find(|e| e.name == "Original data")
            .unwrap();
        assert_eq!(original.type_name, "secure-note/v1");
        let text = original.value["text"].as_str().unwrap();
        assert!(
            text.contains("AutoType")
                && text.contains("PUBLIC-FIXTURE-OLD")
                && text.contains("fixture-plugin")
        );
        let facts = plan.items[0].source_attributes(96 << 20).unwrap();
        assert_eq!(
            facts["group_path"].as_array().unwrap()[1].as_str(),
            Some("Work/メール")
        );
        assert!(
            facts["times"]
                .as_str()
                .unwrap()
                .contains("2026-01-02T00:00:00Z")
        );
    }
    #[test]
    fn unresolved_and_inner_protected_credentials_are_not_usable() {
        for input in [
            "<String><Key>Password</Key><Value>{REF:P@I:11111111111111111111111111111111}</Value></String>",
            "<String><Key>Password</Key><Value Protected='True'>AA==</Value></String>",
        ] {
            let (node, source) = record(input);
            let item = build(
                &node,
                &source,
                &scope(),
                &Options::default(),
                Limits::default(),
                |_| Ok(None),
            )
            .unwrap();
            assert_eq!(item.status, Status::Blocked);
            assert!(
                !item
                    .record
                    .entries
                    .iter()
                    .any(|e| e.type_name == "password/v1")
            );
        }
    }
    #[test]
    fn repeated_names_empty_values_and_binary_order_survive() {
        let (node, source) = record(
            "<String><Key>Repeated</Key><Value>first</Value></String><Binary><Key>public.bin</Key><Value Ref='1'/></Binary><String><Key>Repeated</Key><Value/></String><String><Key></Key><Value ProtectInMemory='True'>PUBLIC-FIXTURE-HIDDEN</Value></String>",
        );
        let item = build(
            &node,
            &source,
            &scope(),
            &Options::default(),
            Limits::default(),
            |value| {
                assert_eq!(value.attribute("Ref"), Some("1"));
                Ok(Some(Binary {
                    bytes: Zeroizing::new(vec![0, 255]),
                    protected: false,
                }))
            },
        )
        .unwrap();
        assert_eq!(item.record.entries[0].name, "Repeated");
        assert_eq!(item.record.entries[1].type_name, "file/v1");
        assert_eq!(item.record.entries[2].name, "Repeated");
        assert_eq!(item.record.entries[2].value["text"].as_str(), Some(""));
        assert_eq!(item.record.entries[3].name, "");
        assert_eq!(item.record.entries[3].type_name, "secret/v1");
        assert!(
            matches!(&item.record.entries[1].value["data"],Value::Binary(bytes) if bytes==&[0,255])
        );
    }
    #[test]
    fn protected_title_and_recycle_bin_are_explicit() {
        let (node, source) = record(
            "<String><Key>Title</Key><Value ProtectInMemory='True'>PUBLIC-FIXTURE-PRIVATE-TITLE</Value></String><String><Key>Password</Key><Value>public fixture</Value></String>",
        );
        let options = Options::default();
        let mut deleted = scope();
        deleted.deleted = true;
        let item = build(
            &node,
            &source,
            &deleted,
            &options,
            Limits::default(),
            |_| Ok(None),
        )
        .unwrap();
        assert_eq!(item.status, Status::Excluded);
        assert_eq!(
            item.record.extra["confidex.title"].as_str(),
            Some("Imported entry")
        );
        assert!(item.record.entries.iter().any(|e| {
            e.type_name == "secure-note/v1"
                && e.value["text"]
                    .as_str()
                    .unwrap()
                    .contains("PUBLIC-FIXTURE-PRIVATE-TITLE")
        }));
        let mut options = Options::default();
        options.include_deleted = true;
        let item = build(
            &node,
            &source,
            &deleted,
            &options,
            Limits::default(),
            |_| Ok(None),
        )
        .unwrap();
        assert_eq!(item.status, Status::Review);
    }
}
