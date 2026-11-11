//! Index source spans first. Record values are materialized one entry at a time.
use super::{
    entry,
    xml::{self, Xml},
};
use crate::import::{Context, Error, ErrorKind, Location, Phase, Reservation};
use quick_xml::events::Event;
use std::ops::Range;
use zeroize::Zeroizing;

pub(in crate::import::formats) struct Group {
    pub header: Range<usize>,
    pub parent: Option<usize>,
    pub name: Zeroizing<String>,
    pub id: Zeroizing<String>,
    pub properties: Vec<Range<usize>>,
    name_seen: bool,
    id_seen: bool,
}
pub(in crate::import::formats) struct Entry {
    pub span: Range<usize>,
    pub group: usize,
    pub nodes: usize,
    pub id: Zeroizing<String>,
}
pub(in crate::import::formats) struct Pool {
    pub id: Zeroizing<String>,
    pub span: Range<usize>,
    pub nodes: usize,
}
pub(in crate::import::formats) struct Document {
    pub groups: Vec<Group>,
    pub entries: Vec<Entry>,
    pub pools: Vec<Pool>,
    pub meta: Vec<Range<usize>>,
    pub root_extra: Vec<(bool, Range<usize>)>,
    pub recycle: Zeroizing<String>,
    pub headers: Vec<Range<usize>>,
    _memory: Reservation,
}
#[derive(Default)]
struct Counts {
    entries: usize,
    groups: usize,
    pools: usize,
    text: usize,
    properties: usize,
    extra: usize,
}
fn malformed(offset: usize) -> Error {
    Error::from(ErrorKind::Malformed).at(Location {
        offset: Some(offset),
        ..Location::default()
    })
}
pub(in crate::import::formats) fn xml_error(error: xml::Error, offset: usize) -> Error {
    Error::from(match error {
        xml::Error::Invalid => ErrorKind::Malformed,
        xml::Error::Limit => ErrorKind::Limit,
        xml::Error::Unsupported => ErrorKind::UnsupportedEncoding,
        xml::Error::Canceled => ErrorKind::Canceled,
    })
    .at(Location {
        offset: Some(offset),
        ..Location::default()
    })
}
fn group_path(path: &[&[u8]]) -> bool {
    path.len() >= 3
        && path[0] == b"KeePassFile"
        && path[1] == b"Root"
        && path[2..].iter().all(|n| *n == b"Group")
}
fn source_name(path: &[&[u8]]) -> bool {
    path.len() > 3
        && ((matches!(path.last(), Some(&b"Name" | &b"UUID"))
            && group_path(&path[..path.len() - 1]))
            || (path.last() == Some(&b"UUID".as_slice())
                && path[path.len() - 2] == b"Entry"
                && group_path(&path[..path.len() - 2])))
}
fn text(event: &Event<'_>) -> Result<Zeroizing<String>, Error> {
    let value = match event {
        Event::Text(value) => value
            .xml10_content()
            .map_err(|_| malformed(0))?
            .into_owned(),
        Event::CData(value) => value
            .xml10_content()
            .map_err(|_| malformed(0))?
            .into_owned(),
        Event::GeneralRef(value) => Xml::reference(value)
            .map_err(|e| xml_error(e, 0))?
            .to_string(),
        _ => String::new(),
    };
    Ok(Zeroizing::new(value))
}
fn scan(
    input: &[u8],
    context: &mut Context<'_>,
    mut output: Option<&mut Document>,
) -> Result<Counts, Error> {
    let limits = context.limits;
    let mut xml = Xml::new(input, limits.depth, limits.nodes, limits.input_bytes)
        .map_err(|e| xml_error(e, 0))?;
    xml.string_limit = limits.string_bytes;
    let mut path = Vec::with_capacity(limits.depth);
    let mut group_stack = Vec::with_capacity(limits.depth);
    let mut current_entry: Option<(usize, usize, usize, Zeroizing<String>)> = None;
    let mut current_pool: Option<(usize, usize, Zeroizing<String>)> = None;
    let mut property: Option<usize> = None;
    let mut metadata: Option<usize> = None;
    let mut root_extra: Option<usize> = None;
    let mut counts = Counts::default();
    let (mut root_count, mut meta_count, mut top_groups) = (0, 0, 0);
    let mut leaf_bytes = 0usize;
    let mut recycle_seen = false;
    let mut checkpoint = 0;
    loop {
        let event = xml.next().map_err(|e| xml_error(e, xml.position))?;
        if xml.event_count() - checkpoint >= 256 {
            context.checkpoint(Phase::Read, xml.position, input.len())?;
            checkpoint = xml.event_count();
        }
        match &event {
            Event::Start(start) | Event::Empty(start) => {
                let empty = matches!(event, Event::Empty(_));
                let name =
                    &input[xml.position + 1..xml.position + 1 + start.name().into_inner().len()];
                if source_name(&path)
                    || path.as_slice()
                        == [
                            b"KeePassFile".as_slice(),
                            b"Meta".as_slice(),
                            b"RecycleBinUUID".as_slice(),
                        ]
                {
                    return Err(malformed(xml.position));
                }
                if (path.is_empty()
                    || (path.as_slice() == [b"KeePassFile".as_slice()] && name == b"Root"))
                    && let Some(doc) = output.as_deref_mut()
                {
                    doc.headers.push(xml.position..xml.offset());
                }
                if path.is_empty() && name != b"KeePassFile" {
                    return Err(ErrorKind::UnsupportedFormat.into());
                }
                if path.as_slice() == [b"KeePassFile".as_slice()] && name == b"Root" {
                    root_count += 1;
                }
                if path.as_slice() == [b"KeePassFile".as_slice()] && name == b"Meta" {
                    meta_count += 1;
                    metadata = Some(xml.position);
                }
                if name == b"Group"
                    && (path.as_slice() == [b"KeePassFile".as_slice(), b"Root".as_slice()]
                        || group_path(&path))
                {
                    if empty {
                        return Err(malformed(xml.position));
                    }
                    if path.len() == 2 {
                        top_groups += 1;
                    }
                    counts.groups += 1;
                    if let Some(doc) = output.as_deref_mut() {
                        doc.groups.push(Group {
                            header: xml.position..xml.offset(),
                            parent: group_stack.last().copied(),
                            name: Zeroizing::new(String::new()),
                            id: Zeroizing::new(String::new()),
                            properties: Vec::new(),
                            name_seen: false,
                            id_seen: false,
                        });
                    }
                    group_stack.push(counts.groups - 1);
                } else if name == b"Entry" && group_path(&path) {
                    if empty || current_entry.is_some() {
                        return Err(malformed(xml.position));
                    }
                    counts.entries += 1;
                    if counts.entries > limits.records {
                        return Err(ErrorKind::Limit.into());
                    }
                    current_entry = Some((
                        xml.position,
                        xml.event_nodes(),
                        *group_stack.last().ok_or_else(|| malformed(xml.position))?,
                        Zeroizing::new(String::new()),
                    ));
                } else if name == b"Binary"
                    && path.as_slice()
                        == [
                            b"KeePassFile".as_slice(),
                            b"Meta".as_slice(),
                            b"Binaries".as_slice(),
                        ]
                {
                    counts.pools += 1;
                    let mut id = None;
                    for attr in start.attributes() {
                        let attr = attr.map_err(|_| malformed(xml.position))?;
                        if attr.key.as_ref() == b"ID" {
                            let value = attr
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    xml.decoder(),
                                )
                                .map_err(|_| malformed(xml.position))?;
                            if value.len() > limits.name_bytes {
                                return Err(ErrorKind::Limit.into());
                            }
                            counts.text += value.len();
                            id = Some(Zeroizing::new(value.into_owned()));
                        }
                    }
                    let id = id.ok_or_else(|| malformed(xml.position))?;
                    if empty {
                        if let Some(doc) = output.as_deref_mut() {
                            doc.pools.push(Pool {
                                id,
                                span: xml.position..xml.offset(),
                                nodes: xml.node_count() - xml.event_nodes(),
                            });
                        }
                    } else {
                        current_pool = Some((xml.position, xml.event_nodes(), id));
                    }
                } else if group_path(&path) {
                    counts.properties += 1;
                    property = Some(xml.position);
                } else if (path.as_slice() == [b"KeePassFile".as_slice(), b"Root".as_slice()]
                    && name != b"Group")
                    || (path.as_slice() == [b"KeePassFile".as_slice()]
                        && !matches!(name, b"Meta" | b"Root"))
                {
                    counts.extra += 1;
                    root_extra = Some(xml.position);
                }
                if source_name(&[path.as_slice(), &[name]].concat())
                    || (path.as_slice() == [b"KeePassFile".as_slice(), b"Meta".as_slice()]
                        && name == b"RecycleBinUUID")
                {
                    leaf_bytes = 0;
                    if name == b"RecycleBinUUID" {
                        if recycle_seen {
                            return Err(ErrorKind::DuplicateKey.into());
                        }
                        recycle_seen = true;
                    }
                    for attr in start.attributes() {
                        let attr = attr.map_err(|_| malformed(xml.position))?;
                        if matches!(attr.key.as_ref(), b"Protected" | b"ProtectInMemory") {
                            let value = Zeroizing::new(
                                attr.decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    xml.decoder(),
                                )
                                .map_err(|_| malformed(xml.position))?
                                .into_owned(),
                            );
                            if entry::flag(Some(&value))? {
                                return Err(ErrorKind::UnsupportedEncoding.into());
                            }
                        }
                    }
                    if group_path(&path)
                        && let Some(doc) = output.as_deref_mut()
                    {
                        let group = &mut doc.groups[*group_stack.last().unwrap()];
                        let seen = if name == b"Name" {
                            &mut group.name_seen
                        } else {
                            &mut group.id_seen
                        };
                        if *seen {
                            return Err(ErrorKind::DuplicateKey.into());
                        }
                        *seen = true;
                    }
                }
                if empty {
                    if group_path(&path)
                        && let Some(begin) = property.take()
                        && let Some(doc) = output.as_deref_mut()
                    {
                        doc.groups[*group_stack.last().unwrap()]
                            .properties
                            .push(begin..xml.offset());
                    }
                    if (path.as_slice() == [b"KeePassFile".as_slice()]
                        || path.as_slice() == [b"KeePassFile".as_slice(), b"Root".as_slice()])
                        && let Some(begin) = root_extra.take()
                        && let Some(doc) = output.as_deref_mut()
                    {
                        doc.root_extra.push((path.len() == 1, begin..xml.offset()));
                    }
                    if let Some(begin) = metadata.take() {
                        if path.as_slice() == [b"KeePassFile".as_slice()] {
                            if let Some(doc) = output.as_deref_mut() {
                                doc.meta.push(begin..xml.offset());
                            }
                        } else {
                            metadata = Some(begin);
                        }
                    }
                } else {
                    path.push(name);
                }
            }
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_) => {
                if (group_path(&path)
                    || path.as_slice() == [b"KeePassFile".as_slice()]
                    || path.as_slice() == [b"KeePassFile".as_slice(), b"Root".as_slice()])
                    && !event.iter().all(u8::is_ascii_whitespace)
                {
                    return Err(malformed(xml.position));
                }
                let recycle = path.as_slice()
                    == [
                        b"KeePassFile".as_slice(),
                        b"Meta".as_slice(),
                        b"RecycleBinUUID".as_slice(),
                    ];
                if source_name(&path) || recycle {
                    if event.len() > limits.name_bytes.saturating_mul(2) {
                        return Err(ErrorKind::Limit.into());
                    }
                    let value = text(&event)?;
                    leaf_bytes += value.len();
                    counts.text += value.len();
                    if leaf_bytes > limits.name_bytes {
                        return Err(ErrorKind::Limit.into());
                    }
                    if let Some(doc) = output.as_deref_mut() {
                        if recycle {
                            super::xml::append_text(&mut doc.recycle, &value);
                        } else if path[path.len() - 2] == b"Group" {
                            let group = &mut doc.groups[*group_stack.last().unwrap()];
                            let target = if path.last() == Some(&b"Name".as_slice()) {
                                &mut group.name
                            } else {
                                &mut group.id
                            };
                            super::xml::append_text(target, &value);
                        } else if let Some((_, _, _, id)) = &mut current_entry {
                            super::xml::append_text(id, &value);
                        }
                    }
                }
            }

            Event::End(end) => {
                let name = end.name();
                let name = name.as_ref();
                if name == b"Entry" && path.len() >= 4 && group_path(&path[..path.len() - 1]) {
                    let (begin, nodes, group, id) = current_entry
                        .take()
                        .ok_or_else(|| malformed(xml.position))?;
                    if let Some(doc) = output.as_deref_mut() {
                        doc.entries.push(Entry {
                            span: begin..xml.offset(),
                            group,
                            nodes: xml.node_count() - nodes,
                            id,
                        });
                    }
                } else if name == b"Group" && group_path(&path) {
                    group_stack.pop();
                } else if name == b"Binary"
                    && path.as_slice()
                        == [
                            b"KeePassFile".as_slice(),
                            b"Meta".as_slice(),
                            b"Binaries".as_slice(),
                            b"Binary".as_slice(),
                        ]
                {
                    let (begin, nodes, id) =
                        current_pool.take().ok_or_else(|| malformed(xml.position))?;
                    if let Some(doc) = output.as_deref_mut() {
                        doc.pools.push(Pool {
                            id,
                            span: begin..xml.offset(),
                            nodes: xml.node_count() - nodes,
                        });
                    }
                }
                path.pop().ok_or_else(|| malformed(xml.position))?;
                if group_path(&path)
                    && let Some(begin) = property.take()
                    && let Some(doc) = output.as_deref_mut()
                {
                    doc.groups[*group_stack.last().unwrap()]
                        .properties
                        .push(begin..xml.offset());
                }
                if path.as_slice() == [b"KeePassFile".as_slice()]
                    && name == b"Meta"
                    && let Some(begin) = metadata.take()
                    && let Some(doc) = output.as_deref_mut()
                {
                    doc.meta.push(begin..xml.offset());
                }
                if (path.as_slice() == [b"KeePassFile".as_slice(), b"Root".as_slice()]
                    || path.as_slice() == [b"KeePassFile".as_slice()])
                    && let Some(begin) = root_extra.take()
                    && let Some(doc) = output.as_deref_mut()
                {
                    doc.root_extra.push((path.len() == 1, begin..xml.offset()));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if root_count != 1 || meta_count > 1 || top_groups != 1 {
        return Err(malformed(input.len()));
    }
    context.checkpoint(Phase::Read, input.len(), input.len())?;
    Ok(counts)
}
impl Document {
    pub fn parse(input: &[u8], context: &mut Context<'_>) -> Result<Self, Error> {
        let first = context
            .memory()
            .reserve(input.len().checked_add(2 << 20).ok_or(ErrorKind::Limit)?)?;
        let counts = scan(input, context, None)?;
        drop(first);
        let scratch = context.reserve_work(context.limits.string_bytes, 0)?;
        let bytes = counts
            .entries
            .checked_mul(std::mem::size_of::<Entry>() + 96)
            .and_then(|n| {
                counts
                    .groups
                    .checked_mul(std::mem::size_of::<Group>() + 96)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                counts
                    .pools
                    .checked_mul(std::mem::size_of::<Pool>() + 96)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                (counts.properties + counts.extra)
                    .checked_mul(std::mem::size_of::<Range<usize>>() * 2)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| counts.text.checked_mul(2).and_then(|m| n.checked_add(m)))
            .ok_or(ErrorKind::Limit)?;
        let memory = context.memory().reserve(bytes)?;
        let mut doc = Self {
            groups: Vec::new(),
            entries: Vec::new(),
            pools: Vec::new(),
            meta: Vec::new(),
            root_extra: Vec::new(),
            recycle: Zeroizing::new(String::new()),
            headers: Vec::with_capacity(2),
            _memory: memory,
        };
        doc.groups
            .try_reserve_exact(counts.groups)
            .map_err(|_| ErrorKind::Allocation)?;
        doc.entries
            .try_reserve_exact(counts.entries)
            .map_err(|_| ErrorKind::Allocation)?;
        doc.pools
            .try_reserve_exact(counts.pools)
            .map_err(|_| ErrorKind::Allocation)?;
        doc.root_extra
            .try_reserve_exact(counts.extra)
            .map_err(|_| ErrorKind::Allocation)?;
        scan(input, context, Some(&mut doc))?;
        let mut ids = std::collections::BTreeSet::new();
        for entry in &doc.entries {
            entry::uuid(&entry.id)?;
            if entry.id.as_str() == "AAAAAAAAAAAAAAAAAAAAAA==" || !ids.insert(entry.id.as_str()) {
                return Err(ErrorKind::DuplicateKey.into());
            }
        }
        ids.clear();
        for group in &doc.groups {
            if !group.name_seen || !group.id_seen {
                return Err(malformed(0));
            }
            entry::uuid(&group.id)?;
            if !ids.insert(group.id.as_str()) {
                return Err(ErrorKind::DuplicateKey.into());
            }
        }
        ids.clear();
        for pool in &doc.pools {
            if pool.id.is_empty() || !ids.insert(pool.id.as_str()) {
                return Err(ErrorKind::DuplicateKey.into());
            }
        }
        drop(ids);
        drop(scratch);
        Ok(doc)
    }
    pub fn ancestors(&self, group: usize) -> Vec<usize> {
        let mut result = Vec::new();
        let mut next = Some(group);
        while let Some(index) = next {
            result.push(index);
            next = self.groups[index].parent;
        }
        result.reverse();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{Format, Limits, Options};
    const DATA: &[u8] =
        include_bytes!("../../../../tests/import_fixtures/keepass_xml/database.xml");
    #[test]
    fn spans_keep_entry_history_and_group_scopes_separate() {
        let options = Options::default();
        let mut callback = |_| true;
        let mut context = Context::new(
            Format::KeepassXml,
            DATA.len(),
            &options,
            Limits::default(),
            &mut callback,
        )
        .unwrap();
        let doc = Document::parse(DATA, &mut context).unwrap();
        assert_eq!(doc.entries.len(), 3);
        assert_eq!(doc.groups.len(), 3);
        assert_eq!(doc.recycle.as_str(), "AgICAgICAgICAgICAgICAg==");
        let first = &doc.entries[0];
        assert_eq!(first.id.as_str(), "EREREREREREREREREREREQ==");
        assert!(
            std::str::from_utf8(&DATA[first.span.clone()])
                .unwrap()
                .contains("<History>")
        );
        let ancestors = doc.ancestors(first.group);
        assert_eq!(ancestors.len(), 2);
        assert_eq!(doc.groups[ancestors[1]].name.as_str(), "Work/メール");
        assert_eq!(doc.meta.len(), 1);
        assert_eq!(doc.root_extra.len(), 1);
    }
    #[test]
    fn published_export_counts_pool_members_and_real_entries() {
        let source =
            include_bytes!("../../../../tests/import_fixtures/keepass_xml/upstream-keepass.xml");
        let options = Options::default();
        let mut callback = |_| true;
        let mut context = Context::new(
            Format::KeepassXml,
            source.len(),
            &options,
            Limits::default(),
            &mut callback,
        )
        .unwrap();
        let doc = Document::parse(source, &mut context).unwrap();
        assert_eq!(doc.entries.len(), 4);
        assert_eq!(doc.pools.len(), 2);
        assert_eq!(doc.pools[0].id.as_str(), "0");
        assert_eq!(doc.pools[1].id.as_str(), "1");
        assert_eq!(doc.groups[doc.entries[2].group].name.as_str(), "Subsub");
    }
    #[test]
    fn duplicate_identity_invalid_structure_and_resource_limits_fail() {
        let root = "<KeePassFile><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>fixture</Name>{}</Group></Root></KeePassFile>";
        for entry in [
            "<Entry/>",
            "<Entry><UUID>EREREREREREREREREREREQ==</UUID></Entry><Entry><UUID>EREREREREREREREREREREQ==</UUID></Entry>",
        ] {
            let source = root.replace("{}", entry);
            let options = Options::default();
            let mut callback = |_| true;
            let mut context = Context::new(
                Format::KeepassXml,
                source.len(),
                &options,
                Limits::default(),
                &mut callback,
            )
            .unwrap();
            assert!(Document::parse(source.as_bytes(), &mut context).is_err());
        }
        let options = Options::default();
        let mut callback = |_| true;
        let limits = Limits {
            records: 2,
            ..Limits::default()
        };
        let mut context = Context::new(
            Format::KeepassXml,
            DATA.len(),
            &options,
            limits,
            &mut callback,
        )
        .unwrap();
        assert_eq!(
            Document::parse(DATA, &mut context).err().unwrap().kind,
            ErrorKind::Limit
        );
    }
}
