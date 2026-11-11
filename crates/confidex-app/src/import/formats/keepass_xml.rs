//! KeePass 2 XML import. Source behaviors are retained, never executed.
pub(super) mod binary;
pub(super) mod document;
pub(super) mod entry;
pub(super) mod mapping;
pub(super) mod writer;
pub(super) mod xml;
use crate::import::{
    Code, Context, Diagnostic, Error, ErrorKind, Item, Limits, Location, Options, Phase,
    Reservation, Status,
};
use confidex_vault::record::{Mapping, Record, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};
pub use writer::Writer;

pub(super) fn load(
    source: &[u8],
    offset: usize,
    context: &mut Context<'_>,
) -> Result<xml::Node, Error> {
    let limits = context.limits;
    let mut xml = xml::Xml::new(source, limits.depth, limits.nodes, limits.input_bytes)
        .map_err(|e| document::xml_error(e, offset))?;
    xml.string_limit = limits.string_bytes;
    let event = xml.next().map_err(|e| document::xml_error(e, offset))?;
    let (start, empty) = match event {
        quick_xml::events::Event::Start(s) => (s, false),
        quick_xml::events::Event::Empty(s) => (s, true),
        _ => return Err(ErrorKind::Malformed.into()),
    };
    xml.element(start, empty, &mut |n| {
        context
            .checkpoint(Phase::Map, offset + n, offset + source.len())
            .is_ok()
    })
    .map_err(|e| document::xml_error(e, offset + xml.position))
}
fn raw(source: &[u8], span: &Range<usize>) -> Value {
    Value::Binary(source[span.clone()].to_vec())
}
fn container(
    doc: &document::Document,
    source: &[u8],
    context: &mut Context<'_>,
) -> Result<(), Error> {
    container_with(
        doc,
        context,
        Mapping::from([("source_format".into(), "keepass2-xml".into())]),
        |span, _| Ok(raw(source, span)),
    )
}

pub(super) fn container_with(
    doc: &document::Document,
    context: &mut Context<'_>,
    attributes: Mapping,
    mut raw: impl FnMut(&Range<usize>, &Context<'_>) -> Result<Value, Error>,
) -> Result<(), Error> {
    let mut attributes = Record {
        extra: attributes,
        entries: Vec::new(),
        tags: Vec::new(),
    };
    let spans = doc
        .meta
        .iter()
        .chain(doc.headers.iter())
        .chain(doc.root_extra.iter().map(|(_, span)| span))
        .chain(doc.groups.iter().map(|g| &g.header))
        .chain(doc.groups.iter().flat_map(|g| g.properties.iter()));
    let prefix = doc.headers.first().map_or(0, |span| span.start);
    let bytes = spans.clone().try_fold(prefix, |n, span| {
        n.checked_add(span.len()).ok_or(ErrorKind::Limit)
    })?;
    let nodes = spans
        .count()
        .checked_mul(8)
        .and_then(|n| {
            doc.groups
                .len()
                .checked_mul(16)
                .and_then(|m| n.checked_add(m))
        })
        .ok_or(ErrorKind::Limit)?;
    let _work = context.reserve_work(bytes, nodes)?;
    fn array<'a>(
        spans: impl Iterator<Item = &'a Range<usize>>,
        context: &Context<'_>,
        raw: &mut impl FnMut(&Range<usize>, &Context<'_>) -> Result<Value, Error>,
    ) -> Result<Value, Error> {
        let mut values = Record::default();
        values.extra.insert("xml".into(), Value::Array(Vec::new()));
        for span in spans {
            let value = raw(span, context)?;
            let Some(Value::Array(items)) = values.extra.get_mut("xml") else {
                unreachable!()
            };
            items.push(value);
        }
        Ok(values.extra.remove("xml").unwrap())
    }
    attributes
        .extra
        .insert("preamble".into(), raw(&(0..prefix), context)?);
    attributes.extra.insert(
        "headers".into(),
        array(doc.headers.iter(), context, &mut raw)?,
    );
    attributes
        .extra
        .insert("meta".into(), array(doc.meta.iter(), context, &mut raw)?);
    attributes
        .extra
        .insert("groups".into(), Value::Array(Vec::new()));
    for group in &doc.groups {
        let mut value = Record::default();
        value
            .extra
            .insert("header".into(), raw(&group.header, context)?);
        value.extra.insert("id".into(), group.id.as_str().into());
        value
            .extra
            .insert("name".into(), group.name.as_str().into());
        value.extra.insert(
            "parent".into(),
            group.parent.map_or(Value::Nil, |p| Value::from(p as u64)),
        );
        value.extra.insert(
            "properties".into(),
            array(group.properties.iter(), context, &mut raw)?,
        );
        let Some(Value::Array(groups)) = attributes.extra.get_mut("groups") else {
            unreachable!()
        };
        groups.push(Value::Map(
            std::mem::take(&mut value.extra)
                .into_iter()
                .map(|(k, v)| (k.into(), v))
                .collect(),
        ));
    }
    attributes
        .extra
        .insert("root_extra".into(), Value::Array(Vec::new()));
    for (file, span) in &doc.root_extra {
        let xml = raw(span, context)?;
        let Some(Value::Array(extras)) = attributes.extra.get_mut("root_extra") else {
            unreachable!()
        };
        extras.push(Value::Map(vec![
            ("parent".into(), if *file { "file" } else { "root" }.into()),
            ("xml".into(), xml),
        ]));
    }
    context.set_container_attributes(std::mem::take(&mut attributes.extra))?;
    context.container_diagnostic(
        Status::Review,
        Diagnostic {
            code: Code::SourceDataPreserved,
            location: Location::default(),
        },
    )?;
    if doc.groups.len() > 1 {
        context.container_diagnostic(
            Status::Review,
            Diagnostic {
                code: Code::SourceGroupsRequireReview,
                location: Location::default(),
            },
        )?;
    }
    Ok(())
}

pub(super) fn build_entry(
    doc: &document::Document,
    index: usize,
    node: &xml::Node,
    source: &str,
    options: &Options,
    limits: Limits,
    binary: impl FnMut(&xml::Node) -> Result<Option<entry::Binary>, Error>,
) -> Result<Item, Error> {
    let path = doc.ancestors(doc.entries[index].group);
    let names = path
        .iter()
        .map(|&g| doc.groups[g].name.as_str())
        .collect::<Vec<_>>();
    let ids = path
        .iter()
        .map(|&g| doc.groups[g].id.as_str())
        .collect::<Vec<_>>();
    let deleted = !doc.recycle.is_empty()
        && doc.recycle.as_str() != "AAAAAAAAAAAAAAAAAAAAAA=="
        && ids.contains(&doc.recycle.as_str());
    let scope = entry::Scope {
        index,
        path: &names,
        group_ids: &ids,
        deleted,
    };
    let mut item = entry::build(node, source, &scope, options, limits, binary)?;
    if path.len() > 1 {
        item.diagnostics.push(Diagnostic {
            code: Code::SourceGroupsRequireReview,
            location: Location {
                item: Some(index),
                ..Location::default()
            },
        });
        if item.status == Status::Ready {
            item.status = Status::Review;
        }
    }
    Ok(item)
}
fn pool<'a>(
    doc: &'a document::Document,
    source: &[u8],
    context: &mut Context<'_>,
) -> Result<(BTreeMap<&'a str, &'a document::Pool>, usize), Error> {
    let mut result = BTreeMap::new();
    let mut total = 0usize;
    for member in &doc.pools {
        let _work = context.reserve_work(member.span.len(), member.nodes)?;
        let node = load(&source[member.span.clone()], member.span.start, context)?;
        if entry::flag(node.attribute("Protected"))? {
            return Err(ErrorKind::UnsupportedEncoding.into());
        }
        let text = node
            .leaf()
            .map_err(|e| document::xml_error(e, member.span.start))?;
        let size = binary::sizes(
            text,
            entry::flag(node.attribute("Compressed"))?,
            context.limits.unpacked_bytes,
        )
        .map_err(|e| document::xml_error(e, member.span.start))?;
        total = total
            .checked_add(size.output)
            .filter(|n| *n <= context.limits.unpacked_bytes)
            .ok_or(ErrorKind::Limit)?;
        let _decode = context.memory().reserve(
            size.working()
                .map_err(|e| document::xml_error(e, member.span.start))?,
        )?;
        drop(
            binary::decode(
                text,
                entry::flag(node.attribute("Compressed"))?,
                context.limits.unpacked_bytes,
            )
            .map_err(|e| document::xml_error(e, member.span.start))?,
        );
        result.insert(member.id.as_str(), member);
    }
    Ok((result, total))
}
fn decode(
    node: &xml::Node,
    compressed: bool,
    context: &Context<'_>,
    guards: &mut Vec<Reservation>,
    total: Option<&mut usize>,
) -> Result<entry::Binary, Error> {
    let text = node.leaf().map_err(|e| document::xml_error(e, 0))?;
    let size = binary::sizes(text, compressed, context.limits.unpacked_bytes)
        .map_err(|e| document::xml_error(e, 0))?;
    if let Some(total) = total {
        *total = total
            .checked_add(size.output)
            .filter(|n| *n <= context.limits.unpacked_bytes)
            .ok_or(ErrorKind::Limit)?;
    }
    guards.push(
        context
            .memory()
            .reserve(size.working().map_err(|e| document::xml_error(e, 0))?)?,
    );
    let protected = entry::flag(node.attribute("ProtectInMemory"))?;
    let bytes = binary::decode(text, compressed, context.limits.unpacked_bytes)
        .map_err(|e| document::xml_error(e, 0))?;
    Ok(entry::Binary { bytes, protected })
}

pub fn parse(source: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    if source.len() > context.limits.input_bytes {
        return Err(ErrorKind::Limit.into());
    }
    let doc = document::Document::parse(source, context)?;
    let (pool, mut unpacked) = pool(&doc, source, context)?;
    let mut resolved = BTreeSet::new();
    container(&doc, source, context)?;
    for (index, location) in doc.entries.iter().enumerate() {
        let _work = context.reserve_work(
            location.span.len().checked_mul(2).ok_or(ErrorKind::Limit)?,
            location.nodes,
        )?;
        let input = &source[location.span.clone()];
        let node = load(input, location.span.start, context)?;
        let mut guards = Vec::new();
        let item = build_entry(
            &doc,
            index,
            &node,
            std::str::from_utf8(input).map_err(|_| ErrorKind::UnsupportedEncoding)?,
            context.options,
            context.limits,
            |value| {
                if let Some(reference) = value.attribute("Ref") {
                    let Some(member) = pool.get(reference) else {
                        return Ok(None);
                    };
                    let _work = context.reserve_work(member.span.len(), member.nodes)?;
                    let pool_node = load(&source[member.span.clone()], member.span.start, context)?;
                    decode(
                        &pool_node,
                        entry::flag(pool_node.attribute("Compressed"))?,
                        context,
                        &mut guards,
                        if resolved.insert(member.id.as_str()) {
                            None
                        } else {
                            Some(&mut unpacked)
                        },
                    )
                    .map(Some)
                } else {
                    decode(value, false, context, &mut guards, Some(&mut unpacked)).map(Some)
                }
            },
        )?;
        context.push(item)?;
        drop(guards);
    }
    Ok(())
}
