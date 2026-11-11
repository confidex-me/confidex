//! Direct KDBX import. No source files or decoded XML exports are written.
use super::{
    super::{Code, Context, Diagnostic, Error, ErrorKind, Location, Phase, Reservation, Status},
    keepass_xml::{self, document::Document},
};
use confidex_vault::record::{Record, Value};
use keepass::bounded::{Limits as DecodeLimits, Raw};
use std::{collections::BTreeSet, mem};
mod pool;
mod protected;
mod writer;
pub use writer::Writer;
#[cfg(test)]
mod tests;

fn decode_error(error: keepass::bounded::Error) -> Error {
    use keepass::bounded::Error as Decode;
    match error {
        Decode::Limit => ErrorKind::Limit,
        Decode::KdfLimit => ErrorKind::KdfLimit,
        Decode::Allocation => ErrorKind::Allocation,
        Decode::Malformed => ErrorKind::Malformed,
        Decode::Unsupported => ErrorKind::UnsupportedEncoding,
        Decode::Canceled => ErrorKind::Canceled,
        Decode::Credentials => ErrorKind::Checksum,
    }
    .into()
}

pub fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    let password = context
        .options
        .password_present
        .then_some(context.options.password.as_str());
    let keyfile = context
        .options
        .keyfile_present
        .then_some(context.options.keyfile.as_slice());
    parse_with(input, password, keyfile, context)
}

/// Explicit credential presence also supports an empty password with a keyfile.
pub fn parse_with(
    input: &[u8],
    password: Option<&str>,
    keyfile: Option<&[u8]>,
    context: &mut Context<'_>,
) -> Result<(), Error> {
    let limits = context.limits;
    if (password.is_none() && keyfile.is_none())
        || password.is_some_and(|p| p.len() > limits.name_bytes)
        || keyfile.is_some_and(|k| k.len() > 1 << 20)
    {
        return Err(ErrorKind::InvalidOptions.into());
    }
    let _credentials = context.memory().reserve(
        password
            .map_or(0, str::len)
            .checked_add(keyfile.map_or(0, <[u8]>::len))
            .ok_or(ErrorKind::Limit)?,
    )?;
    let budget = context
        .memory()
        .available()
        .min(DecodeLimits::default().memory_bytes);
    let mut memory = context.memory().reserve(budget)?;
    let mut raw = Raw::open(
        input,
        password,
        keyfile,
        DecodeLimits {
            input_bytes: limits.input_bytes,
            unpacked_bytes: limits.unpacked_bytes,
            memory_bytes: budget,
            ..DecodeLimits::default()
        },
        &mut |_, _| context.checkpoint(Phase::Read, 0, 0).is_ok(),
    )
    .map_err(decode_error)?;
    memory.shrink_to(raw.memory_bytes())?;
    let mut stream = raw.take_protected().map_err(decode_error)?;
    let values = protected::Values::read(raw.xml(), &mut stream, context)?;
    drop(stream);
    let doc = Document::parse(raw.xml(), context)?;
    let mut pool = pool::Pool::new(&raw, &values, &doc, context)?;
    for (index, location) in doc.entries.iter().enumerate() {
        let fragment = values.fragment(raw.xml(), location.span.clone(), context)?;
        let _work = context.reserve_work(
            fragment
                .bytes
                .len()
                .checked_mul(2)
                .ok_or(ErrorKind::Limit)?,
            location.nodes,
        )?;
        let node = keepass_xml::load(&fragment.bytes, location.span.start, context)?;
        let mut guards = Vec::new();
        let mut item = keepass_xml::build_entry(
            &doc,
            index,
            &node,
            std::str::from_utf8(&fragment.bytes).map_err(|_| ErrorKind::UnsupportedEncoding)?,
            context.options,
            limits,
            |value| {
                let data = if let Some(reference) = value.attribute("Ref") {
                    pool.read(reference, context)?
                } else {
                    Some(pool.inline(value, context)?)
                };
                Ok(data.map(|data| {
                    guards.push(data.memory);
                    keepass_xml::entry::Binary {
                        bytes: data.bytes,
                        protected: data.protected,
                    }
                }))
            },
        )?;
        let mut refs = BTreeSet::new();
        pool::references(&node, &mut refs);
        item.source_attributes
            .insert("binary_pool".into(), Value::Map(Vec::new()));
        for reference in refs {
            let value = if let Some(data) = pool.read(reference, context)? {
                source_binary(data, &mut guards)
            } else {
                item.diagnostics.push(Diagnostic {
                    code: Code::MissingAttachment,
                    location: Location {
                        item: Some(index),
                        ..Location::default()
                    },
                });
                item.status = Status::Blocked;
                Value::Nil
            };
            let Some(Value::Map(refs)) = item.source_attributes.get_mut("binary_pool") else {
                unreachable!()
            };
            refs.push((reference.into(), value));
        }
        context.push(item)?;
    }
    let mut guards = Vec::new();
    guards.push(context.memory().reserve(raw.header().len())?);
    let mut attributes = Record::default();
    attributes
        .extra
        .insert("source_format".into(), "kdbx".into());
    attributes
        .extra
        .insert("version".into(), raw.version().to_string().into());
    attributes
        .extra
        .insert("outer_header".into(), Value::Binary(raw.header().to_vec()));
    attributes
        .extra
        .insert("orphan_binaries".into(), Value::Map(Vec::new()));
    for index in 0..pool.len() {
        if let Some(data) = pool.orphan(index, context)? {
            let Some(Value::Map(orphans)) = attributes.extra.get_mut("orphan_binaries") else {
                unreachable!()
            };
            orphans.push((index.to_string().into(), source_binary(data, &mut guards)));
        }
    }
    keepass_xml::container_with(
        &doc,
        context,
        mem::take(&mut attributes.extra),
        |span, context| {
            let mut fragment = values.fragment(raw.xml(), span.clone(), context)?;
            guards.push(fragment._memory);
            Ok(Value::Binary(mem::take(&mut *fragment.bytes)))
        },
    )?;
    Ok(())
}

fn source_binary(mut data: pool::Data, guards: &mut Vec<Reservation>) -> Value {
    guards.push(data.memory);
    Value::Map(vec![
        ("data".into(), Value::Binary(mem::take(&mut *data.bytes))),
        ("protected".into(), data.protected.into()),
    ])
}
