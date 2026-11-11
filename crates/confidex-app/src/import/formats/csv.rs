//! CSV column mapping is explicit. This module never writes to the vault.
mod mapping;
mod profiles;
mod reader;
mod writer;
use crate::import::{Context, Error, ErrorKind, Limits, Memory, Phase, Progress, Reservation};
pub use mapping::TARGETS;
pub use profiles::Profile;
pub use writer::Writer;
use zeroize::Zeroizing;

pub struct Header {
    names: Vec<Zeroizing<String>>,
    delimiter: u8,
    _memory: Reservation,
}
impl Header {
    pub fn names(&self) -> &[Zeroizing<String>] {
        &self.names
    }
    pub fn delimiter(&self) -> u8 {
        self.delimiter
    }
}
/// Read the first row's width without returning possible credential values.
pub fn column_count(
    input: &[u8],
    delimiter: u8,
    limits: Limits,
    callback: &mut dyn FnMut(Progress) -> bool,
) -> Result<usize, Error> {
    let limits = limits.validate()?;
    let memory = Memory::new(limits.memory_bytes);
    let _input = memory.reserve(input.len())?;
    let _rows = memory.reserve(limits.fields * std::mem::size_of::<reader::Cell>() * 2)?;
    let mut reader = reader::Reader::new(input, delimiter, limits)?;
    let row = reader
        .next(&mut |current| {
            callback(Progress {
                phase: Phase::Read,
                current,
                total: input.len(),
            })
        })?
        .ok_or(ErrorKind::UnsupportedFormat)?;
    if !callback(Progress {
        phase: Phase::Read,
        current: reader.offset(),
        total: input.len(),
    }) {
        return Err(ErrorKind::Canceled.into());
    }
    Ok(row.cells.len())
}
/// Inspect only the selected header row. Parse still validates the whole file.
pub fn header(
    input: &[u8],
    delimiter: u8,
    limits: Limits,
    callback: &mut dyn FnMut(Progress) -> bool,
) -> Result<Header, Error> {
    let limits = limits.validate()?;
    let memory = Memory::new(limits.memory_bytes);
    let _input = memory.reserve(input.len())?;
    let _rows = memory.reserve(limits.fields * std::mem::size_of::<reader::Cell>() * 2)?;
    let mut reader = reader::Reader::new(input, delimiter, limits)?;
    let row = reader
        .next(&mut |current| {
            callback(Progress {
                phase: Phase::Read,
                current,
                total: input.len(),
            })
        })?
        .ok_or(ErrorKind::UnsupportedFormat)?;
    if row.cells.iter().any(|c| c.bytes > limits.name_bytes) {
        return Err(ErrorKind::Limit.into());
    }
    let reservation = memory.reserve(
        row.bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(limits.fields * 256 + (2 << 20)))
            .ok_or(ErrorKind::Limit)?,
    )?;
    let names = row.cells.iter().map(|c| c.decode(reader.source)).collect();
    if !callback(Progress {
        phase: Phase::Read,
        current: reader.offset(),
        total: input.len(),
    }) {
        return Err(ErrorKind::Canceled.into());
    }
    Ok(Header {
        names,
        delimiter,
        _memory: reservation,
    })
}

pub fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    use confidex_vault::record::{Mapping, Value};
    let options = context
        .options
        .csv
        .as_ref()
        .ok_or(ErrorKind::InvalidOptions)?;
    if options
        .columns
        .iter()
        .any(|c| !TARGETS.contains(&c.target.as_str()))
        || options
            .columns
            .iter()
            .filter(|c| c.target == "title")
            .count()
            > 1
        || options
            .columns
            .iter()
            .enumerate()
            .any(|(n, c)| options.columns[..n].iter().any(|p| p.index == c.index))
    {
        return Err(ErrorKind::InvalidOptions.into());
    }
    let limits = context.limits;
    let _rows = context
        .memory()
        .reserve(limits.fields * std::mem::size_of::<reader::Cell>() * 2)?;
    let mut reader = reader::Reader::new(input, options.delimiter, limits)?;
    let first = reader
        .next(&mut |n| context.checkpoint(Phase::Read, n, input.len()).is_ok())?
        .ok_or(ErrorKind::UnsupportedFormat)?;
    let width = first.cells.len();
    if options.columns.iter().any(|c| c.index >= width) {
        return Err(ErrorKind::InvalidOptions.into());
    }
    let _names = context.reserve_work(if options.header { first.bytes } else { 0 }, width)?;
    let requested = (0..width)
        .map(|index| options.columns.iter().find(|c| c.index == index))
        .collect::<Vec<_>>();
    let names = if options.header {
        if first.cells.iter().any(|c| c.bytes > limits.name_bytes) {
            return Err(ErrorKind::Limit.into());
        }
        first
            .cells
            .iter()
            .map(|c| c.decode(reader.source))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let bytes = names
        .iter()
        .map(|s| s.len())
        .sum::<usize>()
        .checked_mul(3)
        .and_then(|n| {
            options
                .columns
                .iter()
                .try_fold(n, |n, c| n.checked_add(c.name.len() + c.target.len()))
        })
        .ok_or(ErrorKind::Limit)?;
    {
        let _work = context.reserve_work(bytes, width.checked_mul(12).ok_or(ErrorKind::Limit)?)?;
        let columns = (0..width)
            .map(|index| {
                let requested = requested[index];
                let source_name = names
                    .get(index)
                    .map_or(Value::Nil, |s| Value::from(s.as_str()));
                let name = requested.map_or_else(
                    || names.get(index).map_or("", |s| s.as_str()),
                    |c| c.name.as_str(),
                );
                Value::Map(vec![
                    ("index".into(), (index as u64).into()),
                    ("source_name".into(), source_name),
                    ("name".into(), name.into()),
                    (
                        "target".into(),
                        requested.map_or("secret/v1", |c| c.target.as_str()).into(),
                    ),
                    ("explicit".into(), requested.is_some().into()),
                ])
            })
            .collect();
        context.set_container_attributes(Mapping::from([
            ("source_format".into(), "generic-csv".into()),
            ("delimiter".into(), u64::from(options.delimiter).into()),
            ("header".into(), options.header.into()),
            ("bom".into(), input.starts_with(&[0xef, 0xbb, 0xbf]).into()),
            ("columns".into(), Value::Array(columns)),
        ]))?;
    }
    let mut pending = if options.header { None } else { Some(first) };
    let mut index = 0usize;
    loop {
        context.checkpoint(Phase::Read, reader.offset(), input.len())?;
        let row = if let Some(row) = pending.take() {
            row
        } else {
            let Some(row) =
                reader.next(&mut |n| context.checkpoint(Phase::Read, n, input.len()).is_ok())?
            else {
                break;
            };
            row
        };
        if row.cells.len() != width {
            return Err(
                Error::from(ErrorKind::Malformed).at(crate::import::Location {
                    item: Some(index),
                    field: None,
                    offset: Some(row.span.start),
                }),
            );
        }
        if index >= limits.records {
            return Err(ErrorKind::Limit.into());
        }
        let _work = context.reserve_work(
            row.bytes.checked_mul(2).ok_or(ErrorKind::Limit)?,
            width.checked_mul(12).ok_or(ErrorKind::Limit)?,
        )?;
        let mut item = mapping::item(index, index + usize::from(options.header), row.span.clone());
        // Nullable producer fields can distinguish quoted and unquoted empties.
        let empty = row
            .cells
            .iter()
            .enumerate()
            .filter(|(_, cell)| cell.bytes == 0)
            .map(|(column, cell)| Value::Array(vec![(column as u64).into(), cell.quoted.into()]))
            .collect::<Vec<_>>();
        if !empty.is_empty() {
            item.source_attributes
                .insert("empty_cells".into(), Value::Array(empty));
        }
        for (column, cell) in row.cells.iter().enumerate() {
            context.checkpoint(Phase::Map, cell.span.start, input.len())?;
            let requested = requested[column];
            let target = requested.map_or("secret/v1", |c| c.target.as_str());
            let name = requested.map_or_else(
                || names.get(column).map_or("", |s| s.as_str()),
                |c| c.name.as_str(),
            );
            let value = cell.decode(reader.source);
            mapping::field(&mut item, column, target, name, &value, requested.is_some())?;
        }
        context.push(item)?;
        index += 1;
    }
    context.checkpoint(Phase::Read, input.len(), input.len())?;
    Ok(())
}
