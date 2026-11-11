use super::{BoundedOutput, Error, scan};
use crate::{encoding::HEADER_LIMITS, record::MAX_ENTRIES};
use rmpv::ValueRef;
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Content,
    Deletion,
}

pub struct Metadata {
    pub epoch: u64,
    pub value_sizes: Vec<u64>,
}
pub struct Header {
    pub vault_id: [u8; 16],
    pub record_id: [u8; 16],
    pub parents: Vec<[u8; 32]>,
    pub metadata: Metadata,
    pub kind: EventKind,
}
pub struct Options<'a> {
    pub vault_id: [u8; 16],
    pub record_id: [u8; 16],
    pub parents: &'a [[u8; 32]],
    pub epoch: u64,
    pub kind: EventKind,
}
impl Options<'_> {
    pub(super) fn validate(&self, empty: bool) -> Result<(), Error> {
        if self.parents.len() > 1024 {
            return Err(Error::Limit);
        }
        if self.kind == EventKind::Deletion && (self.parents.is_empty() || !empty) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
fn array<'a, 'b>(v: &'b ValueRef<'a>) -> Result<&'b [ValueRef<'a>], Error> {
    match v {
        ValueRef::Array(a) => Ok(a),
        _ => Err(Error::Invalid),
    }
}
fn number(v: &ValueRef<'_>) -> Result<u64, Error> {
    v.as_u64().ok_or(Error::Invalid)
}
fn binary<const N: usize>(v: &ValueRef<'_>) -> Result<[u8; N], Error> {
    match v {
        ValueRef::Binary(b) => (*b).try_into().map_err(|_| Error::Invalid),
        _ => Err(Error::Invalid),
    }
}
fn field<'a, 'b>(v: &'b ValueRef<'a>, name: &str) -> Result<&'b ValueRef<'a>, Error> {
    let ValueRef::Map(rows) = v else {
        return Err(Error::Invalid);
    };
    rows.iter()
        .find(|(k, _)| matches!(k, ValueRef::String(s) if s.as_str() == Some(name)))
        .map(|(_, v)| v)
        .ok_or(Error::Invalid)
}
fn collect<T>(
    count: usize,
    items: impl Iterator<Item = Result<T, Error>>,
) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for value in items {
        out.push(value?);
    }
    Ok(out)
}
pub(super) fn decode(input: &[u8]) -> Result<Header, Error> {
    scan(input, HEADER_LIMITS)?;
    let root = rmpv::decode::read_value_ref(&mut &*input).map_err(|_| Error::Invalid)?;
    let fields = array(&root)?;
    if fields.len() != 6 {
        return Err(Error::Invalid);
    }
    if number(&fields[0])? != 2 {
        return Err(Error::Version);
    }
    let vault_id = binary(&fields[1])?;
    let record_id = binary(&fields[2])?;
    let parents = array(&fields[3])?;
    if parents.len() > 1024 {
        return Err(Error::Limit);
    }
    let parents = collect(parents.len(), parents.iter().map(binary))?;
    if parents.windows(2).any(|p| p[0] >= p[1]) {
        return Err(Error::Invalid);
    }
    let kind = match number(&fields[5])? {
        0 => EventKind::Content,
        1 => EventKind::Deletion,
        _ => return Err(Error::Invalid),
    };
    if !matches!(&fields[4], ValueRef::Map(m) if m.len() == 2) {
        return Err(Error::Invalid);
    }
    let epoch = number(field(&fields[4], "epoch")?)?;
    let sizes = array(field(&fields[4], "value_sizes")?)?;
    if sizes.len() > MAX_ENTRIES {
        return Err(Error::Limit);
    }
    let value_sizes = collect(sizes.len(), sizes.iter().map(number))?;
    if kind == EventKind::Deletion && (parents.is_empty() || !value_sizes.is_empty()) {
        return Err(Error::Invalid);
    }
    Ok(Header {
        vault_id,
        record_id,
        parents,
        metadata: Metadata { epoch, value_sizes },
        kind,
    })
}

pub(super) fn encode(options: Options<'_>, sizes: &[u64]) -> Result<Vec<u8>, Error> {
    let mut parents = collect(
        options.parents.len(),
        options.parents.iter().copied().map(Ok),
    )?;
    parents.sort_unstable();
    if parents.windows(2).any(|p| p[0] == p[1]) {
        return Err(Error::Invalid);
    }
    let mut out = BoundedOutput::new(HEADER_LIMITS.bytes)?;
    macro_rules! write {
        ($e:expr) => {
            $e.map_err(|_| Error::Limit)?
        };
    }
    write!(rmp::encode::write_array_len(&mut out, 6));
    write!(rmp::encode::write_uint(&mut out, 2));
    for id in [&options.vault_id, &options.record_id] {
        write!(rmp::encode::write_bin_len(&mut out, 16));
        write!(out.write_all(id));
    }
    write!(rmp::encode::write_array_len(&mut out, parents.len() as u32));
    for id in parents {
        write!(rmp::encode::write_bin_len(&mut out, 32));
        write!(out.write_all(&id));
    }
    write!(rmp::encode::write_map_len(&mut out, 2));
    write!(rmp::encode::write_str(&mut out, "epoch"));
    write!(rmp::encode::write_uint(&mut out, options.epoch));
    write!(rmp::encode::write_str(&mut out, "value_sizes"));
    write!(rmp::encode::write_array_len(&mut out, sizes.len() as u32));
    for &size in sizes {
        write!(rmp::encode::write_uint(&mut out, size));
    }
    write!(rmp::encode::write_uint(
        &mut out,
        u64::from(options.kind == EventKind::Deletion)
    ));
    scan(&out.bytes, HEADER_LIMITS)?;
    Ok(std::mem::take(&mut *out.bytes))
}
