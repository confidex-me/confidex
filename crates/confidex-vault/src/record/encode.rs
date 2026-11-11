use super::{CONTENT_LIMITS, EncodedContent, Entry, Error, MAX_ENTRIES, Mapping, Record, Value};
use std::io::{self, Write};
use zeroize::Zeroizing;

enum Field<'a> {
    Value(&'a Value),
    Text(&'a str),
    Map(&'a Mapping),
    Sized(&'a Mapping),
    Entries(&'a [Entry]),
    Tags(&'a [String]),
}
struct Buffer {
    data: Option<Zeroizing<Vec<u8>>>,
    len: usize,
}
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|n| *n <= CONTENT_LIMITS.bytes)
            .ok_or(io::ErrorKind::FileTooLarge)?;
        if let Some(data) = &mut self.data {
            if end > data.capacity() {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            data.extend_from_slice(bytes);
        }
        self.len = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) struct Encoder {
    buffer: Buffer,
    nodes: usize,
    slots: usize,
    sizes: Vec<u64>,
}
impl Encoder {
    pub fn new(data: Option<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            buffer: Buffer { data, len: 0 },
            nodes: CONTENT_LIMITS.nodes,
            slots: CONTENT_LIMITS.nodes / 2,
            sizes: Vec::new(),
        }
    }
    pub fn bytes(&self) -> usize {
        self.buffer.len
    }
    pub fn nodes(&self) -> usize {
        CONTENT_LIMITS.nodes - self.nodes
    }
    pub fn finish(self) -> EncodedContent {
        EncodedContent {
            bytes: self.buffer.data.unwrap(),
            value_sizes: self.sizes,
        }
    }
    fn node(&mut self, depth: usize) -> Result<(), Error> {
        if depth > CONTENT_LIMITS.depth {
            return Err(Error::Limit);
        }
        self.nodes = self.nodes.checked_sub(1).ok_or(Error::Limit)?;
        Ok(())
    }
    fn text(&mut self, text: &str, depth: usize, key: bool) -> Result<(), Error> {
        self.node(depth)?;
        if text.len() > CONTENT_LIMITS.string || (key && text.len() > CONTENT_LIMITS.key) {
            return Err(Error::Limit);
        }
        rmp::encode::write_str(&mut self.buffer, text).map_err(|_| Error::Limit)
    }
    fn mapping<'a>(
        &mut self,
        count: usize,
        rows: impl Iterator<Item = Result<(&'a str, Field<'a>), Error>>,
        depth: usize,
    ) -> Result<(), Error> {
        self.node(depth)?;
        if count > self.nodes / 2 {
            return Err(Error::Limit);
        }
        self.slots = self.slots.checked_sub(count).ok_or(Error::Limit)?;
        let mut ordered = Vec::new();
        ordered
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for row in rows {
            ordered.push(row?);
        }
        ordered.sort_unstable_by(|a, b| a.0.cmp(b.0));
        if ordered.windows(2).any(|p| p[0].0 == p[1].0) {
            return Err(Error::InvalidEncoding);
        }
        rmp::encode::write_map_len(&mut self.buffer, count as u32).map_err(|_| Error::Limit)?;
        for (key, value) in ordered {
            self.text(key, depth + 1, true)?;
            self.field(value, depth + 1)?;
        }
        self.slots += count;
        Ok(())
    }
    pub fn record(&mut self, record: &Record) -> Result<(), Error> {
        self.mapping(
            record.extra.len() + 2,
            record
                .extra
                .iter()
                .map(|(k, v)| Ok((k.as_str(), Field::Value(v))))
                .chain([
                    Ok(("entries", Field::Entries(&record.entries))),
                    Ok(("tags", Field::Tags(&record.tags))),
                ]),
            0,
        )
    }
    fn field(&mut self, field: Field<'_>, depth: usize) -> Result<(), Error> {
        match field {
            Field::Tags(tags) => {
                self.node(depth)?;
                let mut ordered = Vec::new();
                ordered
                    .try_reserve_exact(tags.len())
                    .map_err(|_| Error::Allocation)?;
                ordered.extend(tags.iter().map(String::as_str));
                ordered.sort_unstable();
                rmp::encode::write_array_len(&mut self.buffer, ordered.len() as u32)
                    .map_err(|_| Error::Limit)?;
                for tag in ordered {
                    self.text(tag, depth + 1, false)?;
                }
                Ok(())
            }
            Field::Text(s) => self.text(s, depth, false),
            Field::Map(map) => self.mapping(
                map.len(),
                map.iter().map(|(k, v)| Ok((k.as_str(), Field::Value(v)))),
                depth,
            ),
            Field::Sized(map) => {
                let start = self.bytes();
                self.field(Field::Map(map), depth)?;
                self.sizes.try_reserve(1).map_err(|_| Error::Allocation)?;
                self.sizes.push((self.bytes() - start) as u64);
                Ok(())
            }
            Field::Entries(entries) => {
                self.node(depth)?;
                if entries.len() > MAX_ENTRIES || entries.len() > self.nodes {
                    return Err(Error::Limit);
                }
                rmp::encode::write_array_len(&mut self.buffer, entries.len() as u32)
                    .map_err(|_| Error::Limit)?;
                for entry in entries {
                    self.mapping(
                        entry.extra.len() + 3,
                        entry
                            .extra
                            .iter()
                            .map(|(k, v)| Ok((k.as_str(), Field::Value(v))))
                            .chain(
                                [
                                    ("name", Field::Text(&entry.name)),
                                    ("type", Field::Text(&entry.type_name)),
                                    ("value", Field::Sized(&entry.value)),
                                ]
                                .into_iter()
                                .map(Ok),
                            ),
                        depth + 1,
                    )?;
                }
                Ok(())
            }
            Field::Value(value) => match value {
                Value::Array(values) => {
                    self.node(depth)?;
                    if values.len() > self.nodes {
                        return Err(Error::Limit);
                    }
                    rmp::encode::write_array_len(&mut self.buffer, values.len() as u32)
                        .map_err(|_| Error::Limit)?;
                    for v in values {
                        self.field(Field::Value(v), depth + 1)?;
                    }
                    Ok(())
                }
                Value::Map(rows) => self.mapping(
                    rows.len(),
                    rows.iter().map(|(k, v)| {
                        k.as_str()
                            .map(|k| (k, Field::Value(v)))
                            .ok_or(Error::InvalidEncoding)
                    }),
                    depth,
                ),
                Value::String(s) => {
                    self.text(s.as_str().ok_or(Error::InvalidEncoding)?, depth, false)
                }
                _ => {
                    self.node(depth)?;
                    if matches!(value, Value::Binary(v)|Value::Ext(_,v) if v.len()>CONTENT_LIMITS.binary)
                    {
                        return Err(Error::Limit);
                    }
                    rmpv::encode::write_value(&mut self.buffer, value).map_err(|_| Error::Limit)
                }
            },
        }
    }
}
