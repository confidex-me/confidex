use super::Error;
use crate::import::{Memory, Reservation};
use confidex_vault::record::{Entry, Mapping, Record, Value};
use std::mem::size_of;

pub(crate) struct Owned {
    pub record: Record,
    _memory: Reservation,
}
impl Owned {
    // The core decoder admits its allocation first; retain that charge for later operations.
    pub fn new(record: Record, memory: &Memory) -> Result<Self, Error> {
        let bytes = resident(&record).ok_or(Error::Limit)?;
        Ok(Self {
            record,
            _memory: memory.reserve(bytes)?,
        })
    }
}

fn resident(record: &Record) -> Option<usize> {
    let mut bytes =
        4096usize.checked_add(record.entries.capacity().checked_mul(size_of::<Entry>())?)?;
    bytes = bytes.checked_add(record.tags.capacity().checked_mul(size_of::<String>())?)?;
    for tag in &record.tags {
        bytes = bytes.checked_add(tag.capacity())?;
    }
    bytes = bytes.checked_add(mapping(&record.extra)?)?;
    for entry in &record.entries {
        bytes = bytes
            .checked_add(entry.name.capacity())?
            .checked_add(entry.type_name.capacity())?;
        bytes = bytes
            .checked_add(mapping(&entry.value)?)?
            .checked_add(mapping(&entry.extra)?)?;
    }
    Some(bytes)
}
fn mapping(map: &Mapping) -> Option<usize> {
    // Include BTreeMap node slack, keys and values instead of counting only payload bytes.
    let mut bytes = map.len().checked_mul(256)?;
    for (key, item) in map {
        bytes = bytes
            .checked_add(key.capacity())?
            .checked_add(value(item)?)?;
    }
    Some(bytes)
}
fn value(item: &Value) -> Option<usize> {
    match item {
        Value::String(text) => text.as_bytes().len().checked_mul(2),
        Value::Binary(bytes) | Value::Ext(_, bytes) => Some(bytes.capacity()),
        Value::Array(items) => {
            let mut bytes = items.capacity().checked_mul(size_of::<Value>())?;
            for item in items {
                bytes = bytes.checked_add(value(item)?)?;
            }
            Some(bytes)
        }
        Value::Map(items) => {
            let mut bytes = items
                .capacity()
                .checked_mul(size_of::<(Value, Value)>())?
                .max(items.len().checked_mul(256)?);
            for (key, item) in items {
                bytes = bytes.checked_add(value(key)?)?.checked_add(value(item)?)?;
            }
            Some(bytes)
        }
        _ => Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resident_values_share_the_plan_budget_until_drop() {
        let memory = Memory::new(32 << 10);
        let mut record = Record::default();
        record
            .extra
            .insert("binary".into(), Value::Binary(vec![9; 8192]));
        record.extra.insert(
            "nested".into(),
            Value::Map(vec![(
                "key".into(),
                Value::Array(vec!["public fixture".into()]),
            )]),
        );
        let before = memory.available();
        let owned = Owned::new(record, &memory).unwrap();
        assert!(before - memory.available() >= 8192 + 4096);
        assert_eq!(owned.record.extra.len(), 2);
        assert!(memory.reserve(before).is_err());
        drop(owned);
        assert_eq!(before, memory.available());
    }
}
