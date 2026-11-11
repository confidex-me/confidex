//! Section spans refer to positions in one revision. They do not identify fields.
use crate::{Error, Field};
use confidex_vault::record::{Record, Value};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub(crate) const KEY: &str = "confidex.sections";
const IMPORT_KEY: &str = "confidex.import.section";
pub const MAX_SECTIONS: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub source: Option<usize>,
    pub name: String,
    pub start: usize,
    pub count: usize,
}
impl Section {
    pub fn new(name: impl Into<String>, start: usize, count: usize) -> Self {
        Self {
            source: None,
            name: name.into(),
            start,
            count,
        }
    }
    pub fn end(&self) -> usize {
        self.start + self.count
    }
}
impl Drop for Section {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

fn one<'a>(map: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>, Error> {
    let mut found = map.iter().filter(|(name, _)| name.as_str() == Some(key));
    let value = found.next().map(|(_, value)| value);
    if found.next().is_some() {
        return Err(Error::Input);
    }
    Ok(value)
}
pub fn validate(sections: &[Section], fields: usize) -> Result<(), Error> {
    if sections.len() > MAX_SECTIONS {
        return Err(Error::Input);
    }
    let mut end = 0;
    for section in sections {
        let next = section
            .start
            .checked_add(section.count)
            .ok_or(Error::Input)?;
        if section.name.len() > 4096 || section.start < end || next > fields {
            return Err(Error::Input);
        }
        end = next;
    }
    Ok(())
}
#[derive(Clone, Copy)]
pub(crate) struct Span<'a> {
    pub source: usize,
    pub name: &'a str,
    pub start: usize,
    pub count: usize,
}
impl Span<'_> {
    pub fn end(self) -> usize {
        self.start + self.count
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Native<'a> {
    root: &'a [(Value, Value)],
    groups: &'a [Value],
}
impl<'a> Native<'a> {
    pub fn iter(self) -> impl Iterator<Item = Span<'a>> {
        self.groups
            .iter()
            .enumerate()
            .map(|(source, value)| span(source, value).expect("validated immutable sections"))
    }
    pub fn unknown(self) -> bool {
        self.root
            .iter()
            .any(|(key, _)| !matches!(key.as_str(), Some("version" | "groups")))
            || self.groups.iter().any(|group| {
                group
                    .as_map()
                    .unwrap()
                    .iter()
                    .any(|(key, _)| !matches!(key.as_str(), Some("name" | "start" | "count")))
            })
    }
}
fn span(source: usize, value: &Value) -> Result<Span<'_>, Error> {
    let map = value.as_map().ok_or(Error::Input)?;
    let number = |key| {
        one(map, key)?
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(Error::Input)
    };
    Ok(Span {
        source,
        name: one(map, "name")?
            .and_then(Value::as_str)
            .ok_or(Error::Input)?,
        start: number("start")?,
        count: number("count")?,
    })
}
pub(crate) fn native(record: &Record) -> Result<Option<Native<'_>>, Error> {
    let Some(value) = record.extra.get(KEY) else {
        return Ok(None);
    };
    let map = value.as_map().ok_or(Error::Input)?;
    if one(map, "version")?.and_then(Value::as_u64) != Some(1) {
        return Err(Error::Input);
    }
    let groups = one(map, "groups")?
        .and_then(Value::as_array)
        .ok_or(Error::Input)?;
    if groups.len() > MAX_SECTIONS {
        return Err(Error::Input);
    }
    let mut end = 0;
    for (source, value) in groups.iter().enumerate() {
        let section = span(source, value)?;
        let next = section
            .start
            .checked_add(section.count)
            .ok_or(Error::Input)?;
        if section.name.len() > 4096 || section.start < end || next > record.entries.len() {
            return Err(Error::Input);
        }
        end = next;
    }
    Ok(Some(Native { root: map, groups }))
}
fn decode(record: &Record) -> Result<Option<Vec<Section>>, Error> {
    Ok(native(record)?.map(|layout| {
        layout
            .iter()
            .map(|s| Section {
                source: Some(s.source),
                name: s.name.into(),
                start: s.start,
                count: s.count,
            })
            .collect()
    }))
}

pub(crate) fn read(record: &Record, fields: &[Field]) -> Option<Vec<Section>> {
    if let Some(mut sections) = decode(record).ok()? {
        let position = |entry| {
            fields
                .iter()
                .take_while(|field| field.source.is_some_and(|source| source < entry))
                .count()
        };
        for section in &mut sections {
            let end = position(section.end());
            section.start = position(section.start);
            section.count = end - section.start;
        }
        return Some(sections);
    }
    let mut sections: Vec<Section> = Vec::new();
    let mut previous = None;
    for (index, field) in fields.iter().enumerate() {
        let group = field
            .source
            .and_then(|source| record.entries.get(source))
            .and_then(|entry| entry.extra.get(IMPORT_KEY))
            .and_then(Value::as_map)
            .and_then(|map| {
                let title = one(map, "title").ok()??.as_str()?;
                if title.is_empty() || title.len() > 4096 {
                    return None;
                }
                let name = one(map, "name").ok()?.and_then(Value::as_str).unwrap_or("");
                Some((name, title))
            });
        if let Some(group) = group {
            if previous == Some(group) {
                sections.last_mut()?.count += 1;
            } else {
                sections.push(Section::new(group.1, index, 1));
            }
        }
        previous = group;
    }
    Some(sections)
}

fn set(map: &mut Vec<(Value, Value)>, key: &str, value: Value, retired: &mut Record) {
    if let Some((_, slot)) = map.iter_mut().find(|(name, _)| name.as_str() == Some(key)) {
        retired.extra.insert(
            retired.extra.len().to_string(),
            std::mem::replace(slot, value),
        );
    } else {
        map.push((key.into(), value));
    }
}
pub(crate) fn apply(
    record: &mut Record,
    sections: Option<&[Section]>,
    fields: usize,
) -> Result<(), Error> {
    let Some(sections) = sections else {
        return Ok(());
    };
    validate(sections, fields)?;
    let old = decode(record)?;
    let mut used = std::collections::BTreeSet::new();
    for source in sections.iter().filter_map(|section| section.source) {
        if source >= old.as_ref().map_or(0, Vec::len) || !used.insert(source) {
            return Err(Error::Input);
        }
    }
    if sections.is_empty()
        && old.is_none()
        && !record
            .entries
            .iter()
            .any(|entry| entry.extra.contains_key(IMPORT_KEY))
    {
        return Ok(());
    }
    let mut root = match record.extra.remove(KEY) {
        Some(Value::Map(map)) => map,
        None => vec![("version".into(), 1_u64.into())],
        _ => unreachable!("validated section metadata"),
    };
    let mut old_groups = match root
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some("groups"))
    {
        Some((_, Value::Array(groups))) => std::mem::take(groups),
        None => vec![],
        _ => unreachable!("validated section metadata"),
    };
    let mut retired = Record::default();
    let mut groups = Vec::with_capacity(sections.len());
    for section in sections {
        let mut group = match section.source {
            Some(index) => match std::mem::replace(&mut old_groups[index], Value::Nil) {
                Value::Map(map) => map,
                _ => unreachable!("validated section source"),
            },
            None => vec![],
        };
        set(
            &mut group,
            "name",
            Value::from(section.name.as_str()),
            &mut retired,
        );
        set(
            &mut group,
            "start",
            Value::from(section.start as u64),
            &mut retired,
        );
        set(
            &mut group,
            "count",
            Value::from(section.count as u64),
            &mut retired,
        );
        groups.push(Value::Map(group));
    }
    retired
        .extra
        .insert("old-groups".into(), Value::Array(old_groups));
    set(&mut root, "groups", Value::Array(groups), &mut retired);
    record.extra.insert(KEY.into(), Value::Map(root));
    Ok(())
}

pub fn remove_field(sections: &mut [Section], field: usize) {
    for section in sections {
        if field < section.start {
            section.start -= 1;
        } else if field < section.end() {
            section.count -= 1;
        }
    }
}
pub fn insert_field(sections: &mut [Section], field: usize, target: Option<usize>) {
    for (index, section) in sections.iter_mut().enumerate() {
        if target == Some(index) {
            section.count += 1;
        } else if field < section.start
            || field == section.start && target.is_none_or(|target| index > target)
        {
            section.start += 1;
        }
    }
}
pub fn move_field(sections: &mut [Section], from: usize, slot: usize, target: Option<usize>) {
    let at = slot.saturating_sub(usize::from(from < slot));
    let source = sections
        .iter()
        .position(|section| section.start <= from && from < section.end());
    if from == at && source == target {
        return;
    }
    remove_field(sections, from);
    insert_field(sections, at, target);
}

pub fn move_section(
    sections: &mut Vec<Section>,
    fields: usize,
    from: usize,
    to: usize,
) -> Result<Vec<usize>, Error> {
    let mut changed = sections.clone();
    let order = move_section_inner(&mut changed, fields, from, to)?;
    *sections = changed;
    Ok(order)
}
fn move_section_inner(
    sections: &mut Vec<Section>,
    fields: usize,
    from: usize,
    to: usize,
) -> Result<Vec<usize>, Error> {
    validate(sections, fields)?;
    if from >= sections.len() || to >= sections.len() {
        return Err(Error::Input);
    }
    let mut order: Vec<_> = (0..fields).collect();
    if from == to {
        return Ok(order);
    }
    let mut section = sections.remove(from);
    let destination = if from < to {
        sections[to - 1].end()
    } else {
        sections[to].start
    };
    let destination = destination - if from < to { section.count } else { 0 };
    let values: Vec<_> = order.drain(section.start..section.end()).collect();
    order.splice(destination..destination, values);
    for other in sections.iter_mut() {
        if other.start >= section.end() {
            other.start -= section.count;
        }
    }
    section.start = destination;
    sections.insert(to, section);
    let count = sections[to].count;
    for (index, other) in sections.iter_mut().enumerate() {
        if index != to && (other.start > destination || other.start == destination && index > to) {
            other.start += count;
        }
    }
    validate(sections, fields)?;
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields;
    use confidex_vault::resources::MAX_OPEN_MEMORY;

    fn record(count: usize) -> Record {
        let fields = (0..count)
            .map(|index| {
                let mut field = crate::field("text/v1").unwrap();
                field.name = format!("Field {index}");
                field
                    .values
                    .insert("text".into(), format!("Public {index}"));
                field
            })
            .collect::<Vec<_>>();
        let mut record = Record::default();
        fields::apply(&mut record, &fields).unwrap();
        record
    }
    fn roundtrip(record: &Record) -> Record {
        let content = record.encode_content(MAX_OPEN_MEMORY).unwrap();
        Record::decode_content(&content.bytes, MAX_OPEN_MEMORY)
            .unwrap()
            .record
    }
    #[test]
    fn empty_and_duplicate_sections_preserve_unknown_metadata_and_field_values() {
        let mut record = record(5);
        let sections = vec![Section::new("Same", 1, 2), Section::new("Same", 4, 0)];
        apply(&mut record, Some(&sections), 5).unwrap();
        let Value::Map(root) = record.extra.get_mut(KEY).unwrap() else {
            panic!("root");
        };
        root.push(("future-root".into(), Value::Binary(vec![11, 12])));
        let Value::Array(groups) = &mut root
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("groups"))
            .unwrap()
            .1
        else {
            panic!("groups");
        };
        let Value::Map(first) = &mut groups[0] else {
            panic!("first group");
        };
        first.push(("future-group".into(), Value::Binary(vec![21, 22])));
        record = roundtrip(&record);
        let fields = fields::read(&record).unwrap();
        let mut sections = read(&record, &fields).unwrap();
        assert_eq!(sections[0].source, Some(0));
        assert_eq!(sections[1].count, 0);
        let order = move_section(&mut sections, 5, 0, 1).unwrap();
        let fields = order
            .iter()
            .map(|&index| fields[index].clone())
            .collect::<Vec<_>>();
        sections[1].name = "Renamed".into();
        apply(&mut record, Some(&sections), 5).unwrap();
        fields::apply(&mut record, &fields).unwrap();
        record = roundtrip(&record);
        let restored = fields::read(&record).unwrap();
        assert_eq!(
            restored
                .iter()
                .map(|field| field.values["text"].as_str())
                .collect::<Vec<_>>(),
            ["Public 0", "Public 3", "Public 1", "Public 2", "Public 4"]
        );
        let root = record.extra[KEY].as_map().unwrap();
        assert_eq!(
            one(root, "future-root").unwrap(),
            Some(&Value::Binary(vec![11, 12]))
        );
        let groups = one(root, "groups").unwrap().unwrap().as_array().unwrap();
        assert_eq!(
            one(groups[1].as_map().unwrap(), "future-group").unwrap(),
            Some(&Value::Binary(vec![21, 22]))
        );
        let mut sections = read(&record, &restored).unwrap();
        sections.remove(1);
        apply(&mut record, Some(&sections), 5).unwrap();
        assert_eq!(fields::read(&record).unwrap().len(), 5);
    }
    #[test]
    fn imported_groups_survive_renames_and_explicit_ungrouping() {
        let mut record = record(3);
        for entry in &mut record.entries[1..] {
            entry.extra.insert(
                IMPORT_KEY.into(),
                Value::Map(vec![
                    ("name".into(), "source-section".into()),
                    ("title".into(), "Imported".into()),
                    ("field_id".into(), "opaque-source-id".into()),
                ]),
            );
        }
        let fields = fields::read(&record).unwrap();
        let mut sections = read(&record, &fields).unwrap();
        assert_eq!(sections, [Section::new("Imported", 1, 2)]);
        sections[0].name = "Changed".into();
        apply(&mut record, Some(&sections), 3).unwrap();
        fields::apply(&mut record, &fields).unwrap();
        assert_eq!(
            read(&record, &fields::read(&record).unwrap()).unwrap()[0].name,
            "Changed"
        );
        apply(&mut record, Some(&[]), 3).unwrap();
        assert!(
            read(&record, &fields::read(&record).unwrap())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            record.entries[1].extra[IMPORT_KEY].as_map().unwrap().len(),
            3
        );
    }
    #[test]
    fn unsupported_and_invalid_layout_is_preserved_without_normalizing_it() {
        let mut record = record(2);
        for value in [
            Value::Binary(vec![7]),
            Value::Map(vec![("version".into(), 2_u64.into())]),
        ] {
            record.extra.insert(KEY.into(), value.clone());
            let fields = fields::read(&record).unwrap();
            assert!(read(&record, &fields).is_none());
            apply(&mut record, None, 2).unwrap();
            fields::apply(&mut record, &fields).unwrap();
            assert_eq!(record.extra[KEY], value);
            assert_eq!(apply(&mut record, Some(&[]), 2), Err(Error::Input));
            assert_eq!(record.extra[KEY], value);
        }
        record.extra.remove(KEY);
        assert!(apply(&mut record, Some(&[Section::new("Bad", usize::MAX, 1)]), 2).is_err());
        assert!(!record.extra.contains_key(KEY));
    }
    #[test]
    fn legacy_expansion_maps_section_spans_to_current_field_positions() {
        let mut record = Record::default();
        record.entries.push(confidex_vault::record::Entry {
            name: "Legacy".into(),
            type_name: "login/v1".into(),
            value: [
                ("username".into(), "user".into()),
                ("password".into(), "public".into()),
            ]
            .into(),
            extra: Default::default(),
        });
        apply(
            &mut record,
            Some(&[Section::new("Account", 0, 1), Section::new("Empty", 1, 0)]),
            1,
        )
        .unwrap();
        let fields = fields::read(&record).unwrap();
        let sections = read(&record, &fields).unwrap();
        assert_eq!(
            (sections[0].start, sections[0].count, sections[1].start),
            (0, 3, 3)
        );
        apply(&mut record, Some(&sections), fields.len()).unwrap();
        fields::apply(&mut record, &fields).unwrap();
        assert_eq!(record.entries.len(), 3);
        let restored = read(&record, &fields::read(&record).unwrap()).unwrap();
        assert_eq!(restored[0].count, 3);
        assert_eq!(restored[1].count, 0);
    }
    #[test]
    fn field_moves_follow_the_destination_group_and_keep_empty_groups() {
        let mut sections = vec![Section::new("A", 1, 2), Section::new("B", 4, 1)];
        move_field(&mut sections, 1, 5, Some(1));
        assert_eq!((sections[0].start, sections[0].count), (1, 1));
        assert_eq!((sections[1].start, sections[1].count), (3, 2));
        remove_field(&mut sections, 1);
        assert_eq!(sections[0].count, 0);
        insert_field(&mut sections, 1, Some(0));
        assert_eq!(sections[0].count, 1);
        validate(&sections, 6).unwrap();
    }
    #[test]
    fn section_reorders_preserve_every_field_and_reject_invalid_moves_atomically() {
        for start in 0..=4 {
            for count in 0..=4 - start {
                for next in start + count..=4 {
                    for tail in 0..=4 - next {
                        let original = vec![
                            Section::new("Same", start, count),
                            Section::new("Same", next, tail),
                        ];
                        for (from, to) in [(0, 1), (1, 0)] {
                            let mut sections = original.clone();
                            let mut order = move_section(&mut sections, 4, from, to).unwrap();
                            validate(&sections, 4).unwrap();
                            order.sort_unstable();
                            assert_eq!(order, [0, 1, 2, 3]);
                            let before = sections.clone();
                            assert!(move_section(&mut sections, 4, 0, 2).is_err());
                            assert_eq!(sections, before);
                        }
                    }
                }
            }
        }
    }
}
