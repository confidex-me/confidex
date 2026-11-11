//! Authenticated revision summaries. Full values are opened separately.
use super::*;
use confidex_vault::record::Entry;
use std::cmp::Reverse;

const PAGE: usize = 16;
const NAMES: usize = 8;
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Cursor {
    pub head: RevisionId,
    pub offset: usize,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Name {
    pub name: String,
    pub type_name: String,
}
impl Drop for Name {
    fn drop(&mut self) {
        self.name.zeroize();
        self.type_name.zeroize();
    }
}
#[derive(Default, Serialize, Deserialize)]
pub struct Changes {
    pub added: Vec<Name>,
    pub changed: Vec<Name>,
    pub removed: Vec<Name>,
    pub title: bool,
    pub tags: bool,
    pub order: bool,
    pub properties: bool,
    pub ambiguous: bool,
    pub omitted: bool,
}
#[derive(Serialize, Deserialize)]
pub struct Revision {
    pub revision: RevisionId,
    pub epoch: u64,
    pub created: bool,
    pub deleted: bool,
    pub merged: bool,
    pub changes: Changes,
}
#[derive(Serialize, Deserialize)]
pub struct Page {
    pub record: RecordId,
    pub head: RevisionId,
    pub revisions: Vec<Revision>,
    pub next: Option<Cursor>,
}
pub(super) struct Session {
    pub record: RecordId,
    pub head: RevisionId,
    order: Vec<RevisionId>,
}
impl Session {
    pub async fn load(
        store: &mut impl Store,
        vault: &lock::OpenedVault,
        record: RecordId,
        head: RevisionId,
    ) -> Result<Self, Error> {
        let graph = sync::graph(
            store,
            vault,
            &[Head {
                record,
                revision: head,
            }],
        )
        .await?;
        let mut children = BTreeMap::<RevisionId, usize>::new();
        let mut seen = BTreeSet::new();
        let mut pending = vec![head];
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            if seen.len() > 100_000 {
                return Err(Error::Storage(confidex_storage::Error::Limit));
            }
            children.entry(id).or_default();
            let node = graph.get(&id).ok_or(Error::Integrity)?;
            if node.record_id != record {
                return Err(Error::Integrity);
            }
            for parent in &node.parents {
                *children.entry(*parent).or_default() += 1;
                pending.push(*parent);
            }
        }
        let mut ready: BTreeSet<_> = children
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(id, _)| (Reverse(graph.get(id).unwrap().epoch), *id))
            .collect();
        let mut order = Vec::with_capacity(seen.len());
        while let Some((_, id)) = ready.pop_first() {
            order.push(id);
            for parent in &graph.get(&id).unwrap().parents {
                let count = children.get_mut(parent).ok_or(Error::Integrity)?;
                *count -= 1;
                if *count == 0 {
                    ready.insert((Reverse(graph.get(parent).unwrap().epoch), *parent));
                }
            }
        }
        if order.len() != seen.len() {
            return Err(Error::Integrity);
        }
        Ok(Self {
            record,
            head,
            order,
        })
    }
    pub fn contains(&self, id: RevisionId) -> bool {
        self.order.contains(&id)
    }
    pub async fn revision(
        &self,
        store: &mut impl Store,
        vault: &lock::OpenedVault,
        revision: RevisionId,
    ) -> Result<Output, Error> {
        if !self.contains(revision) {
            return Err(Error::Input);
        }
        let opened = open(store, vault, self.record, revision).await?;
        let draft = if opened.deleted {
            None
        } else {
            let fields = fields::read(&opened.record)?;
            Some(Draft {
                record: self.record,
                revision: Some(revision),
                title: title(&opened.record)?,
                sections: crate::sections::read(&opened.record, &fields),
                fields,
                tags: opened.record.tags.clone(),
            })
        };
        Ok(Output::Historical {
            record: self.record,
            revision,
            epoch: opened.epoch,
            draft,
        })
    }

    pub async fn page(
        &self,
        store: &mut impl Store,
        vault: &lock::OpenedVault,
        offset: usize,
    ) -> Result<Page, Error> {
        if offset >= self.order.len() {
            return Err(Error::Input);
        }
        let end = (offset + PAGE).min(self.order.len());
        let mut revisions = Vec::new();
        for id in &self.order[offset..end] {
            let opened = open(store, vault, self.record, *id).await?;

            let mut changes = Changes::default();
            if opened.parents.is_empty() {
                compare(&Record::default(), &opened.record, &mut changes);
            }
            for parent in &opened.parents {
                let previous = open(store, vault, self.record, *parent).await?;
                compare(&previous.record, &opened.record, &mut changes);
            }
            if opened.parents.len() > 1 {
                for name in changes.added.drain(..).chain(changes.removed.drain(..)) {
                    if !changes.changed.contains(&name) {
                        if changes.changed.len() < NAMES {
                            changes.changed.push(name);
                        } else {
                            changes.omitted = true;
                        }
                    }
                }
            }
            revisions.push(Revision {
                revision: *id,
                epoch: opened.epoch,
                created: opened.parents.is_empty(),
                deleted: opened.deleted,
                merged: opened.parents.len() > 1,
                changes,
            });
        }
        Ok(Page {
            record: self.record,
            head: self.head,
            revisions,
            next: (end < self.order.len()).then_some(Cursor {
                head: self.head,
                offset: end,
            }),
        })
    }
}
struct Opened {
    record: Record,
    parents: Vec<RevisionId>,
    epoch: u64,
    deleted: bool,
}
async fn open(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    record: RecordId,
    revision: RevisionId,
) -> Result<Opened, Error> {
    let wire = store
        .object(vault.vault_id(), revision)
        .await
        .map_err(|_| Error::Integrity)?;
    let opened = envelope::open(
        &wire,
        vault.keys(),
        vault.anchor(),
        Some(&revision),
        MAX_OPEN_MEMORY,
    )
    .map_err(|_| Error::Integrity)?;
    let header = opened.revision.header();
    if header.record_id != record {
        return Err(Error::Integrity);
    }
    Ok(Opened {
        parents: header.parents.clone(),
        epoch: header.metadata.epoch,
        deleted: header.kind == EventKind::Deletion,
        record: opened.record,
    })
}
fn group_key(entry: &Entry) -> (&str, &str) {
    if entry.name.trim().is_empty() {
        ("", &entry.type_name)
    } else {
        (&entry.name, "")
    }
}
fn groups(record: &Record) -> BTreeMap<(&str, &str), Vec<&Entry>> {
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    for entry in &record.entries {
        groups.entry(group_key(entry)).or_default().push(entry);
    }
    groups
}
fn same(a: &Entry, b: &Entry) -> bool {
    a.name == b.name && a.type_name == b.type_name && a.value == b.value && a.extra == b.extra
}
fn name(names: &mut Vec<Name>, key: (&str, &str), omitted: &mut bool) {
    let mut name = Name {
        name: key.0.chars().take(128).collect(),
        type_name: key.1.chars().take(128).collect(),
    };
    if key.0.chars().nth(128).is_some() {
        name.name.push('…');
        *omitted = true;
    }
    if key.1.chars().nth(128).is_some() {
        name.type_name.push('…');
        *omitted = true;
    }
    if !names.contains(&name) {
        if names.len() < NAMES {
            names.push(name);
        } else {
            *omitted = true;
        }
    }
}
fn compare(old: &Record, new: &Record, changes: &mut Changes) {
    let before = groups(old);
    let after = groups(new);
    for key in before
        .keys()
        .chain(after.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        match (before.get(&key), after.get(&key)) {
            (None, Some(_)) => name(&mut changes.added, key, &mut changes.omitted),
            (Some(_), None) => name(&mut changes.removed, key, &mut changes.omitted),
            (Some(a), Some(b))
                if a.len() != b.len() || !a.iter().zip(b).all(|(a, b)| same(a, b)) =>
            {
                name(&mut changes.changed, key, &mut changes.omitted);
                changes.ambiguous |= a.len() > 1 || b.len() > 1;
            }
            _ => (),
        }
    }
    changes.title |= old.extra.get(TITLE_KEY) != new.extra.get(TITLE_KEY);
    changes.tags |=
        old.tags.iter().collect::<BTreeSet<_>>() != new.tags.iter().collect::<BTreeSet<_>>();
    changes.order |= before.keys().eq(after.keys())
        && before
            .iter()
            .all(|(key, fields)| after[key].len() == fields.len())
        && !old
            .entries
            .iter()
            .map(group_key)
            .eq(new.entries.iter().map(group_key));
    changes.properties |= !old
        .extra
        .iter()
        .filter(|(key, _)| key.as_str() != TITLE_KEY)
        .eq(new
            .extra
            .iter()
            .filter(|(key, _)| key.as_str() != TITLE_KEY));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(name: &str, text: &str) -> Entry {
        Entry {
            name: name.into(),
            type_name: "password/v1".into(),
            value: BTreeMap::from([("password".into(), Value::from(text))]),
            extra: BTreeMap::new(),
        }
    }
    #[test]
    fn summaries_name_changes_without_returning_values_and_group_duplicate_names() {
        let old = Record {
            entries: vec![
                entry("password", "old private sentinel"),
                entry("removed", "removed private sentinel"),
            ],
            tags: Vec::new(),
            extra: BTreeMap::new(),
        };
        let mut new = Record {
            entries: vec![
                entry("password", "new private sentinel"),
                entry("api-key", "new api private sentinel"),
            ],
            tags: Vec::new(),
            extra: BTreeMap::new(),
        };
        new.tags.push("tag".into());
        new.extra.insert(TITLE_KEY.into(), Value::from("Title"));
        let mut changes = Changes::default();
        compare(&old, &new, &mut changes);
        assert_eq!(changes.changed[0].name, "password");
        assert_eq!(changes.added[0].name, "api-key");
        assert_eq!(changes.removed[0].name, "removed");
        assert!(changes.title && changes.tags && !changes.properties && !changes.ambiguous);
        let encoded = serde_json::to_string(&changes).unwrap();
        assert!(!encoded.contains("sentinel"));
        let a = Record {
            entries: vec![entry("same", "a"), entry("same", "b")],
            tags: Vec::new(),
            extra: BTreeMap::new(),
        };
        let b = Record {
            entries: vec![entry("same", "b"), entry("same", "a")],
            tags: Vec::new(),
            extra: BTreeMap::new(),
        };
        let mut changes = Changes::default();
        compare(&a, &b, &mut changes);
        assert!(changes.ambiguous && changes.changed.len() == 1);
        assert!(changes.added.is_empty() && changes.removed.is_empty());
        let before = Record {
            entries: vec![entry("note", "value")],
            tags: vec![],
            extra: BTreeMap::new(),
        };
        let mut after = Record {
            entries: vec![entry("note", "value")],
            tags: vec![],
            extra: BTreeMap::new(),
        };
        after.entries[0].type_name = "secure-note/v1".into();
        let mut changes = Changes::default();
        compare(&before, &after, &mut changes);
        assert_eq!(changes.changed.len(), 1);
        assert!(changes.added.is_empty() && changes.removed.is_empty() && !changes.order);
    }
    #[test]
    fn summaries_bound_names_and_include_opaque_values_and_reordering() {
        let mut old = Record {
            entries: (0..40).map(|i| entry(&format!("field{i}"), "a")).collect(),
            tags: Vec::new(),
            extra: BTreeMap::new(),
        };
        let mut new = Record {
            entries: (0..40).map(|i| entry(&format!("field{i}"), "b")).collect(),
            tags: Vec::new(),
            extra: BTreeMap::new(),
        };
        old.entries[0]
            .extra
            .insert("binary".into(), Value::Binary(vec![1]));
        new.entries[0]
            .extra
            .insert("binary".into(), Value::Binary(vec![2]));
        new.entries.reverse();
        let mut changes = Changes::default();
        compare(&old, &new, &mut changes);
        assert!(changes.order && changes.omitted);
        assert_eq!(changes.changed.len(), NAMES);
        let mut changes = Changes::default();
        compare(&new, &new, &mut changes);
        assert!(changes.changed.is_empty() && !changes.order);
        let mut names = Vec::new();
        let mut omitted = false;
        name(&mut names, (&"x".repeat(129), "password/v1"), &mut omitted);
        assert!(omitted && names[0].name.ends_with('…'));
    }
}
