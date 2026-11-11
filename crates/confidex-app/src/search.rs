//! A session index of authenticated, searchable record content.
use super::{Error, Summary, field_protected, title};
use confidex_storage::{Head, PAGE_SIZE, RecordId, RevisionId, Store};
use confidex_vault::{envelope, lock, record::Record, resources::MAX_OPEN_MEMORY};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(target_arch = "wasm32", test))]
mod memory;
#[cfg(not(target_arch = "wasm32"))]
mod sqlite;
#[cfg(target_arch = "wasm32")]
use memory::Backend;
#[cfg(not(target_arch = "wasm32"))]
use sqlite::Backend;

type Id = [u8; 48];
fn id(head: &Head) -> Id {
    let mut bytes = [0; 48];
    bytes[..16].copy_from_slice(&head.record);
    bytes[16..].copy_from_slice(&head.revision);
    bytes
}
const BATCH: usize = 16;
const MAX_RECORDS: usize = 100_000;
const MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;
const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn query_terms(text: &str) -> Result<Zeroizing<Vec<String>>, Error> {
    if text.len() > 4096 {
        return Err(Error::Input);
    }
    let terms = words(text);
    if terms.len() > 32 {
        return Err(Error::Input);
    }
    Ok(terms)
}
fn words(text: &str) -> Zeroizing<Vec<String>> {
    let lower = Zeroizing::new(text.to_lowercase());
    Zeroizing::new(
        lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|word| !word.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}
fn record_terms(record: &Record) -> Result<Zeroizing<Vec<String>>, Error> {
    let mut text = Zeroizing::new(title(record)?);
    for tag in &record.tags {
        text.push('\n');
        text.push_str(tag);
    }
    for entry in &record.entries {
        if field_protected(entry) {
            continue;
        }
        let key = match entry.type_name.as_str() {
            "login/v1" | "api_key/v1" | "url/v1" => "url",
            "note/v1" | "text/v1" => "text",
            _ => continue,
        };
        if let Some(value) = entry.value.get(key).and_then(|v| v.as_str()) {
            text.push('\n');
            text.push_str(value);
        }
    }
    let mut terms = words(&text);
    terms.sort_unstable();
    terms.dedup_by(|a, b| {
        if a == b {
            a.zeroize();
            true
        } else {
            false
        }
    });
    Ok(terms)
}

struct Cached {
    summary: Summary,
    bytes: usize,
}
pub(super) struct Index {
    backend: Backend,
    records: BTreeMap<Id, Cached>,
    seen: BTreeSet<Id>,
    checked: BTreeSet<RecordId>,
    cursor: Option<Head>,
    bytes: usize,
    ready: bool,
}
impl Index {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            backend: Backend::new()?,
            records: BTreeMap::new(),
            seen: BTreeSet::new(),
            checked: BTreeSet::new(),
            cursor: None,
            bytes: 0,
            ready: false,
        })
    }
    pub fn invalidate(&mut self) {
        self.ready = false;
        self.cursor = None;
        self.seen.clear();
        self.checked.clear();
    }
    fn remove(&mut self, id: Id) -> Result<(), Error> {
        self.backend.remove(id)?;
        if let Some(old) = self.records.remove(&id) {
            self.bytes -= old.bytes;
        }
        Ok(())
    }
    fn replace(&mut self, head: Head, record: &Record) -> Result<(), Error> {
        if !self.records.contains_key(&id(&head)) && self.records.len() >= MAX_RECORDS {
            return Err(Error::Storage(confidex_storage::Error::Limit));
        }
        let terms = record_terms(record)?;
        let summary = Summary {
            head: head.clone(),
            title: title(record)?,
            fields: super::fields::count(record),
            tags: record.tags.clone(),
        };
        // Reserve space for dictionary nodes, reverse terms, postings, and summaries.
        let bytes = 256
            + summary.title.len()
            + summary.tags.iter().map(|t| t.len() + 32).sum::<usize>()
            + terms.iter().map(|word| word.len() * 2 + 128).sum::<usize>();
        let old = self
            .records
            .get(&id(&head))
            .map_or(0, |cached| cached.bytes);
        if self.bytes - old + bytes > MAX_INDEX_BYTES {
            return Err(Error::Storage(confidex_storage::Error::Limit));
        }
        self.backend.replace(id(&head), &terms)?;
        self.records.insert(id(&head), Cached { summary, bytes });
        self.bytes = self.bytes - old + bytes;
        Ok(())
    }
    pub fn changed(
        &mut self,
        head: Head,
        record: Option<&Record>,
        retired: &[RevisionId],
    ) -> Result<(), Error> {
        for &revision in retired {
            self.remove(id(&Head {
                record: head.record,
                revision,
            }))?;
        }
        if let Some(record) = record {
            self.replace(head, record)?;
        } else {
            self.remove(id(&head))?;
        }
        if !self.ready {
            self.invalidate();
        }
        Ok(())
    }
    pub async fn step(
        &mut self,
        store: &mut impl Store,
        vault: &lock::OpenedVault,
    ) -> Result<bool, Error> {
        if self.ready {
            return Ok(true);
        }
        let heads = store
            .branch_heads(vault.vault_id(), self.cursor.as_ref(), None)
            .await?;
        if heads.len() > PAGE_SIZE
            || heads.windows(2).any(|pair| id(&pair[0]) >= id(&pair[1]))
            || heads.first().is_some_and(|head| {
                self.cursor
                    .as_ref()
                    .is_some_and(|cursor| id(head) <= id(cursor))
            })
        {
            return Err(Error::Integrity);
        }
        for head in heads.iter().take(BATCH) {
            self.seen.insert(id(head));
            if self.seen.len() > MAX_RECORDS {
                return Err(Error::Input);
            }
            if self
                .records
                .get(&id(head))
                .is_some_and(|cached| cached.summary.head == *head)
            {
                self.cursor = Some(head.clone());
                continue;
            }
            if self.checked.insert(head.record) {
                let lower = id(&Head {
                    record: head.record,
                    revision: [0; 32],
                });
                let upper = id(&Head {
                    record: head.record,
                    revision: [255; 32],
                });
                if self.records.range(lower..=upper).next().is_some() {
                    let current: BTreeSet<_> =
                        super::record_heads(store, vault.vault_id(), head.record)
                            .await?
                            .iter()
                            .map(id)
                            .collect();
                    let stale: Vec<_> = self
                        .records
                        .range(lower..=upper)
                        .filter(|(key, _)| !current.contains(*key))
                        .map(|(key, _)| *key)
                        .collect();
                    for key in stale {
                        self.remove(key)?;
                    }
                }
            }
            let wire = store.object(vault.vault_id(), head.revision).await?;
            let opened = envelope::open(
                &wire,
                vault.keys(),
                vault.anchor(),
                Some(&head.revision),
                MAX_OPEN_MEMORY,
            )
            .map_err(|_| Error::Integrity)?;
            if opened.revision.header().record_id != head.record {
                return Err(Error::Integrity);
            }
            if opened.revision.header().kind == envelope::EventKind::Deletion {
                self.remove(id(head))?;
            } else {
                self.replace(head.clone(), &opened.record)?;
            }
            self.cursor = Some(head.clone());
        }
        if heads.len() > BATCH {
            return Ok(false);
        }
        let removed: Vec<_> = self
            .records
            .keys()
            .filter(|id| !self.seen.contains(*id))
            .copied()
            .collect();
        for id in removed {
            self.remove(id)?;
        }
        self.ready = true;
        self.seen.clear();
        self.checked.clear();
        Ok(true)
    }
    pub fn rows(
        &self,
        query: &str,
        after: Option<Head>,
        tag: Option<&str>,
    ) -> Result<(Vec<Summary>, bool, Option<Head>), Error> {
        let after = after.as_ref().map(id);
        let terms = query_terms(query)?;
        let ids = if query.is_empty() {
            self.records.keys().copied().collect()
        } else if terms.is_empty() {
            Vec::new()
        } else {
            self.backend.search(&terms)?
        };
        let mut rows = Vec::new();
        let mut bytes = 0;
        let mut more = false;
        for id in ids {
            if after.is_some_and(|after| id <= after) {
                continue;
            }
            let cached = self.records.get(&id).ok_or(Error::Integrity)?;
            if tag.is_some_and(|tag| !cached.summary.tags.iter().any(|t| t == tag)) {
                continue;
            }
            // JSON can use six bytes for one control byte in a title or tag.
            let row_bytes = 512
                + cached.summary.title.len() * 6
                + cached
                    .summary
                    .tags
                    .iter()
                    .map(|tag| tag.len() * 6 + 4)
                    .sum::<usize>();
            if row_bytes > MAX_PAGE_BYTES {
                return Err(Error::Storage(confidex_storage::Error::Limit));
            }
            if rows.len() == PAGE_SIZE || bytes + row_bytes > MAX_PAGE_BYTES {
                more = true;
                break;
            }
            bytes += row_bytes;
            rows.push(cached.summary.clone());
        }
        let next = rows.last().map(|row| row.head.clone());
        Ok((rows, more, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidex_vault::record::{Entry, Mapping, Value};
    #[test]
    fn large_summary_pages_stay_inside_the_browser_response_budget() {
        let mut index = Index::new().unwrap();
        for id in 1..=50u8 {
            let summary = Summary {
                head: Head {
                    record: [id; 16],
                    revision: [id; 32],
                },
                title: "\n".repeat(4096),
                fields: 1,
                tags: (0..256)
                    .map(|tag| format!("{tag:03}{}", "\n".repeat(253)))
                    .collect(),
            };
            index
                .records
                .insert(super::id(&summary.head), Cached { summary, bytes: 0 });
        }
        let (first, more, next) = index.rows("", None, None).unwrap();
        assert!(more && !first.is_empty() && first.len() < PAGE_SIZE);
        assert!(serde_json::to_vec(&first).unwrap().len() < MAX_PAGE_BYTES);
        let (second, _, _) = index.rows("", next, None).unwrap();
        assert!(second[0].head.record > first.last().unwrap().head.record);
    }
    #[test]
    fn backend_parity_after_replace_delete_and_unordered_ids() {
        let mut sql = sqlite::Backend::new().unwrap();
        let mut memory = memory::Backend::new().unwrap();
        for (id, text) in [
            (9, "GitHub account"),
            (2, "café account"),
            (7, "резервная копия"),
            (3, "github deploy"),
            (8, "𞤀𞤁𞤂 account"),
        ] {
            let words = words(text);
            sql.replace([id; 48], &words).unwrap();
            memory.replace([id; 48], &words).unwrap();
        }
        for query in [
            "g",
            "github",
            "github depl",
            "РЕЗЕРВНАЯ КОП",
            "café",
            "account",
            "missing",
            "github OR account",
            "𞤀𞤁",
        ] {
            let terms = query_terms(query).unwrap();
            assert_eq!(
                sql.search(&terms).unwrap(),
                memory.search(&terms).unwrap(),
                "{query}"
            );
        }
        sql.replace([9; 48], &words("replaced")).unwrap();
        memory.replace([9; 48], &words("replaced")).unwrap();
        sql.remove([3; 48]).unwrap();
        memory.remove([3; 48]).unwrap();
        for query in ["github", "repl", "account"] {
            let terms = query_terms(query).unwrap();
            assert_eq!(sql.search(&terms).unwrap(), memory.search(&terms).unwrap());
        }
        assert!(memory.search(&words("github")).unwrap().is_empty());
        assert!(query_terms(&"x".repeat(4097)).is_err());
        assert!(query_terms(&"x ".repeat(33)).is_err());
    }
    #[test]
    fn atomic_values_follow_the_same_search_and_protection_policy() {
        let mut record = Record::default();
        for (kind, key, marker) in [
            ("url/v1", "url", "urlmarker"),
            ("text/v1", "text", "textmarker"),
            ("note/v1", "text", "notemarker"),
            ("secure-note/v1", "text", "securemarker"),
            ("username/v1", "username", "usermarker"),
            ("secret/v1", "secret", "secretmarker"),
            ("password/v1", "password", "passwordmarker"),
        ] {
            record.entries.push(Entry {
                name: "fieldname".into(),
                type_name: kind.into(),
                value: Mapping::from_iter([(key.into(), Value::from(marker))]),
                extra: Mapping::new(),
            });
        }
        assert_eq!(
            record_terms(&record).unwrap(),
            words("notemarker textmarker urlmarker")
        );
        for metadata in [
            Value::Map(vec![("protected".into(), true.into())]),
            Value::from("malformed"),
            Value::Map(vec![
                ("protected".into(), false.into()),
                ("protected".into(), false.into()),
            ]),
        ] {
            for entry in &mut record.entries {
                entry.extra.insert("metadata".into(), metadata.clone());
            }
            assert!(record_terms(&record).unwrap().is_empty());
        }
    }
    #[test]
    fn indexes_only_allowed_values_and_fails_closed_on_bad_protection() {
        let mut record = Record::default();
        record
            .extra
            .insert(super::super::TITLE_KEY.into(), Value::from("heading"));
        record.tags.push("work".into());
        for kind in ["login/v1", "api_key/v1", "unknown/v1", "note/v1"] {
            record.entries.push(Entry {
                name: "excludedname".into(),
                type_name: kind.into(),
                value: Mapping::from_iter([
                    ("url".into(), Value::from("https://allowed.example.test")),
                    ("text".into(), Value::from("publicnote")),
                    ("password".into(), Value::from("excludedpassword")),
                    ("secret".into(), Value::from("excludedkey")),
                ]),
                extra: Mapping::new(),
            });
        }
        let terms = record_terms(&record).unwrap();
        for word in ["heading", "work", "allowed", "publicnote"] {
            assert!(terms.iter().any(|t| t == word));
        }
        assert!(!terms.iter().any(|t| t.starts_with("excluded")));
        for marker in [Value::Boolean(true), Value::from("bad")] {
            record.entries[3].extra.insert(
                "metadata".into(),
                Value::Map(vec![(Value::from("protected"), marker)]),
            );
            assert!(
                !record_terms(&record)
                    .unwrap()
                    .iter()
                    .any(|t| t == "publicnote")
            );
        }
    }
}
