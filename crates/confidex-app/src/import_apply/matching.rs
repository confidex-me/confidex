use super::origin::{Fingerprint, Origin};
use confidex_storage::Head;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Match {
    New,
    Duplicate,
    Conflict,
    RepeatedSource { first: usize },
    RepeatedContent { first: usize },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub head: Head,
    pub deleted: bool,
    pub source_changed: bool,
    pub local_changed: bool,
}

pub(super) struct Existing {
    pub head: Head,
    pub deleted: bool,
    pub current: Fingerprint,
    pub origin: Option<Origin>,
}
#[derive(Default)]
pub(super) struct Catalog {
    pub records: Vec<Existing>,
    sources: BTreeMap<Fingerprint, Vec<usize>>,
    contents: BTreeMap<Fingerprint, Vec<usize>>,
}
impl Catalog {
    pub fn push(&mut self, record: Existing) {
        let index = self.records.len();
        if let Some(origin) = &record.origin {
            if let Some(source) = &origin.source {
                self.sources.entry(source.clone()).or_default().push(index);
            }
            if origin.content != record.current {
                self.contents
                    .entry(origin.content.clone())
                    .or_default()
                    .push(index);
            }
        }
        self.contents
            .entry(record.current.clone())
            .or_default()
            .push(index);
        self.records.push(record);
    }

    pub fn indices(&self, item: &Origin) -> &[usize] {
        if let Some(source) = &item.source {
            self.sources.get(source)
        } else {
            self.contents.get(&item.content)
        }
        .map(Vec::as_slice)
        .unwrap_or_default()
    }

    pub fn candidate(&self, index: usize, item: &Origin) -> Candidate {
        let record = &self.records[index];
        Candidate {
            head: record.head.clone(),
            deleted: record.deleted,
            source_changed: record
                .origin
                .as_ref()
                .is_some_and(|o| o.original != item.original),
            local_changed: record
                .origin
                .as_ref()
                .is_some_and(|o| o.content != record.current),
        }
    }

    pub fn classify(&self, item: &Origin) -> (Match, Option<Head>) {
        let indices = self.indices(item);
        if indices.is_empty() {
            return (Match::New, None);
        }
        for &index in indices {
            let candidate = self.candidate(index, item);
            if !candidate.deleted && !candidate.source_changed && !candidate.local_changed {
                return (Match::Duplicate, Some(candidate.head));
            }
        }
        (Match::Conflict, None)
    }

    pub fn contains(&self, item: &Origin, head: &Head) -> bool {
        self.indices(item)
            .iter()
            .any(|&index| self.records[index].head == *head)
    }
}

#[derive(Default)]
pub(super) struct Repeated {
    sources: BTreeMap<Fingerprint, usize>,
    contents: BTreeMap<Fingerprint, usize>,
}
impl Repeated {
    pub fn check(&mut self, item: &Origin, index: usize) -> Option<Match> {
        let (map, key) = if let Some(source) = &item.source {
            (&mut self.sources, source)
        } else {
            (&mut self.contents, &item.content)
        };
        if let Some(&first) = map.get(key) {
            Some(if item.source.is_some() {
                Match::RepeatedSource { first }
            } else {
                Match::RepeatedContent { first }
            })
        } else {
            map.insert(key.clone(), index);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item(source: Option<u8>, original: u8, content: u8) -> Origin {
        Origin {
            source: source.map(|n| Fingerprint([n; 32])),
            original: Fingerprint([original; 32]),
            content: Fingerprint([content; 32]),
        }
    }
    fn existing(id: u8, deleted: bool, current: u8, origin: Option<Origin>) -> Existing {
        Existing {
            head: Head {
                record: [id; 16],
                revision: [id; 32],
            },
            deleted,
            current: Fingerprint([current; 32]),
            origin,
        }
    }
    #[test]
    fn scoped_identity_does_not_merge_distinct_accounts_with_identical_content() {
        let mut catalog = Catalog::default();
        catalog.push(existing(1, false, 3, Some(item(Some(1), 2, 3))));
        assert_eq!(catalog.classify(&item(Some(1), 2, 3)).0, Match::Duplicate);
        assert_eq!(catalog.classify(&item(Some(9), 2, 3)).0, Match::New);
        assert_eq!(catalog.classify(&item(None, 2, 3)).0, Match::Duplicate);
        assert_eq!(catalog.classify(&item(Some(1), 8, 3)).0, Match::Conflict);
        catalog.records[0].current = Fingerprint([8; 32]);
        assert_eq!(catalog.classify(&item(Some(1), 2, 3)).0, Match::Conflict);
        let candidate = catalog.candidate(0, &item(Some(1), 2, 3));
        assert!(candidate.local_changed && !candidate.source_changed);
    }
    #[test]
    fn deleted_records_and_weak_identity_local_edits_require_explicit_resolution() {
        let mut catalog = Catalog::default();
        catalog.push(existing(1, false, 9, Some(item(None, 2, 3))));
        assert_eq!(catalog.classify(&item(None, 2, 3)).0, Match::Conflict);
        assert_eq!(catalog.classify(&item(None, 2, 9)).0, Match::Conflict);
        catalog.push(existing(2, true, 3, Some(item(Some(4), 2, 3))));
        assert_eq!(catalog.classify(&item(Some(4), 2, 3)).0, Match::Conflict);
        assert!(catalog.candidate(1, &item(Some(4), 2, 3)).deleted);
        catalog.push(existing(3, false, 3, None));
        assert_eq!(catalog.classify(&item(None, 2, 3)).0, Match::Duplicate);
    }
    #[test]
    fn exact_copy_makes_reimport_idempotent_without_hiding_changed_copies() {
        let mut catalog = Catalog::default();
        catalog.push(existing(1, false, 9, Some(item(Some(1), 2, 3))));
        catalog.push(existing(2, false, 3, Some(item(Some(1), 2, 3))));
        let incoming = item(Some(1), 2, 3);
        assert_eq!(catalog.classify(&incoming).1.unwrap().record, [2; 16]);
        assert_eq!(catalog.indices(&incoming).len(), 2);
        assert!(catalog.contains(&incoming, &catalog.records[0].head));
        assert!(!catalog.contains(&item(Some(9), 2, 3), &catalog.records[0].head));
        assert_eq!(catalog.classify(&item(Some(1), 8, 3)).0, Match::Conflict);
    }
    #[test]
    fn repeated_plan_ids_and_weak_content_are_reported_without_quadratic_pairs() {
        let mut repeated = Repeated::default();
        assert!(repeated.check(&item(Some(1), 2, 3), 0).is_none());
        assert_eq!(
            repeated.check(&item(Some(1), 9, 9), 1),
            Some(Match::RepeatedSource { first: 0 })
        );
        assert!(repeated.check(&item(Some(2), 2, 3), 2).is_none());
        assert!(repeated.check(&item(None, 2, 3), 3).is_none());
        assert_eq!(
            repeated.check(&item(None, 9, 3), 4),
            Some(Match::RepeatedContent { first: 3 })
        );
    }
    #[test]
    fn ten_thousand_source_keys_keep_their_own_targets_and_exact_copies() {
        let mut catalog = Catalog::default();
        for id in 0u64..10_000 {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&id.to_be_bytes());
            let mut record_id = [0; 16];
            record_id[..8].copy_from_slice(&id.to_be_bytes());
            catalog.push(Existing {
                head: Head {
                    record: record_id,
                    revision: key,
                },
                deleted: false,
                current: Fingerprint([7; 32]),
                origin: Some(Origin {
                    source: Some(Fingerprint(key)),
                    original: Fingerprint([8; 32]),
                    content: Fingerprint([7; 32]),
                }),
            });
        }
        let mut repeated = Repeated::default();
        for (index, existing) in catalog.records.iter().enumerate() {
            let incoming = existing.origin.as_ref().unwrap();
            assert!(repeated.check(incoming, index).is_none());
            let (kind, target) = catalog.classify(incoming);
            assert_eq!(kind, Match::Duplicate);
            assert_eq!(target.as_ref(), Some(&existing.head));
            assert_eq!(catalog.indices(incoming).len(), 1);
        }
        let incoming = catalog.records[0].origin.as_ref().unwrap();
        for index in 10_000..20_000 {
            assert_eq!(
                repeated.check(incoming, index),
                Some(Match::RepeatedSource { first: 0 })
            );
        }
    }
}
