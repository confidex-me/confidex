use super::{Error, Id};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Default)]
pub(super) struct Backend {
    terms: BTreeMap<String, Vec<Id>>,
    records: BTreeMap<Id, Vec<String>>,
}
impl Backend {
    pub fn new() -> Result<Self, Error> {
        Ok(Self::default())
    }
    pub fn remove(&mut self, id: Id) -> Result<(), Error> {
        if let Some(mut words) = self.records.remove(&id) {
            for word in &words {
                if let Some(ids) = self.terms.get_mut(word) {
                    if let Ok(pos) = ids.binary_search(&id) {
                        ids.remove(pos);
                    }
                    if ids.is_empty()
                        && let Some((mut word, _)) = self.terms.remove_entry(word)
                    {
                        word.zeroize();
                    }
                }
            }
            words.zeroize();
        }
        Ok(())
    }
    pub fn replace(&mut self, id: Id, terms: &[String]) -> Result<(), Error> {
        self.remove(id)?;
        for term in terms {
            let ids = self.terms.entry(term.clone()).or_default();
            if let Err(pos) = ids.binary_search(&id) {
                ids.insert(pos, id);
            }
        }
        self.records.insert(id, terms.to_vec());
        Ok(())
    }
    pub fn search(&self, terms: &[String]) -> Result<Vec<Id>, Error> {
        let mut found: Option<Vec<Id>> = None;
        for (i, term) in terms.iter().enumerate() {
            let ids = if i + 1 == terms.len() {
                let mut ids = Vec::new();
                for (word, posting) in self.terms.range(term.clone()..) {
                    if !word.starts_with(term) {
                        break;
                    }
                    ids.extend_from_slice(posting);
                }
                ids.sort_unstable();
                ids.dedup();
                ids
            } else {
                self.terms.get(term).cloned().unwrap_or_default()
            };
            found = Some(match found {
                None => ids,
                Some(previous) => {
                    let (mut a, mut b) = (0, 0);
                    let mut result = Vec::new();
                    while a < previous.len() && b < ids.len() {
                        match previous[a].cmp(&ids[b]) {
                            std::cmp::Ordering::Less => a += 1,
                            std::cmp::Ordering::Greater => b += 1,
                            std::cmp::Ordering::Equal => {
                                result.push(previous[a]);
                                a += 1;
                                b += 1;
                            }
                        }
                    }
                    result
                }
            });
            if found.as_ref().is_some_and(Vec::is_empty) {
                break;
            }
        }
        Ok(found.unwrap_or_default())
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        for (mut word, _) in std::mem::take(&mut self.terms) {
            word.zeroize();
        }
        for (_, mut terms) in std::mem::take(&mut self.records) {
            terms.zeroize();
        }
    }
}
