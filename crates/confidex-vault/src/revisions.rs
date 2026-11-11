use crate::{
    envelope::{EventKind, VerifiedRevision},
    records_list,
    resources::MAX_OPEN_MEMORY,
    trust::TrustAnchor,
};
use std::mem::size_of;

pub type Id = [u8; 32];
pub type RecordId = [u8; 16];
pub type Reference = (RecordId, Id);
const WORK: usize = 24 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Allocation,
    State,
    WrongTrust,
    Scope,
    ConflictingId,
    OriginalRequired,
    Parents,
    Cycle,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Node {
    pub id: Id,
    pub record_id: RecordId,
    pub parents: Vec<Id>,
    pub epoch: u64,
    pub kind: EventKind,
}
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Report {
    pub heads: Vec<Reference>,
    pub missing: Vec<Id>,
    pub deletions: Vec<Reference>,
}
pub struct Graph {
    vault_id: RecordId,
    key: [u8; 32],
    nodes: Vec<Node>,
    report: Report,
}
pub struct Update<'a> {
    base: &'a Graph,
    base_bytes: usize,
    nodes: Vec<Node>,
    parent_bytes: usize,
    expected_items: usize,
    items: usize,
    edges: usize,
    bytes: usize,
    budget: usize,
    failed: bool,
}
fn vec<T>(capacity: usize) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| Error::Allocation)?;
    Ok(out)
}
fn locate(nodes: &[Node], id: &Id) -> Result<usize, usize> {
    nodes.binary_search_by_key(id, |n| n.id)
}
fn parent_bytes(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|n| n.parents.capacity() * size_of::<Id>())
        .sum()
}
fn scratch(nodes: usize, edges: usize, expected: usize) -> Result<usize, Error> {
    nodes
        .checked_mul(128)
        .and_then(|n| edges.checked_add(expected)?.checked_mul(64)?.checked_add(n))
        .ok_or(Error::Limit)
}
impl Graph {
    pub fn new(anchor: &TrustAnchor) -> Self {
        Self {
            vault_id: anchor.vault_id(),
            key: anchor.public_key(),
            nodes: Vec::new(),
            report: Report::default(),
        }
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    pub fn get(&self, id: &Id) -> Option<&Node> {
        locate(&self.nodes, id).ok().map(|i| &self.nodes[i])
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    pub fn memory_bytes(&self) -> usize {
        self.nodes.capacity() * size_of::<Node>()
            + parent_bytes(&self.nodes)
            + (self.report.heads.capacity() + self.report.deletions.capacity())
                * size_of::<Reference>()
            + self.report.missing.capacity() * size_of::<Id>()
    }
    pub fn begin(&self, expected_items: usize, memory_budget: usize) -> Result<Update<'_>, Error> {
        if expected_items > records_list::MAX_ITEMS || memory_budget > MAX_OPEN_MEMORY {
            return Err(Error::Limit);
        }
        let capacity = self
            .nodes
            .len()
            .checked_add(expected_items)
            .ok_or(Error::Limit)?;
        let parents = parent_bytes(&self.nodes);
        let edges = parents / size_of::<Id>();
        let base_bytes = self.memory_bytes();
        let required = base_bytes
            .checked_add(
                capacity
                    .checked_mul(size_of::<Node>())
                    .ok_or(Error::Limit)?,
            )
            .and_then(|n| n.checked_add(parents))
            .and_then(|n| {
                n.checked_add(scratch(self.nodes.len(), edges, self.report.missing.len()).ok()?)
            })
            .and_then(|n| n.checked_add(WORK))
            .ok_or(Error::Limit)?;
        if required > memory_budget {
            return Err(Error::Limit);
        }
        let mut nodes = vec(capacity)?;
        for node in &self.nodes {
            let mut parents = vec(node.parents.len())?;
            parents.extend_from_slice(&node.parents);
            nodes.push(Node {
                id: node.id,
                record_id: node.record_id,
                parents,
                epoch: node.epoch,
                kind: node.kind,
            });
        }
        let actual_parents = parent_bytes(&nodes);
        let update = Update {
            base: self,
            base_bytes,
            nodes,
            parent_bytes: actual_parents,
            expected_items,
            items: 0,
            edges: 0,
            bytes: 0,
            budget: memory_budget,
            failed: false,
        };
        if update
            .used(0, 0, 0)?
            .checked_add(WORK)
            .ok_or(Error::Limit)?
            > memory_budget
        {
            return Err(Error::Limit);
        }
        Ok(update)
    }
}
impl Update<'_> {
    fn used(
        &self,
        extra_parents: usize,
        extra_node: usize,
        extra_expected: usize,
    ) -> Result<usize, Error> {
        let parent_bytes = self
            .parent_bytes
            .checked_add(extra_parents)
            .ok_or(Error::Limit)?;
        self.base_bytes
            .checked_add(self.nodes.capacity() * size_of::<Node>())
            .and_then(|n| n.checked_add(parent_bytes))
            .and_then(|n| {
                n.checked_add(
                    scratch(
                        self.nodes.len() + extra_node,
                        parent_bytes / size_of::<Id>(),
                        self.base.report.missing.len().checked_add(extra_expected)?,
                    )
                    .ok()?,
                )
            })
            .ok_or(Error::Limit)
    }
    pub fn object_budget(&self) -> usize {
        self.budget
            .saturating_sub(self.used(0, 0, 0).unwrap_or(usize::MAX))
    }
    pub fn contains(&self, id: &Id) -> bool {
        locate(&self.nodes, id).is_ok()
    }
    pub fn stage(
        &mut self,
        revision: &VerifiedRevision<'_>,
        original: Option<&VerifiedRevision<'_>>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        self.failed = true;
        if self.items == self.expected_items {
            return Err(Error::State);
        }
        let header = revision.header();
        if revision.verifying_key() != self.base.key || header.vault_id != self.base.vault_id {
            return Err(Error::WrongTrust);
        }
        let bytes = self
            .bytes
            .checked_add(revision.encoded_len())
            .ok_or(Error::Limit)?;
        let edges = self
            .edges
            .checked_add(header.parents.len())
            .ok_or(Error::Limit)?;
        if bytes > records_list::MAX_BYTES || edges > records_list::MAX_EDGES {
            return Err(Error::Limit);
        }
        match locate(&self.nodes, &revision.id()) {
            Ok(_) => {
                let old = original.ok_or(Error::OriginalRequired)?;
                if old.verifying_key() != self.base.key
                    || old.header().vault_id != self.base.vault_id
                {
                    return Err(Error::WrongTrust);
                }
                if old.id() != revision.id() || !old.same_payload(revision) {
                    return Err(Error::ConflictingId);
                }
            }
            Err(index) => {
                let extra = header.parents.len() * size_of::<Id>();
                if self
                    .used(extra, 1, 0)?
                    .checked_add(WORK)
                    .ok_or(Error::Limit)?
                    > self.budget
                {
                    return Err(Error::Limit);
                }
                let mut parents = vec(header.parents.len())?;
                parents.extend_from_slice(&header.parents);
                let extra = parents.capacity() * size_of::<Id>();
                if self
                    .used(extra, 1, 0)?
                    .checked_add(WORK)
                    .ok_or(Error::Limit)?
                    > self.budget
                {
                    return Err(Error::Limit);
                }
                self.nodes.insert(
                    index,
                    Node {
                        id: revision.id(),
                        record_id: header.record_id,
                        parents,
                        epoch: header.metadata.epoch,
                        kind: header.kind,
                    },
                );
                self.parent_bytes += extra;
            }
        }
        self.items += 1;
        self.edges = edges;
        self.bytes = bytes;
        self.failed = false;
        Ok(())
    }
    pub fn finish(self, expected: &[Id]) -> Result<Graph, Error> {
        if self.failed || self.items != self.expected_items {
            return Err(Error::State);
        }
        if self
            .used(0, 0, expected.len())?
            .checked_add(WORK)
            .ok_or(Error::Limit)?
            > self.budget
        {
            return Err(Error::Limit);
        }
        let report = inspect(&self.nodes, &self.base.report.missing, expected)?;
        Ok(Graph {
            vault_id: self.base.vault_id,
            key: self.base.key,
            nodes: self.nodes,
            report,
        })
    }
}

fn inspect(nodes: &[Node], previous_missing: &[Id], expected: &[Id]) -> Result<Report, Error> {
    let n = nodes.len();
    let edges: usize = nodes.iter().map(|n| n.parents.len()).sum();
    let mut pending = vec(n)?;
    pending.resize(n, 0usize);
    let mut heads = vec(n)?;
    heads.resize(n, true);
    let mut links = vec(edges)?;
    let mut missing = vec(edges + previous_missing.len() + expected.len())?;
    let mut deletions = vec(n)?;
    for (child, node) in nodes.iter().enumerate() {
        if node.parents.windows(2).any(|p| p[0] >= p[1])
            || (node.kind == EventKind::Deletion && node.parents.is_empty())
        {
            return Err(Error::Parents);
        }
        if node.kind == EventKind::Deletion {
            deletions.push((node.record_id, node.id));
        }
        for id in &node.parents {
            match locate(nodes, id) {
                Ok(parent) => {
                    if nodes[parent].record_id != node.record_id {
                        return Err(Error::Scope);
                    }
                    pending[child] += 1;
                    heads[parent] = false;
                    links.push((parent, child));
                }
                Err(_) => missing.push(*id),
            }
        }
    }
    for id in previous_missing.iter().chain(expected) {
        if locate(nodes, id).is_err() {
            missing.push(*id);
        }
    }
    links.sort_unstable();
    missing.sort_unstable();
    missing.dedup();
    deletions.sort_unstable();
    let mut ready = vec(n)?;
    for (i, count) in pending.iter().enumerate() {
        if *count == 0 {
            ready.push(i);
        }
    }
    let mut visited = 0;
    while let Some(parent) = ready.pop() {
        visited += 1;
        let start = links.partition_point(|(p, _)| *p < parent);
        let end = links.partition_point(|(p, _)| *p <= parent);
        for &(_, child) in &links[start..end] {
            pending[child] -= 1;
            if pending[child] == 0 {
                ready.push(child);
            }
        }
    }
    if visited != n {
        return Err(Error::Cycle);
    }
    let mut known_heads = vec(n)?;
    for (i, node) in nodes.iter().enumerate() {
        if heads[i] {
            known_heads.push((node.record_id, node.id));
        }
    }
    known_heads.sort_unstable();
    Ok(Report {
        heads: known_heads,
        missing,
        deletions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(id: u8, parents: &[u8]) -> Node {
        Node {
            id: [id; 32],
            record_id: [8; 16],
            parents: parents.iter().map(|i| [*i; 32]).collect(),
            epoch: 0,
            kind: EventKind::Content,
        }
    }
    #[test]
    fn cycles_and_scope_errors_are_proven_even_with_other_missing_targets() {
        assert_eq!(inspect(&[node(1, &[1])], &[], &[]), Err(Error::Cycle));
        assert_eq!(
            inspect(&[node(1, &[2]), node(2, &[1, 3])], &[], &[]),
            Err(Error::Cycle)
        );
        let mut foreign = node(1, &[]);
        foreign.record_id = [9; 16];
        assert_eq!(
            inspect(&[foreign, node(2, &[1, 3])], &[], &[]),
            Err(Error::Scope)
        );
        assert_eq!(inspect(&[node(1, &[2, 2])], &[], &[]), Err(Error::Parents));
    }
    #[test]
    fn a_long_history_uses_an_iterative_walk() {
        let id = |i: u32| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        };
        let nodes: Vec<_> = (0..10000u32)
            .map(|i| Node {
                id: id(i),
                record_id: [8; 16],
                parents: if i == 0 { vec![] } else { vec![id(i - 1)] },
                epoch: 0,
                kind: EventKind::Content,
            })
            .collect();
        let report = inspect(&nodes, &[], &[]).unwrap();
        assert_eq!(report.heads, vec![([8; 16], id(9999))]);
        assert!(report.missing.is_empty());
    }
}
