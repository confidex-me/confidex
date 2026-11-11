use super::*;

fn verify<'a>(
    wire: &'a [u8],
    vault: &lock::OpenedVault,
    head: &Head,
) -> Result<envelope::VerifiedRevision<'a>, Error> {
    let revision = envelope::verify(wire, vault.anchor(), Some(&head.revision), MAX_OPEN_MEMORY)
        .map_err(|_| Error::Integrity)?;
    if revision.header().record_id != head.record {
        return Err(Error::Integrity);
    }
    Ok(revision)
}

async fn sources(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    head: &Head,
) -> Result<Vec<(RevisionId, u64)>, Error> {
    let wire = store.object(vault.vault_id(), head.revision).await?;
    let revision = verify(&wire, vault, head)?;
    if revision.header().kind != EventKind::Deletion {
        return Ok(Vec::new());
    }

    // A deletion can merge branches. Stop at the first content revision on each path.
    let mut pending: BTreeSet<_> = revision.header().parents.iter().copied().collect();
    let mut seen = BTreeSet::from([head.revision]);
    let mut result = Vec::new();
    while let Some(id) = pending.pop_first() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > 100_000 {
            return Err(Error::Integrity);
        }
        let wire = store.object(vault.vault_id(), id).await?;
        let revision = verify(
            &wire,
            vault,
            &Head {
                record: head.record,
                revision: id,
            },
        )?;
        let header = revision.header();
        match header.kind {
            EventKind::Deletion => pending.extend(header.parents.iter().copied()),
            EventKind::Content => result.push((id, header.metadata.epoch)),
        }
    }
    if result.is_empty() {
        return Err(Error::Integrity);
    }
    Ok(result)
}

pub(super) async fn source_epoch(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    head: &Head,
    source: RevisionId,
) -> Result<u64, Error> {
    sources(store, vault, head)
        .await?
        .into_iter()
        .find_map(|(id, epoch)| (id == source).then_some(epoch))
        .ok_or(Error::Input)
}

pub(super) async fn page(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    after: Option<&Head>,
) -> Result<Output, Error> {
    let heads = store.branch_heads(vault.vault_id(), after, None).await?;
    let limit = confidex_storage::PAGE_SIZE;
    if heads.len() > limit
        || heads
            .first()
            .zip(after)
            .is_some_and(|(first, after)| first <= after)
        || heads.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(Error::Integrity);
    }
    let next = if heads.len() == limit {
        heads.last().cloned()
    } else {
        None
    };
    let mut rows = Vec::new();
    for head in heads {
        for (source, epoch) in sources(store, vault, &head).await? {
            let wire = store.object(vault.vault_id(), source).await?;
            let record = verify(
                &wire,
                vault,
                &Head {
                    record: head.record,
                    revision: source,
                },
            )?
            .open(vault.keys(), MAX_OPEN_MEMORY)
            .map_err(|_| Error::Integrity)?;
            rows.push(DeletedVersion {
                head: head.clone(),
                title: title(&record)?,
                source,
                epoch,
            });
        }
    }
    Ok(Output::TrashPage { rows, next })
}

pub(super) async fn restore(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    head: &Head,
    source: RevisionId,
    epoch: u64,
) -> Result<(), Error> {
    source_epoch(store, vault, head, source).await?;
    let wire = store.object(vault.vault_id(), source).await?;
    let record = verify(
        &wire,
        vault,
        &Head {
            record: head.record,
            revision: source,
        },
    )?
    .open(vault.keys(), MAX_OPEN_MEMORY)
    .map_err(|_| Error::Integrity)?;
    append(
        store,
        vault,
        &record,
        Options {
            vault_id: vault.vault_id(),
            record_id: head.record,
            parents: &[head.revision],
            epoch,
            kind: EventKind::Content,
        },
        true,
    )
    .await?;
    Ok(())
}
