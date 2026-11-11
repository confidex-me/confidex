//! ZIP snapshots contain the same opaque blobs as the sync server.
use super::*;
use confidex_storage::{MAX_BACKUP_BYTES, MAX_BACKUP_OBJECTS, Snapshot, StoredObject};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Write};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

const DOMAIN: &[u8] = b"confidex/backup/v1\0";
const MAX_MANIFEST: usize = 8_000_000;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    lock: String,
    blobs: Vec<String>,
    heads: Vec<Head>,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn prefix(public: &[u8; 32]) -> String {
    let id = hex(&confidex_vault::sync::id(public));
    format!(
        "{}/{}/{}-{}-{}-{}-{}",
        &id[..2],
        &id[2..4],
        &id[..8],
        &id[8..12],
        &id[12..16],
        &id[16..20],
        &id[20..]
    )
}
fn object_path(prefix: &str, digest: &str) -> String {
    format!(
        "{prefix}/{}/{}/{}",
        &digest[..2],
        &digest[2..4],
        &digest[4..]
    )
}
fn signed(bytes: &[u8]) -> Vec<u8> {
    [DOMAIN, bytes].concat()
}
fn archive(bytes: &[u8]) -> Result<ZipArchive<Cursor<&[u8]>>, Error> {
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err(Error::Storage(confidex_storage::Error::Limit));
    }
    let end = bytes
        .windows(22)
        .rposition(|w| w[..4] == *b"PK\x05\x06")
        .ok_or(Error::Integrity)?;
    let footer = &bytes[end..];
    let count = u16::from_le_bytes([footer[10], footer[11]]) as usize;
    let comment = u16::from_le_bytes([footer[20], footer[21]]) as usize;
    if count > MAX_BACKUP_OBJECTS + 3
        || footer.len() != 22 + comment
        || footer[4..8] != [0; 4]
        || footer[8..10] != footer[10..12]
        || end >= 20 && bytes[end - 20..end - 16] == *b"PK\x06\x07"
    {
        return Err(Error::Integrity);
    }
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(|_| Error::Integrity)?;
    if zip.len() != count {
        return Err(Error::Integrity);
    }
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for i in 0..zip.len() {
        let file = zip.by_index_raw(i).map_err(|_| Error::Integrity)?;
        total = total.checked_add(file.size()).ok_or(Error::Integrity)?;
        let name = file.name().map_err(|_| Error::Integrity)?.into_owned();
        if name.len() > 256
            || !names.insert(name)
            || file.enclosed_name().is_none()
            || file.is_dir()
            || file.is_symlink()
            || file.encrypted()
            || total > MAX_BACKUP_BYTES as u64
        {
            return Err(Error::Integrity);
        }
    }
    Ok(zip)
}
fn read(zip: &mut ZipArchive<Cursor<&[u8]>>, name: &str, limit: usize) -> Result<Vec<u8>, Error> {
    let file = zip.by_name(name).map_err(|_| Error::Integrity)?;
    if file.size() > limit as u64 {
        return Err(Error::Integrity);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Integrity)?;
    if bytes.len() > limit {
        return Err(Error::Integrity);
    }
    Ok(bytes)
}
fn lock_file(zip: &mut ZipArchive<Cursor<&[u8]>>) -> Result<(String, Vec<u8>), Error> {
    let names: Vec<_> = zip
        .file_names()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Integrity)?
        .into_iter()
        .filter(|n| n.ends_with(".sealed"))
        .map(|n| n.into_owned())
        .collect();
    if names.len() != 1 {
        return Err(Error::Integrity);
    }
    let wire = read(zip, &names[0], lock::MAX_LOCK)?;
    let header = lock::inspect(&wire).map_err(|_| Error::Integrity)?;
    let expected = format!(
        "{}/locks/{}.sealed",
        prefix(&header.public_key),
        hex(&Sha256::digest(&wire))
    );
    if names[0] != expected {
        return Err(Error::Integrity);
    }
    Ok((names[0].clone(), wire))
}
pub fn inspect(bytes: &[u8]) -> Result<VaultId, Error> {
    let (_, wire) = lock_file(&mut archive(bytes)?)?;
    Ok(lock::inspect(&wire).map_err(|_| Error::Integrity)?.vault_id)
}
pub async fn export(store: &mut impl Store, vault: &lock::OpenedVault) -> Result<Vec<u8>, Error> {
    let mut snapshot = store.snapshot(vault.vault_id()).await?;
    let header = lock::inspect(&snapshot.vault.lock).map_err(|_| Error::Integrity)?;
    if header.vault_id != vault.vault_id() || header.public_key != vault.anchor().public_key() {
        return Err(Error::Integrity);
    }
    let root = prefix(&header.public_key);
    let graph = Graph::new(vault.anchor());
    let mut update = graph
        .begin(snapshot.objects.len(), MAX_OPEN_MEMORY)
        .map_err(|_| Error::Integrity)?;
    for object in &snapshot.objects {
        let verified = envelope::verify(
            &object.wire,
            vault.anchor(),
            Some(&object.head.revision),
            update.object_budget(),
        )
        .map_err(|_| Error::Integrity)?;
        if verified.header().record_id != object.head.record {
            return Err(Error::Integrity);
        }
        update
            .stage(&verified, None)
            .map_err(|_| Error::Integrity)?;
    }
    let graph = update.finish(&[]).map_err(|_| Error::Integrity)?;
    if !graph.report().missing.is_empty() {
        return Err(Error::Integrity);
    }
    let local: BTreeSet<_> = snapshot.heads.iter().map(|h| h.record).collect();
    let mut records = local.clone();
    for (record, revision) in &graph.report().heads {
        if !local.contains(record) {
            if !records.insert(*record) {
                return Err(Error::Integrity);
            }
            snapshot.heads.push(Head {
                record: *record,
                revision: *revision,
            });
        }
    }
    snapshot.heads.sort_by_key(|h| h.record);
    let digest = hex(&Sha256::digest(&snapshot.vault.lock));
    let mut manifest = Manifest {
        version: 1,
        lock: digest.clone(),
        blobs: snapshot
            .objects
            .iter()
            .map(|o| hex(&Sha256::digest(&o.wire)))
            .collect(),
        heads: snapshot.heads,
    };
    manifest.blobs.sort();
    let manifest = serde_json::to_vec(&manifest).map_err(|_| Error::Integrity)?;
    if manifest.len() > MAX_MANIFEST {
        return Err(Error::Storage(confidex_storage::Error::Limit));
    }
    let signature = vault.keys().signing_key().sign(&signed(&manifest));
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let mut put = |name: &str, bytes: &[u8]| -> Result<(), Error> {
        zip.start_file(
            name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .map_err(|_| Error::Integrity)?;
        zip.write_all(bytes).map_err(|_| Error::Integrity)
    };
    put(
        &format!("{root}/locks/{digest}.sealed"),
        &snapshot.vault.lock,
    )?;
    put("backup.json", &manifest)?;
    put("backup.sig", &signature.to_bytes())?;
    for object in snapshot.objects {
        put(
            &object_path(&root, &hex(&Sha256::digest(&object.wire))),
            &object.wire,
        )?;
    }
    let bytes = zip.finish().map_err(|_| Error::Integrity)?.into_inner();
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err(Error::Storage(confidex_storage::Error::Limit));
    }
    Ok(bytes)
}
pub fn restore(
    bytes: &[u8],
    name: &str,
    password: &str,
    key: &str,
) -> Result<(Snapshot, lock::OpenedVault), Error> {
    if name.trim().is_empty() || name.len() > 128 || password.is_empty() || password.len() > 4096 {
        return Err(Error::Input);
    }
    let mut zip = archive(bytes)?;
    let (_, wire) = lock_file(&mut zip)?;
    let code = transfer_code::decode(key).map_err(|_| Error::Key)?;
    let header = lock::inspect(&wire).map_err(|_| Error::Integrity)?;
    if code.id != confidex_vault::sync::id(&header.public_key) {
        return Err(Error::Key);
    }
    let opened = lock::open(
        &wire,
        password.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .map_err(|_| Error::Auth)?;
    let manifest_bytes = read(&mut zip, "backup.json", MAX_MANIFEST)?;
    let signature =
        Signature::from_slice(&read(&mut zip, "backup.sig", 64)?).map_err(|_| Error::Integrity)?;
    VerifyingKey::from_bytes(&header.public_key)
        .map_err(|_| Error::Integrity)?
        .verify_strict(&signed(&manifest_bytes), &signature)
        .map_err(|_| Error::Integrity)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| Error::Integrity)?;
    if manifest.version != 1
        || manifest.lock != hex(&Sha256::digest(&wire))
        || manifest.blobs.len() + 3 != zip.len()
        || manifest.blobs.windows(2).any(|p| p[0] >= p[1])
        || manifest.blobs.iter().any(|r| {
            r.len() != 64
                || !r
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(Error::Integrity);
    }
    let mut objects = Vec::new();
    let graph = Graph::new(opened.anchor());
    let mut update = graph
        .begin(manifest.blobs.len(), MAX_OPEN_MEMORY)
        .map_err(|_| Error::Integrity)?;
    let root = prefix(&header.public_key);
    for digest in manifest.blobs {
        let wire = read(
            &mut zip,
            &object_path(&root, &digest),
            confidex_storage::MAX_OBJECT,
        )?;
        let verified = envelope::verify(&wire, opened.anchor(), None, update.object_budget())
            .map_err(|_| Error::Integrity)?;
        if hex(&Sha256::digest(&wire)) != digest {
            return Err(Error::Integrity);
        }
        update
            .stage(&verified, None)
            .map_err(|_| Error::Integrity)?;
        let head = Head {
            record: verified.header().record_id,
            revision: verified.id(),
        };
        let record = envelope::open(
            &wire,
            opened.keys(),
            opened.anchor(),
            Some(&head.revision),
            MAX_OPEN_MEMORY,
        )
        .map_err(|_| Error::Integrity)?;
        let tags = if record.revision.header().kind == EventKind::Deletion {
            vec![]
        } else {
            record.record.tags.clone()
        };
        drop(record);
        objects.push(StoredObject { head, wire, tags });
    }
    let graph = update.finish(&[]).map_err(|_| Error::Integrity)?;
    if !graph.report().missing.is_empty() {
        return Err(Error::Integrity);
    }
    let snapshot = Snapshot {
        vault: StoredVault {
            info: VaultInfo {
                id: opened.vault_id(),
                name: name.into(),
            },
            lock: wire,
        },
        objects,
        heads: manifest.heads,
    };
    snapshot.validate()?;
    let records: BTreeSet<_> = snapshot.objects.iter().map(|o| o.head.record).collect();
    if records != snapshot.heads.iter().map(|h| h.record).collect() {
        return Err(Error::Integrity);
    }
    Ok((snapshot, opened))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zip_metadata_rejects_duplicate_paths_traversal_and_large_entries() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for name in ["first", "other"] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"fixture").unwrap();
        }
        let mut bytes = writer.finish().unwrap().into_inner();
        assert!(archive(&bytes).is_ok());
        for offset in (0..bytes.len() - 5).collect::<Vec<_>>() {
            if &bytes[offset..offset + 5] == b"other" {
                bytes[offset..offset + 5].copy_from_slice(b"first");
            }
        }
        assert!(archive(&bytes).is_err());
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("../lock.sealed", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"fixture").unwrap();
        assert!(archive(&writer.finish().unwrap().into_inner()).is_err());
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "lock.sealed",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&vec![0; 1_000_000]).unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert!(bytes.len() < 10_000);
        assert!(read(&mut archive(&bytes).unwrap(), "lock.sealed", lock::MAX_LOCK).is_err());
        assert!(inspect(&bytes).is_err());
        assert!(archive(&vec![0; MAX_BACKUP_BYTES + 1]).is_err());
    }
}
