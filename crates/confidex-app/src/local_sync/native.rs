//! Signed object exchange through a directory managed by the operating system.
use super::{Command, Error, Reply, Report};
use crate::{DeviceKeys, StoredVault, VaultInfo, kdf, transfer_code};
use crate::{Engine, Error as AppError, sync};
use confidex_storage::{Head, Store, StoredObject};
use confidex_vault::{entropy, envelope, lock, resources::MAX_OPEN_MEMORY, revisions::Graph};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_OBJECTS: usize = 100_000;
const MAX_LOCKS: usize = 16;
const BATCH_BYTES: usize = 8_000_000;
fn limit() -> Error {
    confidex_storage::Error::Limit.into()
}
fn integrity() -> Error {
    AppError::Integrity.into()
}
fn io(error: std::io::Error) -> Error {
    use std::io::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::NotFound
            | ErrorKind::TimedOut
            | ErrorKind::NotConnected
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::WouldBlock
            | ErrorKind::BrokenPipe
    ) {
        Error::Unavailable
    } else {
        confidex_storage::Error::Storage.into()
    }
}
fn checkpoint(control: &mut impl FnMut() -> bool) -> Result<(), Error> {
    if control() {
        Ok(())
    } else {
        Err(Error::Canceled)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Blob {
    digest: [u8; 32],
    len: usize,
}
impl Blob {
    fn name(self, extension: &str) -> String {
        format!("{}.{}.{extension}", hex(&self.digest), self.len)
    }
    fn parse(name: &str, extension: &str, maximum: usize) -> Option<Self> {
        let stem = name.strip_suffix(&format!(".{extension}"))?;
        let (digest, len) = stem.split_once('.')?;
        let len: usize = len.parse().ok()?;
        if digest.len() != 64
            || len == 0
            || len > maximum
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut bytes = [0; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).ok()?;
        }
        let blob = Self { digest: bytes, len };
        (blob.name(extension) == name).then_some(blob)
    }
}
struct Folder {
    locks: PathBuf,
    records: PathBuf,
}
fn directory(path: &Path, create: bool) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(integrity()),
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            match fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    directory(path, false)
                }
                Err(error) => Err(io(error)),
            }
        }
        Err(error) => Err(io(error)),
    }
}
impl Folder {
    fn open(root: &Path, id: [u8; 16], create: bool) -> Result<Self, Error> {
        let root = root.canonicalize().map_err(io)?;
        directory(&root, false)?;
        let version = root.join("confidex-sync-v1");
        directory(&version, create)?;
        let scope = version.join(hex(&id));
        directory(&scope, create)?;
        let folder = Self {
            locks: scope.join("locks"),
            records: scope.join("records"),
        };
        directory(&folder.locks, create)?;
        directory(&folder.records, create)?;
        Ok(folder)
    }
}
fn list(
    directory: &Path,
    extension: &str,
    maximum: usize,
    count: usize,
) -> Result<Vec<Blob>, Error> {
    let mut output = Vec::new();
    for (index, entry) in fs::read_dir(directory).map_err(io)?.enumerate() {
        if index >= MAX_OBJECTS {
            return Err(limit());
        }
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let Some(blob) = name
            .to_str()
            .and_then(|s| Blob::parse(s, extension, maximum))
        else {
            continue;
        };
        if !entry.file_type().map_err(io)?.is_file() {
            return Err(integrity());
        }
        output.push(blob);
        if output.len() > count {
            return Err(limit());
        }
    }
    output.sort_unstable();
    Ok(output)
}
fn read(directory: &Path, blob: Blob, extension: &str) -> Result<Option<Vec<u8>>, Error> {
    let path = directory.join(blob.name(extension));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    if !metadata.is_file() {
        return Err(integrity());
    }
    if metadata.len() < blob.len as u64 {
        return Ok(None);
    }
    if metadata.len() != blob.len as u64 {
        return Err(integrity());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io)?
        .take(blob.len as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() < blob.len {
        return Ok(None);
    }
    if bytes.len() != blob.len || hash(&bytes) != blob.digest {
        return Err(integrity());
    }
    Ok(Some(bytes))
}
fn write(directory: &Path, bytes: &[u8], extension: &str) -> Result<bool, Error> {
    let blob = Blob {
        digest: hash(bytes),
        len: bytes.len(),
    };
    if matches!(read(directory, blob, extension), Ok(Some(_))) {
        return Ok(false);
    }
    let mut random = [0; 16];
    entropy::fill_random(&mut random).map_err(|_| AppError::Input)?;
    let temporary = directory.join(format!(".{}.pending", hex(&random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(io)?;
    let result = (move || {
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        fs::rename(&temporary, directory.join(blob.name(extension))).map_err(io)?;
        #[cfg(unix)]
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(io)?;
        Ok(true)
    })();
    let _ = fs::remove_file(directory.join(format!(".{}.pending", hex(&random))));
    result
}

/// Read authenticated lock wrappers without opening their encrypted contents.
pub fn locks(root: &Path, id: [u8; 16]) -> Result<Vec<Vec<u8>>, Error> {
    let folder = Folder::open(root, id, false)?;
    let mut output = Vec::new();
    for blob in list(&folder.locks, "lock", 408, MAX_LOCKS)? {
        let Some(bytes) = read(&folder.locks, blob, "lock")? else {
            continue;
        };
        if bytes.len() < 64 {
            return Err(integrity());
        }
        let (wire, signature) = bytes.split_at(bytes.len() - 64);
        let header = lock::inspect(wire).map_err(|_| integrity())?;
        if confidex_vault::sync::id(&header.public_key) != id {
            return Err(integrity());
        }
        VerifyingKey::from_bytes(&header.public_key)
            .map_err(|_| integrity())?
            .verify_strict(
                &confidex_vault::sync::lock_signature_bytes(wire, ""),
                &Signature::from_slice(signature).map_err(|_| integrity())?,
            )
            .map_err(|_| integrity())?;
        output.push(wire.to_vec());
    }
    Ok(output)
}
fn stage(graph: &Graph, wires: &[Vec<u8>], vault: &lock::OpenedVault) -> Result<Graph, Error> {
    let mut update = graph
        .begin(wires.len(), MAX_OPEN_MEMORY)
        .map_err(|_| limit())?;
    for wire in wires {
        let revision = envelope::verify(wire, vault.anchor(), None, update.object_budget())
            .map_err(|_| integrity())?;
        update.stage(&revision, None).map_err(|_| integrity())?;
    }
    update.finish(&[]).map_err(|_| integrity())
}

/// Exchange exact wire objects; incomplete delivery does not replace local tips.
pub async fn synchronize(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    root: &Path,
    control: &mut impl FnMut() -> bool,
) -> Result<Report, Error> {
    checkpoint(control)?;
    let id = confidex_vault::sync::id(vault.keys().signing_key().verifying_key().as_bytes());
    let folder = Folder::open(root, id, true)?;
    let local = sync::all_heads(store, vault.vault_id()).await?;
    let mut graph = sync::graph(store, vault, &local).await?;
    let mut report = Report::default();
    let mut wire = store.vault(vault.vault_id()).await?.lock;
    let header = lock::inspect(&wire).map_err(|_| integrity())?;
    if header.vault_id != vault.vault_id() || header.public_key != vault.anchor().public_key() {
        return Err(integrity());
    }
    let signature = vault
        .keys()
        .signing_key()
        .sign(&confidex_vault::sync::lock_signature_bytes(&wire, ""));
    wire.extend_from_slice(&signature.to_bytes());
    write(&folder.locks, &wire, "lock")?;
    let mut seen = BTreeSet::new();
    let mut todo: Vec<_> = local.iter().map(|h| (h.revision, false)).collect();
    while let Some((revision, ready)) = todo.pop() {
        checkpoint(control)?;
        if ready {
            let wire = store.object(vault.vault_id(), revision).await?;
            envelope::verify(&wire, vault.anchor(), Some(&revision), MAX_OPEN_MEMORY)
                .map_err(|_| integrity())?;
            report.uploaded += usize::from(write(&folder.records, &wire, "record")?);
        } else if seen.insert(revision) {
            todo.push((revision, true));
            let node = graph.get(&revision).ok_or_else(integrity)?;
            todo.extend(node.parents.iter().map(|p| (*p, false)));
        }
    }
    let mut sources = BTreeMap::new();
    let mut batch = Vec::new();
    let mut bytes = 0;
    for blob in list(
        &folder.records,
        "record",
        confidex_storage::MAX_OBJECT,
        MAX_OBJECTS,
    )? {
        checkpoint(control)?;
        let Some(wire) = read(&folder.records, blob, "record")? else {
            report.pending += 1;
            continue;
        };
        let verified = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
            .map_err(|_| integrity())?;
        if verified.header().vault_id != vault.vault_id() {
            return Err(integrity());
        }
        let revision = verified.id();
        if sources
            .insert(revision, blob)
            .is_some_and(|previous| previous != blob)
        {
            return Err(integrity());
        }
        if graph.get(&revision).is_some() {
            continue;
        }
        if bytes + wire.len() > BATCH_BYTES || batch.len() == 128 {
            graph = stage(&graph, &batch, vault)?;
            batch.clear();
            bytes = 0;
        }
        bytes += wire.len();
        batch.push(wire);
    }
    if !batch.is_empty() {
        graph = stage(&graph, &batch, vault)?;
    }
    report.pending += graph.report().missing.len();
    if report.pending != 0 {
        return Ok(report);
    }
    let mut objects = Vec::new();
    bytes = 0;
    for (revision, blob) in sources {
        checkpoint(control)?;
        let Some(wire) = read(&folder.records, blob, "record")? else {
            report.pending += 1;
            return Ok(report);
        };
        match store.object(vault.vault_id(), revision).await {
            Ok(existing) if existing == wire => continue,
            Ok(_) => return Err(integrity()),
            Err(confidex_storage::Error::NotFound) => (),
            Err(error) => return Err(error.into()),
        }
        if bytes + wire.len() > BATCH_BYTES || objects.len() == 256 {
            checkpoint(control)?;
            let count = objects.len();
            sync::publish_local(
                store,
                vault.vault_id(),
                std::mem::take(&mut objects),
                vec![],
            )
            .await?;
            report.downloaded += count;
            bytes = 0;
        }
        let opened = envelope::open(
            &wire,
            vault.keys(),
            vault.anchor(),
            Some(&revision),
            MAX_OPEN_MEMORY,
        )
        .map_err(|_| integrity())?;
        let mut tags = if opened.revision.header().kind == envelope::EventKind::Deletion {
            vec![]
        } else {
            opened.record.tags.clone()
        };
        tags.sort_unstable();
        let head = Head {
            record: opened.revision.header().record_id,
            revision,
        };
        drop(opened);
        bytes += wire.len();
        objects.push(StoredObject { head, wire, tags });
    }
    if !objects.is_empty() {
        checkpoint(control)?;
        let count = objects.len();
        sync::publish_local(store, vault.vault_id(), objects, vec![]).await?;
        report.downloaded += count;
    }
    let remote: Vec<_> = graph
        .report()
        .heads
        .iter()
        .map(|&(record, revision)| Head { record, revision })
        .collect();
    for _ in 0..4 {
        checkpoint(control)?;
        let local = sync::all_heads(store, vault.vault_id()).await?;
        let mut both = local.clone();
        both.extend_from_slice(&remote);
        let graph = sync::graph(store, vault, &both).await?;
        let mut current: BTreeSet<_> = local.into_iter().collect();
        loop {
            checkpoint(control)?;
            let local: Vec<_> = current.iter().cloned().collect();
            let changes = sync::head_changes(&graph, &local)?;
            if changes.is_empty() {
                if sync::all_heads(store, vault.vault_id()).await? == local {
                    return Ok(report);
                }
                break;
            }
            for change in &changes {
                if let Some(revision) = change.expected {
                    current.remove(&Head {
                        record: change.head.record,
                        revision,
                    });
                }
                current.insert(change.head.clone());
            }
            match sync::publish_local(store, vault.vault_id(), vec![], changes).await {
                Ok(()) => (),
                Err(AppError::Storage(confidex_storage::Error::Conflict)) => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    Err(confidex_storage::Error::Conflict.into())
}
impl Engine {
    pub async fn execute_folder(
        &mut self,
        store: &mut impl Store,
        keys: &mut impl DeviceKeys,
        command: &mut Command,
        control: &mut impl FnMut() -> bool,
    ) -> Result<Reply, Error> {
        checkpoint(control)?;
        if let Command::Import {
            name,
            password,
            key,
            path,
            remember,
        } = command
        {
            self.vault = None;
            self.search = None;
            self.history = None;
            self.import_session = None;
            self.import_input = None;
            self.export_session = None;
            self.backup = None;
            if name.is_empty() || name.len() > 128 || password.is_empty() || password.len() > 4096 {
                return Err(AppError::Input.into());
            }
            let root = normalized_root(path)?;
            let code = transfer_code::decode(key).map_err(|_| AppError::Key)?;
            let wrappers = locks(Path::new(&root), code.id)?;
            if wrappers.is_empty() {
                return Err(Error::Unavailable);
            }
            for wire in wrappers {
                checkpoint(control)?;
                let Ok(opened) = lock::open(
                    &wire,
                    password.as_bytes(),
                    &code.secret,
                    kdf::REQUIRED_MEMORY,
                ) else {
                    continue;
                };
                checkpoint(control)?;
                if confidex_vault::sync::id(opened.keys().signing_key().verifying_key().as_bytes())
                    != code.id
                {
                    return Err(integrity());
                }
                let mut info = VaultInfo {
                    id: opened.vault_id(),
                    name: name.clone(),
                };
                match store.vault(info.id).await {
                    Ok(existing) => {
                        let header = lock::inspect(&existing.lock).map_err(|_| integrity())?;
                        if header.vault_id != info.id
                            || header.public_key != opened.anchor().public_key()
                        {
                            return Err(integrity());
                        }
                        crate::audit(store, &opened).await?;
                        info = existing.info;
                    }
                    Err(confidex_storage::Error::NotFound) => {
                        store
                            .create(&StoredVault {
                                info: info.clone(),
                                lock: wire,
                            })
                            .await?
                    }
                    Err(error) => return Err(error.into()),
                }
                sync::configure_folder(store, info.id, Some(&root)).await?;
                let server = sync::configured_server(store, info.id).await?;
                let remembered = *remember && keys.save(info.id, key).await;
                self.vault = Some(opened);
                return Ok(Reply::Opened {
                    info,
                    remembered,
                    server,
                });
            }
            return Err(AppError::Auth.into());
        }
        let id = self.vault.as_ref().ok_or(AppError::Locked)?.vault_id();
        match command {
            Command::Status => Ok(Reply::State {
                vault: id,
                path: sync::configured_folder(store, id).await?,
            }),
            Command::Configure { path } => {
                let root = path.as_deref().map(normalized_root).transpose()?;
                sync::configure_folder(store, id, root.as_deref()).await?;
                Ok(Reply::State {
                    vault: id,
                    path: root,
                })
            }
            Command::Sync => {
                let root = sync::configured_folder(store, id)
                    .await?
                    .ok_or(AppError::SyncDisabled)?;
                let report = self
                    .synchronize_folder(store, Path::new(&root), control)
                    .await?;
                Ok(Reply::Synced { vault: id, report })
            }
            Command::Import { .. } => unreachable!(),
        }
    }
    pub async fn synchronize_folder(
        &mut self,
        store: &mut impl Store,
        root: &Path,
        control: &mut impl FnMut() -> bool,
    ) -> Result<Report, Error> {
        self.export_session = None;
        if let Some(index) = &mut self.search {
            index.invalidate();
        }
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?;
        synchronize(store, vault, root, control).await
    }
}

fn normalized_root(path: &str) -> Result<String, Error> {
    if path.is_empty() || path.len() > 32768 || path.contains('\0') {
        return Err(AppError::Input.into());
    }
    let root = Path::new(path).canonicalize().map_err(io)?;
    directory(&root, false)?;
    let root = root.to_str().ok_or(AppError::Input)?;
    if root.len() > 32768 {
        return Err(AppError::Input.into());
    }
    Ok(root.into())
}
