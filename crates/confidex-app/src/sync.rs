use super::*;
use bytes::Bytes;
use confidex_storage::{HeadChange, StoredObject, SyncCommit};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAX_BODY: usize = 8_000_000;
// Keep D1 queries and object writes within the Workers Free request limits.
const PUSH_RECORDS: usize = 8;
pub struct Reply {
    pub status: u16,
    pub content_type: String,
    pub etag: Option<String>,
    pub cursor: Option<String>,
    pub max_body: Option<usize>,
    pub body: Vec<u8>,
}
#[allow(async_fn_in_trait)]
pub trait Transport {
    async fn send(
        &mut self,
        url: &str,
        method: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Reply, Error>;
}
pub struct Offline;
impl Transport for Offline {
    async fn send(&mut self, _: &str, _: &str, _: &str, _: Vec<u8>) -> Result<Reply, Error> {
        Err(Error::SyncDisabled)
    }
}
#[derive(Default, Serialize, Deserialize)]
pub struct Report {
    pub server: Option<String>,
    pub downloaded: usize,
    pub uploaded: usize,
    pub duplicates: usize,
    pub more: bool,
    pub conflicts: Vec<Conflict>,
}
#[derive(Serialize, Deserialize)]
pub struct Version {
    pub revision: RevisionId,
    pub title: String,
    pub epoch: u64,
    pub deleted: bool,
}
impl Drop for Version {
    fn drop(&mut self) {
        self.title.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub struct Conflict {
    pub record: RecordId,
    pub local: Version,
    pub remote: Version,
}
#[derive(Default, Serialize, Deserialize)]
struct State {
    server: String,
    enabled: bool,
    cursor: u64,
    heads: Vec<Head>,
    #[serde(default)]
    lock_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
}
pub fn server_url(input: &str) -> Result<String, Error> {
    if input.len() > 2048 {
        return Err(Error::Input);
    }
    let mut url = url::Url::parse(input).map_err(|_| Error::Input)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::Input);
    }
    url.set_path("/");
    Ok(url.into())
}
fn id_text(id: [u8; 16]) -> String {
    let h: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
fn address(vault: &lock::OpenedVault) -> [u8; 16] {
    confidex_vault::sync::id(vault.keys().signing_key().verifying_key().as_bytes())
}
fn path(server: &str, id: [u8; 16]) -> String {
    format!("{server}v1/sync/{}", id_text(id))
}

#[test]
fn http_and_https_origins_have_the_same_validation_rules() {
    for scheme in ["http", "https"] {
        assert_eq!(
            server_url(&format!("{scheme}://sync.example.test")).unwrap(),
            format!("{scheme}://sync.example.test/")
        );
        assert_eq!(
            server_url(&format!("{scheme}://192.0.2.1:8080/")).unwrap(),
            format!("{scheme}://192.0.2.1:8080/")
        );
        for suffix in [
            "user:password@sync.example.test/",
            "sync.example.test/prefix",
            "sync.example.test/?query",
            "sync.example.test/#fragment",
        ] {
            assert!(server_url(&format!("{scheme}://{suffix}")).is_err());
        }
    }
    for url in [
        "file:///tmp/vault",
        "data:text/plain,secret",
        "ftp://sync.example.test/",
        "http://",
    ] {
        assert!(server_url(url).is_err());
    }
}
fn encode(parts: &[(&str, &[u8])]) -> Result<(String, Vec<u8>), Error> {
    let mut random = [0; 16];
    entropy::fill_random(&mut random).map_err(|_| Error::Network)?;
    let boundary: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let mut body = Vec::new();
    for (name, bytes) in parts {
        if bytes
            .windows(boundary.len())
            .any(|w| w == boundary.as_bytes())
        {
            return Err(Error::Network);
        }
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
        if body.len() > MAX_BODY {
            return Err(Error::Input);
        }
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    if body.len() > MAX_BODY {
        return Err(Error::Input);
    }
    Ok((format!("multipart/form-data; boundary={boundary}"), body))
}
async fn unpack(reply: Reply) -> Result<Vec<(String, Bytes)>, Error> {
    if reply.body.len() > MAX_BODY {
        return Err(Error::Integrity);
    }
    let boundary = multer::parse_boundary(&reply.content_type).map_err(|_| Error::Integrity)?;
    if boundary.len() > 70 {
        return Err(Error::Integrity);
    }
    let source =
        futures_util::stream::once(async { Ok::<_, std::io::Error>(Bytes::from(reply.body)) });
    let mut parser = multer::Multipart::with_constraints(
        source,
        boundary,
        multer::Constraints::new().size_limit(
            multer::SizeLimit::new()
                .whole_stream(MAX_BODY as u64)
                .per_field(confidex_storage::MAX_OBJECT as u64),
        ),
    );
    let mut parts = Vec::new();
    while let Some(field) = parser.next_field().await.map_err(|_| Error::Integrity)? {
        if parts.len() >= 257 {
            return Err(Error::Integrity);
        }
        let name = field.name().ok_or(Error::Integrity)?.to_owned();
        parts.push((name, field.bytes().await.map_err(|_| Error::Integrity)?));
    }
    Ok(parts)
}
fn one<'a>(parts: &'a [(String, Bytes)], name: &str) -> Result<&'a [u8], Error> {
    let mut values = parts.iter().filter(|(n, _)| n == name);
    let bytes = values.next().ok_or(Error::Integrity)?;
    if values.next().is_some() {
        return Err(Error::Integrity);
    }
    Ok(&bytes.1)
}
async fn checked_lock(reply: Reply, id: [u8; 16]) -> Result<Vec<u8>, Error> {
    if reply.status != 200 {
        return Err(Error::Server(reply.status));
    }
    let etag = reply.etag.clone().ok_or(Error::Integrity)?;
    let parts = unpack(reply).await?;
    if parts.len() != 3 {
        return Err(Error::Integrity);
    }
    let wire = one(&parts, "lock")?;
    let base = std::str::from_utf8(one(&parts, "base")?).map_err(|_| Error::Integrity)?;
    if !base.is_empty()
        && (base.len() != 64
            || !base
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
    {
        return Err(Error::Integrity);
    }
    let header = lock::inspect(wire).map_err(|_| Error::Integrity)?;
    if confidex_vault::sync::id(&header.public_key) != id {
        return Err(Error::Integrity);
    }
    let public = VerifyingKey::from_bytes(&header.public_key).map_err(|_| Error::Integrity)?;
    let signature =
        Signature::from_slice(one(&parts, "signature")?).map_err(|_| Error::Integrity)?;
    public
        .verify_strict(
            &confidex_vault::sync::lock_signature_bytes(wire, base),
            &signature,
        )
        .map_err(|_| Error::Integrity)?;
    let digest: String = Sha256::digest(wire)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if etag != format!("\"{digest}\"") {
        return Err(Error::Integrity);
    }
    Ok(wire.to_vec())
}
pub async fn fetch_lock(
    transport: &mut impl Transport,
    server: &str,
    id: [u8; 16],
) -> Result<Vec<u8>, Error> {
    checked_lock(
        transport.send(&path(server, id), "GET", "", vec![]).await?,
        id,
    )
    .await
}
async fn state(store: &mut impl Store, id: VaultId) -> Result<(Option<Vec<u8>>, State), Error> {
    let bytes = store.sync_state(id).await?;
    let value = match &bytes {
        Some(b) => serde_json::from_slice(b).map_err(|_| Error::Integrity)?,
        None => State::default(),
    };
    Ok((bytes, value))
}
fn checkpoint(
    previous: Option<Vec<u8>>,
    state: &State,
    objects: Vec<StoredObject>,
    heads: Vec<HeadChange>,
) -> Result<SyncCommit, Error> {
    let commit = SyncCommit {
        previous,
        current: serde_json::to_vec(state).map_err(|_| Error::Integrity)?,
        objects,
        heads,
    };
    commit.validate()?;
    Ok(commit)
}
pub(super) async fn publish_local(
    store: &mut impl Store,
    vault: VaultId,
    objects: Vec<StoredObject>,
    heads: Vec<HeadChange>,
) -> Result<(), Error> {
    let previous = store.sync_state(vault).await?;
    let current = match &previous {
        Some(bytes) => bytes.clone(),
        None => serde_json::to_vec(&State::default()).map_err(|_| Error::Integrity)?,
    };
    let commit = SyncCommit {
        previous,
        current,
        objects,
        heads,
    };
    commit.validate()?;
    store.publish_branches(vault, &commit).await?;
    Ok(())
}
pub async fn configured_server(
    store: &mut impl Store,
    vault: VaultId,
) -> Result<Option<String>, Error> {
    let (_, s) = state(store, vault).await?;
    Ok(s.enabled.then_some(s.server))
}
#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn configured_folder(
    store: &mut impl Store,
    vault: VaultId,
) -> Result<Option<String>, Error> {
    let Some(bytes) = store.sync_state(vault).await? else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Error::Integrity)?;
    let object = value.as_object().ok_or(Error::Integrity)?;
    match object.get("folder") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(path))
            if !path.is_empty() && path.len() <= 32768 && !path.contains('\0') =>
        {
            Ok(Some(path.clone()))
        }
        _ => Err(Error::Integrity),
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn configure_folder(
    store: &mut impl Store,
    vault: VaultId,
    path: Option<&str>,
) -> Result<(), Error> {
    let previous = store.sync_state(vault).await?;
    let mut value = match &previous {
        Some(bytes) => {
            serde_json::from_slice::<serde_json::Value>(bytes).map_err(|_| Error::Integrity)?
        }
        None => serde_json::to_value(State::default()).map_err(|_| Error::Integrity)?,
    };
    let object = value.as_object_mut().ok_or(Error::Integrity)?;
    if let Some(path) = path {
        object.insert("folder".into(), path.into());
    } else {
        object.remove("folder");
    }
    store
        .publish_branches(
            vault,
            &SyncCommit {
                previous,
                current: serde_json::to_vec(&value).map_err(|_| Error::Integrity)?,
                objects: vec![],
                heads: vec![],
            },
        )
        .await?;
    Ok(())
}
pub async fn configure(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    server: Option<&str>,
) -> Result<Report, Error> {
    let (previous, mut state) = state(store, vault.vault_id()).await?;
    if let Some(input) = server {
        let server = server_url(input)?;
        if state.server != server {
            state = State {
                server,
                folder: state.folder,
                ..State::default()
            };
        }
        state.enabled = true;
    } else {
        state.enabled = false;
    }
    store
        .publish_branches(
            vault.vault_id(),
            &checkpoint(previous, &state, vec![], vec![])?,
        )
        .await?;
    Ok(Report {
        server: state.enabled.then_some(state.server),
        ..Report::default()
    })
}
pub(super) async fn all_heads(store: &mut impl Store, vault: VaultId) -> Result<Vec<Head>, Error> {
    let mut heads = Vec::new();
    loop {
        let page = store.branch_heads(vault, heads.last(), None).await?;
        if page.is_empty() {
            return Ok(heads);
        }
        heads.extend(page);
        if heads.len() > 100_000 {
            return Err(Error::Input);
        }
    }
}
pub(super) async fn graph(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    heads: &[Head],
) -> Result<Graph, Error> {
    let mut graph = Graph::new(vault.anchor());
    let mut pending: BTreeSet<_> = heads.iter().map(|h| h.revision).collect();
    while !pending.is_empty() {
        let batch: Vec<_> = pending.iter().take(128).copied().collect();
        let mut update = graph
            .begin(batch.len(), MAX_OPEN_MEMORY)
            .map_err(|_| Error::Integrity)?;
        for id in batch {
            pending.remove(&id);
            let wire = store
                .object(vault.vault_id(), id)
                .await
                .map_err(|_| Error::Integrity)?;
            let revision =
                envelope::verify(&wire, vault.anchor(), Some(&id), update.object_budget())
                    .map_err(|_| Error::Integrity)?;
            for parent in &revision.header().parents {
                if !update.contains(parent) {
                    pending.insert(*parent);
                }
            }
            update
                .stage(&revision, None)
                .map_err(|_| Error::Integrity)?;
            if pending.len() > 100_000 {
                return Err(Error::Input);
            }
        }
        graph = update.finish(&[]).map_err(|_| Error::Integrity)?;
        pending.retain(|id| graph.get(id).is_none());
    }
    if !graph.report().missing.is_empty() {
        return Err(Error::Integrity);
    }
    for h in heads {
        if graph
            .get(&h.revision)
            .is_none_or(|n| n.record_id != h.record)
        {
            return Err(Error::Integrity);
        }
    }
    Ok(graph)
}
fn ancestor(graph: &Graph, earlier: RevisionId, later: RevisionId) -> bool {
    let mut todo = vec![later];
    let mut seen = BTreeSet::new();
    while let Some(id) = todo.pop() {
        if id == earlier {
            return true;
        }
        if seen.insert(id)
            && let Some(node) = graph.get(&id)
        {
            todo.extend(&node.parents);
        }
    }
    false
}
pub(super) fn head_changes(combined: &Graph, local: &[Head]) -> Result<Vec<HeadChange>, Error> {
    let desired: BTreeSet<_> = combined.report().heads.iter().copied().collect();
    let present: BTreeSet<_> = local.iter().map(|h| (h.record, h.revision)).collect();
    let mut destinations = BTreeMap::<RecordId, Vec<RevisionId>>::new();
    for &(record, revision) in &desired {
        destinations.entry(record).or_default().push(revision);
    }
    let mut changes = Vec::new();
    let mut targets = BTreeSet::new();
    for head in local {
        if desired.contains(&(head.record, head.revision)) {
            continue;
        }
        let revision = destinations
            .get(&head.record)
            .and_then(|tips| {
                tips.iter()
                    .copied()
                    .find(|&tip| ancestor(combined, head.revision, tip))
            })
            .ok_or(Error::Integrity)?;
        targets.insert((head.record, revision));
        changes.push(HeadChange {
            head: Head {
                record: head.record,
                revision,
            },
            expected: Some(head.revision),
        });
        if changes.len() == 256 {
            break;
        }
    }
    for &(record, revision) in &desired {
        if changes.len() == 256 {
            break;
        }
        if !present.contains(&(record, revision)) && targets.insert((record, revision)) {
            changes.push(HeadChange {
                head: Head { record, revision },
                expected: None,
            });
        }
    }
    Ok(changes)
}
pub async fn step(
    store: &mut impl Store,
    transport: &mut impl Transport,
    vault: &lock::OpenedVault,
    input: &str,
) -> Result<Report, Error> {
    let server = server_url(input)?;
    let id = address(vault);
    let url = path(&server, id);
    let (mut previous, mut state) = state(store, vault.vault_id()).await?;
    if !state.enabled || state.server != server {
        return Err(Error::SyncDisabled);
    }
    let mut reply = transport.send(&url, "GET", "", vec![]).await?;
    if reply.status == 404 {
        let wire = store.vault(vault.vault_id()).await?.lock;
        let signature = vault
            .keys()
            .signing_key()
            .sign(&confidex_vault::sync::lock_signature_bytes(&wire, ""));
        let (content_type, body) =
            encode(&[("lock", &wire), ("signature", &signature.to_bytes())])?;
        let registered = transport
            .send(&format!("{server}v1/sync"), "POST", &content_type, body)
            .await?;
        if !matches!(registered.status, 200 | 201 | 409) {
            return Err(Error::Server(registered.status));
        }
        reply = transport.send(&url, "GET", "", vec![]).await?;
    }
    let wire = checked_lock(reply, id).await?;
    let header = lock::inspect(&wire).map_err(|_| Error::Integrity)?;
    if header.vault_id != vault.vault_id() || header.public_key != vault.anchor().public_key() {
        return Err(Error::Integrity);
    }
    state.lock_digest = Some(
        Sha256::digest(&wire)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    );
    let mut remote_graph = graph(store, vault, &state.heads).await?;
    let response = transport
        .send(
            &format!("{url}/records?after={}", state.cursor),
            "GET",
            "",
            vec![],
        )
        .await?;
    if response.status != 200 {
        return Err(Error::Server(response.status));
    }
    let parts = unpack(response).await?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Meta {
        cursor: String,
        has_more: bool,
    }
    let meta: Meta = serde_json::from_slice(one(&parts, "meta")?).map_err(|_| Error::Integrity)?;
    if parts
        .iter()
        .any(|(name, _)| name != "meta" && name != "record")
    {
        return Err(Error::Integrity);
    }
    let records: Vec<_> = parts.iter().filter(|(n, _)| n == "record").collect();
    if records.len() > 256 || (meta.has_more && records.is_empty()) {
        return Err(Error::Integrity);
    }
    let cursor: u64 = meta.cursor.parse().map_err(|_| Error::Integrity)?;
    if state.cursor.checked_add(records.len() as u64) != Some(cursor) {
        return Err(Error::Integrity);
    }
    let mut report = Report {
        server: Some(server),
        downloaded: records.len(),
        ..Report::default()
    };
    if !records.is_empty() {
        let mut update = remote_graph
            .begin(records.len(), MAX_OPEN_MEMORY)
            .map_err(|_| Error::Integrity)?;
        let mut objects = Vec::new();
        for (_, wire) in records {
            let verified = envelope::verify(wire, vault.anchor(), None, update.object_budget())
                .map_err(|_| Error::Integrity)?;
            if update.contains(&verified.id())
                || verified
                    .header()
                    .parents
                    .iter()
                    .any(|p| !update.contains(p))
            {
                return Err(Error::Integrity);
            }
            update
                .stage(&verified, None)
                .map_err(|_| Error::Integrity)?;
            let record = verified
                .open(vault.keys(), update.object_budget())
                .map_err(|_| Error::Integrity)?;
            objects.push(StoredObject {
                head: Head {
                    record: verified.header().record_id,
                    revision: verified.id(),
                },
                wire: wire.to_vec(),
                tags: if verified.header().kind == EventKind::Deletion {
                    Vec::new()
                } else {
                    record.tags.clone()
                },
            });
        }
        remote_graph = update.finish(&[]).map_err(|_| Error::Integrity)?;
        if !remote_graph.report().missing.is_empty() {
            return Err(Error::Integrity);
        }
        state.cursor = cursor;
        state.heads = remote_graph
            .report()
            .heads
            .iter()
            .map(|(record, revision)| Head {
                record: *record,
                revision: *revision,
            })
            .collect();
        let commit = checkpoint(previous, &state, objects, vec![])?;
        store.publish_branches(vault.vault_id(), &commit).await?;
        previous = Some(commit.current);
    }
    if meta.has_more {
        report.more = true;
        return Ok(report);
    }
    let local = all_heads(store, vault.vault_id()).await?;
    let mut both = local.clone();
    both.extend_from_slice(&state.heads);
    let combined = graph(store, vault, &both).await?;
    let changes = head_changes(&combined, &local)?;
    if !changes.is_empty() {
        store
            .publish_branches(
                vault.vault_id(),
                &checkpoint(previous, &state, vec![], changes)?,
            )
            .await?;
        report.more = true;
        return Ok(report);
    }
    let mut seen = BTreeSet::new();
    let mut todo: Vec<_> = local.iter().map(|h| (h.revision, false)).collect();
    let mut ordered = Vec::new();
    while let Some((id, ready)) = todo.pop() {
        if remote_graph.get(&id).is_some() {
            continue;
        }
        if ready {
            ordered.push(id);
            continue;
        }
        if !seen.insert(id) {
            continue;
        }
        todo.push((id, true));
        let node = combined.get(&id).ok_or(Error::Integrity)?;
        todo.extend(node.parents.iter().map(|id| (*id, false)));
    }
    let mut wires = Vec::new();
    let mut bytes = 0;
    let mut parents = 0;
    for id in ordered.into_iter().take(PUSH_RECORDS) {
        let node = combined.get(&id).ok_or(Error::Integrity)?;
        let wire = store.object(vault.vault_id(), id).await?;
        if bytes + wire.len() + 512 * (wires.len() + 2) > MAX_BODY
            || parents + node.parents.len() > 256
        {
            break;
        }
        bytes += wire.len();
        parents += node.parents.len();
        wires.push(wire);
    }
    if wires.is_empty() {
        if !seen.is_empty() {
            return Err(Error::Input);
        }
        let commit = checkpoint(previous, &state, vec![], vec![])?;
        if commit.previous.as_deref() != Some(commit.current.as_slice()) {
            store.publish_branches(vault.vault_id(), &commit).await?;
        }
        return Ok(report);
    }
    let base = state.cursor.to_string();
    loop {
        let parts: Vec<_> = std::iter::once(("base", base.as_bytes()))
            .chain(wires.iter().map(|w| ("record", w.as_slice())))
            .collect();
        let (content_type, body) = encode(&parts)?;
        let size = body.len();
        let pushed = transport
            .send(&format!("{url}/records"), "POST", &content_type, body)
            .await?;
        if pushed.status == 413 {
            let limit = pushed
                .max_body
                .filter(|n| *n > 0 && *n <= MAX_BODY)
                .ok_or(Error::Server(413))?;
            if wires.len() == 1 || size <= limit {
                return Err(Error::Server(413));
            }
            wires.truncate(wires.len().div_ceil(2));
            continue;
        }
        if pushed.status == 409 {
            report.more = true;
            return Ok(report);
        }
        if pushed.status != 200 {
            return Err(Error::Server(pushed.status));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ack {
            cursor: String,
            accepted: usize,
        }
        let ack: Ack = serde_json::from_slice(&pushed.body).map_err(|_| Error::Integrity)?;
        if ack.accepted != wires.len()
            || ack.cursor.parse::<u64>().ok() != state.cursor.checked_add(wires.len() as u64)
        {
            return Err(Error::Integrity);
        }
        report.uploaded = wires.len();
        report.more = true;
        return Ok(report);
    }
}

pub async fn check(
    store: &mut impl Store,
    transport: &mut impl Transport,
    vault: &lock::OpenedVault,
    input: &str,
) -> Result<Option<Report>, Error> {
    let server = server_url(input)?;
    let (_, state) = state(store, vault.vault_id()).await?;
    if !state.enabled || state.server != server {
        return Err(Error::SyncDisabled);
    }
    if let Some(digest) = &state.lock_digest {
        let reply = transport
            .send(&path(&server, address(vault)), "HEAD", "", vec![])
            .await?;
        if reply.status == 200 {
            let cursor: u64 = reply
                .cursor
                .as_deref()
                .ok_or(Error::Integrity)?
                .parse()
                .map_err(|_| Error::Integrity)?;
            if cursor < state.cursor {
                return Err(Error::Integrity);
            }
            // A checkpoint only triggers synchronization; it never publishes remote data.
            if cursor == state.cursor
                && reply.etag.as_deref() == Some(format!("\"{digest}\"").as_str())
                && all_heads(store, vault.vault_id()).await? == state.heads
            {
                return Ok(None);
            }
        } else if reply.status != 404 {
            return Err(Error::Server(reply.status));
        }
    }
    step(store, transport, vault, &server).await.map(Some)
}

pub async fn resolve(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    record: RecordId,
    local: RevisionId,
    remote: RevisionId,
    keep_local: bool,
    epoch: u64,
) -> Result<(), Error> {
    check_conflict(store, vault, record, local, remote).await?;
    let selected = if keep_local { local } else { remote };
    let wire = store.object(vault.vault_id(), selected).await?;
    let opened = envelope::open(
        &wire,
        vault.keys(),
        vault.anchor(),
        Some(&selected),
        MAX_OPEN_MEMORY,
    )
    .map_err(|_| Error::Integrity)?;
    let wire = envelope::seal(
        &opened.record,
        vault.keys(),
        Options {
            vault_id: vault.vault_id(),
            record_id: record,
            parents: &[local, remote],
            epoch,
            kind: opened.revision.header().kind,
        },
        MAX_OPEN_MEMORY,
    )
    .map_err(|_| Error::Input)?;
    let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
        .map_err(|_| Error::Integrity)?
        .id();
    let mut tags = if opened.revision.header().kind == EventKind::Deletion {
        Vec::new()
    } else {
        opened.record.tags.clone()
    };
    tags.sort_unstable();
    publish_local(
        store,
        vault.vault_id(),
        vec![StoredObject {
            head: Head { record, revision },
            wire,
            tags,
        }],
        [local, remote]
            .into_iter()
            .map(|expected| HeadChange {
                head: Head { record, revision },
                expected: Some(expected),
            })
            .collect(),
    )
    .await
}

pub(super) async fn check_conflict(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    record: RecordId,
    local: RevisionId,
    remote: RevisionId,
) -> Result<(), Error> {
    let (_, state) = state(store, vault.vault_id()).await?;
    let current = record_heads(store, vault.vault_id(), record).await?;
    if local == remote
        || !state
            .heads
            .iter()
            .any(|h| h.record == record && h.revision == remote)
        || ![local, remote]
            .iter()
            .all(|revision| current.iter().any(|h| h.revision == *revision))
    {
        return Err(confidex_storage::Error::Conflict.into());
    }
    let selected = [local, remote].map(|revision| Head { record, revision });
    graph(store, vault, &selected).await?;
    Ok(())
}
