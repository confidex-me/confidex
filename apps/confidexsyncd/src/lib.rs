use bytes::Bytes;
use confidex_vault::{envelope, lock, resources, trust::TrustAnchor};
use futures_util::stream;
use http::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(target_arch = "wasm32")]
mod cloudflare;
#[cfg(not(target_arch = "wasm32"))]
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
pub mod s3;
pub mod storage;

pub const MAX_BODY: usize = 8_000_000;
pub const MAX_RECORDS: usize = 256;
pub const MAX_PAGE_BYTES: usize = MAX_BODY - 131_072;
pub use confidex_vault::sync::LOCK_SIGNATURE_DOMAIN;

#[derive(Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub body_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            body_bytes: MAX_BODY,
        }
    }
}
impl Limits {
    pub fn from_env(value: Option<String>) -> Result<Self> {
        Self {
            body_bytes: match value {
                Some(value) => value.parse().map_err(|_| Error::Storage)?,
                None => MAX_BODY,
            },
        }
        .validate()
    }
    pub fn validate(self) -> Result<Self> {
        if self.body_bytes == 0 || self.body_bytes > MAX_BODY {
            return Err(Error::Storage);
        }
        Ok(self)
    }
    pub fn response(self, mut response: Response<Vec<u8>>) -> Response<Vec<u8>> {
        if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
            response.headers_mut().insert(
                "Sync-Max-Body-Bytes",
                self.body_bytes.to_string().parse().unwrap(),
            );
        }
        response
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadRequest,
    Forbidden,
    NotFound,
    Conflict,
    Precondition,
    TooLarge,
    Invalid,
    Storage,
}
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn response(self) -> Response<Vec<u8>> {
        let (status, code) = match self {
            Self::BadRequest => (400, "bad_request"),
            Self::Forbidden => (403, "invalid_signature"),
            Self::NotFound => (404, "not_found"),
            Self::Conflict => (409, "merge_required"),
            Self::Precondition => (412, "lock_changed"),
            Self::TooLarge => (413, "content_too_large"),
            Self::Invalid => (422, "invalid_object"),
            Self::Storage => (503, "storage_unavailable"),
        };
        json(status, serde_json::json!({"error":code}))
    }
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn lock_id(public_key: &[u8; 32]) -> String {
    Uuid::from_bytes(confidex_vault::sync::id(public_key)).to_string()
}

pub fn lock_signature_bytes(wire: &[u8], previous: &str) -> Vec<u8> {
    confidex_vault::sync::lock_signature_bytes(wire, previous)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Lock {
    pub id: String,
    pub vault_id: String,
    pub public_key: String,
    pub blob: String,
    pub signature: String,
    pub previous: String,
    pub cursor: i64,
}
impl Lock {
    pub fn anchor(&self) -> Result<TrustAnchor> {
        let vault = hex::decode(&self.vault_id).map_err(|_| Error::Storage)?;
        let key = hex::decode(&self.public_key).map_err(|_| Error::Storage)?;
        TrustAnchor::from_local_pin(
            vault.try_into().map_err(|_| Error::Storage)?,
            Some(&key.try_into().map_err(|_| Error::Storage)?),
        )
        .map_err(|_| Error::Storage)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub revision: String,
    pub record_id: String,
    pub blob: String,
    pub size: i64,
}

pub fn verify_lock(wire: &[u8], signature: &[u8], previous: &str) -> Result<Lock> {
    let header = lock::inspect(wire).map_err(|_| Error::Invalid)?;
    let anchor = TrustAnchor::from_local_pin(header.vault_id, Some(&header.public_key))
        .map_err(|_| Error::Invalid)?;
    let signature: &[u8; 64] = signature.try_into().map_err(|_| Error::BadRequest)?;
    anchor
        .verify(
            &header.vault_id,
            &lock_signature_bytes(wire, previous),
            signature,
        )
        .map_err(|_| Error::Forbidden)?;
    Ok(Lock {
        id: lock_id(&header.public_key),
        vault_id: hex::encode(header.vault_id),
        public_key: hex::encode(header.public_key),
        blob: digest(wire),
        signature: hex::encode(signature),
        previous: previous.to_owned(),
        cursor: 0,
    })
}

pub async fn rows<T: DeserializeOwned>(
    index: &impl storage::Index,
    expression: &str,
    suffix: &str,
    values: &[String],
) -> Result<Vec<T>> {
    index
        .query(expression, suffix, values)
        .await?
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Storage))
        .collect()
}

async fn multipart(content_type: &str, body: Bytes) -> Result<Vec<(String, Bytes)>> {
    if body.len() > MAX_BODY {
        return Err(Error::TooLarge);
    }
    let boundary = multer::parse_boundary(content_type).map_err(|_| Error::BadRequest)?;
    if boundary.len() > 70 {
        return Err(Error::BadRequest);
    }
    let source = stream::once(async { Ok::<_, std::io::Error>(body) });
    let constraints = multer::Constraints::new().size_limit(
        multer::SizeLimit::new()
            .whole_stream(MAX_BODY as u64)
            .per_field(envelope::MAX_ENVELOPE as u64),
    );
    let mut parser = multer::Multipart::with_constraints(source, boundary, constraints);
    let mut parts = Vec::new();
    while let Some(field) = parser.next_field().await.map_err(|_| Error::BadRequest)? {
        if parts.len() > MAX_RECORDS {
            return Err(Error::TooLarge);
        }
        let name = field.name().ok_or(Error::BadRequest)?.to_owned();
        if !matches!(name.as_str(), "lock" | "signature" | "base" | "record") {
            return Err(Error::BadRequest);
        }
        let value = field.bytes().await.map_err(|_| Error::BadRequest)?;
        parts.push((name, value));
    }
    Ok(parts)
}

fn one<'a>(parts: &'a [(String, Bytes)], name: &str) -> Result<&'a [u8]> {
    let mut found = parts.iter().filter(|(n, _)| n == name);
    let value = found.next().ok_or(Error::BadRequest)?;
    if found.next().is_some() {
        return Err(Error::BadRequest);
    }
    Ok(&value.1)
}

pub fn encode_multipart(parts: &[(&str, &[u8])]) -> (String, Vec<u8>) {
    let mut boundary = "confidex-sync".to_owned();
    while parts
        .iter()
        .any(|(_, b)| b.windows(boundary.len()).any(|w| w == boundary.as_bytes()))
    {
        boundary.push('x');
    }
    let mut out = Vec::new();
    for (name, body) in parts {
        out.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), out)
}

fn json(status: u16, value: serde_json::Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .body(value.to_string().into_bytes())
        .unwrap()
}
fn multi(parts: &[(&str, &[u8])]) -> Response<Vec<u8>> {
    let (content_type, body) = encode_multipart(parts);
    Response::builder()
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .body(body)
        .unwrap()
}

pub async fn handle<I: storage::Index, B: storage::Blobs>(
    index: &I,
    blobs: &B,
    request: Request<Bytes>,
    limits: Limits,
) -> Response<Vec<u8>> {
    if let Some(response) = public_response(request.method().as_str(), request.uri().path()) {
        return response;
    }
    if request.body().len() > limits.body_bytes {
        return limits.response(Error::TooLarge.response());
    }
    limits.response(match dispatch(index, blobs, request).await {
        Ok(r) => r,
        Err(e) => e.response(),
    })
}

pub fn public_response(method: &str, path: &str) -> Option<Response<Vec<u8>>> {
    if method == "OPTIONS" {
        return Some(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header(
                    "Access-Control-Allow-Methods",
                    "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
                )
                .header("Access-Control-Allow-Headers", "*, Authorization")
                .header("Access-Control-Max-Age", "86400")
                .body(Vec::new())
                .unwrap(),
        );
    }
    if !matches!(method, "GET" | "HEAD") {
        return None;
    }
    if path == "/" {
        return Some(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Cache-Control", "no-store")
                .body(Vec::new())
                .unwrap(),
        );
    }
    let (content_type, body): (&str, &[u8]) = match path {
        "/v1" | "/v1/" => (
            "text/html; charset=utf-8",
            include_bytes!("../openapi.html"),
        ),
        "/v1/openapi.json" => ("application/json", include_bytes!("../openapi.json")),
        "/v1/swagger-ui/5.34.1/swagger-ui.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../swagger-ui/swagger-ui.css"),
        ),
        "/v1/swagger-ui/5.34.1/swagger-ui-bundle.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../swagger-ui/swagger-ui-bundle.js"),
        ),
        "/v1/swagger-ui/5.34.1/swagger-ui-bundle.js.LICENSE.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("../swagger-ui/swagger-ui-bundle.js.LICENSE.txt"),
        ),
        _ => return None,
    };
    Some(
        Response::builder()
            .header("Content-Type", content_type)
            .header("Cache-Control", if path.starts_with("/v1/swagger-ui/") { "public, max-age=31536000, immutable" } else { "no-store" })
            .header("Referrer-Policy", "no-referrer")
            .header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'")
            .body(if method == "HEAD" {
                Vec::new()
            } else {
                body.to_vec()
            })
            .unwrap(),
    )
}

pub fn cors<B>(mut response: Response<B>) -> Response<B> {
    response
        .headers_mut()
        .insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    response
        .headers_mut()
        .insert("Access-Control-Expose-Headers", "*".parse().unwrap());
    response
}

async fn dispatch<I: storage::Index, B: storage::Blobs>(
    index: &I,
    blobs: &B,
    request: Request<Bytes>,
) -> Result<Response<Vec<u8>>> {
    let (request, body) = request.into_parts();
    if body.len() > MAX_BODY {
        return Err(Error::TooLarge);
    }
    if request.headers.contains_key("content-encoding") {
        return Err(Error::BadRequest);
    }
    let root = request.uri.path() == "/v1/sync";
    let tail = request.uri.path().strip_prefix("/v1/sync/").unwrap_or("");
    let mut path = tail.split('/');
    let id = path.next().unwrap_or("");
    let records = path.next() == Some("records");
    if !root && (Uuid::parse_str(id).is_err() || path.next().is_some() || (!records && tail != id))
    {
        return Err(Error::NotFound);
    }
    let content_type = request
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let store = storage::Store { index, blobs };
    if root && request.method == "POST" {
        let parts = multipart(content_type, body).await?;
        if parts.len() != 2 {
            return Err(Error::BadRequest);
        }
        let wire = one(&parts, "lock")?;
        let lock = verify_lock(wire, one(&parts, "signature")?, "")?;
        let created = store.create(&lock, wire).await?;
        let mut response = json(
            if created { 201 } else { 200 },
            serde_json::json!({"id":lock.id}),
        );
        response
            .headers_mut()
            .insert("etag", format!("\"{}\"", lock.blob).parse().unwrap());
        return Ok(response);
    }
    if root {
        return Ok(Response::builder()
            .status(405)
            .header("Allow", "POST")
            .body(Vec::new())
            .unwrap());
    }
    let lock = store.lock(id).await?;
    if !records && request.method == "HEAD" {
        return Ok(Response::builder()
            .header("ETag", format!("\"{}\"", lock.blob))
            .header("Sync-Cursor", lock.cursor.to_string())
            .header("Cache-Control", "no-store")
            .body(Vec::new())
            .unwrap());
    }
    if !records && request.method == "GET" {
        let wire = blobs.get(storage::BlobRef::lock(id, &lock.blob)).await?;
        if digest(&wire) != lock.blob {
            return Err(Error::Storage);
        }
        let signature = hex::decode(&lock.signature).map_err(|_| Error::Storage)?;
        let mut response = multi(&[
            ("lock", &wire),
            ("signature", &signature),
            ("base", lock.previous.as_bytes()),
        ]);
        response
            .headers_mut()
            .insert("etag", format!("\"{}\"", lock.blob).parse().unwrap());
        return Ok(response);
    }
    if !records && request.method == "PUT" {
        let expected = request
            .headers
            .get("if-match")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix('"'))
            .and_then(|v| v.strip_suffix('"'))
            .ok_or(Error::Precondition)?;
        if expected != lock.blob {
            return Err(Error::Precondition);
        }
        let parts = multipart(content_type, body).await?;
        if parts.len() != 2 {
            return Err(Error::BadRequest);
        }
        let wire = one(&parts, "lock")?;
        let updated = verify_lock(wire, one(&parts, "signature")?, expected)?;
        if updated.id != id
            || updated.public_key != lock.public_key
            || updated.vault_id != lock.vault_id
        {
            return Err(Error::Forbidden);
        }
        store.replace(&updated, wire, expected).await?;
        let mut response = json(200, serde_json::json!({"id":id}));
        response
            .headers_mut()
            .insert("etag", format!("\"{}\"", updated.blob).parse().unwrap());
        return Ok(response);
    }
    if records && request.method == "POST" {
        let parts = multipart(content_type, body).await?;
        let base = parse_cursor(
            std::str::from_utf8(one(&parts, "base")?).map_err(|_| Error::BadRequest)?,
        )?;
        if base != lock.cursor {
            return Err(Error::Conflict);
        }
        let anchor = lock.anchor()?;
        let mut pending: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut records = Vec::new();
        let mut parent_count = 0;
        for (name, wire) in &parts {
            if name == "base" {
                continue;
            }
            if name != "record" {
                return Err(Error::BadRequest);
            }
            let verified = envelope::verify(wire, &anchor, None, resources::MAX_OPEN_MEMORY)
                .map_err(|_| Error::Invalid)?;
            let revision = hex::encode(verified.id());
            let record_id = hex::encode(verified.header().record_id);
            if pending.contains_key(&revision) || store.record(id, &revision).await?.is_some() {
                return Err(Error::Conflict);
            }
            parent_count += verified.header().parents.len();
            if parent_count > 256 {
                return Err(Error::TooLarge);
            }
            for parent in &verified.header().parents {
                let parent = hex::encode(parent);
                let parent_record = match pending.get(&parent) {
                    Some(r) => Some(r.clone()),
                    None => store.record(id, &parent).await?,
                };
                if parent_record.as_deref() != Some(record_id.as_str()) {
                    return Err(Error::Invalid);
                }
            }
            pending.insert(revision.clone(), record_id.clone());
            records.push(Record {
                revision,
                record_id,
                blob: digest(wire),
                size: wire.len() as i64,
            });
        }
        if records.is_empty() {
            return Err(Error::BadRequest);
        }
        for (record, (_, wire)) in records
            .iter()
            .zip(parts.iter().filter(|(n, _)| n == "record"))
        {
            blobs
                .put(storage::BlobRef::record(id, &record.blob), wire)
                .await?;
        }
        let cursor = store.append(id, base, &records).await?;
        return Ok(json(
            200,
            serde_json::json!({"cursor":cursor.to_string(),"accepted":records.len()}),
        ));
    }
    if records && request.method == "GET" {
        let query = request.uri.query().unwrap_or("after=0");
        let after = parse_cursor(query.strip_prefix("after=").ok_or(Error::BadRequest)?)?;
        if after > lock.cursor {
            return Err(Error::BadRequest);
        }
        let (cursor, has_more, objects) = store.page(id, after, lock.cursor).await?;
        let meta = serde_json::json!({"cursor":cursor.to_string(),"has_more":has_more}).to_string();
        let mut parts = vec![("meta", meta.as_bytes())];
        parts.extend(objects.iter().map(|b| ("record", b.as_ref())));
        let response = multi(&parts);
        if response.body().len() > MAX_BODY {
            return Err(Error::Storage);
        }
        return Ok(response);
    }
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header("Allow", if records { "GET, POST" } else { "GET, PUT" })
        .body(Vec::new())
        .unwrap())
}

fn parse_cursor(value: &str) -> Result<i64> {
    if value.len() > 19 || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::BadRequest);
    }
    value.parse().map_err(|_| Error::BadRequest)
}
