use crate::{
    storage::{BlobRef, Blobs as BlobTrait, Index as IndexTrait, Statement},
    *,
};
use rusqlite::Connection;
use sqlx::Row;
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
pub enum Index {
    Sqlite(Arc<Mutex<Connection>>),
    Postgres(sqlx::PgPool),
}
impl Index {
    pub async fn open(url: &str) -> Result<Self> {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(4)
                .connect(url)
                .await
                .map_err(|_| Error::Storage)?;
            sqlx::raw_sql(include_str!("../schema.sql"))
                .execute(&pool)
                .await
                .map_err(|_| Error::Storage)?;
            Ok(Self::Postgres(pool))
        } else {
            let connection = Connection::open(url.strip_prefix("sqlite:").unwrap_or(url))
                .map_err(|_| Error::Storage)?;
            connection
                .busy_timeout(Duration::from_secs(5))
                .map_err(|_| Error::Storage)?;
            connection
                .pragma_update(None, "journal_mode", "WAL")
                .map_err(|_| Error::Storage)?;
            connection
                .pragma_update(None, "synchronous", "FULL")
                .map_err(|_| Error::Storage)?;
            connection
                .pragma_update(None, "foreign_keys", true)
                .map_err(|_| Error::Storage)?;
            connection
                .execute_batch(include_str!("../schema.sql"))
                .map_err(|_| Error::Storage)?;
            Ok(Self::Sqlite(Arc::new(Mutex::new(connection))))
        }
    }
}
impl IndexTrait for Index {
    async fn query(
        &self,
        expression: &str,
        suffix: &str,
        values: &[String],
    ) -> Result<Vec<serde_json::Value>> {
        let texts: Vec<String> = match self {
            Self::Sqlite(db) => {
                let db = db.lock().map_err(|_| Error::Storage)?;
                let mut statement = db
                    .prepare(&format!("SELECT CAST({expression} AS TEXT) {suffix}"))
                    .map_err(|_| Error::Storage)?;
                statement
                    .query_map(rusqlite::params_from_iter(values), |row| row.get(0))
                    .map_err(|_| Error::Storage)?
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|_| Error::Storage)?
            }
            Self::Postgres(pool) => {
                let expression = expression
                    .replace("json_object(", "json_build_object(")
                    .replace("json_quote(", "to_json(");
                let sql = format!("SELECT CAST({expression} AS TEXT) {suffix}");
                // Only SQL templates reach this call; values use bind parameters.
                let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
                for value in values {
                    query = query.bind(value);
                }
                query
                    .fetch_all(pool)
                    .await
                    .map_err(|_| Error::Storage)?
                    .into_iter()
                    .map(|r| r.try_get(0).map_err(|_| Error::Storage))
                    .collect::<Result<_>>()?
            }
        };
        texts
            .into_iter()
            .map(|t| serde_json::from_str(&t).map_err(|_| Error::Storage))
            .collect()
    }
    async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<u64>> {
        match self {
            Self::Sqlite(db) => {
                let mut db = db.lock().map_err(|_| Error::Storage)?;
                let tx = db
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|_| Error::Storage)?;
                let mut changes = Vec::new();
                for s in statements {
                    changes.push(tx.execute(&s.sql,rusqlite::params_from_iter(&s.values))
                    .map_err(|e| if matches!(e,rusqlite::Error::SqliteFailure(code,_) if code.code==rusqlite::ErrorCode::ConstraintViolation) {Error::Conflict} else {Error::Storage})? as u64);
                }
                tx.commit().map_err(|_| Error::Storage)?;
                Ok(changes)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(|_| Error::Storage)?;
                let mut changes = Vec::new();
                for s in statements {
                    let mut query = sqlx::query(sqlx::AssertSqlSafe(s.sql.as_str()));
                    for value in &s.values {
                        query = query.bind(value);
                    }
                    changes.push(
                        query
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| {
                                if e.as_database_error()
                                    .is_some_and(|e| e.is_unique_violation())
                                {
                                    Error::Conflict
                                } else {
                                    Error::Storage
                                }
                            })?
                            .rows_affected(),
                    );
                }
                tx.commit().await.map_err(|_| Error::Storage)?;
                Ok(changes)
            }
        }
    }
}

pub enum Blobs {
    Posix(PathBuf),
    Git(PathBuf),
    S3(crate::s3::S3, reqwest::Client),
}
impl Blobs {
    pub fn posix(path: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&path).map_err(|_| Error::Storage)?;
        Ok(Self::Posix(path))
    }
    pub fn git(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            let result = std::process::Command::new("git")
                .args(["init", "--bare", "--quiet"])
                .arg(&path)
                .output()
                .map_err(|_| Error::Storage)?;
            if !result.status.success() {
                return Err(Error::Storage);
            }
        }
        let result = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&path)
            .args(["rev-parse", "--is-bare-repository"])
            .output()
            .map_err(|_| Error::Storage)?;
        if !result.status.success() || result.stdout != b"true\n" {
            return Err(Error::Storage);
        }
        Ok(Self::Git(path))
    }
    pub fn s3(s3: crate::s3::S3) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Storage)?;
        Ok(Self::S3(s3, client))
    }
}
impl BlobTrait for Blobs {
    async fn get(&self, blob: BlobRef<'_>) -> Result<Bytes> {
        let key = blob.digest;
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Storage);
        }
        let bytes = match self {
            Self::Posix(root) => {
                let file = std::fs::File::open(root.join(key)).map_err(|_| Error::Storage)?;
                let mut bytes = Vec::new();
                file.take(MAX_BODY as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| Error::Storage)?;
                bytes
            }
            Self::Git(root) => {
                let mut child = std::process::Command::new("git")
                    .arg("--git-dir")
                    .arg(root)
                    .args(["cat-file", "blob", &format!("refs/confidexsyncd/{key}")])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|_| Error::Storage)?;
                let mut bytes = Vec::new();
                child
                    .stdout
                    .take()
                    .ok_or(Error::Storage)?
                    .take(MAX_BODY as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| Error::Storage)?;
                if bytes.len() > MAX_BODY {
                    let _ = child.kill();
                }
                if !child.wait().map_err(|_| Error::Storage)?.success() {
                    return Err(Error::Storage);
                }
                bytes
            }
            Self::S3(s3, client) => {
                let mut response = client
                    .get(s3.url(blob, false)?)
                    .send()
                    .await
                    .map_err(|_| Error::Storage)?;
                if !response.status().is_success() {
                    return Err(Error::Storage);
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
                    if bytes.len() + chunk.len() > MAX_BODY {
                        return Err(Error::Storage);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                bytes
            }
        };
        if bytes.len() > MAX_BODY || digest(&bytes) != key {
            return Err(Error::Storage);
        }
        Ok(Bytes::from(bytes))
    }
    async fn put(&self, blob: BlobRef<'_>, bytes: &[u8]) -> Result<()> {
        let key = blob.digest;
        if digest(bytes) != key || bytes.len() > MAX_BODY {
            return Err(Error::Storage);
        }
        match self {
            Self::Posix(root) => {
                let mut file = tempfile::NamedTempFile::new_in(root).map_err(|_| Error::Storage)?;
                file.write_all(bytes).map_err(|_| Error::Storage)?;
                file.as_file().sync_all().map_err(|_| Error::Storage)?;
                match file.persist_noclobber(root.join(key)) {
                    Ok(_) => {}
                    Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.get(blob).await?;
                    }
                    Err(_) => return Err(Error::Storage),
                }
                #[cfg(unix)]
                std::fs::File::open(root)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| Error::Storage)?;
                Ok(())
            }
            Self::Git(root) => {
                let mut child = std::process::Command::new("git")
                    .args([
                        "-c",
                        "core.fsync=loose-object,reference",
                        "-c",
                        "core.fsyncMethod=fsync",
                    ])
                    .arg("--git-dir")
                    .arg(root)
                    .args(["hash-object", "-w", "--stdin"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|_| Error::Storage)?;
                child
                    .stdin
                    .take()
                    .ok_or(Error::Storage)?
                    .write_all(bytes)
                    .map_err(|_| Error::Storage)?;
                let output = child.wait_with_output().map_err(|_| Error::Storage)?;
                if !output.status.success() {
                    return Err(Error::Storage);
                }
                let hash = std::str::from_utf8(&output.stdout)
                    .map_err(|_| Error::Storage)?
                    .trim();
                let output = std::process::Command::new("git")
                    .args([
                        "-c",
                        "core.fsync=loose-object,reference",
                        "-c",
                        "core.fsyncMethod=fsync",
                    ])
                    .arg("--git-dir")
                    .arg(root)
                    .args(["update-ref", &format!("refs/confidexsyncd/{key}"), hash])
                    .output()
                    .map_err(|_| Error::Storage)?;
                if output.status.success() {
                    Ok(())
                } else {
                    Err(Error::Storage)
                }
            }
            Self::S3(s3, client) => {
                let response = client
                    .put(s3.url(blob, true)?)
                    .body(bytes.to_vec())
                    .send()
                    .await
                    .map_err(|_| Error::Storage)?;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(Error::Storage)
                }
            }
        }
    }
}

#[derive(Clone)]
struct State {
    index: Index,
    blobs: Arc<storage::Mirrors<Blobs>>,
    admission: Arc<tokio::sync::Semaphore>,
    limits: Limits,
}
pub fn router(index: Index, blobs: Vec<Blobs>, limits: Limits) -> axum::Router {
    axum::Router::new()
        .fallback(endpoint)
        .layer(axum::middleware::map_response(
            |response: axum::response::Response| async { cors(response) },
        ))
        .with_state(State {
            index,
            blobs: Arc::new(storage::Mirrors(blobs)),
            admission: Arc::new(tokio::sync::Semaphore::new(4)),
            limits,
        })
}
async fn endpoint(
    axum::extract::State(state): axum::extract::State<State>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(public) = public_response(request.method().as_str(), request.uri().path()) {
        return public.map(axum::body::Body::from);
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    };
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        Duration::from_secs(30),
        axum::body::to_bytes(body, state.limits.body_bytes),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => {
            return state
                .limits
                .response(Error::TooLarge.response())
                .map(axum::body::Body::from);
        }
        Err(_) => return (StatusCode::REQUEST_TIMEOUT, "request_timeout").into_response(),
    };
    let runtime = tokio::runtime::Handle::current();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        runtime.block_on(handle(
            &state.index,
            &*state.blobs,
            Request::from_parts(parts, body),
            state.limits,
        ))
    })
    .await
    {
        Ok(r) => r.map(axum::body::Body::from),
        Err(_) => Error::Storage.response().map(axum::body::Body::from),
    }
}
