use crate::{
    storage::{BlobRef, Blobs as BlobTrait, Index as IndexTrait, Statement},
    *,
};
use futures_util::StreamExt;
use wasm_bindgen::{JsCast, JsValue};
use worker::{
    Context, D1DatabaseSession, D1SessionConstraint, Env, Fetch, Request as WorkerRequest,
    Response as WorkerResponse, event,
};

struct Index(D1DatabaseSession);
impl IndexTrait for Index {
    async fn query(
        &self,
        expression: &str,
        suffix: &str,
        values: &[String],
    ) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize)]
        struct Row {
            value: String,
        }
        let values: Vec<JsValue> = values.iter().map(|v| JsValue::from_str(v)).collect();
        let result = self
            .0
            .prepare(format!(
                "SELECT CAST({expression} AS TEXT) AS value {suffix}"
            ))
            .bind(&values)
            .map_err(|_| Error::Storage)?
            .all()
            .await
            .map_err(|_| Error::Storage)?;
        result
            .results::<Row>()
            .map_err(|_| Error::Storage)?
            .into_iter()
            .map(|r| serde_json::from_str(&r.value).map_err(|_| Error::Storage))
            .collect()
    }
    async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<u64>> {
        let statements = statements
            .into_iter()
            .map(|s| {
                let values: Vec<JsValue> = s.values.iter().map(|v| JsValue::from_str(v)).collect();
                self.0
                    .prepare(s.sql)
                    .bind(&values)
                    .map_err(|_| Error::Storage)
            })
            .collect::<Result<Vec<_>>>()?;
        let result = self.0.batch(statements).await.map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                Error::Conflict
            } else {
                Error::Storage
            }
        })?;
        result
            .into_iter()
            .map(|r| {
                r.meta()
                    .map_err(|_| Error::Storage)?
                    .and_then(|m| m.changes)
                    .map(|n| n as u64)
                    .ok_or(Error::Storage)
            })
            .collect()
    }
}
struct Blobs(crate::s3::S3);
impl BlobTrait for Blobs {
    async fn get(&self, blob: BlobRef<'_>) -> Result<Bytes> {
        let key = blob.digest;
        let mut response = Fetch::Url(
            self.0
                .url(blob, false)?
                .parse()
                .map_err(|_| Error::Storage)?,
        )
        .send()
        .await
        .map_err(|_| Error::Storage)?;
        if response.status_code() != 200 {
            return Err(Error::Storage);
        }
        let mut stream = response.stream().map_err(|_| Error::Storage)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::Storage)?;
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err(Error::Storage);
            }
            bytes.extend_from_slice(&chunk);
        }
        if digest(&bytes) != key {
            return Err(Error::Storage);
        }
        Ok(bytes.into())
    }
    async fn put(&self, blob: BlobRef<'_>, bytes: &[u8]) -> Result<()> {
        let key = blob.digest;
        if digest(bytes) != key || bytes.len() > MAX_BODY {
            return Err(Error::Storage);
        }
        let mut init = worker::RequestInit::new();
        let array = worker::js_sys::Uint8Array::from(bytes);
        init.with_method(worker::Method::Put)
            .with_body(Some(array.into()));
        let request = WorkerRequest::new_with_init(&self.0.url(blob, true)?, &init)
            .map_err(|_| Error::Storage)?;
        let response = Fetch::Request(request)
            .send()
            .await
            .map_err(|_| Error::Storage)?;
        if (200..300).contains(&response.status_code()) {
            Ok(())
        } else {
            Err(Error::Storage)
        }
    }
}

fn response(response: Response<Vec<u8>>) -> worker::Result<WorkerResponse> {
    let (parts, body) = cors(response).into_parts();
    let mut response = WorkerResponse::from_bytes(body)?.with_status(parts.status.as_u16());
    for (name, value) in &parts.headers {
        response
            .headers_mut()
            .set(name.as_str(), value.to_str().unwrap_or(""))?;
    }
    Ok(response)
}

#[event(fetch)]
pub async fn fetch(
    request: WorkerRequest,
    env: Env,
    _ctx: Context,
) -> worker::Result<WorkerResponse> {
    match fetch_request(request, env).await {
        Ok(response) => Ok(response),
        Err(_) => response(Error::Storage.response()),
    }
}

async fn fetch_request(mut request: WorkerRequest, env: Env) -> worker::Result<WorkerResponse> {
    let url = request.url()?;
    if let Some(public) = public_response(request.method().to_string().as_str(), url.path()) {
        return response(public);
    }
    let limits = match Limits::from_env(env.var("LIMITS_BODY_BYTES").ok().map(|v| v.to_string())) {
        Ok(limits) => limits,
        Err(error) => return response(error.response()),
    };
    let mut builder = Request::builder()
        .method(request.method().to_string().as_str())
        .uri(url.as_str());
    for name in ["content-type", "content-encoding", "if-match"] {
        if let Some(value) = request.headers().get(name)? {
            builder = builder.header(name, value);
        }
    }
    let mut body = Vec::new();
    if matches!(request.method(), worker::Method::Post | worker::Method::Put) {
        let mut stream = match request.stream() {
            Ok(stream) => stream,
            Err(_) => return response(Error::BadRequest.response()),
        };
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => return response(Error::BadRequest.response()),
            };
            if body.len() + chunk.len() > limits.body_bytes {
                return response(limits.response(Error::TooLarge.response()));
            }
            body.extend_from_slice(&chunk);
        }
    }
    let index = Index(
        env.d1("INDEX")?
            .with_session_constraint(D1SessionConstraint::FirstPrimary)?,
    );
    let mut destinations = Vec::new();
    let keys = worker::js_sys::Object::keys(env.unchecked_ref::<worker::js_sys::Object>());
    let names = keys.iter().filter_map(|v| v.as_string());
    let indices = match crate::s3::sections(names, "BACKEND_S3_") {
        Ok(v) => v,
        Err(e) => return response(e.response()),
    };
    for i in indices {
        let s3 = crate::s3::S3::from_env(i, |name| {
            env.var(name)
                .or_else(|_| env.secret(name))
                .map(|v| v.to_string())
                .map_err(|_| Error::Storage)
        });
        match s3 {
            Ok(s3) => destinations.push(Blobs(s3)),
            Err(e) => return response(e.response()),
        }
    }
    if destinations.is_empty() {
        return response(Error::Storage.response());
    }
    let blobs = storage::Mirrors(destinations);
    let request = builder
        .body(Bytes::from(body))
        .map_err(|_| worker::Error::RustError("Invalid HTTP request".into()))?;
    response(handle(&index, &blobs, request, limits).await)
}
