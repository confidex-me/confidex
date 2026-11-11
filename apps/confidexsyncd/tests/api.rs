#![cfg(not(target_arch = "wasm32"))]
use axum::{
    Router,
    body::{Body, to_bytes},
};
use bytes::Bytes;
use confidex_vault::envelope;
use confidexsyncd::{
    native::{Blobs, Index},
    storage::{BlobRef, Blobs as _, Mirrors, Store},
    *,
};
use ed25519_dalek::{Signer, SigningKey};
use http::Request;
use tower::ServiceExt;

#[path = "api/branches.rs"]
mod branches;

fn fixture(name: &str) -> Vec<u8> {
    let text = include_str!("../../../tests/fixtures/vectors.hex");
    hex::decode(
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .unwrap(),
    )
    .unwrap()
}
fn signature(wire: &[u8], previous: &str) -> Vec<u8> {
    SigningKey::from_bytes(&fixture("signing_seed").try_into().unwrap())
        .sign(&lock_signature_bytes(wire, previous))
        .to_bytes()
        .to_vec()
}
enum App {
    Local(Router),
    Remote(String),
}
fn client() -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if let Ok(value) = std::env::var("CONFIDEX_TEST_RESOLVE") {
        let (host, address) = value.split_once('=').unwrap();
        builder = builder.resolve(host, address.parse().unwrap());
    }
    builder.build().unwrap()
}
async fn call(
    app: &App,
    method: &str,
    path: &str,
    parts: &[(&str, &[u8])],
    etag: Option<&str>,
) -> http::Response<Bytes> {
    let (content_type, body) = if parts.is_empty() {
        (String::new(), Vec::new())
    } else {
        encode_multipart(parts)
    };
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", content_type);
    if let Some(etag) = etag {
        request = request.header("if-match", etag);
    }
    match app {
        App::Local(app) => {
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            let (parts, body) = response.into_parts();
            http::Response::from_parts(parts, to_bytes(body, MAX_BODY).await.unwrap())
        }
        App::Remote(base) => {
            let (parts, body) = request.body(body).unwrap().into_parts();
            let response = client()
                .request(parts.method, format!("{base}{path}"))
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .unwrap();
            let mut builder = http::Response::builder().status(response.status());
            *builder.headers_mut().unwrap() = response.headers().clone();
            builder.body(response.bytes().await.unwrap()).unwrap()
        }
    }
}
async fn unpack(response: http::Response<Bytes>) -> Vec<(String, Bytes)> {
    let boundary =
        multer::parse_boundary(response.headers()["content-type"].to_str().unwrap()).unwrap();
    let source =
        futures_util::stream::once(async { Ok::<_, std::io::Error>(response.into_body()) });
    let mut parser = multer::Multipart::new(source, boundary);
    let mut out = Vec::new();
    while let Some(field) = parser.next_field().await.unwrap() {
        let name = field.name().unwrap().to_owned();
        out.push((name, field.bytes().await.unwrap()));
    }
    out
}
fn cursor(response: &http::Response<Bytes>) -> String {
    serde_json::from_slice::<serde_json::Value>(response.body()).unwrap()["cursor"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn server_derives_the_address_and_rejects_another_signing_key() {
    let temp = tempfile::tempdir().unwrap();
    let app = App::Local(native::router(
        Index::open(":memory:").await.unwrap(),
        vec![Blobs::posix(temp.path().join("objects")).unwrap()],
        Limits::default(),
    ));
    let alice = fixture("lock_0");
    let public: [u8; 32] = fixture("verifying_key").try_into().unwrap();
    let id = lock_id(&public);
    assert_eq!(
        id,
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, &public).to_string()
    );
    let registered = call(
        &app,
        "POST",
        "/v1/sync",
        &[("lock", &alice), ("signature", &signature(&alice, ""))],
        None,
    )
    .await;
    assert_eq!(registered.status(), 201);
    let etag = registered.headers()["etag"].to_str().unwrap();
    let bob = SigningKey::from_bytes(&[42; 32]);
    let mut other = alice.clone();
    let offset = other.windows(32).position(|bytes| bytes == public).unwrap();
    other[offset..offset + 32].copy_from_slice(bob.verifying_key().as_bytes());
    let sig = bob
        .sign(&lock_signature_bytes(&other, etag.trim_matches('"')))
        .to_bytes();
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/v1/sync/{id}"),
            &[("lock", &other), ("signature", &sig)],
            Some(etag)
        )
        .await
        .status(),
        403
    );
    let sig = bob.sign(&lock_signature_bytes(&other, "")).to_bytes();
    let registered = call(
        &app,
        "POST",
        "/v1/sync",
        &[("lock", &other), ("signature", &sig)],
        None,
    )
    .await;
    assert_eq!(registered.status(), 201);
    let other_id = lock_id(bob.verifying_key().as_bytes());
    assert_ne!(other_id, id);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(registered.body()).unwrap()["id"],
        other_id
    );
    let stored = unpack(call(&app, "GET", &format!("/v1/sync/{id}"), &[], None).await).await;
    assert_eq!(stored[0].1.as_ref(), alice);
}

async fn lifecycle(app: App) {
    assert_eq!(
        call(&app, "POST", "/v1/sync", &[], None).await.status(),
        400
    );
    let wire = fixture("lock_0");
    let sig = signature(&wire, "");
    let id = lock_id(&fixture("verifying_key").try_into().unwrap());
    let path = format!("/v1/sync/{id}");
    let records = format!("{path}/records");
    assert_eq!(
        call(
            &app,
            "POST",
            &records,
            &[("base", b"0"), ("record", &fixture("revision_0"))],
            None
        )
        .await
        .status(),
        404
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/sync",
            &[("lock", &wire), ("signature", &[0; 64])],
            None
        )
        .await
        .status(),
        403
    );
    let created = call(
        &app,
        "POST",
        "/v1/sync",
        &[("lock", &wire), ("signature", &sig)],
        None,
    )
    .await;
    assert_eq!(created.status(), 201, "{:?}", created.body());
    let etag = created.headers()["etag"].to_str().unwrap().to_owned();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(created.body()).unwrap()["id"],
        id
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/sync",
            &[("lock", &wire), ("signature", &sig)],
            None
        )
        .await
        .status(),
        200
    );
    let stored = unpack(call(&app, "GET", &path, &[], None).await).await;
    assert_eq!(stored[0].1.as_ref(), wire);
    assert_eq!(stored[1].1.as_ref(), sig);
    assert_eq!(
        call(
            &app,
            "POST",
            &records,
            &[("base", b"0"), ("record", &fixture("revision_1"))],
            None
        )
        .await
        .status(),
        422
    );
    let mut bad = fixture("revision_1");
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        call(
            &app,
            "POST",
            &records,
            &[
                ("base", b"0"),
                ("record", &fixture("revision_0")),
                ("record", &bad)
            ],
            None
        )
        .await
        .status(),
        422
    );
    let page = unpack(call(&app, "GET", &records, &[], None).await).await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&page[0].1).unwrap()["cursor"],
        "0"
    );
    let accepted = call(
        &app,
        "POST",
        &records,
        &[
            ("base", b"0"),
            ("record", &fixture("revision_0")),
            ("record", &fixture("revision_1")),
        ],
        None,
    )
    .await;
    assert_eq!(accepted.status(), 200, "{:?}", accepted.body());
    assert_eq!(cursor(&accepted), "2");
    assert_eq!(
        call(
            &app,
            "POST",
            &records,
            &[("base", b"0"), ("record", &fixture("revision_2"))],
            None
        )
        .await
        .status(),
        409
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &records,
            &[("base", b"2"), ("record", &fixture("revision_0"))],
            None
        )
        .await
        .status(),
        409
    );
    let accepted = call(
        &app,
        "POST",
        &records,
        &[
            ("base", b"2"),
            ("record", &fixture("revision_2")),
            ("record", &fixture("revision_3")),
            ("record", &fixture("revision_4")),
        ],
        None,
    )
    .await;
    assert_eq!(accepted.status(), 200, "{:?}", accepted.body());
    assert_eq!(cursor(&accepted), "5");
    let page = unpack(call(&app, "GET", &format!("{records}?after=1"), &[], None).await).await;
    let meta: serde_json::Value = serde_json::from_slice(&page[0].1).unwrap();
    assert_eq!(meta["cursor"], "5");
    assert_eq!(meta["has_more"], false);
    assert_eq!(page.len(), 5);
    for (n, part) in page.iter().skip(1).enumerate() {
        assert_eq!(part.1.as_ref(), fixture(&format!("revision_{}", n + 1)));
    }
    let next = fixture("lock_1");
    assert_eq!(
        call(
            &app,
            "PUT",
            &path,
            &[("lock", &next), ("signature", &signature(&next, ""))],
            Some(&etag)
        )
        .await
        .status(),
        403
    );
    let previous = etag.trim_matches('"');
    let updated = call(
        &app,
        "PUT",
        &path,
        &[("lock", &next), ("signature", &signature(&next, previous))],
        Some(&etag),
    )
    .await;
    assert_eq!(updated.status(), 200, "{:?}", updated.body());
    let updated_etag = updated.headers()["etag"].to_str().unwrap().to_owned();
    assert_eq!(
        call(
            &app,
            "PUT",
            &path,
            &[("lock", &next), ("signature", &signature(&next, previous))],
            Some(&etag)
        )
        .await
        .status(),
        412
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &path,
            &[("lock", &wire), ("signature", &sig)],
            Some(&updated_etag)
        )
        .await
        .status(),
        403
    );
    let stored = unpack(call(&app, "GET", &path, &[], None).await).await;
    assert_eq!(stored[0].1.as_ref(), next);
    assert_eq!(stored[2].1.as_ref(), previous.as_bytes());
    assert_eq!(
        verify_lock(&stored[0].1, &stored[1].1, previous)
            .unwrap()
            .id,
        id
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_fs_and_git_mirror_the_full_signed_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("index.sqlite");
    let fs = temp.path().join("objects");
    let second_fs = temp.path().join("second-objects");
    let git = temp.path().join("objects.git");
    lifecycle(App::Local(native::router(
        Index::open(db.to_str().unwrap()).await.unwrap(),
        vec![
            Blobs::posix(fs.clone()).unwrap(),
            Blobs::posix(second_fs.clone()).unwrap(),
            Blobs::git(git.clone()).unwrap(),
        ],
        Limits::default(),
    )))
    .await;
    let restored = Index::open(db.to_str().unwrap()).await.unwrap();
    let copies = Mirrors(vec![
        Blobs::Posix(fs.clone()),
        Blobs::Posix(second_fs),
        Blobs::Git(git),
    ]);
    let id = lock_id(&fixture("verifying_key").try_into().unwrap());
    let store = Store {
        index: &restored,
        blobs: &copies,
    };
    assert_eq!(store.lock(&id).await.unwrap().cursor, 5);
    let key = digest(&fixture("revision_0"));
    for copy in &copies.0 {
        assert_eq!(
            copy.get(BlobRef::record(&id, &key)).await.unwrap().as_ref(),
            fixture("revision_0")
        );
    }
    std::fs::write(fs.join(&key), b"corrupted replica").unwrap();
    assert_eq!(
        copies
            .get(BlobRef::record(&id, &key))
            .await
            .unwrap()
            .as_ref(),
        fixture("revision_0")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mirror_failure_does_not_publish_and_retry_can_finish() {
    let temp = tempfile::tempdir().unwrap();
    let index = Index::open(":memory:").await.unwrap();
    let missing = temp.path().join("missing");
    let mirrors = Mirrors(vec![
        Blobs::posix(temp.path().join("first")).unwrap(),
        Blobs::Posix(missing.clone()),
    ]);
    let wire = fixture("lock_0");
    let lock = verify_lock(&wire, &signature(&wire, ""), "").unwrap();
    let store = Store {
        index: &index,
        blobs: &mirrors,
    };
    assert_eq!(store.create(&lock, &wire).await, Err(Error::Storage));
    assert!(matches!(store.lock(&lock.id).await, Err(Error::NotFound)));
    std::fs::create_dir(&missing).unwrap();
    assert_eq!(store.create(&lock, &wire).await, Ok(true));
    assert_eq!(std::fs::read(missing.join(&lock.blob)).unwrap(), wire);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_process_connections_do_not_publish_a_losing_batch() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("index.sqlite");
    let blobs = temp.path().join("objects");
    let one = App::Local(native::router(
        Index::open(db.to_str().unwrap()).await.unwrap(),
        vec![Blobs::posix(blobs.clone()).unwrap()],
        Limits::default(),
    ));
    let two = App::Local(native::router(
        Index::open(db.to_str().unwrap()).await.unwrap(),
        vec![Blobs::posix(blobs).unwrap()],
        Limits::default(),
    ));
    let wire = fixture("lock_0");
    assert_eq!(
        call(
            &one,
            "POST",
            "/v1/sync",
            &[("lock", &wire), ("signature", &signature(&wire, ""))],
            None
        )
        .await
        .status(),
        201
    );
    let path = format!(
        "/v1/sync/{}/records",
        lock_id(&fixture("verifying_key").try_into().unwrap())
    );
    assert_eq!(
        call(
            &one,
            "POST",
            &path,
            &[("base", b"0"), ("record", &fixture("revision_0"))],
            None
        )
        .await
        .status(),
        200
    );
    let a = fixture("revision_1");
    let b = fixture("revision_2");
    let a_parts = [("base", &b"1"[..]), ("record", a.as_slice())];
    let b_parts = [("base", &b"1"[..]), ("record", b.as_slice())];
    let (a, b) = tokio::join!(
        call(&one, "POST", &path, &a_parts, None),
        call(&two, "POST", &path, &b_parts, None)
    );
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    let page = unpack(call(&one, "GET", &path, &[], None).await).await;
    assert_eq!(page.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn real_http_enforces_the_body_limit_without_content_length() {
    let temp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = native::router(
        Index::open(":memory:").await.unwrap(),
        vec![Blobs::posix(temp.path().join("objects")).unwrap()],
        Limits { body_bytes: 1024 },
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let stream = futures_util::stream::iter([
        Ok::<_, std::io::Error>(Bytes::from(vec![0; 1024])),
        Ok(Bytes::from_static(b"x")),
    ]);
    let response = client
        .post(format!("http://{address}/v1/sync"))
        .header("content-type", "multipart/form-data; boundary=x")
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    assert_eq!(response.headers()["sync-max-body-bytes"], "1024");
    let wire = fixture("lock_0");
    let sig = signature(&wire, "");
    let (ct, body) = encode_multipart(&[("lock", &wire), ("signature", &sig)]);
    let response = client
        .post(format!("http://{address}/v1/sync"))
        .header("content-type", ct)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    server.abort();
}

#[test]
fn configuration_and_s3_names_have_one_mapping() {
    let config: confidexsyncd::config::Config =
        toml::from_str(include_str!("../example.toml")).unwrap();
    assert_eq!(config.socket().to_string(), "127.0.0.1:8080");
    assert_eq!(config.backend.posix.len(), 1);
    assert_eq!(config.backend.git.len(), 1);
    assert_eq!(config.limits.body_bytes, MAX_BODY);
    let configured: confidexsyncd::config::Config = toml::from_str(&format!(
        "{}\n[limits]\nbody_bytes = 1200000\n",
        include_str!("../example.toml")
    ))
    .unwrap();
    assert_eq!(configured.limits.body_bytes, 1_200_000);
    assert_eq!(Limits::from_env(None).unwrap().body_bytes, MAX_BODY);
    assert_eq!(
        Limits::from_env(Some("1200000".into())).unwrap().body_bytes,
        configured.limits.body_bytes
    );
    for value in ["0", "-1", "8000001", "invalid"] {
        assert!(Limits::from_env(Some(value.into())).is_err());
    }
    let names = [
        "BACKEND_S3_URL_2",
        "BACKEND_S3_ACCESS_KEY_0",
        "BACKEND_S3_SECRET_KEY_2",
    ]
    .map(String::from);
    assert_eq!(s3::sections(names, "BACKEND_S3_").unwrap(), vec![0, 2]);
    let store = s3::S3::from_url(
        "https://example.test/prefix/bucket?region=us-east-1",
        "test".into(),
        "test-secret".into(),
    )
    .unwrap();
    let id = "256d1474-3aae-5a4e-84ab-e1a309014d04";
    let hash = "aabbccdd".repeat(8);
    let url = url::Url::parse(&store.url(BlobRef::record(id, &hash), false).unwrap()).unwrap();
    assert_eq!(
        url.path(),
        format!("/prefix/bucket/25/6d/{id}/aa/bb/{}", &hash[4..])
    );
    let lock = url::Url::parse(&store.url(BlobRef::lock(id, &hash), false).unwrap()).unwrap();
    assert_eq!(
        lock.path(),
        format!("/prefix/bucket/25/6d/{id}/locks/{hash}.sealed")
    );
    let other = "b20ee961-bda5-59e8-a3bd-8a4def1d14f8";
    assert_ne!(
        store.url(BlobRef::record(id, &hash), false).unwrap(),
        store.url(BlobRef::record(other, &hash), false).unwrap()
    );
    for vault in [
        "../escape",
        "256D1474-3AAE-5A4E-84AB-E1A309014D04",
        "invalid",
    ] {
        assert!(store.url(BlobRef::record(vault, &hash), false).is_err());
    }
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "X-Amz-Credential" && v.contains("us-east-1/s3/aws4_request"))
    );
    assert!(s3::S3::from_url("https://example.test/", "a".into(), "b".into()).is_err());
}

#[tokio::test]
async fn cors_preflight_and_error_responses_allow_unrelated_origins() {
    let app = native::router(
        Index::open(":memory:").await.unwrap(),
        Vec::new(),
        Limits { body_bytes: 1024 },
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/sync")
                .header("origin", "https://unrelated.example")
                .header("access-control-request-method", "PUT")
                .header(
                    "access-control-request-headers",
                    "authorization,if-match,x-client-header",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    assert_eq!(
        response.headers()["access-control-allow-headers"],
        "*, Authorization"
    );
    assert!(
        response.headers()["access-control-allow-methods"]
            .to_str()
            .unwrap()
            .contains("PUT")
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    let app = App::Local(app);
    for (method, path, status) in [
        ("GET", "/v1/sync", 405),
        ("POST", "/v1/sync", 400),
        ("GET", "/not-found", 404),
    ] {
        let response = call(&app, method, path, &[], None).await;
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["access-control-expose-headers"], "*");
    }
    let oversized = call(&app, "POST", "/v1/sync", &[("lock", &[0; 1025])], None).await;
    assert_eq!(oversized.status(), 413);
    assert_eq!(oversized.headers()["sync-max-body-bytes"], "1024");
    assert_eq!(oversized.headers()["access-control-allow-origin"], "*");
    let lock = fixture("lock_0");
    let unavailable = call(
        &app,
        "POST",
        "/v1/sync",
        &[("lock", &lock), ("signature", &signature(&lock, ""))],
        None,
    )
    .await;
    assert_eq!(unavailable.status(), 503);
    assert_eq!(unavailable.headers()["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn checkpoint_needs_no_object_backend_and_exposes_both_versions() {
    use confidexsyncd::storage::{Index as _, Statement};
    let index = Index::open(":memory:").await.unwrap();
    let id = "256d1474-3aae-5a4e-84ab-e1a309014d04";
    let digest = "ab".repeat(32);
    index.batch(vec![Statement::new(
        "INSERT INTO sync_locks(id,vault_id,public_key,blob,signature,previous,cursor) VALUES($1,$2,$3,$4,$5,$6,42)",
        vec![id.into(),"07".repeat(16),hex::encode(fixture("verifying_key")),digest.clone(),"00".repeat(64),String::new()],
    )]).await.unwrap();
    let app = App::Local(native::router(index, vec![], Limits::default()));
    let response = call(&app, "HEAD", &format!("/v1/sync/{id}"), &[], None).await;
    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
    assert_eq!(response.headers()["etag"], format!("\"{digest}\""));
    assert_eq!(response.headers()["sync-cursor"], "42");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    assert_eq!(
        call(&app, "GET", &format!("/v1/sync/{id}"), &[], None)
            .await
            .status(),
        503
    );
}

#[tokio::test]
async fn upload_limit_includes_multipart_headers_and_is_advertised_on_rejection() {
    let limit = 1024;
    let app = App::Local(native::router(
        Index::open(":memory:").await.unwrap(),
        Vec::new(),
        Limits { body_bytes: limit },
    ));
    let signature = [0; 64];
    let overhead = encode_multipart(&[("lock", &[]), ("signature", &signature)])
        .1
        .len();
    for (length, status) in [(limit, 422), (limit + 1, 413)] {
        let wire = vec![0; length - overhead];
        let response = call(
            &app,
            "POST",
            "/v1/sync",
            &[("lock", &wire), ("signature", &signature)],
            None,
        )
        .await;
        assert_eq!(response.status(), status);
        if status == 413 {
            assert_eq!(response.headers()["sync-max-body-bytes"], "1024");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(response.body()).unwrap()["error"],
                "content_too_large"
            );
        }
    }
}

#[tokio::test]
async fn root_does_not_redirect_or_require_object_backends() {
    let app = App::Local(native::router(
        Index::open(":memory:").await.unwrap(),
        Vec::new(),
        Limits::default(),
    ));
    for method in ["GET", "HEAD"] {
        let response = call(&app, method, "/?source=test", &[], None).await;
        assert_eq!(response.status(), 404);
        assert!(!response.headers().contains_key("location"));
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.body().is_empty());
    }
    assert_eq!(call(&app, "POST", "/", &[], None).await.status(), 404);
    assert_eq!(call(&app, "GET", "/v1/sync", &[], None).await.status(), 405);
}

#[tokio::test]
async fn openapi_page_and_spec_do_not_require_object_backends() {
    let app = App::Local(native::router(
        Index::open(":memory:").await.unwrap(),
        Vec::new(),
        Limits::default(),
    ));
    for path in ["/v1", "/v1/"] {
        let page = call(&app, "GET", path, &[], None).await;
        assert_eq!(page.status(), 200);
        assert_eq!(page.headers()["content-type"], "text/html; charset=utf-8");
        assert!(
            std::str::from_utf8(page.body())
                .unwrap()
                .contains("SwaggerUIBundle")
        );
        assert!(
            !std::str::from_utf8(page.body())
                .unwrap()
                .contains("https://")
        );
        assert_eq!(page.headers()["referrer-policy"], "no-referrer");
        assert!(
            page.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("connect-src 'self'")
        );
        let head = call(&app, "HEAD", path, &[], None).await;
        assert_eq!(head.status(), 200);
        assert!(head.body().is_empty());
    }
    let response = call(&app, "GET", "/v1/openapi.json", &[], None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    let spec: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    for (path, method) in [
        ("/v1/sync", "post"),
        ("/v1/sync/{id}", "get"),
        ("/v1/sync/{id}", "put"),
        ("/v1/sync/{id}/records", "get"),
        ("/v1/sync/{id}/records", "post"),
    ] {
        assert!(spec["paths"][path][method].is_object());
    }
    assert!(
        spec["components"]["responses"]["TooLarge"]["headers"]["Sync-Max-Body-Bytes"].is_object()
    );
    for (file, content_type) in [
        ("swagger-ui-bundle.js", "text/javascript; charset=utf-8"),
        ("swagger-ui.css", "text/css; charset=utf-8"),
        (
            "swagger-ui-bundle.js.LICENSE.txt",
            "text/plain; charset=utf-8",
        ),
    ] {
        let asset = call(
            &app,
            "GET",
            &format!("/v1/swagger-ui/5.34.1/{file}"),
            &[],
            None,
        )
        .await;
        assert_eq!(asset.status(), 200);
        assert_eq!(asset.headers()["content-type"], content_type);
        assert!(!asset.body().is_empty());
    }
    assert_eq!(call(&app, "POST", "/v1", &[], None).await.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires disposable PostgreSQL and S3 test services"]
async fn postgres_with_s3_and_fs() {
    let database = std::env::var("CONFIDEX_TEST_POSTGRES").unwrap();
    let endpoint = std::env::var("CONFIDEX_TEST_S3").unwrap();
    use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
    let client = reqwest::Client::new();
    let mut destinations = Vec::new();
    for name in ["sync-test-primary", "sync-test-secondary"] {
        let bucket =
            Bucket::new(endpoint.parse().unwrap(), UrlStyle::Path, name, "us-east-1").unwrap();
        let credentials = Credentials::new("sync-test-key", "sync-test-secret");
        let created = client
            .put(
                bucket
                    .create_bucket(&credentials)
                    .sign(std::time::Duration::from_secs(60)),
            )
            .header("content-length", "0")
            .body(Vec::new())
            .send()
            .await
            .unwrap();
        assert!(created.status().is_success(), "{}", created.status());
        destinations.push(
            Blobs::s3(
                s3::S3::from_url(
                    &format!("{endpoint}/{name}?region=us-east-1"),
                    "sync-test-key".into(),
                    "sync-test-secret".into(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
    }
    let temp = tempfile::tempdir().unwrap();
    destinations.push(Blobs::posix(temp.path().join("copy")).unwrap());
    lifecycle(App::Local(native::router(
        Index::open(&database).await.unwrap(),
        destinations,
        Limits::default(),
    )))
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a fresh local Wrangler instance and configured S3 mirrors"]
async fn worker_full_lifecycle() {
    let base = std::env::var("CONFIDEX_TEST_WORKER").unwrap();
    lifecycle(App::Remote(base.clone())).await;
    let source = futures_util::stream::iter([
        Ok::<_, std::io::Error>(Bytes::from(vec![0; MAX_BODY])),
        Ok(Bytes::from_static(b"x")),
    ]);
    let response = client()
        .post(format!("{base}/v1/sync"))
        .header("content-type", "multipart/form-data; boundary=x")
        .body(reqwest::Body::wrap_stream(source))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    assert!(response.headers().contains_key("sync-max-body-bytes"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a Worker endpoint and disposable synthetic vault data"]
async fn worker_accepts_a_large_signed_packet() {
    let app = App::Remote(std::env::var("CONFIDEX_TEST_WORKER").unwrap());
    let lock = fixture("lock_0");
    let registered = call(
        &app,
        "POST",
        "/v1/sync",
        &[("lock", &lock), ("signature", &signature(&lock, ""))],
        None,
    )
    .await;
    assert!(matches!(registered.status().as_u16(), 200 | 201 | 409));
    let id = lock_id(&fixture("verifying_key").try_into().unwrap());
    let path = format!("/v1/sync/{id}/records");
    let page = unpack(call(&app, "GET", &path, &[], None).await).await;
    let meta: serde_json::Value = serde_json::from_slice(&page[0].1).unwrap();
    let base = meta["cursor"].as_str().unwrap();
    let small = fixture("revision_0");
    assert_eq!(&small[..2], &[0x93, 0xc4]);
    let header = &small[3..3 + small[2] as usize];
    let packet = vec![0; envelope::MAX_PACKET];
    let signature = SigningKey::from_bytes(&fixture("signing_seed").try_into().unwrap())
        .sign(&confidex_vault::crypto::signed_record_bytes(
            header, &packet,
        ))
        .to_bytes();
    let mut wire = vec![0x93];
    for bytes in [header, packet.as_slice(), signature.as_slice()] {
        wire.push(0xc6);
        wire.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        wire.extend_from_slice(bytes);
    }
    let anchor = verify_lock(&lock, &self::signature(&lock, ""), "")
        .unwrap()
        .anchor()
        .unwrap();
    envelope::verify(
        &wire,
        &anchor,
        None,
        confidex_vault::resources::MAX_OPEN_MEMORY,
    )
    .unwrap();
    let accepted = call(
        &app,
        "POST",
        &path,
        &[("base", base.as_bytes()), ("record", &wire)],
        None,
    )
    .await;
    assert_eq!(accepted.status(), 200, "{:?}", accepted.body());
    let page = unpack(call(&app, "GET", &format!("{path}?after={base}"), &[], None).await).await;
    assert_eq!(page.len(), 2);
    assert_eq!(page[1].1.as_ref(), wire);
}
