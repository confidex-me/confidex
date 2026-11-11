use super::*;
use confidex_vault::{lock, record::Record, resources::MAX_OPEN_MEMORY};

fn revision(
    vault: &lock::OpenedVault,
    parents: &[[u8; 32]],
    index: usize,
    deleted: bool,
) -> Vec<u8> {
    let mut record = Record::default();
    if !deleted && index % 2 == 1 {
        record.tags.push(format!("public-branch-fixture-{index}"));
    }
    envelope::seal(
        &record,
        vault.keys(),
        envelope::Options {
            vault_id: vault.vault_id(),
            record_id: [17; 16],
            parents,
            epoch: index as u64,
            kind: if deleted {
                envelope::EventKind::Deletion
            } else {
                envelope::EventKind::Content
            },
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap()
}

fn revision_id(vault: &lock::OpenedVault, wire: &[u8]) -> [u8; 32] {
    envelope::verify(wire, vault.anchor(), None, MAX_OPEN_MEMORY)
        .unwrap()
        .id()
}

async fn history(app: &App, path: &str, expected: &[Vec<u8>]) {
    let mut received = Vec::new();
    loop {
        let page = call(
            app,
            "GET",
            &format!("{path}?after={}", received.len()),
            &[],
            None,
        )
        .await;
        assert_eq!(page.status(), 200);
        let parts = unpack(page).await;
        let meta: serde_json::Value = serde_json::from_slice(&parts[0].1).unwrap();
        assert_eq!(parts[0].0, "meta");
        for (name, wire) in &parts[1..] {
            assert_eq!(name, "record");
            received.push(wire.to_vec());
        }
        assert_eq!(meta["cursor"], received.len().to_string());
        assert!(received.len() <= expected.len());
        if meta["has_more"] == false {
            break;
        }
        assert!(parts.len() > 1);
    }
    assert_eq!(received, expected);
}

async fn lifecycle(app: &App) -> (String, Vec<Vec<u8>>) {
    let created = lock::create(b"public-branch-fixture-password", MAX_OPEN_MEMORY).unwrap();
    let vault = &created.vault;
    let signature = vault
        .keys()
        .signing_key()
        .sign(&lock_signature_bytes(&created.lock, ""))
        .to_bytes();
    let registered = call(
        app,
        "POST",
        "/v1/sync",
        &[("lock", &created.lock), ("signature", &signature)],
        None,
    )
    .await;
    assert_eq!(registered.status(), 201);
    let id = lock_id(vault.keys().signing_key().verifying_key().as_bytes());
    let path = format!("/v1/sync/{id}/records");
    let root = revision(vault, &[], 0, false);
    let root_id = revision_id(vault, &root);
    let reply = call(
        app,
        "POST",
        &path,
        &[("base", b"0"), ("record", &root)],
        None,
    )
    .await;
    assert_eq!(reply.status(), 200);
    let mut expected = vec![root];
    let siblings: Vec<_> = (1..=270)
        .map(|index| revision(vault, &[root_id], index, false))
        .collect();
    let a_parts = [
        ("base", b"1".as_slice()),
        ("record", siblings[0].as_slice()),
    ];
    let b_parts = [
        ("base", b"1".as_slice()),
        ("record", siblings[1].as_slice()),
    ];
    let (a, b) = tokio::join!(
        call(app, "POST", &path, &a_parts, None),
        call(app, "POST", &path, &b_parts, None)
    );
    let (first, second) = match (a.status().as_u16(), b.status().as_u16()) {
        (200, 409) => (0, 1),
        (409, 200) => (1, 0),
        statuses => panic!("concurrent base must have one winner: {statuses:?}"),
    };
    expected.push(siblings[first].clone());
    history(app, &path, &expected).await;
    let retry = call(
        app,
        "POST",
        &path,
        &[("base", b"2"), ("record", &siblings[second])],
        None,
    )
    .await;
    assert_eq!(retry.status(), 200);
    expected.push(siblings[second].clone());
    for batch in siblings[2..].chunks(8) {
        let base = expected.len().to_string();
        let parts: Vec<_> = std::iter::once(("base", base.as_bytes()))
            .chain(batch.iter().map(|wire| ("record", wire.as_slice())))
            .collect();
        let accepted = call(app, "POST", &path, &parts, None).await;
        assert_eq!(accepted.status(), 200, "{:?}", accepted.body());
        expected.extend_from_slice(batch);
        assert_eq!(cursor(&accepted), expected.len().to_string());
    }
    history(app, &path, &expected).await;

    let edit = revision(vault, &[revision_id(vault, &siblings[0])], 1001, false);
    let deletion = revision(vault, &[revision_id(vault, &siblings[269])], 1002, true);
    let mut invalid = deletion.clone();
    *invalid.last_mut().unwrap() ^= 1;
    let base = expected.len().to_string();
    let rejected = call(
        app,
        "POST",
        &path,
        &[
            ("base", base.as_bytes()),
            ("record", &edit),
            ("record", &invalid),
        ],
        None,
    )
    .await;
    assert_eq!(rejected.status(), 422);
    history(app, &path, &expected).await;
    let accepted = call(
        app,
        "POST",
        &path,
        &[
            ("base", base.as_bytes()),
            ("record", &edit),
            ("record", &deletion),
        ],
        None,
    )
    .await;
    assert_eq!(accepted.status(), 200);
    expected.extend([edit, deletion]);
    // A lost response must not append the same signed objects twice.
    let repeated = call(
        app,
        "POST",
        &path,
        &[
            ("base", base.as_bytes()),
            ("record", expected.last().unwrap()),
        ],
        None,
    )
    .await;
    assert_eq!(repeated.status(), 409);
    let base = expected.len().to_string();
    let duplicate = call(
        app,
        "POST",
        &path,
        &[
            ("base", base.as_bytes()),
            ("record", expected.last().unwrap()),
        ],
        None,
    )
    .await;
    assert_eq!(duplicate.status(), 409);
    history(app, &path, &expected).await;
    (path, expected)
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_preserves_parallel_branches_across_batches_pages_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("index.sqlite");
    let objects = temp.path().join("objects");
    let app = App::Local(native::router(
        Index::open(database.to_str().unwrap()).await.unwrap(),
        vec![Blobs::posix(objects.clone()).unwrap()],
        Limits::default(),
    ));
    let (path, expected) = lifecycle(&app).await;
    drop(app);
    let reopened = App::Local(native::router(
        Index::open(database.to_str().unwrap()).await.unwrap(),
        vec![Blobs::posix(objects).unwrap()],
        Limits::default(),
    ));
    history(&reopened, &path, &expected).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL database"]
async fn postgres_preserves_parallel_branches_across_batches_and_pages() {
    let database = std::env::var("CONFIDEX_TEST_POSTGRES").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let app = App::Local(native::router(
        Index::open(&database).await.unwrap(),
        vec![Blobs::posix(temp.path().join("objects")).unwrap()],
        Limits::default(),
    ));
    lifecycle(&app).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable local Worker with D1 and S3"]
async fn worker_preserves_parallel_branches_across_batches_and_pages() {
    let app = App::Remote(std::env::var("CONFIDEX_TEST_WORKER").unwrap());
    lifecycle(&app).await;
}
