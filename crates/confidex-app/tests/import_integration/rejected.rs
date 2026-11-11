use super::*;
use confidex_app::import_flow as flow;

fn inputs() -> Vec<(&'static str, Vec<u8>, import::ErrorKind)> {
    use import::ErrorKind;
    let depth = import::Limits::default().depth + 1;
    let deep = format!(
        "{{\"encrypted\":false,\"folders\":[],\"items\":[],\"extra\":{}0{}}}",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    let oversized = serde_json::json!({
        "encrypted": false, "folders": [], "items": [{
            "type": 1, "name": "Public over-limit fields",
            "fields": (0..40).map(|index| serde_json::json!({
                "type": 0, "name": format!("Field {index}"), "value": "a".repeat(65536),
            })).collect::<Vec<_>>(),
            "login": {"username": "public", "password": "public-only-password"},
        }],
    });
    vec![
        (
            "malformed",
            b"{\"encrypted\":false,\"items\":[".to_vec(),
            ErrorKind::Malformed,
        ),
        ("deep", deep.into_bytes(), ErrorKind::Limit),
        ("unknown", b"{}".to_vec(), ErrorKind::UnsupportedFormat),
        (
            "encoding",
            vec![255, 254, 0],
            ErrorKind::UnsupportedEncoding,
        ),
        (
            "record-limit",
            serde_json::to_vec(&oversized).unwrap(),
            ErrorKind::Limit,
        ),
    ]
}

pub async fn first<S: Store>(store: &mut S) -> (Created, Snapshot) {
    let case = &crate::cases::CASES[0];
    let (mut engine, created) = faults::setup(store).await;
    let id = created.info.id;
    faults::write_concurrent(store, id, &created.key).await;
    let before = store.snapshot(id).await.unwrap();
    assert_eq!((before.heads.len(), before.objects.len()), (1, 1));
    let inputs = inputs().into_iter().chain(std::iter::once_with(|| {
        (
            "file-limit",
            vec![0; flow::MAX_FILE_BYTES + 1],
            import::ErrorKind::Limit,
        )
    }));
    for (name, bytes, expected) in inputs {
        let review = service::prepare(&mut engine, store, case, "valid-before-refusal.json").await;
        let oversized = bytes.len() > flow::MAX_FILE_BYTES;
        let prepare = flow::Command::Prepare {
            operation: 50,
            file_name: format!("public-{name}.json"),
            format: Some(case.format),
            options: case.options(""),
            bytes,
        };
        let result = if oversized {
            // Test raw input admission without expanding its bytes into JSON numbers.
            let Output::VendorImport(result) =
                command(&mut engine, store, Command::VendorImport(prepare)).await
            else {
                panic!("large input dispatch")
            };
            result
        } else {
            service::exchange(&mut engine, store, prepare).await
        };
        assert!(
            matches!(result, Err(flow::Error::Parse(error)) if error.kind == expected),
            "{name}"
        );
        service::stale_review(&mut engine, store, review.token).await;
        same_snapshot(&before, &store.snapshot(id).await.unwrap());
        assert_eq!(
            search(&mut engine, store, faults::CONCURRENT).await,
            [before.heads[0].record]
        );
        assert!(search(&mut engine, store, "Почта").await.is_empty());
    }
    let review = service::prepare(&mut engine, store, case, "valid-after-refusals.json").await;
    let expected = case.plan();
    let flow::Reply::Applied { report, .. } = service::exchange(
        &mut engine,
        store,
        flow::Command::Apply {
            operation: 51,
            token: review.token,
            selection: choices(&expected),
            epoch: 42,
        },
    )
    .await
    .unwrap() else {
        panic!("retry")
    };
    assert_eq!(
        (report.added, report.updated, report.skipped),
        (case.selected, 0, 0)
    );
    let after = store.snapshot(id).await.unwrap();
    assert_eq!(
        (after.heads.len(), after.objects.len()),
        (case.selected + 1, case.selected + 1)
    );
    assert_eq!(
        store.object(id, before.heads[0].revision).await.unwrap(),
        before.objects[0].wire
    );
    assert_eq!(
        store
            .head(id, before.heads[0].record)
            .await
            .unwrap()
            .as_ref(),
        Some(&before.heads[0])
    );
    reopened(store, &created, &after).await;
    (created, after)
}

pub async fn reopened<S: Store>(store: &mut S, created: &Created, expected: &Snapshot) {
    let case = &crate::cases::CASES[0];
    let mut engine = index::open(store, created).await;
    same_snapshot(expected, &store.snapshot(created.info.id).await.unwrap());
    let survivor = search(&mut engine, store, faults::CONCURRENT).await;
    assert_eq!(survivor.len(), 1);
    let imported: Vec<_> = expected
        .heads
        .iter()
        .filter(|head| head.record != survivor[0])
        .cloned()
        .collect();
    let records = verify(store, created, case, &case.plan(), &imported).await;
    search_checks(&mut engine, store, case, &case.plan(), &records).await;
}
