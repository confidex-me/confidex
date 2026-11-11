use super::*;
use confidex_app::import_apply::Control;
use zeroize::Zeroizing;

pub const CONCURRENT: &str = "Concurrent public record";

pub fn large_input() -> Zeroizing<Vec<u8>> {
    use std::fmt::Write;
    let mut password = Zeroizing::new(String::from("resourcefailureprivate"));
    for index in 0..8192u32 {
        write!(password, "{index:08x}").unwrap();
    }
    let case = &crate::cases::CASES[0];
    changes::json_password(case.input, case.format, &password)
}

pub async fn storage_failure<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    created: &Created,
    input: &[u8],
    error: confidex_storage::Error,
) -> Snapshot {
    let id = created.info.id;
    let before = store.snapshot(id).await.unwrap();
    assert_eq!((before.heads.len(), before.objects.len()), (1, 1));
    assert_eq!(
        search(engine, store, CONCURRENT).await,
        [before.heads[0].record]
    );
    let case = &crate::cases::CASES[0];
    let expected = case.plan_from(input);
    engine.begin_import().unwrap();
    let review = engine
        .review_import(store, id, case.plan_from(input), &mut |_| true)
        .await
        .unwrap();
    assert_eq!(
        engine
            .apply_import(store, review.token, &choices(&expected), 42, &mut |_| true)
            .await,
        Err(Error::App(confidex_app::Error::Storage(error)))
    );
    assert!(engine.import_plan(review.token).is_err());
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    assert_eq!(
        search(engine, store, CONCURRENT).await,
        [before.heads[0].record]
    );
    assert!(search(engine, store, "Почта").await.is_empty());
    before
}

pub async fn retry<S: Store>(
    store: &mut S,
    created: &Created,
    survivor: &Snapshot,
    input: &[u8],
) -> Snapshot {
    let mut engine = Engine::default();
    command(
        &mut engine,
        store,
        Command::Unlock {
            vault: created.info.id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await;
    let case = &crate::cases::CASES[0];
    let id = created.info.id;
    let independent = &survivor.heads[0];
    let expected = case.plan_from(input);
    engine.begin_import().unwrap();
    let review = engine
        .review_import(store, id, case.plan_from(input), &mut |_| true)
        .await
        .unwrap();
    assert!(review.items.iter().all(|item| item.matching == Match::New));
    let report = engine
        .apply_import(store, review.token, &choices(&expected), 42, &mut |_| true)
        .await
        .unwrap();
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
        store.object(id, independent.revision).await.unwrap(),
        survivor.objects[0].wire
    );
    assert_eq!(
        store.head(id, independent.record).await.unwrap().as_ref(),
        Some(independent)
    );
    let imported: Vec<_> = after
        .heads
        .iter()
        .filter(|head| head.record != independent.record)
        .cloned()
        .collect();
    let records = verify(store, created, case, &expected, &imported).await;
    search_checks(&mut engine, store, case, &expected, &records).await;
    assert_eq!(
        search(&mut engine, store, CONCURRENT).await,
        [independent.record]
    );
    assert!(
        search(&mut engine, store, "resourcefailureprivate")
            .await
            .is_empty()
    );
    let repeated = engine
        .review_import(store, id, case.plan_from(input), &mut |_| true)
        .await
        .unwrap();
    assert!(
        repeated
            .items
            .iter()
            .all(|item| item.matching == Match::Duplicate)
    );
    engine.cancel_import(repeated.token).unwrap();
    after
}

pub async fn setup<S: Store>(store: &mut S) -> (Engine, Created) {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        store,
        Command::Create {
            name: "Public failure fixture".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("create")
    };
    (engine, created)
}
pub async fn write_concurrent<S: Store>(store: &mut S, id: VaultId, key: &str) {
    let mut engine = Engine::default();
    command(
        &mut engine,
        store,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: key.into(),
            remember: false,
        },
    )
    .await;
    let mut draft = confidex_app::new_record().unwrap();
    draft.title = CONCURRENT.into();
    draft.tags = vec!["concurrent-test".into()];
    assert!(matches!(
        command(&mut engine, store, Command::Save { draft, epoch: 77 }).await,
        Output::Saved(_)
    ));
}
pub async fn concurrent<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    created: &Created,
    writer: &mut impl Control,
) {
    let case = &crate::cases::CASES[0];
    let id = created.info.id;
    let expected = case.plan();
    engine.begin_import().unwrap();
    let review = engine
        .review_import(store, id, case.plan(), &mut |_| true)
        .await
        .unwrap();
    let selection = choices(&expected);
    assert!(store.snapshot(id).await.unwrap().objects.is_empty());
    assert_eq!(
        engine
            .apply_import(store, review.token, &selection, 42, writer)
            .await,
        Err(Error::App(confidex_app::Error::Storage(
            confidex_storage::Error::Conflict
        )))
    );
    assert!(engine.import_plan(review.token).is_err());
    let survivor = store.snapshot(id).await.unwrap();
    assert_eq!((survivor.heads.len(), survivor.objects.len()), (1, 1));
    let independent = &survivor.heads[0];
    let Output::Draft(draft) = command(
        engine,
        store,
        Command::Open {
            record: independent.record,
        },
    )
    .await
    else {
        panic!("concurrent record")
    };
    assert_eq!(draft.title, CONCURRENT);
    assert_eq!(draft.tags, ["concurrent-test"]);
    retry(store, created, &survivor, case.input).await;
}
