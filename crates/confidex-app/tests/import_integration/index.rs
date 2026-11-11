use super::*;

pub async fn open<S: Store>(store: &mut S, created: &Created) -> Engine {
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
    engine
}

pub async fn failed<S: Store>(engine: &mut Engine, store: &mut S) {
    for _ in 0..2 {
        let mut failed = false;
        for _ in 0..4 {
            let reply = engine
                .execute(
                    store,
                    &mut Keys,
                    &mut Request {
                        generation: 1,
                        command: Command::Search {
                            query: String::new(),
                            after: None,
                            tag: None,
                            refresh: false,
                        },
                    },
                )
                .await;
            match reply.result {
                Ok(Output::Indexing) => (),
                Err(confidex_app::Error::Integrity) => {
                    failed = true;
                    break;
                }
                _ => panic!("a damaged object must not produce partial search rows"),
            }
        }
        assert!(
            failed,
            "the three-record rebuild did not reach the damaged object"
        );
    }
}

pub async fn recovered<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    created: &Created,
    before: &Snapshot,
) {
    let id = created.info.id;
    same_snapshot(before, &store.snapshot(id).await.unwrap());
    let mut found = search(engine, store, "").await;
    found.sort_unstable();
    assert_eq!(
        found,
        before
            .heads
            .iter()
            .map(|head| head.record)
            .collect::<Vec<_>>()
    );
    let case = &crate::cases::CASES[0];
    let expected = case.plan();
    let records = verify(store, created, case, &expected, &before.heads).await;
    search_checks(engine, store, case, &expected, &records).await;
    let review = engine
        .review_import(store, id, case.plan(), &mut |_| true)
        .await
        .unwrap();
    assert!(
        review
            .items
            .iter()
            .all(|item| item.matching == Match::Duplicate)
    );
    engine.cancel_import(review.token).unwrap();
    same_snapshot(before, &store.snapshot(id).await.unwrap());
}
