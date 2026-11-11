use confidex_app::{
    Command, DeviceKeys, Engine, Output, Request,
    import::Plan,
    import_apply::{Action, Choice, Match, Selection},
};
use confidex_storage::Store;
use confidex_vault::{envelope, kdf, lock, resources::MAX_OPEN_MEMORY, transfer_code};
const PASSWORD: &str = "public-csv-test-password";
const SOURCE: &[u8]=b"title,username,password,public,CONTEXTONLYHEADER\nSame,alice,PASSWORDALPHA,VISIBLEALPHA,HIDDENALPHA\nSame,bob,PASSWORDBETA,VISIBLEBETA,HIDDENBETA\n";
fn incoming(input: &[u8]) -> Plan {
    use confidex_app::import::{self, CsvColumn, CsvMapping, Format, Limits, Options};
    let columns = [
        (0, "title", ""),
        (1, "username/v1", "User"),
        (2, "password/v1", "Password"),
        (3, "note/v1", "Public note"),
        (4, "secret/v1", "Protected"),
    ]
    .into_iter()
    .map(|(index, target, name)| CsvColumn {
        index,
        target: target.into(),
        name: name.into(),
    })
    .collect();
    let options = Options {
        source_instance: Some("public-csv-engine-source".into()),
        password: String::new(),
        keyfile: Vec::new(),
        password_present: false,
        keyfile_present: false,
        include_archived: false,
        include_deleted: false,
        csv: Some(CsvMapping {
            delimiter: b',',
            header: true,
            columns,
        }),
    };
    import::prepare(
        Format::Csv,
        input,
        &options,
        Limits::default(),
        &mut |_| true,
        import::formats::csv::parse,
    )
    .unwrap()
}
struct Keys;
impl DeviceKeys for Keys {
    async fn remove(&mut self, _: [u8; 16]) -> bool {
        true
    }
    async fn load(&mut self, _: [u8; 16]) -> Option<String> {
        None
    }
    async fn save(&mut self, _: [u8; 16], _: &str) -> bool {
        false
    }
}
async fn command<S: Store>(engine: &mut Engine, store: &mut S, command: Command) -> Output {
    engine
        .execute(
            store,
            &mut Keys,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
        .unwrap()
}
fn selection(action: Action) -> Selection {
    Selection {
        container_reviewed: true,
        choices: (0..2)
            .map(|_| Choice {
                action: action.clone(),
                reviewed: true,
            })
            .collect(),
    }
}
async fn search<S: Store>(engine: &mut Engine, store: &mut S, text: &str) -> usize {
    loop {
        match command(
            engine,
            store,
            Command::Search {
                query: text.into(),
                after: None,
                tag: None,
                refresh: false,
            },
        )
        .await
        {
            Output::Indexing => {}
            Output::Rows { rows, .. } => return rows.len(),
            _ => panic!("unexpected search reply"),
        }
    }
}
pub async fn first<S: Store>(store: &mut S) -> confidex_app::Created {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        store,
        Command::Create {
            name: "CSV fixture".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("create")
    };
    let id = created.info.id;
    assert_eq!(engine.begin_import().unwrap(), id);
    let expected = incoming(SOURCE);
    let expected = expected
        .items
        .iter()
        .map(|i| i.record_bytes().to_vec())
        .collect::<Vec<_>>();
    let review = engine
        .review_import(store, id, incoming(SOURCE), &mut |_| true)
        .await
        .unwrap();
    assert!(review.items.iter().all(|i| i.matching == Match::New));
    assert!(store.heads(id, None).await.unwrap().is_empty());
    let report = engine
        .apply_import(
            store,
            review.token,
            &selection(Action::Create),
            17,
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!(report.added, 2);
    assert_eq!(search(&mut engine, store, "VISIBLEALPHA").await, 1);
    for needle in ["HIDDENALPHA", "PASSWORDALPHA", "CONTEXTONLYHEADER"] {
        assert_eq!(search(&mut engine, store, needle).await, 0);
    }
    let saved = store.vault(id).await.unwrap();
    let code = transfer_code::decode(&created.key).unwrap();
    let vault = lock::open(
        &saved.lock,
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let heads = store.heads(id, None).await.unwrap();
    assert_eq!(heads.len(), 2);
    for head in &heads {
        let wire = store.object(id, head.revision).await.unwrap();
        assert!(
            !wire
                .windows(b"HIDDENALPHA".len())
                .any(|s| s == b"HIDDENALPHA")
        );
        let mut opened = envelope::open(
            &wire,
            vault.keys(),
            vault.anchor(),
            Some(&head.revision),
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        assert!(
            opened
                .record
                .extra
                .remove("confidex.import.origin")
                .is_some()
        );
        let bytes = opened.record.encode_content(MAX_OPEN_MEMORY).unwrap();
        assert!(
            expected
                .iter()
                .any(|e| e.as_slice() == bytes.bytes.as_slice())
        );
    }

    created
}
pub async fn reopened<S: Store>(store: &mut S, created: &confidex_app::Created) {
    let id = created.info.id;
    let heads = store.heads(id, None).await.unwrap();
    assert_eq!(heads.len(), 2);
    let mut engine = Engine::default();
    command(
        &mut engine,
        store,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await;
    engine.begin_import().unwrap();
    let review = engine
        .review_import(store, id, incoming(SOURCE), &mut |_| true)
        .await
        .unwrap();
    assert!(review.items.iter().all(|i| i.matching == Match::Duplicate));
    assert_eq!(
        engine
            .apply_import(
                store,
                review.token,
                &selection(Action::Skip),
                18,
                &mut |_| true
            )
            .await
            .unwrap()
            .skipped,
        2
    );
    let reordered=b"title,username,password,public,CONTEXTONLYHEADER\nSame,bob,PASSWORDBETA,VISIBLEBETA,HIDDENBETA\nSame,alice,PASSWORDALPHA,VISIBLEALPHA,HIDDENALPHA\n";
    engine.begin_import().unwrap();
    let review = engine
        .review_import(store, id, incoming(reordered), &mut |_| true)
        .await
        .unwrap();
    assert!(review.items.iter().all(|i| i.matching != Match::New));
    engine
        .apply_import(
            store,
            review.token,
            &selection(Action::Skip),
            19,
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!(store.heads(id, None).await.unwrap(), heads);
    assert_eq!(search(&mut engine, store, "VISIBLEBETA").await, 1);
}

use crate::load as dataset;
async fn head_count<S: Store>(store: &mut S, vault: [u8; 16]) -> usize {
    let mut after = None;
    let mut count = 0;
    loop {
        let page = store.heads(vault, after).await.unwrap();
        if page.is_empty() {
            return count;
        }
        assert!(
            page.iter()
                .all(|head| after.is_none_or(|id| head.record > id))
        );
        after = page.last().map(|head| head.record);
        count += page.len();
        assert!(count <= dataset::ROWS);
    }
}
pub async fn first_load<S: Store>(
    store: &mut S,
    progress: &mut impl FnMut(&'static str),
) -> confidex_app::Created {
    first_load_observed(store, &mut |event| {
        if let LoadEvent::Boundary(phase) = event {
            progress(phase);
        }
    })
    .await
}
#[derive(Clone, Copy)]
pub enum LoadEvent {
    Boundary(&'static str),
    Parse(confidex_app::import::Progress),
    Apply(confidex_app::import_apply::Progress),
    Parsed {
        input: usize,
        encoded: usize,
        retained: usize,
    },
    Applied,
}
pub async fn first_load_observed<S: Store>(
    store: &mut S,
    observer: &mut impl FnMut(LoadEvent),
) -> confidex_app::Created {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        store,
        Command::Create {
            name: "CSV 10000-row fixture".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("create")
    };
    observer(LoadEvent::Boundary("create"));
    let id = engine.begin_import().unwrap();
    let source = zeroize::Zeroizing::new(dataset::source());
    let plan = dataset::plan_with(source.as_bytes(), &mut |progress| {
        observer(LoadEvent::Parse(progress));
        true
    });
    observer(LoadEvent::Parsed {
        input: source.len(),
        encoded: plan.statistics.encoded_bytes,
        retained: confidex_app::import::Limits::default().memory_bytes - plan.memory().available(),
    });
    drop(source);
    observer(LoadEvent::Boundary("parse-map-validate"));
    let review = engine
        .review_import(store, id, plan, &mut |_| true)
        .await
        .unwrap();
    assert_eq!(review.items.len(), dataset::ROWS);
    assert!(review.items.iter().all(|i| i.matching == Match::New));
    assert!(store.heads(id, None).await.unwrap().is_empty());
    observer(LoadEvent::Boundary("review"));
    let choices = Selection {
        container_reviewed: true,
        choices: (0..dataset::ROWS)
            .map(|_| Choice {
                action: Action::Create,
                reviewed: true,
            })
            .collect(),
    };
    let report = engine
        .apply_import(store, review.token, &choices, 20, &mut |progress| {
            observer(LoadEvent::Apply(progress));
            true
        })
        .await
        .unwrap();
    assert_eq!(report.added, dataset::ROWS);
    observer(LoadEvent::Applied);
    assert_eq!(head_count(store, id).await, dataset::ROWS);
    observer(LoadEvent::Boundary("seal-commit"));
    assert_eq!(search(&mut engine, store, "public9999").await, 1);
    for query in [
        "user9999",
        "PASSWORD9999",
        "HIDDEN9999",
        "SECRET9999",
        "Примечание",
    ] {
        assert_eq!(search(&mut engine, store, query).await, 0);
    }
    observer(LoadEvent::Boundary("index-search"));
    created
}
pub async fn reopened_load<S: Store>(
    store: &mut S,
    created: &confidex_app::Created,
    progress: &mut impl FnMut(&'static str),
) {
    let mut engine = Engine::default();
    let id = created.info.id;
    command(
        &mut engine,
        store,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await;
    progress("reopen-unlock");
    engine.begin_import().unwrap();
    let source = zeroize::Zeroizing::new(dataset::source());
    let plan = dataset::plan(source.as_bytes());
    drop(source);
    progress("repeat-parse");
    let review = engine
        .review_import(store, id, plan, &mut |_| true)
        .await
        .unwrap();
    assert_eq!(review.items.len(), dataset::ROWS);
    assert!(review.items.iter().all(|i| i.matching == Match::Duplicate));
    progress("repeat-review");
    let saved = store.vault(id).await.unwrap();
    let code = transfer_code::decode(&created.key).unwrap();
    let vault = lock::open(
        &saved.lock,
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let expected = engine.import_plan(review.token).unwrap();
    let mut seen = vec![false; dataset::ROWS];
    let mut after = None;
    loop {
        let page = store.heads(id, after).await.unwrap();
        if page.is_empty() {
            break;
        }
        assert!(
            page.iter()
                .all(|head| after.is_none_or(|id| head.record > id))
        );
        after = page.last().map(|head| head.record);
        for head in page {
            let wire = store.object(id, head.revision).await.unwrap();
            let mut opened = envelope::open(
                &wire,
                vault.keys(),
                vault.anchor(),
                Some(&head.revision),
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let row: usize = opened.record.extra["confidex.title"]
                .as_str()
                .unwrap()
                .strip_prefix("Public ")
                .unwrap()
                .parse()
                .unwrap();
            assert!(!std::mem::replace(&mut seen[row], true));
            assert!(
                opened
                    .record
                    .extra
                    .remove("confidex.import.origin")
                    .is_some()
            );
            let bytes = opened.record.encode_content(MAX_OPEN_MEMORY).unwrap();
            assert_eq!(bytes.bytes.as_slice(), expected.items[row].record_bytes());
        }
    }
    assert!(seen.iter().all(|present| *present));
    drop(vault);
    progress("verify-all-fields");
    let choices = Selection {
        container_reviewed: true,
        choices: (0..dataset::ROWS)
            .map(|_| Choice {
                action: Action::Skip,
                reviewed: true,
            })
            .collect(),
    };
    assert_eq!(
        engine
            .apply_import(store, review.token, &choices, 21, &mut |_| true)
            .await
            .unwrap()
            .skipped,
        dataset::ROWS
    );
    assert_eq!(head_count(store, id).await, dataset::ROWS);
    progress("repeat-skip");
    assert_eq!(search(&mut engine, store, "public9999").await, 1);
    progress("reopened-index-search");
}
