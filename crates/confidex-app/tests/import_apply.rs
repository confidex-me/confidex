#![cfg(not(target_arch = "wasm32"))]
use confidex_app::{
    self as app, Command, DeviceKeys, Engine, Error as AppError, Output, Request,
    import::{self, Context, Format, Limits, Plan, Source, Status},
    import_apply::{Action, Choice, Error, Match, Phase, Progress, Report, Selection},
};
use confidex_storage::{Head, SqliteStore, Store};
use confidex_vault::{
    envelope, kdf, lock,
    record::{Entry, Record, Value},
    resources::MAX_OPEN_MEMORY,
    transfer_code,
};
const PASSWORD: &str = "public-import-test-password";
const ORIGIN: &str = "confidex.import.origin";
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
async fn command(
    engine: &mut Engine,
    store: &mut SqliteStore,
    command: Command,
) -> Result<Output, AppError> {
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
}
fn run(f: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f);
}
fn entry(kind: &str, key: &str, text: &str) -> Entry {
    Entry {
        name: "Repeated".into(),
        type_name: kind.into(),
        value: [(key.into(), text.into())].into(),
        extra: Default::default(),
    }
}
fn plan(items: &[(&str, &str, Status)], context: bool, weak: bool) -> Plan {
    let mut options = import::Options::default();
    options.source_instance = Some("public-stable-instance".into());
    let mut callback = |_| true;
    let mut builder = Context::new(
        Format::BitwardenJson,
        0,
        &options,
        Limits::default(),
        &mut callback,
    )
    .unwrap();
    if context {
        builder
            .set_container_attributes(
                [
                    ("entries".into(), Value::Binary(vec![0, 255, 3])),
                    ("tags".into(), "container-secret-needle".into()),
                ]
                .into(),
            )
            .unwrap();
    }
    for (index, (id, note, status)) in items.iter().enumerate() {
        let mut record = Record::default();
        record
            .extra
            .insert("confidex.title".into(), "Same title".into());
        record
            .extra
            .insert("vendor-extra".into(), Value::Binary(vec![255, 0, 7]));
        record.tags = vec!["import-fixture".into()];
        record.entries = vec![
            entry("url/v1", "url", "https://public-index-needle.invalid"),
            entry("note/v1", "text", note),
            entry("password/v1", "password", "hidden-password-needle"),
            entry("secure-note/v1", "text", "hidden-note-needle"),
        ];
        let mut hidden = entry("text/v1", "text", "hidden-text-needle");
        hidden.extra.insert(
            "metadata".into(),
            Value::Map(vec![("protected".into(), true.into())]),
        );
        record.entries.push(hidden);
        record.entries.push(Entry {
            name: "Repeated".into(),
            type_name: "totp/v1".into(),
            value: [
                (
                    "secret".into(),
                    Value::Binary(b"12345678901234567890".to_vec()),
                ),
                ("algorithm".into(), "SHA256".into()),
                ("digits".into(), 8u64.into()),
                ("period".into(), 45u64.into()),
                ("t0".into(), 0u64.into()),
            ]
            .into(),
            extra: Default::default(),
        });
        record.entries.push(Entry {
            name: String::new(),
            type_name: "file/v1".into(),
            value: [("data".into(), Value::Binary(vec![0, 255, 9]))].into(),
            extra: Default::default(),
        });
        let mut source = Source::default();
        source.locator = index;
        source.account = Some("account".into());
        source.vault = Some("foreign-vault".into());
        if !weak {
            source.item = Some((*id).into());
        }
        builder
            .push(import::Item {
                source,
                record,
                source_attributes: [
                    ("entries".into(), "source-only-date-2000".into()),
                    ("tags".into(), Value::Binary(vec![255, 0])),
                ]
                .into(),
                status: *status,
                diagnostics: vec![],
            })
            .unwrap();
    }
    builder.finish().unwrap()
}
fn choices(actions: impl IntoIterator<Item = Action>) -> Selection {
    Selection {
        container_reviewed: true,
        choices: actions
            .into_iter()
            .map(|action| Choice {
                action,
                reviewed: true,
            })
            .collect(),
    }
}
async fn create(engine: &mut Engine, store: &mut SqliteStore) -> app::Created {
    let Output::Created(created) = command(
        engine,
        store,
        Command::Create {
            name: "Synthetic import vault".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    .unwrap() else {
        panic!("create")
    };
    created
}
async fn opened(store: &mut SqliteStore, created: &app::Created) -> lock::OpenedVault {
    let stored = store.vault(created.info.id).await.unwrap();
    let code = transfer_code::decode(&created.key).unwrap();
    lock::open(
        &stored.lock,
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap()
}
async fn content(store: &mut SqliteStore, vault: &lock::OpenedVault, head: &Head) -> Record {
    let wire = store.object(vault.vault_id(), head.revision).await.unwrap();
    let opened = envelope::open(
        &wire,
        vault.keys(),
        vault.anchor(),
        Some(&head.revision),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    assert_eq!(opened.revision.header().record_id, head.record);
    opened.record
}
async fn search(engine: &mut Engine, store: &mut SqliteStore, text: &str) -> usize {
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
        .unwrap()
        {
            Output::Indexing => (),
            Output::Rows { rows, .. } => return rows.len(),
            _ => panic!("search"),
        }
    }
}
fn property<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .unwrap()
        .1
}

#[test]
fn importing_into_one_revision_branch_keeps_its_sibling_and_rejects_catalog_races() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("branches.sqlite")).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        let review = engine
            .review_import(
                &mut store,
                id,
                plan(&[("a", "original", Status::Ready)], false, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        engine
            .apply_import(
                &mut store,
                review.token,
                &choices([Action::Create]),
                1,
                &mut |_| true,
            )
            .await
            .unwrap();
        let root = store.branch_heads(id, None, None).await.unwrap().remove(0);
        let Output::Draft(base) = command(
            &mut engine,
            &mut store,
            Command::OpenRevision {
                record: root.record,
                revision: root.revision,
            },
        )
        .await
        .unwrap() else {
            panic!("draft")
        };
        let mut branches = Vec::new();
        for title in ["First branch", "Second branch"] {
            let mut draft = base.clone();
            draft.title = title.into();
            let Output::Saved(head) =
                command(&mut engine, &mut store, Command::Save { draft, epoch: 2 })
                    .await
                    .unwrap()
            else {
                panic!("save")
            };
            branches.push(head);
        }
        let peer_wire = store.object(id, branches[1].revision).await.unwrap();
        let review = engine
            .review_import(
                &mut store,
                id,
                plan(&[("a", "source changed", Status::Ready)], false, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(review.items[0].matching, Match::Conflict);
        let candidates = engine.import_candidates(review.token, 0, 0).unwrap();
        assert_eq!(candidates.items.len(), 2);
        assert!(
            branches
                .iter()
                .all(|h| candidates.items.iter().any(|c| c.head == *h))
        );
        let report = engine
            .apply_import(
                &mut store,
                review.token,
                &choices([Action::Update(branches[0].clone())]),
                3,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(report.updated, 1);
        let current = store.branch_heads(id, None, None).await.unwrap();
        assert_eq!(current.len(), 2);
        assert!(current.contains(&branches[1]) && !current.contains(&branches[0]));
        assert_eq!(
            store.object(id, branches[1].revision).await.unwrap(),
            peer_wire
        );
        let review = engine
            .review_import(
                &mut store,
                id,
                plan(
                    &[("a", "another source change", Status::Ready)],
                    false,
                    false,
                ),
                &mut |_| true,
            )
            .await
            .unwrap();
        let mut offline = base;
        offline.title = "Late offline branch".into();
        command(
            &mut engine,
            &mut store,
            Command::Save {
                draft: offline,
                epoch: 1,
            },
        )
        .await
        .unwrap();
        let before = store.snapshot(id).await.unwrap();
        assert!(matches!(
            engine
                .apply_import(
                    &mut store,
                    review.token,
                    &choices([Action::Update(branches[1].clone())]),
                    4,
                    &mut |_| true
                )
                .await,
            Err(Error::App(AppError::Storage(
                confidex_storage::Error::Conflict
            )))
        ));
        let after = store.snapshot(id).await.unwrap();
        assert_eq!(after.heads, before.heads);
        assert_eq!(after.objects.len(), before.objects.len());
    });
}

#[test]
fn apply_reopen_search_repeat_edit_and_delete_keep_the_actual_record_model() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        assert_eq!(
            search(&mut engine, &mut store, "visible-index-needle").await,
            0
        );
        let review = engine
            .review_import(
                &mut store,
                id,
                plan(
                    &[
                        ("a", "visible-index-needle", Status::Ready),
                        ("b", "visible-index-needle", Status::Ready),
                    ],
                    true,
                    false,
                ),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert!(review.items.iter().all(|i| i.matching == Match::New));
        assert!(store.heads(id, None).await.unwrap().is_empty());
        let report = engine
            .apply_import(
                &mut store,
                review.token,
                &choices([Action::Create, Action::Create]),
                42,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(
            report,
            Report {
                added: 2,
                updated: 0,
                skipped: 0
            }
        );
        let injector = rusqlite::Connection::open(&path).unwrap();
        injector
            .execute_batch("ALTER TABLE objects RENAME TO paused_objects")
            .unwrap();
        assert!(
            command(
                &mut engine,
                &mut store,
                Command::Search {
                    query: "visible-index-needle".into(),
                    after: None,
                    tag: None,
                    refresh: false
                }
            )
            .await
            .is_err()
        );
        injector
            .execute_batch("ALTER TABLE paused_objects RENAME TO objects")
            .unwrap();
        let retry = engine
            .review_import(
                &mut store,
                id,
                plan(
                    &[
                        ("a", "visible-index-needle", Status::Ready),
                        ("b", "visible-index-needle", Status::Ready),
                    ],
                    true,
                    false,
                ),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert!(
            retry
                .items
                .iter()
                .all(|item| item.matching == Match::Duplicate)
        );
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    retry.token,
                    &choices([Action::Skip, Action::Skip]),
                    42,
                    &mut |_| true
                )
                .await
                .unwrap()
                .skipped,
            2
        );
        assert!(matches!(
            engine.import_plan(review.token),
            Err(Error::InvalidSession)
        ));
        let heads = store.heads(id, None).await.unwrap();
        assert_eq!(heads.len(), 2);
        let vault = opened(&mut store, &created).await;
        let mut carriers = 0;
        let mut refs = 0;
        for head in &heads {
            let record = content(&mut store, &vault, head).await;
            assert_eq!(record.entries.len(), 7);
            assert_eq!(record.entries[0].name, record.entries[1].name);
            assert_eq!(record.entries[6].name, "");
            assert_eq!(record.extra["vendor-extra"], Value::Binary(vec![255, 0, 7]));
            assert_eq!(record.entries[5].value["digits"].as_u64(), Some(8));
            assert_eq!(record.entries[5].value["period"].as_u64(), Some(45));
            assert_eq!(
                record.entries[6].value["data"],
                Value::Binary(vec![0, 255, 9])
            );
            let origin = &record.extra[ORIGIN];
            assert_eq!(
                property(property(origin, "attributes"), "entries").as_str(),
                Some("source-only-date-2000")
            );
            let context = property(origin, "container");
            if context
                .as_map()
                .unwrap()
                .iter()
                .any(|(k, _)| k.as_str() == Some("attributes"))
            {
                carriers += 1;
                assert_eq!(
                    property(property(context, "attributes"), "entries"),
                    &Value::Binary(vec![0, 255, 3])
                );
            } else {
                refs += 1;
                let Value::Binary(revision) = property(context, "revision") else {
                    panic!("reference")
                };
                assert!(heads.iter().any(|h| h.revision.as_slice() == revision));
            }
            let wire = store.object(id, head.revision).await.unwrap();
            assert!(!wire.windows(22).any(|b| b == b"hidden-password-needle"));
            let verified = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY).unwrap();
            assert_eq!(verified.header().metadata.epoch, 42);
        }
        assert_eq!((carriers, refs), (1, 1));
        assert_eq!(
            search(&mut engine, &mut store, "visible-index-needle").await,
            2
        );
        assert_eq!(
            search(&mut engine, &mut store, "public-index-needle").await,
            2
        );
        for text in [
            "hidden-password-needle",
            "hidden-note-needle",
            "hidden-text-needle",
            "container-secret-needle",
            "source-only-date-2000",
            "12345678901234567890",
        ] {
            assert_eq!(search(&mut engine, &mut store, text).await, 0);
        }
        drop(store);
        let mut store = SqliteStore::open(&path).unwrap();
        let mut engine = Engine::default();
        command(
            &mut engine,
            &mut store,
            Command::Unlock {
                vault: id,
                password: PASSWORD.into(),
                key: created.key.clone(),
                remember: false,
            },
        )
        .await
        .unwrap();
        let repeat = engine
            .review_import(
                &mut store,
                id,
                plan(
                    &[
                        ("a", "visible-index-needle", Status::Ready),
                        ("b", "visible-index-needle", Status::Ready),
                    ],
                    true,
                    false,
                ),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert!(repeat.items.iter().all(|i| i.matching == Match::Duplicate));
        let first = repeat.items[0].duplicate.clone().unwrap();
        let second = repeat.items[1].duplicate.clone().unwrap();
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    repeat.token,
                    &choices([Action::Skip, Action::Skip]),
                    99,
                    &mut |_| true
                )
                .await
                .unwrap()
                .skipped,
            2
        );
        assert_eq!(store.snapshot(id).await.unwrap().objects.len(), 2);
        let changed = engine
            .review_import(
                &mut store,
                id,
                plan(&[("a", "source-changed-note", Status::Ready)], true, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(changed.items[0].matching, Match::Conflict);
        let candidates = engine.import_candidates(changed.token, 0, 0).unwrap();
        assert!(candidates.items[0].source_changed && !candidates.items[0].local_changed);
        engine
            .apply_import(
                &mut store,
                changed.token,
                &choices([Action::Update(first.clone())]),
                100,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(store.snapshot(id).await.unwrap().objects.len(), 3);
        assert_eq!(
            search(&mut engine, &mut store, "source-changed-note").await,
            1
        );
        let Output::Draft(mut draft) = command(
            &mut engine,
            &mut store,
            Command::Open {
                record: first.record,
            },
        )
        .await
        .unwrap() else {
            panic!("draft")
        };
        draft.title = "Local title edit".into();
        command(&mut engine, &mut store, Command::Save { draft, epoch: 101 })
            .await
            .unwrap();
        let local = engine
            .review_import(
                &mut store,
                id,
                plan(&[("a", "source-changed-note", Status::Ready)], true, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(local.items[0].matching, Match::Conflict);
        assert!(engine.import_candidates(local.token, 0, 0).unwrap().items[0].local_changed);
        engine.cancel_import(local.token).unwrap();
        command(
            &mut engine,
            &mut store,
            Command::Delete {
                record: second.record,
                expected: second.revision,
                epoch: 102,
            },
        )
        .await
        .unwrap();
        let deleted = engine
            .review_import(
                &mut store,
                id,
                plan(&[("b", "visible-index-needle", Status::Ready)], true, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(deleted.items[0].matching, Match::Conflict);
        assert!(engine.import_candidates(deleted.token, 0, 0).unwrap().items[0].deleted);
        engine
            .apply_import(
                &mut store,
                deleted.token,
                &choices([Action::Skip]),
                103,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(
            search(&mut engine, &mut store, "visible-index-needle").await,
            0
        );
    });
}

#[test]
fn cancellation_lock_and_atomic_failure_leave_no_imported_rows() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        let items = [("a", "note", Status::Ready), ("b", "note", Status::Ready)];
        let canceled = plan(&items, false, false);
        let memory = canceled.memory().clone();
        assert!(matches!(
            engine
                .review_import(&mut store, id, canceled, &mut |p: Progress| p.phase
                    != Phase::Review)
                .await,
            Err(Error::Canceled)
        ));
        assert_eq!(memory.available(), Limits::default().memory_bytes);
        for phase in [Phase::Seal, Phase::Commit] {
            let review = engine
                .review_import(&mut store, id, plan(&items, false, false), &mut |_| true)
                .await
                .unwrap();
            assert_eq!(
                engine
                    .apply_import(
                        &mut store,
                        review.token,
                        &choices([Action::Create, Action::Create]),
                        1,
                        &mut |p: Progress| p.phase != phase
                    )
                    .await,
                Err(Error::Canceled)
            );
            assert!(store.snapshot(id).await.unwrap().objects.is_empty());
        }
        let pending = plan(&items, false, false);
        let memory = pending.memory().clone();
        let review = engine
            .review_import(&mut store, id, pending, &mut |_| true)
            .await
            .unwrap();
        command(&mut engine, &mut store, Command::Lock)
            .await
            .unwrap();
        assert_eq!(memory.available(), Limits::default().memory_bytes);
        assert!(matches!(
            engine.import_plan(review.token),
            Err(Error::InvalidSession)
        ));
        assert_eq!(engine.begin_import(), Err(Error::App(AppError::Locked)));
        command(
            &mut engine,
            &mut store,
            Command::Unlock {
                vault: id,
                password: PASSWORD.into(),
                key: created.key.clone(),
                remember: false,
            },
        )
        .await
        .unwrap();
        let review = engine
            .review_import(&mut store, id, plan(&items, false, false), &mut |_| true)
            .await
            .unwrap();
        let injector = rusqlite::Connection::open(&path).unwrap();
        injector.execute_batch("CREATE TRIGGER fail_import BEFORE INSERT ON objects WHEN (SELECT COUNT(*) FROM objects)=1 BEGIN SELECT RAISE(ABORT,'public import failure'); END;").unwrap();
        assert!(
            engine
                .apply_import(
                    &mut store,
                    review.token,
                    &choices([Action::Create, Action::Create]),
                    1,
                    &mut |_| true
                )
                .await
                .is_err()
        );
        assert!(store.snapshot(id).await.unwrap().objects.is_empty());
        assert!(store.heads(id, None).await.unwrap().is_empty());
        injector.execute_batch("DROP TRIGGER fail_import").unwrap();
        let retry = engine
            .review_import(&mut store, id, plan(&items, false, false), &mut |_| true)
            .await
            .unwrap();
        assert!(retry.items.iter().all(|i| i.matching == Match::New));
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    retry.token,
                    &choices([Action::Create, Action::Create]),
                    2,
                    &mut |_| true
                )
                .await
                .unwrap()
                .added,
            2
        );
    });
}

#[test]
fn stale_confirmations_and_other_writers_cannot_apply_a_different_plan() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        let old = engine
            .review_import(
                &mut store,
                id,
                plan(&[("old", "old", Status::Ready)], false, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(engine.begin_import().unwrap(), id);
        assert!(matches!(
            engine.import_plan(old.token),
            Err(Error::InvalidSession)
        ));
        let new = engine
            .review_import(
                &mut store,
                id,
                plan(&[("new", "new", Status::Ready)], false, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    old.token,
                    &choices([Action::Create]),
                    1,
                    &mut |_| true
                )
                .await,
            Err(Error::InvalidSession)
        );
        assert!(engine.cancel_import(old.token).is_err());
        assert!(engine.import_plan(new.token).is_ok());
        let mut other = SqliteStore::open(&path).unwrap();
        let mut other_engine = Engine::default();
        command(
            &mut other_engine,
            &mut other,
            Command::Unlock {
                vault: id,
                password: PASSWORD.into(),
                key: created.key.clone(),
                remember: false,
            },
        )
        .await
        .unwrap();
        let mut draft = app::new_record().unwrap();
        draft.title = "Concurrent local record".into();
        command(
            &mut other_engine,
            &mut other,
            Command::Save { draft, epoch: 2 },
        )
        .await
        .unwrap();
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    new.token,
                    &choices([Action::Create]),
                    3,
                    &mut |_| true
                )
                .await,
            Err(Error::App(AppError::Storage(
                confidex_storage::Error::Conflict
            )))
        );
        let snapshot = store.snapshot(id).await.unwrap();
        assert_eq!(snapshot.heads.len(), 1);
        assert_eq!(snapshot.objects.len(), 1);
        assert_eq!(search(&mut engine, &mut store, "new").await, 0);
    });
}

#[test]
fn selected_carrier_explicit_choices_and_weak_history_are_preserved() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("vault.sqlite")).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        let review = engine
            .review_import(
                &mut store,
                id,
                plan(
                    &[
                        ("unselected", "a", Status::Blocked),
                        ("b", "b", Status::Ready),
                        ("c", "c", Status::Ready),
                    ],
                    true,
                    false,
                ),
                &mut |_| true,
            )
            .await
            .unwrap();
        let memory = engine.import_plan(review.token).unwrap().memory().clone();
        engine
            .apply_import(
                &mut store,
                review.token,
                &choices([Action::Skip, Action::Create, Action::Create]),
                1,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(memory.available(), Limits::default().memory_bytes);
        let vault = opened(&mut store, &created).await;
        let heads = store.heads(id, None).await.unwrap();
        for head in &heads {
            let record = content(&mut store, &vault, head).await;
            let origin = &record.extra[ORIGIN];
            let source_id = property(property(origin, "source"), "item")
                .as_str()
                .unwrap();
            let container = property(origin, "container");
            let is_carrier = container
                .as_map()
                .unwrap()
                .iter()
                .any(|(k, _)| k.as_str() == Some("attributes"));
            assert_eq!(is_carrier, source_id == "b");
        }
        let review = engine
            .review_import(
                &mut store,
                id,
                plan(&[("b", "b", Status::Ready)], true, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(review.items[0].matching, Match::Duplicate);
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    review.token,
                    &choices([Action::Create]),
                    2,
                    &mut |_| true
                )
                .await,
            Err(Error::InvalidChoice)
        );
        let repeated = engine
            .review_import(
                &mut store,
                id,
                plan(
                    &[
                        ("copy-source", "same", Status::Ready),
                        ("copy-source", "same", Status::Ready),
                    ],
                    false,
                    false,
                ),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(
            repeated.items[1].matching,
            Match::RepeatedSource { first: 0 }
        );
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    repeated.token,
                    &choices([Action::Create, Action::Create]),
                    2,
                    &mut |_| true
                )
                .await,
            Err(Error::InvalidChoice)
        );
        let repeated = engine
            .review_import(
                &mut store,
                id,
                plan(
                    &[
                        ("copy-source", "same", Status::Ready),
                        ("copy-source", "same", Status::Ready),
                    ],
                    false,
                    false,
                ),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    repeated.token,
                    &choices([Action::Create, Action::Copy]),
                    2,
                    &mut |_| true
                )
                .await
                .unwrap()
                .added,
            2
        );
        let repeated = engine
            .review_import(
                &mut store,
                id,
                plan(&[("copy-source", "same", Status::Ready)], false, false),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(repeated.items[0].matching, Match::Duplicate);
        assert_eq!(repeated.items[0].candidates, 2);
        engine.cancel_import(repeated.token).unwrap();
        let empty = engine
            .review_import(&mut store, id, plan(&[], true, false), &mut |_| true)
            .await
            .unwrap();
        assert_eq!(
            engine
                .apply_import(&mut store, empty.token, &choices([]), 3, &mut |_| true)
                .await,
            Err(Error::NoCarrier)
        );
        let weak = engine
            .review_import(
                &mut store,
                id,
                plan(&[("", "unique-weak-note", Status::Ready)], false, true),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(weak.items[0].matching, Match::New);
        engine
            .apply_import(
                &mut store,
                weak.token,
                &choices([Action::Create]),
                4,
                &mut |_| true,
            )
            .await
            .unwrap();
        let weak = engine
            .review_import(
                &mut store,
                id,
                plan(&[("", "unique-weak-note", Status::Ready)], false, true),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(weak.items[0].matching, Match::Duplicate);
        let target = weak.items[0].duplicate.clone().unwrap();
        engine.cancel_import(weak.token).unwrap();
        let Output::Draft(mut draft) = command(
            &mut engine,
            &mut store,
            Command::Open {
                record: target.record,
            },
        )
        .await
        .unwrap() else {
            panic!("draft")
        };
        draft.title = "Weak identity local edit".into();
        command(&mut engine, &mut store, Command::Save { draft, epoch: 5 })
            .await
            .unwrap();
        let weak = engine
            .review_import(
                &mut store,
                id,
                plan(&[("", "unique-weak-note", Status::Ready)], false, true),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(weak.items[0].matching, Match::Conflict);
        assert!(engine.import_candidates(weak.token, 0, 0).unwrap().items[0].local_changed);
        engine.cancel_import(weak.token).unwrap();
        let prior = store.head(id, target.record).await.unwrap().unwrap();
        let wire = envelope::seal(
            &Record::default(),
            vault.keys(),
            envelope::Options {
                vault_id: id,
                record_id: target.record,
                parents: &[prior.revision],
                epoch: 6,
                kind: envelope::EventKind::Deletion,
            },
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
            .unwrap()
            .id();
        let tombstone = Head {
            record: target.record,
            revision,
        };
        store
            .append(id, &tombstone, Some(prior.revision), &wire, &[])
            .await
            .unwrap();
        let weak = engine
            .review_import(
                &mut store,
                id,
                plan(&[("", "unique-weak-note", Status::Ready)], false, true),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(weak.items[0].matching, Match::Conflict);
        let candidates = engine.import_candidates(weak.token, 0, 0).unwrap();
        assert_eq!(candidates.items.len(), 1);
        assert!(candidates.items[0].deleted);
        engine
            .apply_import(
                &mut store,
                weak.token,
                &choices([Action::Update(tombstone)]),
                7,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(search(&mut engine, &mut store, "unique-weak-note").await, 1);
    });
}

#[test]
fn encrypted_provenance_counts_toward_the_whole_record_limit() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("vault.sqlite")).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let mut state = 0x48d2a5f137e691a3u64;
        let mut bytes = |length| {
            (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect::<Vec<_>>()
        };
        let mut record = Record::default();
        record.entries.push(Entry {
            name: "Public synthetic file".into(),
            type_name: "file/v1".into(),
            value: [("data".into(), Value::Binary(bytes(2_050_000)))].into(),
            extra: Default::default(),
        });
        let options = import::Options::default();
        let mut callback = |_| true;
        let mut context =
            Context::new(Format::Csv, 0, &options, Limits::default(), &mut callback).unwrap();
        context
            .push(import::Item {
                source: Source::default(),
                record,
                source_attributes: [("original".into(), Value::Binary(bytes(2_050_000)))].into(),
                status: Status::Ready,
                diagnostics: vec![],
            })
            .unwrap();
        let review = engine
            .review_import(
                &mut store,
                created.info.id,
                context.finish().unwrap(),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    review.token,
                    &choices([Action::Create]),
                    1,
                    &mut |_| true
                )
                .await,
            Err(Error::Limit)
        );
        assert!(
            store
                .snapshot(created.info.id)
                .await
                .unwrap()
                .objects
                .is_empty()
        );
    });
}

fn property_mut<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    let Value::Map(values) = value else {
        panic!("fixture metadata map")
    };
    &mut values
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(key))
        .unwrap()
        .1
}

#[test]
fn immutable_container_references_are_authenticated_before_duplicate_matching() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("vault.sqlite")).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        let items = [
            ("carrier", "same", Status::Ready),
            ("reference", "same", Status::Ready),
        ];
        let review = engine
            .review_import(&mut store, id, plan(&items, true, false), &mut |_| true)
            .await
            .unwrap();
        engine
            .apply_import(
                &mut store,
                review.token,
                &choices([Action::Create, Action::Create]),
                1,
                &mut |_| true,
            )
            .await
            .unwrap();
        let vault = opened(&mut store, &created).await;
        let heads = store.heads(id, None).await.unwrap();
        let mut carrier = None;
        let mut reference = None;
        for head in heads {
            let record = content(&mut store, &vault, &head).await;
            let source = property(property(&record.extra[ORIGIN], "source"), "item")
                .as_str()
                .unwrap();
            if source == "carrier" {
                carrier = Some(head);
            } else {
                reference = Some(head);
            }
        }
        let carrier = carrier.unwrap();
        let reference = reference.unwrap();
        for mode in 0..3 {
            let mut record = content(&mut store, &vault, &reference).await;
            let context = property_mut(record.extra.get_mut(ORIGIN).unwrap(), "container");
            let (field, value) = match mode {
                0 => ("revision", vec![8; 32]),
                1 => ("record", vec![8; 16]),
                _ => ("digest", vec![8; 32]),
            };
            let mut retired = Record::default();
            retired.extra.insert(
                "old".into(),
                std::mem::replace(property_mut(context, field), Value::Binary(value)),
            );
            let expected = store
                .head(id, reference.record)
                .await
                .unwrap()
                .unwrap()
                .revision;
            let wire = envelope::seal(
                &record,
                vault.keys(),
                envelope::Options {
                    vault_id: id,
                    record_id: reference.record,
                    parents: &[expected],
                    epoch: mode + 2,
                    kind: envelope::EventKind::Content,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .id();
            store
                .append(
                    id,
                    &Head {
                        record: reference.record,
                        revision,
                    },
                    Some(expected),
                    &wire,
                    &record.tags,
                )
                .await
                .unwrap();
            assert!(matches!(
                engine
                    .review_import(&mut store, id, plan(&items, true, false), &mut |_| true)
                    .await,
                Err(Error::InvalidProvenance)
            ));
            assert_eq!(store.heads(id, None).await.unwrap().len(), 2);
        }
        let record = content(&mut store, &vault, &reference).await;
        let expected = store
            .head(id, reference.record)
            .await
            .unwrap()
            .unwrap()
            .revision;
        let wire = envelope::seal(
            &record,
            vault.keys(),
            envelope::Options {
                vault_id: id,
                record_id: reference.record,
                parents: &[expected],
                epoch: 9,
                kind: envelope::EventKind::Content,
            },
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
            .unwrap()
            .id();
        store
            .append(
                id,
                &Head {
                    record: reference.record,
                    revision,
                },
                Some(expected),
                &wire,
                &record.tags,
            )
            .await
            .unwrap();
        command(
            &mut engine,
            &mut store,
            Command::Delete {
                record: carrier.record,
                expected: carrier.revision,
                epoch: 10,
            },
        )
        .await
        .unwrap();
        let review = engine
            .review_import(&mut store, id, plan(&items, true, false), &mut |_| true)
            .await
            .unwrap();
        assert_eq!(review.items[0].matching, Match::Conflict);
        assert_eq!(review.items[1].matching, Match::Duplicate);
    });
}

#[test]
fn shared_container_diagnostics_cannot_be_bypassed_by_item_selection() {
    run(async {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("vault.sqlite")).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        let diagnostic = import::Diagnostic {
            code: import::Code::SourceDataPreserved,
            location: import::Location::default(),
        };
        for (count, status, action, ack) in [
            (1, Status::Blocked, Action::Skip, true),
            (0, Status::Blocked, Action::Skip, true),
            (1, Status::Review, Action::Create, false),
        ] {
            let mut source = if count == 0 {
                plan(&[], true, false)
            } else {
                plan(&[("global", "public-note", Status::Ready)], true, false)
            };
            source.container_status = status;
            source.container_diagnostics.push(diagnostic);
            let review = engine
                .review_import(&mut store, id, source, &mut |_| true)
                .await
                .unwrap();
            assert_eq!(review.container_status, status);
            assert_eq!(review.container_diagnostics, vec![diagnostic]);
            let mut selection = choices((0..count).map(|_| action.clone()));
            selection.container_reviewed = ack;
            assert_eq!(
                engine
                    .apply_import(&mut store, review.token, &selection, 1, &mut |_| true)
                    .await,
                Err(Error::InvalidChoice)
            );
            assert!(store.snapshot(id).await.unwrap().objects.is_empty());
        }
        let mut source = plan(&[("global", "public-note", Status::Ready)], true, false);
        source.container_status = Status::Review;
        source.container_diagnostics.push(diagnostic);
        let review = engine
            .review_import(&mut store, id, source, &mut |_| true)
            .await
            .unwrap();
        assert_eq!(
            engine
                .apply_import(
                    &mut store,
                    review.token,
                    &choices([Action::Create]),
                    2,
                    &mut |_| true
                )
                .await
                .unwrap()
                .added,
            1
        );
    });
}

#[test]
fn actual_bitwarden_fixture_reaches_encrypted_storage_and_reimports_safely() {
    run(async {
        fn parsed() -> Plan {
            let mut options = import::Options::default();
            options.source_instance = Some("public-fixture-source".into());
            import::prepare(
                Format::BitwardenJson,
                include_bytes!("import_fixtures/bitwarden_json/personal.json"),
                &options,
                Limits::default(),
                &mut |_| true,
                import::formats::bitwarden_json::parse,
            )
            .unwrap()
        }
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "import_fixtures/bitwarden_json/personal.expected.json"
        ))
        .unwrap();
        let expected = golden["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| matches!(record["status"].as_str(), Some("ready" | "review")))
            .count();
        assert!(expected > 0);
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::open(&dir.path().join("vault.sqlite")).unwrap();
        let mut engine = Engine::default();
        let created = create(&mut engine, &mut store).await;
        let id = created.info.id;
        assert_eq!(engine.begin_import().unwrap(), id);
        let review = engine
            .review_import(&mut store, id, parsed(), &mut |_| true)
            .await
            .unwrap();
        let selection = choices(review.items.iter().map(|item| {
            if matches!(item.status, Status::Ready | Status::Review) {
                Action::Create
            } else {
                Action::Skip
            }
        }));
        let report = engine
            .apply_import(&mut store, review.token, &selection, 100, &mut |_| true)
            .await
            .unwrap();
        assert_eq!(report.added, expected);
        assert_eq!(store.heads(id, None).await.unwrap().len(), expected);
        assert_eq!(
            search(&mut engine, &mut store, "PUBLIC-FIXTURE-PASSWORD").await,
            0
        );
        assert_eq!(engine.begin_import().unwrap(), id);
        let review = engine
            .review_import(&mut store, id, parsed(), &mut |_| true)
            .await
            .unwrap();
        assert!(
            review
                .items
                .iter()
                .filter(|item| matches!(item.status, Status::Ready | Status::Review))
                .all(|item| item.matching == Match::Duplicate)
        );
        let count = review.items.len();
        engine
            .apply_import(
                &mut store,
                review.token,
                &choices((0..count).map(|_| Action::Skip)),
                101,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(store.snapshot(id).await.unwrap().objects.len(), expected);
    });
}
