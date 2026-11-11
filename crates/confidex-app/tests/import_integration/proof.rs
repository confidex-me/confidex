use crate::cases::Case;
use confidex_app::{
    Command, Created, DeviceKeys, Engine, Output, Request,
    import::{self, Plan, Source, Status},
    import_apply::{Action, Choice, Error, Match, Phase, Selection},
};
use confidex_storage::{Head, RecordId, Snapshot, Store, VaultId};
use confidex_vault::{
    envelope, kdf, lock, record::Value, resources::MAX_OPEN_MEMORY, transfer_code,
};
pub mod changes;
pub mod faults;
pub mod index;
pub mod rejected;
pub mod service;

const PASSWORD: &str = "public-integration-password";
const ORIGIN: &str = "confidex.import.origin";
struct Keys;
impl DeviceKeys for Keys {
    async fn remove(&mut self, _: VaultId) -> bool {
        true
    }
    async fn load(&mut self, _: VaultId) -> Option<String> {
        None
    }
    async fn save(&mut self, _: VaultId, _: &str) -> bool {
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
fn accepted(status: Status) -> bool {
    matches!(status, Status::Ready | Status::Review)
}
fn choices(plan: &Plan) -> Selection {
    Selection {
        container_reviewed: true,
        choices: plan
            .items
            .iter()
            .map(|item| Choice {
                action: if accepted(item.status) {
                    Action::Create
                } else {
                    Action::Skip
                },
                reviewed: true,
            })
            .collect(),
    }
}
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .unwrap()
        .1
}
fn has(value: &Value, key: &str) -> bool {
    value
        .as_map()
        .unwrap()
        .iter()
        .any(|(k, _)| k.as_str() == Some(key))
}
fn same_map(value: &Value, expected: &Value) {
    assert_eq!(
        value.as_map().unwrap().len(),
        expected.as_map().unwrap().len()
    );
    for (key, expected) in expected.as_map().unwrap() {
        let key = key.as_str().unwrap();
        assert!(field(value, key) == expected, "attribute {key}");
    }
}
fn same_source(value: &Value, source: &Source) -> bool {
    field(value, "locator").as_u64() == Some(source.locator as u64)
        && [
            ("instance", &source.instance),
            ("account", &source.account),
            ("vault", &source.vault),
            ("item", &source.item),
        ]
        .iter()
        .all(|(name, expected)| match expected {
            Some(expected) => field(value, name).as_str() == Some(expected),
            None => matches!(field(value, name), Value::Nil),
        })
}
async fn heads<S: Store>(store: &mut S, id: VaultId) -> Vec<Head> {
    let mut result: Vec<Head> = Vec::new();
    loop {
        let after = result.last().map(|head| head.record);
        let page = store.heads(id, after).await.unwrap();
        if page.is_empty() {
            return result;
        }
        assert!(
            page.iter()
                .all(|head| after.is_none_or(|a| head.record > a))
        );
        result.extend(page);
        assert!(result.len() <= 16);
    }
}
async fn search<S: Store>(engine: &mut Engine, store: &mut S, query: &str) -> Vec<RecordId> {
    loop {
        match command(
            engine,
            store,
            Command::Search {
                query: query.into(),
                after: None,
                tag: None,
                refresh: false,
            },
        )
        .await
        {
            Output::Indexing => (),
            Output::Rows { rows, more, .. } => {
                assert!(!more);
                return rows.into_iter().map(|row| row.head.record).collect();
            }
            _ => panic!("search"),
        }
    }
}
async fn verify<S: Store>(
    store: &mut S,
    created: &Created,
    case: &Case,
    expected: &Plan,
    selected: &[Head],
) -> Vec<(usize, Head)> {
    let id = created.info.id;
    let saved = store.vault(id).await.unwrap();
    let code = transfer_code::decode(&created.key).unwrap();
    let vault = lock::open(
        &saved.lock,
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let mut seen = vec![false; case.total];
    let mut carriers = 0;
    let container =
        import::attribute_record(expected.container_attributes(MAX_OPEN_MEMORY).unwrap());
    let mut result = Vec::new();
    for head in selected.iter().cloned() {
        let wire = store.object(id, head.revision).await.unwrap();
        for marker in [
            b"PUBLIC-FIXTURE-PASSWORD".as_slice(),
            b"public-integration-source",
        ] {
            assert!(!wire.windows(marker.len()).any(|bytes| bytes == marker));
        }
        let mut opened = envelope::open(
            &wire,
            vault.keys(),
            vault.anchor(),
            Some(&head.revision),
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        let full = opened.record.encode_content(MAX_OPEN_MEMORY).unwrap();
        for password in [Some(crate::cases::EXPORT_PASSWORD), case.password]
            .into_iter()
            .flatten()
            .filter(|password| !password.is_empty())
        {
            assert!(
                !full
                    .bytes
                    .windows(password.len())
                    .any(|bytes| bytes == password.as_bytes())
            );
        }
        if let Some(keyfile) = case.keyfile {
            assert!(!keyfile.is_empty());
            assert!(
                !full
                    .bytes
                    .windows(keyfile.len())
                    .any(|bytes| bytes == keyfile)
            );
        }
        assert_eq!(opened.revision.header().record_id, head.record);
        assert_eq!(opened.revision.header().metadata.epoch, 42);
        let mut provenance = confidex_vault::record::Record::default();
        provenance
            .extra
            .insert(ORIGIN.into(), opened.record.extra.remove(ORIGIN).unwrap());
        let origin = &provenance.extra[ORIGIN];
        assert_eq!(field(origin, "format").as_str(), Some(case.origin));
        let index = expected
            .items
            .iter()
            .position(|item| same_source(field(origin, "source"), &item.source))
            .unwrap();
        assert!(accepted(expected.items[index].status));
        assert!(!std::mem::replace(&mut seen[index], true));
        let content = opened.record.encode_content(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            content.bytes.as_slice(),
            expected.items[index].record_bytes(),
            "{} record {index}",
            case.name
        );
        let attributes = import::attribute_record(
            expected.items[index]
                .source_attributes(MAX_OPEN_MEMORY)
                .unwrap(),
        );
        same_map(field(origin, "attributes"), &attributes.extra["attributes"]);
        let context = field(origin, "container");
        if expected.container_attributes_bytes().is_none() {
            assert!(context.as_map().unwrap().is_empty());
        } else if has(context, "attributes") {
            carriers += 1;
            same_map(field(context, "attributes"), &container.extra["attributes"]);
        } else {
            let carrier_id: [u8; 16] = field(context, "record")
                .as_slice()
                .unwrap()
                .try_into()
                .unwrap();
            let revision: [u8; 32] = field(context, "revision")
                .as_slice()
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                store.head(id, carrier_id).await.unwrap().unwrap().revision,
                revision
            );
            let wire = store.object(id, revision).await.unwrap();
            let opened = envelope::open(
                &wire,
                vault.keys(),
                vault.anchor(),
                Some(&revision),
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            assert_eq!(opened.revision.header().record_id, carrier_id);
            let carrier = field(&opened.record.extra[ORIGIN], "container");
            assert_eq!(field(context, "digest"), field(carrier, "digest"));
            same_map(field(carrier, "attributes"), &container.extra["attributes"]);
        }
        result.push((index, head));
    }
    assert_eq!(result.len(), case.selected);
    assert_eq!(
        carriers,
        usize::from(expected.container_attributes_bytes().is_some())
    );
    for (item, seen) in expected.items.iter().zip(seen) {
        assert_eq!(seen, accepted(item.status));
    }
    result
}
async fn search_checks<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    case: &Case,
    expected: &Plan,
    records: &[(usize, Head)],
) {
    let (index, head) = &records[0];
    let record = expected.items[*index].record(MAX_OPEN_MEMORY).unwrap();
    let title = record.extra["confidex.title"].as_str().unwrap();
    assert!(!title.trim().is_empty());
    assert!(
        search(engine, store, title).await.contains(&head.record),
        "{} title search",
        case.name
    );
    for query in [
        "PUBLIC-FIXTURE-PASSWORD",
        "PUBLIC-FIXTURE-HIDDEN",
        "PUBLIC-FIXTURE-GUARDED",
        "PUBLIC-FIXTURE-PIN",
        "PUBLIC-FIXTURE-FUTURE",
        "PUBLIC-FIXTURE-SECURE-NOTE",
        "PUBLIC-FIXTURE-ORG",
        "PUBLIC-FIXTURE-PLUGIN",
        "PUBLIC-FIXTURE-OLD",
        "Private fixture note",
        "12345678901234567890",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "public-integration-source",
        "alice",
        "operator",
    ] {
        assert!(
            search(engine, store, query).await.is_empty(),
            "{} private search: {query}",
            case.name
        );
    }
}
fn same_snapshot(before: &Snapshot, after: &Snapshot) {
    assert_eq!(before.vault.info.id, after.vault.info.id);
    assert_eq!(before.vault.info.name, after.vault.info.name);
    assert_eq!(before.vault.lock, after.vault.lock);
    assert_eq!(before.heads, after.heads);
    assert_eq!(before.objects.len(), after.objects.len());
    for object in &before.objects {
        let restored = after
            .objects
            .iter()
            .find(|other| other.head == object.head)
            .unwrap();
        assert_eq!(object.wire, restored.wire);
        assert_eq!(object.tags, restored.tags);
    }
}

async fn backup_roundtrip<S: Store>(
    engine: &mut Engine,
    store: &mut S,
    created: &Created,
    pending: [u8; 16],
) {
    let id = created.info.id;
    let before = store.snapshot(id).await.unwrap();
    let Output::Backup(archive) = command(engine, store, Command::ExportBackup).await else {
        panic!("backup");
    };
    for marker in [
        PASSWORD.as_bytes(),
        created.key.as_bytes(),
        b"public-integration-source",
    ] {
        assert!(!archive.windows(marker.len()).any(|bytes| bytes == marker));
    }
    assert_eq!(
        import::inspect(&archive, import::Limits::default(), &mut |_| true)
            .unwrap_err()
            .kind,
        import::ErrorKind::OwnBackup
    );
    assert!(matches!(
        command(engine, store, Command::InspectBackup { archive }).await,
        Output::BackupReady
    ));
    assert!(engine.import_plan(pending).is_err());
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    let conflict = engine
        .execute(
            store,
            &mut Keys,
            &mut Request {
                generation: 1,
                command: Command::RestoreBackup {
                    name: "Must not replace an existing vault".into(),
                    password: PASSWORD.into(),
                    key: created.key.clone(),
                    remember: false,
                },
            },
        )
        .await
        .result;
    assert!(matches!(
        conflict,
        Err(confidex_app::Error::Storage(
            confidex_storage::Error::Conflict
        ))
    ));
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
    store.remove(id).await.unwrap();
    let wrong = engine
        .execute(
            store,
            &mut Keys,
            &mut Request {
                generation: 1,
                command: Command::RestoreBackup {
                    name: created.info.name.clone(),
                    password: "wrong-public-password".into(),
                    key: created.key.clone(),
                    remember: false,
                },
            },
        )
        .await
        .result;
    assert!(wrong.is_err());
    assert!(
        store
            .vaults()
            .await
            .unwrap()
            .iter()
            .all(|info| info.id != id)
    );
    let Output::Opened {
        info,
        remembered,
        server,
        ..
    } = command(
        engine,
        store,
        Command::RestoreBackup {
            name: created.info.name.clone(),
            password: PASSWORD.into(),
            key: created.key.clone(),
            remember: false,
        },
    )
    .await
    else {
        panic!("restore");
    };
    assert_eq!(info.id, id);
    assert!(!remembered && server.is_none());
    assert!(store.sync_state(id).await.unwrap().is_none());
    same_snapshot(&before, &store.snapshot(id).await.unwrap());
}

pub async fn first<S: Store>(store: &mut S, case: &Case) -> Created {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        store,
        Command::Create {
            name: format!("Public {} fixture", case.name),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("create")
    };
    let id = created.info.id;
    let expected = case.plan();
    let selection = choices(&expected);
    if case.format == import::Format::BitwardenEncryptedJson {
        let before = store.snapshot(id).await.unwrap();
        for (password, error) in [
            ("", import::ErrorKind::InvalidOptions),
            ("wrong", import::ErrorKind::Checksum),
            (
                crate::cases::EXPORT_PASSWORD.trim(),
                import::ErrorKind::Checksum,
            ),
        ] {
            engine.begin_import().unwrap();
            let review = engine
                .review_import(store, id, case.plan(), &mut |_| true)
                .await
                .unwrap();
            engine.begin_import().unwrap();
            assert_eq!(
                case.try_plan_from(case.input, password).err().unwrap().kind,
                error
            );
            assert!(engine.import_plan(review.token).is_err());
            assert_eq!(
                engine
                    .apply_import(store, review.token, &selection, 42, &mut |_| true)
                    .await,
                Err(Error::InvalidSession)
            );
            same_snapshot(&before, &store.snapshot(id).await.unwrap());
        }
    }
    let mut denied = Vec::new();
    if expected.container_status == Status::Review {
        let mut choice = selection.clone();
        choice.container_reviewed = false;
        denied.push(choice);
    }
    if let Some(index) = expected
        .items
        .iter()
        .position(|item| item.status == Status::Review)
    {
        let mut choice = selection.clone();
        choice.choices[index].reviewed = false;
        denied.push(choice);
    }
    for (index, item) in expected.items.iter().enumerate() {
        if !accepted(item.status) {
            let mut choice = selection.clone();
            choice.choices[index].action = Action::Create;
            denied.push(choice);
        }
    }
    for choice in denied {
        assert_eq!(engine.begin_import().unwrap(), id);
        let review = engine
            .review_import(store, id, case.plan(), &mut |_| true)
            .await
            .unwrap();
        assert_eq!(
            engine
                .apply_import(store, review.token, &choice, 42, &mut |_| true)
                .await,
            Err(Error::InvalidChoice)
        );
        assert!(engine.import_plan(review.token).is_err());
        let snapshot = store.snapshot(id).await.unwrap();
        assert!(snapshot.heads.is_empty() && snapshot.objects.is_empty());
    }
    assert_eq!(engine.begin_import().unwrap(), id);
    let review = engine
        .review_import(store, id, case.plan(), &mut |_| true)
        .await
        .unwrap();
    assert!(review.items.iter().all(|item| item.matching == Match::New));
    assert!(store.snapshot(id).await.unwrap().objects.is_empty());
    assert_eq!(
        engine
            .apply_import(
                store,
                review.token,
                &selection,
                42,
                &mut |p: confidex_app::import_apply::Progress| p.phase != Phase::Commit
            )
            .await,
        Err(Error::Canceled)
    );
    assert!(engine.import_plan(review.token).is_err());
    let snapshot = store.snapshot(id).await.unwrap();
    assert!(snapshot.heads.is_empty() && snapshot.objects.is_empty());
    assert_eq!(engine.begin_import().unwrap(), id);
    let review = engine
        .review_import(store, id, case.plan(), &mut |_| true)
        .await
        .unwrap();
    let report = engine
        .apply_import(store, review.token, &selection, 42, &mut |_| true)
        .await
        .unwrap();
    assert_eq!(report.added, case.selected);
    assert_eq!(report.updated, 0);
    assert_eq!(report.skipped, case.total - case.selected);
    let selected = heads(store, id).await;
    let records = verify(store, &created, case, &expected, &selected).await;
    search_checks(&mut engine, store, case, &expected, &records).await;
    created
}
pub async fn reopened<S: Store>(store: &mut S, case: &Case, created: &Created) {
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
    let expected = case.plan();
    assert_eq!(engine.begin_import().unwrap(), id);
    let pending = engine
        .review_import(store, id, case.plan(), &mut |_| true)
        .await
        .unwrap();
    backup_roundtrip(&mut engine, store, created, pending.token).await;
    assert!(engine.import_plan(pending.token).is_err());
    let selected = heads(store, id).await;
    let records = verify(store, created, case, &expected, &selected).await;
    let previous = heads(store, id).await;
    assert_eq!(engine.begin_import().unwrap(), id);
    let review = engine
        .review_import(store, id, case.plan(), &mut |_| true)
        .await
        .unwrap();
    for item in &review.items {
        if accepted(item.status) {
            assert_eq!(item.matching, Match::Duplicate, "{}", case.name);
        }
    }
    let selection = Selection {
        container_reviewed: true,
        choices: review
            .items
            .iter()
            .map(|_| Choice {
                action: Action::Skip,
                reviewed: true,
            })
            .collect(),
    };
    assert_eq!(
        engine
            .apply_import(store, review.token, &selection, 43, &mut |_| true)
            .await
            .unwrap()
            .skipped,
        case.total
    );
    assert_eq!(heads(store, id).await, previous);
    search_checks(&mut engine, store, case, &expected, &records).await;
}
