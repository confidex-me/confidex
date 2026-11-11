use confidex_app::{
    Command, DeviceKeys, Engine, Output, Request,
    import::{self, ErrorKind, Format, Limits, Options, Plan},
    import_apply::{Action, Choice, Match, Selection},
};
use confidex_storage::Store;
use confidex_vault::{envelope, kdf, lock, resources::MAX_OPEN_MEMORY, transfer_code};
const PASSWORD: &str = "public-encrypted-import-vault-password";
const EXPORT_PASSWORD: &str = " Public test-only 密码 é e\u{301} ";
const SOURCE: &[u8] = include_bytes!("../import_fixtures/bitwarden_encrypted_json/argon2-128.json");
fn plan(password: &str) -> Result<Plan, import::Error> {
    let mut options = Options::default();
    options.source_instance = Some("public-encrypted-source".into());
    options.password = password.into();
    import::prepare(
        Format::BitwardenEncryptedJson,
        SOURCE,
        &options,
        Limits::default(),
        &mut |_| true,
        import::formats::bitwarden_encrypted_json::parse,
    )
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
        choices: (0..3)
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
            Output::Indexing => (),
            Output::Rows { rows, .. } => return rows.len(),
            _ => panic!("search reply"),
        }
    }
}
pub async fn first<S: Store>(store: &mut S) -> confidex_app::Created {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        &mut engine,
        store,
        Command::Create {
            name: "Public encrypted import".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("create reply")
    };
    let id = created.info.id;
    engine.begin_import().unwrap();
    assert_eq!(plan("wrong").err().unwrap().kind, ErrorKind::Checksum);
    assert!(store.heads(id, None).await.unwrap().is_empty());
    let expected = plan(EXPORT_PASSWORD).unwrap();
    let mut expected: Vec<_> = expected
        .items
        .iter()
        .map(|item| item.record_bytes().to_vec())
        .collect();
    let review = engine
        .review_import(store, id, plan(EXPORT_PASSWORD).unwrap(), &mut |_| true)
        .await
        .unwrap();
    assert!(review.items.iter().all(|item| item.matching == Match::New));
    assert!(store.heads(id, None).await.unwrap().is_empty());
    let report = engine
        .apply_import(
            store,
            review.token,
            &selection(Action::Create),
            10,
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!(report.added, 3);
    assert_eq!(search(&mut engine, store, "public first").await, 1);
    for needle in [
        "PUBLIC-FIXTURE-PASSWORD",
        "PUBLIC-FIXTURE-HIDDEN",
        "PUBLIC-FIXTURE-SECURE-NOTE",
        "PUBLIC-FIXTURE-OLD",
        "PUBLIC-FIXTURE-FUTURE",
    ] {
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
    let mut actual = Vec::new();
    let heads = store.heads(id, None).await.unwrap();
    assert_eq!(heads.len(), 3);
    for head in heads {
        let wire = store.object(id, head.revision).await.unwrap();
        assert!(
            !wire
                .windows(b"PUBLIC-FIXTURE-PASSWORD".len())
                .any(|w| w == b"PUBLIC-FIXTURE-PASSWORD")
        );
        assert!(
            !wire
                .windows(EXPORT_PASSWORD.len())
                .any(|w| w == EXPORT_PASSWORD.as_bytes())
        );
        let mut record = envelope::open(
            &wire,
            vault.keys(),
            vault.anchor(),
            Some(&head.revision),
            MAX_OPEN_MEMORY,
        )
        .unwrap()
        .record;
        assert!(record.extra.remove("confidex.import.origin").is_some());
        actual.push(
            record
                .encode_content(MAX_OPEN_MEMORY)
                .unwrap()
                .bytes
                .to_vec(),
        );
    }
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    command(&mut engine, store, Command::Lock).await;
    created
}
pub async fn reopened<S: Store>(store: &mut S, created: &confidex_app::Created) {
    let id = created.info.id;
    let heads = store.heads(id, None).await.unwrap();
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
        .review_import(store, id, plan(EXPORT_PASSWORD).unwrap(), &mut |_| true)
        .await
        .unwrap();
    assert!(
        review
            .items
            .iter()
            .all(|item| item.matching == Match::Duplicate)
    );
    let report = engine
        .apply_import(
            store,
            review.token,
            &selection(Action::Skip),
            11,
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!(report.skipped, 3);
    assert_eq!(store.heads(id, None).await.unwrap(), heads);
    assert_eq!(search(&mut engine, store, "public first").await, 1);
}
