use confidex_app::import::{
    self, Context, Error, ErrorKind, Format, Limits, Options, Phase, Plan,
    formats::{bitwarden_encrypted_json, bitwarden_json},
};
use confidex_vault::resources::MAX_OPEN_MEMORY;
use serde_json::{Value as Json, json};

const PASSWORD: &str = " Public test-only 密码 é e\u{301} ";
const LEGACY: &[u8] = include_bytes!("import_fixtures/bitwarden_encrypted_json/pbkdf2-legacy.json");
const PLAIN: &[u8] = include_bytes!("import_fixtures/bitwarden_json/personal.json");
#[cfg(not(target_arch = "wasm32"))]
#[path = "import_bitwarden_encrypted/proof.rs"]
mod proof;
fn options(password: &str) -> Options {
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    options.password = password.into();
    options
}
fn run(input: &[u8], password: &str) -> Result<Plan, Error> {
    import::prepare(
        Format::BitwardenEncryptedJson,
        input,
        &options(password),
        Limits::default(),
        &mut |_| true,
        bitwarden_encrypted_json::parse,
    )
}
fn changed(change: impl FnOnce(&mut Json)) -> Vec<u8> {
    let mut value: Json = serde_json::from_slice(LEGACY).unwrap();
    change(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn producer_exports_have_identical_records_for_all_kdfs() {
    let reference = import::prepare(
        Format::BitwardenJson,
        PLAIN,
        &options(""),
        Limits::default(),
        &mut |_| true,
        bitwarden_json::parse,
    )
    .unwrap();
    for input in [
        LEGACY,
        include_bytes!("import_fixtures/bitwarden_encrypted_json/pbkdf2.json").as_slice(),
        include_bytes!("import_fixtures/bitwarden_encrypted_json/argon2.json").as_slice(),
        include_bytes!("import_fixtures/bitwarden_encrypted_json/argon2-64.json").as_slice(),
        include_bytes!("import_fixtures/bitwarden_encrypted_json/argon2-128.json").as_slice(),
        include_bytes!("import_fixtures/bitwarden_encrypted_json/argon2-min.json").as_slice(),
    ] {
        let plan = run(input, PASSWORD).unwrap();
        assert_eq!(plan.items.len(), reference.items.len());
        for (actual, expected) in plan.items.iter().zip(&reference.items) {
            assert_eq!(actual.record_bytes(), expected.record_bytes());
            assert_eq!(
                actual.source_attributes_bytes(),
                expected.source_attributes_bytes()
            );
            assert_eq!(actual.status, expected.status);
            assert_eq!(actual.diagnostics, expected.diagnostics);
            assert_eq!(actual.source.item, expected.source.item);
            assert_eq!(actual.source.instance, expected.source.instance);
        }
        let mut metadata = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
        assert!(metadata.remove("bitwarden.encryption").is_some());
        assert_eq!(
            metadata,
            reference.container_attributes(MAX_OPEN_MEMORY).unwrap()
        );
    }
}

#[test]
fn wrong_password_and_each_authenticated_component_fail_closed() {
    for password in ["wrong", PASSWORD.trim(), " Public test-only 密码 é é "] {
        assert_eq!(
            run(LEGACY, password).err().unwrap().kind,
            ErrorKind::Checksum
        );
    }
    for name in ["data", "encKeyValidation_DO_NOT_EDIT"] {
        for part in 0..3 {
            let input = changed(|root| {
                let mut value = root[name].as_str().unwrap().as_bytes().to_vec();
                let start = if part == 0 {
                    2
                } else {
                    value
                        .iter()
                        .enumerate()
                        .filter(|(_, b)| **b == b'|')
                        .nth(part - 1)
                        .unwrap()
                        .0
                        + 1
                };
                value[start] = if value[start] == b'A' { b'B' } else { b'A' };
                root[name] = String::from_utf8(value).unwrap().into();
            });
            assert_eq!(
                run(&input, PASSWORD).err().unwrap().kind,
                ErrorKind::Checksum
            );
        }
    }
    assert_eq!(
        run(LEGACY, "").err().unwrap().kind,
        ErrorKind::InvalidOptions
    );
}

#[test]
fn unsupported_account_kdf_versions_and_malformed_envelopes_do_no_key_work() {
    let cases = [
        (
            changed(|r| {
                r.as_object_mut().unwrap().remove("passwordProtected");
            }),
            ErrorKind::UnsupportedFormat,
        ),
        (
            changed(|r| r["passwordProtected"] = false.into()),
            ErrorKind::UnsupportedFormat,
        ),
        (
            changed(|r| r["kdfType"] = 7.into()),
            ErrorKind::UnsupportedVersion,
        ),
        (
            changed(|r| r["kdfIterations"] = 4999.into()),
            ErrorKind::Limit,
        ),
        (
            changed(|r| r["kdfIterations"] = 2_000_001.into()),
            ErrorKind::Limit,
        ),
        (
            changed(|r| r["kdfIterations"] = json!(1e100)),
            ErrorKind::UnsupportedVersion,
        ),
        (
            changed(|r| r["kdfIterations"] = json!(5000.5)),
            ErrorKind::UnsupportedVersion,
        ),
        (
            changed(|r| r["kdfMemory"] = 16.into()),
            ErrorKind::UnsupportedVersion,
        ),
        (
            changed(|r| r["future"] = true.into()),
            ErrorKind::UnsupportedVersion,
        ),
        (
            changed(|r| r["salt"] = "not-base64".into()),
            ErrorKind::Malformed,
        ),
        (
            changed(|r| r["data"] = "0.unauthed|data".into()),
            ErrorKind::UnsupportedVersion,
        ),
        (
            changed(|r| r["data"] = "2.AA==|AA==|AA==".into()),
            ErrorKind::Malformed,
        ),
        (
            changed(|r| r["data"] = format!("{}|extra", r["data"].as_str().unwrap()).into()),
            ErrorKind::Malformed,
        ),
    ];
    for (input, expected) in cases {
        let mut entered = false;
        let result = import::prepare(
            Format::BitwardenEncryptedJson,
            &input,
            &options(PASSWORD),
            Limits::default(),
            &mut |p| {
                entered |= p.phase == Phase::Read && p.total == 3;
                true
            },
            bitwarden_encrypted_json::parse,
        );
        assert_eq!(result.err().unwrap().kind, expected);
        assert!(!entered);
    }
}

#[test]
fn argon_parameters_and_memory_are_bounded_before_expensive_work() {
    for (key, value) in [
        ("kdfIterations", 1),
        ("kdfIterations", 11),
        ("kdfMemory", 15),
        ("kdfMemory", 1025),
        ("kdfMemory", u32::MAX),
        ("kdfParallelism", 0),
        ("kdfParallelism", 17),
    ] {
        let input = changed(|r| {
            r["kdfType"] = 1.into();
            r["kdfIterations"] = 2.into();
            r["kdfMemory"] = 16.into();
            r["kdfParallelism"] = 1.into();
            r[key] = value.into();
        });
        assert_eq!(run(&input, PASSWORD).err().unwrap().kind, ErrorKind::Limit);
    }
    let input = include_bytes!("import_fixtures/bitwarden_encrypted_json/argon2-64.json");
    let limits = Limits {
        memory_bytes: 16 << 20,
        ..Limits::default()
    };
    let result = import::prepare(
        Format::BitwardenEncryptedJson,
        input,
        &options(PASSWORD),
        limits,
        &mut |_| true,
        bitwarden_encrypted_json::parse,
    );
    assert_eq!(result.err().unwrap().kind, ErrorKind::Limit);
    let input = changed(|root| {
        root["kdfType"] = 1.into();
        root["kdfIterations"] = 2.into();
        root["kdfMemory"] = 1024.into();
        root["kdfParallelism"] = 1.into();
    });
    assert_eq!(run(&input, PASSWORD).err().unwrap().kind, ErrorKind::Limit);
}

#[test]
fn cancellation_at_each_opening_checkpoint_releases_working_memory() {
    for stage in 0..3 {
        let opts = options(PASSWORD);
        let mut callback =
            |p: import::Progress| !(p.phase == Phase::Read && p.total == 3 && p.current == stage);
        let mut context = Context::new(
            Format::BitwardenEncryptedJson,
            LEGACY.len(),
            &opts,
            Limits::default(),
            &mut callback,
        )
        .unwrap();
        let memory = context.memory().clone();
        let available = memory.available();
        assert_eq!(
            bitwarden_encrypted_json::parse(LEGACY, &mut context)
                .unwrap_err()
                .kind,
            ErrorKind::Canceled
        );
        assert_eq!(memory.available(), available);
        drop(context);
        assert_eq!(memory.available(), Limits::default().memory_bytes);
    }
}

#[test]
fn duplicate_json_keys_truncation_and_payload_limits_are_rejected() {
    let mut duplicate = LEGACY.to_vec();
    duplicate.splice(1..1, b"\"encrypted\":true,".iter().copied());
    assert_eq!(
        run(&duplicate, PASSWORD).err().unwrap().kind,
        ErrorKind::DuplicateKey
    );
    for length in [0, 1, LEGACY.len() / 2, LEGACY.len() - 3] {
        assert!(run(&LEGACY[..length], PASSWORD).is_err());
    }
    let limits = Limits {
        unpacked_bytes: 128,
        ..Limits::default()
    };
    assert_eq!(
        import::prepare(
            Format::BitwardenEncryptedJson,
            LEGACY,
            &options(PASSWORD),
            limits,
            &mut |_| true,
            bitwarden_encrypted_json::parse
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Limit
    );
}

#[test]
fn authenticated_payloads_still_require_supported_plain_json() {
    for (input, expected) in [
        (
            include_bytes!("import_fixtures/bitwarden_encrypted_json/invalid-json.json").as_slice(),
            ErrorKind::Malformed,
        ),
        (
            include_bytes!("import_fixtures/bitwarden_encrypted_json/encrypted-plaintext.json")
                .as_slice(),
            ErrorKind::UnsupportedFormat,
        ),
    ] {
        assert_eq!(run(input, PASSWORD).err().unwrap().kind, expected);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sqlite_preview_apply_reopen_and_repeat_keep_secrets_protected() {
    use confidex_storage::SqliteStore;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&path).unwrap();
            let created = proof::first(&mut store).await;
            drop(store);
            let mut store = SqliteStore::open(&path).unwrap();
            proof::reopened(&mut store, &created).await;
        });
}
