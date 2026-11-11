use confidex_app::import::{
    self, Code, ErrorKind, Format, Limits, Options, Phase, Plan, Status, formats::bitwarden_json,
};
use confidex_vault::{record::Value, resources::MAX_OPEN_MEMORY, ssh};
use serde_json::{Value as Json, json};

fn options() -> Options {
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    options
}
fn parse(input: &[u8]) -> Plan {
    import::prepare(
        Format::BitwardenJson,
        input,
        &options(),
        Limits::default(),
        &mut |_| true,
        bitwarden_json::parse,
    )
    .unwrap()
}
fn value(input: &Json) -> Value {
    match input {
        Json::Null => Value::Nil,
        Json::Bool(v) => (*v).into(),
        Json::Number(v) => v
            .as_i64()
            .map(Value::from)
            .or_else(|| v.as_u64().map(Value::from))
            .unwrap(),
        Json::String(v) => v.as_str().into(),
        Json::Array(v) => Value::Array(v.iter().map(value).collect()),
        Json::Object(v) if v.len() == 1 && v.contains_key("$binary") => {
            let text = v["$binary"].as_str().unwrap();
            Value::Binary(
                (0..text.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                    .collect(),
            )
        }
        Json::Object(v) => Value::Map(
            v.iter()
                .map(|(k, v)| (k.as_str().into(), value(v)))
                .collect(),
        ),
    }
}

#[test]
fn personal_and_organization_exports_match_the_independent_golden_records() {
    for (input, expected) in [
        (
            include_bytes!("import_fixtures/bitwarden_json/personal.json").as_slice(),
            include_str!("import_fixtures/bitwarden_json/personal.expected.json"),
        ),
        (
            include_bytes!("import_fixtures/bitwarden_json/organization.json").as_slice(),
            include_str!("import_fixtures/bitwarden_json/organization.expected.json"),
        ),
    ] {
        let plan = parse(input);
        let golden: Json = serde_json::from_str(expected).unwrap();
        assert_eq!(
            plan.items.len(),
            golden["records"].as_array().unwrap().len()
        );
        for (actual, expected) in plan.items.iter().zip(golden["records"].as_array().unwrap()) {
            let record = actual.record(MAX_OPEN_MEMORY).unwrap();
            let attributes = actual.source_attributes(MAX_OPEN_MEMORY).unwrap();
            assert_eq!(
                actual.source.instance.as_deref(),
                expected["source"]["instance"].as_str()
            );
            assert_eq!(
                actual.source.vault.as_deref(),
                expected["source"]["vault"].as_str()
            );
            assert_eq!(
                actual.source.item.as_deref(),
                expected["source"]["item"].as_str()
            );
            assert_eq!(
                serde_json::to_value(actual.status).unwrap(),
                expected["status"]
            );
            let diagnostics: Vec<_> = actual
                .diagnostics
                .iter()
                .map(|d| serde_json::to_value(d.code).unwrap())
                .collect();
            assert_eq!(diagnostics, *expected["diagnostics"].as_array().unwrap());
            assert_eq!(
                record.tags,
                expected["record"]["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                record.extra["confidex.title"],
                value(&expected["record"]["extra"]["confidex.title"])
            );
            let entries = expected["record"]["entries"].as_array().unwrap();
            assert_eq!(record.entries.len(), entries.len());
            for (entry, expected) in record.entries.iter().zip(entries) {
                assert_eq!(entry.name, expected["name"].as_str().unwrap());
                assert_eq!(entry.type_name, expected["type"].as_str().unwrap());
                if entry.name == "Original data" {
                    let a: Json =
                        serde_json::from_str(entry.value["text"].as_str().unwrap()).unwrap();
                    let b: Json =
                        serde_json::from_str(expected["value"]["text"].as_str().unwrap()).unwrap();
                    assert_eq!(a, b);
                } else {
                    for (key, expected) in expected["value"].as_object().unwrap() {
                        assert_eq!(entry.value[key], value(expected));
                    }
                }
                for (key, expected) in expected["extra"].as_object().unwrap() {
                    assert_eq!(entry.extra[key], value(expected));
                }
            }
            for (key, expected) in expected["source_attributes"].as_object().unwrap() {
                assert_eq!(attributes[key], value(expected));
            }
        }
    }
}

#[test]
fn pinned_producer_capture_keeps_unsupported_material_protected() {
    let plan = parse(include_bytes!(
        "import_fixtures/bitwarden_json/producer-personal.json"
    ));
    assert_eq!(plan.items.len(), 8);
    for index in [0, 4, 5, 6, 7] {
        assert_eq!(plan.items[index].status, Status::Review);
        let record = plan.items[index].record(MAX_OPEN_MEMORY).unwrap();
        let original = record
            .entries
            .iter()
            .find(|entry| entry.name == "Original data")
            .unwrap();
        assert_eq!(original.type_name, "secure-note/v1");
        let raw: Json = serde_json::from_str(original.value["text"].as_str().unwrap()).unwrap();
        assert!(raw.get("type").is_some());
    }
    for index in [2, 3] {
        let record = plan.items[index].record(MAX_OPEN_MEMORY).unwrap();
        assert!(
            record
                .entries
                .iter()
                .any(|entry| entry.type_name == "secret/v1")
        );
        assert!(record.entries.len() >= 6);
    }
    let login = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert!(
        !login
            .entries
            .iter()
            .filter(|entry| entry.type_name == "text/v1")
            .any(|entry| entry
                .value
                .values()
                .any(|v| v.as_str() == Some("PUBLIC-FIXTURE-FUTURE")))
    );
}

#[test]
fn valid_synthetic_ssh_key_remains_usable_after_mapping() {
    let input = include_bytes!("import_fixtures/bitwarden_json/ssh-key.json");
    let plan = parse(input);
    let source: Json = serde_json::from_slice(input).unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let key = ssh::Key::from_value(&record.entries[0].value, ssh::REQUIRED_MEMORY).unwrap();
    assert_eq!(
        key.fingerprint(),
        source["items"][0]["sshKey"]["keyFingerprint"]
            .as_str()
            .unwrap()
    );
    let message = b"public Bitwarden import fixture";
    let signature = key.sign(message).unwrap();
    ssh::verify(&key.public_blob().unwrap(), message, &signature).unwrap();
    let attributes = plan.items[0].source_attributes(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        attributes["sshKey.publicKey"].as_str(),
        source["items"][0]["sshKey"]["publicKey"].as_str()
    );
}

#[test]
fn malformed_ssh_public_slots_cannot_expose_an_unknown_secret_to_search() {
    let mut input: Json = serde_json::from_slice(include_bytes!(
        "import_fixtures/bitwarden_json/ssh-key.json"
    ))
    .unwrap();
    input["items"][0]["sshKey"]["publicKey"] = "PUBLIC-FIXTURE-SECRET-IN-WRONG-SLOT".into();
    let plan = parse(&serde_json::to_vec(&input).unwrap());
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(plan.items[0].status, Status::Review);
    assert!(
        !record
            .entries
            .iter()
            .filter(|entry| entry.type_name == "text/v1")
            .any(|entry| entry
                .value
                .values()
                .any(|value| value.as_str() == Some("PUBLIC-FIXTURE-SECRET-IN-WRONG-SLOT")))
    );
}

#[test]
fn unknown_json_integer_is_preserved_as_source_bytes_without_rounding() {
    let input = br#"{"encrypted":false,"folders":[],"items":[{"type":99,"name":"Future","future":123456789012345678901234567890}]}"#;
    let plan = parse(input);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert!(
        record.entries[0].value["text"]
            .as_str()
            .unwrap()
            .contains("123456789012345678901234567890")
    );
}

#[test]
fn malformed_source_facts_are_not_silently_coerced_or_dropped() {
    for extra in [
        r#""revisionDate":123456789012345678901234567890"#,
        r#""deletedDate":123456789012345678901234567890"#,
        r#""archivedDate":123456789012345678901234567890"#,
        r#""favorite":123456789012345678901234567890"#,
        r#""reprompt":123456789012345678901234567890"#,
        r#""passwordHistory":[{"password":"PUBLIC-FIXTURE","lastUsedDate":123456789012345678901234567890}]"#,
        r#""card":{"future":null}"#,
    ] {
        let input = format!(
            r#"{{"encrypted":false,"folders":[],"items":[{{"type":3,"name":"Public fixture",{extra}}}]}}"#
        );
        let plan = parse(input.as_bytes());
        assert_eq!(plan.items[0].status, Status::Review);
        let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
        let source = record
            .entries
            .iter()
            .find(|entry| entry.name == "Original data")
            .unwrap()
            .value["text"]
            .as_str()
            .unwrap();
        assert!(source.contains(extra));
    }
}

#[test]
fn duplicate_source_ids_are_rejected_within_their_vault_scope() {
    let item = json!({"id":"same-id","type":2,"name":"Public fixture"});
    let input =
        serde_json::to_vec(&json!({"encrypted":false,"folders":[],"items":[item.clone(),item]}))
            .unwrap();
    let error = import::prepare(
        Format::BitwardenJson,
        &input,
        &options(),
        Limits::default(),
        &mut |_| true,
        bitwarden_json::parse,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::AmbiguousFormat);
    assert_eq!(error.location.item, Some(1));
    let input = serde_json::to_vec(&json!({"encrypted":false,"collections":[],"items":[
        {"id":"same-id","organizationId":"org-a","type":2,"name":"Public A"},
        {"id":"same-id","organizationId":"org-b","type":2,"name":"Public B"}
    ]}))
    .unwrap();
    let plan = parse(&input);
    assert_eq!(plan.items.len(), 2);
    assert_ne!(plan.items[0].source.vault, plan.items[1].source.vault);
}

#[test]
fn archive_and_recycle_items_are_unselected_unless_requested() {
    let input = serde_json::to_vec(&json!({"encrypted":false,"folders":[],"items":[{"type":2,"name":"Archived","archivedDate":"2026-01-01"},{"type":2,"name":"Deleted","deletedDate":"2026-01-02"}]})).unwrap();
    let plan = parse(&input);
    assert!(
        plan.items
            .iter()
            .all(|item| item.status == Status::Excluded)
    );
    let mut options = options();
    options.include_archived = true;
    options.include_deleted = true;
    let plan = import::prepare(
        Format::BitwardenJson,
        &input,
        &options,
        Limits::default(),
        &mut |_| true,
        bitwarden_json::parse,
    )
    .unwrap();
    assert!(plan.items.iter().all(|item| item.status == Status::Ready));
}

#[test]
fn admission_refuses_encryption_ambiguity_duplicate_keys_and_bad_shapes() {
    for (input, expected) in [
        (
            br#"{"encrypted":true,"items":[]}"#.as_slice(),
            ErrorKind::UnsupportedFormat,
        ),
        (
            br#"{"folders":[],"items":[]}"#.as_slice(),
            ErrorKind::Malformed,
        ),
        (
            br#"{"encrypted":0,"items":[]}"#.as_slice(),
            ErrorKind::Malformed,
        ),
        (
            br#"{"encrypted":false,"folders":[],"collections":[],"items":[]}"#.as_slice(),
            ErrorKind::AmbiguousFormat,
        ),
        (
            br#"{"encrypted":false,"items":{},"items":[]}"#.as_slice(),
            ErrorKind::DuplicateKey,
        ),
        (
            br#"{"encrypted":false,"folders":[],"items":[{"organizationId":"org","type":1}]}"#
                .as_slice(),
            ErrorKind::AmbiguousFormat,
        ),
        (
            br#"{"encrypted":false,"collections":[],"items":[{"type":1}]}"#.as_slice(),
            ErrorKind::AmbiguousFormat,
        ),
    ] {
        let error = import::prepare(
            Format::BitwardenJson,
            input,
            &options(),
            Limits::default(),
            &mut |_| true,
            bitwarden_json::parse,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, expected);
    }
}

#[test]
fn unresolved_groups_block_the_item_instead_of_discarding_membership() {
    let plan = parse(br#"{"encrypted":false,"folders":[],"items":[{"id":"item","folderId":"missing","type":1,"name":"Public fixture"}]}"#);
    assert_eq!(plan.items[0].status, Status::Blocked);
    assert!(
        plan.items[0]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::UnresolvedFieldReference)
    );
}

#[test]
fn cancel_and_resource_limits_refuse_the_plan() {
    let input = include_bytes!("import_fixtures/bitwarden_json/personal.json");
    let error = import::prepare(
        Format::BitwardenJson,
        input,
        &options(),
        Limits::default(),
        &mut |p| p.phase != Phase::Map,
        bitwarden_json::parse,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Canceled);
    let limits = Limits {
        records: 2,
        ..Limits::default()
    };
    let error = import::prepare(
        Format::BitwardenJson,
        input,
        &options(),
        limits,
        &mut |_| true,
        bitwarden_json::parse,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Limit);
}

#[test]
fn shared_document_metadata_survives_without_records_or_a_selected_group() {
    let input = br#"{"encrypted":false,"folders":[{"id":"unused","name":"Public folder","future":123456789012345678901234567890}],"futureRoot":{"protected":"PUBLIC-FIXTURE"},"items":[]}"#;
    let plan = parse(input);
    assert!(plan.items.is_empty());
    assert_eq!(plan.container_status, Status::Review);
    assert_eq!(plan.container_diagnostics.len(), 1);
    let attributes = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    let text = attributes["bitwarden.document.json"].as_str().unwrap();
    assert!(text.contains("123456789012345678901234567890"));
    let document: Json = serde_json::from_str(text).unwrap();
    assert_eq!(document["folders"][0]["name"], "Public folder");
    assert_eq!(document["futureRoot"]["protected"], "PUBLIC-FIXTURE");
    assert!(document.get("items").is_none());
    assert!(plan.container_attributes_bytes().is_some());
}

#[test]
fn unsupported_document_policy_requires_review_and_is_stored_only_once() {
    let input = br#"{"encrypted":false,"folders":[{"id":"folder","name":"Public folder","hidePasswords":true}],"futureRoot":"PUBLIC-FIXTURE","items":[{"id":"a","type":2,"name":"A","folderId":"folder"},{"id":"b","type":2,"name":"B","folderId":"folder"}]}"#;
    let plan = parse(input);
    assert_eq!(plan.items.len(), 2);
    assert_eq!(plan.container_status, Status::Review);
    assert_eq!(plan.container_diagnostics.len(), 1);
    assert_eq!(
        plan.container_diagnostics[0].code,
        Code::SourceDataPreserved
    );
    for item in &plan.items {
        assert_eq!(item.status, Status::Ready);
        assert!(
            plan.container_diagnostics
                .iter()
                .any(|d| d.code == Code::SourceDataPreserved)
        );
        assert!(
            !item
                .source_attributes(MAX_OPEN_MEMORY)
                .unwrap()
                .contains_key("bitwarden.document.json")
        );
    }
    let context = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    assert!(
        context["bitwarden.document.json"]
            .as_str()
            .unwrap()
            .contains("hidePasswords")
    );
}

#[test]
fn archive_extension_adds_binary_files_before_core_validation() {
    fn wrapper(input: &[u8], context: &mut import::Context<'_>) -> Result<(), import::Error> {
        let extra = std::collections::BTreeMap::from([(
            "entries".into(),
            Value::Array(vec!["public-file.bin".into()]),
        )]);
        bitwarden_json::parse_with(input, context, extra, &mut |source, item, context| {
            assert_eq!(source["id"], "public-item");
            let reservation = context.memory().reserve(4)?;
            item.record.entries.push(confidex_vault::record::Entry {
                name: "Public attachment".into(),
                type_name: "file/v1".into(),
                value: std::collections::BTreeMap::from([
                    ("filename".into(), "public-file.bin".into()),
                    ("data".into(), Value::Binary(vec![0, 255, 0, 1])),
                ]),
                extra: std::collections::BTreeMap::new(),
            });
            Ok(vec![reservation])
        })
    }
    let input=br#"{"encrypted":false,"folders":[],"items":[{"id":"public-item","type":2,"name":"Public fixture","notes":"Public note"}]}"#;
    let plan = import::prepare(
        Format::BitwardenZip,
        input,
        &options(),
        Limits::default(),
        &mut |_| true,
        wrapper,
    )
    .unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries.len(), 2);
    assert_eq!(
        record.entries[1].value["data"],
        Value::Binary(vec![0, 255, 0, 1])
    );
    assert_eq!(
        plan.container_attributes(MAX_OPEN_MEMORY).unwrap()["entries"],
        Value::Array(vec!["public-file.bin".into()])
    );
}

#[test]
#[ignore = "Run explicitly for real Bitwarden JSON parser budget calibration"]
fn ten_thousand_bitwarden_items_fit_the_default_plan_budget() {
    let mut input = String::from("{\"encrypted\":false,\"folders\":[],\"items\":[");
    for index in 0..10_000 {
        if index > 0 {
            input.push(',');
        }
        let fields: Vec<_>=(0..10).map(|field|json!({"name":format!("Field {field}"),"value":format!("PUBLIC-FIXTURE-{index}-{field}"),"type":0})).collect();
        let item = json!({"id":format!("public-item-{index}"),"type":2,"name":format!("Public fixture {index}"),"secureNote":{"type":0},"fields":fields});
        input.push_str(&serde_json::to_string(&item).unwrap());
    }
    input.push_str("]}");
    input.shrink_to_fit();
    let started = std::time::Instant::now();
    let plan = parse(input.as_bytes());
    assert_eq!(plan.items.len(), 10_000);
    assert_eq!(plan.statistics.ready, 10_000);
    assert!(plan.statistics.encoded_bytes < Limits::default().plan_bytes);
    for index in [0, 9_999] {
        let record = plan.items[index].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(record.entries.len(), 10);
        assert_eq!(
            record.entries[9].value["text"].as_str(),
            Some(format!("PUBLIC-FIXTURE-{index}-9").as_str())
        );
    }
    eprintln!(
        "Bitwarden parser: {} items, {} input bytes, {} encoded plan bytes, {} ms",
        plan.items.len(),
        input.len(),
        plan.statistics.encoded_bytes,
        started.elapsed().as_millis()
    );
}
