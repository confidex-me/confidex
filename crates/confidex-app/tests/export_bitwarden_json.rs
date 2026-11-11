use confidex_app::{
    export::{self, Code, Consent, Error, Limits, Records},
    import::{
        self, Format, Options, Status,
        formats::bitwarden_json::{self, Profile, Writer},
    },
};
use confidex_vault::{
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
};
use serde_json::{Value as Json, json};
#[path = "export_bitwarden_json/proof.rs"]
mod proof;

#[test]
fn browser_proof_matches_the_portable_writer() {
    proof::run();
}

fn field(name: &str, kind: &str, key: &str, value: &str) -> Entry {
    Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), value.into())]),
        extra: Mapping::new(),
    }
}
fn plan(records: Vec<Record>, profile: Profile) -> export::Plan {
    let mut snapshot = Records::new(Limits::default()).unwrap();
    for record in records {
        snapshot.push(record).unwrap();
    }
    export::prepare(snapshot, Box::new(Writer::new(profile)), &mut |_| true).unwrap()
}
fn import(bytes: &[u8]) -> import::Plan {
    let mut options = Options::default();
    options.source_instance = Some("public-export-check".into());
    import::prepare(
        Format::BitwardenJson,
        bytes,
        &options,
        import::Limits::default(),
        &mut |_| true,
        bitwarden_json::parse,
    )
    .unwrap()
}
fn custom() -> Record {
    Record {
        entries: vec![
            field("", "text/v1", "text", ""),
            field("Same", "text/v1", "text", "line one\n\"line two\"\\公開"),
            field("Same", "secret/v1", "secret", "PUBLIC-HIDDEN"),
        ],
        tags: vec![],
        extra: Mapping::from([("confidex.title".into(), "Public test".into())]),
    }
}
#[test]
fn ordered_custom_fields_keep_empty_repeated_names_and_hidden_values() {
    let plan = plan(vec![custom()], Profile::Personal);
    assert!(plan.issues().is_empty());
    let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    assert!(!artifact.file.encrypted);
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(
        output,
        json!({"encrypted":false,"folders":[],"items":[{
            "type":2,"name":"Public test","favorite":false,"reprompt":0,"secureNote":{"type":0},
            "fields":[{"name":"","value":"","type":0},{"name":"Same","value":"line one\n\"line two\"\\公開","type":0},{"name":"Same","value":"PUBLIC-HIDDEN","type":1}]
        }]})
    );
    let imported = import(artifact.bytes());
    assert_eq!(imported.items[0].status, Status::Ready);
    let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    for (a, b) in record.entries.iter().zip(&custom().entries) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.type_name, b.type_name);
        assert_eq!(a.value, b.value);
    }
    assert_eq!(record.entries.len(), 3);
}
#[test]
fn boolean_fields_keep_their_kind_only_while_the_current_value_is_boolean() {
    let mut record = custom();
    let mut boolean = field("Checkbox", "text/v1", "text", "false");
    boolean.extra.insert(
        "confidex.import.field".into(),
        Value::Map(vec![
            ("type".into(), 2u64.into()),
            ("linkedId".into(), Value::Nil),
        ]),
    );
    record.entries.push(boolean);
    let exported = plan(vec![record], Profile::Personal);
    assert!(exported.issues().is_empty());
    let artifact = exported.write(Consent::Lossless, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(
        output["items"][0]["fields"][3],
        json!({"name":"Checkbox","value":"false","type":2,"linkedId":null})
    );
    let imported = import(artifact.bytes());
    let mut record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    record.entries[3]
        .value
        .insert("text".into(), "current text".into());
    let exported = plan(vec![record], Profile::Personal);
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field == Some(3) && issue.code == Code::SourceContext)
    );
    let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(output["items"][0]["fields"][3]["value"], "current text");
    assert_eq!(output["items"][0]["fields"][3]["type"], 0);
}
fn login() -> Record {
    Record {
        entries: vec![
            field("Username", "username/v1", "username", "public-user"),
            field(
                "Password",
                "password/v1",
                "password",
                "PUBLIC-CURRENT-PASSWORD",
            ),
            field("URL", "url/v1", "url", "https://one.invalid/"),
            field("URL", "url/v1", "url", "https://two.invalid/path?q=1&v=2"),
        ],
        tags: vec![],
        extra: Mapping::from([("confidex.title".into(), "Current title".into())]),
    }
}
#[test]
fn current_values_override_source_metadata_and_deleted_values_do_not_return() {
    let mut record = login();
    record.extra.insert(
        "confidex.import.origin".into(),
        Value::Map(vec![(
            "attributes".into(),
            Value::Map(vec![("password".into(), "PUBLIC-STALE-PASSWORD".into())]),
        )]),
    );
    let plan = plan(vec![record], Profile::Personal);
    assert_eq!(plan.issues().len(), 1);
    assert_eq!(plan.issues()[0].code, Code::SourceContext);
    assert_eq!(plan.check_consent(Consent::Lossless), Err(Error::Losses));
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert!(
        !std::str::from_utf8(artifact.bytes())
            .unwrap()
            .contains("STALE")
    );
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(
        output["items"][0]["login"]["password"],
        "PUBLIC-CURRENT-PASSWORD"
    );
    assert_eq!(
        output["items"][0]["login"]["uris"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let mut deleted = login();
    deleted.entries.remove(1);
    deleted.extra.insert(
        "confidex.import.origin".into(),
        "PUBLIC-STALE-PASSWORD".into(),
    );
    let artifact = plan_for_deleted(deleted);
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert!(output["items"][0]["login"].get("password").is_none());
}
fn plan_for_deleted(record: Record) -> export::Artifact {
    plan(vec![record], Profile::Personal)
        .write(Consent::AllowLosses, &mut |_| true)
        .unwrap()
}
#[test]
fn canonical_login_and_multiple_uris_roundtrip_without_loss() {
    let source = login();
    let plan = plan(vec![source], Profile::Personal);
    assert!(plan.issues().is_empty());
    let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    let imported = import(artifact.bytes());
    let actual = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(actual.entries.len(), 4);
    for (a, b) in actual.entries.iter().zip(&login().entries) {
        assert_eq!(a.type_name, b.type_name);
        assert_eq!(a.name, b.name);
        assert_eq!(a.value, b.value);
    }
}

#[test]
fn url_labels_are_reported_before_the_uri_schema_discards_them() {
    let mut record = login();
    record.entries[2].name = "First link".into();
    record.entries[3].name = "Second link".into();
    let review = plan(vec![record], Profile::Personal);
    assert_eq!(
        review
            .issues()
            .iter()
            .map(|i| (i.field, i.code))
            .collect::<Vec<_>>(),
        [(Some(2), Code::FieldNames), (Some(3), Code::FieldNames)]
    );
    assert_eq!(
        review.write(Consent::Lossless, &mut |_| true).err(),
        Some(Error::Losses)
    );
}
fn source_policy(format: &str, attributes: Vec<(&str, Value)>) -> Value {
    Value::Map(vec![
        ("version".into(), 1u64.into()),
        ("format".into(), format.into()),
        (
            "attributes".into(),
            Value::Map(
                attributes
                    .into_iter()
                    .map(|(key, value)| (key.into(), value))
                    .collect(),
            ),
        ),
    ])
}
fn uri_policy(uri: &str, policy: u64) -> Value {
    Value::Map(vec![
        ("uri".into(), uri.into()),
        ("match".into(), policy.into()),
    ])
}
#[test]
fn source_policies_are_reconciled_without_replaying_old_credentials_or_urls() {
    let mut record = login();
    record.extra.insert(
        "confidex.import.origin".into(),
        source_policy(
            "bitwarden-json",
            vec![
                ("favorite", true.into()),
                ("reprompt", 1u64.into()),
                (
                    "login.uris",
                    Value::Array(vec![
                        uri_policy("https://one.invalid/", 5),
                        uri_policy("https://two.invalid/path?q=1&v=2", 3),
                    ]),
                ),
                ("login.password", "PUBLIC-STALE-PASSWORD".into()),
            ],
        ),
    );
    let exported = plan(vec![record], Profile::Personal);
    assert_eq!(exported.issues().len(), 1);
    assert_eq!(exported.issues()[0].code, Code::SourceContext);
    let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(output["items"][0]["favorite"], true);
    assert_eq!(output["items"][0]["reprompt"], 1);
    assert_eq!(output["items"][0]["login"]["uris"][0]["match"], 5);
    assert_eq!(output["items"][0]["login"]["uris"][1]["match"], 3);
    assert!(
        !std::str::from_utf8(artifact.bytes())
            .unwrap()
            .contains("STALE")
    );
    for (current, source) in [
        (
            "https://changed.invalid/",
            vec![uri_policy("https://one.invalid/", 5)],
        ),
        (
            "https://one.invalid/",
            vec![
                uri_policy("https://one.invalid/", 5),
                uri_policy("https://one.invalid/", 3),
            ],
        ),
    ] {
        let mut record = login();
        record.entries[2].value.insert("url".into(), current.into());
        record.extra.insert(
            "confidex.import.origin".into(),
            source_policy("bitwarden-json", vec![("login.uris", Value::Array(source))]),
        );
        let exported = plan(vec![record], Profile::Personal);
        assert!(
            exported
                .issues()
                .iter()
                .any(|issue| issue.field == Some(2) && issue.code == Code::Protection)
        );
        let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
        assert_eq!(
            output["items"][0]["login"]["uris"][0],
            json!({"uri":current,"match":null})
        );
    }
}
#[test]
fn unknown_source_policy_and_foreign_metadata_are_not_silently_applied() {
    let mut record = login();
    record.extra.insert(
        "confidex.import.origin".into(),
        source_policy(
            "bitwarden-json",
            vec![
                ("reprompt", 99u64.into()),
                ("login.uris", "future representation".into()),
            ],
        ),
    );
    let exported = plan(vec![record], Profile::Personal);
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field.is_none() && issue.code == Code::Protection)
    );
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field == Some(2) && issue.code == Code::Protection)
    );
    let mut record = login();
    record.extra.insert(
        "confidex.import.origin".into(),
        source_policy(
            "onepassword1pux",
            vec![("favorite", true.into()), ("reprompt", 1u64.into())],
        ),
    );
    let artifact = plan(vec![record], Profile::Personal)
        .write(Consent::AllowLosses, &mut |_| true)
        .unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(output["items"][0]["favorite"], false);
    assert_eq!(output["items"][0]["reprompt"], 0);
}
#[test]
fn reader_normalization_is_reported_and_blank_notes_remain_custom_values() {
    for name in ["", " \t\n", "\u{feff}\u{a0}"] {
        let mut record = custom();
        record.extra.insert("confidex.title".into(), name.into());
        let exported = plan(vec![record], Profile::Personal);
        assert!(
            exported
                .issues()
                .iter()
                .any(|issue| issue.field.is_none() && issue.code == Code::UnknownValue)
        );
    }
    let mut record = custom();
    record
        .extra
        .insert("confidex.title".into(), "\u{85}".into());
    assert!(plan(vec![record], Profile::Personal).issues().is_empty());
    for value in ["", " \n", "\u{feff}"] {
        let mut record = Record::default();
        record
            .entries
            .push(field("Notes", "secure-note/v1", "text", value));
        let exported = plan(vec![record], Profile::Personal);
        assert!(
            exported
                .issues()
                .iter()
                .any(|issue| issue.field == Some(0) && issue.code == Code::UnsupportedField)
        );
        let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
        assert!(output["items"][0].get("notes").is_none());
        assert_eq!(
            output["items"][0]["fields"][0],
            json!({"name":"Notes","value":value,"type":1})
        );
    }
}
#[test]
fn card_and_identity_bindings_keep_current_components_and_do_not_restore_deleted_values() {
    let source = import(include_bytes!(
        "export_fixtures/bitwarden_json/card-identity.input.json"
    ));
    let card = source.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let mut identity = source.items[1].record(MAX_OPEN_MEMORY).unwrap();
    identity
        .entries
        .iter_mut()
        .find(|field| field.name == "Email")
        .unwrap()
        .value
        .insert("text".into(), "current@example.invalid".into());
    identity
        .entries
        .retain(|field| field.name != "Passport number");
    identity.extra.insert(
        "confidex.import.origin".into(),
        "PUBLIC-OLD-ID old@example.invalid".into(),
    );
    let exported = plan(vec![card, identity], Profile::Personal);
    assert_eq!(exported.issues().len(), 1);
    assert_eq!(exported.issues()[0].code, Code::SourceContext);
    let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(output["items"][0]["type"], 3);
    assert_eq!(
        output["items"][0]["card"],
        json!({"cardholderName":"Public Holder","brand":"Visa","number":"4111111111111111","expMonth":"04","expYear":"2030","code":"123"})
    );
    assert_eq!(output["items"][1]["type"], 4);
    assert_eq!(
        output["items"][1]["identity"],
        json!({"firstName":"Public","lastName":"Example","email":"current@example.invalid","phone":""})
    );
    let text = std::str::from_utf8(artifact.bytes()).unwrap();
    assert!(!text.contains("PUBLIC-OLD-ID"));
    assert!(!text.contains("old@example.invalid"));
    let roundtrip = import(artifact.bytes());
    assert_eq!(
        roundtrip.items[0]
            .record(MAX_OPEN_MEMORY)
            .unwrap()
            .entries
            .len(),
        6
    );
    assert_eq!(
        roundtrip.items[1]
            .record(MAX_OPEN_MEMORY)
            .unwrap()
            .entries
            .len(),
        4
    );
}
#[test]
fn repeated_personal_slots_are_custom_fields_and_protection_or_name_changes_are_reported() {
    let source = import(include_bytes!(
        "export_fixtures/bitwarden_json/card-identity.input.json"
    ));
    let mut card = source.items[0].record(MAX_OPEN_MEMORY).unwrap();
    card.entries[0].name = "Renamed cardholder".into();
    card.entries[0].extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    let mut repeated = field(
        "Another card number",
        "secret/v1",
        "secret",
        "PUBLIC-SECOND-NUMBER",
    );
    repeated.extra.insert(
        "confidex.import.field".into(),
        Value::Map(vec![
            ("group".into(), "card".into()),
            ("slot".into(), "number".into()),
        ]),
    );
    card.entries.push(repeated);
    let exported = plan(vec![card], Profile::Personal);
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field == Some(0) && issue.code == Code::FieldNames)
    );
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field == Some(0) && issue.code == Code::Protection)
    );
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field == Some(6) && issue.code == Code::SourceContext)
    );
    let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(output["items"][0]["card"]["number"], "4111111111111111");
    assert_eq!(
        output["items"][0]["fields"][0],
        json!({"name":"Another card number","value":"PUBLIC-SECOND-NUMBER","type":1})
    );
}
#[test]
fn changed_field_types_do_not_keep_their_old_native_role() {
    let source = import(include_bytes!(
        "export_fixtures/bitwarden_json/card-identity.input.json"
    ));
    let mut card = source.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let number = &mut card.entries[2];
    number.type_name = "text/v1".into();
    number.value = Mapping::from([("text".into(), "Current plain text".into())]);
    number.extra.remove("metadata");
    let exported = plan(vec![card], Profile::Personal);
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field == Some(2) && issue.code == Code::SourceContext)
    );
    let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert!(output["items"][0]["card"].get("number").is_none());
    assert_eq!(
        output["items"][0]["fields"][0],
        json!({"name":"Card number","value":"Current plain text","type":0})
    );
}
#[test]
fn every_identity_component_keeps_its_own_slot() {
    let identity = json!({"title":"Ms","firstName":"Public","middleName":"Middle","lastName":"Example","address1":"One","address2":"Two","address3":"Three","city":"City","state":"State","postalCode":"00000","country":"XX","company":"Company","email":"public@example.invalid","phone":"","ssn":"PUBLIC-SSN","username":"public-user","passportNumber":"PUBLIC-PASSPORT","licenseNumber":"PUBLIC-LICENSE"});
    let source = import(serde_json::to_string(&json!({"encrypted":false,"folders":[],"items":[{"type":4,"name":"Identity","identity":identity}]})).unwrap().as_bytes());
    let record = source.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries.len(), 18);
    let exported = plan(vec![record], Profile::Personal);
    assert!(exported.issues().is_empty());
    let artifact = exported.write(Consent::Lossless, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(output["items"][0]["identity"], identity);
}
fn ssh_record() -> Record {
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
        "public SSH fixture",
    )
    .unwrap();
    Record {
        entries: vec![Entry {
            name: "SSH key".into(),
            type_name: "ssh/v1".into(),
            value: Mapping::from([(
                "private_key".into(),
                Value::Binary(key.to_bytes().unwrap().to_vec()),
            )]),
            extra: Mapping::new(),
        }],
        tags: vec![],
        extra: Mapping::from([("confidex.title".into(), "Public SSH".into())]),
    }
}
#[test]
fn native_ssh_keeps_a_valid_private_key_public_key_and_fingerprint() {
    let source = ssh_record();
    let exported = plan(vec![ssh_record()], Profile::Personal);
    assert!(exported.issues().is_empty());
    let artifact = exported.write(Consent::Lossless, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert_eq!(output["items"][0]["type"], 5);
    let ssh = &output["items"][0]["sshKey"];
    let key = ssh_key::PrivateKey::from_openssh(ssh["privateKey"].as_str().unwrap()).unwrap();
    assert_eq!(
        key.public_key().to_openssh().unwrap(),
        ssh["publicKey"].as_str().unwrap()
    );
    assert_eq!(
        key.public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        ssh["keyFingerprint"].as_str().unwrap()
    );
    let imported = import(artifact.bytes());
    let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries[0].value, source.entries[0].value);
}
#[test]
fn ssh_decode_requires_shared_memory_and_invalid_keys_cannot_publish() {
    for limited in [false, true] {
        let limits = Limits {
            records: 1,
            issues: 1,
            memory_bytes: if limited {
                8 << 20
            } else {
                Limits::default().memory_bytes
            },
            ..Limits::default()
        };
        let mut records = Records::new(limits).unwrap();
        let memory = records.memory().clone();
        let mut record = ssh_record();
        if !limited {
            record.entries[0]
                .value
                .insert("private_key".into(), Value::Binary(vec![1]));
        }
        records.push(record).unwrap();
        let prepared = export::prepare(
            records,
            Box::new(Writer::new(Profile::Personal)),
            &mut |_| true,
        );
        if limited {
            assert!(matches!(prepared, Err(Error::Limit)));
        } else {
            let exported = prepared.unwrap();
            assert_eq!(
                exported.check_consent(Consent::AllowLosses),
                Err(Error::Blocked)
            );
            assert!(matches!(
                exported.write(Consent::AllowLosses, &mut |_| panic!(
                    "Blocked key must not write"
                )),
                Err(Error::Blocked)
            ));
        }
        assert_eq!(memory.available(), limits.memory_bytes);
    }
}
#[test]
fn review_reports_order_names_protection_unknown_values_and_attachments() {
    let mut record = custom();
    let mut username = field("Custom username", "username/v1", "username", "public-user");
    username.extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    username
        .value
        .insert("unknown".into(), "PUBLIC-EXTRA".into());
    record.entries.push(username);
    record.entries.push(Entry {
        name: "Public file".into(),
        type_name: "file/v1".into(),
        value: Mapping::from([("data".into(), Value::Binary(vec![1, 2, 3]))]),
        extra: Mapping::new(),
    });
    let plan = plan(vec![record], Profile::Personal);
    for code in [
        Code::FieldOrder,
        Code::FieldNames,
        Code::Protection,
        Code::UnknownValue,
        Code::Attachments,
    ] {
        assert!(
            plan.issues().iter().any(|issue| issue.code == code),
            "{code:?}"
        );
    }
    assert_eq!(plan.check_consent(Consent::Lossless), Err(Error::Losses));
    assert!(plan.issues().iter().filter(|i| i.field == Some(3)).count() >= 4);
}
#[test]
fn personal_and_organization_groups_use_distinct_schemas_and_deduplicate_names() {
    for profile in [Profile::Personal, Profile::Organization] {
        let mut first = custom();
        first.tags = vec!["Shared".into(), "Second".into()];
        let mut second = custom();
        second.tags = vec!["Shared".into()];
        let plan = plan(vec![first, second], profile);
        assert_eq!(
            plan.issues().iter().any(|i| i.code == Code::Tags),
            profile == Profile::Personal
        );
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
        let (key, absent, count) = if profile == Profile::Personal {
            ("folders", "collections", 1)
        } else {
            ("collections", "folders", 2)
        };
        assert!(output.get(absent).is_none());
        assert_eq!(output[key].as_array().unwrap().len(), count);
        let imported = import(artifact.bytes());
        let first = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
        let second = imported.items[1].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            first.tags,
            if profile == Profile::Personal {
                vec!["Shared"]
            } else {
                vec!["Second", "Shared"]
            }
        );
        assert_eq!(second.tags, ["Shared"]);
    }
}
fn otp(secret: &[u8], start: u64) -> Entry {
    Entry {
        name: "One-time code".into(),
        type_name: "totp/v1".into(),
        value: Mapping::from([
            ("secret".into(), Value::Binary(secret.to_vec())),
            ("algorithm".into(), "SHA256".into()),
            ("digits".into(), 8u64.into()),
            ("period".into(), 45u64.into()),
            ("t0".into(), start.into()),
        ]),
        extra: Mapping::new(),
    }
}
#[test]
fn totp_uses_current_parameters_and_rfc4648_base32_without_silent_start_change() {
    for (secret, encoded) in [
        (&b"f"[..], "MY"),
        (b"fo", "MZXQ"),
        (b"foo", "MZXW6"),
        (b"foob", "MZXW6YQ"),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI"),
    ] {
        let record = Record {
            entries: vec![otp(secret, 0)],
            tags: vec![],
            extra: Mapping::new(),
        };
        let plan = plan(vec![record], Profile::Personal);
        assert!(plan.issues().is_empty());
        let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
        let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
        assert_eq!(
            output["items"][0]["login"]["totp"],
            format!("otpauth://totp/Confidex?secret={encoded}&algorithm=SHA256&digits=8&period=45")
        );
        let imported = import(artifact.bytes());
        let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(record.entries[0].value, otp(secret, 0).value);
    }
    let record = Record {
        entries: vec![otp(b"PUBLIC", 7)],
        tags: vec![],
        extra: Mapping::new(),
    };
    let plan = plan(vec![record], Profile::Personal);
    assert_eq!(plan.issues()[0].code, Code::TotpParameters);
    assert_eq!(plan.check_consent(Consent::Lossless), Err(Error::Losses));
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert!(output["items"][0]["login"].get("totp").is_none());
}
#[test]
fn additional_totp_keeps_its_current_seed_and_parameters_in_a_hidden_custom_field() {
    let first = otp(b"f", 0);
    let mut second = otp(b"foobar", 0);
    second.name = "Backup code".into();
    let record = Record {
        entries: vec![first, second],
        tags: vec![],
        extra: Mapping::new(),
    };
    let exported = plan(vec![record], Profile::Personal);
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.field == Some(1) && issue.code == Code::UnsupportedField)
    );
    let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    let field = &output["items"][0]["fields"][0];
    assert_eq!(field["name"], "Backup code");
    assert_eq!(field["type"], 1);
    let current = import::totp::entry(field["value"].as_str().unwrap()).unwrap();
    assert_eq!(current.value, otp(b"foobar", 0).value);
}
#[test]
fn totp_provenance_is_reused_only_when_it_matches_current_parameters() {
    for raw in [
        "otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45",
        "MZXW6YTBOI======",
    ] {
        let entry = import::totp::entry(raw).unwrap();
        let mut record = Record::default();
        record.entries.push(entry);
        let exported = plan(vec![record], Profile::Personal);
        assert!(exported.issues().is_empty());
        let artifact = exported.write(Consent::Lossless, &mut |_| true).unwrap();
        let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
        assert_eq!(output["items"][0]["login"]["totp"], raw);
        let mut entry = import::totp::entry(raw).unwrap();
        entry
            .value
            .insert("secret".into(), Value::Binary(b"f".to_vec()));
        let mut record = Record::default();
        record.entries.push(entry);
        let exported = plan(vec![record], Profile::Personal);
        assert!(
            exported
                .issues()
                .iter()
                .any(|issue| issue.field == Some(0) && issue.code == Code::SourceContext)
        );
        let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
        assert!(
            output["items"][0]["login"]["totp"]
                .as_str()
                .unwrap()
                .contains("secret=MY&")
        );
        assert!(
            !std::str::from_utf8(artifact.bytes())
                .unwrap()
                .contains("MZXW6YTBOI")
        );
    }
    let mut entry = import::totp::entry("MZXW6YTBOI======").unwrap();
    entry.value.insert("digits".into(), 8u64.into());
    let mut record = Record::default();
    record.entries.push(entry);
    let exported = plan(vec![record], Profile::Personal);
    assert!(
        exported
            .issues()
            .iter()
            .any(|issue| issue.code == Code::SourceContext)
    );
    let artifact = exported.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
    assert!(
        output["items"][0]["login"]["totp"]
            .as_str()
            .unwrap()
            .contains("&digits=8&")
    );
}
#[test]
fn totp_source_parsing_is_charged_to_the_shared_review_budget() {
    let limits = Limits {
        records: 1,
        issues: 1,
        memory_bytes: 5 << 20,
        ..Limits::default()
    };
    let mut records = Records::new(limits).unwrap();
    let memory = records.memory().clone();
    let mut entry = otp(b"foobar", 0);
    let raw = format!("otpauth://totp/{}?secret=MZXW6YTBOI", "a".repeat(512 << 10));
    entry.extra.insert(
        "confidex.import.totp".into(),
        Value::Map(vec![("uri".into(), raw.into())]),
    );
    let mut record = Record::default();
    record.entries.push(entry);
    records.push(record).unwrap();
    assert!(matches!(
        export::prepare(
            records,
            Box::new(Writer::new(Profile::Personal)),
            &mut |_| true
        ),
        Err(Error::Limit)
    ));
    assert_eq!(memory.available(), limits.memory_bytes);
}
#[test]
fn output_limits_and_cancellation_leave_no_artifact() {
    let mut records = Records::new(Limits {
        output_bytes: 32,
        ..Limits::default()
    })
    .unwrap();
    records.push(custom()).unwrap();
    let limited = export::prepare(
        records,
        Box::new(Writer::new(Profile::Personal)),
        &mut |_| true,
    )
    .unwrap();
    assert!(matches!(
        limited.write(Consent::Lossless, &mut |_| true),
        Err(Error::Limit)
    ));
    let plan = plan(
        vec![Record {
            entries: vec![otp(&[7; 128], 0)],
            tags: vec![],
            extra: Mapping::new(),
        }],
        Profile::Organization,
    );
    let mut checkpoints = 0;
    assert!(matches!(
        plan.write(Consent::Lossless, &mut |_| {
            checkpoints += 1;
            checkpoints < 100
        }),
        Err(Error::Canceled)
    ));
    assert_eq!(checkpoints, 100);
}
#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Needs pinned upstream source files in CONFIDEX_BITWARDEN_SOURCE"]
fn pinned_independent_reader_opens_actual_writer_output() {
    let source =
        std::env::var_os("CONFIDEX_BITWARDEN_SOURCE").expect("Set CONFIDEX_BITWARDEN_SOURCE");
    let directory = tempfile::tempdir().unwrap();
    for profile in [Profile::Personal, Profile::Organization] {
        let mut auth = login();
        auth.tags = vec!["Shared".into(), "Second".into()];
        auth.extra.insert(
            "confidex.import.origin".into(),
            source_policy(
                "bitwarden-json",
                vec![
                    ("favorite", true.into()),
                    ("reprompt", 1u64.into()),
                    (
                        "login.uris",
                        Value::Array(vec![
                            uri_policy("https://one.invalid/", 5),
                            uri_policy("https://two.invalid/path?q=1&v=2", 3),
                        ]),
                    ),
                ],
            ),
        );
        auth.entries.push(otp(b"f", 0));
        auth.entries
            .push(field("Notes", "note/v1", "text", "Public notes"));
        let mut note = custom();
        note.tags = vec!["Shared".into()];
        let mut boolean = field("Checkbox", "text/v1", "text", "false");
        boolean.extra.insert(
            "confidex.import.field".into(),
            Value::Map(vec![
                ("type".into(), 2u64.into()),
                ("linkedId".into(), Value::Nil),
            ]),
        );
        note.entries.push(boolean);
        let source = import(include_bytes!(
            "export_fixtures/bitwarden_json/card-identity.input.json"
        ));
        let mut card = source.items[0].record(MAX_OPEN_MEMORY).unwrap();
        card.tags = vec!["Shared".into()];
        let mut identity = source.items[1].record(MAX_OPEN_MEMORY).unwrap();
        identity
            .entries
            .iter_mut()
            .find(|f| f.name == "Email")
            .unwrap()
            .value
            .insert("text".into(), "current@example.invalid".into());
        identity.entries.retain(|f| f.name != "Passport number");
        let mut blank_note = Record::default();
        blank_note
            .entries
            .push(field("Notes", "secure-note/v1", "text", "\u{feff}"));
        blank_note
            .extra
            .insert("confidex.title".into(), "Blank note".into());
        let mut blank_title = custom();
        blank_title
            .extra
            .insert("confidex.title".into(), "\u{feff} ".into());
        let artifact = plan(
            vec![
                auth,
                note,
                card,
                identity,
                blank_note,
                blank_title,
                ssh_record(),
            ],
            profile,
        )
        .write(Consent::AllowLosses, &mut |_| true)
        .unwrap();
        std::fs::write(directory.path().join(artifact.file.name), artifact.bytes()).unwrap();
    }
    let output = std::process::Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/export_fixtures/bitwarden_json/reader.cjs"
        ))
        .arg(source)
        .arg(directory.path().join("bitwarden-personal.json"))
        .arg(directory.path().join("bitwarden-organization.json"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
