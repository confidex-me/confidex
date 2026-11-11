#[path = "export_fixtures/keepass_common.rs"]
mod keepass_common;
use confidex_app::{
    export::{self, Consent},
    import::Status,
};
use confidex_vault::{
    record::{Record, Value},
    resources::MAX_OPEN_MEMORY,
};
#[path = "export_keepass_xml/proof.rs"]
mod proof;
use proof::common::field;
use proof::{fixture, imported, plan};

fn groups(record: &mut Record, instance: &str, ids: &[[u8; 16]], names: &[&str]) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    record.extra.insert(
        "confidex.import.origin".into(),
        Value::Map(vec![
            ("version".into(), 1u64.into()),
            ("format".into(), "keepass-xml".into()),
            (
                "source".into(),
                Value::Map(vec![("instance".into(), instance.into())]),
            ),
            (
                "attributes".into(),
                Value::Map(vec![
                    (
                        "group_path".into(),
                        Value::Array(names.iter().map(|s| (*s).into()).collect()),
                    ),
                    (
                        "group_ids".into(),
                        Value::Array(ids.iter().map(|id| STANDARD.encode(id).into()).collect()),
                    ),
                ]),
            ),
        ]),
    );
}
#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Requires KeePassXC CLI in CONFIDEX_KEEPASSXC_CLI"]
fn independent_keepassxc_reads_actual_xml_values_and_protection() {
    let cli = std::env::var_os("CONFIDEX_KEEPASSXC_CLI").unwrap();
    let consumer_fixture = || {
        let mut record = fixture();
        record.entries[9].value.insert(
            "data".into(),
            Value::Binary((0..6145).map(|n| n as u8).collect()),
        );
        record
            .entries
            .insert(9, field("\u{e000}", "text/v1", "text", "PUBLIC-BMP-KEY"));
        record
            .entries
            .insert(10, field("🙂", "text/v1", "text", "PUBLIC-ASTRAL-KEY"));
        record
    };
    let (plan, _) = plan(consumer_fixture(), export::Limits::default());
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(artifact.file.name);
    std::fs::write(&path, artifact.bytes()).unwrap();
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/export_fixtures/keepass_xml/reader.py"
        ))
        .arg(cli)
        .arg(&path)
        .output()
        .unwrap();
    let mut options = confidex_app::import::Options::default();
    options.password_present = true;
    options.password = "PUBLIC-XML-EXPORT-DATABASE".into();
    options.source_instance = Some("public-cli-database".into());
    let database = std::fs::read(path.with_extension("kdbx")).unwrap();
    let parsed = confidex_app::import::prepare(
        confidex_app::import::Format::Kdbx,
        &database,
        &options,
        confidex_app::import::Limits::default(),
        &mut |_| true,
        confidex_app::import::formats::kdbx::parse,
    )
    .unwrap();
    let actual = parsed.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(actual.tags, fixture().tags);
    for expected in &consumer_fixture().entries {
        let actual = actual
            .entries
            .iter()
            .find(|e| e.name == expected.name)
            .unwrap();
        let normalized = if expected.name == "Unicode <&>" {
            [("text".into(), "\tCR\nLF\n🙂".into())].into()
        } else {
            expected.value.clone()
        };
        assert_eq!(
            actual.value, normalized,
            "actual stored KDBX value differs at {}",
            expected.name
        );
    }
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn source_group_components_and_distinct_scopes_do_not_collapse() {
    use confidex_app::import::formats::keepass_xml::Writer;
    let mut records = export::Records::new(export::Limits::default()).unwrap();
    for (instance, child) in [("A", 2), ("A", 2), ("A", 3), ("B", 2), ("", 2), ("", 2)] {
        let mut record = Record::default();
        groups(
            &mut record,
            instance,
            &[[1; 16], [child; 16]],
            &["Source <&>", "Same"],
        );
        records.push(record).unwrap();
    }
    let plan = export::prepare(
        records,
        Box::new(Writer::new(1_735_689_600).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    assert!(
        plan.issues()
            .iter()
            .all(|i| matches!(i.code, export::Code::SourceContext | export::Code::Sections))
    );
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let imported = imported(artifact.bytes());
    assert_eq!(imported.items.len(), 6);
    let attributes: Vec<_> = imported
        .items
        .iter()
        .map(|item| item.source_attributes(MAX_OPEN_MEMORY).unwrap())
        .collect();
    for attribute in &attributes {
        assert_eq!(
            attribute["group_path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            ["Confidex", "Source <&>", "Same"]
        );
    }
    assert_eq!(attributes[0]["group_ids"], attributes[1]["group_ids"]);
    assert_ne!(attributes[1]["group_ids"], attributes[2]["group_ids"]);
    assert_ne!(attributes[2]["group_ids"], attributes[3]["group_ids"]);
    assert_ne!(attributes[4]["group_ids"], attributes[5]["group_ids"]);
}

#[test]
fn unsafe_source_otp_text_is_replaced_by_current_parameters() {
    let mut record = fixture();
    let raw =
        "otpauth://totp/{REF:P@T:other}?secret=MZXW6YTBOI&algorithm=SHA256&digits=8&period=45";
    record.entries[7].extra.insert(
        "confidex.import.totp".into(),
        Value::Map(vec![("uri".into(), raw.into())]),
    );
    let (plan, _) = plan(record, export::Limits::default());
    assert!(
        plan.issues()
            .iter()
            .any(|i| i.field == Some(7) && i.code == export::Code::SourceContext)
    );
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert!(
        !std::str::from_utf8(artifact.bytes())
            .unwrap()
            .contains("{REF:")
    );
    let imported = imported(artifact.bytes());
    let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries[7].value, fixture().entries[7].value);
}

#[test]
fn matching_otp_source_keeps_its_label_and_issuer_but_changed_values_win() {
    let raw = "otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45";
    for changed in [false, true] {
        let mut record = fixture();
        record.entries[7].extra.insert(
            "confidex.import.totp".into(),
            Value::Map(vec![("uri".into(), raw.into())]),
        );
        if changed {
            record.entries[7]
                .value
                .insert("period".into(), 60u64.into());
        }
        let (plan, _) = plan(record, export::Limits::default());
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let plan = imported(artifact.bytes());
        let current = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
        let entry = &current.entries[7];
        assert_eq!(
            entry.value["period"].as_u64(),
            Some(if changed { 60 } else { 45 })
        );
        let source = entry.extra["confidex.import.totp"].as_map().unwrap()[0]
            .1
            .as_str()
            .unwrap();
        assert_eq!(source == raw, !changed);
    }
}

#[test]
fn portable_worker_proof_preserves_values_and_stops_failed_output() {
    proof::run();
}

#[test]
fn conflicting_keys_cannot_be_overwritten_with_loss_consent() {
    for name in ["Title", "Password", "Empty", "CR\rkey"] {
        let mut record = fixture();
        record
            .entries
            .push(field(name, "text/v1", "text", "PUBLIC-SECOND"));
        let (plan, _) = plan(record, export::Limits::default());
        assert!(plan.issues().iter().any(|i| i.field == Some(11)
            && i.severity == export::Severity::Blocked
            && i.code == export::Code::FieldNames));
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
    }
}

#[test]
fn invalid_xml_and_executable_placeholders_are_blocked_before_writing() {
    for value in [
        "invalid\0text",
        "{REF:P@T:other}",
        "{USERNAME}",
        "a{ENV:HOME}",
    ] {
        let mut record = fixture();
        record.entries[4]
            .value
            .insert("secret".into(), value.into());
        let (plan, _) = plan(record, export::Limits::default());
        assert!(
            plan.issues()
                .iter()
                .any(|i| i.field == Some(4) && i.severity == export::Severity::Blocked)
        );
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
    }
    for name in [
        "otp",
        "TimeOtp-Secret-Base32",
        "TOTP Seed",
        "HmacOtp-Counter",
    ] {
        let mut record = Record::default();
        record
            .entries
            .push(field(name, "text/v1", "text", "PUBLIC"));
        let (plan, _) = plan(record, export::Limits::default());
        assert!(
            plan.issues()
                .iter()
                .any(|i| i.code == export::Code::TotpParameters
                    && i.severity == export::Severity::Blocked)
        );
    }
}

#[test]
fn names_and_additional_native_fields_get_exact_type_loss_review() {
    let mut record = Record::default();
    record.entries.extend([
        field("First", "url/v1", "url", "https://one.invalid/"),
        field("Second", "url/v1", "url", "https://two.invalid/"),
        field("Masked", "text/v1", "text", "PUBLIC-HIDDEN"),
    ]);
    record.entries[2].extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    let (plan, _) = plan(record, export::Limits::default());
    assert_eq!(
        plan.issues()
            .iter()
            .map(|i| (i.field, i.code))
            .collect::<Vec<_>>(),
        [
            (Some(0), export::Code::FieldNames),
            (None, export::Code::FieldOrder),
            (Some(1), export::Code::UnsupportedField),
            (Some(2), export::Code::UnsupportedField),
        ]
    );
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let imported = imported(artifact.bytes());
    let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        record
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.type_name.as_str()))
            .collect::<Vec<_>>(),
        [
            ("URL", "url/v1"),
            ("Second", "text/v1"),
            ("Masked", "secret/v1")
        ]
    );
    assert_eq!(
        record.entries[0].value["url"].as_str(),
        Some("https://one.invalid/")
    );
    assert_eq!(
        record.entries[1].value["text"].as_str(),
        Some("https://two.invalid/")
    );
    assert_eq!(
        record.entries[2].value["secret"].as_str(),
        Some("PUBLIC-HIDDEN")
    );
}

#[test]
fn tags_and_unknown_source_data_are_not_silently_exported() {
    let mut record = fixture();
    record
        .tags
        .extend(["cannot;join".into(), " trimmed ".into(), "CR\rtag".into()]);
    record.extra.insert(
        "confidex.import.origin".into(),
        Value::Map(vec![
            ("version".into(), 1u64.into()),
            ("format".into(), "keepass-xml".into()),
            (
                "attributes".into(),
                Value::Map(vec![("old_password".into(), "PUBLIC-OLD-REMOVED".into())]),
            ),
        ]),
    );
    record.entries.push(confidex_vault::record::Entry {
        name: "File".into(),
        type_name: "file/v1".into(),
        value: [
            ("filename".into(), "public.bin".into()),
            ("data".into(), Value::Binary(vec![0, 255])),
        ]
        .into(),
        extra: Default::default(),
    });
    record.entries[4].value.insert("future".into(), true.into());
    let (plan, _) = plan(record, export::Limits::default());
    for code in [
        export::Code::Tags,
        export::Code::SourceContext,
        export::Code::UnknownValue,
    ] {
        assert!(plan.issues().iter().any(|i| i.code == code));
    }
    assert!(
        plan.issues()
            .iter()
            .any(|i| i.field == Some(4) && i.code == export::Code::UnknownValue)
    );
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let text = std::str::from_utf8(artifact.bytes()).unwrap();
    assert!(!text.contains("PUBLIC-OLD-REMOVED"));
    let plan = imported(artifact.bytes());
    assert_ne!(plan.items[0].status, Status::Blocked);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.tags, ["CR\rtag", "Work", "旅行"]);
    assert_eq!(record.entries.len(), 12);
    assert_eq!(
        record.entries[11].value["data"].as_slice(),
        Some(&[0, 255][..])
    );
}

#[test]
fn attachment_names_have_their_own_key_space_and_protection_is_never_dropped() {
    for protected in [false, true] {
        let mut record = fixture();
        if protected {
            record.entries[9].extra.insert(
                "metadata".into(),
                Value::Map(vec![("protected".into(), true.into())]),
            );
        } else {
            record.entries[10]
                .value
                .insert("filename".into(), "sample.bin".into());
        }
        let (plan, _) = plan(record, export::Limits::default());
        assert!(
            plan.issues()
                .iter()
                .any(|i| i.severity == export::Severity::Blocked
                    && i.code
                        == if protected {
                            export::Code::Protection
                        } else {
                            export::Code::FieldNames
                        })
        );
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
    }
    let mut record = fixture();
    record.entries[9]
        .value
        .insert("filename".into(), "Password".into());
    let (plan, _) = plan(record, export::Limits::default());
    assert!(plan.issues().iter().any(|i| i.field == Some(9)
        && i.code == export::Code::FieldNames
        && i.severity == export::Severity::Loss));
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let imported = imported(artifact.bytes());
    let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries[9].name, "Password");
    assert_eq!(
        record.entries[9].value["data"].as_slice(),
        Some(&[0, 255, 7][..])
    );
    assert_eq!(
        record.entries[1].value["password"].as_str(),
        Some("PUBLIC-PASSWORD")
    );
}

#[test]
fn group_memory_is_admitted_before_building_the_tree() {
    let limits = export::Limits {
        records: 3,
        issues: 32,
        ..export::Limits::default()
    };
    let mut records = export::Records::new(limits).unwrap();
    let memory = records.memory().clone();
    let ids: Vec<_> = (1..=26).map(|n| [n; 16]).collect();
    for _ in 0..3 {
        let mut record = Record::default();
        groups(&mut record, "public", &ids, &vec!["Group"; 26]);
        records.push(record).unwrap();
    }
    let held = memory.available() - 8192;
    let pressure = memory.reserve(held).unwrap();
    let plan = export::prepare(
        records,
        Box::new(confidex_app::import::formats::keepass_xml::Writer::new(1_735_689_600).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    let mut callbacks = 0;
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| {
            callbacks += 1;
            true
        })
        .err(),
        Some(export::Error::Limit)
    );
    assert_eq!(callbacks, 1);
    assert_eq!(memory.available(), limits.memory_bytes - held);
    drop(pressure);
    assert_eq!(memory.available(), limits.memory_bytes);
}

#[test]
fn time_bounds_and_new_uuid_scopes_are_explicit() {
    assert!(matches!(
        confidex_app::import::formats::keepass_xml::Writer::new(253_402_300_800),
        Err(export::Error::InvalidOptions)
    ));
    let mut uuids = std::collections::BTreeSet::new();
    for _ in 0..2 {
        let (plan, _) = plan(fixture(), export::Limits::default());
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let plan = imported(artifact.bytes());
        assert!(uuids.insert(plan.items[0].source.item.clone().unwrap()));
    }
}

#[test]
fn group_traversal_keeps_each_records_binary_pool_bindings() {
    let mut records = export::Records::new(export::Limits::default()).unwrap();
    for index in 0..3 {
        let mut record = Record::default();
        record
            .extra
            .insert("confidex.title".into(), format!("Item{index}").into());
        groups(
            &mut record,
            "public",
            &[[1; 16], [if index == 1 { 3 } else { 2 }; 16]],
            &["Original", if index == 1 { "Right" } else { "Left" }],
        );
        record.entries.push(confidex_vault::record::Entry {
            name: "same.bin".into(),
            type_name: "file/v1".into(),
            value: [
                ("filename".into(), "same.bin".into()),
                ("data".into(), Value::Binary(vec![index])),
            ]
            .into(),
            extra: Default::default(),
        });
        records.push(record).unwrap();
    }
    let plan = export::prepare(
        records,
        Box::new(confidex_app::import::formats::keepass_xml::Writer::new(1_735_689_600).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let imported = imported(artifact.bytes());
    assert_eq!(imported.items.len(), 3);
    for (item, expected) in imported.items.iter().zip([0, 2, 1]) {
        let record = item.record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            record.extra["confidex.title"].as_str(),
            Some(format!("Item{expected}").as_str())
        );
        assert_eq!(
            record.entries[0].value["data"].as_slice(),
            Some(&[expected][..])
        );
    }
}

#[test]
fn all_record_fields_fit_alongside_the_separate_title() {
    let mut record = Record::default();
    let count = confidex_app::import::Limits::default().fields;
    for index in 0..count {
        record.entries.push(field(
            &format!("Field{index:03}"),
            "text/v1",
            "text",
            "PUBLIC",
        ));
    }
    let (plan, _) = plan(record, export::Limits::default());
    assert!(plan.issues().is_empty());
    let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    let imported = imported(artifact.bytes());
    assert_eq!(
        imported.items[0]
            .record(MAX_OPEN_MEMORY)
            .unwrap()
            .entries
            .len(),
        count
    );
}

#[test]
fn key_order_matches_the_consumers_utf16_order() {
    for (names, loss) in [(["🙂", "\u{e000}"], false), (["\u{e000}", "🙂"], true)] {
        let mut record = Record::default();
        for name in names {
            record
                .entries
                .push(field(name, "text/v1", "text", "PUBLIC"));
        }
        let (plan, _) = plan(record, export::Limits::default());
        assert_eq!(
            plan.issues()
                .iter()
                .any(|i| i.code == export::Code::FieldOrder),
            loss
        );
    }
}

#[test]
fn a_shared_source_root_does_not_gain_another_wrapper_on_each_export() {
    let mut record = Record::default();
    record
        .entries
        .push(field("Only", "text/v1", "text", "PUBLIC"));
    groups(
        &mut record,
        "public",
        &[[1; 16], [2; 16]],
        &["Root", "Child"],
    );
    for _ in 0..2 {
        let (plan, _) = plan(record, export::Limits::default());
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let imported = imported(artifact.bytes());
        let attributes = imported.items[0]
            .source_attributes(MAX_OPEN_MEMORY)
            .unwrap();
        assert_eq!(
            attributes["group_path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            ["Root", "Child"]
        );
        record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
        record.extra.insert(
            "confidex.import.origin".into(),
            Value::Map(vec![
                ("version".into(), 1u64.into()),
                ("format".into(), "keepass-xml".into()),
                (
                    "source".into(),
                    Value::Map(vec![("instance".into(), "public".into())]),
                ),
                (
                    "attributes".into(),
                    Value::Map(attributes.into_iter().map(|(k, v)| (k.into(), v)).collect()),
                ),
            ]),
        );
    }
}
