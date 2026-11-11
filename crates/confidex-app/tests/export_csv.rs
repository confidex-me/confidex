use confidex_app::{
    export::{self, Code, Column, Consent, Csv, Source},
    import::formats::csv,
};
use confidex_vault::{
    record::{Record, Value},
    resources::MAX_OPEN_MEMORY,
};
#[path = "export_csv/proof.rs"]
mod proof;
use proof::{config, field, firefox_record, fixture, imported, login, mapping, plan, profile};

#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Requires pinned Bitwarden CSV sources and packages, Python, and Node"]
fn independent_readers_verify_each_profile_without_replaying_source_snapshots() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let shared = std::env::var_os("CONFIDEX_BITWARDEN_SOURCE").unwrap();
    let sources = std::env::var_os("CONFIDEX_CSV_READER_SOURCE").unwrap();
    for profile_id in ["chromium", "firefox", "apple-passwords"] {
        let mut record = login();
        record.extra.insert(
            "confidex.import.origin".into(),
            Value::Map(vec![("old-password".into(), "PUBLIC-OLD-REMOVED".into())]),
        );
        let (plan, _) = plan(vec![record], profile(profile_id), export::Limits::default());
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let mut child = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/export_fixtures/csv/reader.py"
            ))
            .arg(profile_id)
            .arg(&shared)
            .arg(&sources)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(artifact.bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
}

#[test]
fn portable_proof_preserves_all_delimiters_roles_and_current_values() {
    proof::run();
}

fn one(source: Source, heading: &str) -> Csv {
    Csv {
        profile: None,
        delimiter: b',',
        header: true,
        columns: vec![Column {
            heading: heading.into(),
            source,
        }],
    }
}
fn selected(index: usize, kind: &str, key: &str) -> Source {
    Source::Field {
        index,
        type_name: kind.into(),
        key: key.into(),
    }
}

#[test]
fn exact_csv_syntax_never_prefixes_formulas_or_normalizes_text() {
    let mut record = Record::default();
    record.entries.push(field(
        "same,\"x\"\r\n",
        "password/v1",
        "password",
        " =1+2,\"公開\"\r\n\r\n",
    ));
    let (plan, _) = plan(
        vec![record],
        one(selected(0, "password/v1", "password"), "same,\"x\"\r\n"),
        export::Limits::default(),
    );
    assert!(plan.issues().is_empty());
    let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    assert_eq!(
        artifact.bytes(),
        "\"same,\"\"x\"\"\r\n\"\r\n\" =1+2,\"\"公開\"\"\r\n\r\n\"\r\n".as_bytes()
    );
}
#[test]
fn repeated_headings_are_positional_but_repeated_bindings_are_invalid() {
    let config = config(b',', true);
    assert!(csv::Writer::new(config).is_ok());
    for source in [Source::Title, Source::Tags, selected(0, "text/v1", "text")] {
        let mut config = one(source, "a");
        let other = match &config.columns[0].source {
            Source::Title => Source::Title,
            Source::Tags => Source::Tags,
            Source::Field {
                index,
                type_name,
                key,
            } => selected(*index, type_name, key),
        };
        config.columns.push(Column {
            heading: "b".into(),
            source: other,
        });
        assert!(matches!(
            csv::Writer::new(config),
            Err(export::Error::InvalidOptions)
        ));
    }
    for config in [
        profile("unknown"),
        one(Source::Title, "bad\0header"),
        {
            let mut c = profile("chromium");
            c.header = false;
            c
        },
        {
            let mut c = profile("firefox");
            c.delimiter = b';';
            c
        },
    ] {
        assert!(matches!(
            csv::Writer::new(config),
            Err(export::Error::InvalidOptions)
        ));
    }
}
#[test]
fn missing_fields_wrong_types_missing_values_and_nul_cannot_be_overridden() {
    for source in [
        selected(99, "text/v1", "text"),
        selected(0, "password/v1", "password"),
        selected(0, "username/v1", "absent"),
    ] {
        let (plan, memory) = plan(
            vec![fixture()],
            one(source, "Repeated"),
            export::Limits::default(),
        );
        assert!(
            plan.issues()
                .iter()
                .any(|i| i.severity == export::Severity::Blocked)
        );
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
    let mut record = Record::default();
    record
        .entries
        .push(field("Public", "text/v1", "text", "bad\0value"));
    let (plan, _) = plan(
        vec![record],
        one(selected(0, "text/v1", "text"), "Public"),
        export::Limits::default(),
    );
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true).err(),
        Some(export::Error::Blocked)
    );
}
#[test]
fn explicit_selection_reports_names_order_protection_tags_extra_values_and_history() {
    let mut record = fixture();
    record.tags = vec!["旅行".into()];
    record
        .extra
        .insert("confidex.history".into(), "PUBLIC-OLD-REMOVED".into());
    record.entries[4].extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    record.entries[4]
        .value
        .insert("extra".into(), "not represented".into());
    let mut config = config(b',', true);
    config.columns[5].heading = "Changed label".into();
    config.columns.swap(1, 2);
    let (plan, _) = plan(vec![record], config, export::Limits::default());
    for code in [
        Code::FieldNames,
        Code::FieldOrder,
        Code::Protection,
        Code::Tags,
        Code::UnknownValue,
        Code::UnknownMetadata,
    ] {
        assert!(plan.issues().iter().any(|i| i.code == code), "{code:?}");
    }
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Losses)
    );
}
#[test]
fn every_profile_uses_the_shared_headers_and_keeps_current_login_values() {
    for p in [
        csv::Profile::Chromium,
        csv::Profile::Firefox,
        csv::Profile::ApplePasswords,
    ] {
        let (plan, _) = plan(vec![login()], profile(p.id()), export::Limits::default());
        assert!(
            plan.issues()
                .iter()
                .all(|i| i.severity != export::Severity::Blocked)
        );
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let header = csv::header(
            artifact.bytes(),
            b',',
            confidex_app::import::Limits::default(),
            &mut |_| true,
        )
        .unwrap();
        assert_eq!(header.profiles(), [p]);
        let actual = imported(artifact.bytes(), p.mapping(&header).unwrap());
        let record = actual.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert!(
            record
                .entries
                .iter()
                .any(|e| e.value.get("password").and_then(Value::as_str) == Some("PUBLIC-CURRENT"))
        );
        if p == csv::Profile::ApplePasswords {
            assert_eq!(
                record.entries.last().unwrap().value,
                login().entries.last().unwrap().value
            );
        }
    }
}
#[test]
fn quote_chunk_boundaries_keep_multibyte_characters_crlf_and_quotes() {
    let value = "a".repeat(65_535) + "\"公開\r\n\"";
    let mut record = Record::default();
    record
        .entries
        .push(field("Boundary", "text/v1", "text", &value));
    let config = one(selected(0, "text/v1", "text"), "Boundary");
    let map = mapping(&config);
    let (plan, _) = plan(vec![record], config, export::Limits::default());
    let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    let actual = imported(artifact.bytes(), map);
    assert_eq!(
        actual.items[0].record(MAX_OPEN_MEMORY).unwrap().entries[0].value["text"].as_str(),
        Some(value.as_str())
    );
}

#[test]
fn tags_are_visible_json_but_never_claimed_as_csv_tag_semantics() {
    let mut record = Record::default();
    record.tags = vec!["a,\"b\"".into(), "旅行".into()];
    let config = one(Source::Tags, "Tags");
    let map = mapping(&config);
    let (plan, _) = plan(vec![record], config, export::Limits::default());
    assert_eq!(
        plan.issues().iter().map(|i| i.code).collect::<Vec<_>>(),
        [Code::Tags]
    );
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let result = imported(artifact.bytes(), map);
    let actual = result.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert!(actual.tags.is_empty());
    let value = actual.entries[0].value["secret"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<String>>(value).unwrap(),
        ["a,\"b\"", "旅行"]
    );
}

#[test]
fn profiles_report_extra_urls_files_and_hidden_text_before_writing() {
    let mut record = login();
    record
        .entries
        .push(field("Second", "url/v1", "url", "https://second.invalid/"));
    record.entries.push(confidex_vault::record::Entry {
        name: "File".into(),
        type_name: "file/v1".into(),
        value: [
            ("filename".into(), "public.bin".into()),
            ("data".into(), Value::Binary(vec![0, 255, 7])),
        ]
        .into(),
        extra: Default::default(),
    });
    let (plan, _) = plan(vec![record], profile("chromium"), export::Limits::default());
    for code in [
        Code::MultipleUrls,
        Code::Attachments,
        Code::TotpParameters,
        Code::Protection,
    ] {
        assert!(plan.issues().iter().any(|i| i.code == code));
    }
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Losses)
    );
}

#[test]
fn otp_edits_are_exported_and_old_source_parameters_are_not_replayed() {
    let mut record = fixture();
    let otp = record.entries.last_mut().unwrap();
    otp.value
        .insert("secret".into(), Value::Binary(b"f".to_vec()));
    otp.value.insert("digits".into(), 6u64.into());
    let config = config(b',', true);
    let map = mapping(&config);
    let (plan, _) = plan(vec![record], config, export::Limits::default());
    assert!(plan.issues().iter().any(|i| i.code == Code::SourceContext));
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let text = std::str::from_utf8(artifact.bytes()).unwrap();
    assert!(!text.contains("MZXW6YTBOI"));
    assert!(text.contains("secret=MY&algorithm=SHA256&digits=6&period=45"));
    let actual = imported(artifact.bytes(), map).items[0]
        .record(MAX_OPEN_MEMORY)
        .unwrap();
    assert_eq!(
        actual.entries.last().unwrap().value["secret"].as_slice(),
        Some(&b"f"[..])
    );
    assert_eq!(
        actual.entries.last().unwrap().value["digits"].as_u64(),
        Some(6)
    );
}

#[test]
fn verified_firefox_columns_keep_current_metadata_values_and_nullable_empties() {
    for changed in [false, true] {
        let mut record = firefox_record();
        record.entries[2]
            .value
            .insert("password".into(), "PUBLIC-CURRENT".into());
        if changed {
            record.entries[3]
                .value
                .insert("secret".into(), "PUBLIC-EDITED-REALM".into());
        }
        record.entries[5]
            .value
            .insert("secret".into(), "{current-guid}".into());
        record.entries.swap(0, 8);
        let (plan, _) = plan(vec![record], profile("firefox"), export::Limits::default());
        assert!(
            plan.issues()
                .iter()
                .all(|i| i.severity != export::Severity::Blocked)
        );
        assert!(plan.issues().iter().any(|i| i.code == Code::FieldOrder));
        assert!(plan.issues().iter().any(|i| i.code == Code::Protection));
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let text = std::str::from_utf8(artifact.bytes()).unwrap();
        assert!(!text.contains("PUBLIC-OLD-REMOVED"));
        if changed {
            assert!(text.contains("\"PUBLIC-EDITED-REALM\",\"\",\"{current-guid}\""));
        } else {
            assert!(text.contains("\"PUBLIC-CURRENT\",,\"\",\"{current-guid}\""));
        }
        let header = csv::header(
            artifact.bytes(),
            b',',
            confidex_app::import::Limits::default(),
            &mut |_| true,
        )
        .unwrap();
        let roundtrip = imported(
            artifact.bytes(),
            csv::Profile::Firefox.mapping(&header).unwrap(),
        );
        let actual = roundtrip.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(actual.entries.len(), 9);
        assert_eq!(
            actual.entries[3].value["secret"].as_str(),
            Some(if changed { "PUBLIC-EDITED-REALM" } else { "" })
        );
        assert_eq!(
            actual.entries[5].value["secret"].as_str(),
            Some("{current-guid}")
        );
        assert_eq!(
            actual.entries[6].value["secret"].as_str(),
            Some("1735689600000")
        );
        assert_eq!(
            actual.entries[8].value["secret"].as_str(),
            Some("1735689602000")
        );
    }
}

#[test]
fn duplicate_source_columns_or_changed_types_cannot_bind_active_profile_roles() {
    for duplicate in [false, true] {
        let mut record = firefox_record();
        if duplicate {
            let mut field = field("Local", "secret/v1", "secret", "PUBLIC-OTHER");
            field
                .extra
                .insert("confidex.import.csv.column".into(), 3u64.into());
            record.entries.push(field);
        } else {
            record.entries[1].type_name = "text/v1".into();
        }
        let (plan, _) = plan(vec![record], profile("firefox"), export::Limits::default());
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
    }
}

#[test]
fn editable_secret_names_do_not_become_firefox_realms_ids_or_times() {
    let mut record = login();
    for name in ["httpRealm", "formActionOrigin", "guid", "timeCreated"] {
        record
            .entries
            .push(field(name, "secret/v1", "secret", "PUBLIC-NOT-A-POLICY"));
    }
    let (plan, _) = plan(vec![record], profile("firefox"), export::Limits::default());
    assert!(
        plan.issues()
            .iter()
            .any(|i| i.code == Code::UnsupportedField)
    );
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert!(
        !std::str::from_utf8(artifact.bytes())
            .unwrap()
            .contains("PUBLIC-NOT-A-POLICY")
    );
}
