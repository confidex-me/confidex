use confidex_app::import::{
    self, Code, Error, Format, Limits, Options, Plan, Status, formats::onepassword_1pux,
};
use confidex_vault::{record::Value, resources::MAX_OPEN_MEMORY};
use serde_json::{Value as Json, json};
use std::io::Write;

#[path = "onepassword/templates.rs"]
mod templates;

const ATTRIBUTES: &[u8] =
    include_bytes!("import_fixtures/onepassword_1pux/export/export.attributes");
const DATA: &[u8] = include_bytes!("import_fixtures/onepassword_1pux/export/export.data");
const FILE: &[u8] = b"PUBLIC FIXTURE DOCUMENT\n\0\xff";
fn pack(attributes: &[u8], data: &[u8], files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in [("export.attributes", attributes), ("export.data", data)]
        .into_iter()
        .chain(files.iter().copied())
    {
        writer
            .start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn run(input: &[u8]) -> Result<Plan, Error> {
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    import::prepare(
        Format::Onepassword1pux,
        input,
        &options,
        Limits::default(),
        &mut |_| true,
        onepassword_1pux::parse,
    )
}
fn fixture() -> Json {
    serde_json::from_slice(DATA).unwrap()
}
fn mutated(data: &Json) -> Vec<u8> {
    pack(
        ATTRIBUTES,
        &serde_json::to_vec(data).unwrap(),
        &[("files/document-1___fixture.bin", FILE)],
    )
}
#[test]
fn fixture_maps_order_protection_totp_binary_and_vault_scope() {
    let plan = run(include_bytes!(
        "import_fixtures/onepassword_1pux/account.1pux"
    ))
    .unwrap();
    assert_eq!(plan.items.len(), 4);
    assert_eq!(plan.container_status, Status::Ready);
    assert_eq!(plan.items[0].status, Status::Review);
    assert_eq!(plan.items[1].status, Status::Ready);
    assert_eq!(plan.items[2].status, Status::Excluded);
    assert_eq!(plan.items[3].status, Status::Ready);
    assert_eq!(plan.items[0].source.item, plan.items[3].source.item);
    assert_ne!(plan.items[0].source.vault, plan.items[3].source.vault);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        record.entries[..10]
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        [
            "username",
            "password",
            "Primary",
            "Other",
            "Notes",
            "PIN",
            "Repeated",
            "Repeated",
            "",
            "One-time code"
        ]
    );
    assert_eq!(record.entries[5].type_name, "secret/v1");
    assert_eq!(record.entries[6].type_name, "text/v1");
    assert_eq!(
        record.entries[7].extra["metadata"].as_map().unwrap()[0]
            .1
            .as_bool(),
        Some(true)
    );
    let otp = &record.entries[9];
    assert_eq!(otp.type_name, "totp/v1");
    assert_eq!(otp.value["algorithm"].as_str(), Some("SHA256"));
    assert_eq!(otp.value["period"].as_u64(), Some(45));
    assert!(matches!(&otp.value["secret"],Value::Binary(bytes) if bytes==b"12345678901234567890"));
    for e in record.entries.iter().filter(|e| e.name == "Original data") {
        assert!(
            !e.value["text"]
                .as_str()
                .unwrap()
                .contains("PUBLIC-FIXTURE-PASSWORD")
        );
    }
    let document = plan.items[1].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(document.entries.len(), 1);
    assert_eq!(document.entries[0].value["data"].as_slice(), Some(FILE));
    let mut attrs = confidex_vault::record::Record::default();
    attrs.extra = plan.items[0].source_attributes(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        serde_json::from_str::<Json>(attrs.extra["item"].as_str().unwrap()).unwrap(),
        fixture()["accounts"][0]["vaults"][0]["items"][0]
    );
}

#[test]
fn login_designations_work_without_html_field_names() {
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][0]["details"]["loginFields"] = json!([
        {"value":"https://login.example.invalid", "id":"", "fieldType":"T", "designation":"username"},
        {"value":"PUBLIC-FIXTURE-PASSWORD", "id":"", "fieldType":"P", "designation":"password"},
        {"value":"", "name":"", "fieldType":"T", "guarded":true},
        {"value":"public null-name fixture", "name":null, "id":"custom", "fieldType":"T"}
    ]);
    let url = &mut data["accounts"][0]["vaults"][0]["items"][0]["overview"]["urls"][0];
    url.as_object_mut().unwrap().remove("label");
    url["mode"] = json!("default");
    let plan = run(&mutated(&data)).unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries[0].type_name, "username/v1");
    assert_eq!(record.entries[0].name, "username");
    assert_eq!(
        record.entries[0].value["username"].as_str(),
        Some("https://login.example.invalid")
    );
    assert_eq!(record.entries[1].type_name, "password/v1");
    assert_eq!(record.entries[1].name, "password");
    assert_eq!(
        record.entries[1].value["password"].as_str(),
        Some("PUBLIC-FIXTURE-PASSWORD")
    );
    assert_eq!(record.entries[2].name, "");
    assert_eq!(record.entries[3].name, "custom");
    assert_eq!(record.entries[4].type_name, "url/v1");
    assert_eq!(record.entries[4].name, "URL");
    assert!(record.entries.iter().all(|e| {
        e.extra
            .get("confidex.import.original")
            .and_then(Value::as_str)
            .is_none_or(|p| !p.starts_with("/details/loginFields/"))
    }));
}
#[test]
fn missing_and_wrong_size_documents_do_not_succeed() {
    let missing = run(&pack(ATTRIBUTES, DATA, &[])).unwrap();
    assert_eq!(missing.items[1].status, Status::Blocked);
    assert!(
        missing.items[1]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::MissingAttachment)
    );
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][1]["details"]["documentAttributes"]["decryptedSize"] =
        json!(999);
    assert_eq!(
        run(&mutated(&data)).err().unwrap().kind,
        import::ErrorKind::SizeMismatch
    );
}
#[test]
fn unmatched_files_and_root_extensions_are_retained_with_plan_review() {
    let mut data = fixture();
    data["futureRoot"] = json!({"flag":true});
    let input = pack(
        ATTRIBUTES,
        &serde_json::to_vec(&data).unwrap(),
        &[
            ("files/document-1___fixture.bin", FILE),
            ("files/icon.bin", b"\0\xfficon"),
        ],
    );
    let plan = run(&input).unwrap();
    assert_eq!(plan.container_status, Status::Review);
    let mut context = confidex_vault::record::Record::default();
    context.extra = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    let files = context.extra["unmatched_files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    let fields = files[0].as_map().unwrap();
    assert!(
        fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("data")
                && value.as_slice() == Some(&b"\0\xfficon"[..]))
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
#[ignore = "Optional pinned upstream sample, supplied outside the repository"]
fn published_upstream_sample() {
    let path = std::env::var("CONFIDEX_TEST_1PUX")
        .expect("Set CONFIDEX_TEST_1PUX to the published upstream test fixture");
    let source = std::fs::read(path).unwrap();
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&source)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        digest,
        "6b47d336892273870380dac87b63014c0de65f2f4b6bd11c5cba0fd277725b02"
    );
    let plan = run(&source).unwrap();
    println!(
        "items={} ready={} review={} blocked={} excluded={}",
        plan.items.len(),
        plan.statistics.ready,
        plan.statistics.review,
        plan.statistics.blocked,
        plan.statistics.excluded
    );
    assert_eq!(plan.items.len(), 9);
    for (index, item) in plan.items.iter().enumerate() {
        println!(
            "item={index} status={:?} diagnostics={:?}",
            item.status, item.diagnostics
        );
    }
    assert_eq!(plan.statistics.blocked, 0);
    let document = plan.items[5].record(MAX_OPEN_MEMORY).unwrap();
    assert!(document.entries.iter().any(|e| e.type_name == "file/v1"));
}

#[test]
fn historical_double_separator_is_exact_and_ambiguous_paths_block() {
    let old = pack(ATTRIBUTES, DATA, &[("files/document-1__fixture.bin", FILE)]);
    let plan = run(&old).unwrap();
    assert_eq!(plan.items[1].status, Status::Ready);
    let ambiguous = pack(
        ATTRIBUTES,
        DATA,
        &[
            ("files/document-1__fixture.bin", FILE),
            ("files/document-1___fixture.bin", FILE),
        ],
    );
    assert_eq!(run(&ambiguous).unwrap().items[1].status, Status::Blocked);
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][1]["file"] =
        json!({"path":"files/document-1__fixture.bin"});
    let explicit = pack(
        ATTRIBUTES,
        &serde_json::to_vec(&data).unwrap(),
        &[
            ("files/document-1__fixture.bin", FILE),
            ("files/document-1___fixture.bin", FILE),
        ],
    );
    let plan = run(&explicit).unwrap();
    assert_eq!(plan.items[1].status, Status::Ready);
    assert_eq!(plan.container_status, Status::Review);
}
#[test]
fn missing_ids_require_review_and_never_become_row_ids() {
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][0]
        .as_object_mut()
        .unwrap()
        .remove("uuid");
    let plan = run(&mutated(&data)).unwrap();
    assert!(plan.items[0].source.item.is_none());
    assert_eq!(plan.items[0].status, Status::Review);
    assert!(
        plan.items[0]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::MissingSourceScope)
    );
}
#[test]
fn unknown_and_protected_values_are_not_mapped_as_public_text() {
    let mut data = fixture();
    let item = &mut data["accounts"][0]["vaults"][0]["items"][0];
    item["details"]["sections"][0]["fields"][0]["title"] = json!("Original data");
    item["details"]["sections"][0]["fields"].as_array_mut().unwrap().push(json!({"title":"unknown","id":"unknown","value":{"future":"PUBLIC-UNKNOWN"},"guarded":true}));
    item["overview"]["urls"][0]["guarded"] = json!(true);
    let plan = run(&mutated(&data)).unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let primary = record.entries.iter().find(|e| e.name == "Primary").unwrap();
    assert_eq!(
        primary.extra["metadata"].as_map().unwrap()[0].1.as_bool(),
        Some(true)
    );
    assert_eq!(
        record
            .entries
            .iter()
            .filter(|e| e.type_name == "url/v1"
                && e.value["url"].as_str() == Some("https://mail.example.invalid"))
            .count(),
        1
    );
    assert!(
        record
            .entries
            .iter()
            .any(|e| e.extra.contains_key("confidex.import.original")
                && e.value["text"].as_str().unwrap().contains("PUBLIC-UNKNOWN"))
    );
    assert!(!record.entries.iter().any(|e|e.type_name=="text/v1"&&e.value["text"].as_str()==Some("PUBLIC-UNKNOWN")));
}
#[test]
fn raw_unknown_numbers_and_nulls_are_preserved_without_rounding() {
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][0]["details"]["future"] =
        json!({"number":"REPLACE_WITH_NUMBER","nullable":null,"empty":""});
    let source = serde_json::to_string(&data)
        .unwrap()
        .replace("\"REPLACE_WITH_NUMBER\"", "123456789012345678901234567890");
    let plan = run(&pack(
        ATTRIBUTES,
        source.as_bytes(),
        &[("files/document-1___fixture.bin", FILE)],
    ))
    .unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let raw = record
        .entries
        .iter()
        .filter(|e| e.extra.contains_key("confidex.import.original"))
        .find_map(|e| {
            e.value["text"]
                .as_str()
                .filter(|s| s.contains("123456789012345678901234567890"))
        })
        .unwrap();
    assert!(raw.contains("\"nullable\":null"));
    assert!(raw.contains("\"empty\":\"\""));
    assert!(!raw.contains("PUBLIC-FIXTURE-PASSWORD"));
}
#[test]
fn malformed_versions_structure_and_references_cannot_apply() {
    assert_eq!(
        run(&pack(br#"{"version":4}"#, DATA, &[]))
            .err()
            .unwrap()
            .kind,
        import::ErrorKind::UnsupportedVersion
    );
    assert!(run(&pack(ATTRIBUTES, b"{\"accounts\":", &[])).is_err());
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][0]["value"] =
        json!({"reference":"unresolved-id"});
    let plan = run(&mutated(&data)).unwrap();
    assert_eq!(plan.items[0].status, Status::Blocked);
    assert!(
        plan.items[0]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::UnresolvedFieldReference)
    );
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][0]["overview"]["protected"] = json!(true);
    let plan = run(&mutated(&data)).unwrap();
    assert_eq!(plan.items[0].status, Status::Blocked);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        record.extra["confidex.title"].as_str(),
        Some("Imported item")
    );
    assert!(
        record
            .entries
            .iter()
            .all(|e| e.type_name == "secure-note/v1")
    );
}
#[test]
fn otp_extensions_are_preserved_and_standard_seeds_remain_functional() {
    let mut data = fixture();
    let fields =
        &mut data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"];
    fields[4]["value"]["totp"] = json!("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    let plan = run(&mutated(&data)).unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let otp = record
        .entries
        .iter()
        .find(|e| e.type_name == "totp/v1")
        .unwrap();
    assert_eq!(otp.value["period"].as_u64(), Some(30));
    assert_eq!(otp.value["algorithm"].as_str(), Some("SHA1"));
    for suffix in [
        "&counter=1",
        "&digits=5",
        "&period=0",
        "&period=60",
        "&encoder=steam",
        "&issuer=bad%",
    ] {
        let mut data = fixture();
        let value = &mut data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"]
            [4]["value"]["totp"];
        *value = json!(format!("{}{suffix}", value.as_str().unwrap()));
        let plan = run(&mutated(&data)).unwrap();
        let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert!(!record.entries.iter().any(|e| e.type_name == "totp/v1"));
        assert_eq!(plan.items[0].status, Status::Review);
    }
}
#[test]
fn cancellation_limits_and_archive_damage_return_no_plan() {
    let source = include_bytes!("import_fixtures/onepassword_1pux/account.1pux");
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    assert_eq!(
        import::prepare(
            Format::Onepassword1pux,
            source,
            &options,
            Limits::default(),
            &mut |p| p.phase != import::Phase::Map,
            onepassword_1pux::parse
        )
        .err()
        .unwrap()
        .kind,
        import::ErrorKind::Canceled
    );
    let limits = Limits {
        records: 1,
        ..Limits::default()
    };
    assert_eq!(
        import::prepare(
            Format::Onepassword1pux,
            source,
            &options,
            limits,
            &mut |_| true,
            onepassword_1pux::parse
        )
        .err()
        .unwrap()
        .kind,
        import::ErrorKind::Limit
    );
    assert!(run(&source[..source.len() - 1]).is_err());
}

#[test]
fn archived_selection_is_explicit_and_empty_values_keep_their_fields() {
    let source = include_bytes!("import_fixtures/onepassword_1pux/account.1pux");
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    options.include_archived = true;
    let plan = import::prepare(
        Format::Onepassword1pux,
        source,
        &options,
        Limits::default(),
        &mut |_| true,
        onepassword_1pux::parse,
    )
    .unwrap();
    assert_eq!(plan.items[2].status, Status::Review);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let empty = record.entries.iter().find(|e| e.name.is_empty()).unwrap();
    assert_eq!(empty.value["text"].as_str(), Some(""));
}

#[test]
#[ignore = "Separate native/WASM resource calibration"]
fn ten_thousand_login_items() {
    use std::fmt::Write;
    let mut data = String::from(
        "{\"accounts\":[{\"attrs\":{\"uuid\":\"public-account\"},\"vaults\":[{\"attrs\":{\"uuid\":\"public-vault\"},\"items\":[",
    );
    for i in 0..10_000 {
        if i != 0 {
            data.push(',');
        }
        write!(data,r#"{{"uuid":"item-{i}","categoryUuid":"001","state":"active","overview":{{"title":"Public fixture {i}","url":"https://example.invalid/{i}"}},"details":{{"loginFields":[{{"name":"username","fieldType":"T","designation":"username","value":"fixture-{i}"}},{{"name":"password","fieldType":"P","designation":"password","value":"PUBLIC-FIXTURE-{i}"}}]}}}}"#).unwrap();
    }
    data.push_str("]}]}]}");
    let source = pack(ATTRIBUTES, data.as_bytes(), &[]);
    drop(data);
    let start = std::time::Instant::now();
    let plan = run(&source).unwrap();
    assert_eq!(plan.items.len(), 10_000);
    assert_eq!(plan.statistics.ready, 10_000);
    assert_eq!(plan.container_status, Status::Ready);
    assert_eq!(
        plan.items[9999]
            .record(MAX_OPEN_MEMORY)
            .unwrap()
            .entries
            .len(),
        3
    );
    println!(
        "source_bytes={} plan_bytes={} elapsed_ms={}",
        source.len(),
        plan.statistics.encoded_bytes,
        start.elapsed().as_millis()
    );
}

#[test]
fn inactive_null_union_members_do_not_hide_the_selected_value() {
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][1]["value"]
        ["concealed"] = Json::Null;
    data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][1]["value"]
        ["reference"] = Json::Null;
    let plan = run(&mutated(&data)).unwrap();
    assert_ne!(plan.items[0].status, Status::Blocked);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert!(record.entries.iter().any(|e| e.name == "Repeated"
        && e.type_name == "text/v1"
        && e.value["text"].as_str() == Some("public first")));
}

#[test]
fn unknown_property_paths_keep_slashes_and_tildes_unambiguous() {
    let mut data = fixture();
    data["accounts"][0]["vaults"][0]["items"][0]["details"]["a/b~c"] = json!("PUBLIC-UNKNOWN-PATH");
    let plan = run(&mutated(&data)).unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert!(record.entries.iter().any(|e| {
        e.extra
            .get("confidex.import.original")
            .and_then(Value::as_str)
            == Some("/details/a~1b~0c")
    }));
}

#[test]
fn title_only_items_do_not_gain_artificial_fields() {
    let mut data = fixture();
    let item = &mut data["accounts"][0]["vaults"][0]["items"][0];
    item["overview"] = json!({"title":"Public title only","tags":[]});
    item["details"] = json!({});
    item["favIndex"] = json!(0);
    let plan = run(&mutated(&data)).unwrap();
    assert_eq!(plan.items[0].status, Status::Ready);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert!(record.entries.is_empty());
    assert_eq!(
        record.extra["confidex.title"].as_str(),
        Some("Public title only")
    );
}
