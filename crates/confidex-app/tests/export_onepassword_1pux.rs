use confidex_app::export::{self, Consent, Records};
use confidex_app::import::{
    self, Code, ErrorKind, Format, Limits, Options, Status, formats::onepassword_1pux,
};
use confidex_vault::record::{Entry, Mapping, Record, Value};
use confidex_vault::resources::MAX_OPEN_MEMORY;
use std::io::{Read, Write};

const INPUT: &[u8] = include_bytes!("export_fixtures/onepassword_1pux/section-files.input.json");
#[path = "export_onepassword_1pux/proof.rs"]
mod proof;

#[test]
fn public_worker_proof_keeps_concealed_values_and_clears_failed_artifacts() {
    proof::run();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Requires pinned upstream sources, Node, and esbuild"]
fn pinned_independent_consumer_reads_actual_writer_output() {
    let shared = std::env::var_os("CONFIDEX_BITWARDEN_READER_SOURCE").unwrap();
    let source = std::env::var_os("CONFIDEX_ONEPASSWORD_READER_SOURCE").unwrap();
    let mut records = Records::new(export::Limits::default()).unwrap();
    records.push(proof::fixture()).unwrap();
    let mut login = Record::default();
    login.entries.extend([
        scalar("User", "username/v1", "username", "public-user"),
        scalar("Password", "password/v1", "password", "PUBLIC-CURRENT"),
        scalar("One", "url/v1", "url", "https://one.invalid/"),
        scalar("Two", "url/v1", "url", "https://two.invalid/"),
    ]);
    records.push(login).unwrap();
    let artifact = export::prepare(
        records,
        Box::new(onepassword_1pux::Writer::new(CREATED).unwrap()),
        &mut |_| true,
    )
    .unwrap()
    .write(Consent::AllowLosses, &mut |_| true)
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(artifact.file.name);
    std::fs::write(&path, artifact.bytes()).unwrap();
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/export_fixtures/onepassword_1pux/reader.py"
        ))
        .arg(path)
        .arg(shared)
        .arg(source)
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

fn pack(data: &[u8], files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in [
        ("export.attributes", &b"{\"version\":3}"[..]),
        ("export.data", data),
    ]
    .into_iter()
    .chain(files.iter().copied())
    {
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}
fn prepare(data: &[u8], files: &[(&str, &[u8])]) -> Result<import::Plan, import::Error> {
    let mut options = Options::default();
    options.source_instance = Some("public-section-file-source".into());
    import::prepare(
        Format::Onepassword1pux,
        &pack(data, files),
        &options,
        Limits::default(),
        &mut |_| true,
        onepassword_1pux::parse,
    )
}
const FILES: &[(&str, &[u8])] = &[
    ("files/file-1___same.bin", &[0, 255, 7]),
    ("files/file-2___same.bin", &[]),
    ("files/main-1___main.bin", &[9]),
];

#[test]
fn section_files_keep_each_payload_name_and_position_alongside_a_document() {
    let plan = prepare(INPUT, FILES).unwrap();
    assert_eq!(plan.container_status, Status::Ready);
    assert_eq!(plan.items.len(), 1);
    assert_ne!(plan.items[0].status, Status::Blocked);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        record
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["", "Repeated", "Repeated", "Repeated", "", "main.bin"]
    );
    assert_eq!(
        record
            .entries
            .iter()
            .map(|e| e.type_name.as_str())
            .collect::<Vec<_>>(),
        [
            "text/v1",
            "file/v1",
            "secret/v1",
            "file/v1",
            "text/v1",
            "file/v1"
        ]
    );
    assert_eq!(
        record.entries[1].value["filename"].as_str(),
        Some("same.bin")
    );
    assert_eq!(
        record.entries[3].value["filename"].as_str(),
        Some("same.bin")
    );
    assert_eq!(
        record.entries[1].value["data"].as_slice(),
        Some(&[0, 255, 7][..])
    );
    assert_eq!(record.entries[3].value["data"].as_slice(), Some(&[][..]));
    assert_eq!(record.entries[5].value["data"].as_slice(), Some(&[9][..]));
    for index in [1, 3] {
        assert!(
            record.entries[index]
                .extra
                .contains_key("confidex.import.section")
        );
    }
}

#[test]
fn section_files_require_exact_ids_and_cannot_use_another_same_named_file() {
    let plan = prepare(INPUT, &FILES[1..]).unwrap();
    assert_eq!(plan.items[0].status, Status::Blocked);
    assert!(
        plan.items[0]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::MissingAttachment && d.location.field == Some(1))
    );
}

#[test]
fn wrong_section_size_is_rejected_before_a_plan_can_apply() {
    let mut source: serde_json::Value = serde_json::from_slice(INPUT).unwrap();
    source["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][1]["value"]
        ["file"]["decryptedSize"] = 4.into();
    let error = prepare(&serde_json::to_vec(&source).unwrap(), FILES)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::SizeMismatch);
    assert_eq!(error.location.field, Some(1));
}

#[test]
fn section_separator_collisions_are_blocked_and_legacy_paths_are_exact() {
    let legacy = [
        ("files/file-1__same.bin", FILES[0].1),
        ("files/file-2__same.bin", FILES[1].1),
        ("files/main-1__main.bin", FILES[2].1),
    ];
    let plan = prepare(INPUT, &legacy).unwrap();
    assert_eq!(plan.container_status, Status::Ready);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        record.entries[1].value["data"].as_slice(),
        Some(&[0, 255, 7][..])
    );
    assert_eq!(
        record.entries[1].extra["confidex.import.file_path"].as_str(),
        Some("files/file-1__same.bin")
    );
    let mut ambiguous = FILES.to_vec();
    ambiguous.push(legacy[0]);
    let plan = prepare(INPUT, &ambiguous).unwrap();
    assert_eq!(plan.items[0].status, Status::Blocked);
    assert!(
        plan.items[0]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::UnsupportedFeature && d.location.field == Some(1))
    );
}

#[test]
fn unsafe_and_unknown_section_file_descriptors_are_blocked() {
    for (key, value) in [
        ("documentId", serde_json::json!("../file-1")),
        ("fileName", serde_json::json!("../same.bin")),
        ("future", serde_json::json!(true)),
    ] {
        let mut source: serde_json::Value = serde_json::from_slice(INPUT).unwrap();
        source["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][1]["value"]
            ["file"][key] = value;
        let plan = prepare(&serde_json::to_vec(&source).unwrap(), FILES).unwrap();
        assert_eq!(plan.items[0].status, Status::Blocked);
        assert!(
            plan.items[0]
                .diagnostics
                .iter()
                .any(|d| d.code == Code::UnsupportedEncoding && d.location.field == Some(1))
        );
    }
}

const CREATED: u64 = 1_735_689_600;
fn scalar(name: &str, kind: &str, key: &str, value: &str) -> Entry {
    Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), value.into())]),
        extra: Mapping::new(),
    }
}
fn file(name: &str, filename: &str, data: &[u8]) -> Entry {
    Entry {
        name: name.into(),
        type_name: "file/v1".into(),
        value: Mapping::from([
            ("filename".into(), filename.into()),
            ("data".into(), Value::Binary(data.to_vec())),
        ]),
        extra: Mapping::new(),
    }
}
fn plan(record: Record) -> export::Plan {
    let mut records = Records::new(export::Limits::default()).unwrap();
    records.push(record).unwrap();
    export::prepare(
        records,
        Box::new(onepassword_1pux::Writer::new(CREATED).unwrap()),
        &mut |_| true,
    )
    .unwrap()
}
fn member_bytes(bytes: &[u8], name: &str) -> Vec<u8> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut bytes = Vec::new();
    zip.by_name(name).unwrap().read_to_end(&mut bytes).unwrap();
    bytes
}
fn data(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(&member_bytes(bytes, "export.data")).unwrap()
}
fn roundtrip(bytes: &[u8]) -> Record {
    let mut options = Options::default();
    options.source_instance = Some("public-writer-roundtrip".into());
    let plan = import::prepare(
        Format::Onepassword1pux,
        bytes,
        &options,
        Limits::default(),
        &mut |_| true,
        onepassword_1pux::parse,
    )
    .unwrap();
    assert_eq!(plan.container_status, Status::Ready);
    assert_eq!(plan.items.len(), 1);
    assert_ne!(plan.items[0].status, Status::Blocked);
    plan.items[0].record(MAX_OPEN_MEMORY).unwrap()
}
fn protected(entry: &Entry) -> bool {
    matches!(
        entry.type_name.as_str(),
        "password/v1" | "secret/v1" | "secure-note/v1"
    ) || entry
        .extra
        .get("metadata")
        .and_then(Value::as_map)
        .is_some_and(|m| {
            m.iter()
                .any(|(k, v)| k.as_str() == Some("protected") && v.as_bool() == Some(true))
        })
}
fn set_sections(record: &mut Record, sections: &[(&str, u64, u64)]) {
    record.extra.insert(
        "confidex.sections".into(),
        Value::Map(vec![
            ("version".into(), 1u64.into()),
            (
                "groups".into(),
                Value::Array(
                    sections
                        .iter()
                        .map(|(name, start, count)| {
                            Value::Map(vec![
                                ("name".into(), (*name).into()),
                                ("start".into(), (*start).into()),
                                ("count".into(), (*count).into()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    );
}

#[test]
fn writer_streams_version_three_with_current_fields_and_distinct_file_bindings() {
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "Public mixed".into());
    record.tags = vec!["demo".into(), "旅行".into()];
    record.entries.extend([
        scalar("", "text/v1", "text", ""),
        scalar("account", "username/v1", "username", "public-user"),
        scalar("pass", "password/v1", "password", "PUBLIC-CURRENT"),
        scalar("Same", "url/v1", "url", "https://one.invalid/a?q=1&v=2"),
        scalar("", "url/v1", "url", "https://two.invalid/"),
        scalar("Repeated", "text/v1", "text", "line one\n\"two\"\\公開"),
        scalar("Repeated", "secret/v1", "secret", "PUBLIC-HIDDEN"),
    ]);
    let mut url = scalar("Protected URI", "url/v1", "url", "https://private.invalid/");
    url.extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    record.entries.push(url);
    let uri = "otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45";
    record.entries.push(import::totp::entry(uri).unwrap());
    record.entries.extend([
        file("Repeated", "same.bin", &[0, 255, 7]),
        file("Repeated", "same.bin", &[]),
        scalar("", "secure-note/v1", "text", ""),
    ]);
    let mut expected: Vec<_> = record
        .entries
        .iter()
        .map(|e| {
            (
                e.name.clone(),
                e.type_name.clone(),
                e.value.clone(),
                protected(e),
            )
        })
        .collect();
    expected[7].1 = "secret/v1".into();
    expected[7].2 = Mapping::from([("secret".into(), "https://private.invalid/".into())]);
    let tags = record.tags.clone();
    let plan = plan(record);
    assert_eq!(plan.issues().len(), 1);
    assert_eq!(plan.issues()[0].code, export::Code::UnsupportedField);
    assert_eq!(plan.issues()[0].field, Some(7));
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert_eq!(artifact.file.name, "confidex.1pux");
    assert!(!artifact.file.encrypted);
    let attributes: serde_json::Value =
        serde_json::from_slice(&member_bytes(artifact.bytes(), "export.attributes")).unwrap();
    assert_eq!(attributes["version"], 3);
    assert_eq!(attributes["createdAt"], CREATED);
    let json = data(artifact.bytes());
    let item = &json["accounts"][0]["vaults"][0]["items"][0];
    assert_eq!(item["categoryUuid"], "001");
    assert_eq!(item["createdAt"], CREATED);
    assert_eq!(item["overview"]["urls"].as_array().unwrap().len(), 2);
    assert_eq!(item["overview"]["url"], "https://one.invalid/a?q=1&v=2");
    assert_eq!(item["details"]["loginFields"][0]["name"], "");
    assert_eq!(item["details"]["loginFields"][1]["designation"], "username");
    assert_eq!(item["details"]["loginFields"][2]["designation"], "password");
    let fields = item["details"]["sections"][0]["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 7);
    assert_eq!(fields[2]["value"]["concealed"], "https://private.invalid/");
    assert_eq!(fields[3]["value"]["totp"], uri);
    let id_one = fields[4]["value"]["file"]["documentId"].as_str().unwrap();
    let id_two = fields[5]["value"]["file"]["documentId"].as_str().unwrap();
    assert_ne!(id_one, id_two);
    for id in [id_one, id_two, item["uuid"].as_str().unwrap()] {
        assert_eq!(id.len(), 26);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || matches!(b, b'2'..=b'7'))
        );
    }
    assert_eq!(
        member_bytes(artifact.bytes(), &format!("files/{id_one}___same.bin")),
        [0, 255, 7]
    );
    assert!(member_bytes(artifact.bytes(), &format!("files/{id_two}___same.bin")).is_empty());
    let imported = roundtrip(artifact.bytes());
    assert_eq!(imported.entries.len(), expected.len());
    for (actual, (name, kind, value, hidden)) in imported.entries.iter().zip(&expected) {
        assert_eq!(&actual.name, name);
        assert_eq!(&actual.type_name, kind);
        assert_eq!(&actual.value, value);
        assert_eq!(&protected(actual), hidden);
    }
    assert_eq!(imported.tags, tags);
}

#[test]
fn source_snapshots_cannot_restore_deleted_values_or_policies() {
    let make = || {
        let mut record = Record::default();
        record
            .entries
            .push(scalar("pass", "password/v1", "password", "PUBLIC-CURRENT"));
        record.extra.insert("confidex.import.origin".into(), Value::Map(vec![("version".into(), 1u64.into()), ("format".into(), "onepassword-1pux".into()), ("attributes".into(), Value::Map(vec![("item".into(), "{\"details\":{\"password\":\"PUBLIC-OLD-REMOVED\"},\"state\":\"archived\",\"favIndex\":1}".into())]))]));
        record
    };
    let review = plan(make());
    assert!(
        review
            .issues()
            .iter()
            .any(|i| i.code == export::Code::SourceContext)
    );
    assert_eq!(
        review.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Losses)
    );
    let artifact = plan(make())
        .write(Consent::AllowLosses, &mut |_| true)
        .unwrap();
    let json = data(artifact.bytes());
    let item = &json["accounts"][0]["vaults"][0]["items"][0];
    assert_eq!(item["details"]["loginFields"][0]["value"], "PUBLIC-CURRENT");
    assert_eq!(item["state"], "active");
    assert_eq!(item["favIndex"], 0);
    assert!(!json.to_string().contains("PUBLIC-OLD-REMOVED"));
}

#[test]
fn edited_section_files_take_the_current_name_bytes_and_group_title() {
    let source = prepare(INPUT, FILES).unwrap();
    let mut current = source.items[0].record(MAX_OPEN_MEMORY).unwrap();
    current.entries[1].name = "Renamed file".into();
    current.entries[1]
        .value
        .insert("filename".into(), "edited.bin".into());
    current.entries[1]
        .value
        .insert("data".into(), Value::Binary(vec![4, 2]));
    set_sections(&mut current, &[("Edited group", 0, 5)]);
    let review = plan(current);
    assert!(
        review
            .issues()
            .iter()
            .any(|i| i.code == export::Code::SourceContext)
    );
    let artifact = review.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let json = data(artifact.bytes());
    let sections = &json["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"];
    assert_eq!(sections[0]["title"], "Edited group");
    let field = &sections[0]["fields"][1];
    assert_eq!(field["title"], "Renamed file");
    assert_eq!(field["value"]["file"]["fileName"], "edited.bin");
    let id = field["value"]["file"]["documentId"].as_str().unwrap();
    assert_eq!(
        member_bytes(artifact.bytes(), &format!("files/{id}___edited.bin")),
        [4, 2]
    );
    let imported = roundtrip(artifact.bytes());
    assert_eq!(imported.entries[1].name, "Renamed file");
    assert_eq!(
        imported.entries[1].value["filename"].as_str(),
        Some("edited.bin")
    );
    assert_eq!(
        imported.entries[1].value["data"].as_slice(),
        Some(&[4, 2][..])
    );
}

#[test]
fn current_empty_and_repeated_sections_survive_a_real_archive_roundtrip() {
    let mut record = Record::default();
    record.entries.extend([
        scalar("", "text/v1", "text", "first"),
        scalar("Same", "secret/v1", "secret", "PUBLIC-HIDDEN"),
    ]);
    set_sections(
        &mut record,
        &[
            ("", 0, 0),
            ("Repeated", 0, 1),
            ("Repeated", 1, 0),
            ("", 1, 1),
            ("Repeated", 2, 0),
        ],
    );
    let review = plan(record);
    assert!(review.issues().is_empty(), "{:?}", review.issues());
    let artifact = review.write(Consent::Lossless, &mut |_| true).unwrap();
    let json = data(artifact.bytes());
    let sections = json["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"]
        .as_array()
        .unwrap();
    assert_eq!(
        sections
            .iter()
            .map(|s| s["title"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["", "Repeated", "Repeated", "", "Repeated"]
    );
    assert_eq!(
        sections
            .iter()
            .map(|s| s["fields"].as_array().unwrap().len())
            .collect::<Vec<_>>(),
        [0, 1, 0, 1, 0]
    );
    let names: std::collections::BTreeSet<_> = sections
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), sections.len());
    let imported = roundtrip(artifact.bytes());
    let layout = imported.extra["confidex.sections"]
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_str() == Some("groups"))
        .unwrap()
        .1
        .as_array()
        .unwrap();
    assert_eq!(layout.len(), 5);
    for (group, (title, start, count)) in layout.iter().zip([
        ("", 0, 0),
        ("Repeated", 0, 1),
        ("Repeated", 1, 0),
        ("", 1, 1),
        ("Repeated", 2, 0),
    ]) {
        let member = |key| {
            group
                .as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(member("name").as_str(), Some(title));
        assert_eq!(member("start").as_u64(), Some(start));
        assert_eq!(member("count").as_u64(), Some(count));
    }
}

#[test]
fn removing_or_opaque_current_sections_never_restores_old_imported_group_names() {
    for opaque in [false, true] {
        let source = prepare(INPUT, FILES).unwrap();
        let mut record = source.items[0].record(MAX_OPEN_MEMORY).unwrap();
        set_sections(&mut record, &[]);
        if opaque {
            record.extra.insert(
                "confidex.sections".into(),
                Value::Map(vec![
                    ("version".into(), 2u64.into()),
                    ("groups".into(), Value::Array(vec![])),
                ]),
            );
        }
        let review = plan(record);
        assert!(
            review
                .issues()
                .iter()
                .any(|i| i.code == export::Code::Sections)
        );
        let artifact = review.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let json = data(artifact.bytes());
        let sections = json["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"]
            .as_array()
            .unwrap();
        assert!(sections.iter().all(|s| s["title"] == ""));
    }
}

#[test]
fn impossible_order_types_metadata_and_unsafe_names_require_review() {
    let mut record = Record::default();
    record.entries.extend([
        scalar("Secret", "secret/v1", "secret", "PUBLIC-HIDDEN"),
        scalar("pass", "password/v1", "password", "PUBLIC-PASS"),
        scalar("Note", "note/v1", "text", "Public note"),
    ]);
    record.entries[2]
        .value
        .insert("future".into(), Value::Ext(42, vec![7]));
    record.entries[2].extra.insert("future".into(), true.into());
    let review = plan(record);
    for code in [
        export::Code::FieldOrder,
        export::Code::UnsupportedField,
        export::Code::UnknownValue,
        export::Code::UnknownMetadata,
    ] {
        assert!(review.issues().iter().any(|i| i.code == code));
    }
    assert_eq!(
        review.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Losses)
    );
    let mut record = Record::default();
    record.entries.push(file("unsafe", "../source.bin", &[1]));
    let review = plan(record);
    assert!(review.issues().iter().any(|i| i.severity == export::Severity::Blocked && i.code == export::Code::Attachments));
    assert_eq!(
        review.write(Consent::AllowLosses, &mut |_| true).err(),
        Some(export::Error::Blocked)
    );
}

#[test]
fn new_exports_use_fresh_identity_scopes_and_reject_invalid_time() {
    assert!(matches!(
        onepassword_1pux::Writer::new(u64::MAX),
        Err(export::Error::InvalidOptions)
    ));
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..2 {
        let artifact = plan(Record::default())
            .write(Consent::Lossless, &mut |_| true)
            .unwrap();
        let json = data(artifact.bytes());
        for value in [
            &json["accounts"][0]["attrs"]["uuid"],
            &json["accounts"][0]["vaults"][0]["attrs"]["uuid"],
            &json["accounts"][0]["vaults"][0]["items"][0]["uuid"],
        ] {
            assert!(ids.insert(value.as_str().unwrap().to_owned()));
        }
    }
}

#[test]
fn cancellation_and_output_limits_clear_the_whole_archive_and_snapshot() {
    for cancel in [false, true] {
        let limits = export::Limits {
            records: 4,
            snapshot_bytes: 1 << 20,
            output_bytes: if cancel { 2 << 20 } else { 128 << 10 },
            ..Default::default()
        };
        let mut records = Records::new(limits).unwrap();
        let memory = records.memory().clone();
        let mut record = Record::default();
        record
            .entries
            .push(file("Public large file", "large.bin", &vec![7; 900_000]));
        records.push(record).unwrap();
        let review = export::prepare(
            records,
            Box::new(onepassword_1pux::Writer::new(CREATED).unwrap()),
            &mut |_| true,
        )
        .unwrap();
        assert!(review.issues().is_empty());
        let mut callbacks = 0;
        let result = review.write(Consent::Lossless, &mut |_| {
            callbacks += 1;
            !cancel || callbacks < 100
        });
        assert_eq!(
            result.err(),
            Some(if cancel {
                export::Error::Canceled
            } else {
                export::Error::Limit
            })
        );
        if cancel {
            assert_eq!(callbacks, 100);
        }
        assert_eq!(memory.available(), limits.memory_bytes);
    }
}

#[test]
fn zip_directory_memory_is_admitted_before_allocating_long_member_names() {
    let limits = export::Limits {
        records: 1,
        issues: 32,
        ..Default::default()
    };
    let mut records = Records::new(limits).unwrap();
    let memory = records.memory().clone();
    let mut record = Record::default();
    let name = "x".repeat(4000) + ".bin";
    for _ in 0..256 {
        record.entries.push(file("Public", &name, &[]));
    }
    records.push(record).unwrap();
    let held = memory.available() - (1 << 20);
    let pressure = memory.reserve(held).unwrap();
    let review = export::prepare(
        records,
        Box::new(onepassword_1pux::Writer::new(CREATED).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    assert_eq!(
        review.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Limit)
    );
    assert_eq!(memory.available(), limits.memory_bytes - held);
    drop(pressure);
    assert_eq!(memory.available(), limits.memory_bytes);
}

#[test]
fn progress_reaches_json_and_file_passes_before_completion() {
    let mut records = Records::new(export::Limits::default()).unwrap();
    for index in 0..2 {
        let mut record = Record::default();
        record.entries.push(file("Public", "same.bin", &[index]));
        records.push(record).unwrap();
    }
    let review = export::prepare(
        records,
        Box::new(onepassword_1pux::Writer::new(CREATED).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    let mut positions = std::collections::BTreeSet::new();
    let artifact = review
        .write(Consent::Lossless, &mut |p| {
            if p.total == 4 {
                positions.insert(p.current);
            }
            true
        })
        .unwrap();
    assert_eq!(positions, std::collections::BTreeSet::from([0, 1, 2, 3, 4]));
    let json = data(artifact.bytes());
    let items = json["accounts"][0]["vaults"][0]["items"]
        .as_array()
        .unwrap();
    let mut ids = std::collections::BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        assert!(ids.insert(item["uuid"].as_str().unwrap()));
        let document = &item["details"]["sections"][0]["fields"][0]["value"]["file"];
        let id = document["documentId"].as_str().unwrap();
        assert!(ids.insert(id));
        assert_eq!(
            member_bytes(artifact.bytes(), &format!("files/{id}___same.bin")),
            [index as u8]
        );
    }
}

#[test]
fn section_limit_counts_empty_groups_and_required_ungrouped_containers() {
    let make = |extra| {
        let mut record = Record::default();
        set_sections(&mut record, &vec![("Repeated", 0, 0); 512]);
        if extra {
            record
                .entries
                .push(scalar("Public", "secret/v1", "secret", "PUBLIC-HIDDEN"));
        }
        record
    };
    let artifact = plan(make(false))
        .write(Consent::Lossless, &mut |_| true)
        .unwrap();
    let imported = roundtrip(artifact.bytes());
    assert!(imported.entries.is_empty());
    let mut records = Records::new(export::Limits::default()).unwrap();
    records.push(make(true)).unwrap();
    let result = export::prepare(
        records,
        Box::new(onepassword_1pux::Writer::new(CREATED).unwrap()),
        &mut |_| true,
    );
    assert_eq!(result.err(), Some(export::Error::Limit));
}
