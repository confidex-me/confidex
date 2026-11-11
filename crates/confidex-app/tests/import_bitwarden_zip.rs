use confidex_app::import::{
    self, Code, Error, ErrorKind, Format, Limits, Options, Phase, Plan, Status,
    formats::{bitwarden_json, bitwarden_zip},
};
use confidex_vault::{record::Value, resources::MAX_OPEN_MEMORY};
use std::io::{Cursor, Read, Write};

const PERSONAL: &[u8] = include_bytes!("import_fixtures/bitwarden_zip/personal.zip");
const DOCUMENT: &[u8] = br#"{"encrypted":false,"folders":[],"items":[{"id":"a","type":1,"name":"Unique","login":{"username":"user","password":"PUBLIC"}}]}"#;
fn run(input: &[u8], limits: Limits) -> Result<Plan, Error> {
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    import::prepare(
        Format::BitwardenZip,
        input,
        &options,
        limits,
        &mut |_| true,
        bitwarden_zip::parse,
    )
}
fn parse(input: &[u8]) -> Plan {
    run(input, Limits::default()).unwrap()
}
fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        writer
            .start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn members(input: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut zip = zip::ZipArchive::new(Cursor::new(input)).unwrap();
    (0..zip.len())
        .filter_map(|i| {
            let mut file = zip.by_index(i).unwrap();
            if file.is_dir() {
                return None;
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            Some((file.name().unwrap().into_owned(), bytes))
        })
        .collect()
}

#[test]
fn pinned_export_preserves_files_ownership_names_and_plain_json_semantics() {
    let plan = parse(PERSONAL);
    assert_eq!(plan.items.len(), 3);
    assert_eq!(plan.container_status, Status::Review);
    assert!(
        plan.container_diagnostics
            .iter()
            .any(|d| d.code == Code::UnsupportedFeature)
    );
    let attrs = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        attrs["bitwarden.zip.attachment-inventory-verified"],
        Value::from(false)
    );
    let original = members(PERSONAL);
    let json = &original
        .iter()
        .find(|(name, _)| name == "data.json")
        .unwrap()
        .1;
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    let plain = import::prepare(
        Format::BitwardenJson,
        json,
        &options,
        Limits::default(),
        &mut |_| true,
        bitwarden_json::parse,
    )
    .unwrap();
    for (index, item) in plan.items.iter().enumerate() {
        assert_eq!(item.source.item, plain.items[index].source.item);
        assert_eq!(item.source.vault, plain.items[index].source.vault);
        assert_eq!(
            item.source_attributes_bytes(),
            plain.items[index].source_attributes_bytes()
        );
        let mut record = item.record(MAX_OPEN_MEMORY).unwrap();
        let files: Vec<_> = record
            .entries
            .iter()
            .filter(|e| e.type_name == "file/v1")
            .collect();
        assert_eq!(files.len(), [3, 1, 0][index]);
        for file in files {
            let path = file.extra["bitwarden.zip.path"].as_str().unwrap();
            let bytes = &original.iter().find(|(name, _)| name == path).unwrap().1;
            assert_eq!(file.value["data"], Value::Binary(bytes.clone()));
            assert_eq!(file.value["filename"].as_str(), Some(file.name.as_str()));
            if index == 0 {
                assert!(path.starts_with("attachments/Почта _ 東京/"));
            }
            if index == 1 {
                assert!(path.starts_with("attachments/Second/"));
            }
        }
        record.entries.retain(|e| e.type_name != "file/v1");
        let expected = plain.items[index].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            record.encode_content(MAX_OPEN_MEMORY).unwrap().bytes,
            expected.encode_content(MAX_OPEN_MEMORY).unwrap().bytes
        );
    }
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let files: Vec<_> = record
        .entries
        .iter()
        .filter(|e| e.type_name == "file/v1")
        .collect();
    assert_eq!(
        files.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        ["scanpart.txt", "scanpart_1.txt", "résumé.txt"]
    );
    assert_eq!(files[1].value["data"], Value::Binary(Vec::new()));
}

#[test]
fn producer_collisions_block_the_container_without_guessing_ownership() {
    for input in [
        include_bytes!("import_fixtures/bitwarden_zip/duplicate.zip").as_slice(),
        include_bytes!("import_fixtures/bitwarden_zip/sanitize.zip").as_slice(),
        include_bytes!("import_fixtures/bitwarden_zip/suffix.zip").as_slice(),
    ] {
        let plan = parse(input);
        assert_eq!(plan.container_status, Status::Blocked);
        assert!(
            plan.container_diagnostics
                .iter()
                .any(|d| d.code == Code::UnresolvedFieldReference)
        );
        let attrs = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
        assert!(
            matches!(&attrs["bitwarden.zip.unresolved"], Value::Array(values) if !values.is_empty())
        );
        assert!(plan.items.iter().all(|item| {
            item.record(MAX_OPEN_MEMORY)
                .unwrap()
                .entries
                .iter()
                .all(|e| e.type_name != "file/v1")
        }));
    }
}

#[test]
fn skipped_download_is_blocked_and_restricted_orphan_cannot_disappear() {
    let skipped = parse(include_bytes!("import_fixtures/bitwarden_zip/skipped.zip"));
    assert_eq!(skipped.items[0].status, Status::Blocked);
    assert!(
        skipped.items[0]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::MissingAttachment)
    );
    let orphan = parse(include_bytes!(
        "import_fixtures/bitwarden_zip/restricted.zip"
    ));
    assert!(orphan.items.is_empty());
    assert_eq!(orphan.container_status, Status::Blocked);
    assert!(
        orphan
            .container_diagnostics
            .iter()
            .any(|d| d.code == Code::MissingAttachment)
    );
}

#[test]
fn extra_paths_and_nested_attachment_layouts_are_explicitly_blocked() {
    for path in [
        "unknown.bin",
        "attachments/Unique/nested/file.txt",
        "attachments/Unknown/file.txt",
    ] {
        let input = archive(&[("data.json", DOCUMENT), (path, b"public")]);
        let plan = parse(&input);
        assert_eq!(plan.container_status, Status::Blocked);
        let attrs = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
        assert!(
            matches!(&attrs["bitwarden.zip.unresolved"], Value::Array(values)
            if values.contains(&Value::from(path)))
        );
    }
}

#[test]
fn suffix_like_real_names_are_unambiguous_when_no_duplicate_source_name_exists() {
    let json = br#"{"encrypted":false,"items":[{"id":"a","type":2,"name":"Name"},{"id":"b","type":2,"name":"Name_1"}]}"#;
    let input = archive(&[
        ("data.json", json),
        ("attachments/Name_1/file.txt", b"public"),
    ]);
    let plan = parse(&input);
    assert_ne!(plan.container_status, Status::Blocked);
    let a = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let b = plan.items[1].record(MAX_OPEN_MEMORY).unwrap();
    assert!(a.entries.iter().all(|e| e.type_name != "file/v1"));
    assert!(b.entries.iter().any(|e| e.type_name == "file/v1"));
}

#[test]
fn ownership_prepass_decodes_names_and_applies_the_producer_underscore_rules() {
    let json =
        br#"{"encrypted":false,"items":[{"id":"a","type":2,"name":"a___/b\u0020\u6771\u4eac"}]}"#;
    let input = archive(&[
        ("data.json", json),
        ("attachments/a_b 東京/file.txt", b"public"),
    ]);
    let plan = parse(&input);
    assert_ne!(plan.container_status, Status::Blocked);
    assert!(
        plan.items[0]
            .record(MAX_OPEN_MEMORY)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.type_name == "file/v1")
    );
}

#[test]
fn organization_encrypted_and_missing_documents_are_not_claimed_as_individual_zip() {
    for json in [
        br#"{"encrypted":false,"collections":[],"items":[]}"#.as_slice(),
        br#"{"encrypted":true,"items":[]}"#.as_slice(),
    ] {
        let input = archive(&[("data.json", json)]);
        assert_eq!(
            run(&input, Limits::default()).err().unwrap().kind,
            ErrorKind::UnsupportedFormat
        );
    }
    assert_eq!(
        run(&archive(&[("other.json", DOCUMENT)]), Limits::default())
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsupportedFormat
    );
}

#[test]
fn shared_json_validation_is_kept_at_the_zip_boundary() {
    for (json, error) in [
        (br#"{"encrypted":false,"items":[],"items":[]}"#.as_slice(), ErrorKind::DuplicateKey),
        (br#"{"encrypted":false,"items":[{"name":null}]}"#.as_slice(), ErrorKind::Malformed),
        (br#"{"encrypted":false,"items":[{"name":"x","id":"a","type":2},{"name":"y","id":"a","type":2}]}"#.as_slice(), ErrorKind::AmbiguousFormat),
    ] {
        assert_eq!(run(&archive(&[("data.json", json)]), Limits::default()).err().unwrap().kind, error);
    }
}

#[test]
fn crc_truncation_duplicate_and_unsafe_paths_fail_before_apply() {
    let mut corrupt = archive(&[
        ("data.json", DOCUMENT),
        ("attachments/Unique/file.txt", b"AABB"),
    ]);
    let offset = corrupt.windows(4).position(|w| w == b"AABB").unwrap();
    corrupt[offset] ^= 1;
    assert_eq!(
        run(&corrupt, Limits::default()).err().unwrap().kind,
        ErrorKind::Checksum
    );
    for end in [0, 10, PERSONAL.len() - 1] {
        assert!(run(&PERSONAL[..end], Limits::default()).is_err());
    }
    let unsafe_zip = archive(&[
        ("data.json", DOCUMENT),
        ("attachments/../escape", b"public"),
    ]);
    assert_eq!(
        run(&unsafe_zip, Limits::default()).err().unwrap().kind,
        ErrorKind::InvalidPath
    );
    let mut duplicate = archive(&[
        ("data.json", DOCUMENT),
        ("extra-a", b"a"),
        ("extra-b", b"b"),
    ]);
    for offset in (0..duplicate.len() - 6).rev() {
        if &duplicate[offset..offset + 7] == b"extra-b" {
            duplicate[offset + 6] = b'a';
        }
    }
    assert_eq!(
        run(&duplicate, Limits::default()).err().unwrap().kind,
        ErrorKind::DuplicatePath
    );
}

#[test]
fn archive_and_record_budgets_include_all_files_and_cancellation() {
    let input = archive(&[
        ("data.json", DOCUMENT),
        ("attachments/Unique/file", b"public"),
    ]);
    for limits in [
        Limits {
            unpacked_bytes: DOCUMENT.len(),
            ..Limits::default()
        },
        Limits {
            zip_entries: 1,
            ..Limits::default()
        },
        Limits {
            fields: 2,
            ..Limits::default()
        },
        Limits {
            plan_bytes: 10,
            ..Limits::default()
        },
    ] {
        assert_eq!(run(&input, limits).err().unwrap().kind, ErrorKind::Limit);
    }
    let result = import::prepare(
        Format::BitwardenZip,
        &input,
        &Options::default(),
        Limits::default(),
        &mut |p| p.phase != Phase::Read,
        bitwarden_zip::parse,
    );
    assert_eq!(result.err().unwrap().kind, ErrorKind::Canceled);
    let result = import::prepare(
        Format::BitwardenZip,
        &input,
        &Options::default(),
        Limits::default(),
        &mut |p| p.phase != Phase::Validate,
        bitwarden_zip::parse,
    );
    assert_eq!(result.err().unwrap().kind, ErrorKind::Canceled);
}

#[test]
fn compressed_record_cap_applies_to_the_sum_without_modifying_files() {
    let mut state = 0x0135_79bd_u32;
    let bytes: Vec<u8> = (0..2_100_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let input = archive(&[
        ("data.json", DOCUMENT),
        ("attachments/Unique/one", &bytes),
        ("attachments/Unique/two", &bytes),
    ]);
    assert_eq!(
        run(&input, Limits::default()).err().unwrap().kind,
        ErrorKind::Limit
    );
    let one = archive(&[("data.json", DOCUMENT), ("attachments/Unique/one", &bytes)]);
    let plan = parse(&one);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        record.entries.last().unwrap().value["data"],
        Value::Binary(bytes)
    );
}

#[test]
fn compressed_files_work_and_archive_bombs_are_rejected_before_allocation() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (path, bytes) in [
        ("data.json", DOCUMENT),
        ("attachments/Unique/file.png", b"public\0\xff".as_slice()),
    ] {
        writer.start_file(path, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    let input = writer.finish().unwrap().into_inner();
    let plan = parse(&input);
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let file = record.entries.last().unwrap();
    assert_eq!(file.type_name, "file/v1");
    assert_eq!(file.value["data"], Value::Binary(b"public\0\xff".to_vec()));
    let mut bomb = input;
    let central = bomb.windows(4).rposition(|w| w == b"PK\x01\x02").unwrap();
    bomb[central + 24..central + 28].copy_from_slice(&2_000_000_u32.to_le_bytes());
    assert_eq!(
        run(&bomb, Limits::default()).err().unwrap().kind,
        ErrorKind::Limit
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[path = "import_bitwarden_zip/app.rs"]
mod app;
