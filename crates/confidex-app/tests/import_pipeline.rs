use confidex_app::import::{
    self, Context, Error, ErrorKind, Format, Item, Limits, Options, Phase, Source, Status,
};
use confidex_vault::{
    record::{Entry, Mapping, Record},
    resources::MAX_OPEN_MEMORY,
};

fn item() -> Item {
    let mut source = Source::default();
    source.item = Some("fixture-id".into());
    Item {
        source,
        record: Record {
            entries: vec![Entry {
                name: "secret".into(),
                type_name: "password/v1".into(),
                value: Mapping::from([("password".into(), "synthetic-secret".into())]),
                extra: Mapping::new(),
            }],
            tags: Vec::new(),
            extra: Mapping::new(),
        },
        source_attributes: Mapping::from([("original".into(), "synthetic-source".into())]),
        status: Status::Ready,
        diagnostics: Vec::new(),
    }
}
fn parse(_input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    context.push(item())
}
#[test]
fn plan_preserves_core_and_source_attributes() {
    let mut options = Options::default();
    options.source_instance = Some("fixture-source".into());
    let plan = import::prepare(
        Format::BitwardenJson,
        b"fixture",
        &options,
        Limits::default(),
        &mut |_| true,
        parse,
    )
    .unwrap();
    assert_eq!(plan.statistics.ready, 1);
    assert!(plan.items[0].source.has_scoped_id());
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries[0].name, "secret");
    assert_eq!(
        record.entries[0].value["password"].as_str(),
        Some("synthetic-secret")
    );
    let mut attributes = Record::default();
    attributes.extra = plan.items[0].source_attributes(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        attributes.extra["original"].as_str(),
        Some("synthetic-source")
    );
}
#[test]
fn missing_scope_requires_review_and_cancellation_returns_no_plan() {
    let plan = import::prepare(
        Format::BitwardenJson,
        b"",
        &Options::default(),
        Limits::default(),
        &mut |_| true,
        parse,
    )
    .unwrap();
    assert_eq!(plan.statistics.review, 1);
    let result = import::prepare(
        Format::BitwardenJson,
        b"",
        &Options::default(),
        Limits::default(),
        &mut |p| p.phase != Phase::Validate,
        parse,
    );
    assert_eq!(result.err().unwrap().kind, ErrorKind::Canceled);
}
fn check_json(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    let document = import::json::Document::parse(input, context)?;
    let root = import::json::object(document.raw(), context)?;
    let array = import::json::array(root.get("items").ok_or(ErrorKind::Malformed)?)?;
    for value in array {
        let value = import::json::owned(value?, context)?;
        assert!(value.is_object());
    }
    Ok(())
}
#[test]
fn json_borrows_items_and_rejects_duplicate_decoded_keys() {
    let run = |input: &[u8]| {
        import::prepare(
            Format::BitwardenJson,
            input,
            &Options::default(),
            Limits::default(),
            &mut |_| true,
            check_json,
        )
    };
    assert!(run(br#"{"items":[{"secret":"synthetic"},{"secret":"different"}]}"#).is_ok());
    assert_eq!(
        run(br#"{"items":[],"it\u0065ms":[]}"#).err().unwrap().kind,
        ErrorKind::DuplicateKey
    );
    assert_eq!(
        run(br#"{"items":[{"secret":"synthetic","secret":"different"}]}"#)
            .err()
            .unwrap()
            .kind,
        ErrorKind::DuplicateKey
    );
    assert!(run(br#"{"items":[{}],}"#).is_err());
}
fn read_zip(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    let mut archive = import::archive::Archive::open(input, context)?;
    let index = archive.index("export.data").ok_or(ErrorKind::Malformed)?;
    let buffer = archive.read(index, context)?;
    assert_eq!(&*buffer, b"synthetic\0\xff");
    Ok(())
}
fn zip(name: &str) -> Vec<u8> {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"synthetic\0\xff").unwrap();
    writer.finish().unwrap().into_inner()
}
#[test]
fn zip_checks_crc_paths_and_truncation() {
    let run = |input: &[u8]| {
        import::prepare(
            Format::Onepassword1pux,
            input,
            &Options::default(),
            Limits::default(),
            &mut |_| true,
            read_zip,
        )
    };
    let mut valid = zip("export.data");
    assert!(run(&valid).is_ok());
    assert_eq!(
        run(&zip("../export.data")).err().unwrap().kind,
        ErrorKind::InvalidPath
    );
    assert!(run(&valid[..valid.len() - 1]).is_err());
    let position = valid.windows(9).position(|w| w == b"synthetic").unwrap();
    valid[position] ^= 1;
    assert!(run(&valid).is_err());
}

fn validate_archive(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    let mut archive = import::archive::Archive::open(input, context)?;
    for index in 0..archive.len() {
        if !archive.names().nth(index).unwrap().ends_with('/') {
            let _bytes = archive.read(index, context)?;
        }
    }
    Ok(())
}
fn archive_result(input: &[u8], limits: Limits) -> Result<import::Plan, Error> {
    import::prepare(
        Format::Onepassword1pux,
        input,
        &Options::default(),
        limits,
        &mut |_| true,
        validate_archive,
    )
}
fn multi_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
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
fn central(input: &[u8]) -> Vec<usize> {
    input
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"PK\x01\x02")
        .map(|(i, _)| i)
        .collect()
}
#[test]
fn archive_rejects_duplicate_paths_special_files_encryption_and_bombs() {
    let mut duplicate = multi_zip(&[("a.txt", b"a"), ("b.txt", b"b")]);
    let positions: Vec<_> = duplicate
        .windows(5)
        .enumerate()
        .filter(|(_, w)| *w == b"b.txt")
        .map(|(i, _)| i)
        .collect();
    for position in positions {
        duplicate[position] = b'a';
    }
    assert_eq!(
        archive_result(&duplicate, Limits::default())
            .err()
            .unwrap()
            .kind,
        ErrorKind::DuplicatePath
    );
    for path in [
        "/absolute",
        "C:/drive",
        "x\\y",
        "x/../y",
        "x/./y",
        "x//y",
        "x\0y",
    ] {
        assert_eq!(
            archive_result(&zip(path), Limits::default())
                .err()
                .unwrap()
                .kind,
            ErrorKind::InvalidPath
        );
    }
    let original = zip("export.data");
    let cd = central(&original)[0];
    let mut symlink = original.clone();
    symlink[cd + 5] = 3;
    symlink[cd + 38..cd + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
    assert_eq!(
        archive_result(&symlink, Limits::default())
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidPath
    );
    let mut encrypted = original.clone();
    encrypted[cd + 8] |= 1;
    encrypted[6] |= 1;
    assert_eq!(
        archive_result(&encrypted, Limits::default())
            .err()
            .unwrap()
            .kind,
        ErrorKind::EncryptedArchive
    );
    let mut bomb = original.clone();
    bomb[cd + 24..cd + 28].copy_from_slice(&(2_000_000u32).to_le_bytes());
    assert_eq!(
        archive_result(&bomb, Limits::default()).err().unwrap().kind,
        ErrorKind::Limit
    );
    let mut unsupported = original.clone();
    unsupported[cd + 10..cd + 12].copy_from_slice(&12u16.to_le_bytes());
    assert_eq!(
        archive_result(&unsupported, Limits::default())
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsupportedCompression
    );
    let limits = Limits {
        zip_entries: 1,
        ..Limits::default()
    };
    assert_eq!(
        archive_result(&multi_zip(&[("a", b""), ("b", b"")]), limits)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Limit
    );
}
#[test]
fn archive_rejects_overlapping_local_headers() {
    let inner = zip("inner");
    let embedded = &inner[..central(&inner)[0]];
    let mut overlapping = multi_zip(&[("outer", embedded), ("inner", b"synthetic\0\xff")]);
    let headers = central(&overlapping);
    let data_start = 30
        + u16::from_le_bytes(overlapping[26..28].try_into().unwrap()) as usize
        + u16::from_le_bytes(overlapping[28..30].try_into().unwrap()) as usize;
    overlapping[headers[1] + 42..headers[1] + 46]
        .copy_from_slice(&(data_start as u32).to_le_bytes());
    assert_eq!(
        archive_result(&overlapping, Limits::default())
            .err()
            .unwrap()
            .kind,
        ErrorKind::ArchiveOverlap
    );
}
#[test]
fn archive_accepts_small_zip64_and_rejects_forged_zip64_offsets() {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "export.data",
            zip::write::SimpleFileOptions::default().large_file(true),
        )
        .unwrap();
    writer.write_all(b"synthetic\0\xff").unwrap();
    let valid = writer.finish().unwrap().into_inner();
    assert!(archive_result(&valid, Limits::default()).is_ok());
    // Replace only the archive footer with an actual ZIP64 directory locator.
    let end = valid.len() - 22;
    let directory_size = u32::from_le_bytes(valid[end + 12..end + 16].try_into().unwrap());
    let directory_offset = u32::from_le_bytes(valid[end + 16..end + 20].try_into().unwrap());
    let mut zip64 = valid[..end].to_vec();
    zip64.extend_from_slice(b"PK\x06\x06");
    zip64.extend_from_slice(&44u64.to_le_bytes());
    zip64.extend_from_slice(&[45, 0, 45, 0]);
    zip64.extend_from_slice(&[0; 8]);
    zip64.extend_from_slice(&1u64.to_le_bytes());
    zip64.extend_from_slice(&1u64.to_le_bytes());
    zip64.extend_from_slice(&(directory_size as u64).to_le_bytes());
    zip64.extend_from_slice(&(directory_offset as u64).to_le_bytes());
    let locator = zip64.len();
    zip64.extend_from_slice(b"PK\x06\x07");
    zip64.extend_from_slice(&0u32.to_le_bytes());
    zip64.extend_from_slice(&(end as u64).to_le_bytes());
    zip64.extend_from_slice(&1u32.to_le_bytes());
    zip64.extend_from_slice(&valid[end..]);
    let footer = zip64.len() - 22;
    zip64[footer + 8..footer + 12].fill(0xff);
    zip64[footer + 12..footer + 20].fill(0xff);
    assert!(archive_result(&zip64, Limits::default()).is_ok());
    zip64[locator + 8..locator + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(archive_result(&zip64, Limits::default()).is_err());
}
#[test]
fn inspect_uses_contents_and_requires_csv_confirmation() {
    let inspect = |input: &[u8]| import::inspect(input, Limits::default(), &mut |_| true);
    assert_eq!(
        inspect(include_bytes!(
            "import_fixtures/bitwarden_json/personal.json"
        ))
        .unwrap()
        .candidates,
        vec![Format::BitwardenJson]
    );
    assert_eq!(
        inspect(include_bytes!(
            "import_fixtures/onepassword_1pux/account.1pux"
        ))
        .unwrap()
        .candidates,
        vec![Format::Onepassword1pux]
    );
    assert_eq!(
        inspect(include_bytes!("import_fixtures/keepass_xml/database.xml"))
            .unwrap()
            .candidates,
        vec![Format::KeepassXml]
    );
    assert!(
        inspect(include_bytes!("import_fixtures/csv/generic.csv"))
            .unwrap()
            .confirmation_required
    );
    assert_eq!(
        inspect(&zip("vault/locks/lock.sealed")).unwrap_err().kind,
        ErrorKind::OwnBackup
    );
    assert!(inspect(br#"<!DOCTYPE KeePassFile [<!ENTITY x SYSTEM "file:///secret">]><KeePassFile>&x;</KeePassFile>"#).is_err());
    assert!(inspect(b"<KeePassFile><Root></KeePassFile>").is_err());
    assert!(
        inspect(b"PK,name\nvalue,other")
            .unwrap()
            .confirmation_required
    );
    assert!(inspect(b"<KeePassFile>&#0;</KeePassFile>").is_err());
    let mixed = multi_zip(&[
        ("export.attributes", b"{}"),
        ("export.data", b"{}"),
        ("data.json", br#"{"items":[],"folders":[]}"#),
    ]);
    let inspected = inspect(&mixed).unwrap();
    assert_eq!(inspected.candidates.len(), 2);
    assert!(inspected.confirmation_required);
}
#[test]
fn json_limits_apply_before_dom_and_raw_numbers_remain_exact() {
    fn raw(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        let document = import::json::Document::parse(input, context)?;
        let object = import::json::object(document.raw(), context)?;
        assert_eq!(
            object.get("unknown").unwrap().get(),
            "123456789012345678901234567890"
        );
        Ok(())
    }
    assert!(
        import::prepare(
            Format::BitwardenJson,
            br#"{"unknown":123456789012345678901234567890}"#,
            &Options::default(),
            Limits::default(),
            &mut |_| true,
            raw
        )
        .is_ok()
    );
    fn validate(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        import::json::Document::parse(input, context).map(|_| ())
    }
    let run = |input: &[u8], limits| {
        import::prepare(
            Format::BitwardenJson,
            input,
            &Options::default(),
            limits,
            &mut |_| true,
            validate,
        )
    };
    let mut limits = Limits {
        depth: 2,
        ..Limits::default()
    };
    assert_eq!(run(b"[[[]]]", limits).err().unwrap().kind, ErrorKind::Limit);
    limits = Limits::default();
    limits.string_bytes = 3;
    assert_eq!(
        run(br#"["long"]"#, limits).err().unwrap().kind,
        ErrorKind::Limit
    );
    limits = Limits::default();
    limits.nodes = 2;
    assert_eq!(
        run(b"[1,2,3]", limits).err().unwrap().kind,
        ErrorKind::Limit
    );
    limits = Limits::default();
    limits.input_bytes = 2;
    assert_eq!(run(b"[1]", limits).err().unwrap().kind, ErrorKind::Limit);
}

mod golden {
    include!("import_fixture_contract.rs");
    use confidex_app::import::{
        self, Context, Diagnostic, Error, Format, Item, Limits, Location, Options, Source,
    };
    use confidex_vault::resources::MAX_OPEN_MEMORY;

    fn record(input: &Json) -> Record {
        Record {
            entries: input["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| Entry {
                    name: e["name"].as_str().unwrap().into(),
                    type_name: e["type"].as_str().unwrap().into(),
                    value: mapping(&e["value"]),
                    extra: mapping(&e["extra"]),
                })
                .collect(),
            tags: input["tags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap().into())
                .collect(),
            extra: mapping(&input["extra"]),
        }
    }
    fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        let expected: Json = serde_json::from_slice(input).unwrap();
        for (locator, item) in expected["records"].as_array().unwrap().iter().enumerate() {
            let mut source = Source::default();
            source.instance = item["source"]["instance"].as_str().map(str::to_owned);
            source.account = item["source"]["account"].as_str().map(str::to_owned);
            source.vault = item["source"]["vault"].as_str().map(str::to_owned);
            source.item = item["source"]["item"].as_str().map(str::to_owned);
            source.locator = locator;
            context.push(Item {
                source,
                record: record(&item["record"]),
                source_attributes: mapping(&item["source_attributes"]),
                status: serde_json::from_value(item["status"].clone()).unwrap(),
                diagnostics: item["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| Diagnostic {
                        code: serde_json::from_value(c.clone()).unwrap(),
                        location: Location::default(),
                    })
                    .collect(),
            })?;
        }
        Ok(())
    }
    #[test]
    fn fixture_plans_preserve_all_fields_binary_protection_and_metadata() {
        for (text, format) in EXPECTED.iter().zip([
            Format::BitwardenJson,
            Format::BitwardenJson,
            Format::Onepassword1pux,
            Format::KeepassXml,
            Format::Csv,
        ]) {
            let plan = import::prepare(
                format,
                text.as_bytes(),
                &Options::default(),
                Limits::default(),
                &mut |_| true,
                parse,
            )
            .unwrap();
            let expected: Json = serde_json::from_str(text).unwrap();
            let items = expected["records"].as_array().unwrap();
            assert_eq!(plan.items.len(), items.len());
            for (actual, expected) in plan.items.iter().zip(items) {
                let a = actual
                    .record(MAX_OPEN_MEMORY)
                    .unwrap()
                    .encode_content(MAX_OPEN_MEMORY)
                    .unwrap();
                let e = record(&expected["record"])
                    .encode_content(MAX_OPEN_MEMORY)
                    .unwrap();
                assert_eq!(a.bytes, e.bytes);
                let mut attributes = Record::default();
                attributes.extra = actual.source_attributes(MAX_OPEN_MEMORY).unwrap();
                assert_eq!(attributes.extra, mapping(&expected["source_attributes"]));
                assert_eq!(
                    actual.status,
                    serde_json::from_value(expected["status"].clone()).unwrap()
                );
                assert_eq!(
                    actual.diagnostics.len(),
                    expected["diagnostics"].as_array().unwrap().len()
                );
                assert_eq!(
                    actual.source.instance.as_deref(),
                    Some("public-fixture-source")
                );
                assert_eq!(
                    actual.source.item.as_deref(),
                    expected["source"]["item"].as_str()
                );
            }
        }
    }
}
#[test]
fn cancellation_and_failure_release_shared_reservations() {
    let options = Options::default();
    let mut callback = |_| true;
    let mut context = Context::new(
        Format::BitwardenJson,
        64,
        &options,
        Limits::default(),
        &mut callback,
    )
    .unwrap();
    let before = context.memory().available();
    assert!(import::json::Document::parse(br#"{"unclosed": }"#, &mut context).is_err());
    assert_eq!(before, context.memory().available());
    assert!(import::archive::Archive::open(&zip("../escape"), &mut context).is_err());
    assert_eq!(before, context.memory().available());
    let memory = context.memory().clone();
    let temporary = context.reserve_work(100, 10).unwrap();
    assert!(memory.available() < before);
    drop(temporary);
    assert_eq!(memory.available(), before);
    drop(context);
    assert_eq!(memory.available(), Limits::default().memory_bytes);
    let mut callback = |p: import::Progress| p.phase != Phase::Read;
    assert_eq!(
        import::prepare(
            Format::BitwardenJson,
            br#"{"items":[]}"#,
            &options,
            Limits::default(),
            &mut callback,
            check_json
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Canceled
    );
}
#[test]
fn plan_rejects_invalid_values_and_compressed_core_overflow() {
    fn invalid(_: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        let mut invalid = item();
        invalid.record.entries[0].value.clear();
        context.push(invalid)
    }
    let error = import::prepare(
        Format::Csv,
        b"",
        &Options::default(),
        Limits::default(),
        &mut |_| true,
        invalid,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::InvalidRecord);
    assert_eq!(error.location.field, Some(0));
    fn too_large(_: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        let _work = context.reserve_work(4_100_000, 10)?;
        let mut state = 1u32;
        let bytes = (0..4_100_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let mut large = item();
        large.record.entries.clear();
        large.record.entries.push(Entry {
            name: "binary".into(),
            type_name: "file/v1".into(),
            value: Mapping::from([("data".into(), confidex_vault::record::Value::Binary(bytes))]),
            extra: Mapping::new(),
        });
        context.push(large)
    }
    assert_eq!(
        import::prepare(
            Format::Csv,
            b"",
            &Options::default(),
            Limits::default(),
            &mut |_| true,
            too_large
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Limit
    );
}
#[test]
#[ignore = "Run separately for native/WASM resource calibration"]
fn ten_thousand_items_use_a_bounded_encoded_plan() {
    use std::fmt::Write;
    let mut input = String::from("{\"items\":[");
    for index in 0..10_000 {
        if index != 0 {
            input.push(',');
        }
        write!(input, "{{\"id\":{index},\"fields\":[").unwrap();
        for field in 0..10 {
            if field != 0 {
                input.push(',');
            }
            write!(input, "\"synthetic-value-{index}-{field}\"").unwrap();
        }
        input.push_str("]}");
    }
    input.push_str("]}");
    fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        let document = import::json::Document::parse(input, context)?;
        let root = import::json::object(document.raw(), context)?;
        for (index, raw) in import::json::array(root.get("items").unwrap())?.enumerate() {
            context.checkpoint(Phase::Map, index, 10_000)?;
            let value = import::json::owned(raw?, context)?;
            let mut source = Source::default();
            source.item = Some(value["id"].to_string());
            source.locator = index;
            let record = Record {
                entries: value["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .map(|(i, v)| Entry {
                        name: format!("field-{i}"),
                        type_name: "text/v1".into(),
                        value: Mapping::from([("text".into(), v.as_str().unwrap().into())]),
                        extra: Mapping::new(),
                    })
                    .collect(),
                tags: Vec::new(),
                extra: Mapping::new(),
            };
            context.push(Item {
                source,
                record,
                source_attributes: Mapping::new(),
                status: Status::Ready,
                diagnostics: Vec::new(),
            })?;
        }
        Ok(())
    }
    let mut options = Options::default();
    options.source_instance = Some("synthetic-benchmark".into());
    let start = std::time::Instant::now();
    let plan = import::prepare(
        Format::Csv,
        input.as_bytes(),
        &options,
        Limits::default(),
        &mut |_| true,
        parse,
    )
    .unwrap();
    assert_eq!(plan.items.len(), 10_000);
    assert_eq!(plan.statistics.ready, 10_000);
    assert!(plan.statistics.encoded_bytes < 16 << 20);
    assert_eq!(
        plan.items[9999].record(MAX_OPEN_MEMORY).unwrap().entries[9].value["text"].as_str(),
        Some("synthetic-value-9999-9")
    );
    println!(
        "input_bytes={} plan_bytes={} elapsed_ms={}",
        input.len(),
        plan.statistics.encoded_bytes,
        start.elapsed().as_millis()
    );
}

#[test]
fn shared_container_metadata_is_retained_once_even_without_items() {
    fn parse(_: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        context.set_container_attributes(Mapping::from([
            ("entries".into(), "source entries".into()),
            ("tags".into(), "source tags".into()),
            ("groups".into(), "source groups".into()),
        ]))
    }
    let plan = import::prepare(
        Format::KeepassXml,
        b"",
        &Options::default(),
        Limits::default(),
        &mut |_| true,
        parse,
    )
    .unwrap();
    assert!(plan.items.is_empty());
    let mut attributes = Record::default();
    attributes.extra = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(attributes.extra["entries"].as_str(), Some("source entries"));
    assert_eq!(attributes.extra["tags"].as_str(), Some("source tags"));
    assert_eq!(attributes.extra.len(), 3);
    fn twice(_: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        context.set_container_attributes(Mapping::new())?;
        context.set_container_attributes(Mapping::new())
    }
    assert_eq!(
        import::prepare(
            Format::Csv,
            b"",
            &Options::default(),
            Limits::default(),
            &mut |_| true,
            twice
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::InvalidOptions
    );
}

#[test]
fn zip_preflight_handles_every_truncation_and_single_byte_mutation() {
    let valid = zip("export.data");
    for length in 0..valid.len() {
        assert!(archive_result(&valid[..length], Limits::default()).is_err());
    }
    for offset in 0..valid.len() {
        let mut changed = valid.clone();
        changed[offset] ^= 0x80;
        let _accepted_or_rejected = archive_result(&changed, Limits::default());
    }
}

#[test]
fn container_diagnostics_survive_empty_plans_and_cannot_lower_a_block() {
    fn parse(_: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        let diagnostic = import::Diagnostic {
            code: import::Code::UnsupportedFeature,
            location: import::Location::default(),
        };
        context.container_diagnostic(Status::Review, diagnostic)?;
        context.container_diagnostic(Status::Blocked, diagnostic)?;
        context.container_diagnostic(Status::Ready, diagnostic)
    }
    let plan = import::prepare(
        Format::Csv,
        b"",
        &Options::default(),
        Limits::default(),
        &mut |_| true,
        parse,
    )
    .unwrap();
    assert!(plan.items.is_empty());
    assert_eq!(plan.container_status, Status::Blocked);
    assert_eq!(plan.container_diagnostics.len(), 1);
    let memory = plan.memory().clone();
    drop(plan);
    assert_eq!(memory.available(), Limits::default().memory_bytes);
    fn too_many(_: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        context.container_diagnostic(
            Status::Review,
            import::Diagnostic {
                code: import::Code::SourceDataPreserved,
                location: import::Location::default(),
            },
        )?;
        context.container_diagnostic(
            Status::Review,
            import::Diagnostic {
                code: import::Code::UnsupportedFeature,
                location: import::Location::default(),
            },
        )
    }
    let limits = Limits {
        fields: 1,
        ..Limits::default()
    };
    assert_eq!(
        import::prepare(
            Format::Csv,
            b"",
            &Options::default(),
            limits,
            &mut |_| true,
            too_many
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Limit
    );
}

#[test]
fn title_only_records_keep_missing_fields_distinct_from_empty_values() {
    fn title_only(_: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
        for (id, status) in [
            ("public-ready", Status::Ready),
            ("public-review", Status::Review),
        ] {
            let mut item = item();
            item.source.item = Some(id.into());
            item.record.entries.clear();
            item.record
                .extra
                .insert("confidex.title".into(), "Public title-only fixture".into());
            item.status = status;
            context.push(item)?;
        }
        Ok(())
    }
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    let plan = import::prepare(
        Format::BitwardenJson,
        b"",
        &options,
        Limits::default(),
        &mut |_| true,
        title_only,
    )
    .unwrap();
    assert_eq!(plan.items.len(), 2);
    assert_eq!(plan.statistics.ready, 1);
    assert_eq!(plan.statistics.review, 1);
    for item in &plan.items {
        let record = item.record(MAX_OPEN_MEMORY).unwrap();
        assert!(record.entries.is_empty());
        assert_eq!(
            record.extra["confidex.title"].as_str(),
            Some("Public title-only fixture")
        );
        assert_eq!(
            item.source_attributes(MAX_OPEN_MEMORY).unwrap()["original"].as_str(),
            Some("synthetic-source")
        );
    }
}
