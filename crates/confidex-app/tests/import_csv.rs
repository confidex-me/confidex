#[path = "import_csv/load.rs"]
mod load;
use confidex_app::import::formats::csv::{self, Profile};
use confidex_app::import::{
    self, Code, CsvColumn, CsvMapping, Error, ErrorKind, Format, Limits, Options, Plan, Status,
};
use confidex_vault::record::Value;

const GENERIC: &[u8] = include_bytes!("import_fixtures/csv/generic.csv");
fn options(mapping: CsvMapping) -> Options {
    Options {
        source_instance: Some("public-fixture-source".into()),
        password: String::new(),
        keyfile: Vec::new(),
        password_present: false,
        keyfile_present: false,
        include_archived: false,
        include_deleted: false,
        csv: Some(mapping),
    }
}
fn plan(input: &[u8], mapping: CsvMapping) -> Result<Plan, Error> {
    import::prepare(
        Format::Csv,
        input,
        &options(mapping),
        Limits::default(),
        &mut |_| true,
        csv::parse,
    )
}
fn mapping(header: bool, delimiter: u8, columns: &[(usize, &str, &str)]) -> CsvMapping {
    CsvMapping {
        delimiter,
        header,
        columns: columns
            .iter()
            .map(|&(index, target, name)| CsvColumn {
                index,
                target: target.into(),
                name: name.into(),
            })
            .collect(),
    }
}
fn generic_mapping() -> CsvMapping {
    let source: serde_json::Value =
        serde_json::from_str(include_str!("import_fixtures/csv/mapping.json")).unwrap();
    CsvMapping {
        delimiter: source["delimiter"].as_str().unwrap().as_bytes()[0],
        header: source["header"].as_bool().unwrap(),
        columns: source["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| CsvColumn {
                index: c["index"].as_u64().unwrap() as usize,
                target: c["target"].as_str().unwrap().into(),
                name: c["name"].as_str().unwrap_or("").into(),
            })
            .collect(),
    }
}
#[test]
fn a_small_csv_can_be_canceled_before_mapping_its_next_row() {
    let input = b"name,value\nFirst,one\nSecond,two\n";
    let next = input
        .windows(6)
        .position(|bytes| bytes == b"Second")
        .unwrap();
    let options = options(mapping(
        true,
        b',',
        &[(0, "title", ""), (1, "text/v1", "Value")],
    ));
    let mut boundary = false;
    let mut mapped_next = false;
    let mut callback = |progress: import::Progress| {
        mapped_next |= progress.phase == import::Phase::Map && progress.current >= next;
        if progress.phase == import::Phase::Read && progress.current == next {
            boundary = true;
            return false;
        }
        true
    };
    let limits = Limits::default();
    let mut context =
        import::Context::new(Format::Csv, input.len(), &options, limits, &mut callback).unwrap();
    let memory = context.memory().clone();
    let error = csv::parse(input, &mut context).unwrap_err();
    drop(context);
    assert_eq!(error.kind, ErrorKind::Canceled);
    assert!(boundary && !mapped_next);
    assert_eq!(memory.available(), limits.memory_bytes);
}
#[test]
fn generic_matches_reviewed_values_names_order_and_protection() {
    let parsed = plan(GENERIC, generic_mapping()).unwrap();
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("import_fixtures/csv/expected.json")).unwrap();
    assert_eq!(parsed.items.len(), 2);
    for (index, item) in parsed.items.iter().enumerate() {
        assert_eq!(item.status, Status::Ready);
        assert!(item.source.item.is_none());
        assert_eq!(item.source.locator, index);
        let actual = item.record(64 << 20).unwrap();
        let expected = &golden["records"][index]["record"];
        assert_eq!(
            actual.extra["confidex.title"].as_str(),
            expected["extra"]["confidex.title"].as_str()
        );
        assert_eq!(
            actual.entries.len(),
            expected["entries"].as_array().unwrap().len()
        );
        for (entry, expected) in actual
            .entries
            .iter()
            .zip(expected["entries"].as_array().unwrap())
        {
            assert_eq!(entry.name, expected["name"].as_str().unwrap());
            assert_eq!(entry.type_name, expected["type"].as_str().unwrap());
            for (key, value) in &entry.value {
                match value {
                    Value::String(s) => assert_eq!(s.as_str(), expected["value"][key].as_str()),
                    Value::Integer(n) => assert_eq!(n.as_u64(), expected["value"][key].as_u64()),
                    Value::Binary(b) => assert_eq!(b, b"12345678901234567890"),
                    _ => panic!("unexpected fixture value kind"),
                }
            }
            if entry.type_name == "secret/v1" {
                assert_eq!(entry.extra["metadata"]["protected"].as_bool(), Some(true));
            }
        }
        assert_eq!(
            item.source_attributes(64 << 20).unwrap()["row"].as_u64(),
            Some((index + 1) as u64)
        );
    }
    let empty = parsed.items[1].source_attributes(64 << 20).unwrap();
    assert_eq!(
        empty["empty_totp_columns"].as_array().unwrap()[0].as_u64(),
        Some(8)
    );
    let context = parsed.container_attributes(64 << 20).unwrap();
    assert_eq!(context["bom"].as_bool(), Some(true));
    let columns = context["columns"].as_array().unwrap();
    assert_eq!(
        columns[5]["source_name"].as_str(),
        columns[6]["source_name"].as_str()
    );
    assert_eq!(columns[7]["source_name"].as_str(), Some(""));
}
#[test]
fn verified_profiles_preserve_source_values_and_missing_source_capabilities() {
    for (input, profile, count) in [
        (
            include_bytes!("import_fixtures/csv/chromium-upstream.csv").as_slice(),
            Profile::Chromium,
            1,
        ),
        (
            include_bytes!("import_fixtures/csv/chromium-100.csv").as_slice(),
            Profile::Chromium,
            1,
        ),
        (
            include_bytes!("import_fixtures/csv/firefox.csv").as_slice(),
            Profile::Firefox,
            2,
        ),
        (
            include_bytes!("import_fixtures/csv/apple-passwords-upstream.csv").as_slice(),
            Profile::ApplePasswords,
            1,
        ),
        (
            include_bytes!("import_fixtures/csv/apple-passwords-legacy-upstream.csv").as_slice(),
            Profile::ApplePasswords,
            1,
        ),
    ] {
        let header = csv::header(input, b',', Limits::default(), &mut |_| true).unwrap();
        assert_eq!(header.profiles(), [profile]);
        let parsed = plan(input, profile.mapping(&header).unwrap()).unwrap();
        assert_eq!(parsed.items.len(), count);
        for item in &parsed.items {
            assert!(item.source.item.is_none());
            let record = item.record(64 << 20).unwrap();
            assert!(record.entries.iter().any(|e| e.type_name == "password/v1"));
            assert!(!record.entries.iter().any(|e| e.type_name == "file/v1"));
            assert!(!record.entries.iter().any(|e| e.type_name == "note/v1"));
        }
        if profile == Profile::Firefox {
            let attributes = parsed.items[0].source_attributes(64 << 20).unwrap();
            let empty = attributes["empty_cells"].as_array().unwrap();
            assert_eq!(empty[0].as_array().unwrap()[0].as_u64(), Some(3));
            assert_eq!(empty[0].as_array().unwrap()[1].as_bool(), Some(false));
            let record = parsed.items[1].record(64 << 20).unwrap();
            assert_eq!(
                record.entries[0].value["url"].as_str(),
                Some("https://service.example.invalid/日本語")
            );
            assert_eq!(
                record.entries[2].value["password"].as_str(),
                Some("PUBLIC-\"FIXTURE\"\r\nSECOND-LINE")
            );
            assert_eq!(record.entries[5].name, "guid");
            assert_eq!(record.entries[5].type_name, "secret/v1");
        }
    }
}
#[test]
fn unmapped_columns_stay_private_and_bad_totp_is_not_a_default_code() {
    let source =
        b"title,extra,extra,,otp\r\nPublic,one,PUBLIC-HIDDEN,,otpauth://hotp/Public?secret=MY\r\n";
    let parsed = plan(
        source,
        mapping(true, b',', &[(0, "title", ""), (4, "totp/v1", "otp")]),
    )
    .unwrap();
    let item = &parsed.items[0];
    assert_eq!(item.status, Status::Review);
    let record = item.record(64 << 20).unwrap();
    assert_eq!(
        record
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["extra", "extra", "", "otp"]
    );
    assert_eq!(record.entries[0].type_name, "secret/v1");
    assert_eq!(
        record.entries[1].value["secret"].as_str(),
        Some("PUBLIC-HIDDEN")
    );
    assert_eq!(record.entries[2].value["secret"].as_str(), Some(""));
    assert_eq!(record.entries[3].type_name, "secure-note/v1");
    assert!(
        item.diagnostics
            .iter()
            .any(|d| d.code == Code::UnsupportedFeature)
    );
    assert!(!record.entries.iter().any(|e| e.type_name == "totp/v1"));
}
#[test]
fn manual_mapping_reset_and_no_header_preserve_values() {
    let source = b"alice;PUBLIC-FIXTURE;\"line\r\nsecond\";https://example.invalid/a?x=1&x=2";
    let first = plan(
        source,
        mapping(
            false,
            b';',
            &[
                (0, "username/v1", "User"),
                (1, "password/v1", "Password"),
                (2, "secure-note/v1", "Notes"),
                (3, "url/v1", "URL"),
            ],
        ),
    )
    .unwrap();
    let record = first.items[0].record(64 << 20).unwrap();
    assert_eq!(record.entries.len(), 4);
    assert_eq!(
        record.entries[2].value["text"].as_str(),
        Some("line\r\nsecond")
    );
    assert_eq!(
        record.entries[3].value["url"].as_str(),
        Some("https://example.invalid/a?x=1&x=2")
    );
    let second = plan(
        source,
        mapping(
            false,
            b';',
            &[
                (0, "text/v1", ""),
                (1, "secret/v1", ""),
                (2, "note/v1", "Public note"),
                (3, "url/v1", "URL"),
            ],
        ),
    )
    .unwrap();
    let changed = second.items[0].record(64 << 20).unwrap();
    assert_eq!(changed.entries[2].type_name, "note/v1");
    assert_eq!(changed.entries[2].value, record.entries[2].value);
    assert_eq!(changed.entries[0].name, changed.entries[1].name);
    assert_eq!(record.entries[2].type_name, "secure-note/v1");
    assert_eq!(
        first.items[0].source_attributes(64 << 20).unwrap()["row"].as_u64(),
        Some(0)
    );
}
#[test]
fn malformed_rows_options_and_cancellation_return_no_plan() {
    for source in [
        b"a,b\n1".as_slice(),
        b"a,b\n1,2,3",
        b"a,b\n1,\"broken",
        b"a,b\n1,\"closed\"tail",
        b"a,b\n1,quote\"",
        b"a,b\n1,\xff",
        b"a,b\n1,\0",
    ] {
        assert!(plan(source, mapping(true, b',', &[])).is_err());
    }
    for columns in [
        vec![(2, "text/v1", "")],
        vec![(0, "title", ""), (1, "title", "")],
        vec![(0, "text/v1", ""), (0, "secret/v1", "")],
        vec![(0, "ignore", "")],
    ] {
        assert_eq!(
            plan(b"a,b\n1,2", mapping(true, b',', &columns))
                .err()
                .unwrap()
                .kind,
            ErrorKind::InvalidOptions
        );
    }
    let source = b"a,b\n1,2\n3,4";
    for phase in [
        import::Phase::Read,
        import::Phase::Map,
        import::Phase::Validate,
    ] {
        let error = import::prepare(
            Format::Csv,
            source,
            &options(mapping(true, b',', &[])),
            Limits::default(),
            &mut |p| p.phase != phase,
            csv::parse,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ErrorKind::Canceled);
    }
    for limits in [
        Limits {
            input_bytes: 3,
            ..Limits::default()
        },
        Limits {
            fields: 1,
            ..Limits::default()
        },
        Limits {
            nodes: 3,
            ..Limits::default()
        },
        Limits {
            memory_bytes: 1024,
            ..Limits::default()
        },
        Limits {
            plan_bytes: 1,
            ..Limits::default()
        },
        Limits {
            records: 1,
            ..Limits::default()
        },
    ] {
        let error = import::prepare(
            Format::Csv,
            source,
            &options(mapping(true, b',', &[])),
            limits,
            &mut |_| true,
            csv::parse,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ErrorKind::Limit);
    }
}
#[test]
fn title_only_and_header_only_inputs_keep_their_source_context() {
    let parsed = plan(b"Title\nPublic", mapping(true, b',', &[(0, "title", "")])).unwrap();
    assert!(parsed.items[0].record(64 << 20).unwrap().entries.is_empty());
    let parsed = plan(b"a,a,", mapping(true, b',', &[])).unwrap();
    assert!(parsed.items.is_empty());
    assert_eq!(
        parsed.container_attributes(64 << 20).unwrap()["columns"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[path = "import_csv/apply.rs"]
mod apply;

#[test]
fn header_inspection_is_bounded_and_does_not_certify_unread_rows() {
    let header = csv::header(
        b"\xef\xbb\xbfa,a,,\"n\r\nm\"\r\n\"broken",
        b',',
        Limits::default(),
        &mut |_| true,
    )
    .unwrap();
    assert_eq!(
        header
            .names()
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        ["a", "a", "", "n\r\nm"]
    );
    assert_eq!(header.delimiter(), b',');
    assert!(header.profiles().is_empty());
    assert!(plan(b"a\n\"broken", mapping(true, b',', &[])).is_err());
    for limits in [
        Limits {
            name_bytes: 2,
            ..Limits::default()
        },
        Limits {
            memory_bytes: 10,
            ..Limits::default()
        },
        Limits {
            string_bytes: 2,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            csv::header(b"long,name", b',', limits, &mut |_| true)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Limit
        );
    }
    assert_eq!(
        csv::header(b"name", b',', Limits::default(), &mut |_| false)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Canceled
    );
    assert_eq!(
        csv::header(&[0xff, 0xfe, 0, 0], b',', Limits::default(), &mut |_| true)
            .err()
            .unwrap()
            .kind,
        ErrorKind::UnsupportedEncoding
    );
}

#[test]
fn canonical_plans_match_native_and_wasm() {
    use sha2::{Digest, Sha256};
    for (label, input, profile) in [
        ("generic", GENERIC, None),
        (
            "chromium",
            include_bytes!("import_fixtures/csv/chromium-upstream.csv").as_slice(),
            Some(Profile::Chromium),
        ),
        (
            "chromium-100",
            include_bytes!("import_fixtures/csv/chromium-100.csv").as_slice(),
            Some(Profile::Chromium),
        ),
        (
            "firefox",
            include_bytes!("import_fixtures/csv/firefox.csv").as_slice(),
            Some(Profile::Firefox),
        ),
        (
            "apple",
            include_bytes!("import_fixtures/csv/apple-passwords-upstream.csv").as_slice(),
            Some(Profile::ApplePasswords),
        ),
        (
            "apple-legacy",
            include_bytes!("import_fixtures/csv/apple-passwords-legacy-upstream.csv").as_slice(),
            Some(Profile::ApplePasswords),
        ),
    ] {
        let mapping = if let Some(profile) = profile {
            profile
                .mapping(&csv::header(input, b',', Limits::default(), &mut |_| true).unwrap())
                .unwrap()
        } else {
            generic_mapping()
        };
        let parsed = plan(input, mapping).unwrap();
        let mut hash = Sha256::new();
        hash.update(parsed.container_attributes_bytes().unwrap());
        hash.update(serde_json::to_vec(&parsed.container_status).unwrap());
        hash.update(serde_json::to_vec(&parsed.container_diagnostics).unwrap());
        for item in &parsed.items {
            hash.update(item.record_bytes());
            hash.update(item.source_attributes_bytes());
            hash.update(serde_json::to_vec(&item.source).unwrap());
            hash.update(serde_json::to_vec(&item.status).unwrap());
            hash.update(serde_json::to_vec(&item.diagnostics).unwrap());
        }
        let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        println!("csv-plan-{label}={digest}");
    }
}

#[test]
fn large_text_obeys_the_whole_record_compressed_cap() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut state = 0x4353565055424c49u64;
    let bytes: Vec<u8> = (0..4_100_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    for (size, fits) in [(3_900_000, true), (4_100_000, false)] {
        let encoded = STANDARD.encode(&bytes[..size]);
        let chunks = encoded
            .as_bytes()
            .chunks(700_000)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>();
        let names = (0..chunks.len())
            .map(|n| format!("Data{n}"))
            .collect::<Vec<_>>();
        let source = format!("{}\n{}", names.join(","), chunks.join(","));
        let columns = names
            .iter()
            .enumerate()
            .map(|(index, name)| CsvColumn {
                index,
                name: name.clone(),
                target: "secret/v1".into(),
            })
            .collect();
        let result = plan(
            source.as_bytes(),
            CsvMapping {
                delimiter: b',',
                header: true,
                columns,
            },
        );
        if fits {
            let parsed = result.unwrap();
            let record = parsed.items[0].record(64 << 20).unwrap();
            assert_eq!(record.entries.len(), chunks.len());
            for (entry, expected) in record.entries.iter().zip(chunks) {
                assert_eq!(entry.value["secret"].as_str(), Some(expected));
            }
        } else {
            assert_eq!(result.err().unwrap().kind, ErrorKind::Limit);
        }
    }
    let source = format!(
        "Data\n{}",
        "x".repeat(confidex_vault::encoding::CONTENT_LIMITS.string + 1)
    );
    let error = plan(
        source.as_bytes(),
        mapping(true, b',', &[(0, "secret/v1", "Data")]),
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::Limit);
    assert!(error.location.offset.is_some());
}

#[test]
#[ignore = "Run separately for native/WASM parser memory calibration"]
fn ten_thousand_rows_use_a_bounded_plan() {
    let source = load::source();
    let started = std::time::Instant::now();
    let parsed = load::plan(source.as_bytes());
    assert_eq!(parsed.items.len(), 10_000);
    assert_eq!(parsed.statistics.ready, 10_000);
    let last = parsed.items[9999].record(64 << 20).unwrap();
    assert_eq!(last.entries.len(), 10);
    assert_eq!(last.entries[9].value["secret"].as_str(), Some("SECRET9999"));
    assert_eq!(last.entries[6].value["text"].as_str(), Some(""));
    assert_eq!(last.entries[7].type_name, "totp/v1");
    println!(
        "csv-10k input_bytes={} plan_bytes={} retained_accounted_bytes={} elapsed_ms={}",
        source.len(),
        parsed.statistics.encoded_bytes,
        Limits::default().memory_bytes - parsed.memory().available(),
        started.elapsed().as_millis()
    );
}

#[test]
fn no_header_inspection_does_not_expose_or_limit_data_as_column_names() {
    let input = format!("alice,{}", "P".repeat(5000));
    assert_eq!(
        csv::column_count(input.as_bytes(), b',', Limits::default(), &mut |_| true).unwrap(),
        2
    );
    assert_eq!(
        csv::header(input.as_bytes(), b',', Limits::default(), &mut |_| true)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Limit
    );
    let parsed = plan(
        input.as_bytes(),
        mapping(
            false,
            b',',
            &[(0, "username/v1", "User"), (1, "password/v1", "Password")],
        ),
    )
    .unwrap();
    assert_eq!(
        parsed.items[0].record(64 << 20).unwrap().entries[1].value["password"]
            .as_str()
            .unwrap()
            .len(),
        5000
    );
    assert_eq!(
        csv::column_count(input.as_bytes(), b',', Limits::default(), &mut |_| false)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Canceled
    );
}

#[test]
fn multiple_urls_and_repeated_empty_names_stay_independent() {
    let input =
        "a,a,\r\nhttps://one.example.invalid/a?x=1&x=2,https://two.example.invalid/日本語,\r\n";
    let parsed = plan(
        input.as_bytes(),
        mapping(
            true,
            b',',
            &[
                (0, "url/v1", "Site"),
                (1, "url/v1", "Site"),
                (2, "text/v1", ""),
            ],
        ),
    )
    .unwrap();
    let record = parsed.items[0].record(64 << 20).unwrap();
    assert_eq!(
        record
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["Site", "Site", ""]
    );
    assert_eq!(
        record.entries[0].value["url"].as_str(),
        Some("https://one.example.invalid/a?x=1&x=2")
    );
    assert_eq!(
        record.entries[1].value["url"].as_str(),
        Some("https://two.example.invalid/日本語")
    );
    assert_eq!(record.entries[2].value["text"].as_str(), Some(""));
}

#[test]
fn additional_fixture_bytes_match_the_reviewed_manifest() {
    use sha2::{Digest, Sha256};
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("import_fixtures/csv/sources.json")).unwrap();
    for (name, bytes) in [
        (
            "chromium-upstream.csv",
            include_bytes!("import_fixtures/csv/chromium-upstream.csv").as_slice(),
        ),
        (
            "chromium-100.csv",
            include_bytes!("import_fixtures/csv/chromium-100.csv").as_slice(),
        ),
        (
            "firefox.csv",
            include_bytes!("import_fixtures/csv/firefox.csv").as_slice(),
        ),
        (
            "apple-passwords-upstream.csv",
            include_bytes!("import_fixtures/csv/apple-passwords-upstream.csv").as_slice(),
        ),
        (
            "apple-passwords-legacy-upstream.csv",
            include_bytes!("import_fixtures/csv/apple-passwords-legacy-upstream.csv").as_slice(),
        ),
    ] {
        let expected = manifest["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["file"].as_str() == Some(name))
            .unwrap();
        let hash: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hash, expected["sha256"].as_str().unwrap(), "{name}");
    }
}
