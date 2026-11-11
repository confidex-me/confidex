use confidex_app::import::formats::keepass_xml::parse;
use confidex_app::import::{Code, Error, Status};
use confidex_vault::record::Value;

use confidex_app::import::{self, Format, Limits, Options, Plan};
const SOURCE: &[u8] = include_bytes!("import_fixtures/keepass_xml/database.xml");
fn plan(source: &[u8], include_deleted: bool) -> Result<Plan, Error> {
    let mut options = Options::default();
    options.source_instance = Some("public-fixture-source".into());
    options.include_deleted = include_deleted;
    import::prepare(
        Format::KeepassXml,
        source,
        &options,
        Limits::default(),
        &mut |_| true,
        parse,
    )
}
fn database(entries: &str) -> String {
    format!(
        "<KeePassFile><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>fixture</Name>{entries}</Group></Root></KeePassFile>"
    )
}
fn source_entry(id: u8, fields: &str) -> String {
    use base64::Engine;
    let id = base64::engine::general_purpose::STANDARD.encode([id; 16]);
    format!("<Entry><UUID>{id}</UUID>{fields}</Entry>")
}
#[test]
fn complete_fixture_has_review_blocked_and_recycle_states() {
    let parsed = plan(SOURCE, false).unwrap();
    assert_eq!(parsed.items.len(), 3);
    assert_eq!(parsed.items[0].status, Status::Review);
    assert_eq!(parsed.items[1].status, Status::Blocked);
    assert_eq!(parsed.items[2].status, Status::Excluded);
    let last = parsed.items[2].record(96 << 20).unwrap();
    assert_eq!(last.tags, ["Work", "メール"]);
    assert!(
        parsed.items[1]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::UnresolvedFieldReference)
    );
    let container = parsed.container_attributes(96 << 20).unwrap();
    assert_eq!(container["groups"].as_array().unwrap().len(), 3);
    assert_eq!(container["meta"].as_array().unwrap().len(), 1);
    let included = plan(SOURCE, true).unwrap();
    assert_ne!(included.items[2].status, Status::Excluded);
}
#[test]
fn published_export_resolves_exact_binary_pool_data() {
    let source = include_bytes!("import_fixtures/keepass_xml/upstream-keepass.xml");
    let parsed = plan(source, false).unwrap();
    assert_eq!(parsed.items.len(), 4);
    let record = parsed.items[0].record(96 << 20).unwrap();
    let file = record
        .entries
        .iter()
        .find(|e| e.type_name == "file/v1")
        .unwrap();
    assert_eq!(file.value["filename"].as_str(), Some("myattach.txt"));
    assert!(matches!(&file.value["data"],Value::Binary(data) if data==b"abcdefghijk"));
    assert_eq!(parsed.items[3].status, Status::Excluded);
}
#[test]
fn empty_document_metadata_and_root_extensions_are_retained_once() {
    let source=database("").replace("<Root>","<Meta><Generator>public fixture</Generator><CustomData>PUBLIC-FIXTURE-META</CustomData></Meta><Extension>PUBLIC-FIXTURE-ROOT</Extension><Root>");
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert!(parsed.items.is_empty());
    let attributes = parsed.container_attributes(96 << 20).unwrap();
    assert!(
        matches!(&attributes["meta"].as_array().unwrap()[0],Value::Binary(data) if data.windows(b"PUBLIC-FIXTURE-META".len()).any(|s|s==b"PUBLIC-FIXTURE-META"))
    );
    assert_eq!(attributes["root_extra"].as_array().unwrap().len(), 1);
    let mut entries = String::new();
    for id in 1..=20 {
        entries.push_str(&source_entry(
            id,
            "<String><Key>Password</Key><Value>public fixture</Value></String>",
        ));
    }
    let source = database(&entries).replace(
        "<Root>",
        &format!(
            "<Meta><CustomData>{}</CustomData></Meta><Root>",
            "X".repeat(1 << 20)
        ),
    );
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(parsed.items.len(), 20);
    assert!(parsed.statistics.encoded_bytes < 2 << 20);
}
#[test]
fn title_only_entries_are_valid_empty_records() {
    let source = database(&source_entry(
        1,
        "<String><Key>Title</Key><Value>Only a title</Value></String>",
    ));
    let parsed = plan(source.as_bytes(), false).unwrap();
    let record = parsed.items[0].record(96 << 20).unwrap();
    assert!(record.entries.is_empty());
    assert_eq!(
        record.extra["confidex.title"].as_str(),
        Some("Only a title")
    );
}

#[test]
fn one_plain_title_does_not_consume_the_record_field_budget() {
    let limit = Limits::default().fields;
    let mut fields =
        String::from("<String><Key>Title</Key><Value>Public boundary</Value></String>");
    for index in 0..limit {
        fields.push_str(&format!(
            "<String><Key>Field{index}</Key><Value>PUBLIC</Value></String>"
        ));
    }
    let source = database(&source_entry(1, &fields));
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(
        parsed.items[0].record(96 << 20).unwrap().entries.len(),
        limit
    );
    fields.push_str("<String><Key>Overflow</Key><Value>PUBLIC</Value></String>");
    assert_eq!(
        plan(database(&source_entry(1, &fields)).as_bytes(), false)
            .err()
            .unwrap()
            .kind,
        import::ErrorKind::Limit
    );
    let mut options = Options::default();
    options.source_instance = Some("public-boundary".into());
    let limits = Limits {
        fields: 1,
        ..Limits::default()
    };
    let entry = source_entry(
        1,
        "<String><Key>Title</Key><Value>Public</Value></String><String><Key>Only</Key><Value>PUBLIC</Value></String>",
    );
    assert_eq!(
        import::prepare(
            Format::KeepassXml,
            database(&entry).as_bytes(),
            &options,
            limits,
            &mut |_| true,
            parse
        )
        .unwrap()
        .items[0]
            .record(96 << 20)
            .unwrap()
            .entries
            .len(),
        1
    );
    for title in [
        "<String><Key>Title</Key><Value ProtectInMemory=\"True\">PUBLIC</Value></String>",
        "<String><Key>Title</Key><Value>{USERNAME}</Value></String>",
        "<String><Key>Title</Key><Value>One</Value></String><String><Key>Title</Key><Value>Two</Value></String>",
    ] {
        let source = database(&source_entry(
            1,
            &format!("{title}<String><Key>Only</Key><Value>PUBLIC</Value></String>"),
        ));
        assert_eq!(
            import::prepare(
                Format::KeepassXml,
                source.as_bytes(),
                &options,
                limits,
                &mut |_| true,
                parse
            )
            .err()
            .unwrap()
            .kind,
            import::ErrorKind::Limit
        );
    }
}
#[test]
fn native_timeotp_placeholder_becomes_a_code_field() {
    let source = database(&source_entry(
        1,
        "<String><Key>Password</Key><Value>{TIMEOTP}</Value></String><String><Key>TimeOtp-Secret-Base32</Key><Value>GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ</Value></String><String><Key>TimeOtp-Algorithm</Key><Value>HMAC-SHA256</Value></String><String><Key>TimeOtp-Length</Key><Value>8</Value></String><String><Key>TimeOtp-Period</Key><Value>45</Value></String>",
    ));
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(parsed.items[0].status, Status::Review);
    let record = parsed.items[0].record(96 << 20).unwrap();
    assert!(record.entries.iter().any(|e| e.type_name == "totp/v1"));
    assert!(!record.entries.iter().any(|e| e.type_name == "password/v1"));
}
#[test]
fn missing_files_entities_and_wrong_formats_do_not_succeed() {
    let source = database(&source_entry(
        1,
        "<Binary><Key>missing.bin</Key><Value Ref='99'/></Binary>",
    ));
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(parsed.items[0].status, Status::Blocked);
    assert!(
        parsed.items[0]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::MissingAttachment)
    );
    assert!(plan(b"<!DOCTYPE KeePassFile [<!ENTITY secret SYSTEM 'file:///private/secret'>]><KeePassFile>&secret;</KeePassFile>",false).is_err());
    assert!(plan(b"<Other/>", false).is_err());
}

#[test]
fn canonical_plans_match_native_and_wasm() {
    use sha2::{Digest, Sha256};
    for (label, source) in [
        ("synthetic", SOURCE),
        (
            "upstream",
            include_bytes!("import_fixtures/keepass_xml/upstream-keepass.xml").as_slice(),
        ),
        (
            "keepassxc-2.7.11",
            include_bytes!("import_fixtures/keepass_xml/keepassxc-2.7.11.xml").as_slice(),
        ),
    ] {
        let parsed = plan(source, false).unwrap();
        let mut hash = Sha256::new();
        hash.update(parsed.container_attributes_bytes().unwrap());
        hash.update(serde_json::to_vec(&parsed.container_status).unwrap());
        hash.update(serde_json::to_vec(&parsed.container_diagnostics).unwrap());
        for item in &parsed.items {
            hash.update(item.record_bytes());
            hash.update(item.source_attributes_bytes());
            hash.update(serde_json::to_vec(&item.status).unwrap());
            hash.update(serde_json::to_vec(&item.diagnostics).unwrap());
            hash.update(serde_json::to_vec(&item.source).unwrap());
        }
        let digest: String = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        println!("keepass-plan-{label}={digest}");
    }
}

#[test]
#[ignore = "Run separately for native/WASM resource calibration"]
fn ten_thousand_entries_use_a_bounded_plan() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::fmt::Write;
    let mut source = String::with_capacity(24 << 20);
    write!(source,"<KeePassFile><Meta><Generator>Confidex public benchmark</Generator><CustomData><Item><Key>Public context</Key><Value>{}</Value></Item></CustomData></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Public fixture</Name>","PUBLIC-FIXTURE-CONTEXT".repeat(3000)).unwrap();
    for index in 0u64..10_000 {
        let mut id = [0; 16];
        id[..8].copy_from_slice(&(index + 1).to_le_bytes());
        id[8..].copy_from_slice(b"PUBLICID");
        let id = STANDARD.encode(id);
        write!(source,"\n<Entry>\n<UUID>{id}</UUID>\n<Times><CreationTime>2026-01-01T00:00:00Z</CreationTime><LastModificationTime>2026-01-02T00:00:00Z</LastModificationTime></Times>\n<Tags>Work;メール</Tags><String><Key>Title</Key><Value>Public entry {index}</Value></String>").unwrap();
        for field in 0..10 {
            let name = match field {
                0 => "UserName".into(),
                1 => "Password".into(),
                2 => "URL".into(),
                3 => "Notes".into(),
                _ => format!("Field {field}"),
            };
            let value = if field == 2 {
                format!("https://example.invalid/public/{index}")
            } else {
                format!("public-fixture-{index}-{field}")
            };
            let protected = if field == 1 || field % 3 == 0 {
                " ProtectInMemory='True'"
            } else {
                ""
            };
            write!(
                source,
                "\n <String>\n  <Key>{name}</Key>\n  <Value{protected}>{value}</Value>\n </String>"
            )
            .unwrap();
        }
        write!(source,"\n<AutoType><Enabled>True</Enabled><DefaultSequence>{{USERNAME}}{{TAB}}{{PASSWORD}}{{ENTER}}</DefaultSequence></AutoType><History><Entry><UUID>{id}</UUID><String><Key>Password</Key><Value ProtectInMemory='True'>PUBLIC-FIXTURE-OLD-{index}</Value></String></Entry></History>\n</Entry>").unwrap();
    }
    source.push_str("</Group></Root></KeePassFile>");
    source.shrink_to_fit();
    let started = std::time::Instant::now();
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(parsed.items.len(), 10_000);
    assert_eq!(parsed.statistics.review, 10_000);
    assert!(parsed.statistics.encoded_bytes < 48 << 20);
    let last = parsed.items[9999].record(96 << 20).unwrap();
    assert_eq!(last.entries.len(), 11);
    assert_eq!(
        last.entries[9].value["secret"].as_str(),
        Some("public-fixture-9999-9")
    );
    let accounted = Limits::default().memory_bytes - parsed.memory().available();
    println!(
        "keepass-10k input_bytes={} plan_bytes={} retained_accounted_bytes={} elapsed_ms={}",
        source.len(),
        parsed.statistics.encoded_bytes,
        accounted,
        started.elapsed().as_millis()
    );
}

#[test]
fn nested_empty_extensions_and_attributes_are_not_truncated_or_lost() {
    let source = database(&source_entry(1, "<String custom='PUBLIC-TITLE-ATTRIBUTE'><Key custom='PUBLIC-KEY-ATTRIBUTE'>Title</Key><Value>Public</Value><Extension/></String><Tags custom='PUBLIC-TAGS-ATTRIBUTE'>tag</Tags>"))
        .replace("<Group>", "<Group custom='PUBLIC-GROUP-ATTRIBUTE'><CustomData><Item><Empty/><Value>PUBLIC-GROUP-END</Value></Item></CustomData>")
        .replace("<Root>", "<Extension><Empty/><Value>PUBLIC-ROOT-END</Value></Extension><Root>");
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(parsed.container_status, Status::Review);
    assert!(
        parsed
            .container_diagnostics
            .iter()
            .any(|d| d.code == Code::SourceDataPreserved)
    );
    let context = parsed.container_attributes(96 << 20).unwrap();
    let Value::Binary(header) = &context["groups"].as_array().unwrap()[0]["header"] else {
        panic!()
    };
    assert!(
        header
            .windows(b"PUBLIC-GROUP-ATTRIBUTE".len())
            .any(|s| s == b"PUBLIC-GROUP-ATTRIBUTE")
    );
    let Value::Binary(extension) = &context["root_extra"].as_array().unwrap()[0]["xml"] else {
        panic!()
    };
    assert!(extension.ends_with(b"PUBLIC-ROOT-END</Value></Extension>"));
    let properties = context["groups"].as_array().unwrap()[0]["properties"]
        .as_array()
        .unwrap();
    assert!(properties.iter().any(|v|matches!(v,Value::Binary(s) if s.ends_with(b"PUBLIC-GROUP-END</Value></Item></CustomData>"))));
    let record = parsed.items[0].record(96 << 20).unwrap();
    let original = record
        .entries
        .iter()
        .find(|e| e.name == "Original data")
        .unwrap();
    let text = original.value["text"].as_str().unwrap();
    for marker in [
        "PUBLIC-TITLE-ATTRIBUTE",
        "PUBLIC-KEY-ATTRIBUTE",
        "PUBLIC-TAGS-ATTRIBUTE",
    ] {
        assert!(text.contains(marker));
    }
    let empty = plan(database("").as_bytes(), false).unwrap();
    assert_eq!(empty.container_status, Status::Review);
    assert!(empty.items.is_empty());
}

fn with_limits(source: &[u8], limits: Limits) -> Result<Plan, Error> {
    import::prepare(
        Format::KeepassXml,
        source,
        &Options::default(),
        limits,
        &mut |_| true,
        parse,
    )
}

#[test]
fn binary_budgets_cover_orphans_inline_data_and_repeated_references() {
    let data = "YWJj".repeat(32);
    let file = "<Binary><Key>public.bin</Key><Value Ref='0'/></Binary>";
    let inline = format!("<Binary><Key>public.bin</Key><Value>{data}</Value></Binary>");
    let pooled = |fields: &str| {
        database(&source_entry(1, fields)).replace(
            "<Root>",
            &format!("<Meta><Binaries><Binary ID='0'>{data}</Binary></Binaries></Meta><Root>"),
        )
    };
    let limits = Limits {
        unpacked_bytes: 512,
        ..Limits::default()
    };
    assert!(with_limits(pooled(file).as_bytes(), limits).is_ok());
    assert!(with_limits(pooled("").as_bytes(), limits).is_ok());
    for source in [
        pooled(&file.repeat(6)),
        pooled(&inline.repeat(5)),
        database(&source_entry(1, &inline.repeat(6))),
    ] {
        assert_eq!(
            with_limits(source.as_bytes(), limits).err().unwrap().kind,
            import::ErrorKind::Limit
        );
    }
    let source = database(&source_entry(
        1,
        "<Binary><Key>public.bin</Key><Value>A?==</Value></Binary>",
    ));
    assert!(plan(source.as_bytes(), false).is_err());
}

#[test]
fn malformed_structure_limits_and_cancellation_return_no_plan() {
    let source = database(&source_entry(
        1,
        "<String><Key>Password</Key><Value>public</Value></String>",
    ));
    for bad in [
        source.replace("<Root>", "<Root>lost text"),
        source.replace(
            "<Name>fixture</Name>",
            "<Name><Child>fixture</Child></Name>",
        ),
        source.replace("<Root>", "<Meta><Extension>]]></Extension></Meta><Root>"),
        source.replace(
            "<Root>",
            "<Meta><Extension>&unknown;</Extension></Meta><Root>",
        ),
        source[..source.len() - 1].into(),
    ] {
        assert!(plan(bad.as_bytes(), false).is_err());
    }
    for kind in 0..6 {
        let mut limits = Limits::default();
        match kind {
            0 => limits.input_bytes = source.len() - 1,
            1 => limits.depth = 4,
            2 => limits.nodes = 5,
            3 => limits.string_bytes = 3,
            4 => limits.memory_bytes = 1024,
            _ => limits.plan_bytes = 1,
        }
        assert_eq!(
            with_limits(source.as_bytes(), limits).err().unwrap().kind,
            import::ErrorKind::Limit
        );
    }
    let attributes: String = (0..513).map(|n| format!(" a{n}='public' ")).collect();
    let many_attributes = source.replace("<Root>", &format!("<Root{attributes}>"));
    assert_eq!(
        plan(many_attributes.as_bytes(), false).err().unwrap().kind,
        import::ErrorKind::Limit
    );
    let error = import::prepare(
        Format::KeepassXml,
        source.as_bytes(),
        &Options::default(),
        Limits::default(),
        &mut |progress| progress.phase != import::Phase::Map,
        parse,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, import::ErrorKind::Canceled);
    let literals = database(&source_entry(
        1,
        "<String><Key>Password</Key><Value>{NEWPASSWORDLITERAL}{GROUPhello}{TIMEOTPliteral}</Value></String>",
    ));
    let parsed = plan(literals.as_bytes(), false).unwrap();
    assert_ne!(parsed.items[0].status, Status::Blocked);
}

#[test]
fn imported_files_obey_the_whole_record_compressed_cap() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut state = 0x4e554c4c5055424cu64;
    let bytes: Vec<u8> = (0..4_100_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    for (size, fits) in [(3_900_000, true), (4_100_000, false)] {
        let source = database(&source_entry(
            1,
            &format!(
                "<Binary><Key>public.bin</Key><Value>{}</Value></Binary>",
                STANDARD.encode(&bytes[..size])
            ),
        ));
        let result = plan(source.as_bytes(), false);
        if fits {
            let parsed = result.unwrap();
            let record = parsed.items[0].record(96 << 20).unwrap();
            assert!(
                matches!(&record.entries[0].value["data"],Value::Binary(data) if data==&bytes[..size])
            );
        } else {
            assert_eq!(result.err().unwrap().kind, import::ErrorKind::Limit);
        }
    }
}

#[test]
fn unexpected_protection_and_mixed_data_do_not_leak_or_disappear() {
    let source = database(&source_entry(
        1,
        "PUBLIC-ENTRY-TEXT<String>PUBLIC-STRING-TEXT<Key>Password</Key><Value>public</Value></String><Tags ProtectInMemory='True'>PUBLIC-SECRET-TAG</Tags>",
    ));
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(parsed.items[0].status, Status::Blocked);
    let record = parsed.items[0].record(96 << 20).unwrap();
    assert!(record.tags.is_empty());
    let original = record
        .entries
        .iter()
        .find(|e| e.name == "Original data")
        .unwrap();
    let text = original.value["text"].as_str().unwrap();
    for marker in [
        "PUBLIC-ENTRY-TEXT",
        "PUBLIC-STRING-TEXT",
        "PUBLIC-SECRET-TAG",
    ] {
        assert!(text.contains(marker));
    }
    let source = database(&source_entry(
        1,
        "<Binary><Key>public.bin</Key><Value Ref='0'>PUBLIC-AMBIGUOUS-DATA</Value></Binary>",
    ))
    .replace(
        "<Root>",
        "<Meta><Binaries><Binary ID='0'>YWJj</Binary></Binaries></Meta><Root>",
    );
    let parsed = plan(source.as_bytes(), false).unwrap();
    assert_eq!(parsed.items[0].status, Status::Blocked);
    let record = parsed.items[0].record(96 << 20).unwrap();
    assert!(!record.entries.iter().any(|e| e.type_name == "file/v1"));
    assert!(
        record.entries[0].value["text"]
            .as_str()
            .unwrap()
            .contains("PUBLIC-AMBIGUOUS-DATA")
    );
}

#[test]
fn real_keepassxc_export_preserves_fields_and_reports_omitted_attachment_data() {
    let source = include_bytes!("import_fixtures/keepass_xml/keepassxc-2.7.11.xml");
    let parsed = plan(source, false).unwrap();
    assert_eq!(parsed.items.len(), 3);
    assert_eq!(parsed.items[2].status, Status::Excluded);
    let record = parsed.items[0].record(96 << 20).unwrap();
    assert_eq!(
        record.extra["confidex.title"].as_str(),
        Some("Почта — 東京")
    );
    assert_eq!(record.entries[0].name, "Empty");
    assert_eq!(record.entries[0].value["text"].as_str(), Some(""));
    let hidden = record
        .entries
        .iter()
        .find(|e| e.name == "Hidden custom")
        .unwrap();
    assert_eq!(hidden.type_name, "secret/v1");
    let url = record
        .entries
        .iter()
        .find(|e| e.type_name == "url/v1")
        .unwrap();
    assert_eq!(url.extra["metadata"]["protected"].as_bool(), Some(true));
    let otp = record
        .entries
        .iter()
        .find(|e| e.type_name == "totp/v1")
        .unwrap();
    assert_eq!(otp.value["algorithm"].as_str(), Some("SHA256"));
    assert_eq!(otp.value["digits"].as_u64(), Some(8));
    assert_eq!(otp.value["period"].as_u64(), Some(45));
    let included = plan(source, true).unwrap();
    assert_eq!(included.items[2].status, Status::Blocked);
    assert!(
        included.items[2]
            .diagnostics
            .iter()
            .any(|d| d.code == Code::MissingAttachment)
    );
    let record = included.items[2].record(96 << 20).unwrap();
    assert!(!record.entries.iter().any(|e| e.type_name == "file/v1"));
}

#[test]
fn shared_totp_parser_preserves_keepass_extensions_without_changing_standard_policy() {
    let uri = "otpauth://TOTP/Public?secret=GEZD-GNBV%20GY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=HMAC-SHA-256&digits=8&period=45";
    assert!(confidex_app::import::totp::entry(uri).is_none());
    let source = |uri: &str| {
        database(&source_entry(
            1,
            &format!(
                "<String><Key>otp</Key><Value>{}</Value></String>",
                uri.replace('&', "&amp;")
            ),
        ))
    };
    let parsed = plan(source(uri).as_bytes(), false).unwrap();
    let record = parsed.items[0].record(96 << 20).unwrap();
    let otp = record
        .entries
        .iter()
        .find(|e| e.type_name == "totp/v1")
        .unwrap();
    assert_eq!(otp.name, "otp");
    assert_eq!(otp.value["algorithm"].as_str(), Some("SHA256"));
    assert_eq!(otp.value["digits"].as_u64(), Some(8));
    assert_eq!(otp.value["period"].as_u64(), Some(45));
    assert!(matches!(&otp.value["secret"], Value::Binary(s) if s==b"12345678901234567890"));
    assert_eq!(otp.extra["confidex.import.totp"]["uri"].as_str(), Some(uri));
    for suffix in ["&counter=1", "&algorithm=SHA1", "&secret=OTHER"] {
        let parsed = plan(source(&format!("{uri}{suffix}")).as_bytes(), false).unwrap();
        let record = parsed.items[0].record(96 << 20).unwrap();
        assert!(!record.entries.iter().any(|e| e.type_name == "totp/v1"));
        assert_eq!(record.entries[0].type_name, "secure-note/v1");
        assert_eq!(parsed.items[0].status, Status::Review);
    }
}
