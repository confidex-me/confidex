use super::*;

const INPUT: &[u8] = include_bytes!("../import_fixtures/onepassword_1pux/templates.1pux");

#[test]
fn invalid_or_future_typed_values_keep_exact_protected_fragments() {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(INPUT)).unwrap();
    let source: Json = serde_json::from_reader(archive.by_name("export.data").unwrap()).unwrap();
    let ssh = source["accounts"][0]["vaults"][0]["items"][16]["details"]["sections"][0]["fields"]
        [0]["value"]["sshKey"]
        .clone();
    let mut conflict = ssh.clone();
    conflict["metadata"]["privateKey"] = json!("PUBLIC-FIXTURE-CONFLICT");
    let mut mismatch = ssh;
    mismatch["metadata"]["publicKey"] = json!("ssh-ed25519 AAAA");
    for value in [
        json!({"date":i64::MAX}),
        json!({"monthYear":203013}),
        json!({"email":{"email_address":"fixture@example.invalid","future":"PUBLIC-FIXTURE"}}),
        json!({"address":{"street":"Public street","future":"PUBLIC-FIXTURE"}}),
        json!({"sshKey":conflict}),
        json!({"sshKey":mismatch}),
    ] {
        let field = json!({"title":"Public fixture","id":"fixture","value":value});
        let mut data = fixture();
        data["accounts"][0]["vaults"][0]["items"][0]["details"] =
            json!({"sections":[{"fields":[field]}]});
        let plan = run(&mutated(&data)).unwrap();
        let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
        let entry = record
            .entries
            .iter()
            .find(|e| e.extra.contains_key("confidex.import.original"))
            .unwrap();
        assert_eq!(entry.type_name, "secure-note/v1");
        let original: Json = serde_json::from_str(entry.value["text"].as_str().unwrap()).unwrap();
        assert_eq!(original["data"], field);
        assert!(
            plan.items[0]
                .diagnostics
                .iter()
                .any(|d| d.code == Code::UnsupportedFeature)
        );
    }
}

#[test]
fn dates_use_utc_and_keep_calendar_precision() {
    for (timestamp, expected) in [
        (-62135596800i64, (1, 1, 1)),
        (-1, (1969, 12, 31)),
        (0, (1970, 1, 1)),
        (1709164800, (2024, 2, 29)),
        (253402300799, (9999, 12, 31)),
    ] {
        let mut data = fixture();
        data["accounts"][0]["vaults"][0]["items"][0]["details"] = json!({"sections":[{"fields":[
            {"title":"Date","id":"date","guarded":true,"value":{"date":timestamp}},
            {"title":"Expiry","id":"expiry","value":{"monthYear":202402}}
        ]}]});
        let plan = run(&mutated(&data)).unwrap();
        let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
        let date = record.entries.iter().find(|e| e.name == "Date").unwrap();
        assert_eq!(date.type_name, "date/v1");
        assert_eq!(
            (
                date.value["year"].as_u64().unwrap(),
                date.value["month"].as_u64().unwrap(),
                date.value["day"].as_u64().unwrap()
            ),
            expected
        );
        assert!(date.extra.contains_key("metadata"));
        let expiry = record.entries.iter().find(|e| e.name == "Expiry").unwrap();
        assert_eq!(expiry.type_name, "month-year/v1");
        assert_eq!(expiry.value["month"].as_u64(), Some(2));
        assert!(!expiry.value.contains_key("day"));
    }
}

#[test]
fn captured_template_values_become_editable_fields_instead_of_json() {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(INPUT)).unwrap();
    let source: Json = serde_json::from_reader(archive.by_name("export.data").unwrap()).unwrap();
    let plan = run(INPUT).unwrap();
    let mut count = 0;
    for (item, raw) in plan.items.iter().zip(
        source["accounts"][0]["vaults"][0]["items"]
            .as_array()
            .unwrap(),
    ) {
        assert!(
            !item
                .diagnostics
                .iter()
                .any(|d| d.code == Code::UnsupportedFeature),
            "{}",
            raw["overview"]["title"]
        );
        let record = item.record(MAX_OPEN_MEMORY).unwrap();
        assert!(
            record
                .entries
                .iter()
                .all(|e| !e.extra.contains_key("confidex.import.original")),
            "{}",
            raw["overview"]["title"]
        );
        for section in raw["details"]["sections"].as_array().unwrap() {
            for field in section["fields"].as_array().unwrap() {
                let entry = record
                    .entries
                    .iter()
                    .find(|e| {
                        e.name == field["title"].as_str().unwrap()
                            && e.extra
                                .get("confidex.import.section")
                                .and_then(Value::as_map)
                                .is_some_and(|map| {
                                    map.iter().any(|(key, value)| {
                                        key.as_str() == Some("field_id")
                                            && value.as_str() == field["id"].as_str()
                                    })
                                })
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "Field was not mapped: {} / {}",
                            raw["overview"]["title"], field["id"]
                        )
                    });
                let (kind, value) = field["value"].as_object().unwrap().iter().next().unwrap();
                let expected = match kind.as_str() {
                    "string" | "concealed" if field["multiline"] == true => "secure-note/v1",
                    "date" => "date/v1",
                    "monthYear" => "month-year/v1",
                    "sshKey" => "ssh/v1",
                    "address" => "note/v1",
                    "concealed" | "creditCardNumber" => "secret/v1",
                    "url" => "url/v1",
                    _ => "text/v1",
                };
                assert_eq!(entry.type_name, expected, "{}", field["id"]);
                match kind.as_str() {
                    "date" => {
                        assert_eq!(entry.value["year"].as_u64(), Some(2026));
                        assert_eq!(entry.value["day"].as_u64(), Some(1));
                    }
                    "monthYear" => {
                        assert_eq!(entry.value["year"].as_u64(), Some(2030));
                        assert!(!entry.value.contains_key("day"));
                    }
                    "email" => assert_eq!(
                        entry.value["text"].as_str(),
                        value["email_address"].as_str()
                    ),
                    "address" => {
                        let text = entry.value["text"].as_str().unwrap();
                        for (key, value) in value.as_object().unwrap() {
                            if !value.as_str().unwrap().is_empty() {
                                assert!(
                                    text.contains(&format!("{key}: {}", value.as_str().unwrap()))
                                );
                            }
                        }
                    }
                    "sshKey" => {
                        let key = confidex_vault::ssh::Key::from_value(
                            &entry.value,
                            confidex_vault::ssh::REQUIRED_MEMORY,
                        )
                        .unwrap();
                        assert_eq!(
                            key.fingerprint(),
                            value["metadata"]["fingerprint"].as_str().unwrap()
                        );
                        let message = b"public 1Password fixture challenge";
                        let signature = key.sign(message).unwrap();
                        confidex_vault::ssh::verify(
                            &key.public_blob().unwrap(),
                            message,
                            &signature,
                        )
                        .unwrap();
                    }
                    _ => assert_eq!(
                        entry.value.values().next().unwrap().as_str(),
                        value.as_str()
                    ),
                }
                if field["guarded"] == true
                    || matches!(kind.as_str(), "concealed" | "creditCardNumber" | "sshKey")
                {
                    assert!(
                        entry
                            .extra
                            .get("metadata")
                            .and_then(Value::as_map)
                            .is_some_and(|map| map
                                .iter()
                                .any(|(key, value)| key.as_str() == Some("protected")
                                    && value.as_bool() == Some(true)))
                    );
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 175);
}

#[test]
fn captured_templates_retain_every_item_field_and_document() {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(INPUT)).unwrap();
    assert_eq!(archive.len(), 4);
    assert!(
        archive
            .file_names()
            .all(|name| !name.unwrap().contains(".DS_Store"))
    );
    let source: Json = serde_json::from_reader(archive.by_name("export.data").unwrap()).unwrap();
    let account = &source["accounts"][0];
    let vault = &account["vaults"][0];
    let items = vault["items"].as_array().unwrap();
    let plan = run(INPUT).unwrap();
    assert_eq!(plan.items.len(), 22);
    assert_eq!(plan.statistics.blocked, 0);
    assert_eq!(plan.statistics.excluded, 0);
    let expected = [
        ("109", 8),
        ("107", 9),
        ("002", 16),
        ("112", 7),
        ("103", 11),
        ("006", 0),
        ("003", 0),
        ("102", 9),
        ("106", 11),
        ("100", 13),
        ("004", 25),
        ("108", 2),
        ("104", 7),
        ("001", 0),
        ("115", 3),
        ("110", 10),
        ("114", 1),
        ("001", 0),
        ("113", 8),
        ("101", 10),
        ("105", 8),
        ("111", 17),
    ];
    for ((item, raw), (category, fields)) in plan.items.iter().zip(items).zip(expected) {
        assert_eq!(raw["categoryUuid"], category);
        assert_eq!(
            raw["details"]["sections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["fields"].as_array().unwrap().len())
                .sum::<usize>(),
            fields
        );
        assert_eq!(
            item.source.account.as_deref(),
            account["attrs"]["uuid"].as_str()
        );
        assert_eq!(
            item.source.vault.as_deref(),
            vault["attrs"]["uuid"].as_str()
        );
        assert_eq!(item.source.item.as_deref(), raw["uuid"].as_str());
        let attributes = item.source_attributes(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            serde_json::from_str::<Json>(attributes["item"].as_str().unwrap()).unwrap(),
            *raw
        );
        let record = item.record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            record.extra["confidex.title"].as_str(),
            raw["overview"]["title"].as_str()
        );
        assert!(record.entries.len() >= fields);
        for entry in record
            .entries
            .iter()
            .filter(|e| e.extra.contains_key("confidex.import.original"))
        {
            assert_eq!(entry.type_name, "secure-note/v1");
            let preserved: Json =
                serde_json::from_str(entry.value["text"].as_str().unwrap()).unwrap();
            assert_eq!(
                Some(&preserved["data"]),
                raw.pointer(preserved["path"].as_str().unwrap())
            );
        }
    }
    let document = plan.items[5].record(MAX_OPEN_MEMORY).unwrap();
    let file = document
        .entries
        .iter()
        .find(|e| e.type_name == "file/v1")
        .unwrap();
    assert_eq!(
        file.value["filename"].as_str(),
        Some("passport-public-sample.png")
    );
    use std::io::Read;
    let mut expected = Vec::new();
    archive
        .by_name("files/ipgch6ssxb5uzqoqfnnrcqkucu__passport-public-sample.png")
        .unwrap()
        .read_to_end(&mut expected)
        .unwrap();
    assert_eq!(file.value["data"].as_slice(), Some(expected.as_slice()));
    let context = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(context["unmatched_files"].as_array().unwrap().len(), 1);
    assert_eq!(plan.container_status, Status::Review);
}
