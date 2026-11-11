use confidex_vault::record::{Entry, Mapping, Record, Value};
use serde_json::Value as Json;
use std::collections::BTreeSet;

const EXPECTED: &[&str] = &[
    include_str!("import_fixtures/bitwarden_json/personal.expected.json"),
    include_str!("import_fixtures/bitwarden_json/organization.expected.json"),
    include_str!("import_fixtures/onepassword_1pux/expected.json"),
    include_str!("import_fixtures/keepass_xml/expected.json"),
    include_str!("import_fixtures/csv/expected.json"),
];

fn value(input: &Json) -> Value {
    match input {
        Json::Null => Value::Nil,
        Json::Bool(v) => Value::Boolean(*v),
        Json::Number(v) => Value::from(v.as_i64().unwrap()),
        Json::String(v) => Value::from(v.as_str()),
        Json::Array(items) => Value::Array(items.iter().map(value).collect()),
        Json::Object(items) if items.len() == 1 && items.contains_key("$binary") => {
            let text = items["$binary"].as_str().unwrap();
            assert_eq!(text.len() % 2, 0);
            Value::Binary(
                (0..text.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                    .collect(),
            )
        }
        Json::Object(items) => Value::Map(
            items
                .iter()
                .map(|(key, item)| (Value::from(key.as_str()), value(item)))
                .collect(),
        ),
    }
}
fn mapping(input: &Json) -> Mapping {
    input
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, item)| (key.clone(), value(item)))
        .collect()
}

#[test]
fn expected_import_records_use_existing_core_schemas() {
    let mut identities = BTreeSet::new();
    let mut record_count = 0;
    let mut found_repeated_names = false;
    let mut found_empty_name = false;
    let mut found_hidden_text = false;
    let mut found_advanced_totp = false;
    let mut found_binary_file = false;
    for text in EXPECTED {
        let expected: Json = serde_json::from_str(text).unwrap();
        assert_eq!(expected["schema"], 1);
        for item in expected["records"].as_array().unwrap() {
            if item["source"]["item"].is_string() {
                assert!(identities.insert(item["source"].to_string()));
            }
            let source = &item["record"];
            let record = Record {
                entries: source["entries"]
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
                tags: source["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap().into())
                    .collect(),
                extra: mapping(&source["extra"]),
            };
            assert!(source.get("type").is_none());
            record.validate_structure().unwrap();
            assert!(record.extra["confidex.title"].as_str().is_some());
            assert_eq!(item["source"]["instance"], "public-fixture-source");
            let names: BTreeSet<_> = record.entries.iter().map(|e| &e.name).collect();
            found_repeated_names |= names.len() < record.entries.len();
            for e in &record.entries {
                e.validate_value().unwrap();
                assert!(!matches!(e.type_name.as_str(), "login/v1" | "api_key/v1"));
                found_empty_name |= e.name.is_empty();
                found_hidden_text |= e.type_name == "text/v1"
                    && e.extra.get("metadata").is_some_and(|m| {
                        m.as_map().is_some_and(|fields| {
                            fields.iter().any(|(key, flag)| {
                                key.as_str() == Some("protected") && flag.as_bool() == Some(true)
                            })
                        })
                    });
                if e.type_name == "totp/v1" {
                    found_advanced_totp |= e.value["algorithm"].as_str() == Some("SHA256")
                        && e.value["period"].as_u64() == Some(45)
                        && e.value["digits"].as_u64() == Some(8);
                }
                found_binary_file |= e.type_name == "file/v1"
                    && matches!(&e.value["data"], Value::Binary(data) if data.contains(&0) && data.contains(&255));
            }
            record_count += 1;
        }
    }
    assert_eq!(record_count, 13);
    assert!(found_repeated_names && found_empty_name && found_hidden_text);
    assert!(found_advanced_totp && found_binary_file);
}
