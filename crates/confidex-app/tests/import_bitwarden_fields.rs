#[path = "../src/import/formats/bitwarden_json/fields.rs"]
mod fields;

use confidex_vault::record::Value;
use serde_json::{Value as Json, json};

#[test]
fn custom_fields_match_independent_golden_order_names_values_and_protection() {
    let source: Json =
        serde_json::from_str(include_str!("import_fixtures/bitwarden_json/personal.json")).unwrap();
    let golden: Json = serde_json::from_str(include_str!(
        "import_fixtures/bitwarden_json/personal.expected.json"
    ))
    .unwrap();
    let expected = &golden["records"][0]["record"]["entries"];
    let entries: Vec<_> = source["items"][0]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| fields::custom(field).unwrap())
        .collect();
    assert_eq!(entries.len(), 4);
    for (index, entry) in entries.iter().enumerate() {
        entry.validate_value().unwrap();
        assert_eq!(entry.name, expected[index + 6]["name"].as_str().unwrap());
        assert_eq!(
            entry.type_name,
            expected[index + 6]["type"].as_str().unwrap()
        );
        let (key, value) = entry.value.iter().next().unwrap();
        assert_eq!(value.as_str(), expected[index + 6]["value"][key].as_str());
        assert_eq!(
            entry.extra["confidex.import.field"].as_map().unwrap()[0]
                .1
                .as_u64(),
            Some([0, 1, 0, 2][index])
        );
        assert_eq!(entry.extra.contains_key("metadata"), index == 1);
    }
    assert_eq!(entries[0].name, entries[1].name);
    assert_eq!(entries[2].name, "");
    assert_eq!(entries[2].value["text"].as_str(), Some(""));
    assert_eq!(
        entries[1].extra["metadata"].as_map().unwrap()[0],
        ("protected".into(), true.into())
    );
}

#[test]
fn unsupported_custom_fields_cannot_become_indexable_text() {
    let captured: Json = serde_json::from_str(include_str!(
        "import_fixtures/bitwarden_json/producer-personal.json"
    ))
    .unwrap();
    for field in &captured["items"][0]["fields"].as_array().unwrap()[4..] {
        assert!(fields::custom(field).is_none());
    }
    for field in [
        json!({"name":"Hidden","value":17,"type":1}),
        json!({"name":"Hidden","value":null,"type":1}),
        json!({"name":"Hidden","type":1}),
        json!({"value":"PUBLIC-FIXTURE","type":0}),
        json!({"name":null,"value":"PUBLIC-FIXTURE","type":0}),
        json!({"name":"Future","value":"PUBLIC-FIXTURE","type":-1}),
        json!({"name":"Future","value":"PUBLIC-FIXTURE","type":1.5}),
        json!({"name":"Future","value":"PUBLIC-FIXTURE","type":"1"}),
        json!({"name":"Future","value":"PUBLIC-FIXTURE","type":0,"protected":true}),
        json!({"name":"Linked","value":"PUBLIC-FIXTURE","type":0,"linkedId":101}),
        json!({"name":"Boolean","value":"yes","type":2}),
        json!([]),
    ] {
        assert!(fields::custom(&field).is_none());
    }
}

#[test]
fn explicit_null_link_metadata_and_false_boolean_are_preserved() {
    let input = json!({"name":"Flag","value":"false","type":2,"linkedId":null});
    let entry = fields::custom(&input).unwrap();
    assert_eq!(entry.value["text"].as_str(), Some("false"));
    assert_eq!(
        entry.extra["confidex.import.field"].as_map().unwrap()[1],
        ("linkedId".into(), Value::Nil)
    );
    assert!(!entry.extra.contains_key("metadata"));
}

#[test]
fn card_components_stay_separate_without_normalization_or_checksum_rejection() {
    let input = json!({
        "cardholderName":"Public Fixture", "brand":"local-card",
        "number":"0000 0000 0000 0001", "expMonth":"04", "expYear":"2030", "code":"007"
    });
    let mut entries = Vec::new();
    assert!(fields::personal(3, &input, &mut entries));
    assert!(input.is_object());
    assert_eq!(
        entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        [
            "Cardholder",
            "Brand",
            "Card number",
            "Expiry month",
            "Expiry year",
            "Security code"
        ]
    );
    assert_eq!(
        entries[2].value["secret"].as_str(),
        Some("0000 0000 0000 0001")
    );
    assert_eq!(entries[3].value["text"].as_str(), Some("04"));
    assert_eq!(entries[4].value["text"].as_str(), Some("2030"));
    assert_eq!(entries[5].value["secret"].as_str(), Some("007"));
    for entry in &entries {
        entry.validate_value().unwrap();
    }
    assert!(entries[2].extra.contains_key("metadata"));
    assert!(entries[5].extra.contains_key("metadata"));
    assert_eq!(
        entries[3].extra["confidex.import.field"].as_map().unwrap()[1]
            .1
            .as_str(),
        Some("expMonth")
    );
}

#[test]
fn identity_empty_components_and_sensitive_identifiers_keep_their_meaning() {
    let captured: Json = serde_json::from_str(include_str!(
        "import_fixtures/bitwarden_json/producer-personal.json"
    ))
    .unwrap();
    let input = captured["items"][3]["identity"].clone();
    let mut entries = Vec::new();
    assert!(fields::personal(4, &input, &mut entries));
    assert!(input.is_object());
    assert_eq!(entries.len(), 17);
    assert_eq!(entries[1].name, "First name");
    assert_eq!(entries[2].value["text"].as_str(), Some(""));
    assert_eq!(entries[3].name, "Last name");
    for name in [
        "Social security number",
        "Passport number",
        "License number",
    ] {
        let entry = entries.iter().find(|entry| entry.name == name).unwrap();
        assert_eq!(entry.type_name, "secret/v1");
        assert!(entry.extra.contains_key("metadata"));
    }
    for entry in &entries {
        entry.validate_value().unwrap();
    }
}

#[test]
fn null_and_future_personal_values_remain_available_for_protected_fallback() {
    let input =
        json!({"firstName":"", "middleName":null, "lastName":17, "future":"PUBLIC-FIXTURE-FUTURE"});
    let mut entries = Vec::new();
    assert!(!fields::personal(4, &input, &mut entries));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].value["text"].as_str(), Some(""));
    assert_eq!(
        input,
        json!({"firstName":"","middleName":null,"lastName":17,"future":"PUBLIC-FIXTURE-FUTURE"})
    );
    assert!(!fields::personal(99, &input, &mut entries));
    assert!(!fields::personal(3, &Json::Null, &mut entries));
    assert_eq!(entries.len(), 1);
}
