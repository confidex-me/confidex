use confidex_vault::{
    crypto::{VaultKeys, clamp_material},
    envelope::{self, EventKind, Options},
    record::{Entry, Mapping, Record, Value, ValueError},
    resources::MAX_OPEN_MEMORY,
    trust::TrustAnchor,
};

fn entry(ty: &str, fields: &[(&str, &str)]) -> Entry {
    Entry {
        name: String::new(),
        type_name: ty.into(),
        value: fields
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        extra: Mapping::new(),
    }
}
#[test]
fn personal_schemas_allow_empty_and_partial_values_and_validate_only_present_fields() {
    for ty in ["card/v1", "person/v1", "document/v1", "passport/v1"] {
        let mut e = entry(ty, &[]);
        assert_eq!(e.validate_value(), Ok(()));
        e.value.insert("future".into(), Value::Ext(4, vec![0, 193]));
        assert_eq!(e.validate_value(), Ok(()));
        let field = if ty == "person/v1" { "name" } else { "number" };
        e.value.insert(field.into(), "".into());
        assert_eq!(e.validate_value(), Ok(()));
        e.value.insert(field.into(), 123.into());
        assert_eq!(e.validate_value(), Err(ValueError::WrongType(field)));
        e.value.remove(field);
        assert_eq!(e.validate_value(), Ok(()));
    }
}
#[test]
fn cards_people_passports_and_documents_round_trip_inside_one_encrypted_record() {
    let keys = VaultKeys::from_material(1, &clamp_material([3; 32])[..]).unwrap();
    let pin = TrustAnchor::from_local_pin(
        [7; 16],
        Some(&keys.signing_key().verifying_key().to_bytes()),
    )
    .unwrap();
    let mut record = Record {
        tags: Vec::new(),
        entries: vec![
            entry(
                "card/v1",
                &[
                    ("number", "0000 0000 0000 0000"),
                    ("holder", "Synthetic Holder"),
                    ("expiry", "12/40"),
                    ("cvv", "000"),
                    ("pin", "0000"),
                ],
            ),
            entry(
                "person/v1",
                &[
                    ("name", "Мария Example"),
                    ("address", "Example street 0"),
                    ("birth_date", "2000-02-29"),
                ],
            ),
            entry(
                "passport/v1",
                &[
                    ("number", "SYNTHETIC-PASSPORT"),
                    ("country", "Example"),
                    ("expires", "No expiry"),
                ],
            ),
            entry(
                "document/v1",
                &[
                    ("kind", "Permit"),
                    ("number", "SYNTHETIC-DOCUMENT"),
                    ("issuer", "Example issuer"),
                ],
            ),
            entry("note/v1", &[("text", "mixed arbitrary fields")]),
        ],
        extra: Mapping::new(),
    };
    record.entries[0]
        .value
        .insert("future".into(), Value::Binary(vec![1, 193, 0]));
    for e in &record.entries {
        e.validate_value().unwrap();
    }
    let options = || Options {
        vault_id: [7; 16],
        record_id: [8; 16],
        parents: &[],
        epoch: 123,
        kind: EventKind::Content,
    };
    let wire = envelope::seal(&record, &keys, options(), MAX_OPEN_MEMORY).unwrap();
    let mut opened = envelope::open(&wire, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
    for (a, b) in record.entries.iter().zip(&opened.record.entries) {
        assert_eq!(a.type_name, b.type_name);
        assert_eq!(a.value, b.value);
    }
    opened.record.entries.swap(0, 3);
    opened.record.entries.remove(1);
    let second = envelope::seal(&opened.record, &keys, options(), MAX_OPEN_MEMORY).unwrap();
    let after = envelope::open(&second, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(after.record.entries.len(), 4);
    assert_eq!(after.record.entries[0].type_name, "document/v1");
    assert_eq!(
        after.record.entries[2].value["future"],
        Value::Binary(vec![1, 193, 0])
    );
}
#[test]
fn reading_preserves_a_known_type_with_a_value_that_fails_explicit_validation() {
    let mut e = entry("passport/v1", &[]);
    e.value.insert("expires".into(), 2040.into());
    let record = Record {
        tags: Vec::new(),
        entries: vec![e],
        extra: Mapping::new(),
    };
    let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let decoded = Record::decode_content(&encoded.bytes, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(decoded.record.entries[0].value["expires"], 2040.into());
    assert_eq!(
        decoded.record.entries[0].validate_value(),
        Err(ValueError::WrongType("expires"))
    );
}
