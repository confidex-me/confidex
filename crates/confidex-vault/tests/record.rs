use confidex_vault::{
    record::{Entry, Error, MAX_ENTRIES, Mapping, Record, Value, ValueError},
    resources::{MAX_DECOMPRESSED, MAX_OPEN_MEMORY},
};

fn entry(ty: &str, value: &[(&str, Value)]) -> Entry {
    Entry {
        name: String::new(),
        type_name: ty.into(),
        value: value
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
        extra: Mapping::new(),
    }
}

#[test]
fn independent_field_schemas_accept_empty_strings_and_retain_unknown_values() {
    for (kind, key) in [
        ("text/v1", "text"),
        ("username/v1", "username"),
        ("password/v1", "password"),
        ("url/v1", "url"),
        ("secret/v1", "secret"),
        ("note/v1", "text"),
        ("secure-note/v1", "text"),
    ] {
        let mut field = entry(
            kind,
            &[(key, "".into()), ("future", Value::Binary(vec![7]))],
        );
        assert_eq!(field.validate_value(), Ok(()));
        field.value.insert(key.into(), Value::Nil);
        assert_eq!(field.validate_value(), Err(ValueError::WrongType(key)));
        field.value.remove(key);
        assert_eq!(field.validate_value(), Err(ValueError::Missing(key)));
    }
}

#[test]
fn file_shape_checks_binary_data_and_optional_labels_without_opening_contents() {
    for bytes in [vec![], vec![0x50, 0x4b, 0xc1, 255]] {
        let mut file = entry("file/v1", &[("data", Value::Binary(bytes))]);
        assert_eq!(file.validate_value(), Ok(()));
        file.value
            .insert("filename".into(), "../untrusted.zip".into());
        file.value.insert("mime".into(), "".into());
        file.value
            .insert("future".into(), Value::Ext(5, vec![0xc1]));
        assert_eq!(file.validate_value(), Ok(()));
        for field in ["data", "filename", "mime"] {
            let old = file.value.insert(field.into(), Value::Nil).unwrap();
            assert_eq!(file.validate_value(), Err(ValueError::WrongType(field)));
            file.value.insert(field.into(), old);
        }
        file.value.remove("data");
        assert_eq!(file.validate_value(), Err(ValueError::Missing("data")));
    }
}
fn raw(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).unwrap();
    bytes
}
fn raw_entries(count: usize) -> Vec<u8> {
    let e = Value::Map(vec![
        ("name".into(), "".into()),
        ("type".into(), "x".into()),
        ("value".into(), Value::Map(vec![])),
    ]);
    raw(Value::Map(vec![(
        "entries".into(),
        Value::Array(vec![e; count]),
    )]))
}

#[test]
fn encrypted_tags_are_bounded_unique_and_canonical() {
    for count in [255, 256, 257] {
        let mut record = Record::default();
        record.tags = (0..count).rev().map(|n| format!("t{n:03}")).collect();
        let result = record.encode_content(MAX_OPEN_MEMORY);
        if count > 256 {
            assert!(matches!(result, Err(Error::Limit)));
        } else {
            let result = result.unwrap();
            let opened = Record::decode_content(&result.bytes, MAX_OPEN_MEMORY).unwrap();
            assert!(opened.record.tags.windows(2).all(|p| p[0] < p[1]));
            assert_eq!(opened.record.tags.len(), count);
        }
    }
    for tags in [vec!["b", "a"], vec!["a", "a"]] {
        let bytes = raw(Value::Map(vec![
            ("entries".into(), Value::Array(vec![])),
            (
                "tags".into(),
                Value::Array(tags.into_iter().map(Value::from).collect()),
            ),
        ]));
        assert!(matches!(
            Record::decode_content(&bytes, MAX_OPEN_MEMORY),
            Err(Error::InvalidStructure)
        ));
    }
    let mut record = Record::default();
    record.tags = vec!["é".repeat(128)];
    assert!(record.encode_content(MAX_OPEN_MEMORY).is_ok());
    record.tags[0].push('x');
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::Limit)
    ));
    record.tags = vec!["same".into(), "same".into()];
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::InvalidStructure)
    ));
    record.tags.clear();
    record.extra.insert("tags".into(), Value::Nil);
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::ReservedField { index: None })
    ));
}

#[test]
fn mixed_standard_entries_round_trip_without_type_validation_on_read() {
    let mut record = Record::default();
    record.entries = vec![
        entry(
            "login/v1",
            &[
                ("username", "u".into()),
                ("password", "p".into()),
                ("url", "https://example.test".into()),
            ],
        ),
        entry("password/v1", &[("password", "p".into())]),
        entry("api_key/v1", &[("secret", "s".into())]),
        entry("note/v1", &[("text", "héllo".into())]),
    ];
    for e in &record.entries {
        e.validate_value().unwrap();
    }
    let bytes = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let decoded = Record::decode_content(&bytes.bytes, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(bytes.value_sizes, decoded.value_sizes);
    for e in &decoded.record.entries {
        e.validate_value().unwrap();
    }
    record.entries[0].value.insert("username".into(), 1.into());
    assert_eq!(
        record.entries[0].validate_value(),
        Err(ValueError::WrongType("username"))
    );
    let bytes = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    assert!(Record::decode_content(&bytes.bytes, MAX_OPEN_MEMORY).is_ok());
}

#[test]
fn unknown_fields_repeated_names_reorder_and_delete_are_preserved() {
    let mut record = Record::default();
    record
        .extra
        .insert("future".into(), Value::Binary(vec![0xc1, 255]));
    let mut e = entry("future/v1", &[("opaque", Value::Ext(3, vec![0xc1, 0]))]);
    e.extra.insert("future".into(), true.into());
    record.entries = vec![e, entry("note/v1", &[("text", "x".into())])];
    assert_eq!(
        record.entries[0].validate_value(),
        Err(ValueError::UnsupportedType)
    );
    let first = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let mut decoded = Record::decode_content(&first.bytes, MAX_OPEN_MEMORY)
        .unwrap()
        .record;
    assert_eq!(decoded.extra, record.extra);
    assert_eq!(decoded.entries[0].value, record.entries[0].value);
    decoded.entries[1]
        .value
        .insert("text".into(), "changed".into());
    decoded.entries.swap(0, 1);
    let second = decoded.encode_content(MAX_OPEN_MEMORY).unwrap();
    let result = Record::decode_content(&second.bytes, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(result.record.entries[1].extra, record.entries[0].extra);
    assert_eq!(result.record.entries[1].value, record.entries[0].value);
    assert_eq!(first.value_sizes[0], second.value_sizes[1]);
    decoded.entries.remove(0);
    assert_eq!(
        decoded.encode_content(MAX_OPEN_MEMORY).unwrap().value_sizes,
        vec![first.value_sizes[0]]
    );
}

#[test]
fn actual_value_spans_use_original_nonminimal_wire_widths() {
    let bytes =
        b"\x81\xa7entries\x91\x83\xa4name\xa0\xa4type\xa1x\xa5value\xde\x00\x01\xa1x\xcc\x01";
    let decoded = Record::decode_content(bytes, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(decoded.value_sizes, vec![7]);
    let canonical = decoded.record.encode_content(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(canonical.value_sizes, vec![4]);
    assert_ne!(&canonical.bytes[..], bytes);
    let nodes =
        confidex_vault::encoding::scan_messagepack(bytes, confidex_vault::encoding::CONTENT_LIMITS)
            .unwrap()
            .nodes;
    let required = bytes.len() * 2 + nodes * 256 + 2 * 1024 * 1024;
    assert!(Record::decode_content(bytes, required).is_ok());
    assert!(matches!(
        Record::decode_content(bytes, required - 1),
        Err(Error::Limit)
    ));
}

#[test]
fn float_bits_and_explicit_type_failures_are_preserved() {
    let mut record = Record::default();
    record.entries.push(entry(
        "future/v1",
        &[
            ("f32", Value::F32(f32::from_bits(0x7fc0_0011))),
            ("f64", Value::F64(f64::from_bits(0x7ff8_0000_0000_0011))),
        ],
    ));
    let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let decoded = Record::decode_content(&encoded.bytes, MAX_OPEN_MEMORY).unwrap();
    let Value::F32(a) = decoded.record.entries[0].value["f32"] else {
        panic!()
    };
    let Value::F64(b) = decoded.record.entries[0].value["f64"] else {
        panic!()
    };
    assert_eq!(a.to_bits(), 0x7fc0_0011);
    assert_eq!(b.to_bits(), 0x7ff8_0000_0000_0011);
    let mut login = entry("login/v1", &[("username", "u".into())]);
    assert_eq!(login.validate_value(), Err(ValueError::Missing("password")));
    login.value.insert("password".into(), "p".into());
    login.value.insert("url".into(), false.into());
    assert_eq!(login.validate_value(), Err(ValueError::WrongType("url")));
}

#[test]
fn invalid_structure_encoding_and_budget_fail_without_owned_results() {
    for bytes in [
        b"\xc1".as_slice(),
        b"\x82\xa7entries\x90\xa7entries\x90",
        b"\x81\xa7entries\x91\xc0",
        b"\x81\xa7entries\x91\x81\xa4name\xa0",
        b"\x81\xa7entries\x90\x00",
    ] {
        assert!(Record::decode_content(bytes, MAX_OPEN_MEMORY).is_err());
    }
    assert!(matches!(
        Record::decode_content(&raw_entries(1), 0),
        Err(Error::Limit)
    ));
    let mut record = Record::default();
    record.entries.push(entry("x", &[]));
    assert!(matches!(record.encode_content(0), Err(Error::Limit)));
    record.extra.insert("entries".into(), Value::Nil);
    assert_eq!(
        record.validate_structure(),
        Err(Error::ReservedField { index: None })
    );
    record.extra.clear();
    record.entries[0].type_name.clear();
    assert_eq!(
        record.validate_structure(),
        Err(Error::EmptyType { index: 0 })
    );
}

#[test]
fn entry_count_boundaries_are_enforced_on_read_and_write() {
    for count in [MAX_ENTRIES - 1, MAX_ENTRIES, MAX_ENTRIES + 1] {
        let bytes = raw_entries(count);
        let result = Record::decode_content(&bytes, MAX_OPEN_MEMORY);
        if count > MAX_ENTRIES {
            assert!(matches!(result, Err(Error::Limit)));
        } else {
            assert_eq!(result.unwrap().record.entries.len(), count);
        }
    }
    let mut record = Record::default();
    record.entries = (0..=MAX_ENTRIES).map(|_| entry("x", &[])).collect();
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::Limit)
    ));
}

#[test]
fn constructed_deep_or_ambiguous_values_fail_before_output_allocation() {
    let mut record = Record::default();
    let mut deep = Value::Nil;
    for _ in 0..65 {
        deep = Value::Array(vec![deep]);
    }
    record.entries.push(entry("x", &[("deep", deep)]));
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::Limit)
    ));
    record.entries[0].value.insert(
        "deep".into(),
        Value::Map(vec![("x".into(), 0.into()), ("x".into(), 1.into())]),
    );
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::InvalidEncoding)
    ));
    record.entries[0]
        .value
        .insert("deep".into(), Value::Map(vec![(1.into(), 0.into())]));
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn full_content_byte_boundary_is_inclusive_and_owned_payloads_remain_readable() {
    let mut record = Record::default();
    record.entries.push(entry("x", &[]));
    record.entries[0]
        .value
        .insert("data".into(), Value::Binary(vec![0; MAX_DECOMPRESSED - 46]));
    assert!(matches!(
        record.encode_content(MAX_OPEN_MEMORY),
        Err(Error::Limit)
    ));
    if let Value::Binary(data) = record.entries[0].value.get_mut("data").unwrap() {
        data.pop();
    }
    let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(encoded.bytes.len(), MAX_DECOMPRESSED);
    drop(record);
    let decoded = Record::decode_content(&encoded.bytes, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(decoded.value_sizes, encoded.value_sizes);
    drop(encoded);
    let Value::Binary(data) = &decoded.record.entries[0].value["data"] else {
        panic!()
    };
    assert_eq!(data.len(), MAX_DECOMPRESSED - 47);
}
