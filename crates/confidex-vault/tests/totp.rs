use confidex_vault::{
    record::{Entry, Mapping, Record, Value, ValueError},
    resources::MAX_OPEN_MEMORY,
    totp::{Algorithm, Error, Totp, decode_secret},
};

#[test]
fn rfc6238_appendix_b_vectors_and_constant_length_verification() {
    let times = [
        59,
        1_111_111_109,
        1_111_111_111,
        1_234_567_890,
        2_000_000_000,
        20_000_000_000,
    ];
    for (algorithm, length, expected) in [
        (
            Algorithm::Sha1,
            20,
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        ),
        (
            Algorithm::Sha256,
            32,
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        ),
        (
            Algorithm::Sha512,
            64,
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        ),
    ] {
        let secret: Vec<u8> = b"1234567890".iter().copied().cycle().take(length).collect();
        let totp = Totp::new(&secret, algorithm, 8, 30, 0).unwrap();
        for (time, expected) in times.into_iter().zip(expected) {
            assert_eq!(totp.generate(time).unwrap().as_str(), expected);
            assert!(totp.verify(time, expected).unwrap());
            for wrong in ["", "0000000", "000000000", "abcdefgh", "éééé", "00000000"] {
                assert!(!totp.verify(time, wrong).unwrap());
            }
        }
    }
}

#[test]
fn time_step_boundaries_t0_and_large_counters_do_not_overflow() {
    let key = b"12345678901234567890";
    let totp = Totp::new(key, Algorithm::Sha1, 6, 30, 100).unwrap();
    assert_eq!(totp.generate(99).err(), Some(Error::TimeBeforeStart));
    assert_eq!(totp.generate(100).unwrap().as_str(), "755224");
    assert_eq!(totp.generate(129).unwrap().as_str(), "755224");
    assert_eq!(totp.generate(130).unwrap().as_str(), "287082");
    assert_eq!(totp.generate(100).unwrap().valid_for_seconds, 30);
    assert_eq!(totp.generate(129).unwrap().valid_for_seconds, 1);
    assert_eq!(totp.generate(130).unwrap().valid_for_seconds, 30);
    assert!(
        Totp::new(key, Algorithm::Sha512, 8, 1, 0)
            .unwrap()
            .generate(u64::MAX)
            .is_ok()
    );
    assert!(
        Totp::new(key, Algorithm::Sha256, 7, 86_400, u64::MAX)
            .unwrap()
            .generate(u64::MAX)
            .is_ok()
    );
}

#[test]
fn base32_import_checks_padding_unused_bits_and_size() {
    for (text, bytes) in [
        ("MY======", b"f".as_slice()),
        ("MZXQ====", b"fo"),
        ("MZXW6===", b"foo"),
        ("MZXW6YQ=", b"foob"),
        ("MZXW6YTB", b"fooba"),
        ("MZXW6YTBOI======", b"foobar"),
    ] {
        for input in [text.to_owned(), text.trim_end_matches('=').to_lowercase()] {
            assert_eq!(&decode_secret(&input).unwrap()[..], bytes);
        }
    }
    for bad in [
        "",
        "=",
        "A",
        "AAA",
        "AAAAAA",
        "MZ",
        "MY=",
        "MY=======",
        "M=Y=====",
        "MY====== ",
        "M0",
        "M1",
        "éé",
        "MY-=====",
    ] {
        assert_eq!(decode_secret(bad).err(), Some(Error::InvalidBase32));
    }
    assert_eq!(decode_secret(&"A".repeat(205)).unwrap().len(), 128);
    assert_eq!(
        decode_secret(&format!("{}===", "A".repeat(205)))
            .unwrap()
            .len(),
        128
    );
    for n in [207, 208, 209, 4096] {
        assert!(decode_secret(&"A".repeat(n)).is_err());
    }
}

#[test]
fn typed_parameters_validate_explicitly_and_round_trip_without_coercion() {
    let mut entry = Entry {
        name: String::new(),
        type_name: "totp/v1".into(),
        value: Mapping::from([(
            "secret".into(),
            Value::Binary(b"12345678901234567890".to_vec()),
        )]),
        extra: Mapping::new(),
    };
    assert_eq!(entry.validate_value(), Ok(()));
    assert_eq!(
        Totp::from_value(&entry.value)
            .unwrap()
            .generate(59)
            .unwrap()
            .as_str(),
        "287082"
    );
    for (field, bad) in [
        ("secret", Value::Binary(vec![])),
        ("secret", Value::Binary(vec![0; 129])),
        ("algorithm", "MD5".into()),
        ("algorithm", "sha1".into()),
        ("digits", 0.into()),
        ("digits", 9.into()),
        ("digits", u64::MAX.into()),
        ("period", 0.into()),
        ("period", 86_401.into()),
        ("period", u64::MAX.into()),
    ] {
        let old = entry.value.insert(field.into(), bad);
        assert_eq!(entry.validate_value(), Err(ValueError::InvalidValue(field)));
        if let Some(v) = old {
            entry.value.insert(field.into(), v);
        } else {
            entry.value.remove(field);
        }
    }
    for (field, bad) in [
        ("secret", "MY".into()),
        ("algorithm", Value::Nil),
        ("digits", "6".into()),
        ("period", (-1).into()),
        ("t0", Value::F64(0.0)),
    ] {
        let old = entry.value.insert(field.into(), bad);
        assert_eq!(entry.validate_value(), Err(ValueError::WrongType(field)));
        if let Some(v) = old {
            entry.value.insert(field.into(), v);
        } else {
            entry.value.remove(field);
        }
    }
    entry.value.remove("secret");
    assert_eq!(entry.validate_value(), Err(ValueError::Missing("secret")));
    entry
        .value
        .insert("secret".into(), "invalid persisted value".into());
    entry
        .value
        .insert("future".into(), Value::Ext(4, vec![0xc1]));
    let record = Record {
        tags: Vec::new(),
        entries: vec![entry],
        extra: Mapping::new(),
    };
    let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let decoded = Record::decode_content(&encoded.bytes, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(decoded.record.entries[0].value, record.entries[0].value);
    assert_eq!(
        decoded.record.entries[0].validate_value(),
        Err(ValueError::WrongType("secret"))
    );
}
