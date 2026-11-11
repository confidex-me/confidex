use confidex_vault::{
    crypto::{self, VaultKeys, clamp_material},
    envelope::{self, Error, EventKind, Options},
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
    trust::{TrustAnchor, TrustError},
};
use ed25519_dalek::Signer;

fn keys() -> VaultKeys {
    VaultKeys::from_material(1, &clamp_material([3; 32])[..]).unwrap()
}
fn anchor(keys: &VaultKeys) -> TrustAnchor {
    TrustAnchor::from_local_pin(
        [7; 16],
        Some(&keys.signing_key().verifying_key().to_bytes()),
    )
    .unwrap()
}
fn options() -> Options<'static> {
    Options {
        vault_id: [7; 16],
        record_id: [8; 16],
        parents: &[],
        epoch: 1_794_096_000_123,
        kind: EventKind::Content,
    }
}
fn record() -> Record {
    Record {
        tags: vec!["z".into(), "a".into()],
        entries: vec![Entry {
            name: "".into(),
            type_name: "note/v1".into(),
            value: Mapping::from([("text".into(), "secret é".into())]),
            extra: Mapping::from([("future".into(), Value::Ext(3, vec![193, 0]))]),
        }],
        extra: Mapping::new(),
    }
}
fn encode(v: Value) -> Vec<u8> {
    let mut b = Vec::new();
    rmpv::encode::write_value(&mut b, &v).unwrap();
    b
}
fn header() -> Vec<Value> {
    vec![
        2.into(),
        Value::Binary(vec![7; 16]),
        Value::Binary(vec![8; 16]),
        Value::Array(vec![]),
        Value::Map(vec![
            ("epoch".into(), options().epoch.into()),
            ("value_sizes".into(), Value::Array(vec![])),
        ]),
        0.into(),
    ]
}
fn metadata(h: &mut [Value], key: &str, value: Value) {
    let Value::Map(m) = &mut h[4] else {
        unreachable!()
    };
    m.iter_mut()
        .find(|(k, _)| k.as_str() == Some(key))
        .unwrap()
        .1 = value;
}
fn signed(h: &[u8], c: Vec<u8>, keys: &VaultKeys) -> Vec<u8> {
    let sig = keys
        .signing_key()
        .sign(&crypto::signed_record_bytes(h, &c))
        .to_bytes();
    encode(Value::Array(vec![
        Value::Binary(h.to_vec()),
        Value::Binary(c),
        Value::Binary(sig.to_vec()),
    ]))
}
fn verify_header(h: Vec<Value>) -> Result<(), Error> {
    let keys = keys();
    let wire = signed(&encode(Value::Array(h)), vec![0; 48], &keys);
    envelope::verify(&wire, &anchor(&keys), None, MAX_OPEN_MEMORY).map(|_| ())
}
fn fixture(name: &str) -> Vec<u8> {
    let text = include_str!("../../../tests/fixtures/vectors.hex");
    let hex = text
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap();
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn public_api_opens_unchanged_golden_revisions_and_negative_vectors() {
    let material = clamp_material(std::array::from_fn(|i| i as u8));
    let keys = VaultKeys::from_material(1, &material[..]).unwrap();
    let pin = anchor(&keys);
    for i in 0..5 {
        let wire = fixture(&format!("revision_{i}"));
        let expected: [u8; 32] = fixture(&format!("revision_id_{i}")).try_into().unwrap();
        let opened = envelope::open(&wire, &keys, &pin, Some(&expected), MAX_OPEN_MEMORY).unwrap();
        assert_eq!(opened.revision.id(), expected);
        assert_eq!(
            opened.revision.header().metadata.epoch,
            1_794_096_000_030 + i
        );
        assert_eq!(opened.record.entries.len(), if i == 4 { 0 } else { 2 });
    }
    for (name, expected) in [
        ("negative_record_version", Error::Version),
        (
            "negative_signature",
            Error::Trust(TrustError::InvalidSignature),
        ),
        (
            "negative_resigned_header",
            Error::Crypto(crypto::Error::Authentication),
        ),
        ("negative_sizes", Error::ValueSizes),
    ] {
        assert_eq!(
            envelope::open(&fixture(name), &keys, &pin, None, MAX_OPEN_MEMORY).err(),
            Some(expected)
        );
    }
}

#[test]
fn fresh_seals_round_trip_and_canonicalize_public_sets() {
    let keys = keys();
    let pin = anchor(&keys);
    let record = record();
    let first = envelope::seal(&record, &keys, options(), MAX_OPEN_MEMORY).unwrap();
    let second = envelope::seal(&record, &keys, options(), MAX_OPEN_MEMORY).unwrap();
    assert_ne!(first, second);
    let opened = envelope::open(&first, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(opened.record.tags, ["a", "z"]);
    assert_eq!(opened.revision.header().metadata.epoch, options().epoch);
    assert_eq!(
        opened.record.entries[0].value["text"].as_str(),
        Some("secret é")
    );
    assert_eq!(
        opened.record.entries[0].extra["future"],
        Value::Ext(3, vec![193, 0])
    );
    assert_eq!(
        envelope::open(&first, &keys, &pin, Some(&[0; 32]), MAX_OPEN_MEMORY).err(),
        Some(Error::UnexpectedRevision)
    );
    let wrong = VaultKeys::from_material(1, &clamp_material([4; 32])[..]).unwrap();
    assert_eq!(
        envelope::open(&first, &wrong, &pin, None, MAX_OPEN_MEMORY).err(),
        Some(Error::Crypto(crypto::Error::Authentication))
    );
    for budget in [0, 24 * 1024 * 1024 - 1, MAX_OPEN_MEMORY + 1] {
        assert_eq!(
            envelope::verify(&first, &pin, None, budget).err(),
            Some(Error::Limit)
        );
        assert_eq!(
            envelope::seal(&record, &keys, options(), budget).err(),
            Some(Error::Limit)
        );
    }
}

#[test]
fn header_schema_counts_orders_and_epoch_are_checked_before_crypto() {
    for n in [4095, 4096, 4097] {
        let mut h = header();
        metadata(&mut h, "value_sizes", Value::Array(vec![1.into(); n]));
        assert_eq!(
            verify_header(h),
            if n <= 4096 { Ok(()) } else { Err(Error::Limit) }
        );
    }
    for n in [1023, 1024, 1025] {
        let mut h = header();
        h[3] = Value::Array(
            (0..n)
                .map(|i: u32| {
                    let mut id = vec![0; 32];
                    id[..4].copy_from_slice(&i.to_be_bytes());
                    Value::Binary(id)
                })
                .collect(),
        );
        assert_eq!(
            verify_header(h),
            if n <= 1024 { Ok(()) } else { Err(Error::Limit) }
        );
    }
    for bad in [Value::Nil, (-1).into(), Value::F64(1.0), "1".into()] {
        let mut h = header();
        metadata(&mut h, "epoch", bad);
        assert_eq!(verify_header(h), Err(Error::Invalid));
    }
    for epoch in [0, u64::MAX] {
        let mut h = header();
        metadata(&mut h, "epoch", epoch.into());
        assert_eq!(verify_header(h), Ok(()));
    }
    let mut h = header();
    h[0] = 1.into();
    assert_eq!(verify_header(h), Err(Error::Version));
    let mut h = header();
    let Value::Map(m) = &mut h[4] else {
        unreachable!()
    };
    m.push(("tags".into(), Value::Array(vec![])));
    assert_eq!(verify_header(h), Err(Error::Invalid));
    let mut h = header();
    h[3] = Value::Array(vec![Value::Binary(vec![0; 32]); 2]);
    assert_eq!(verify_header(h), Err(Error::Invalid));
    let mut h = header();
    let Value::Map(m) = &mut h[4] else {
        unreachable!()
    };
    m.pop();
    assert_eq!(verify_header(h), Err(Error::Invalid));
    let mut h = header();
    h[5] = 1.into();
    assert_eq!(verify_header(h), Err(Error::Invalid));
}

#[test]
fn outer_framing_signature_and_expected_id_stop_before_decryption() {
    let keys = keys();
    let pin = anchor(&keys);
    let good = signed(&encode(Value::Array(header())), vec![0; 48], &keys);
    assert!(envelope::verify(&good, &pin, None, MAX_OPEN_MEMORY).is_ok());
    assert!(matches!(
        envelope::open(&good, &keys, &pin, None, MAX_OPEN_MEMORY),
        Err(Error::Crypto(_))
    ));
    for n in 0..good.len() {
        assert!(envelope::verify(&good[..n], &pin, None, MAX_OPEN_MEMORY).is_err());
    }
    let mut bad = good.clone();
    bad.push(0);
    assert_eq!(
        envelope::verify(&bad, &pin, None, MAX_OPEN_MEMORY).err(),
        Some(Error::Invalid)
    );
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        envelope::open(&bad, &keys, &pin, None, MAX_OPEN_MEMORY).err(),
        Some(Error::Trust(TrustError::InvalidSignature))
    );
    let other = TrustAnchor::from_local_pin(
        [9; 16],
        Some(&keys.signing_key().verifying_key().to_bytes()),
    )
    .unwrap();
    assert_eq!(
        envelope::verify(&good, &other, None, MAX_OPEN_MEMORY).err(),
        Some(Error::Trust(TrustError::WrongVault))
    );
    assert_eq!(
        envelope::verify(&good, &pin, Some(&[0; 32]), MAX_OPEN_MEMORY).err(),
        Some(Error::UnexpectedRevision)
    );
    let oversized = signed(
        &encode(Value::Array(header())),
        vec![0; envelope::MAX_PACKET + 1],
        &keys,
    );
    assert_eq!(
        envelope::verify(&oversized, &pin, None, MAX_OPEN_MEMORY).err(),
        Some(Error::Limit)
    );
}

#[test]
fn deletion_creation_requires_parents_and_empty_content() {
    let keys = keys();
    let mut o = options();
    o.kind = EventKind::Deletion;
    assert_eq!(
        envelope::seal(&Record::default(), &keys, o, MAX_OPEN_MEMORY).err(),
        Some(Error::Invalid)
    );
    let parents = [[9; 32]];
    let mut o = options();
    o.kind = EventKind::Deletion;
    o.parents = &parents;
    assert_eq!(
        envelope::seal(&record(), &keys, o, MAX_OPEN_MEMORY).err(),
        Some(Error::Invalid)
    );
    let mut o = options();
    o.kind = EventKind::Deletion;
    o.parents = &parents;
    let wire = envelope::seal(&Record::default(), &keys, o, MAX_OPEN_MEMORY).unwrap();
    let opened = envelope::open(&wire, &keys, &anchor(&keys), None, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(opened.revision.header().kind, EventKind::Deletion);
    assert!(opened.record.entries.is_empty());
}

#[test]
fn tags_are_only_available_after_authenticated_opening() {
    let keys = keys();
    let pin = anchor(&keys);
    let mut record = record();
    record.tags = vec!["sensitive-tag-銀行-unique-fixture".into()];
    let wire = envelope::seal(&record, &keys, options(), MAX_OPEN_MEMORY).unwrap();
    let tag = record.tags[0].as_bytes();
    assert!(!wire.windows(tag.len()).any(|bytes| bytes == tag));
    let verified = envelope::verify(&wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(verified.header().metadata.epoch, options().epoch);
    let content = verified.open(&keys, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(content.tags, record.tags);
}

#[test]
fn compression_cap_is_applied_before_emitting_an_envelope() {
    let mut data = vec![0u8; 4_100_000];
    let mut state = 7u32;
    for b in &mut data {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *b = state as u8;
    }
    let mut r = record();
    r.entries[0].type_name = "file/v1".into();
    r.entries[0].value = Mapping::from([("data".into(), Value::Binary(data))]);
    r.entries[0].validate_value().unwrap();
    assert_eq!(
        envelope::seal(&r, &keys(), options(), MAX_OPEN_MEMORY).err(),
        Some(Error::Limit)
    );
}

#[test]
fn full_content_boundary_round_trips_through_encryption_and_budgeting() {
    let keys = keys();
    let mut record = Record::default();
    let size = confidex_vault::resources::MAX_DECOMPRESSED - 47;
    record.entries.push(Entry {
        name: String::new(),
        type_name: "x".into(),
        value: Mapping::from([("data".into(), Value::Binary(vec![0; size]))]),
        extra: Mapping::new(),
    });
    let wire = envelope::seal(&record, &keys, options(), MAX_OPEN_MEMORY).unwrap();
    drop(record);
    let pin = anchor(&keys);
    let opened = envelope::open(&wire, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        opened.record.entries[0].value["data"]
            .as_slice()
            .unwrap()
            .len(),
        size
    );
    drop(opened);
    assert!(envelope::open(&wire, &keys, &pin, None, 64 * 1024 * 1024).is_err());
}

fn file_record(size: usize) -> Record {
    Record {
        tags: Vec::new(),
        entries: vec![Entry {
            name: String::new(),
            type_name: "file/v1".into(),
            value: Mapping::from([("data".into(), Value::Binary(vec![0; size]))]),
            extra: Mapping::new(),
        }],
        extra: Mapping::new(),
    }
}

#[test]
fn file_larger_than_compressed_cap_round_trips_with_encrypted_labels_and_exact_sizes() {
    let keys = keys();
    let mut r = file_record(5_000_000);
    r.entries[0]
        .value
        .insert("filename".into(), "../scan.zip".into());
    r.entries[0]
        .value
        .insert("mime".into(), "application/zip".into());
    r.entries[0]
        .value
        .insert("future".into(), Value::Ext(8, vec![0xc1, 255]));
    let expected = encode(Value::Map(
        r.entries[0]
            .value
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.clone()))
            .collect(),
    ))
    .len();
    assert!(expected > 5_000_000);
    let wire = envelope::seal(&r, &keys, options(), MAX_OPEN_MEMORY).unwrap();
    assert!(wire.len() < 100_000);
    for label in [b"../scan.zip".as_slice(), b"application/zip"] {
        assert!(!wire.windows(label.len()).any(|w| w == label));
    }
    let pin = anchor(&keys);
    let opened = envelope::open(&wire, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        opened.revision.header().metadata.value_sizes,
        [expected as u64]
    );
    assert_eq!(opened.record.entries[0].value, r.entries[0].value);
    assert_eq!(opened.record.entries[0].validate_value(), Ok(()));
}

#[test]
fn encrypted_files_accept_exact_compressed_boundary_and_reject_the_next_byte() {
    use hpke::rand_core::SeedableRng;
    // Stored blocks fix the stream size independently of compressor heuristics.
    fn stored(raw: &[u8]) -> Vec<u8> {
        let mut out = vec![0x78, 0x01];
        let blocks = raw.chunks(65_535);
        let count = blocks.len();
        assert_eq!(count, 62);
        for (i, block) in blocks.enumerate() {
            out.push(u8::from(i + 1 == count));
            let len = block.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(block);
        }
        let (mut a, mut b) = (1u32, 0u32);
        for &byte in raw {
            a = (a + u32::from(byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        out.extend_from_slice(&((b << 16) | a).to_be_bytes());
        out
    }
    let keys = keys();
    let pin = anchor(&keys);
    for length in [3_999_999, 4_000_000, 4_000_001] {
        let raw_len = length - 316;
        let mut r = file_record(raw_len - 100);
        let overhead = r.encode_content(MAX_OPEN_MEMORY).unwrap().bytes.len() - (raw_len - 100);
        let Value::Binary(data) = r.entries[0].value.get_mut("data").unwrap() else {
            unreachable!()
        };
        data.resize(raw_len - overhead, 0);
        let content = r.encode_content(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(content.bytes.len(), raw_len);
        let compressed = stored(&content.bytes);
        assert_eq!(compressed.len(), length);
        let mut h = header();
        metadata(
            &mut h,
            "value_sizes",
            Value::Array(content.value_sizes.iter().map(|n| (*n).into()).collect()),
        );
        let h = encode(Value::Array(h));
        let mut rng = chacha20::ChaCha20Rng::from_seed([1; 32]);
        let ciphertext =
            crypto::seal_record(&keys.secret_key(), &compressed, &h, &mut rng).unwrap();
        assert_eq!(ciphertext.len(), length + 48);
        let wire = signed(&h, ciphertext, &keys);
        if length <= 4_000_000 {
            let opened = envelope::open(&wire, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
            assert_eq!(opened.record.entries[0].value, r.entries[0].value);
            assert_eq!(
                opened.revision.header().metadata.value_sizes,
                content.value_sizes
            );
        } else {
            assert_eq!(
                envelope::open(&wire, &keys, &pin, None, MAX_OPEN_MEMORY).err(),
                Some(Error::Limit)
            );
        }
    }
}

#[test]
fn protected_note_is_encrypted_entry_metadata_in_an_ordinary_revision() {
    let keys = keys();
    let pin = anchor(&keys);
    let mut content = record();
    let mut previous = None;
    for (epoch, protected) in [false, true, false].into_iter().enumerate() {
        let metadata = Value::Map(vec![
            ("future-ui-attribute".into(), Value::Ext(4, vec![1, 2, 3])),
            ("protected".into(), Value::Boolean(protected)),
        ]);
        content.entries[0]
            .extra
            .insert("metadata".into(), metadata.clone());
        let parents: Vec<_> = previous.into_iter().collect();
        let wire = envelope::seal(
            &content,
            &keys,
            Options {
                parents: &parents,
                epoch: epoch as u64,
                ..options()
            },
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        let opened = envelope::open(&wire, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
        let field = &opened.record.entries[0];
        assert_eq!(field.type_name, "note/v1");
        assert_eq!(field.value, content.entries[0].value);
        assert_eq!(field.extra["metadata"], metadata);
        assert_eq!(field.extra["future"], content.entries[0].extra["future"]);
        assert_eq!(opened.revision.header().parents, parents);
        assert_eq!(opened.record.tags, ["a", "z"]);
        previous = Some(opened.revision.id());
    }
}
