use confidex_vault::{
    crypto, envelope, kdf,
    lock::{self, Error},
    record::Record,
    resources::MAX_OPEN_MEMORY,
    secret_key_text,
    trust::TrustError,
};
use rmpv::Value;

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
fn encode(value: &Value) -> Vec<u8> {
    let mut b = Vec::new();
    rmpv::encode::write_value(&mut b, value).unwrap();
    b
}

#[test]
fn public_inspection_checks_framing_and_profile_without_unlocking() {
    let header = lock::inspect(&fixture("lock_0")).unwrap();
    assert_eq!(header.vault_id, [7; 16]);
    assert_eq!(header.public_key.as_slice(), fixture("verifying_key"));
    assert!(lock::inspect(&fixture("negative_kdf")).is_err());
    assert!(lock::inspect(&fixture("negative_lock_version")).is_err());
    let mut trailing = fixture("lock_0");
    trailing.push(0);
    assert!(lock::inspect(&trailing).is_err());
    let mut changed = fixture("lock_0");
    *changed.last_mut().unwrap() ^= 1;
    assert!(lock::inspect(&changed).is_ok());
}
fn decode(wire: &[u8]) -> Value {
    rmpv::decode::read_value(&mut &*wire).unwrap()
}

#[test]
fn both_golden_locks_derive_password_keys_and_open_the_same_records() {
    let sk =
        secret_key_text::decode(std::str::from_utf8(&fixture("secret_key_text")).unwrap()).unwrap();
    let first = lock::open(
        &fixture("lock_0"),
        &fixture("password_0"),
        &sk,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let second = lock::open(
        &fixture("lock_1"),
        &fixture("password_1"),
        &sk,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    assert_eq!(first.vault_id(), [7; 16]);
    assert_eq!(first.anchor().public_key(), second.anchor().public_key());
    assert_eq!(
        first.keys().lock_plaintext(),
        second.keys().lock_plaintext()
    );
    let wire = fixture("revision_0");
    for vault in [&first, &second] {
        assert_eq!(
            envelope::open(&wire, vault.keys(), vault.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .record
                .entries
                .len(),
            2
        );
    }
}

#[test]
fn rewrapping_keeps_old_clients_keys_and_every_records_list_byte_unchanged() {
    use confidex_vault::records_list::{Limits, Reader, Writer};
    let old_lock = fixture("lock_0");
    let original_lock = old_lock.clone();
    let sk =
        secret_key_text::decode(std::str::from_utf8(&fixture("secret_key_text")).unwrap()).unwrap();
    let vault = lock::open(&old_lock, &fixture("password_0"), &sk, kdf::REQUIRED_MEMORY).unwrap();
    let keys_before = vault.keys().lock_plaintext();
    let list = fixture("records_list");
    let original_list = list.clone();
    for (password, budget, expected) in [
        (
            vec![0; 4097],
            kdf::REQUIRED_MEMORY,
            Error::Kdf(kdf::Error::InputLength),
        ),
        (
            vec![],
            kdf::REQUIRED_MEMORY - 1,
            Error::Kdf(kdf::Error::ResourceLimit),
        ),
        (vec![], MAX_OPEN_MEMORY + 1, Error::Limit),
    ] {
        assert_eq!(vault.rewrap(&password, budget).err(), Some(expected));
        assert_eq!(old_lock, original_lock);
        assert_eq!(vault.keys().lock_plaintext(), keys_before);
    }
    let first = vault
        .rewrap(b"new\0password", kdf::REQUIRED_MEMORY)
        .unwrap();
    let second = vault
        .rewrap(b"new\0password", kdf::REQUIRED_MEMORY)
        .unwrap();
    assert_ne!(first, second);
    assert_ne!(first, old_lock);
    assert!(lock::open(&first, &fixture("password_0"), &sk, kdf::REQUIRED_MEMORY).is_err());
    for (wire, password) in [
        (&old_lock, fixture("password_0")),
        (&first, b"new\0password".to_vec()),
        (&second, b"new\0password".to_vec()),
    ] {
        let client = lock::open(wire, &password, &sk, kdf::REQUIRED_MEMORY).unwrap();
        assert_eq!(client.keys().lock_plaintext(), keys_before);
        assert_eq!(client.keys().secret_key(), sk);
        assert_eq!(client.vault_id(), vault.vault_id());
        assert_eq!(client.anchor().public_key(), vault.anchor().public_key());
        let mut reader = Reader::new(list.as_slice(), client.anchor(), Limits::default()).unwrap();
        let mut output = Vec::new();
        let mut writer = Writer::new(
            &mut output,
            client.anchor(),
            reader.declared_items(),
            Limits::default(),
        )
        .unwrap();
        while let Some(object) = reader.read_next(MAX_OPEN_MEMORY).unwrap() {
            object
                .revision
                .open(client.keys(), MAX_OPEN_MEMORY)
                .unwrap();
            writer.push(object.wire, MAX_OPEN_MEMORY).unwrap();
        }
        reader.finish().unwrap();
        writer.finish().unwrap();
        assert_eq!(output, original_list);
    }
    assert_eq!(old_lock, original_lock);
    assert_eq!(list, original_list);
}

#[test]
fn creation_exposes_only_an_authenticated_context_and_separate_secret_key() {
    let created = lock::create(b"password\0UTF-8: \xc3\xa9", kdf::REQUIRED_MEMORY).unwrap();
    assert!(created.lock.len() <= lock::MAX_LOCK);
    let text = secret_key_text::encode(&created.vault.keys().secret_key());
    let sk = secret_key_text::decode(std::str::from_utf8(&text[..]).unwrap()).unwrap();
    let opened = lock::open(
        &created.lock,
        b"password\0UTF-8: \xc3\xa9",
        &sk,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    assert_eq!(opened.vault_id(), created.vault.vault_id());
    assert_eq!(
        opened.anchor().public_key(),
        created.vault.anchor().public_key()
    );
    let record = Record::default();
    let wire = envelope::seal(
        &record,
        created.vault.keys(),
        envelope::Options {
            vault_id: opened.vault_id(),
            record_id: [9; 16],
            parents: &[],
            epoch: 0,
            kind: envelope::EventKind::Content,
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    assert!(
        envelope::open(&wire, opened.keys(), opened.anchor(), None, MAX_OPEN_MEMORY)
            .unwrap()
            .record
            .entries
            .is_empty()
    );
    assert!(!created.lock.windows(32).any(|b| b == &sk[..]));
    assert!(
        !created
            .lock
            .windows(33)
            .any(|b| b == &opened.keys().lock_plaintext()[..])
    );
}

#[test]
fn wrong_secrets_and_changed_authenticated_header_fail() {
    let sk: [u8; 32] = fixture("secret_key").try_into().unwrap();
    let wire = fixture("lock_0");
    let password = fixture("password_0");
    assert_eq!(
        lock::open(&wire, b"wrong password", &sk, kdf::REQUIRED_MEMORY).err(),
        Some(Error::Crypto(crypto::Error::Authentication))
    );
    assert_eq!(
        lock::open(&wire, &password, &[0; 32], kdf::REQUIRED_MEMORY).err(),
        Some(Error::Crypto(crypto::Error::Authentication))
    );
    let mut changed = decode(&wire);
    let Value::Array(fields) = &mut changed else {
        unreachable!()
    };
    let Value::Binary(h) = &fields[0] else {
        unreachable!()
    };
    let mut header = decode(h);
    let Value::Array(h) = &mut header else {
        unreachable!()
    };
    h[1] = Value::Binary(vec![9; 16]);
    fields[0] = Value::Binary(encode(&header));
    assert_eq!(
        lock::open(&encode(&changed), &password, &sk, kdf::REQUIRED_MEMORY).err(),
        Some(Error::Crypto(crypto::Error::Authentication))
    );
    assert_eq!(wire, fixture("lock_0"));
}

#[test]
fn authenticated_header_key_must_match_recovered_material() {
    let sk: [u8; 32] = fixture("secret_key").try_into().unwrap();
    let p: [u8; 32] = fixture("p_0").try_into().unwrap();
    let keys = crypto::VaultKeys::from_material(
        1,
        &crypto::clamp_material(std::array::from_fn(|i| i as u8))[..],
    )
    .unwrap();
    let mut wire = decode(&fixture("lock_0"));
    let Value::Array(fields) = &mut wire else {
        unreachable!()
    };
    let Value::Binary(h) = &fields[0] else {
        unreachable!()
    };
    let mut header = decode(h);
    let Value::Array(h) = &mut header else {
        unreachable!()
    };
    h[2] = Value::Binary(vec![0; 32]);
    let h = encode(&header);
    let packet = crypto::seal_lock(&keys, &p, &sk, &[9; 24], &h).unwrap();
    fields[0] = Value::Binary(h);
    fields[1] = Value::Binary(packet);
    assert_eq!(
        lock::open(
            &encode(&wire),
            &fixture("password_0"),
            &sk,
            kdf::REQUIRED_MEMORY
        )
        .err(),
        Some(Error::Trust(TrustError::KeyMismatch))
    );
}

#[test]
fn malformed_versions_profiles_lengths_and_budgets_stop_before_kdf() {
    let sk: [u8; 32] = fixture("secret_key").try_into().unwrap();
    let wire = fixture("lock_0");
    let password = fixture("password_0");
    for (name, error) in [
        ("negative_lock_version", Error::Version),
        ("negative_kdf", Error::Kdf(kdf::Error::UnsupportedProfile)),
    ] {
        assert_eq!(
            lock::open(&fixture(name), &password, &sk, 0).err(),
            Some(error)
        );
    }
    for end in 0..wire.len() {
        assert!(lock::open(&wire[..end], &password, &sk, 0).is_err());
    }
    let mut bad = wire.clone();
    bad.push(0);
    assert_eq!(
        lock::open(&bad, &password, &sk, kdf::REQUIRED_MEMORY).err(),
        Some(Error::Invalid)
    );
    assert_eq!(
        lock::open(
            &vec![0; lock::MAX_LOCK + 1],
            &password,
            &sk,
            kdf::REQUIRED_MEMORY
        )
        .err(),
        Some(Error::Limit)
    );
    for budget in [0, kdf::REQUIRED_MEMORY - 1] {
        assert_eq!(
            lock::open(&wire, &password, &sk, budget).err(),
            Some(Error::Kdf(kdf::Error::ResourceLimit))
        );
        assert_eq!(
            lock::create(&password, budget).err(),
            Some(Error::Kdf(kdf::Error::ResourceLimit))
        );
    }
    assert_eq!(
        lock::create(&password, MAX_OPEN_MEMORY + 1).err(),
        Some(Error::Limit)
    );
    let long = vec![0; kdf::MAX_PASSWORD + 1];
    assert_eq!(
        lock::open(&wire, &long, &sk, kdf::REQUIRED_MEMORY).err(),
        Some(Error::Kdf(kdf::Error::InputLength))
    );
    assert_eq!(
        lock::create(&long, kdf::REQUIRED_MEMORY).err(),
        Some(Error::Kdf(kdf::Error::InputLength))
    );
}
