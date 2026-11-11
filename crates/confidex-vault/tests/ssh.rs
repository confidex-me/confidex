use confidex_vault::{
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
    ssh::{self, Error, Key},
};
use hpke::rand_core::SeedableRng;
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};

fn fixture(algorithm: Algorithm) -> PrivateKey {
    let mut rng = chacha20::ChaCha20Rng::from_seed([42; 32]);
    PrivateKey::random(&mut rng, algorithm).unwrap()
}

#[test]
fn supported_keys_import_validate_sign_and_survive_record_round_trips() {
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    ] {
        let private = fixture(algorithm.clone());
        let pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let key = Key::import(pem.as_bytes(), None, MAX_OPEN_MEMORY).unwrap();
        let mut value = key.to_value().unwrap();
        value.insert("future".into(), Value::Ext(4, vec![0xc1]));
        let record = Record {
            tags: Vec::new(),
            entries: vec![Entry {
                name: "SSH".into(),
                type_name: "ssh/v1".into(),
                value,
                extra: Mapping::new(),
            }],
            extra: Mapping::new(),
        };
        record.entries[0].validate_value().unwrap();
        let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
        let decoded = Record::decode_content(&encoded.bytes, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(decoded.record.entries[0].value, record.entries[0].value);
        let recovered = Key::from_value(&decoded.record.entries[0].value, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(key.fingerprint(), recovered.fingerprint());
        assert_eq!(
            key.public_blob().unwrap(),
            private.public_key().to_bytes().unwrap()
        );
        assert_eq!(
            key.public_text().unwrap(),
            private.public_key().to_openssh().unwrap()
        );
        let exported = key.private_text().unwrap();
        let imported = Key::import(exported.as_bytes(), None, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(key.fingerprint(), imported.fingerprint());
        assert_eq!(
            key.key_type(),
            if algorithm == Algorithm::Ed25519 {
                "Ed25519"
            } else {
                "ECDSA P-256"
            }
        );
        let signature = recovered.sign(b"SSH authentication data").unwrap();
        ssh::verify(
            &key.public_blob().unwrap(),
            b"SSH authentication data",
            &signature,
        )
        .unwrap();
        assert_eq!(
            ssh::verify(&key.public_blob().unwrap(), b"changed", &signature),
            Err(Error::Signature)
        );
        let mut trailing = signature.to_vec();
        trailing.push(0);
        assert_eq!(
            ssh::verify(
                &key.public_blob().unwrap(),
                b"SSH authentication data",
                &trailing
            ),
            Err(Error::Invalid)
        );
    }
}

#[test]
fn encrypted_import_checks_password_and_kdf_work_before_decrypting() {
    let private = fixture(Algorithm::Ed25519);
    for (rounds, salt, expected) in [
        (1, vec![7; 16], None),
        (65, vec![7; 16], Some(Error::Limit)),
        (1, vec![7; 65], Some(Error::Limit)),
    ] {
        let encrypted = private
            .encrypt_with(
                ssh_key::Cipher::Aes256Ctr,
                ssh_key::Kdf::Bcrypt { salt, rounds },
                123,
                b"import password",
            )
            .unwrap();
        let pem = encrypted.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let result = Key::import(pem.as_bytes(), Some(b"import password"), MAX_OPEN_MEMORY);
        if let Some(expected) = expected {
            assert_eq!(result.err(), Some(expected));
        } else {
            let key = result.unwrap();
            assert_eq!(
                key.public_blob().unwrap(),
                private.public_key().to_bytes().unwrap()
            );
            assert!(Key::from_value(&key.to_value().unwrap(), MAX_OPEN_MEMORY).is_ok());
            assert_eq!(
                Key::import(pem.as_bytes(), None, MAX_OPEN_MEMORY).err(),
                Some(Error::PassphraseRequired)
            );
            assert_eq!(
                Key::import(pem.as_bytes(), Some(b"wrong"), MAX_OPEN_MEMORY).err(),
                Some(Error::Authentication)
            );
        }
    }
}

#[test]
fn malformed_input_budgets_signature_limits_and_mismatched_keys_are_rejected() {
    let private = fixture(Algorithm::Ed25519);
    let pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
    for n in 0..pem.len() - 1 {
        assert!(Key::import(&pem.as_bytes()[..n], None, MAX_OPEN_MEMORY).is_err());
    }
    assert_eq!(
        Key::import(&vec![0; ssh::MAX_KEY + 1], None, MAX_OPEN_MEMORY).err(),
        Some(Error::Limit)
    );
    assert_eq!(
        Key::import(pem.as_bytes(), None, ssh::REQUIRED_MEMORY - 1).err(),
        Some(Error::Limit)
    );
    assert_eq!(
        Key::import(pem.as_bytes(), Some(&vec![0; 4097]), MAX_OPEN_MEMORY).err(),
        Some(Error::Limit)
    );
    let key = Key::import(pem.as_bytes(), None, MAX_OPEN_MEMORY).unwrap();
    assert!(key.sign(&vec![0; ssh::MAX_MESSAGE]).is_ok());
    assert_eq!(
        key.sign(&vec![0; ssh::MAX_MESSAGE + 1]).err(),
        Some(Error::Limit)
    );
    let mut value = key.to_value().unwrap();
    let Value::Binary(raw) = value.get_mut("private_key").unwrap() else {
        unreachable!()
    };
    let public = private.key_data().ed25519().unwrap().public.as_ref();
    let offset = raw.windows(32).position(|b| b == public).unwrap();
    raw[offset] ^= 1;
    assert!(Key::from_value(&value, MAX_OPEN_MEMORY).is_err());
    let entry = Entry {
        name: String::new(),
        type_name: "ssh/v1".into(),
        value,
        extra: Mapping::new(),
    };
    entry.validate_value().unwrap();
}
