use super::*;

fn fixture() -> ssh_key::PrivateKey {
    ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
        "public SSH fixture",
    )
    .unwrap()
}

#[test]
fn projections_are_derived_and_never_written_back_as_independent_values() {
    let pem = fixture().to_openssh(ssh_key::LineEnding::LF).unwrap();
    let mut field = import(pem.as_bytes(), None).unwrap();
    assert!(field.values["public_key"].starts_with("ssh-ed25519 "));
    assert!(field.values["fingerprint"].starts_with("SHA256:"));
    assert_eq!(field.values["key_type"], "Ed25519");
    assert!(field.values["private_key"].starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    let expected = field.values.clone();
    for value in field.values.values_mut() {
        value.zeroize();
        *value = "not authoritative".into();
    }
    let record = crate::field_record(&field).unwrap();
    assert_eq!(record.entries[0].value.len(), 1);
    let actual = crate::fields::read(&record).unwrap();
    assert_eq!(actual[0].values, expected);
}

#[test]
fn encrypted_input_requires_a_password_and_bad_input_does_not_produce_a_field() {
    let encrypted = fixture()
        .encrypt_with(
            ssh_key::Cipher::Aes256Ctr,
            ssh_key::Kdf::Bcrypt {
                salt: vec![7; 16],
                rounds: 1,
            },
            123,
            b"public passphrase",
        )
        .unwrap();
    let pem = encrypted.to_openssh(ssh_key::LineEnding::LF).unwrap();
    assert!(matches!(
        import(pem.as_bytes(), None),
        Err(Error::PassphraseRequired)
    ));
    assert!(matches!(
        import(pem.as_bytes(), Some("bad")),
        Err(Error::Authentication)
    ));
    let field = import(pem.as_bytes(), Some("public passphrase")).unwrap();
    assert_eq!(field.values["key_type"], "Ed25519");
    assert!(import(&vec![0; MAX_KEY + 1], None).is_err());
    assert!(matches!(import(b"invalid", None), Err(Error::Invalid)));
    assert!(matches!(
        import(pem.as_bytes(), Some(&"x".repeat(4097))),
        Err(Error::Limit)
    ));
}

use zeroize::Zeroize;
