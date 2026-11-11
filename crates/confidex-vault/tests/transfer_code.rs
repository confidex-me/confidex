use confidex_vault::{
    crypto::{VaultKeys, clamp_material},
    sync, transfer_code,
};

fn keys() -> VaultKeys {
    VaultKeys::from_material(1, &clamp_material(std::array::from_fn(|i| i as u8))[..]).unwrap()
}

#[test]
fn transfer_preserves_the_original_secret_and_restores_the_public_uuid() {
    let keys = keys();
    let secret = keys.secret_key();
    let public = keys.signing_key().verifying_key().to_bytes();
    let encoded = transfer_code::encode(&secret, &public);
    let text = std::str::from_utf8(&encoded[..]).unwrap();
    assert_eq!(text.len(), 87);
    assert_eq!(text.split('-').count(), 11);
    assert!(text.split('-').all(|s| s.len() == 7));
    assert_eq!(text.replace('-', "").len(), 77);
    let expected = sync::id(&public);
    assert_eq!(expected[6] >> 4, 5);
    assert_eq!(expected[8] >> 6, 2);
    for text in [
        text.to_owned(),
        text.replace('-', ""),
        format!("\t{}\n", text.to_ascii_lowercase()),
    ] {
        let decoded = transfer_code::decode(&text).unwrap();
        assert_eq!(*decoded.secret, *secret);
        assert_eq!(decoded.id, expected);
    }
}

#[test]
fn transfer_matches_an_independent_sha_and_base32_vector() {
    let text = transfer_code::encode(&[0; 32], &[1; 32]);
    assert_eq!(
        std::str::from_utf8(&text[..]).unwrap(),
        "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAA2JFQ-VNQO6TO-CQQNRTP-YWSZQV2"
    );
    assert_eq!(
        sync::id(&[1; 32]),
        [
            0x0d, 0x24, 0xb0, 0xab, 0x60, 0xef, 0x5d, 0xc2, 0x84, 0x1b, 0x19, 0xbf, 0x16, 0x96,
            0x61, 0x5d
        ]
    );
}

#[test]
fn decoder_rejects_noncanonical_text_and_wrong_checksum() {
    let keys = keys();
    let encoded = transfer_code::encode(
        &keys.secret_key(),
        keys.signing_key().verifying_key().as_bytes(),
    );
    let text = std::str::from_utf8(&encoded[..]).unwrap();
    for text in [
        text[..86].to_owned(),
        format!("{text}-"),
        text.replacen('-', "_", 1),
        text.replacen('A', "0", 1),
        "Ж".repeat(77),
        "A".repeat(129),
        "A".repeat(52),
        "AAAAAA-AAAAAAA-AAAAAA-AAAAAAA-AAAAAA-AAAAAAA-AAAAAA-AAAAAAA".into(),
    ] {
        if text == std::str::from_utf8(&encoded[..]).unwrap() {
            continue;
        }
        assert!(transfer_code::decode(&text).is_err());
    }
    let mut plain = text.replace('-', "").into_bytes();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let last = alphabet.iter().position(|c| *c == plain[76]).unwrap();
    plain[76] = alphabet[last | 1];
    assert!(transfer_code::decode(std::str::from_utf8(&plain).unwrap()).is_err());

    let mut accepted = 0;
    for value in 0..16 {
        let mut plain = text.replace('-', "").into_bytes();
        let a = alphabet.iter().position(|c| *c == plain[60]).unwrap();
        let b = alphabet.iter().position(|c| *c == plain[61]).unwrap();
        plain[60] = alphabet[(a & !1) | (value >> 3)];
        plain[61] = alphabet[(b & 3) | ((value & 7) << 2)];
        accepted +=
            usize::from(transfer_code::decode(std::str::from_utf8(&plain).unwrap()).is_ok());
    }
    assert_eq!(accepted, 1);
}
