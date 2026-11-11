use super::*;
#[cfg(feature = "save_kdbx4")]
use crate::config::{DatabaseConfig, KdfConfig};

const PASSWORD: &str = "PUBLIC-FIXTURE-DATABASE";
const V3: &[u8] = include_bytes!("../../tests/resources/test_db_with_password.kdbx");
const V4: &[u8] =
    include_bytes!("../../../../crates/confidex-app/tests/import_fixtures/kdbx/password.kdbx");
const FILE: &[u8] =
    include_bytes!("../../../../crates/confidex-app/tests/import_fixtures/kdbx/public.key");
const WITH_FILE: &[u8] =
    include_bytes!("../../../../crates/confidex-app/tests/import_fixtures/kdbx/keyfile.kdbx");
const BOTH: &[u8] =
    include_bytes!("../../../../crates/confidex-app/tests/import_fixtures/kdbx/both.kdbx");

#[test]
fn independently_read_variant_matrix_and_wrong_keyfiles() -> Result<(), Error> {
    use crate::config::OuterCipherConfig;
    let raw_key = include_bytes!("../../tests/resources/bounded/public.raw").as_slice();
    let xml_key = include_bytes!("../../tests/resources/bounded/public-v2.keyx").as_slice();
    let hex_key = include_bytes!("../../tests/resources/bounded/public.hex").as_slice();
    for (input, password, keyfile, cipher) in [
        (
            include_bytes!("../../tests/resources/bounded/argon2d-aes.kdbx").as_slice(),
            Some("PUBLIC-VARIANT-DATABASE"),
            None,
            OuterCipherConfig::AES256,
        ),
        (
            include_bytes!("../../tests/resources/bounded/argon2d-aes-v10.kdbx").as_slice(),
            Some("PUBLIC-VARIANT-DATABASE"),
            None,
            OuterCipherConfig::AES256,
        ),
        (
            include_bytes!("../../tests/resources/bounded/argon2id-chacha.kdbx").as_slice(),
            Some("PUBLIC-VARIANT-DATABASE"),
            Some(xml_key),
            OuterCipherConfig::ChaCha20,
        ),
        (
            include_bytes!("../../tests/resources/bounded/aes-twofish.kdbx").as_slice(),
            None,
            Some(raw_key),
            OuterCipherConfig::Twofish,
        ),
        (
            include_bytes!("../../tests/resources/bounded/argon2id-aes-hex.kdbx").as_slice(),
            None,
            Some(hex_key),
            OuterCipherConfig::AES256,
        ),
    ] {
        let header = Header::inspect(input, &Limits::default(), &mut |_| true)?;
        assert_eq!(header.version(), &DatabaseVersion::KDB4(1));
        assert_eq!(header.cipher(), &cipher);
        let mut raw = Raw::open(input, password, keyfile, Limits::default(), &mut |_, _| {
            true
        })?;
        assert!(raw
            .header()
            .windows(b"PUBLIC-EXTENSION".len())
            .any(|part| part == b"PUBLIC-EXTENSION"));
        assert_eq!(raw.binary_count(), 2);
        for index in 0..2 {
            let binary = raw.binary(index).ok_or(Error::Malformed)?;
            if binary.bytes.is_empty() {
                assert!(!binary.protected);
            } else {
                assert_eq!(binary.bytes, b"PUBLIC-KDBX-BINARY\0\xff\n");
                assert!(binary.protected);
            }
        }
        let decrypted = values(&mut raw)?;
        assert!(decrypted
            .iter()
            .any(|value| value.as_slice() == b"PUBLIC-VARIANT-PASSWORD"));
        assert!(decrypted
            .iter()
            .any(|value| value.as_slice() == b"PUBLIC-VARIANT-CUSTOM"));
        if keyfile.is_some() {
            assert_eq!(
                Raw::open(
                    input,
                    password,
                    Some(&[10; 32]),
                    Limits::default(),
                    &mut |_, _| true
                )
                .err(),
                Some(Error::Credentials)
            );
        }
    }
    let argon = include_bytes!("../../tests/resources/bounded/argon2id-chacha.kdbx");
    let mut derived = false;
    assert_eq!(
        Raw::open(
            argon,
            Some("PUBLIC-VARIANT-DATABASE"),
            Some(xml_key),
            Limits {
                argon_memory: 65535,
                ..Limits::default()
            },
            &mut |phase, _| {
                derived |= phase == Phase::Kdf;
                true
            }
        )
        .err(),
        Some(Error::KdfLimit)
    );
    assert!(!derived);
    Ok(())
}

fn values(raw: &mut Raw) -> Result<Vec<Zeroizing<Vec<u8>>>, Error> {
    let mut stream = raw.take_protected()?;
    let mut reader =
        Reader::from_str(std::str::from_utf8(raw.xml()).map_err(|_| Error::Malformed)?);
    let mut active = false;
    let mut encoded = Zeroizing::new(String::new());
    let mut output = Vec::new();
    reader.config_mut().expand_empty_elements = true;
    loop {
        match reader.read_event().map_err(|_| Error::Malformed)? {
            Event::Start(event) => {
                for attribute in event.attributes() {
                    let attribute = attribute.map_err(|_| Error::Malformed)?;
                    if attribute.key.as_ref() == "Protected" && attribute.value.as_ref() == "True" {
                        if active {
                            return Err(Error::Malformed);
                        }
                        active = true;
                    }
                }
            }
            Event::Text(text) if active => encoded.push_str(text.as_ref()),
            Event::End(_) if active => {
                encoded.retain(|character| !character.is_ascii_whitespace());
                let decoded = Zeroizing::new(
                    STANDARD
                        .decode(encoded.as_bytes())
                        .map_err(|_| Error::Malformed)?,
                );
                output.push(stream.decrypt(&decoded)?);
                encoded.clear();
                active = false;
            }
            Event::Eof => break,
            _ => (),
        }
    }
    Ok(output)
}

#[test]
fn real_producers_preserve_xml_protection_and_binary_pool() -> Result<(), Error> {
    for (input, password, keyfile) in [
        (V4, Some(PASSWORD), None),
        (WITH_FILE, None, Some(FILE)),
        (BOTH, Some(PASSWORD), Some(FILE)),
    ] {
        let mut raw = Raw::open(input, password, keyfile, Limits::default(), &mut |_, _| {
            true
        })?;
        assert_eq!(raw.version(), &DatabaseVersion::KDB4(0));
        assert!(raw.memory_bytes() < Limits::default().memory_bytes);
        let xml = std::str::from_utf8(raw.xml()).map_err(|_| Error::Malformed)?;
        assert!(xml.contains("KPXC_RANDOM_SLUG"));
        assert!(!xml.contains("PUBLIC-FIXTURE-PASSWORD"));
        assert_eq!(raw.binary_count(), 2);
        let mut attachment = false;
        let mut empty = false;
        for index in 0..raw.binary_count() {
            let binary = raw.binary(index).ok_or(Error::Malformed)?;
            if binary.bytes.is_empty() {
                empty = true;
            }
            if binary.bytes == b"PUBLIC-FIXTURE-ATTACHMENT\x00\xff\n" {
                attachment = true;
            }
        }
        assert!(attachment && empty);
        let values = values(&mut raw)?;
        assert!(values
            .iter()
            .any(|value| value.as_slice() == b"PUBLIC-FIXTURE-PASSWORD"));
        assert!(values
            .iter()
            .any(|value| value.as_slice() == b"PUBLIC-FIXTURE-HIDDEN"));
        for expected in [
            b"PUBLIC-FIXTURE-OLD".as_slice(),
            b"PUBLIC-FIXTURE-DELETED".as_slice(),
        ] {
            assert!(values.iter().any(|value| value.as_slice() == expected));
        }
        assert!(raw.take_protected().is_err());
    }
    let mut raw = Raw::open(
        V3,
        Some("demopass"),
        None,
        Limits::default(),
        &mut |_, _| true,
    )?;
    assert_eq!(raw.version(), &DatabaseVersion::KDB3(1));
    assert_eq!(raw.binary_count(), 0);
    assert!(!values(&mut raw)?.is_empty());
    let header = Header::inspect(V3, &Limits::default(), &mut |_| true)?;
    let field = header.field(8).ok_or(Error::Malformed)?;
    let position = V3
        .windows(field.len())
        .position(|window| window == field)
        .ok_or(Error::Malformed)?;
    let mut changed = V3.to_vec();
    *changed.get_mut(position).ok_or(Error::Malformed)? ^= 1;
    assert_eq!(
        Raw::open(
            &changed,
            Some("demopass"),
            None,
            Limits::default(),
            &mut |_, _| true
        )
        .err(),
        Some(Error::Credentials)
    );
    Ok(())
}

#[test]
fn header_binding_is_required_and_rejects_forged_xml_metadata() -> Result<(), Error> {
    let header = b"public-header";
    let hash = STANDARD.encode(calculate_sha256(&[header]));
    let xml = format!("<KeePassFile><Meta><HeaderHash>{hash}</HeaderHash></Meta><Root><Unknown>value &amp; other</Unknown></Root></KeePassFile>");
    bind_header(xml.as_bytes(), header, &mut |_, _| true)?;
    assert_eq!(
        bind_header(xml.as_bytes(), b"different", &mut |_, _| true),
        Err(Error::Credentials)
    );
    for altered in [
        xml.replace(&format!("<HeaderHash>{hash}</HeaderHash>"), ""),
        xml.replace(
            "</Meta>",
            &format!("<HeaderHash>{hash}</HeaderHash></Meta>"),
        ),
        format!("<!DOCTYPE KeePassFile>{xml}"),
        xml.replace(&hash, "not base64"),
    ] {
        assert!(bind_header(altered.as_bytes(), header, &mut |_, _| true).is_err());
    }
    assert_eq!(
        bind_header(xml.as_bytes(), header, &mut |_, _| false),
        Err(Error::Canceled)
    );
    Ok(())
}

#[test]
fn inner_pool_headers_are_bounded_and_fail_closed() -> Result<(), Error> {
    fn field(id: u8, value: &[u8]) -> Vec<u8> {
        let mut output = vec![id];
        output.extend_from_slice(&(value.len() as u32).to_le_bytes());
        output.extend_from_slice(value);
        output
    }
    let mut prefix = field(1, &2u32.to_le_bytes());
    prefix.extend_from_slice(&field(2, &[9; 32]));
    let mut valid = prefix.clone();
    valid.extend_from_slice(&field(3, &[1, 7, 8]));
    valid.extend_from_slice(&field(0, &[]));
    valid.extend_from_slice(b"<KeePassFile/>");
    let (_, binaries, start) = inner_header(&valid, 2, &mut |_, _| true)?;
    assert_eq!(binaries.len(), 1);
    assert!(binaries.first().ok_or(Error::Malformed)?.protected);
    assert_eq!(valid.get(start..), Some(b"<KeePassFile/>".as_slice()));
    for suffix in [
        field(3, &[]),
        field(3, &[2, 7]),
        field(1, &2u32.to_le_bytes()),
        field(0, &[0]),
        field(2, &[9; 32]),
    ] {
        let mut invalid = prefix.clone();
        invalid.extend_from_slice(&suffix);
        invalid.extend_from_slice(&field(0, &[]));
        assert!(inner_header(&invalid, 2, &mut |_, _| true).is_err());
    }
    assert!(matches!(
        inner_header(&valid, 0, &mut |_, _| true),
        Err(Error::Limit)
    ));
    let mut protected = Protected {
        cipher: Some(
            InnerCipherConfig::Plain
                .get_cipher(&[])
                .map_err(crypto_error)?,
        ),
        consumed: 0,
        total_limit: 2,
        output_limit: 2,
    };
    assert_eq!(protected.decrypt(&[1, 2, 3]).err(), Some(Error::Limit));
    assert_eq!(protected.decrypt(&[]).err(), Some(Error::Malformed));
    Ok(())
}

#[cfg(feature = "save_kdbx4")]
fn fast_database() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let config = DatabaseConfig {
        kdf_config: KdfConfig::Aes { rounds: 10 },
        ..DatabaseConfig::default()
    };
    let mut database = crate::Database::with_config(config);
    database.root_mut().add_entry().edit(|entry| {
        entry.set_unprotected("Title", "PUBLIC-SYNTHETIC");
        entry.set_protected("Password", "PUBLIC-SYNTHETIC-SECRET");
    });
    let mut output = Vec::new();
    crate::format::kdbx4::dump_kdbx4(
        &database,
        &DatabaseKey::new().with_password(PASSWORD),
        &mut output,
    )?;
    Ok(output)
}

#[cfg(feature = "save_kdbx4")]
fn replace_payload(input: &[u8], payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Write;
    let header = Header::inspect(input, &Limits::default(), &mut |_| true)?;
    let transformed = derive(
        &header,
        Some(PASSWORD),
        None,
        &Limits::default(),
        &mut |_, _| true,
    )?;
    let seed = header.field(4).ok_or(Error::Malformed)?;
    let master = Zeroizing::new(calculate_sha256(&[seed, transformed.as_slice()]));
    let hmac = Zeroizing::new(calculate_sha512(&[
        seed,
        transformed.as_slice(),
        &HMAC_KEY_END,
    ]));
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload)?;
    let compressed = Zeroizing::new(encoder.finish()?);
    let encrypted = header
        .cipher()
        .get_cipher(&master, header.field(7).ok_or(Error::Malformed)?)?
        .encrypt(&compressed)?;
    let mut output = input
        .get(..header.raw().len() + 64)
        .ok_or(Error::Malformed)?
        .to_vec();
    output.extend_from_slice(&crate::format::hmac_block_stream::write_hmac_block_stream(
        &encrypted, &hmac,
    )?);
    Ok(output)
}

#[test]
#[cfg(feature = "save_kdbx4")]
fn authentication_cancellation_and_resource_gates() -> Result<(), Box<dyn std::error::Error>> {
    let input = fast_database()?;
    let header = Header::inspect(&input, &Limits::default(), &mut |_| true)?;
    assert_eq!(
        Raw::open(
            &input,
            Some("wrong"),
            None,
            Limits::default(),
            &mut |_, _| true
        )
        .err(),
        Some(Error::Credentials)
    );
    for position in [
        header.raw().len() + 32,
        header.raw().len() + 64,
        input.len() - 36,
    ] {
        let mut corrupt = input.clone();
        *corrupt.get_mut(position).ok_or(Error::Malformed)? ^= 1;
        let mut decrypted = false;
        assert_eq!(
            Raw::open(
                &corrupt,
                Some(PASSWORD),
                None,
                Limits::default(),
                &mut |phase, _| {
                    decrypted |= phase == Phase::Decrypt;
                    true
                }
            )
            .err(),
            Some(Error::Credentials)
        );
        assert!(!decrypted);
    }
    for phase in [
        Phase::Header,
        Phase::Kdf,
        Phase::Authenticate,
        Phase::Decrypt,
        Phase::Inflate,
        Phase::Inner,
    ] {
        assert_eq!(
            Raw::open(
                &input,
                Some(PASSWORD),
                None,
                Limits::default(),
                &mut |current, _| current != phase
            )
            .err(),
            Some(Error::Canceled)
        );
    }
    for limits in [
        Limits {
            aes_rounds: 9,
            ..Limits::default()
        },
        Limits {
            input_bytes: input.len() - 1,
            ..Limits::default()
        },
        Limits {
            memory_bytes: HEADER_WORK + input.len(),
            ..Limits::default()
        },
    ] {
        let mut derived = false;
        assert_eq!(
            Raw::open(&input, Some(PASSWORD), None, limits, &mut |phase, _| {
                derived |= phase == Phase::Kdf;
                true
            })
            .err(),
            Some(if limits.aes_rounds == 9 {
                Error::KdfLimit
            } else {
                Error::Limit
            })
        );
        assert!(!derived);
    }
    assert_eq!(
        Raw::open(
            &input,
            Some(&"x".repeat(4097)),
            None,
            Limits::default(),
            &mut |_, _| true
        )
        .err(),
        Some(Error::Limit)
    );
    assert_eq!(
        Raw::open(
            &input,
            Some(PASSWORD),
            Some(&vec![0; 1_048_577]),
            Limits::default(),
            &mut |_, _| true
        )
        .err(),
        Some(Error::Limit)
    );
    let original = Raw::open(
        &input,
        Some(PASSWORD),
        None,
        Limits::default(),
        &mut |_, _| true,
    )?;
    let mut payload = original
        .data
        .get(..original.xml.start)
        .ok_or(Error::Malformed)?
        .to_vec();
    payload.extend_from_slice(b"<KeePassFile><Unknown>");
    payload.resize((2 << 20) + payload.len(), b'x');
    payload.extend_from_slice(b"</Unknown></KeePassFile>");
    let oversized = replace_payload(&input, &payload)?;
    assert_eq!(
        Raw::open(
            &oversized,
            Some(PASSWORD),
            None,
            Limits {
                unpacked_bytes: 65536,
                ..Limits::default()
            },
            &mut |_, _| true
        )
        .err(),
        Some(Error::Limit)
    );
    let preserved = Raw::open(
        &oversized,
        Some(PASSWORD),
        None,
        Limits::default(),
        &mut |_, _| true,
    )?;
    assert_eq!(
        preserved.xml(),
        payload.get(original.xml.start..).ok_or(Error::Malformed)?
    );
    Ok(())
}
