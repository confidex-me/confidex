use super::*;
use crate::bounded::Raw;
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn config() -> DatabaseConfig {
    DatabaseConfig {
        kdf_config: KdfConfig::Aes { rounds: 10 },
        compression_config: CompressionConfig::None,
        ..DatabaseConfig::default()
    }
}
fn xml(encoder: &mut Encoder<'_, '_>, output: &mut dyn Write) -> io::Result<()> {
    output.write_all(b"<KeePassFile><Meta/><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Name>Public</Name><Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID><String><Key>Title</Key><Value>Current</Value></String><String><Key>Password</Key><Value Protected=\"True\">")?;
    let encrypted = encoder
        .encrypt("PUBLIC-CURRENT\r\n秘密".as_bytes())
        .map_err(io_fail)?;
    write!(output, "{}", STANDARD.encode(&*encrypted))?;
    output.write_all(b"</Value></String><Binary><Key>public.bin</Key><Value Ref=\"0\"/></Binary><Binary><Key>empty.bin</Key><Value Ref=\"1\"/></Binary></Entry></Group></Root></KeePassFile>")
}

#[test]
fn current_xml_and_borrowed_binary_pool_roundtrip_all_credential_modes(
) -> Result<(), Box<dyn std::error::Error>> {
    let payload: Vec<u8> = (0..200_003).map(|i| (i % 251) as u8).collect();
    let keyfile = [7; 32];
    for credentials in [
        (Some("PUBLIC-PASSWORD"), None),
        (None, Some(keyfile.as_slice())),
        (Some("PUBLIC-PASSWORD"), Some(keyfile.as_slice())),
        (Some(""), None),
        (Some(""), Some(keyfile.as_slice())),
    ] {
        let mut last = usize::MAX;
        let mut high = 0;
        let mut bytes = Vec::new();
        save(
            &config(),
            credentials,
            Limits::default(),
            &mut bytes,
            [
                Binary {
                    bytes: &payload,
                    protected: true,
                },
                Binary {
                    bytes: &[],
                    protected: false,
                },
            ],
            xml,
            &mut |event| {
                if let SaveEvent::Memory(n) = event {
                    last = n;
                    high = high.max(n);
                }
                true
            },
        )?;
        assert_eq!(last, 0);
        assert!(high <= Limits::default().memory_bytes);
        let mut raw = Raw::open(
            &bytes,
            credentials.0,
            credentials.1,
            Limits::default(),
            &mut |_, _| true,
        )?;
        assert_eq!(raw.binary_count(), 2);
        let first = raw.binary(0).ok_or(Error::Malformed)?;
        assert_eq!(first.bytes, payload);
        assert!(first.protected);
        let empty = raw.binary(1).ok_or(Error::Malformed)?;
        assert!(empty.bytes.is_empty() && !empty.protected);
        let text = std::str::from_utf8(raw.xml())?;
        assert!(!text.contains("PUBLIC-CURRENT"));
        let encrypted = text
            .split("<Value Protected=\"True\">")
            .nth(1)
            .and_then(|s| s.split("</Value>").next())
            .ok_or(Error::Malformed)?;
        let encrypted = Zeroizing::new(STANDARD.decode(encrypted)?);
        let mut stream = raw.take_protected()?;
        assert_eq!(
            &*stream.decrypt(&encrypted)?,
            "PUBLIC-CURRENT\r\n秘密".as_bytes()
        );
        assert!(Raw::open(
            &bytes,
            Some("PUBLIC-WRONG"),
            credentials.1,
            Limits::default(),
            &mut |_, _| true
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn sizes_counts_kdf_and_memory_are_admitted_and_never_publish_failed_payloads() {
    let payload = vec![7; 200_003];
    for limits in [
        Limits {
            memory_bytes: HEADER_WORK - 1,
            ..Limits::default()
        },
        Limits {
            input_bytes: 128,
            ..Limits::default()
        },
        Limits {
            unpacked_bytes: 64,
            ..Limits::default()
        },
        Limits {
            blocks: 1,
            ..Limits::default()
        },
        Limits {
            aes_rounds: 9,
            ..Limits::default()
        },
    ] {
        let mut output = Vec::new();
        let mut memory = 0;
        let result = save(
            &config(),
            (Some("PUBLIC"), None),
            limits,
            &mut output,
            [
                Binary {
                    bytes: &payload,
                    protected: false,
                },
                Binary {
                    bytes: &[],
                    protected: false,
                },
            ],
            xml,
            &mut |event| {
                if let SaveEvent::Memory(n) = event {
                    memory = n;
                }
                true
            },
        );
        let expected = if limits.aes_rounds == 9 {
            Error::KdfLimit
        } else {
            Error::Limit
        };
        assert!(matches!(result, Err(SaveError::Boundary(error)) if error == expected));
        assert!(output.is_empty());
        assert_eq!(memory, 0);
    }
}

#[test]
fn cancellation_and_serializer_failure_clear_every_library_charge() {
    let payload = vec![7; 200_003];
    for stage in 0..4 {
        let mut output = Vec::new();
        let mut memory = 0;
        let result = save(
            &config(),
            (Some("PUBLIC"), None),
            Limits::default(),
            &mut output,
            [
                Binary {
                    bytes: &payload,
                    protected: false,
                },
                Binary {
                    bytes: &[],
                    protected: false,
                },
            ],
            |encoder, output| {
                if stage == 3 {
                    Err(io::ErrorKind::InvalidData.into())
                } else {
                    xml(encoder, output)
                }
            },
            &mut |event| {
                if let SaveEvent::Memory(n) = event {
                    memory = n;
                }
                !matches!(
                    (stage, event),
                    (0, SaveEvent::Kdf(_))
                        | (1, SaveEvent::Serialize(_))
                        | (2, SaveEvent::Write(_))
                )
            },
        );
        assert!(matches!(
            result,
            Err(SaveError::Boundary(Error::Canceled | Error::Malformed))
        ));
        assert!(output.is_empty());
        assert_eq!(memory, 0);
    }
}

#[test]
fn invalid_credentials_and_unconfirmed_write_variants_fail_before_output() {
    for credentials in [
        (None, None),
        (
            Some("PUBLIC"),
            Some(b"<KeyFile><Key/></KeyFile>".as_slice()),
        ),
    ] {
        let mut output = Vec::new();
        let result = save(
            &config(),
            credentials,
            Limits::default(),
            &mut output,
            [],
            xml,
            &mut |_| true,
        );
        assert!(matches!(
            result,
            Err(SaveError::Boundary(Error::Credentials))
        ));
        assert!(output.is_empty());
    }
    for variant in 0..4 {
        let mut config = config();
        match variant {
            0 => config.version = DatabaseVersion::KDB3(1),
            1 => config.outer_cipher_config = OuterCipherConfig::Twofish,
            2 => config.inner_cipher_config = InnerCipherConfig::Salsa20,
            _ => config.compression_config = CompressionConfig::GZip,
        }
        let mut output = Vec::new();
        assert!(matches!(
            save(
                &config,
                (Some("PUBLIC"), None),
                Limits::default(),
                &mut output,
                [],
                xml,
                &mut |_| true
            ),
            Err(SaveError::Boundary(Error::Unsupported))
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn rejected_shared_memory_and_destination_errors_release_work() -> Result<(), SaveError> {
    let payload = vec![7; 200_003];
    let mut output = Vec::new();
    let mut memory = 0;
    let result = save(
        &config(),
        (Some("PUBLIC"), None),
        Limits::default(),
        &mut output,
        [Binary {
            bytes: &payload,
            protected: false,
        }],
        xml,
        &mut |event| {
            if let SaveEvent::Memory(n) = event {
                memory = n;
                return n <= HEADER_WORK;
            }
            true
        },
    );
    assert!(matches!(result, Err(SaveError::Boundary(Error::Canceled))));
    assert_eq!(memory, 0);
    assert!(output.is_empty());

    struct Destination(usize);
    impl Write for Destination {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 >= 100 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let count = bytes.len().min(100 - self.0);
            self.0 += count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut destination = Destination(0);
    let result = save(
        &config(),
        (Some("PUBLIC"), None),
        Limits::default(),
        &mut destination,
        [],
        xml,
        &mut |event| {
            if let SaveEvent::Memory(n) = event {
                memory = n;
            }
            true
        },
    );
    assert!(matches!(result, Err(SaveError::Boundary(Error::Malformed))));
    assert_eq!(destination.0, 100);
    assert_eq!(memory, 0);
    Ok(())
}

#[test]
fn argon2id_profile_uses_fresh_randomness_and_authenticates_every_block() -> Result<(), SaveError> {
    let mut config = config();
    config.kdf_config = KdfConfig::Argon2id {
        memory: 64 << 20,
        iterations: 3,
        parallelism: 1,
        version: argon2::Version::V0x13,
    };
    let mut outputs = [Vec::new(), Vec::new()];
    for output in &mut outputs {
        let mut last = 0;
        save(
            &config,
            (Some("PUBLIC"), None),
            Limits::default(),
            output,
            [
                Binary {
                    bytes: &[],
                    protected: false,
                },
                Binary {
                    bytes: &[],
                    protected: false,
                },
            ],
            xml,
            &mut |event| {
                if let SaveEvent::Memory(n) = event {
                    last = n;
                }
                true
            },
        )?;
        assert_eq!(last, 0);
    }
    assert_ne!(outputs[0], outputs[1]);
    for output in outputs {
        let _raw = Raw::open(
            &output,
            Some("PUBLIC"),
            None,
            Limits::default(),
            &mut |_, _| true,
        )?;
        for position in [12, output.len() - 37, output.len() - 36] {
            let mut corrupted = output.clone();
            if let Some(byte) = corrupted.get_mut(position) {
                *byte ^= 1;
            }
            assert!(Raw::open(
                &corrupted,
                Some("PUBLIC"),
                None,
                Limits::default(),
                &mut |_, _| true
            )
            .is_err());
        }
    }
    Ok(())
}
