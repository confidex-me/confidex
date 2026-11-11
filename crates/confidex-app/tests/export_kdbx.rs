#[path = "export_fixtures/keepass_common.rs"]
mod keepass_common;
use confidex_app::{
    export::{self, Consent},
    import::{self, Format, Options, formats::kdbx},
};
use confidex_vault::{
    record::{Record, Value},
    resources::MAX_OPEN_MEMORY,
};
#[path = "export_kdbx/proof.rs"]
mod proof;

#[test]
fn portable_writer_preserves_current_values_and_protection_and_clears_work() {
    proof::run();
}

#[test]
fn current_values_replace_source_snapshots_and_otp_parameters() {
    let mut record = proof::fixture();
    record.entries[1]
        .value
        .insert("password".into(), "PUBLIC-NEW-CURRENT".into());
    record.entries[7]
        .value
        .insert("period".into(), 60u64.into());
    record.entries[7].extra.insert("confidex.import.totp".into(),Value::Map(vec![("uri".into(),
        "otpauth://totp/Old:public?secret=MZXW6YTBOI&issuer=Old&algorithm=SHA256&digits=8&period=45".into())]));
    record.extra.insert(
        "confidex.import.origin".into(),
        Value::Map(vec![(
            "old-password".into(),
            "PUBLIC-REMOVED-SOURCE".into(),
        )]),
    );
    let (plan, _) = proof::plan(record, 0, export::Limits::default());
    assert!(
        plan.issues()
            .iter()
            .any(|i| i.code == export::Code::SourceContext)
    );
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let parsed = proof::imported(artifact.bytes(), 0);
    let record = parsed.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        record.entries[1].value["password"].as_str(),
        Some("PUBLIC-NEW-CURRENT")
    );
    assert_eq!(record.entries[7].value["period"].as_u64(), Some(60));
    assert!(!record.extra.contains_key("confidex.import.origin"));
}

#[test]
fn duplicate_keys_block_before_cipher_work_and_unknown_fields_need_consent() {
    let mut record = proof::fixture();
    record.entries.push(proof::fixture().entries.remove(1));
    let (plan, _) = proof::plan(record, 0, export::Limits::default());
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| panic!("blocked writer ran"))
            .err(),
        Some(export::Error::Blocked)
    );
    let mut record = proof::fixture();
    record.entries[4].type_name = "future/v9".into();
    let (plan, _) = proof::plan(record, 0, export::Limits::default());
    assert!(
        plan.issues()
            .iter()
            .any(|i| i.field == Some(4) && i.code == export::Code::UnsupportedField)
    );
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Losses)
    );
}

#[test]
fn wrong_credentials_and_terminal_mac_never_return_imported_records() {
    let (plan, _) = proof::plan(proof::fixture(), 2, export::Limits::default());
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    for (password, keyfile, corrupt) in [
        ("PUBLIC-WRONG", proof::KEY, false),
        (proof::PASSWORD, [8; 32], false),
        (proof::PASSWORD, proof::KEY, true),
    ] {
        let mut bytes = artifact.bytes().to_vec();
        if corrupt {
            let index = bytes.len() - 36;
            bytes[index] ^= 1;
        }
        let options = Options {
            password: password.into(),
            keyfile: keyfile.to_vec(),
            password_present: true,
            keyfile_present: true,
            source_instance: None,
            include_archived: false,
            include_deleted: false,
            csv: None,
        };
        assert_eq!(
            import::prepare(
                Format::Kdbx,
                &bytes,
                &options,
                import::Limits::default(),
                &mut |_| true,
                kdbx::parse
            )
            .err()
            .unwrap()
            .kind,
            import::ErrorKind::Checksum
        );
    }
}

#[test]
fn credentials_are_explicit_and_password_limits_match_the_decoder() {
    for password in [None, Some(String::new()), Some("public".into())] {
        assert!(matches!(
            kdbx::Writer::new(
                0,
                export::Options::Password {
                    password,
                    keyfile: Some(Vec::new())
                }
            ),
            Err(export::Error::InvalidOptions)
        ));
    }
    for options in [
        export::Options::Plain,
        export::Options::Password {
            password: None,
            keyfile: None,
        },
        export::Options::Password {
            password: Some("x".repeat(4097)),
            keyfile: None,
        },
        export::Options::Password {
            password: None,
            keyfile: Some(vec![0; (1 << 20) + 1]),
        },
    ] {
        assert!(matches!(
            kdbx::Writer::new(0, options),
            Err(export::Error::InvalidOptions)
        ));
    }
    kdbx::Writer::new(
        0,
        export::Options::Password {
            password: Some("x".repeat(4096)),
            keyfile: None,
        },
    )
    .unwrap();
    let mut records = export::Records::new(export::Limits::default()).unwrap();
    records.push(Record::default()).unwrap();
    let plan = export::prepare(
        records,
        Box::new(
            kdbx::Writer::new(
                0,
                export::Options::Password {
                    password: Some("public".into()),
                    keyfile: Some(b"<KeyFile><Key/></KeyFile>".to_vec()),
                },
            )
            .unwrap(),
        ),
        &mut |_| true,
    )
    .unwrap();
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true).err(),
        Some(export::Error::InvalidOptions)
    );
}

#[test]
fn shared_memory_admission_keeps_other_owners_and_releases_failed_kdf_work() {
    let (plan, memory) = proof::plan(proof::fixture(), 0, export::Limits::default());
    let held = memory.available() - (16 << 20);
    let pressure = memory.reserve(held).unwrap();
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true).err(),
        Some(export::Error::Limit)
    );
    assert_eq!(memory.available(), MAX_OPEN_MEMORY - held);
    drop(pressure);
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
}

#[test]
fn payload_limit_inside_a_public_value_keeps_its_resource_error() {
    let mut record = proof::fixture();
    record.entries[6]
        .value
        .insert("text".into(), "X".repeat(4096).into());
    let (plan, memory) = proof::plan(
        record,
        0,
        export::Limits {
            output_bytes: 2048,
            ..export::Limits::default()
        },
    );
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true).err(),
        Some(export::Error::Limit)
    );
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Requires CONFIDEX_KEEPASSXC_CLI"]
fn independent_keepassxc_reads_current_kdbx_values() {
    use base64::Engine as _;
    use sha2::Digest as _;
    let cli = std::env::var_os("CONFIDEX_KEEPASSXC_CLI").unwrap();
    let directory = tempfile::tempdir().unwrap();
    for (mode, name) in [
        "password",
        "keyfile",
        "both",
        "empty-password",
        "empty-both",
    ]
    .iter()
    .enumerate()
    {
        std::fs::write(
            directory.path().join(format!("{name}.kdbx")),
            proof::artifact(mode).unwrap().bytes(),
        )
        .unwrap();
    }
    std::fs::write(directory.path().join("public.key"), proof::KEY).unwrap();
    let xml_v1 = format!(
        "<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>{}</Data></Key></KeyFile>",
        base64::engine::general_purpose::STANDARD.encode(proof::KEY)
    );
    let hash = sha2::Sha256::digest(proof::KEY)[..4]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    let xml_v2 = format!(
        "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{hash}\">{}</Data></Key></KeyFile>",
        "07".repeat(32)
    );
    let utf16 = [0xff, 0xfe]
        .into_iter()
        .chain(xml_v2.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    for (kind, key) in [
        ("hex", "07".repeat(32).into_bytes()),
        ("xml-v1", xml_v1.into_bytes()),
        ("xml-v2", xml_v2.into_bytes()),
        ("utf16", utf16),
        (
            "bare",
            b"PUBLIC ARBITRARY FILE WITH MORE THAN 32 BYTES\n".to_vec(),
        ),
    ] {
        std::fs::write(directory.path().join(format!("{kind}.key")), &key).unwrap();
        for with_password in [false, true] {
            let mut records = export::Records::new(export::Limits::default()).unwrap();
            records.push(proof::fixture()).unwrap();
            let options = export::Options::Password {
                password: with_password.then(|| proof::PASSWORD.into()),
                keyfile: Some(key.clone()),
            };
            let plan = export::prepare(
                records,
                Box::new(kdbx::Writer::new(0, options).unwrap()),
                &mut |_| true,
            )
            .unwrap();
            let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
            std::fs::write(
                directory.path().join(format!(
                    "key-{kind}-{}.kdbx",
                    if with_password { "both" } else { "keyfile" }
                )),
                artifact.bytes(),
            )
            .unwrap();
        }
    }
    let result = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/export_fixtures/kdbx/reader.py"
        ))
        .arg(cli)
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    print!("{}", String::from_utf8_lossy(&result.stdout));
    let resaved = std::fs::read(directory.path().join("password-resaved.kdbx")).unwrap();
    let raw = keepass::bounded::Raw::open(
        &resaved,
        Some(proof::PASSWORD),
        None,
        keepass::bounded::Limits::default(),
        &mut |_, _| true,
    )
    .unwrap();
    assert!((0..raw.binary_count()).all(|i| raw.binary(i).unwrap().protected));
    println!("KeePassXC retained protected attachments on save");
}

#[test]
fn group_traversal_keeps_binary_refs_and_inner_stream_in_physical_order() {
    let mut records = export::Records::new(export::Limits::default()).unwrap();
    for index in 0..3 {
        let mut record = proof::fixture();
        record
            .extra
            .insert("confidex.title".into(), format!("Public{index}").into());
        record.entries[1]
            .value
            .insert("password".into(), format!("PUBLIC-{index}").into());
        record.entries[9]
            .value
            .insert("data".into(), Value::Binary(vec![index]));
        record.extra.insert(
            "confidex.import.origin".into(),
            Value::Map(vec![
                ("version".into(), 1u64.into()),
                ("format".into(), "kdbx".into()),
                (
                    "source".into(),
                    Value::Map(vec![("instance".into(), "public".into())]),
                ),
                (
                    "attributes".into(),
                    Value::Map(vec![
                        (
                            "group_path".into(),
                            Value::Array(vec![if index == 1 { "Right" } else { "Left" }.into()]),
                        ),
                        (
                            "group_ids".into(),
                            Value::Array(vec![
                                if index == 1 {
                                    "AQEBAQEBAQEBAQEBAQEBAQ=="
                                } else {
                                    "AgICAgICAgICAgICAgICAg=="
                                }
                                .into(),
                            ]),
                        ),
                    ]),
                ),
            ]),
        );
        records.push(record).unwrap();
    }
    let plan = export::prepare(
        records,
        Box::new(kdbx::Writer::new(0, proof::credentials(0)).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    let parsed = proof::imported(artifact.bytes(), 0);
    for (item, index) in parsed.items.iter().zip([0, 2, 1]) {
        let current = item.record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            current.entries[1].value["password"].as_str(),
            Some(format!("PUBLIC-{index}").as_str())
        );
        assert_eq!(
            current.entries[9].value["data"].as_slice(),
            Some([index].as_slice())
        );
    }
}

#[test]
fn cancellation_after_serialization_and_after_sealing_clears_all_output() {
    for stage in [2, 3] {
        let (plan, memory) = proof::plan(proof::fixture(), 0, export::Limits::default());
        let mut hit = false;
        let result = plan.write(Consent::AllowLosses, &mut |progress| {
            hit |= progress.total == 3 && progress.current >= stage;
            !hit
        });
        assert!(hit);
        assert_eq!(result.err(), Some(export::Error::Canceled));
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
}
