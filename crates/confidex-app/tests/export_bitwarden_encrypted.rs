use base64::{Engine, prelude::BASE64_STANDARD};
use confidex_app::{
    export::{self, Consent, Error},
    import::{
        ErrorKind,
        formats::{bitwarden_encrypted_json::Writer, bitwarden_json::Profile},
    },
};
use serde_json::Value as Json;
#[path = "export_bitwarden_encrypted/proof.rs"]
mod proof;

#[test]
fn portable_output_has_plaintext_mapping_and_preserves_current_values() {
    proof::run();
}
#[test]
fn credentials_are_required_exact_and_keyfiles_are_not_silently_ignored() {
    for options in [
        export::Options::Plain,
        export::Options::Password {
            password: None,
            keyfile: None,
        },
        export::Options::Password {
            password: Some(String::new()),
            keyfile: None,
        },
        export::Options::Password {
            password: Some("public".into()),
            keyfile: Some(vec![]),
        },
        export::Options::Password {
            password: Some("x".repeat(export::MAX_PASSWORD_BYTES + 1)),
            keyfile: None,
        },
    ] {
        assert_eq!(
            Writer::new(Profile::Personal, options).err().unwrap(),
            Error::InvalidOptions
        );
    }
    let bytes = proof::artifact(Profile::Personal).unwrap();
    for password in [
        "PUBLIC-WRONG",
        proof::PASSWORD.trim(),
        " Public export 密码 é é ",
    ] {
        assert_eq!(
            proof::imported(&bytes, password).err().unwrap().kind,
            ErrorKind::Checksum
        );
    }
}
#[test]
fn every_file_uses_fresh_authenticated_components_and_detects_changes() {
    let one = proof::artifact(Profile::Personal).unwrap();
    let two = proof::artifact(Profile::Personal).unwrap();
    let a: Json = serde_json::from_slice(&one).unwrap();
    let b: Json = serde_json::from_slice(&two).unwrap();
    assert_eq!(a["encrypted"], true);
    assert_eq!(a["passwordProtected"], true);
    assert_eq!(
        (
            a["kdfType"].as_u64(),
            a["kdfIterations"].as_u64(),
            a["kdfMemory"].as_u64(),
            a["kdfParallelism"].as_u64()
        ),
        (Some(1), Some(3), Some(64), Some(4))
    );
    assert_ne!(a["salt"], b["salt"]);
    assert_eq!(
        BASE64_STANDARD
            .decode(a["salt"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    for name in ["encKeyValidation_DO_NOT_EDIT", "data"] {
        assert_ne!(a[name], b[name]);
        let parts: Vec<_> = a[name]
            .as_str()
            .unwrap()
            .strip_prefix("2.")
            .unwrap()
            .split('|')
            .collect();
        assert_eq!(parts.len(), 3);
        let other: Vec<_> = b[name]
            .as_str()
            .unwrap()
            .strip_prefix("2.")
            .unwrap()
            .split('|')
            .collect();
        assert_ne!(parts[0], other[0]);
        assert_ne!(
            a["data"].as_str().unwrap().split('|').next(),
            a["encKeyValidation_DO_NOT_EDIT"]
                .as_str()
                .unwrap()
                .split('|')
                .next()
        );

        for at in 0..3 {
            let mut changed = a.clone();
            let mut values: Vec<String> = parts.iter().map(|s| (*s).to_owned()).collect();
            let mut bytes = BASE64_STANDARD.decode(&values[at]).unwrap();
            bytes[0] ^= 1;
            values[at] = BASE64_STANDARD.encode(bytes);
            changed[name] = format!("2.{}", values.join("|")).into();
            assert_eq!(
                proof::imported(&serde_json::to_vec(&changed).unwrap(), proof::PASSWORD)
                    .err()
                    .unwrap()
                    .kind,
                ErrorKind::Checksum
            );
        }
    }
    let text = std::str::from_utf8(&one).unwrap();
    for secret in [
        "PUBLIC-CURRENT",
        "old@example.invalid",
        "4111111111111111",
        proof::PASSWORD,
    ] {
        assert!(!text.contains(secret));
    }
}
#[test]
fn resource_refusal_and_cancel_release_all_shared_memory_without_an_artifact() {
    let limits = export::Limits::default();
    let (plan, memory) = proof::plan(Profile::Personal, proof::records(), limits);
    let reserved = memory.reserve(memory.available() - (1 << 20)).unwrap();
    let before = memory.available();
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true)
            .err()
            .unwrap(),
        Error::Limit
    );
    assert!(memory.available() > before);
    drop(reserved);
    assert_eq!(memory.available(), limits.memory_bytes);
    for stop in [1, 3, 30] {
        let (plan, memory) = proof::plan(Profile::Personal, proof::records(), limits);
        let mut count = 0;
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| {
                count += 1;
                count < stop
            })
            .err()
            .unwrap(),
            Error::Canceled
        );
        assert_eq!(count, stop);
        assert_eq!(memory.available(), limits.memory_bytes);
    }
    let (plan, memory) = proof::plan(
        Profile::Personal,
        proof::records(),
        export::Limits {
            output_bytes: 256,
            ..limits
        },
    );
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true)
            .err()
            .unwrap(),
        Error::Limit
    );
    assert_eq!(memory.available(), limits.memory_bytes);
}
#[test]
fn encryption_keeps_the_same_loss_gate_and_blocks_invalid_ssh_before_cipher_work() {
    let (plan, memory) = proof::plan(
        Profile::Personal,
        proof::records(),
        export::Limits::default(),
    );
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| panic!("unapproved write"))
            .err()
            .unwrap(),
        Error::Losses
    );
    assert_eq!(memory.available(), export::Limits::default().memory_bytes);
    let mut records = proof::records();
    records[2].entries.clear();
    records[2].entries.push(confidex_vault::record::Entry {
        name: "bad".into(),
        type_name: "ssh/v1".into(),
        value: confidex_vault::record::Mapping::from([(
            "private_key".into(),
            confidex_vault::record::Value::Binary(vec![1; 64]),
        )]),
        extra: confidex_vault::record::Mapping::new(),
    });
    let (plan, memory) = proof::plan(Profile::Personal, records, export::Limits::default());
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| panic!("blocked write"))
            .err()
            .unwrap(),
        Error::Blocked
    );
    assert_eq!(memory.available(), export::Limits::default().memory_bytes);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Requires pinned Bitwarden SDK and source readers"]
fn independent_bitwarden_sdk_and_json_reader_open_actual_outputs() {
    let directory = tempfile::tempdir().unwrap();
    for (name, profile) in [
        ("personal", Profile::Personal),
        ("organization", Profile::Organization),
    ] {
        std::fs::write(
            directory.path().join(format!("{name}.json")),
            proof::artifact(profile).unwrap(),
        )
        .unwrap();
    }
    let result = std::process::Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/export_fixtures/bitwarden_encrypted/reader.cjs"
        ))
        .arg(std::env::var_os("CONFIDEX_BITWARDEN_CRYPTO_SOURCE").unwrap())
        .arg(std::env::var_os("CONFIDEX_BITWARDEN_SDK").unwrap())
        .arg(std::env::var_os("CONFIDEX_BITWARDEN_SOURCE").unwrap())
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
}

#[test]
fn output_limit_and_cancel_inside_a_large_value_keep_their_errors() {
    let limits = export::Limits::default();
    for cancel in [false, true] {
        let mut records = proof::records();
        records[2].entries.push(proof::field(
            "large",
            "text/v1",
            "text",
            &"x".repeat(200_003),
        ));
        let (plan, memory) = proof::plan(
            Profile::Personal,
            records,
            export::Limits {
                output_bytes: if cancel {
                    limits.output_bytes
                } else {
                    32 << 10
                },
                ..limits
            },
        );
        let mut steps = 0;
        let result = plan.write(Consent::AllowLosses, &mut |p| {
            if p.current == 2 {
                steps += 1;
            }
            !cancel || steps < 10
        });
        assert_eq!(
            result.err().unwrap(),
            if cancel {
                Error::Canceled
            } else {
                Error::Limit
            }
        );
        if cancel {
            assert_eq!(steps, 10);
        }
        assert_eq!(memory.available(), limits.memory_bytes);
    }
}
