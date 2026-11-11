use confidex_app::import::totp;

use confidex_vault::{record::Value, totp::Totp};
use serde_json::Value as Json;

const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn plain_seed_uses_core_defaults_and_preserves_representation() {
    let entry = totp::entry(SEED).unwrap();
    entry.validate_value().unwrap();
    assert_eq!(entry.type_name, "totp/v1");
    assert_eq!(
        entry.value["secret"],
        Value::Binary(b"12345678901234567890".to_vec())
    );
    assert_eq!(
        Totp::from_value(&entry.value)
            .unwrap()
            .generate(59)
            .unwrap()
            .as_str(),
        "287082"
    );
    assert_eq!(
        entry.extra["confidex.import.totp"].as_map().unwrap()[0]
            .1
            .as_str(),
        Some(SEED)
    );
    assert!(totp::entry(&SEED.to_ascii_lowercase()).is_some());
}

#[test]
fn non_default_provisioning_matches_independent_golden_record() {
    let input: Json =
        serde_json::from_str(include_str!("import_fixtures/bitwarden_json/personal.json")).unwrap();
    let uri = input["items"][0]["login"]["totp"].as_str().unwrap();
    let entry = totp::entry(uri).unwrap();
    entry.validate_value().unwrap();
    assert_eq!(
        entry.value["secret"],
        Value::Binary(b"12345678901234567890".to_vec())
    );
    assert_eq!(entry.value["algorithm"].as_str(), Some("SHA256"));
    assert_eq!(entry.value["digits"].as_u64(), Some(8));
    assert_eq!(entry.value["period"].as_u64(), Some(45));
    assert_eq!(entry.value["t0"].as_u64(), Some(0));
    let expected: Json = serde_json::from_str(include_str!(
        "import_fixtures/bitwarden_json/personal.expected.json"
    ))
    .unwrap();
    assert_eq!(
        entry.extra["confidex.import.totp"].as_map().unwrap()[0]
            .1
            .as_str(),
        expected["records"][0]["record"]["entries"][4]["extra"]["confidex.import.totp"]["uri"]
            .as_str()
    );
}

#[test]
fn unsupported_and_ambiguous_parameters_request_protected_fallback() {
    let prefix = format!("otpauth://totp/Fixture?secret={SEED}");
    for suffix in [
        "&algorithm=MD5",
        "&digits=5",
        "&digits=9",
        "&period=0",
        "&period=86401",
        "&period=18446744073709551616",
        "&digits=%2B6",
        "&period=-1",
        "&counter=5",
        "&t0=10",
        "&secret=MY",
        "&algorithm=SHA1&algorithm=SHA256",
        "&issuer=A&issuer=B",
        "&Secret=MY",
        "&issuer=%ff",
        "&issuer=%GG",
        "#fragment",
    ] {
        assert!(
            totp::entry(&format!("{prefix}{suffix}")).is_none(),
            "{suffix}"
        );
    }
    for input in [
        "",
        "A",
        "INVALID!",
        "MZ",
        "steam://PUBLICFIXTURE",
        "otpauth://hotp/Fixture?secret=MY&counter=0",
        "otpauth://user@totp/Fixture?secret=MY",
        "otpauth://totp:123/Fixture?secret=MY",
        "otpauth://totp/?secret=MY",
        "otpauth://totp/Fixture",
        "otpauth://totp/Fixture?secret=MY\n",
        " otpauth://totp/Fixture?secret=MY",
        "otpauth://totp/Fixture?secret=M%00Y",
    ] {
        assert!(totp::entry(input).is_none(), "{input}");
    }
}

#[test]
fn supported_algorithms_and_percent_encoded_seed_use_core_validation() {
    for algorithm in ["SHA1", "sha256", "SHA512"] {
        let uri = format!(
            "otpauth://totp/Fixture%3Aalice?secret=M%59%3D%3D%3D%3D%3D%3D&algorithm={algorithm}&digits=8&period=86400&issuer=Public%20Fixture"
        );
        let entry = totp::entry(&uri).unwrap();
        entry.validate_value().unwrap();
        assert_eq!(entry.value["secret"], Value::Binary(vec![b'f']));
        assert_eq!(
            entry.value["algorithm"].as_str(),
            Some(algorithm.to_ascii_uppercase().as_str())
        );
    }
    assert!(totp::entry(&"A".repeat(209)).is_none());
}
