//! KeePass field semantics are shared by the XML adapter and future KDBX input.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use confidex_vault::{
    record::{Entry, Mapping, Value},
    totp,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::import::formats) enum Issue {
    UnresolvedReference,
    UnsupportedOtp,
    InvalidField,
}
type Result<T> = std::result::Result<T, Issue>;

pub(in crate::import::formats) fn dynamic(value: &str) -> bool {
    value.match_indices('{').any(|(at, _)| {
        let rest = &value[at + 1..];
        [
            "REF:",
            "S:",
            "URL:",
            "T-CONV:",
            "T-REPLACE-RX:",
            "CMD:",
            "ENV:",
            "NEWPASSWORD:",
            "DB_",
            "GROUP_",
            "DT_",
        ]
        .iter()
        .any(|prefix| {
            rest.get(..prefix.len())
                .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
        }) || [
            "TITLE}",
            "USERNAME}",
            "PASSWORD}",
            "URL}",
            "NOTES}",
            "UUID}",
            "TOTP}",
            "BASE}",
            "GROUP}",
            "NEWPASSWORD}",
            "TIMEOTP}",
            "HMACOTP}",
        ]
        .iter()
        .any(|token| {
            rest.get(..token.len())
                .is_some_and(|part| part.eq_ignore_ascii_case(token))
        })
    })
}
pub(in crate::import::formats) fn text_field(
    name: &str,
    value: &str,
    protected: bool,
) -> Result<Entry> {
    if dynamic(value) {
        return Err(Issue::UnresolvedReference);
    }
    let (kind, key) = match name {
        "UserName" => ("username/v1", "username"),
        "Password" => ("password/v1", "password"),
        "URL" => ("url/v1", "url"),
        "Notes" => ("secure-note/v1", "text"),
        _ if protected => ("secret/v1", "secret"),
        _ => ("text/v1", "text"),
    };
    let mut entry = Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), Value::from(value))]),
        extra: Mapping::new(),
    };
    if protected && name != "Notes" {
        entry.extra.insert(
            "metadata".into(),
            Value::Map(vec![(Value::from("protected"), Value::Boolean(true))]),
        );
    }
    entry.validate_value().map_err(|_| Issue::InvalidField)?;
    Ok(entry)
}
fn algorithm(value: &str) -> Result<&'static str> {
    for (name, alternate, short) in [
        ("SHA1", "HMAC-SHA-1", "HMAC-SHA1"),
        ("SHA256", "HMAC-SHA-256", "HMAC-SHA256"),
        ("SHA512", "HMAC-SHA-512", "HMAC-SHA512"),
    ] {
        if value.eq_ignore_ascii_case(name)
            || value.eq_ignore_ascii_case(alternate)
            || value.eq_ignore_ascii_case(short)
        {
            return Ok(name);
        }
    }
    Err(Issue::UnsupportedOtp)
}
fn number(text: &str) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Issue::UnsupportedOtp);
    }
    text.parse().map_err(|_| Issue::UnsupportedOtp)
}
fn base32(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    if text.len() > 416 {
        return Err(Issue::UnsupportedOtp);
    }
    let mut compact = Zeroizing::new(String::with_capacity(text.len()));
    for character in text
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '\t' | '\r' | '\n'))
    {
        compact.push(character);
    }
    totp::decode_secret(&compact).map_err(|_| Issue::UnsupportedOtp)
}
fn otp(
    name: &str,
    mut seed: Zeroizing<Vec<u8>>,
    algorithm: &str,
    digits: u64,
    period: u64,
) -> Result<Entry> {
    let mut entry = Entry {
        name: name.into(),
        type_name: "totp/v1".into(),
        value: Mapping::from([
            ("secret".into(), Value::Binary(std::mem::take(&mut *seed))),
            ("algorithm".into(), Value::from(algorithm)),
            ("digits".into(), Value::from(digits)),
            ("period".into(), Value::from(period)),
            ("t0".into(), Value::from(0u64)),
        ]),
        extra: Mapping::new(),
    };
    entry.validate_value().map_err(|_| Issue::UnsupportedOtp)?;
    entry
        .extra
        .insert("confidex.import.totp".into(), Value::Map(Vec::new()));
    Ok(entry)
}
fn source(entry: &mut Entry, key: &str, value: &str) {
    let Value::Map(fields) = entry.extra.get_mut("confidex.import.totp").unwrap() else {
        unreachable!()
    };
    fields.push((Value::from(key), Value::from(value)));
}
pub(in crate::import::formats) fn otp_uri(name: &str, value: &str) -> Result<Entry> {
    let mut entry = crate::import::totp::keepass_uri(value).ok_or(Issue::UnsupportedOtp)?;
    entry.name = name.into();
    Ok(entry)
}
pub(in crate::import::formats) fn otp_keeotp(name: &str, query: &str) -> Result<Entry> {
    let mut secret = None;
    let mut algo = "SHA1";
    let (mut digits, mut period) = (6, 30);
    let mut seen: Vec<Zeroizing<String>> = Vec::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let key = Zeroizing::new(key.into_owned());
        let value = Zeroizing::new(value.into_owned());
        if seen.iter().any(|prior| prior.as_str() == key.as_str())
            || key.contains('\u{fffd}')
            || value.contains('\u{fffd}')
        {
            return Err(Issue::UnsupportedOtp);
        }
        match key.as_str() {
            "key" => secret = Some(base32(&value)?),
            "otpHashMode" => algo = algorithm(&value)?,
            "size" => digits = number(&value)?,
            "step" => period = number(&value)?,
            _ => return Err(Issue::UnsupportedOtp),
        }
        seen.push(key);
    }
    let mut entry = otp(
        name,
        secret.ok_or(Issue::UnsupportedOtp)?,
        algo,
        digits,
        period,
    )?;
    source(&mut entry, "keeotp", query);
    Ok(entry)
}
pub(in crate::import::formats) fn otp_legacy(
    name: &str,
    seed: &str,
    settings: &str,
) -> Result<Entry> {
    let (period, digits) = if settings.is_empty() {
        (30, 6)
    } else {
        let (period, digits) = settings.split_once(';').ok_or(Issue::UnsupportedOtp)?;
        (number(period)?, number(digits)?)
    };
    let mut entry = otp(name, base32(seed)?, "SHA1", digits, period)?;
    source(&mut entry, "seed", seed);
    source(&mut entry, "settings", settings);
    Ok(entry)
}
pub(in crate::import::formats) fn otp_keepass(
    name: &str,
    seed: &str,
    encoding: &str,
    algo: &str,
    digits: &str,
    period: &str,
) -> Result<Entry> {
    let bytes = match encoding {
        "Base32" => base32(seed)?,
        "Base64" if seed.len() <= 172 => {
            let mut output = Zeroizing::new([0u8; 128]);
            let length = STANDARD
                .decode_slice(seed, &mut *output)
                .map_err(|_| Issue::UnsupportedOtp)?;
            Zeroizing::new(output[..length].to_vec())
        }
        "Hex" if seed.len() <= 256 && seed.len().is_multiple_of(2) && seed.is_ascii() => {
            let mut bytes = Zeroizing::new(Vec::new());
            for i in (0..seed.len()).step_by(2) {
                bytes.push(
                    u8::from_str_radix(&seed[i..i + 2], 16).map_err(|_| Issue::UnsupportedOtp)?,
                );
            }
            bytes
        }
        "Utf8" if seed.len() <= 128 => Zeroizing::new(seed.as_bytes().to_vec()),
        _ => return Err(Issue::UnsupportedOtp),
    };
    let mut entry = otp(
        name,
        bytes,
        if algo.is_empty() {
            "SHA1"
        } else {
            algorithm(algo)?
        },
        if digits.is_empty() {
            6
        } else {
            number(digits)?
        },
        if period.is_empty() {
            30
        } else {
            number(period)?
        },
    )?;
    source(&mut entry, "format", "keepass-timeotp");
    source(&mut entry, "encoding", encoding);
    source(&mut entry, "seed", seed);
    source(&mut entry, "algorithm", algo);
    source(&mut entry, "digits", digits);
    source(&mut entry, "period", period);
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    #[test]
    fn hidden_values_and_unmarked_passwords_remain_secret() {
        for (name, value, hidden, kind) in [
            ("Password", "public fixture", false, "password/v1"),
            ("Notes", "first\n\nsecond", false, "secure-note/v1"),
            ("Hidden", "public fixture", true, "secret/v1"),
            ("UserName", "alice", true, "username/v1"),
            ("URL", "https://example.invalid", true, "url/v1"),
            ("", "", false, "text/v1"),
        ] {
            let entry = text_field(name, value, hidden).unwrap();
            assert_eq!(entry.name, name);
            assert_eq!(entry.type_name, kind);
            entry.validate_value().unwrap();
        }
        for value in [
            "{REF:P@I:abc}",
            "prefix{ref:u@T:fixture}suffix",
            "{S:secret}",
            "{PASSWORD}",
            "{TIMEOTP}",
            "{CMD:rm -rf /}",
        ] {
            assert!(matches!(
                text_field("Password", value, false),
                Err(Issue::UnresolvedReference)
            ));
        }
        assert!(!dynamic("literal {test} password"));
    }
    #[test]
    fn otp_dialects_have_equal_secrets_and_explicit_parameters() {
        let uri = format!(
            "otpauth://totp/Fixture:alice?secret={SEED}&algorithm=SHA256&digits=8&period=45&issuer=Fixture"
        );
        let entries = [
            otp_uri("otp", &uri).unwrap(),
            otp_keeotp(
                "otp",
                &format!("key={SEED}&size=8&step=45&otpHashMode=HMAC-SHA-256"),
            )
            .unwrap(),
            otp_keepass("TimeOtp", SEED, "Base32", "HMAC-SHA256", "8", "45").unwrap(),
        ];
        for entry in &entries {
            assert_eq!(entry.value["algorithm"].as_str(), Some("SHA256"));
            assert_eq!(entry.value["digits"].as_u64(), Some(8));
            assert_eq!(entry.value["period"].as_u64(), Some(45));
            assert!(
                matches!(&entry.value["secret"],Value::Binary(bytes) if bytes==b"12345678901234567890")
            );
        }
        for encoding in ["Utf8", "Hex", "Base64"] {
            let encoded = match encoding {
                "Utf8" => "12345678901234567890".to_string(),
                "Hex" => "3132333435363738393031323334353637383930".into(),
                _ => STANDARD.encode(b"12345678901234567890"),
            };
            let entry = otp_keepass("otp", &encoded, encoding, "", "", "").unwrap();
            assert_eq!(entry.value["secret"], entries[0].value["secret"]);
        }
        let entry = otp_legacy("TOTP Seed", SEED, "45;8").unwrap();
        assert_eq!(entry.value["period"].as_u64(), Some(45));
    }
    #[test]
    fn unsupported_otp_does_not_turn_into_a_default_code() {
        for suffix in [
            "&algorithm=unknown",
            "&digits=5",
            "&period=0",
            "&period=30&period=60",
            "&encoder=steam",
            "&counter=1",
            "&t0=30",
            "&issuer=broken%",
            "&secret=OTHER",
        ] {
            assert!(
                otp_uri(
                    "otp",
                    &format!("otpauth://totp/Fixture?secret={SEED}{suffix}")
                )
                .is_err()
            );
        }
        assert!(otp_uri("otp", &format!("otpauth://hotp/Fixture?secret={SEED}")).is_err());
        assert!(otp_legacy("otp", SEED, "30;S").is_err());
        assert!(otp_keepass("otp", SEED, "Base32", "SHA3", "6", "30").is_err());
    }
}
