//! Decode admitted TOTP source text without executing source behavior.
use confidex_vault::{
    record::{Entry, Mapping, Value},
    totp::{Algorithm, Totp, decode_secret},
};
use url::Url;
use zeroize::Zeroizing;

/// The caller admits the input and retains unsupported text in protected source data.
pub fn entry(input: &str) -> Option<Entry> {
    parse(input, false)
}

pub(crate) fn keepass_uri(input: &str) -> Option<Entry> {
    if !input.contains("://") {
        return None;
    }
    parse(input, true)
}

fn parse(input: &str, keepass: bool) -> Option<Entry> {
    if input.len() > super::Limits::default().string_bytes {
        return None;
    }
    let value = if input.contains("://") {
        uri(input, keepass)?
    } else {
        value(input, "SHA1", 6, 30, keepass)?
    };
    Some(Entry {
        name: "One-time code".into(),
        type_name: "totp/v1".into(),
        value,
        extra: Mapping::from([(
            "confidex.import.totp".into(),
            Value::Map(vec![(
                if input.contains("://") { "uri" } else { "seed" }.into(),
                input.into(),
            )]),
        )]),
    })
}

fn value(
    secret: &str,
    algorithm: &str,
    digits: u64,
    period: u64,
    keepass: bool,
) -> Option<Mapping> {
    let mut compact = Zeroizing::new(String::new());
    let mut decoded = if keepass {
        if secret.len() > 416 {
            return None;
        }
        compact.reserve_exact(secret.len());
        for c in secret
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | '\t' | '\r' | '\n'))
        {
            compact.push(c);
        }
        decode_secret(&compact).ok()?
    } else {
        decode_secret(secret).ok()?
    };
    let selected = match algorithm {
        "SHA1" => Algorithm::Sha1,
        "SHA256" => Algorithm::Sha256,
        "SHA512" => Algorithm::Sha512,
        _ => return None,
    };
    Totp::new(
        &decoded,
        selected,
        digits.try_into().ok()?,
        period.try_into().ok()?,
        0,
    )
    .ok()?;
    Some(Mapping::from([
        (
            "secret".into(),
            Value::Binary(std::mem::take(&mut *decoded)),
        ),
        ("algorithm".into(), algorithm.into()),
        ("digits".into(), digits.into()),
        ("period".into(), period.into()),
        ("t0".into(), 0u64.into()),
    ]))
}

fn uri(input: &str, keepass: bool) -> Option<Mapping> {
    if input.chars().any(char::is_whitespace) || input.chars().any(char::is_control) {
        return None;
    }
    for (index, byte) in input.bytes().enumerate() {
        if byte == b'%'
            && !input
                .as_bytes()
                .get(index + 1..index + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
        {
            return None;
        }
    }
    let url = Url::parse(input).ok()?;
    let result = (|| {
        if url.scheme() != "otpauth"
            || !url.host_str().is_some_and(|host| {
                if keepass {
                    host.eq_ignore_ascii_case("totp")
                } else {
                    host == "totp"
                }
            })
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
            || url.path().len() <= 1
        {
            return None;
        }
        let (mut secret, mut algorithm, mut digits, mut period, mut seen) =
            (Zeroizing::new(String::new()), "SHA1", 6, 30, 0u8);
        for (key, text) in url.query_pairs() {
            let key = Zeroizing::new(key.into_owned());
            let text = Zeroizing::new(text.into_owned());
            if key.contains('\u{fffd}') || text.contains('\u{fffd}') {
                return None;
            }
            let flag = match key.as_str() {
                "secret" => 1,
                "algorithm" => 2,
                "digits" => 4,
                "period" => 8,
                "issuer" => 16,
                _ => return None,
            };
            if seen & flag != 0 {
                return None;
            }
            seen |= flag;
            match key.as_str() {
                "secret" => secret = text,
                "algorithm" => {
                    algorithm = algorithm_name(&text, keepass)?;
                }
                "digits" => digits = number(&text)?,
                "period" => period = number(&text)?,
                _ => {}
            }
        }
        value(&secret, algorithm, digits, period, keepass)
    })();
    // Url owns a copy of the provisioning secret. Wipe it on every exit path.
    let _: Zeroizing<String> = Zeroizing::new(url.into());
    result
}

fn number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn algorithm_name(text: &str, keepass: bool) -> Option<&'static str> {
    for (standard, legacy, alternate) in [
        ("SHA1", "HMAC-SHA-1", "HMAC-SHA1"),
        ("SHA256", "HMAC-SHA-256", "HMAC-SHA256"),
        ("SHA512", "HMAC-SHA-512", "HMAC-SHA512"),
    ] {
        if text.eq_ignore_ascii_case(standard)
            || (keepass
                && (text.eq_ignore_ascii_case(legacy) || text.eq_ignore_ascii_case(alternate)))
        {
            return Some(standard);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keepass_uri_extensions_do_not_change_standard_seed_policy() {
        let uri = "otpauth://TOTP/Public?secret=GEZD-GNBV%20GY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=HMAC-SHA-256&digits=8&period=45";
        assert!(entry(uri).is_none());
        let parsed = keepass_uri(uri).unwrap();
        assert_eq!(parsed.value["algorithm"].as_str(), Some("SHA256"));
        assert_eq!(parsed.value["digits"].as_u64(), Some(8));
        assert_eq!(parsed.value["period"].as_u64(), Some(45));
        assert!(matches!(&parsed.value["secret"],Value::Binary(s) if s==b"12345678901234567890"));
        assert_eq!(
            parsed.extra["confidex.import.totp"]["uri"].as_str(),
            Some(uri)
        );
        assert!(keepass_uri("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").is_none());
        assert!(keepass_uri(&format!("{uri}&counter=1")).is_none());
        assert!(keepass_uri(&format!("{uri}&algorithm=SHA1")).is_none());
    }
    #[test]
    fn oversized_source_is_refused_before_uri_parsing() {
        let input = format!(
            "otpauth://totp/Public?secret=MY&issuer={}",
            "x".repeat(super::super::Limits::default().string_bytes)
        );
        assert!(entry(&input).is_none());
        assert!(keepass_uri(&input).is_none());
    }
}
