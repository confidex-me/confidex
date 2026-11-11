//! Reconcile source text with current TOTP parameters before serialization.
use super::Error;
use confidex_vault::{
    record::{Entry, Value},
    totp::Totp,
};
use serde::{Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

pub(crate) fn valid_totp(entry: &Entry) -> bool {
    entry.type_name == "totp/v1"
        && Totp::from_value(&entry.value).is_ok()
        && entry.value.get("t0").map_or(Some(0), Value::as_u64) == Some(0)
}
pub(crate) fn otp_raw(entry: &Entry) -> Option<&str> {
    if !valid_totp(entry) {
        return None;
    }
    let fields = entry.extra.get("confidex.import.totp")?.as_map()?;
    if fields.len() != 1 {
        return None;
    }
    let key = fields[0].0.as_str()?;
    let raw = fields[0].1.as_str()?;
    ((key == "uri" && raw.contains("://")) || (key == "seed" && !raw.contains("://")))
        .then_some(raw)
}
pub(crate) fn otp_scratch(raw: &str) -> Result<usize, Error> {
    raw.len()
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(64 << 10))
        .ok_or(Error::Limit)
}
pub(crate) fn matching_otp(entry: &Entry) -> Option<&str> {
    let raw = otp_raw(entry)?;
    let parsed = crate::import::totp::entry(raw)?;
    let source = &parsed.value;
    let current = &entry.value;
    let same = source.get("secret") == current.get("secret")
        && source["algorithm"].as_str()
            == Some(
                current
                    .get("algorithm")
                    .and_then(Value::as_str)
                    .unwrap_or("SHA1"),
            )
        && [("digits", 6), ("period", 30), ("t0", 0)]
            .iter()
            .all(|(key, default)| {
                source[*key].as_u64()
                    == Some(
                        current
                            .get(*key)
                            .and_then(Value::as_u64)
                            .unwrap_or(*default),
                    )
            });
    same.then_some(raw)
}
pub(crate) struct Otp<'a>(pub(crate) &'a Entry, pub(crate) Option<&'a str>);
impl fmt::Display for Otp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Value::Binary(secret) = &self.0.value["secret"] else {
            return Err(fmt::Error);
        };
        f.write_str("otpauth://totp/Confidex?secret=")?;
        let (mut bits, mut buffer) = (0u8, Zeroizing::new(0u16));
        for byte in secret {
            *buffer = (*buffer << 8) | u16::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let byte = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[usize::from((*buffer >> bits) & 31)];
                f.write_str(std::str::from_utf8(&[byte]).map_err(|_| fmt::Error)?)?;
            }
            *buffer &= (1 << bits) - 1;
        }
        if bits != 0 {
            let byte =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[usize::from((*buffer << (5 - bits)) & 31)];
            f.write_str(std::str::from_utf8(&[byte]).map_err(|_| fmt::Error)?)?;
        }
        write!(
            f,
            "&algorithm={}&digits={}&period={}",
            self.0
                .value
                .get("algorithm")
                .and_then(Value::as_str)
                .unwrap_or("SHA1"),
            self.0
                .value
                .get("digits")
                .and_then(Value::as_u64)
                .unwrap_or(6),
            self.0
                .value
                .get("period")
                .and_then(Value::as_u64)
                .unwrap_or(30)
        )
    }
}
impl Serialize for Otp<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if let Some(raw) = self.1 {
            s.serialize_str(raw)
        } else {
            s.collect_str(self)
        }
    }
}
