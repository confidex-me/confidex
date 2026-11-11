use crate::record::{Mapping, Value, ValueError};
use hmac::{Hmac, KeyInit, Mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAX_SECRET: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TimeBeforeStart,
    InvalidBase32,
    Allocation,
}

pub struct Totp<'a> {
    secret: &'a [u8],
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    t0: u64,
}
pub struct Code {
    bytes: Zeroizing<[u8; 8]>,
    digits: usize,
    pub valid_for_seconds: u32,
}
impl Code {
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.digits]).unwrap()
    }
}
impl<'a> Totp<'a> {
    pub fn new(
        secret: &'a [u8],
        algorithm: Algorithm,
        digits: u8,
        period: u32,
        t0: u64,
    ) -> Result<Self, ValueError> {
        if secret.is_empty() || secret.len() > MAX_SECRET {
            return Err(ValueError::InvalidValue("secret"));
        }
        if !(6..=8).contains(&digits) {
            return Err(ValueError::InvalidValue("digits"));
        }
        if !(1..=86_400).contains(&period) {
            return Err(ValueError::InvalidValue("period"));
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
            t0,
        })
    }
    pub fn from_value(value: &'a Mapping) -> Result<Self, ValueError> {
        let Value::Binary(secret) = value.get("secret").ok_or(ValueError::Missing("secret"))?
        else {
            return Err(ValueError::WrongType("secret"));
        };
        let algorithm = match value.get("algorithm") {
            None => Algorithm::Sha1,
            Some(v) => match v.as_str().ok_or(ValueError::WrongType("algorithm"))? {
                "SHA1" => Algorithm::Sha1,
                "SHA256" => Algorithm::Sha256,
                "SHA512" => Algorithm::Sha512,
                _ => return Err(ValueError::InvalidValue("algorithm")),
            },
        };
        let number = |field, default| match value.get(field) {
            None => Ok(default),
            Some(v) => v.as_u64().ok_or(ValueError::WrongType(field)),
        };
        let digits =
            u8::try_from(number("digits", 6)?).map_err(|_| ValueError::InvalidValue("digits"))?;
        let period =
            u32::try_from(number("period", 30)?).map_err(|_| ValueError::InvalidValue("period"))?;
        Self::new(secret, algorithm, digits, period, number("t0", 0)?)
    }
    pub fn generate(&self, unix_seconds: u64) -> Result<Code, Error> {
        let elapsed = unix_seconds
            .checked_sub(self.t0)
            .ok_or(Error::TimeBeforeStart)?;
        let counter = (elapsed / u64::from(self.period)).to_be_bytes();
        macro_rules! calculate {
            ($hash:ty, $length:expr) => {{
                let mut mac = Hmac::<$hash>::new_from_slice(self.secret).unwrap();
                mac.update(&counter);
                let digest = Zeroizing::<[u8; $length]>::new(mac.finalize().into_bytes().into());
                let offset = usize::from(digest[digest.len() - 1] & 15);
                u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff
            }};
        }
        let mut number = match self.algorithm {
            Algorithm::Sha1 => calculate!(sha1::Sha1, 20),
            Algorithm::Sha256 => calculate!(sha2::Sha256, 32),
            Algorithm::Sha512 => calculate!(sha2::Sha512, 64),
        };
        let mut bytes = Zeroizing::new([b'0'; 8]);
        for digit in bytes[..usize::from(self.digits)].iter_mut().rev() {
            *digit += (number % 10) as u8;
            number /= 10;
        }
        Ok(Code {
            bytes,
            digits: usize::from(self.digits),
            valid_for_seconds: self.period - (elapsed % u64::from(self.period)) as u32,
        })
    }
    pub fn verify(&self, unix_seconds: u64, candidate: &str) -> Result<bool, Error> {
        let code = self.generate(unix_seconds)?;
        Ok(bool::from(
            code.as_str().as_bytes().ct_eq(candidate.as_bytes()),
        ))
    }
}

pub fn decode_secret(input: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if input.is_empty() || input.len() > 208 || !input.is_ascii() {
        return Err(Error::InvalidBase32);
    }
    let text = input.trim_end_matches('=');
    let residue = text.len() % 8;
    if !matches!(residue, 0 | 2 | 4 | 5 | 7)
        || (text.len() != input.len() && input.len() - text.len() != (8 - residue) % 8)
        || text.is_empty()
        || text.len() * 5 / 8 > MAX_SECRET
    {
        return Err(Error::InvalidBase32);
    }
    let mut secret = Zeroizing::new(Vec::new());
    secret
        .try_reserve_exact(text.len() * 5 / 8)
        .map_err(|_| Error::Allocation)?;
    let (mut accumulator, mut bits) = (0u16, 0u8);
    for c in text.bytes() {
        let digit = match c.to_ascii_uppercase() {
            b'A'..=b'Z' => c.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(Error::InvalidBase32),
        };
        accumulator = (accumulator << 5) | u16::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            secret.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if accumulator != 0 {
        return Err(Error::InvalidBase32);
    }
    Ok(secret)
}
