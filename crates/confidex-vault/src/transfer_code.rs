//! A local transfer code contains the original secret and a public sync address.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CHECKSUM_DOMAIN: &[u8] = b"confidex/transfer-code/checksum/v1\0";
pub const SYMBOLS: usize = 77;
pub const FORMATTED: usize = 87;

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidCode;

pub struct Code {
    pub secret: Zeroizing<[u8; 32]>,
    pub id: [u8; 16],
}

fn checksum(bytes: &[u8; 48]) -> u8 {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(bytes);
    hash.finalize()[0] & 0xf0
}

pub fn encode(secret: &[u8; 32], public_key: &[u8; 32]) -> Zeroizing<[u8; FORMATTED]> {
    let mut bytes = Zeroizing::new([0; 48]);
    bytes[..32].copy_from_slice(secret);
    bytes[32..].copy_from_slice(&crate::sync::id(public_key));
    bytes[38] = (bytes[38] & 15) | checksum(&bytes);
    let mut text = Zeroizing::new([b'-'; FORMATTED]);
    for digit in 0..SYMBOLS {
        let mut value = 0;
        for bit in digit * 5..digit * 5 + 5 {
            value <<= 1;
            if bit < 384 {
                value |= (bytes[bit / 8] >> (7 - bit % 8)) & 1;
            }
        }
        text[digit + digit / 7] = ALPHABET[usize::from(value)];
    }
    text
}

pub fn decode(input: &str) -> Result<Code, InvalidCode> {
    if input.len() > 128 || !input.is_ascii() {
        return Err(InvalidCode);
    }
    let input = input
        .trim_matches(|c| matches!(c, '\t'..='\r' | ' '))
        .as_bytes();
    if input.len() != SYMBOLS && input.len() != FORMATTED {
        return Err(InvalidCode);
    }
    let mut bytes = Zeroizing::new([0; 48]);
    let mut digit = 0;
    for (index, byte) in input.iter().enumerate() {
        if input.len() == FORMATTED && index % 8 == 7 {
            if *byte != b'-' {
                return Err(InvalidCode);
            }
            continue;
        }
        let value = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(InvalidCode),
        };
        if digit == SYMBOLS - 1 && value & 1 != 0 {
            return Err(InvalidCode);
        }
        for offset in 0..5 {
            let bit = digit * 5 + offset;
            if bit < 384 {
                bytes[bit / 8] |= ((value >> (4 - offset)) & 1) << (7 - bit % 8);
            }
        }
        digit += 1;
    }
    let received = bytes[38] & 0xf0;
    bytes[38] = (bytes[38] & 15) | 0x50;
    if bytes[40] & 0xc0 != 0x80 || !bool::from(received.ct_eq(&checksum(&bytes))) {
        return Err(InvalidCode);
    }
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&bytes[..32]);
    Ok(Code {
        secret,
        id: bytes[32..].try_into().map_err(|_| InvalidCode)?,
    })
}
