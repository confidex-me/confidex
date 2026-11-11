use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SEPARATORS: [usize; 7] = [6, 14, 21, 29, 36, 44, 51];

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidSecretKeyText;

pub fn encode(key: &[u8; 32]) -> Zeroizing<[u8; 59]> {
    let mut text = Zeroizing::new([b'-'; 59]);
    let mut digit = 0;
    for (index, byte) in text.iter_mut().enumerate() {
        if SEPARATORS.contains(&index) {
            continue;
        }
        let mut value = 0;
        for bit in digit * 5..digit * 5 + 5 {
            value <<= 1;
            if bit < 256 {
                value |= (key[bit / 8] >> (7 - bit % 8)) & 1;
            }
        }
        *byte = ALPHABET[usize::from(value)];
        digit += 1;
    }
    text
}

pub fn decode(input: &str) -> Result<Zeroizing<[u8; 32]>, InvalidSecretKeyText> {
    if input.len() > 128 || !input.is_ascii() {
        return Err(InvalidSecretKeyText);
    }
    let text = input
        .trim_matches(|c| matches!(c, '\t'..='\r' | ' '))
        .as_bytes();
    if text.len() != 52 && text.len() != 59 {
        return Err(InvalidSecretKeyText);
    }
    let mut key = Zeroizing::new([0; 32]);
    let mut digit = 0;
    for (index, byte) in text.iter().enumerate() {
        if text.len() == 59 && SEPARATORS.contains(&index) {
            if *byte != b'-' {
                return Err(InvalidSecretKeyText);
            }
            continue;
        }
        let value = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(InvalidSecretKeyText),
        };
        if digit == 51 && value & 15 != 0 {
            return Err(InvalidSecretKeyText);
        }
        for offset in 0..5 {
            let bit = digit * 5 + offset;
            if bit < 256 {
                key[bit / 8] |= ((value >> (4 - offset)) & 1) << (7 - bit % 8);
            }
        }
        digit += 1;
    }
    Ok(key)
}
