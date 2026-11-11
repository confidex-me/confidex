//! Decode a referenced XML binary without extracting it to the file system.
use super::xml::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

pub(in crate::import::formats) struct Sizes {
    pub encoded: usize,
    pub packed: usize,
    pub output: usize,
}
impl Sizes {
    pub fn working(&self) -> Result<usize> {
        self.encoded
            .checked_add(self.packed.checked_mul(2).ok_or(Error::Limit)?)
            .and_then(|n| n.checked_add(self.output))
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Limit)
    }
}
pub(in crate::import::formats) fn sizes(
    text: &str,
    compressed: bool,
    limit: usize,
) -> Result<Sizes> {
    if !text.is_ascii() {
        return Err(Error::Invalid);
    }
    let encoded = text.bytes().filter(|b| !b.is_ascii_whitespace()).count();
    if !encoded.is_multiple_of(4) {
        return Err(Error::Invalid);
    }
    let padding = text
        .bytes()
        .rev()
        .filter(|b| !b.is_ascii_whitespace())
        .take_while(|b| *b == b'=')
        .count();
    if padding > 2 {
        return Err(Error::Invalid);
    }
    let packed = encoded
        .checked_div(4)
        .and_then(|n| n.checked_mul(3))
        .and_then(|n| n.checked_sub(padding))
        .ok_or(Error::Invalid)?;
    // KeePassXC writes an empty compressed pool member without a gzip stream.
    let output = if compressed && packed != 0 {
        if packed < 18 {
            return Err(Error::Invalid);
        }
        let mut suffix = [0; 16];
        for (i, b) in text
            .bytes()
            .rev()
            .filter(|b| !b.is_ascii_whitespace())
            .take(16)
            .enumerate()
        {
            suffix[15 - i] = b;
        }
        let mut decoded = Zeroizing::new([0u8; 12]);
        let n = STANDARD
            .decode_slice(suffix, &mut *decoded)
            .map_err(|_| Error::Invalid)?;
        if n < 8 {
            return Err(Error::Invalid);
        }
        u32::from_le_bytes(decoded[n - 4..n].try_into().map_err(|_| Error::Invalid)?) as usize
    } else {
        packed
    };
    if output > limit {
        return Err(Error::Limit);
    }
    Ok(Sizes {
        encoded,
        packed,
        output,
    })
}
pub(in crate::import::formats) fn decode(
    text: &str,
    compressed: bool,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let size = sizes(text, compressed, limit)?;
    let mut compact = Zeroizing::new(String::with_capacity(size.encoded));
    for byte in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
        compact.push(char::from(byte));
    }
    let mut decoded = Zeroizing::new(vec![0; size.packed]);
    let count = STANDARD
        .decode_slice(compact.as_bytes(), &mut decoded)
        .map_err(|_| Error::Invalid)?;
    if count != size.packed {
        return Err(Error::Invalid);
    }
    if !compressed || size.packed == 0 {
        return Ok(decoded);
    }
    let mut output = Zeroizing::new(vec![0; size.output.checked_add(1).ok_or(Error::Limit)?]);
    let mut gzip = flate2::bufread::GzDecoder::new(Cursor::new(&*decoded));
    let mut used = 0;
    loop {
        let count = gzip.read(&mut output[used..]).map_err(|_| Error::Invalid)?;
        used += count;
        if used > size.output {
            return Err(Error::Invalid);
        }
        if count == 0 {
            break;
        }
    }
    if used != size.output || gzip.get_ref().position() as usize != decoded.len() {
        return Err(Error::Invalid);
    }
    output.truncate(used);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keepassxc_empty_compressed_pool_member_has_no_gzip_bytes() {
        for text in ["", " \n\t"] {
            assert_eq!(sizes(text, true, 0).unwrap().output, 0);
            assert!(decode(text, true, 0).unwrap().is_empty());
        }
        assert!(decode("AA==", true, 1).is_err());
    }
    #[test]
    fn published_pool_has_exact_bytes_and_rejects_corruption() {
        let sample =
            include_str!("../../../../tests/import_fixtures/keepass_xml/upstream-keepass.xml");
        let mut xml =
            super::super::xml::Xml::new(sample.as_bytes(), 64, 50_000, 8_000_000).unwrap();
        let root = loop {
            if let quick_xml::events::Event::Start(start) = xml.next().unwrap() {
                break xml.element(start, false, &mut |_| true).unwrap();
            }
        };
        let pool = root
            .child("Meta")
            .unwrap()
            .unwrap()
            .child("Binaries")
            .unwrap()
            .unwrap();
        for (node, expected) in pool
            .children
            .iter()
            .zip([b"0123456789".as_slice(), b"abcdefghijk".as_slice()])
        {
            assert_eq!(
                decode(node.leaf().unwrap(), true, 11).unwrap().as_slice(),
                expected
            );
            assert!(matches!(
                decode(node.leaf().unwrap(), true, 9),
                Err(Error::Limit)
            ));
            let mut corrupt = STANDARD.decode(node.leaf().unwrap()).unwrap();
            let last = corrupt.len() - 8;
            corrupt[last] ^= 1;
            assert!(matches!(
                decode(&STANDARD.encode(corrupt), true, 11),
                Err(Error::Invalid)
            ));
        }
    }
    #[test]
    fn base64_and_gzip_limits_do_not_allow_silent_extra_data() {
        assert_eq!(
            decode("AA D/\r\n", false, 3).unwrap().as_slice(),
            [0, 0, 255]
        );
        assert!(decode("%%%", false, 3).is_err());
        assert!(matches!(decode("AA==", false, 0), Err(Error::Limit)));
        assert!(matches!(
            decode(&"A".repeat(100_000), false, 1),
            Err(Error::Limit)
        ));
        let mut compressor =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut compressor, &[b'X'; 8192]).unwrap();
        let mut bytes = compressor.finish().unwrap();
        assert!(matches!(
            decode(&STANDARD.encode(&bytes), true, 4096),
            Err(Error::Limit)
        ));
        assert_eq!(
            decode(&STANDARD.encode(&bytes), true, 8192).unwrap().len(),
            8192
        );
        bytes.push(0);
        assert!(matches!(
            decode(&STANDARD.encode(&bytes), true, 8192),
            Err(Error::Invalid)
        ));
        assert!(matches!(
            decode(&STANDARD.encode(&bytes[..8]), true, 8192),
            Err(Error::Invalid)
        ));
    }
}
