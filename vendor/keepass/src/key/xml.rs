use super::ParseXmlKeyFileError;
use crate::crypt::calculate_sha256;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use quick_xml::{events::Event, Reader};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, ParseXmlKeyFileError>;
const INVALID: ParseXmlKeyFileError = ParseXmlKeyFileError::Invalid;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    Root,
    Meta,
    Version,
    Key,
    Data,
}

pub(super) fn parse(input: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut converted = Zeroizing::new(String::new());
    let utf16 = input.starts_with(&[255, 254]) || input.starts_with(&[254, 255]);
    let text = if utf16 {
        if !input.len().is_multiple_of(2) {
            return Ok(None);
        }
        let little = input.starts_with(&[255, 254]);
        let raw = input.get(2..).ok_or(INVALID)?;
        converted
            .try_reserve_exact(raw.len().saturating_mul(2))
            .map_err(|_| INVALID)?;
        let units = raw.as_chunks::<2>().0.iter().map(|bytes| {
            if little {
                u16::from_le_bytes(*bytes)
            } else {
                u16::from_be_bytes(*bytes)
            }
        });
        for character in char::decode_utf16(units) {
            match character {
                Ok(character) => converted.push(character),
                Err(_) => return Ok(None),
            }
        }
        converted.as_str()
    } else {
        match std::str::from_utf8(input) {
            Ok(text) => text,
            Err(_) => return Ok(None),
        }
    };
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut stack = Vec::with_capacity(3);
    let mut root = false;
    let mut closed = false;
    let mut bad_preamble = false;
    let mut declared = false;
    let (mut meta, mut key, mut version_seen, mut data_seen) = (false, false, false, false);
    let mut version = Zeroizing::new(String::new());
    let mut data = Zeroizing::new(String::new());
    let mut checksum = None;
    loop {
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(_) if !root && !text.contains("<KeyFile") => return Ok(None),
            Err(_) => return Err(INVALID),
        };
        match event {
            Event::Start(event) => {
                let name = event.name();
                if !root {
                    if name.as_ref() != "KeyFile" {
                        return Ok(None);
                    }
                    if bad_preamble {
                        return Err(INVALID);
                    }
                    root = true;
                }
                if closed {
                    return Err(INVALID);
                }
                let tag = match (stack.as_slice(), name.as_ref()) {
                    ([], "KeyFile") => Tag::Root,
                    ([Tag::Root], "Meta") if !meta => {
                        meta = true;
                        Tag::Meta
                    }
                    ([Tag::Root], "Key") if !key => {
                        key = true;
                        Tag::Key
                    }
                    ([Tag::Root, Tag::Meta], "Version") if !version_seen => {
                        version_seen = true;
                        Tag::Version
                    }
                    ([Tag::Root, Tag::Key], "Data") if !data_seen => {
                        data_seen = true;
                        Tag::Data
                    }
                    _ => return Err(INVALID),
                };
                for attribute in event.attributes() {
                    let attribute = attribute.map_err(|_| INVALID)?;
                    if tag != Tag::Data || attribute.key.as_ref() != "Hash" || checksum.is_some() {
                        return Err(INVALID);
                    }
                    let mut hash = [0; 4];
                    hex::decode_to_slice(attribute.value.as_ref(), &mut hash)
                        .map_err(|_| INVALID)?;
                    checksum = Some(hash);
                }
                stack.push(tag);
            }
            Event::End(_) => {
                if stack.pop().is_none() {
                    return Err(INVALID);
                }
                if stack.is_empty() {
                    closed = true;
                }
            }
            Event::Text(value) => {
                let value = value.as_ref();
                let target = match stack.as_slice() {
                    [Tag::Root, Tag::Meta, Tag::Version] => Some((&mut version, 128)),
                    [Tag::Root, Tag::Key, Tag::Data] => Some((&mut data, 4096)),
                    _ => None,
                };
                if let Some((target, limit)) = target {
                    if target.len() + value.len() > limit {
                        return Err(INVALID);
                    }
                    target.push_str(value);
                } else if !value.trim().is_empty() {
                    return if root { Err(INVALID) } else { Ok(None) };
                }
            }
            Event::Decl(decl) => {
                if root || declared {
                    return Err(INVALID);
                }
                declared = true;
                if decl.version().map_err(|_| INVALID)?.as_ref() != "1.0" {
                    bad_preamble = true;
                }
                if let Some(encoding) = decl.encoding() {
                    let encoding = encoding.map_err(|_| INVALID)?;
                    let encoding: &str = encoding.as_ref();
                    let allowed = encoding.eq_ignore_ascii_case("utf-8")
                        || (utf16 && encoding.eq_ignore_ascii_case("utf-16"));
                    if !allowed {
                        bad_preamble = true;
                    }
                }
            }
            Event::DocType(_) if !root => bad_preamble = true,
            Event::Comment(_) => (),
            Event::Eof => break,
            _ if !root => return Ok(None),
            _ => return Err(INVALID),
        }
    }
    if !root {
        return Ok(None);
    }
    if !closed || !stack.is_empty() || !key || !data_seen {
        return Err(INVALID);
    }
    data.retain(|c| !c.is_ascii_whitespace());
    let mut output = Zeroizing::new([0; 64]);
    let length = match version.trim() {
        "" | "1.0" | "1.00" => {
            if checksum.is_some() {
                return Err(INVALID);
            }
            STANDARD
                .decode_slice(data.as_bytes(), &mut output[..])
                .map_err(|_| INVALID)?
        }
        "2.0" => {
            hex::decode_to_slice(data.as_bytes(), output.get_mut(..32).ok_or(INVALID)?)
                .map_err(|_| INVALID)?;
            let hash = Zeroizing::new(calculate_sha256(&[output.get(..32).ok_or(INVALID)?]));
            if hash.get(..4) != checksum.as_ref().map(|bytes| bytes.as_slice()) {
                return Err(INVALID);
            }
            32
        }
        _ => return Err(INVALID),
    };
    if length != 32 {
        return Err(INVALID);
    }
    Ok(Some(output.get(..length).ok_or(INVALID)?.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(version: &str, attribute: &str, data: &str) -> String {
        format!("<KeyFile><Meta><Version>{version}</Version></Meta><Key><Data{attribute}>{data}</Data></Key></KeyFile>")
    }

    #[test]
    fn xml_versions_and_utf16_decode_the_same_public_key() -> Result<()> {
        let key = [9; 32];
        let hash = hex::encode(calculate_sha256(&[&key]).get(..4).ok_or(INVALID)?);
        for xml in [
            fixture("1.00", "", &STANDARD.encode(key)),
            fixture("2.0", &format!(" Hash=\"{hash}\""), &hex::encode(key)),
        ] {
            let decoded = parse(xml.as_bytes());
            assert!(decoded.is_ok(), "public UTF-8 XML key");
            assert_eq!(decoded?, Some(key.to_vec()));
            assert_eq!(
                parse(format!("\u{feff}{xml}").as_bytes())?,
                Some(key.to_vec())
            );
            for little in [true, false] {
                let mut utf16 = if little {
                    vec![255, 254]
                } else {
                    vec![254, 255]
                };
                let declared = format!("<?xml version=\"1.0\" encoding=\"utf-16\"?>{xml}");
                for unit in declared.encode_utf16() {
                    utf16.extend_from_slice(&if little {
                        unit.to_le_bytes()
                    } else {
                        unit.to_be_bytes()
                    });
                }
                let decoded = parse(&utf16);
                assert!(
                    decoded.is_ok(),
                    "public UTF-16 XML key, little endian: {}",
                    little
                );
                assert_eq!(decoded?, Some(key.to_vec()));
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_xml_keys_do_not_fall_back_to_file_hashes() -> Result<()> {
        let encoded = STANDARD.encode([9; 32]);
        for xml in [
            "<KeyFile".to_owned(),
            fixture("2.0", " Hash=\"00000000\"", &hex::encode([9; 32])),
            fixture("2.0", "", &hex::encode([9; 32])),
            fixture("3.0", "", &encoded),
            fixture("1.00", "", "not-base64"),
            fixture("1.00", "", &encoded).replace("</Data>", "</Data><Data>"),
            format!("{}<extra/>", fixture("1.00", "", &encoded)),
            format!("<!DOCTYPE KeyFile>{}", fixture("1.00", "", &encoded)),
            fixture("1.00", "", &encoded).replace("<Key>", "<Key>&entity;"),
        ] {
            assert!(parse(xml.as_bytes()).is_err());
        }
        assert_eq!(parse(b"bare-key-file")?, None);
        assert_eq!(parse(b"<!DOCTYPE Other><Other/>")?, None);
        Ok(())
    }
}
