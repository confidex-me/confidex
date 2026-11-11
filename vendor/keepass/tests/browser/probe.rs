use base64::{engine::general_purpose::STANDARD, Engine as _};
use keepass::bounded::{Error, Header, Limits, Phase, Raw};
use quick_xml::{events::Event, Reader};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn read(input: &[u8], password: Option<&str>, key: Option<&[u8]>) -> Result<(usize, usize), Error> {
    let mut raw = Raw::open(input, password, key, Limits::default(), &mut |_, _| true)?;
    let resident = raw.memory_bytes();
    let mut inner = raw.take_protected()?;
    let mut reader =
        Reader::from_str(std::str::from_utf8(raw.xml()).map_err(|_| Error::Malformed)?);
    reader.config_mut().expand_empty_elements = true;
    let mut protected = false;
    let mut encoded = Zeroizing::new(String::new());
    let mut count = 0;
    loop {
        match reader.read_event().map_err(|_| Error::Malformed)? {
            Event::Start(event) => {
                for attribute in event.attributes() {
                    let attribute = attribute.map_err(|_| Error::Malformed)?;
                    if attribute.key.as_ref() == "Protected" && attribute.value.as_ref() == "True" {
                        protected = true;
                    }
                }
            }
            Event::Text(text) if protected => encoded.push_str(text.as_ref()),
            Event::End(_) if protected => {
                let decoded = Zeroizing::new(
                    STANDARD
                        .decode(encoded.as_bytes())
                        .map_err(|_| Error::Malformed)?,
                );
                let plaintext = inner.decrypt(&decoded)?;
                if plaintext.starts_with(b"PUBLIC-") {
                    count += 1;
                }
                encoded.clear();
                protected = false;
            }
            Event::Eof => break,
            _ => (),
        }
    }
    if count == 0 {
        return Err(Error::Malformed);
    }
    for index in 0..raw.binary_count() {
        let binary = raw.binary(index).ok_or(Error::Malformed)?;
        if !binary.bytes.is_empty()
            && binary.bytes != b"PUBLIC-KDBX-BINARY\0\xff\n"
            && binary.bytes != b"PUBLIC-FIXTURE-ATTACHMENT\0\xff\n"
        {
            return Err(Error::Malformed);
        }
    }
    Ok((resident, count))
}

#[wasm_bindgen]
pub fn probe() -> Result<String, JsValue> {
    perform().map_err(|error| JsValue::from_str(&format!("{error:?}")))
}

fn perform() -> Result<String, Error> {
    let fixture = |name: &str| match name {
        "v10" => include_bytes!(concat!(
            env!("CONFIDEX_KDBX_ROOT"),
            "/tests/resources/bounded/argon2d-aes-v10.kdbx"
        ))
        .as_slice(),
        "d" => include_bytes!(concat!(
            env!("CONFIDEX_KDBX_ROOT"),
            "/tests/resources/bounded/argon2d-aes.kdbx"
        ))
        .as_slice(),
        "id" => include_bytes!(concat!(
            env!("CONFIDEX_KDBX_ROOT"),
            "/tests/resources/bounded/argon2id-chacha.kdbx"
        ))
        .as_slice(),
        "twofish" => include_bytes!(concat!(
            env!("CONFIDEX_KDBX_ROOT"),
            "/tests/resources/bounded/aes-twofish.kdbx"
        ))
        .as_slice(),
        _ => include_bytes!(concat!(
            env!("CONFIDEX_KDBX_ROOT"),
            "/tests/resources/bounded/argon2id-aes-hex.kdbx"
        ))
        .as_slice(),
    };
    let xml_key = include_bytes!(concat!(
        env!("CONFIDEX_KDBX_ROOT"),
        "/tests/resources/bounded/public-v2.keyx"
    ))
    .as_slice();
    let raw_key = include_bytes!(concat!(
        env!("CONFIDEX_KDBX_ROOT"),
        "/tests/resources/bounded/public.raw"
    ))
    .as_slice();
    let hex_key = include_bytes!(concat!(
        env!("CONFIDEX_KDBX_ROOT"),
        "/tests/resources/bounded/public.hex"
    ))
    .as_slice();
    let v4 = include_bytes!(concat!(env!("CONFIDEX_APP_KDBX"), "/password.kdbx")).as_slice();
    let file = include_bytes!(concat!(env!("CONFIDEX_APP_KDBX"), "/keyfile.kdbx")).as_slice();
    let both = include_bytes!(concat!(env!("CONFIDEX_APP_KDBX"), "/both.kdbx")).as_slice();
    let key = include_bytes!(concat!(env!("CONFIDEX_APP_KDBX"), "/public.key")).as_slice();
    let mut resident = 0;
    let mut protected = 0;
    for (input, password, keyfile) in [
        (v4, Some("PUBLIC-FIXTURE-DATABASE"), None),
        (file, None, Some(key)),
        (both, Some("PUBLIC-FIXTURE-DATABASE"), Some(key)),
        (fixture("d"), Some("PUBLIC-VARIANT-DATABASE"), None),
        (fixture("v10"), Some("PUBLIC-VARIANT-DATABASE"), None),
        (
            fixture("id"),
            Some("PUBLIC-VARIANT-DATABASE"),
            Some(xml_key),
        ),
        (fixture("twofish"), None, Some(raw_key)),
        (fixture("hex"), None, Some(hex_key)),
    ] {
        let (size, values) = read(input, password, keyfile)?;
        resident = resident.max(size);
        protected += values;
    }
    let input = fixture("id");
    let mut forged = input.to_vec();
    let header = Header::inspect(input, &Limits::default(), &mut |_| true)?;
    for (name, value) in [(b'M', 64u64 << 20), (b'I', 3)] {
        let marker = [5, 1, 0, 0, 0, name, 8, 0, 0, 0];
        let position = header
            .raw()
            .windows(marker.len())
            .position(|part| part == marker)
            .ok_or(Error::Malformed)?
            + marker.len();
        forged
            .get_mut(position..position + 8)
            .ok_or(Error::Malformed)?
            .copy_from_slice(&value.to_le_bytes());
    }
    let size = header.raw().len();
    let hash = Sha256::digest(forged.get(..size).ok_or(Error::Malformed)?);
    forged
        .get_mut(size..size + 32)
        .ok_or(Error::Malformed)?
        .copy_from_slice(&hash);
    let mut derived = false;
    let rejected = Raw::open(
        &forged,
        Some("PUBLIC-VARIANT-DATABASE"),
        Some(xml_key),
        Limits::default(),
        &mut |phase, count| {
            derived |= phase == Phase::Kdf && count > 0;
            true
        },
    );
    if rejected.err() != Some(Error::Credentials) || !derived {
        return Err(Error::Malformed);
    }
    if Raw::open(
        input,
        Some("wrong"),
        Some(xml_key),
        Limits::default(),
        &mut |_, _| true,
    )
    .err()
        != Some(Error::Credentials)
    {
        return Err(Error::Malformed);
    }
    if Raw::open(
        input,
        Some("PUBLIC-VARIANT-DATABASE"),
        Some(xml_key),
        Limits::default(),
        &mut |phase, _| phase != Phase::Kdf,
    )
    .err()
        != Some(Error::Canceled)
    {
        return Err(Error::Malformed);
    }
    Ok(format!("{{\"databases\":8,\"protected\":{protected},\"resident\":{resident},\"large_argon_rejected\":true,\"wrong_key_rejected\":true,\"cancel\":true}}"))
}
