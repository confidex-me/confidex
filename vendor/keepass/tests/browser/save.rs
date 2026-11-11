//! Public synthetic save proof. No user database is read.
use base64::{display::Base64Display, engine::general_purpose::STANDARD, Engine as _};
use keepass::{
    bounded::{save, Binary, Encoder, Error, Limits, Raw, SaveError, SaveEvent},
    config::{CompressionConfig, DatabaseConfig, KdfConfig},
};
use std::{
    fmt::Write as _,
    io::{self, Write},
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn xml(encoder: &mut Encoder<'_, '_>, output: &mut dyn Write) -> io::Result<()> {
    output.write_all(b"<KeePassFile><Meta/><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Name>Confidex</Name><Entry><UUID>AgICAgICAgICAgICAgICAg==</UUID><String><Key>Title</Key><Value>Public</Value></String><String><Key>UserName</Key><Value>public-user</Value></String>")?;
    for (key, value) in [
        ("Password", "PUBLIC-CURRENT\r\n秘密"),
        ("Private", "PUBLIC-NOTE"),
        ("Empty", ""),
    ] {
        let bytes = encoder
            .encrypt(value.as_bytes())
            .map_err(|_| io::ErrorKind::Other)?;
        write!(
            output,
            "<String><Key>{key}</Key><Value Protected=\"True\">{}</Value></String>",
            Base64Display::new(&bytes, &STANDARD)
        )?;
    }
    output.write_all(b"<Binary><Key>public.bin</Key><Value Ref=\"0\"/></Binary><Binary><Key>empty.bin</Key><Value Ref=\"1\"/></Binary></Entry></Group></Root></KeePassFile>")
}

#[wasm_bindgen]
pub fn probe() -> Result<String, JsValue> {
    perform().map_err(|error| JsValue::from_str(&format!("{error}")))
}

fn perform() -> Result<String, SaveError> {
    let mut config = DatabaseConfig::default();
    config.compression_config = CompressionConfig::None;
    config.kdf_config = KdfConfig::Argon2id {
        memory: 64 << 20,
        iterations: 3,
        parallelism: 1,
        version: argon2::Version::V0x13,
    };
    let key = [7; 32];
    let payload = Zeroizing::new((0..200_003).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    let mut result = String::from("{\"files\":[");
    for (index, (name, password, keyfile)) in [
        ("password", Some("PUBLIC-KDBX-EXPORT"), None),
        ("keyfile", None, Some(key.as_slice())),
        ("both", Some("PUBLIC-KDBX-EXPORT"), Some(key.as_slice())),
        ("empty-password", Some(""), None),
        ("empty-both", Some(""), Some(key.as_slice())),
    ]
    .into_iter()
    .enumerate()
    {
        let mut output = Zeroizing::new(Vec::new());
        let mut live = 0;
        let mut peak = 0;
        save(
            &config,
            (password, keyfile),
            Limits::default(),
            &mut *output,
            [
                Binary {
                    bytes: &payload,
                    protected: true,
                },
                Binary {
                    bytes: &[],
                    protected: false,
                },
            ],
            xml,
            &mut |event| {
                if let SaveEvent::Memory(n) = event {
                    live = n;
                    peak = peak.max(n);
                }
                true
            },
        )?;
        if live != 0 || peak > Limits::default().memory_bytes {
            return Err(Error::Limit.into());
        }
        let mut raw = Raw::open(
            &output,
            password,
            keyfile,
            Limits::default(),
            &mut |_, _| true,
        )?;
        let first = raw.binary(0).ok_or(Error::Malformed)?;
        let empty = raw.binary(1).ok_or(Error::Malformed)?;
        if first.bytes != *payload || !first.protected || !empty.bytes.is_empty() || empty.protected
        {
            return Err(Error::Malformed.into());
        }
        let encoded = std::str::from_utf8(raw.xml())
            .map_err(|_| Error::Malformed)?
            .split("<Value Protected=\"True\">")
            .skip(1)
            .map(|s| STANDARD.decode(s.split("</Value>").next().unwrap_or("")))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Malformed)?;
        let mut stream = raw.take_protected()?;
        if encoded.len() != 3 {
            return Err(Error::Malformed.into());
        }
        for (bytes, expected) in encoded
            .iter()
            .zip(["PUBLIC-CURRENT\r\n秘密", "PUBLIC-NOTE", ""])
        {
            if &*stream.decrypt(bytes)? != expected.as_bytes() {
                return Err(Error::Malformed.into());
            }
        }
        if index != 0 {
            result.push(',');
        }
        write!(
            result,
            "{{\"name\":\"{name}\",\"peak\":{peak},\"bytes\":{},\"base64\":\"{}\"}}",
            output.len(),
            Base64Display::new(&output, &STANDARD)
        )
        .map_err(|_| Error::Allocation)?;
    }
    let mut canceled = Vec::new();
    let mut live = 0;
    let failure = save(
        &config,
        (Some("PUBLIC"), None),
        Limits::default(),
        &mut canceled,
        [],
        xml,
        &mut |event| {
            if let SaveEvent::Memory(n) = event {
                live = n;
            }
            !matches!(event, SaveEvent::Serialize(_))
        },
    );
    if !matches!(failure, Err(SaveError::Boundary(Error::Canceled)))
        || live != 0
        || !canceled.is_empty()
    {
        return Err(Error::Malformed.into());
    }
    result.push_str("],\"cancel\":true}");
    Ok(result)
}
