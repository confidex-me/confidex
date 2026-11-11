use crate::import::{Format, Source};
use confidex_vault::record::{Record, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub(super) const KEY: &str = "confidex.import.origin";

// These hashes contain information about secrets. Keep them inside the session or sealed Record.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Fingerprint(pub [u8; 32]);
impl Drop for Fingerprint {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) struct Origin {
    pub source: Option<Fingerprint>,
    pub original: Fingerprint,
    pub content: Fingerprint,
}

pub(super) fn format_name(format: Format) -> &'static str {
    match format {
        Format::BitwardenJson => "bitwarden-json",
        Format::Onepassword1pux => "onepassword1pux",
        Format::KeepassXml => "keepass-xml",
        Format::BitwardenZip => "bitwarden-zip",
        Format::Csv => "csv",
        Format::Kdbx => "kdbx",
        Format::BitwardenEncryptedJson => "bitwarden-encrypted-json",
    }
}

fn fingerprint(domain: &[u8], parts: &[Option<&[u8]>]) -> Fingerprint {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update([u8::from(part.is_some())]);
        if let Some(bytes) = part {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
    }
    Fingerprint(hash.finalize().into())
}

fn scoped(format: &str, parts: [Option<&str>; 4]) -> Option<Fingerprint> {
    if parts[0].is_none_or(|s| s.trim().is_empty()) || parts[3].is_none_or(str::is_empty) {
        return None;
    }
    Some(fingerprint(
        b"Confidex import source v1\0",
        &[
            Some(format.as_bytes()),
            parts[0].map(str::as_bytes),
            parts[1].map(str::as_bytes),
            parts[2].map(str::as_bytes),
            parts[3].map(str::as_bytes),
        ],
    ))
}

pub(super) fn source_key(format: Format, source: &Source) -> Option<Fingerprint> {
    scoped(
        format_name(format),
        [
            source.instance.as_deref(),
            source.account.as_deref(),
            source.vault.as_deref(),
            source.item.as_deref(),
        ],
    )
}

pub(super) fn source_digest(
    record: &[u8],
    attributes: &[u8],
    container: Option<&Fingerprint>,
) -> Fingerprint {
    fingerprint(
        b"Confidex import original v1\0",
        &[
            Some(record),
            Some(attributes),
            container.map(|digest| digest.0.as_slice()),
        ],
    )
}

pub(super) fn content_digest(
    record: &mut Record,
    budget: usize,
) -> Result<Fingerprint, confidex_vault::record::Error> {
    let mut retired = Record::default();
    if let Some(origin) = record.extra.remove(KEY) {
        retired.extra.insert(KEY.into(), origin);
    }
    let encoded = record.encode_content(budget);
    if let Some(origin) = retired.extra.remove(KEY) {
        record.extra.insert(KEY.into(), origin);
    }
    encoded.map(|content| encoded_content_digest(&content.bytes))
}

pub(super) fn encoded_content_digest(bytes: &[u8]) -> Fingerprint {
    fingerprint(b"Confidex import content v1\0", &[Some(bytes)])
}

fn field<'a>(map: &'a [(Value, Value)], name: &str) -> Result<&'a Value, ()> {
    let mut found = map.iter().filter(|(key, _)| key.as_str() == Some(name));
    let value = &found.next().ok_or(())?.1;
    if found.next().is_some() {
        return Err(());
    }
    Ok(value)
}
fn hash(value: &Value) -> Result<Fingerprint, ()> {
    match value {
        Value::Binary(bytes) => Ok(Fingerprint(bytes.as_slice().try_into().map_err(|_| ())?)),
        _ => Err(()),
    }
}

fn keys(map: &[(Value, Value)], names: &[&str]) -> Result<(), ()> {
    if map.len() != names.len()
        || map
            .iter()
            .any(|(k, _)| k.as_str().is_none_or(|s| !names.contains(&s)))
    {
        return Err(());
    }
    for name in names {
        field(map, name)?;
    }
    Ok(())
}

pub(super) fn container_digest(bytes: &[u8]) -> Fingerprint {
    fingerprint(b"Confidex import container v1\0", &[Some(bytes)])
}
pub(super) fn carrier(mut attributes: Record, digest: &Fingerprint) -> Record {
    let mut result = Record::default();
    result
        .extra
        .insert("digest".into(), Value::Binary(digest.0.to_vec()));
    result
        .extra
        .insert("attributes".into(), into_map(&mut attributes));
    result
}
pub(super) fn reference(record: [u8; 16], revision: [u8; 32], digest: &Fingerprint) -> Record {
    let mut result = Record::default();
    result
        .extra
        .insert("digest".into(), Value::Binary(digest.0.to_vec()));
    result
        .extra
        .insert("record".into(), Value::Binary(record.to_vec()));
    result
        .extra
        .insert("revision".into(), Value::Binary(revision.to_vec()));
    result
}

pub(super) enum Container {
    None,
    Carrier {
        payload: Record,
        digest: Fingerprint,
    },
    Reference {
        record: [u8; 16],
        revision: [u8; 32],
        digest: Fingerprint,
    },
}

pub(super) fn take_container(record: &mut Record) -> Result<Container, ()> {
    let Some(root) = record.extra.get_mut(KEY) else {
        return Ok(Container::None);
    };
    let Value::Map(root) = root else {
        return Err(());
    };
    let context = &mut root
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("container"))
        .ok_or(())?
        .1;
    validate_container(context)?;
    let Value::Map(context) = context else {
        return Err(());
    };
    if context.is_empty() {
        return Ok(Container::None);
    }
    let digest = hash(field(context, "digest")?)?;
    if let Some((_, attributes)) = context
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("attributes"))
    {
        let Value::Map(values) = attributes else {
            return Err(());
        };
        if values.iter().any(|(key, _)| key.as_str().is_none()) {
            return Err(());
        }
        let Value::Map(values) = std::mem::replace(attributes, Value::Nil) else {
            unreachable!()
        };
        let attributes = values
            .into_iter()
            .map(|(key, value)| {
                let Value::String(key) = key else {
                    unreachable!()
                };
                (key.into_str().expect("checked attribute key"), value)
            })
            .collect();
        Ok(Container::Carrier {
            payload: crate::import::attribute_record(attributes),
            digest,
        })
    } else {
        let Value::Binary(record) = field(context, "record")? else {
            return Err(());
        };
        let Value::Binary(revision) = field(context, "revision")? else {
            return Err(());
        };
        Ok(Container::Reference {
            record: record.as_slice().try_into().map_err(|_| ())?,
            revision: revision.as_slice().try_into().map_err(|_| ())?,
            digest,
        })
    }
}

fn validate_container(value: &Value) -> Result<(), ()> {
    let map = value.as_map().ok_or(())?;
    if map.is_empty() {
        return Ok(());
    }
    hash(field(map, "digest")?)?;
    if map.iter().any(|(k, _)| k.as_str() == Some("attributes")) {
        keys(map, &["digest", "attributes"])?;
        field(map, "attributes")?.as_map().ok_or(())?;
    } else {
        keys(map, &["digest", "record", "revision"])?;
        for (name, size) in [("record", 16), ("revision", 32)] {
            if !matches!(field(map,name)?, Value::Binary(bytes) if bytes.len() == size) {
                return Err(());
            }
        }
    }
    Ok(())
}

pub(super) fn read(record: &Record) -> Result<Option<Origin>, ()> {
    let Some(value) = record.extra.get(KEY) else {
        return Ok(None);
    };
    let map = value.as_map().ok_or(())?;
    keys(
        map,
        &[
            "version",
            "format",
            "source",
            "original",
            "content",
            "attributes",
            "container",
        ],
    )?;
    if field(map, "version")?.as_u64() != Some(1) {
        return Err(());
    }
    let format = field(map, "format")?.as_str().ok_or(())?;
    if ![
        "bitwarden-json",
        "onepassword1pux",
        "keepass-xml",
        "bitwarden-zip",
        "csv",
        "kdbx",
        "bitwarden-encrypted-json",
    ]
    .contains(&format)
    {
        return Err(());
    }
    let source = field(map, "source")?.as_map().ok_or(())?;
    keys(source, &["instance", "account", "vault", "item", "locator"])?;
    let mut parts = [None; 4];
    for (part, name) in parts
        .iter_mut()
        .zip(["instance", "account", "vault", "item"])
    {
        let value = field(source, name)?;
        *part = match value {
            Value::Nil => None,
            Value::String(value) => {
                let value = value.as_str().ok_or(())?;
                if value.len() > 4096 {
                    return Err(());
                }
                Some(value)
            }
            _ => return Err(()),
        };
    }
    field(source, "locator")?.as_u64().ok_or(())?;
    field(map, "attributes")?.as_map().ok_or(())?;
    validate_container(field(map, "container")?)?;
    Ok(Some(Origin {
        source: scoped(format, parts),
        original: hash(field(map, "original")?)?,
        content: hash(field(map, "content")?)?,
    }))
}

pub(super) fn attach(
    record: &mut Record,
    format: Format,
    source: &Source,
    fingerprints: &Origin,
    mut attributes: Record,
    mut container: Record,
) -> Result<(), ()> {
    if record.extra.contains_key(KEY) {
        return Err(());
    }
    let mut origin = Record::default();
    origin.extra.insert("version".into(), 1u64.into());
    origin
        .extra
        .insert("format".into(), format_name(format).into());
    let mut metadata = Record::default();
    for (name, value) in [
        ("instance", &source.instance),
        ("account", &source.account),
        ("vault", &source.vault),
        ("item", &source.item),
    ] {
        metadata.extra.insert(
            name.into(),
            value.as_deref().map(Value::from).unwrap_or(Value::Nil),
        );
    }
    metadata
        .extra
        .insert("locator".into(), (source.locator as u64).into());
    origin
        .extra
        .insert("source".into(), into_map(&mut metadata));
    origin.extra.insert(
        "original".into(),
        Value::Binary(fingerprints.original.0.to_vec()),
    );
    origin.extra.insert(
        "content".into(),
        Value::Binary(fingerprints.content.0.to_vec()),
    );
    origin
        .extra
        .insert("attributes".into(), into_map(&mut attributes));
    origin
        .extra
        .insert("container".into(), into_map(&mut container));
    record.extra.insert(KEY.into(), into_map(&mut origin));
    Ok(())
}
fn into_map(record: &mut Record) -> Value {
    Value::Map(
        std::mem::take(&mut record.extra)
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
    )
}
