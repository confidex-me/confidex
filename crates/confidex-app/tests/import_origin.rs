pub use confidex_app::import;
#[path = "../src/import_apply/matching.rs"]
mod matching;
#[path = "../src/import_apply/origin.rs"]
mod origin;

use confidex_vault::{
    record::{Entry, Record, Value},
    resources::MAX_OPEN_MEMORY,
};
use import::{Format, Source};
use origin::{
    Fingerprint, KEY, Origin, attach, carrier, container_digest, content_digest, read, reference,
    source_digest, source_key,
};

fn source() -> Source {
    let mut source = Source::default();
    source.instance = Some("public-source-instance".into());
    source.account = Some("account".into());
    source.vault = Some("vault".into());
    source.item = Some("item".into());
    source
}
fn record() -> Record {
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "Same title".into());
    record.entries.push(Entry {
        name: "duplicate".into(),
        type_name: "password/v1".into(),
        value: [("password".into(), "public-synthetic-secret".into())].into(),
        extra: Default::default(),
    });
    record.entries.push(Entry {
        name: "duplicate".into(),
        type_name: "file/v1".into(),
        value: [("data".into(), Value::Binary(vec![0, 255, 1]))].into(),
        extra: Default::default(),
    });
    record
}

#[test]
fn identity_is_scoped_length_framed_and_independent_of_locator() {
    let mut source = source();
    let original = source_key(Format::BitwardenJson, &source).unwrap();
    source.locator = 99;
    assert!(source_key(Format::BitwardenJson, &source).unwrap() == original);
    for name in ["instance", "account", "vault", "item"] {
        let mut changed = self::source();
        let field = match name {
            "instance" => &mut changed.instance,
            "account" => &mut changed.account,
            "vault" => &mut changed.vault,
            _ => &mut changed.item,
        };
        *field = Some("other".into());
        assert!(source_key(Format::BitwardenJson, &changed).unwrap() != original);
    }
    assert!(source_key(Format::KeepassXml, &source).unwrap() != original);
    source.account = Some("a".into());
    source.vault = Some("bc".into());
    let framed = source_key(Format::Csv, &source);
    source.account = Some("ab".into());
    source.vault = Some("c".into());
    assert!(source_key(Format::Csv, &source) != framed);
    source.account = None;
    let absent = source_key(Format::Csv, &source);
    source.account = Some(String::new());
    assert!(source_key(Format::Csv, &source) != absent);
    source.instance = Some(" \n".into());
    assert!(source_key(Format::Csv, &source).is_none());
    source.instance = Some("instance".into());
    source.item = None;
    assert!(source_key(Format::Csv, &source).is_none());
}

#[test]
fn provenance_round_trip_preserves_binary_and_is_excluded_from_local_edit_hash() {
    let mut record = record();
    let bytes = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let content = content_digest(&mut record, MAX_OPEN_MEMORY).unwrap();
    let context = container_digest(b"container");
    let changed = container_digest(b"changed");
    let original = source_digest(&bytes.bytes, b"attributes", Some(&context));
    assert!(original != source_digest(&bytes.bytes, b"changed", Some(&context)));
    assert!(original != source_digest(&bytes.bytes, b"attributes", Some(&changed)));
    assert!(original != source_digest(&bytes.bytes, b"attributes", None));
    assert!(source_digest(b"ab", b"c", None) != source_digest(b"a", b"bc", None));
    let mut attributes = Record::default();
    attributes
        .extra
        .insert("entries".into(), Value::Binary(vec![0, 255]));
    attributes
        .extra
        .insert("tags".into(), "source-only-tags".into());
    let source = source();
    attach(
        &mut record,
        Format::BitwardenJson,
        &source,
        &Origin {
            source: None,
            original: original.clone(),
            content: content.clone(),
        },
        attributes,
        Record::default(),
    )
    .unwrap();
    assert!(content_digest(&mut record, MAX_OPEN_MEMORY).unwrap() == content);
    assert!(record.extra.contains_key(KEY));
    let reopened = Record::decode_content(
        &record.encode_content(MAX_OPEN_MEMORY).unwrap().bytes,
        MAX_OPEN_MEMORY,
    )
    .unwrap()
    .record;
    let origin = read(&reopened).unwrap().unwrap();
    assert!(origin.source == source_key(Format::BitwardenJson, &source));
    assert!(origin.original == original && origin.content == content);
    let map = reopened.extra[KEY].as_map().unwrap();
    let attrs = map
        .iter()
        .find(|(k, _)| k.as_str() == Some("attributes"))
        .unwrap()
        .1
        .as_map()
        .unwrap();
    assert_eq!(
        attrs
            .iter()
            .find(|(k, _)| k.as_str() == Some("entries"))
            .unwrap()
            .1,
        Value::Binary(vec![0, 255])
    );
    record.entries[0]
        .value
        .insert("password".into(), "local-edit".into());
    assert!(content_digest(&mut record, MAX_OPEN_MEMORY).unwrap() != content);
    assert!(content_digest(&mut record, 1).is_err());
    assert!(record.extra.contains_key(KEY));
}

#[test]
fn malformed_or_future_provenance_is_not_treated_as_an_unimported_record() {
    let mut record = record();
    assert!(read(&record).unwrap().is_none());
    let fingerprint = Fingerprint([7; 32]);
    let fingerprints = Origin {
        source: None,
        original: fingerprint.clone(),
        content: fingerprint,
    };
    attach(
        &mut record,
        Format::Csv,
        &Source::default(),
        &fingerprints,
        Record::default(),
        Record::default(),
    )
    .unwrap();
    assert!(read(&record).unwrap().unwrap().source.is_none());
    assert!(
        attach(
            &mut record,
            Format::Csv,
            &Source::default(),
            &fingerprints,
            Record::default(),
            Record::default()
        )
        .is_err()
    );
    let map = match record.extra.get_mut(KEY).unwrap() {
        Value::Map(map) => map,
        _ => unreachable!(),
    };
    map.push(("version".into(), 1u64.into()));
    assert!(read(&record).is_err());
    let map = match record.extra.get_mut(KEY).unwrap() {
        Value::Map(map) => map,
        _ => unreachable!(),
    };
    map.pop();
    map.iter_mut()
        .find(|(k, _)| k.as_str() == Some("version"))
        .unwrap()
        .1 = 2u64.into();
    assert!(read(&record).is_err());
}

#[test]
fn container_can_be_carried_once_and_referenced_by_immutable_revision() {
    let payload = import::attribute_record([("tags".into(), "vendor-data".into())].into());
    let digest = container_digest(&payload.encode_content(MAX_OPEN_MEMORY).unwrap().bytes);
    assert!(digest != container_digest(b"changed"));
    let fingerprints = Origin {
        source: None,
        original: digest.clone(),
        content: digest.clone(),
    };
    let mut attrs = Record::default();
    attrs.extra.insert("tags".into(), "vendor-data".into());
    let mut first = record();
    let mut second = record();
    attach(
        &mut first,
        Format::Csv,
        &Source::default(),
        &fingerprints,
        Record::default(),
        carrier(attrs, &digest),
    )
    .unwrap();
    attach(
        &mut second,
        Format::Csv,
        &Source::default(),
        &fingerprints,
        Record::default(),
        reference([1; 16], [2; 32], &digest),
    )
    .unwrap();
    assert!(read(&first).unwrap().is_some() && read(&second).unwrap().is_some());
    let origin::Container::Carrier {
        payload,
        digest: stored,
    } = origin::take_container(&mut first).unwrap()
    else {
        panic!("carrier")
    };
    assert!(
        stored == digest
            && container_digest(&payload.encode_content(MAX_OPEN_MEMORY).unwrap().bytes) == digest
    );
    let origin::Container::Reference {
        record,
        revision,
        digest: stored,
    } = origin::take_container(&mut second).unwrap()
    else {
        panic!("reference")
    };
    assert_eq!(record, [1; 16]);
    assert_eq!(revision, [2; 32]);
    assert!(stored == digest);
    assert!(matches!(
        origin::take_container(&mut Record::default()).unwrap(),
        origin::Container::None
    ));
    let encoded = second.encode_content(MAX_OPEN_MEMORY).unwrap();
    assert!(!encoded.bytes.windows(11).any(|b| b == b"vendor-data"));
    let Value::Map(origin) = second.extra.get_mut(KEY).unwrap() else {
        unreachable!()
    };
    let Value::Map(container) = &mut origin
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("container"))
        .unwrap()
        .1
    else {
        unreachable!()
    };
    container
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("revision"))
        .unwrap()
        .1 = Value::Binary(vec![0; 31]);
    assert!(read(&second).is_err());
}
