use confidex_vault::{
    crypto::{self, VaultKeys},
    envelope,
    records_list::{self, Error, Limits, Reader, Writer},
    resources::MAX_OPEN_MEMORY,
    trust::TrustAnchor,
};
use ed25519_dalek::Signer;
use rmpv::Value;
use std::io::{self, Cursor, Read, Write};

fn fixture(name: &str) -> Vec<u8> {
    let text = include_str!("../../../tests/fixtures/vectors.hex");
    let hex = text
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap();
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn keys() -> VaultKeys {
    VaultKeys::from_material(
        1,
        &crypto::clamp_material(std::array::from_fn(|i| i as u8))[..],
    )
    .unwrap()
}
fn anchor(keys: &VaultKeys) -> TrustAnchor {
    TrustAnchor::from_local_pin(
        [7; 16],
        Some(&keys.signing_key().verifying_key().to_bytes()),
    )
    .unwrap()
}
fn list(revisions: Vec<Vec<u8>>) -> Vec<u8> {
    let v = Value::Array(vec![
        "confidex/records".into(),
        2.into(),
        Value::Binary(vec![7; 16]),
        Value::Array(revisions.into_iter().map(Value::Binary).collect()),
    ]);
    let mut b = Vec::new();
    rmpv::encode::write_value(&mut b, &v).unwrap();
    b
}
struct Chunks<R>(R);
impl<R: Read> Read for Chunks<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = b.len().min(3);
        self.0.read(&mut b[..n])
    }
}

#[test]
fn streaming_reader_and_writer_preserve_golden_envelopes_and_empty_lists() {
    let keys = keys();
    let pin = anchor(&keys);
    let source = fixture("records_list");
    let mut reader = Reader::new(Chunks(source.as_slice()), &pin, Limits::default()).unwrap();
    let mut writer = Writer::new(Vec::new(), &pin, 5, Limits::default()).unwrap();
    for i in 0..5 {
        let object = reader.read_next(MAX_OPEN_MEMORY).unwrap().unwrap();
        assert_eq!(object.wire, fixture(&format!("revision_{i}")));
        let expected: [u8; 32] = fixture(&format!("revision_id_{i}")).try_into().unwrap();
        assert_eq!(object.revision.id(), expected);
        let record = object.revision.open(&keys, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(record.entries.len(), if i == 4 { 0 } else { 2 });
        writer.push(object.wire, MAX_OPEN_MEMORY).unwrap();
    }
    assert!(reader.read_next(MAX_OPEN_MEMORY).unwrap().is_none());
    let summary = reader.finish().unwrap();
    assert_eq!(summary.items, 5);
    assert_eq!(summary.edges, 5);
    assert_eq!(summary.bytes, source.len());
    assert_eq!(writer.finish().unwrap(), source);
    let empty = Writer::new(Vec::new(), &pin, 0, Limits::default())
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(empty, fixture("empty_list"));
    assert_eq!(
        Reader::new(empty.as_slice(), &pin, Limits::default())
            .unwrap()
            .finish()
            .unwrap()
            .items,
        0
    );
}

#[test]
fn byte_item_and_edge_limits_are_inclusive_and_count_duplicate_deliveries() {
    let keys = keys();
    let pin = anchor(&keys);
    let revision = fixture("revision_3");
    let source = list(vec![revision.clone(), revision.clone()]);
    let limits = Limits {
        bytes: source.len(),
        items: 2,
        edges: 4,
    };
    let mut reader = Reader::new(source.as_slice(), &pin, limits).unwrap();
    let a = reader
        .read_next(MAX_OPEN_MEMORY)
        .unwrap()
        .unwrap()
        .revision
        .id();
    let b = reader
        .read_next(MAX_OPEN_MEMORY)
        .unwrap()
        .unwrap()
        .revision
        .id();
    assert_eq!(a, b);
    assert_eq!(reader.finish().unwrap().edges, 4);
    let mut writer = Writer::new(Vec::new(), &pin, 2, limits).unwrap();
    writer.push(&revision, MAX_OPEN_MEMORY).unwrap();
    writer.push(&revision, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(writer.finish().unwrap(), source);
    for low in [
        Limits {
            bytes: source.len() - 1,
            ..limits
        },
        Limits { edges: 3, ..limits },
    ] {
        let mut r = Reader::new(source.as_slice(), &pin, low).unwrap();
        assert!(r.read_next(MAX_OPEN_MEMORY).unwrap().is_some());
        assert_eq!(r.read_next(MAX_OPEN_MEMORY).err(), Some(Error::Limit));
        assert_eq!(r.finish().err(), Some(Error::State));
        let mut w = Writer::new(Vec::new(), &pin, 2, low).unwrap();
        w.push(&revision, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(w.push(&revision, MAX_OPEN_MEMORY), Err(Error::Limit));
        assert_eq!(w.finish().err(), Some(Error::State));
    }
    assert_eq!(
        Reader::new(source.as_slice(), &pin, Limits { items: 1, ..limits }).err(),
        Some(Error::Limit)
    );
    assert_eq!(
        Writer::new(Vec::new(), &pin, 2, Limits { items: 1, ..limits }).err(),
        Some(Error::Limit)
    );
    for count in [9999, 10000, 10001] {
        let mut prefix = fixture("empty_list");
        prefix.pop();
        rmp::encode::write_array_len(&mut prefix, count).unwrap();
        assert_eq!(
            Reader::new(prefix.as_slice(), &pin, Limits::default()).is_ok(),
            count <= 10000
        );
        assert_eq!(
            Writer::new(Vec::new(), &pin, count as usize, Limits::default()).is_ok(),
            count <= 10000
        );
    }
    for bad in [
        Limits {
            bytes: records_list::MAX_BYTES + 1,
            ..Limits::default()
        },
        Limits {
            items: records_list::MAX_ITEMS + 1,
            ..Limits::default()
        },
        Limits {
            edges: records_list::MAX_EDGES + 1,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            Reader::new(source.as_slice(), &pin, bad).err(),
            Some(Error::Limit)
        );
    }
}

fn checked_import(source: &[u8], accepted: &mut Vec<Vec<u8>>) -> Result<(), Error> {
    let keys = keys();
    let pin = anchor(&keys);
    let mut staged = Vec::new();
    let mut reader = Reader::new(source, &pin, Limits::default())?;
    while let Some(object) = reader.read_next(MAX_OPEN_MEMORY)? {
        let _record = object
            .revision
            .open(&keys, MAX_OPEN_MEMORY)
            .map_err(Error::Envelope)?;
        staged.push(object.wire.to_vec());
    }
    reader.finish()?;
    accepted.extend(staged);
    Ok(())
}

#[test]
fn import_is_staged_until_content_and_the_whole_stream_are_checked() {
    let mut accepted = vec![fixture("revision_0")];
    let saved = accepted.clone();
    let mut trailing = fixture("records_list");
    trailing.push(0);
    let mut truncated = fixture("records_list");
    truncated.pop();
    for bad in [
        trailing,
        truncated,
        list(vec![fixture("revision_0"), fixture("negative_signature")]),
        list(vec![fixture("revision_0"), fixture("negative_sizes")]),
    ] {
        assert!(checked_import(&bad, &mut accepted).is_err());
        assert_eq!(accepted, saved);
    }
    checked_import(&fixture("records_list"), &mut accepted).unwrap();
    assert_eq!(accepted.len(), 6);
}

struct FailureReader {
    inner: Cursor<Vec<u8>>,
    fail_at: u64,
}
impl Read for FailureReader {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.inner.position() >= self.fail_at {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let n = b.len().min((self.fail_at - self.inner.position()) as usize);
        self.inner.read(&mut b[..n])
    }
}
struct FailureWriter {
    remaining: usize,
}
impl Write for FailureWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let n = b.len().min(self.remaining);
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn corrupt_streams_wrong_scope_and_io_errors_cannot_finish_successfully() {
    let keys = keys();
    let pin = anchor(&keys);
    let wire = fixture("records_list");
    assert_eq!(
        Reader::new(
            fixture("negative_list_version").as_slice(),
            &pin,
            Limits::default()
        )
        .err(),
        Some(Error::Version)
    );
    let other = TrustAnchor::from_local_pin([9; 16], Some(&pin.public_key())).unwrap();
    assert_eq!(
        Reader::new(fixture("empty_list").as_slice(), &other, Limits::default()).err(),
        Some(Error::WrongVault)
    );
    let mut reader = Reader::new(wire.as_slice(), &pin, Limits::default()).unwrap();
    assert_eq!(
        reader.read_next(0).err(),
        Some(Error::Envelope(envelope::Error::Limit))
    );
    assert_eq!(reader.read_next(MAX_OPEN_MEMORY).err(), Some(Error::State));
    assert_eq!(
        Reader::new(wire.as_slice(), &pin, Limits::default())
            .unwrap()
            .finish()
            .err(),
        Some(Error::State)
    );
    assert_eq!(
        Writer::new(Vec::new(), &pin, 1, Limits::default())
            .unwrap()
            .finish()
            .err(),
        Some(Error::State)
    );
    let mut extra = Writer::new(Vec::new(), &pin, 0, Limits::default()).unwrap();
    assert_eq!(
        extra.push(&fixture("revision_0"), MAX_OPEN_MEMORY),
        Err(Error::State)
    );
    assert_eq!(extra.finish().err(), Some(Error::State));
    let failed = FailureReader {
        inner: Cursor::new(wire),
        fail_at: 50,
    };
    let mut reader = Reader::new(failed, &pin, Limits::default()).unwrap();
    assert_eq!(
        reader.read_next(MAX_OPEN_MEMORY).err(),
        Some(Error::Io(io::ErrorKind::PermissionDenied))
    );
    assert_eq!(reader.finish().err(), Some(Error::State));
    let mut writer =
        Writer::new(FailureWriter { remaining: 50 }, &pin, 1, Limits::default()).unwrap();
    assert_eq!(
        writer.push(&fixture("revision_0"), MAX_OPEN_MEMORY),
        Err(Error::Io(io::ErrorKind::PermissionDenied))
    );
    assert_eq!(writer.finish().err(), Some(Error::State));
}

fn object_with_parents(count: u32) -> Vec<u8> {
    let mut root = rmpv::decode::read_value(&mut fixture("revision_0").as_slice()).unwrap();
    let Value::Array(fields) = &mut root else {
        unreachable!()
    };
    let Value::Binary(h) = &fields[0] else {
        unreachable!()
    };
    let mut header = rmpv::decode::read_value(&mut h.as_slice()).unwrap();
    let Value::Array(values) = &mut header else {
        unreachable!()
    };
    values[3] = Value::Array(
        (0..count)
            .map(|i| {
                let mut id = vec![0; 32];
                id[..4].copy_from_slice(&i.to_be_bytes());
                Value::Binary(id)
            })
            .collect(),
    );
    let mut h = Vec::new();
    rmpv::encode::write_value(&mut h, &header).unwrap();
    let Value::Binary(c) = &fields[1] else {
        unreachable!()
    };
    let signature = keys()
        .signing_key()
        .sign(&crypto::signed_record_bytes(&h, c))
        .to_bytes();
    fields[0] = Value::Binary(h);
    fields[2] = Value::Binary(signature.to_vec());
    let mut wire = Vec::new();
    rmpv::encode::write_value(&mut wire, &root).unwrap();
    wire
}

#[test]
fn actual_full_edge_boundary_counts_duplicate_signed_headers() {
    let keys = keys();
    let pin = anchor(&keys);
    let common = object_with_parents(1024);
    for total in [99_999, 100_000, 100_001] {
        let mut items = vec![common.clone(); 97];
        items.push(object_with_parents(total - 97 * 1024));
        let source = list(items.clone());
        let mut reader = Reader::new(source.as_slice(), &pin, Limits::default()).unwrap();
        let mut writer = Writer::new(io::sink(), &pin, items.len(), Limits::default()).unwrap();
        for wire in items.iter().take(97) {
            assert!(reader.read_next(MAX_OPEN_MEMORY).unwrap().is_some());
            writer.push(wire, MAX_OPEN_MEMORY).unwrap();
        }
        if total <= 100_000 {
            assert!(reader.read_next(MAX_OPEN_MEMORY).unwrap().is_some());
            assert_eq!(reader.finish().unwrap().edges, total as usize);
            writer.push(&items[97], MAX_OPEN_MEMORY).unwrap();
            writer.finish().unwrap();
        } else {
            assert_eq!(reader.read_next(MAX_OPEN_MEMORY).err(), Some(Error::Limit));
            assert_eq!(writer.push(&items[97], MAX_OPEN_MEMORY), Err(Error::Limit));
        }
    }
}
