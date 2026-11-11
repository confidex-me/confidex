use confidex_vault::{
    crypto::{self, VaultKeys},
    envelope::{self, EventKind, Options},
    record::Record,
    resources::MAX_OPEN_MEMORY,
    revisions::{Error, Graph},
    trust::TrustAnchor,
};
use ed25519_dalek::Signer;
use rmpv::Value;

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
fn anchor(keys: &VaultKeys, vault: [u8; 16]) -> TrustAnchor {
    TrustAnchor::from_local_pin(vault, Some(&keys.signing_key().verifying_key().to_bytes()))
        .unwrap()
}
fn id(i: usize) -> [u8; 32] {
    fixture(&format!("revision_id_{i}")).try_into().unwrap()
}

#[test]
fn branches_merges_and_deletions_survive_transactional_updates_and_replay() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let wires: Vec<_> = (0..5).map(|i| fixture(&format!("revision_{i}"))).collect();
    let v: Vec<_> = wires
        .iter()
        .map(|w| envelope::verify(w, &pin, None, MAX_OPEN_MEMORY).unwrap())
        .collect();
    let graph = Graph::new(&pin);
    let mut u = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    u.stage(&v[0], None).unwrap();
    let graph = u.finish(&[]).unwrap();
    assert_eq!(graph.report().heads, vec![([8; 16], id(0))]);
    assert!(graph.report().missing.is_empty());
    let mut u = graph.begin(2, MAX_OPEN_MEMORY).unwrap();
    u.stage(&v[2], None).unwrap();
    u.stage(&v[1], None).unwrap();
    let graph = u.finish(&[]).unwrap();
    let mut heads = vec![([8; 16], id(1)), ([8; 16], id(2))];
    heads.sort();
    assert_eq!(graph.report().heads, heads);
    let mut u = graph.begin(2, MAX_OPEN_MEMORY).unwrap();
    u.stage(&v[4], None).unwrap();
    u.stage(&v[3], None).unwrap();
    let graph = u.finish(&[]).unwrap();
    assert_eq!(graph.report().heads, vec![([8; 16], id(4))]);
    assert_eq!(graph.report().deletions, vec![([8; 16], id(4))]);
    let mut u = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    u.stage(&v[0], Some(&v[0])).unwrap();
    let replay = u.finish(&[]).unwrap();
    assert_eq!(replay.report(), graph.report());
    assert_eq!(replay.len(), 5);
    assert_eq!(replay.get(&id(0)).unwrap().epoch, 1_794_096_000_030);
    let mut bad = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(bad.stage(&v[0], None), Err(Error::OriginalRequired));
    assert!(matches!(bad.finish(&[]), Err(Error::State)));
    assert_eq!(graph.len(), 5);
    let mut bad = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(bad.stage(&v[0], Some(&v[1])), Err(Error::ConflictingId));
    assert_eq!(graph.report().deletions, vec![([8; 16], id(4))]);
}

#[test]
fn pending_parents_and_explicit_expectations_remain_incomplete_until_received() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let wires: Vec<_> = (0..4).map(|i| fixture(&format!("revision_{i}"))).collect();
    let v: Vec<_> = wires
        .iter()
        .map(|w| envelope::verify(w, &pin, None, MAX_OPEN_MEMORY).unwrap())
        .collect();
    let graph = Graph::new(&pin);
    let mut u = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    u.stage(&v[3], None).unwrap();
    let graph = u.finish(&[id(0)]).unwrap();
    let mut missing = vec![id(0), id(1), id(2)];
    missing.sort();
    assert_eq!(graph.report().missing, missing);
    let graph = graph
        .begin(0, MAX_OPEN_MEMORY)
        .unwrap()
        .finish(&[])
        .unwrap();
    assert_eq!(graph.report().missing, missing);
    let mut u = graph.begin(3, MAX_OPEN_MEMORY).unwrap();
    for item in &v[..3] {
        u.stage(item, None).unwrap();
    }
    let graph = u.finish(&[]).unwrap();
    assert!(graph.report().missing.is_empty());
    assert_eq!(graph.report().heads, vec![([8; 16], id(3))]);
}

fn sealed(
    keys: &VaultKeys,
    record: [u8; 16],
    parents: &[[u8; 32]],
    epoch: u64,
    vault: [u8; 16],
) -> Vec<u8> {
    envelope::seal(
        &Record::default(),
        keys,
        Options {
            vault_id: vault,
            record_id: record,
            parents,
            epoch,
            kind: EventKind::Content,
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap()
}
#[test]
fn a_late_foreign_parent_rejects_the_candidate_without_replacing_accepted_history() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let parent_wire = sealed(&keys, [9; 16], &[], 50, [7; 16]);
    let parent = envelope::verify(&parent_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let child_wire = sealed(&keys, [8; 16], &[parent.id()], 0, [7; 16]);
    let child = envelope::verify(&child_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let graph = Graph::new(&pin);
    let mut u = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    u.stage(&child, None).unwrap();
    let graph = u.finish(&[]).unwrap();
    assert_eq!(graph.report().missing, vec![parent.id()]);
    let mut u = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    u.stage(&parent, None).unwrap();
    assert!(matches!(u.finish(&[]), Err(Error::Scope)));
    assert_eq!(graph.len(), 1);
    assert_eq!(graph.report().missing, vec![parent.id()]);
}

#[test]
fn authenticated_other_keys_or_vaults_cannot_enter_the_graph() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let graph = Graph::new(&pin);
    let other = VaultKeys::from_material(1, &crypto::clamp_material([3; 32])[..]).unwrap();
    for (sender, vault) in [(&other, [7; 16]), (&keys, [9; 16])] {
        let sender_pin = anchor(sender, vault);
        let wire = sealed(sender, [8; 16], &[], 0, vault);
        let r = envelope::verify(&wire, &sender_pin, None, MAX_OPEN_MEMORY).unwrap();
        let mut u = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(u.stage(&r, None), Err(Error::WrongTrust));
        assert!(matches!(u.finish(&[]), Err(Error::State)));
    }
    assert!(graph.is_empty());
}

#[test]
fn duplicate_identity_ignores_outer_framing_and_admission_precedes_allocations() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let wire = fixture("revision_0");
    let original = envelope::verify(&wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let value = rmpv::decode::read_value(&mut wire.as_slice()).unwrap();
    let Value::Array(fields) = value else {
        unreachable!()
    };
    let mut alternative = vec![0xdd, 0, 0, 0, 3];
    for f in fields {
        let Value::Binary(b) = f else { unreachable!() };
        alternative.push(0xc6);
        alternative.extend_from_slice(&(b.len() as u32).to_be_bytes());
        alternative.extend_from_slice(&b);
    }
    let alt = envelope::verify(&alternative, &pin, None, MAX_OPEN_MEMORY).unwrap();
    assert!(original.same_payload(&alt));
    assert_eq!(original.id(), alt.id());
    assert_ne!(original.encoded_len(), alt.encoded_len());
    let graph = Graph::new(&pin);
    assert!(matches!(
        graph.begin(1, 24 * 1024 * 1024),
        Err(Error::Limit)
    ));
    assert!(matches!(
        graph.begin(1, MAX_OPEN_MEMORY + 1),
        Err(Error::Limit)
    ));
    for count in [9999, 10000, 10001] {
        assert_eq!(graph.begin(count, MAX_OPEN_MEMORY).is_ok(), count <= 10000);
    }
    let mut u = graph.begin(2, MAX_OPEN_MEMORY).unwrap();
    u.stage(&original, None).unwrap();
    u.stage(&alt, Some(&original)).unwrap();
    let graph = u.finish(&[]).unwrap();
    assert_eq!(graph.len(), 1);
    assert!(matches!(
        graph.begin(1, MAX_OPEN_MEMORY).unwrap().finish(&[]),
        Err(Error::State)
    ));
    let empty = Graph::new(&pin);
    assert!(matches!(
        empty
            .begin(0, 24 * 1024 * 1024)
            .unwrap()
            .finish(&[[99; 32]]),
        Err(Error::Limit)
    ));
}

fn signed_payload(keys: &VaultKeys, ciphertext_bytes: usize) -> Vec<u8> {
    let mut v = rmpv::decode::read_value(&mut fixture("revision_0").as_slice()).unwrap();
    let Value::Array(fields) = &mut v else {
        unreachable!()
    };
    let Value::Binary(h) = &fields[0] else {
        unreachable!()
    };
    let c = vec![0; ciphertext_bytes];
    let sig = keys
        .signing_key()
        .sign(&crypto::signed_record_bytes(h, &c))
        .to_bytes();
    fields[1] = Value::Binary(c);
    fields[2] = Value::Binary(sig.to_vec());
    let mut wire = Vec::new();
    rmpv::encode::write_value(&mut wire, &v).unwrap();
    wire
}
#[test]
fn envelope_byte_budget_counts_replays_without_collecting_a_large_batch() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let payload = envelope::MAX_PACKET;
    let large_wire = signed_payload(&keys, payload);
    let large = envelope::verify(&large_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let count = confidex_vault::records_list::MAX_BYTES / large_wire.len();
    let rest = confidex_vault::records_list::MAX_BYTES - count * large_wire.len();
    let overhead = large_wire.len() - payload;
    for extra in [0, 1] {
        let tail_wire = signed_payload(&keys, rest - overhead + extra);
        assert_eq!(tail_wire.len(), rest + extra);
        let tail = envelope::verify(&tail_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
        let graph = Graph::new(&pin);
        let mut u = graph.begin(count + 1, MAX_OPEN_MEMORY).unwrap();
        for i in 0..count {
            u.stage(&large, if i == 0 { None } else { Some(&large) })
                .unwrap();
        }
        if extra == 0 {
            u.stage(&tail, None).unwrap();
            assert_eq!(u.finish(&[]).unwrap().len(), 2);
        } else {
            assert_eq!(u.stage(&tail, None), Err(Error::Limit));
            assert!(matches!(u.finish(&[]), Err(Error::State)));
        }
    }
}

#[test]
fn concurrent_delete_edit_and_a_later_content_child_do_not_erase_the_deletion() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let root_wire = fixture("revision_0");
    let root = envelope::verify(&root_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let parents = [root.id()];
    let deleted_wire = envelope::seal(
        &Record::default(),
        &keys,
        Options {
            vault_id: [7; 16],
            record_id: [8; 16],
            parents: &parents,
            epoch: 999,
            kind: EventKind::Deletion,
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let deleted = envelope::verify(&deleted_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let edit_wire = sealed(&keys, [8; 16], &parents, 0, [7; 16]);
    let edit = envelope::verify(&edit_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let graph = Graph::new(&pin);
    let mut u = graph.begin(3, MAX_OPEN_MEMORY).unwrap();
    for v in [&deleted, &edit, &root] {
        u.stage(v, None).unwrap();
    }
    let graph = u.finish(&[]).unwrap();
    let mut heads = vec![([8; 16], deleted.id()), ([8; 16], edit.id())];
    heads.sort();
    assert_eq!(graph.report().heads, heads);
    let child_wire = sealed(&keys, [8; 16], &[deleted.id(), edit.id()], 0, [7; 16]);
    let child = envelope::verify(&child_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    let mut u = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    u.stage(&child, None).unwrap();
    let graph = u.finish(&[]).unwrap();
    assert_eq!(graph.report().heads, vec![([8; 16], child.id())]);
    assert_eq!(graph.report().deletions, vec![([8; 16], deleted.id())]);
}

fn edge_object(keys: &VaultKeys, count: u32) -> Vec<u8> {
    let mut v = rmpv::decode::read_value(&mut fixture("revision_0").as_slice()).unwrap();
    let Value::Array(fields) = &mut v else {
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
    let sig = keys
        .signing_key()
        .sign(&crypto::signed_record_bytes(&h, c))
        .to_bytes();
    fields[0] = Value::Binary(h);
    fields[2] = Value::Binary(sig.to_vec());
    let mut wire = Vec::new();
    rmpv::encode::write_value(&mut wire, &v).unwrap();
    wire
}
#[test]
fn edge_budget_counts_deliveries_even_when_the_index_deduplicates_nodes() {
    let keys = keys();
    let pin = anchor(&keys, [7; 16]);
    let first_wire = edge_object(&keys, 1024);
    let first = envelope::verify(&first_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
    for total in [100_000, 100_001] {
        let tail_wire = edge_object(&keys, total - 97 * 1024);
        let tail = envelope::verify(&tail_wire, &pin, None, MAX_OPEN_MEMORY).unwrap();
        let graph = Graph::new(&pin);
        let mut u = graph.begin(98, MAX_OPEN_MEMORY).unwrap();
        for i in 0..97 {
            u.stage(&first, if i == 0 { None } else { Some(&first) })
                .unwrap();
        }
        if total == 100_000 {
            u.stage(&tail, None).unwrap();
            assert_eq!(u.finish(&[]).unwrap().len(), 2);
        } else {
            assert_eq!(u.stage(&tail, None), Err(Error::Limit));
            assert!(matches!(u.finish(&[]), Err(Error::State)));
        }
    }
}
