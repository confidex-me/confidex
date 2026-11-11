use confidex_vault::{
    envelope::{self, EventKind, Options},
    kdf, lock,
    record::{Entry, Mapping, Record, Value},
    records_list::{Limits, Reader, Writer},
    resources::MAX_OPEN_MEMORY,
    revisions::Graph,
    secret_key_text,
    trust::TrustAnchor,
};

#[test]
fn create_edit_delete_lock_reopen_and_old_client_use_compose_without_storage_policy() {
    let created = lock::create(b"initial password", kdf::REQUIRED_MEMORY).unwrap();
    let vault_id = created.vault.vault_id();
    let pin = created.vault.anchor().public_key();
    let secret_text = secret_key_text::encode(&created.vault.keys().secret_key());
    let mut record = Record {
        tags: Vec::new(),
        entries: vec![Entry {
            name: "password".into(),
            type_name: "password/v1".into(),
            value: Mapping::from([
                ("password".into(), "synthetic password".into()),
                ("future".into(), Value::Ext(7, vec![0xc1])),
            ]),
            extra: Mapping::new(),
        }],
        extra: Mapping::new(),
    };
    let options = |parents, epoch, kind| Options {
        vault_id,
        record_id: [10; 16],
        parents,
        epoch,
        kind,
    };
    let first = envelope::seal(
        &record,
        created.vault.keys(),
        options(&[], 100, EventKind::Content),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let first_id = envelope::verify(&first, created.vault.anchor(), None, MAX_OPEN_MEMORY)
        .unwrap()
        .id();
    record.entries[0]
        .value
        .insert("password".into(), "updated synthetic password".into());
    let first_parent = [first_id];
    let second = envelope::seal(
        &record,
        created.vault.keys(),
        options(&first_parent, 90, EventKind::Content),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let second_id = envelope::verify(&second, created.vault.anchor(), None, MAX_OPEN_MEMORY)
        .unwrap()
        .id();
    let second_parent = [second_id];
    let deletion = envelope::seal(
        &Record::default(),
        created.vault.keys(),
        options(&second_parent, 110, EventKind::Deletion),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let deletion_id = envelope::verify(&deletion, created.vault.anchor(), None, MAX_OPEN_MEMORY)
        .unwrap()
        .id();
    let mut stored = Vec::new();
    let mut writer =
        Writer::new(&mut stored, created.vault.anchor(), 3, Limits::default()).unwrap();
    for wire in [&deletion, &first, &second] {
        writer.push(wire, MAX_OPEN_MEMORY).unwrap();
    }
    writer.finish().unwrap();
    let new_lock = created
        .vault
        .rewrap(b"replacement password", kdf::REQUIRED_MEMORY)
        .unwrap();
    let old_lock = created.lock;
    drop(record);
    drop(created.vault);

    let locked_pin = TrustAnchor::from_local_pin(vault_id, Some(&pin)).unwrap();
    let graph = Graph::new(&locked_pin);
    let mut update = graph.begin(3, MAX_OPEN_MEMORY).unwrap();
    let mut reader = Reader::new(stored.as_slice(), &locked_pin, Limits::default()).unwrap();
    while let Some(object) = reader.read_next(update.object_budget()).unwrap() {
        update.stage(&object.revision, None).unwrap();
    }
    reader.finish().unwrap();
    let graph = update.finish(&[]).unwrap();
    assert_eq!(graph.len(), 3);
    assert!(graph.report().missing.is_empty());
    assert_eq!(graph.report().heads, [([10; 16], deletion_id)]);
    assert_eq!(graph.report().deletions, [([10; 16], deletion_id)]);

    let sk = secret_key_text::decode(std::str::from_utf8(&secret_text[..]).unwrap()).unwrap();
    let old_client = lock::open(&old_lock, b"initial password", &sk, kdf::REQUIRED_MEMORY).unwrap();
    let new_client = lock::open(
        &new_lock,
        b"replacement password",
        &sk,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    for client in [&old_client, &new_client] {
        assert_eq!(client.anchor().public_key(), pin);
        let mut reader =
            Reader::new(stored.as_slice(), client.anchor(), Limits::default()).unwrap();
        let mut count = 0;
        while let Some(object) = reader.read_next(MAX_OPEN_MEMORY).unwrap() {
            let content = object
                .revision
                .open(client.keys(), MAX_OPEN_MEMORY)
                .unwrap();
            for entry in &content.entries {
                entry.validate_value().unwrap();
                assert_eq!(entry.value["future"], Value::Ext(7, vec![0xc1]));
            }
            count += 1;
        }
        reader.finish().unwrap();
        assert_eq!(count, 3);
    }
    let fresh_record = Record {
        tags: Vec::new(),
        entries: vec![],
        extra: Mapping::new(),
    };
    let fresh = envelope::seal(
        &fresh_record,
        old_client.keys(),
        Options {
            vault_id,
            record_id: [11; 16],
            parents: &[],
            epoch: 120,
            kind: EventKind::Content,
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let opened = envelope::open(
        &fresh,
        new_client.keys(),
        new_client.anchor(),
        None,
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let mut update = graph.begin(1, MAX_OPEN_MEMORY).unwrap();
    update.stage(&opened.revision, None).unwrap();
    let accepted = update.finish(&[]).unwrap();
    assert_eq!(accepted.len(), 4);
    assert_eq!(accepted.report().deletions, graph.report().deletions);
    assert_eq!(graph.len(), 3);
}
