#![cfg(not(target_arch = "wasm32"))]

use confidex_app::{self as app, Command, DeviceKeys, Engine, Output, Request};
use confidex_storage::{Head, SqliteStore, Store, VaultId};
use confidex_vault::{
    envelope::{self, EventKind, Options},
    kdf, lock,
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
    secret_key_text, transfer_code,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Default)]
struct Keys {
    saved: BTreeMap<VaultId, String>,
    quick_unlock: BTreeMap<VaultId, (u64, Zeroizing<Vec<u8>>)>,
    now: Option<u64>,
    refuse_changes: bool,
}
impl DeviceKeys for Keys {
    async fn remove(&mut self, id: VaultId) -> bool {
        self.quick_unlock.remove(&id);
        if let Some(mut key) = self.saved.remove(&id) {
            zeroize::Zeroize::zeroize(&mut key);
        }
        true
    }

    async fn load(&mut self, id: VaultId) -> Option<String> {
        self.saved.get(&id).cloned()
    }
    async fn save(&mut self, id: VaultId, key: &str) -> bool {
        self.saved.insert(id, key.into());
        true
    }
    fn now_ms(&self) -> Option<u64> {
        self.now
    }
    async fn device_unlock_verified_at(&mut self, id: VaultId) -> Option<u64> {
        self.quick_unlock.get(&id).map(|(time, _)| *time)
    }
    async fn load_device_unlock(&mut self, id: VaultId) -> Option<Zeroizing<Vec<u8>>> {
        self.quick_unlock.get(&id).map(|(_, value)| value.clone())
    }
    async fn save_device_unlock(&mut self, id: VaultId, time: u64, value: &[u8]) -> bool {
        if self.refuse_changes {
            return false;
        }
        self.quick_unlock
            .insert(id, (time, Zeroizing::new(value.to_vec())));
        true
    }
    async fn disable_device_unlock(&mut self, id: VaultId, key: &str) -> bool {
        if self.refuse_changes {
            return false;
        }
        self.saved.insert(id, key.into());
        self.quick_unlock.remove(&id);
        true
    }
}
async fn run(
    engine: &mut Engine,
    store: &mut SqliteStore,
    keys: &mut Keys,
    command: Command,
) -> Result<Output, app::Error> {
    engine
        .execute(
            store,
            keys,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
}

#[test]
fn existing_vault_device_unlock_requires_password_again_at_expiry() {
    const PASSWORD: &str = "public-test-password";
    const VERIFIED_AT: u64 = 1_000_000;
    let expires = VERIFIED_AT + u64::from(app::device_unlock::DEFAULT_MINUTES) * 60_000;
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(std::path::Path::new(":memory:")).unwrap();
            let mut engine = Engine::default();
            let mut keys = Keys {
                now: Some(VERIFIED_AT),
                ..Keys::default()
            };
            let created = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Create {
                    name: "Fixture".into(),
                    password: PASSWORD.into(),
                    remember: true,
                },
            )
            .await
            .unwrap();
            let Output::Created(created) = created else {
                panic!("create output")
            };
            let vault = created.info.id;
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Select { vault },
            )
            .await
            .unwrap();
            let enrolled = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::EnrollDeviceUnlock {
                    vault,
                    password: PASSWORD.into(),
                    key: String::new(),
                    remember: true,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                enrolled,
                Output::Opened {
                    device_unlock_verified_at: Some(VERIFIED_AT),
                    ..
                }
            ));

            let unlock = |password: &str| Command::Unlock {
                vault,
                password: password.into(),
                key: String::new(),
                remember: true,
            };
            let mut engine = Engine::default();
            keys.now = Some(expires - 1);
            let opened = run(&mut engine, &mut store, &mut keys, unlock(""))
                .await
                .unwrap();
            assert!(matches!(
                opened,
                Output::Opened {
                    device_unlock_verified_at: Some(VERIFIED_AT),
                    ..
                }
            ));
            keys.now = Some(expires);
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, unlock("")).await,
                Err(app::Error::PasswordRequired)
            ));
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, unlock("wrong")).await,
                Err(app::Error::Auth)
            ));
            assert_eq!(
                keys.device_unlock_verified_at(vault).await,
                Some(VERIFIED_AT)
            );
            let renewed = run(&mut engine, &mut store, &mut keys, unlock(PASSWORD))
                .await
                .unwrap();
            assert!(matches!(
                renewed,
                Output::Opened { device_unlock_verified_at: Some(time), .. } if time == expires
            ));
            assert_eq!(keys.device_unlock_verified_at(vault).await, Some(expires));
            let before = store.snapshot(vault).await.unwrap();
            let other = [99; 16];
            keys.quick_unlock
                .insert(other, (VERIFIED_AT, Zeroizing::new(vec![42])));
            let setting = |enabled, password: &str| Command::SetDeviceUnlock {
                vault,
                enabled,
                password: password.into(),
            };
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::SetDeviceUnlock {
                        vault: other,
                        enabled: false,
                        password: String::new()
                    }
                )
                .await,
                Err(app::Error::Locked)
            ));
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, setting(false, "")).await,
                Ok(Output::DeviceUnlockChanged { verified_at: None })
            ));
            assert!(!keys.quick_unlock.contains_key(&vault));
            assert!(keys.quick_unlock.contains_key(&other));
            assert_eq!(keys.saved[&vault], created.key);
            keys.refuse_changes = true;
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, setting(true, PASSWORD)).await,
                Err(app::Error::Credentials)
            ));
            assert!(!keys.quick_unlock.contains_key(&vault));
            keys.refuse_changes = false;
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, setting(true, "wrong")).await,
                Err(app::Error::Auth)
            ));
            assert!(!keys.quick_unlock.contains_key(&vault));
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::List {
                        after: None,
                        tag: None
                    }
                )
                .await,
                Ok(Output::Rows { .. })
            ));
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, setting(true, PASSWORD)).await,
                Ok(Output::DeviceUnlockChanged { verified_at: Some(time) }) if time == expires
            ));
            keys.refuse_changes = true;
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, setting(false, "")).await,
                Err(app::Error::Credentials)
            ));
            assert!(keys.quick_unlock.contains_key(&vault));
            keys.refuse_changes = false;
            let after = store.snapshot(vault).await.unwrap();
            assert_eq!(before.heads, after.heads);
            assert_eq!(before.vault.lock, after.vault.lock);
            assert_eq!(before.objects.len(), after.objects.len());
            run(&mut engine, &mut store, &mut keys, Command::Lock)
                .await
                .unwrap();
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, setting(false, "")).await,
                Err(app::Error::Locked)
            ));
            assert!(matches!(
                run(&mut engine, &mut store, &mut keys, unlock("")).await,
                Ok(Output::Opened {
                    device_unlock_verified_at: Some(_),
                    ..
                })
            ));
        });
}

#[test]
fn encrypted_lifecycle_restarts_and_checks_historical_drafts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = SqliteStore::open(&path).unwrap();
            let mut keys = Keys::default();
            let mut engine = Engine::default();
            let created = run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Create {
                    name: "Fixture".into(),
                    password: "private-password-fixture".into(),
                    remember: true,
                },
            )
            .await
            .unwrap();
            let Output::Created(created) = created else {
                panic!("create output")
            };
            let id = created.info.id;
            let mut draft = app::new_record().unwrap();
            draft.title = "private-title-fixture".into();
            let mut field = app::field("password/v1").unwrap();
            field
                .values
                .insert("password".into(), "private-value-fixture".into());
            draft.fields.push(field);
            let mut note = app::field("note/v1").unwrap();
            note.values
                .insert("text".into(), "private-note-fixture".into());
            draft.fields.push(note);
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Save {
                    draft: draft.clone(),
                    epoch: 123,
                },
            )
            .await
            .unwrap();
            let record = draft.record;
            let vault = lock::open(
                &store.vault(id).await.unwrap().lock,
                b"private-password-fixture",
                &transfer_code::decode(&created.key).unwrap().secret,
                kdf::REQUIRED_MEMORY,
            )
            .unwrap();
            let legacy = secret_key_text::encode(&vault.keys().secret_key());
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Unlock {
                        vault: id,
                        password: "private-password-fixture".into(),
                        key: String::from_utf8(legacy.to_vec()).unwrap(),
                        remember: true,
                    }
                )
                .await,
                Err(app::Error::Key)
            ));
            let wrong_address = transfer_code::encode(&vault.keys().secret_key(), &[1; 32]);
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Unlock {
                        vault: id,
                        password: "private-password-fixture".into(),
                        key: String::from_utf8(wrong_address.to_vec()).unwrap(),
                        remember: true,
                    }
                )
                .await,
                Err(app::Error::Key)
            ));
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Unlock {
                    vault: id,
                    password: "private-password-fixture".into(),
                    key: created.key.clone(),
                    remember: true,
                },
            )
            .await
            .unwrap();
            let head = store.head(id, record).await.unwrap().unwrap();
            let mut raw = envelope::open(
                &store.object(id, head.revision).await.unwrap(),
                vault.keys(),
                vault.anchor(),
                Some(&head.revision),
                MAX_OPEN_MEMORY,
            )
            .unwrap()
            .record;
            raw.tags = vec!["fixture-tag".into()];
            raw.extra
                .insert("future.record".into(), Value::Binary(vec![1, 2, 3]));
            raw.entries[0]
                .extra
                .insert("future.entry".into(), Value::Binary(vec![4, 5]));
            raw.entries[0]
                .value
                .insert("binary".into(), Value::Binary(vec![6, 7]));
            raw.entries[0]
                .value
                .insert("oversized".into(), Value::from("x".repeat(65537)));
            raw.entries[1].extra.insert(
                "metadata".into(),
                Value::Map(vec![
                    (Value::from("future.policy"), Value::Binary(vec![8, 9])),
                    (Value::from("protected"), Value::Boolean(true)),
                ]),
            );
            let wire = envelope::seal(
                &raw,
                vault.keys(),
                Options {
                    vault_id: id,
                    record_id: record,
                    parents: &[head.revision],
                    epoch: 123,
                    kind: EventKind::Content,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .id();
            store
                .append(
                    id,
                    &Head { record, revision },
                    Some(head.revision),
                    &wire,
                    &raw.tags,
                )
                .await
                .unwrap();
            let Output::Draft(mut first) =
                run(&mut engine, &mut store, &mut keys, Command::Open { record })
                    .await
                    .unwrap()
            else {
                panic!("draft")
            };
            assert!(first.fields[1].protected);
            assert_eq!(first.fields[1].type_name, "secure-note/v1");
            let mut stale = first.clone();
            first.title = "changed".into();
            run(
                &mut engine,
                &mut store,
                &mut keys,
                Command::Save {
                    draft: first,
                    epoch: 124,
                },
            )
            .await
            .unwrap();
            stale.title = "stale".into();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::CheckDraft { draft: stale }
                )
                .await,
                Ok(Output::Checked { .. })
            ));
            run(&mut engine, &mut store, &mut keys, Command::Lock)
                .await
                .unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::List {
                        after: None,
                        tag: None
                    }
                )
                .await,
                Err(app::Error::Locked)
            ));
            assert!(matches!(
                run(
                    &mut engine,
                    &mut store,
                    &mut keys,
                    Command::Unlock {
                        vault: id,
                        password: "wrong".into(),
                        key: created.key.clone(),
                        remember: false
                    }
                )
                .await,
                Err(app::Error::Auth)
            ));
            drop(engine);
            drop(store);
            let mut reopened = SqliteStore::open(&path).unwrap();
            let mut engine = Engine::default();
            run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Unlock {
                    vault: id,
                    password: "private-password-fixture".into(),
                    key: String::new(),
                    remember: true,
                },
            )
            .await
            .unwrap();
            let Output::Draft(draft) = run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Open { record },
            )
            .await
            .unwrap() else {
                panic!("reopen")
            };
            assert_eq!(draft.title, "changed");
            assert_eq!(draft.fields[0].values["password"], "private-value-fixture");
            assert_eq!(draft.tags, ["fixture-tag"]);
            assert_eq!(draft.fields[0].opaque, 2);
            let current = envelope::open(
                &reopened.object(id, draft.revision.unwrap()).await.unwrap(),
                vault.keys(),
                vault.anchor(),
                draft.revision.as_ref(),
                MAX_OPEN_MEMORY,
            )
            .unwrap()
            .record;
            assert_eq!(current.extra["future.record"], Value::Binary(vec![1, 2, 3]));
            assert_eq!(
                current.entries[0].extra["future.entry"],
                Value::Binary(vec![4, 5])
            );
            assert_eq!(
                current.entries[0].value["binary"],
                Value::Binary(vec![6, 7])
            );
            assert_eq!(
                current.entries[0].value["oversized"]
                    .as_str()
                    .unwrap()
                    .len(),
                65537
            );
            assert!(draft.fields[1].protected);
            assert_eq!(
                current.entries[1].extra["metadata"],
                raw.entries[1].extra["metadata"]
            );
            let mut changed = draft.clone();
            changed.fields[1].protected = false;
            changed.fields[1].type_name = "note/v1".into();
            run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Save {
                    draft: changed,
                    epoch: 126,
                },
            )
            .await
            .unwrap();
            let Output::Draft(draft) = run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Open { record },
            )
            .await
            .unwrap() else {
                panic!("note policy")
            };
            assert!(!draft.fields[1].protected);
            assert_eq!(draft.fields[1].type_name, "note/v1");
            assert_eq!(draft.fields[1].values["text"], "private-note-fixture");
            let latest = envelope::open(
                &reopened.object(id, draft.revision.unwrap()).await.unwrap(),
                vault.keys(),
                vault.anchor(),
                draft.revision.as_ref(),
                MAX_OPEN_MEMORY,
            )
            .unwrap()
            .record;
            assert_eq!(
                latest.entries[1].extra["metadata"],
                Value::Map(vec![
                    (Value::from("future.policy"), Value::Binary(vec![8, 9])),
                    (Value::from("protected"), Value::Boolean(false)),
                ])
            );
            // Opening an old compound entry must not create a revision.
            let mixed = app::new_record().unwrap().record;
            let mut old = Record::default();
            old.entries = vec![
                Entry {
                    name: "Work".into(),
                    type_name: "login/v1".into(),
                    value: Mapping::from_iter([
                        ("username".into(), Value::from("alice")),
                        ("password".into(), Value::from("legacy-private-fixture")),
                        ("url".into(), Value::from("https://legacy.example.test")),
                        ("vendor".into(), Value::Binary(vec![9, 8])),
                    ]),
                    extra: Mapping::from_iter([("vendor".into(), Value::Binary(vec![7]))]),
                },
                Entry {
                    name: "API".into(),
                    type_name: "api_key/v1".into(),
                    value: Mapping::from_iter([(
                        "secret".into(),
                        Value::from("api-private-fixture"),
                    )]),
                    extra: Mapping::new(),
                },
            ];
            let original = envelope::seal(
                &old,
                vault.keys(),
                Options {
                    vault_id: id,
                    record_id: mixed,
                    parents: &[],
                    epoch: 126,
                    kind: EventKind::Content,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let old_revision = envelope::verify(&original, vault.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .id();
            reopened
                .append(
                    id,
                    &Head {
                        record: mixed,
                        revision: old_revision,
                    },
                    None,
                    &original,
                    &[],
                )
                .await
                .unwrap();
            let Output::Draft(mut independent) = run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Open { record: mixed },
            )
            .await
            .unwrap() else {
                panic!("legacy draft")
            };
            assert_eq!(independent.fields.len(), 5);
            assert_eq!(
                reopened.head(id, mixed).await.unwrap().unwrap().revision,
                old_revision
            );
            independent.fields[0].name = "Repeated name".into();
            independent.fields[1].name = "Repeated name".into();
            independent.fields.swap(0, 1);
            independent.fields.remove(2);
            independent.fields.push(app::field("text/v1").unwrap());
            run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Save {
                    draft: independent,
                    epoch: 127,
                },
            )
            .await
            .unwrap();
            let Output::Draft(saved) = run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Open { record: mixed },
            )
            .await
            .unwrap() else {
                panic!("independent draft")
            };
            assert_eq!(
                saved
                    .fields
                    .iter()
                    .map(|f| f.type_name.as_str())
                    .collect::<Vec<_>>(),
                [
                    "password/v1",
                    "username/v1",
                    "secret/v1",
                    "url/v1",
                    "text/v1"
                ]
            );
            assert!(saved.fields.iter().all(|f| f.source_key.is_none()));
            assert_eq!(saved.fields[0].name, saved.fields[1].name);
            assert_eq!(saved.fields[0].values["password"], "legacy-private-fixture");
            let saved_wire = reopened.object(id, saved.revision.unwrap()).await.unwrap();
            let saved_raw = envelope::open(
                &saved_wire,
                vault.keys(),
                vault.anchor(),
                saved.revision.as_ref(),
                MAX_OPEN_MEMORY,
            )
            .unwrap()
            .record;
            assert_eq!(
                saved_raw.entries[1].value["vendor"],
                Value::Binary(vec![9, 8])
            );
            assert_eq!(saved_raw.entries[1].extra["vendor"], Value::Binary(vec![7]));
            assert_eq!(
                saved_raw
                    .entries
                    .iter()
                    .filter(|e| e.value.contains_key("vendor"))
                    .count(),
                1
            );
            assert!(!saved_raw.entries.iter().any(|e| {
                e.value
                    .values()
                    .any(|v| v.as_str() == Some("https://legacy.example.test"))
            }));
            assert_eq!(
                reopened.object(id, old_revision).await.unwrap(),
                original.to_vec()
            );
            run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Delete {
                    record: mixed,
                    expected: saved.revision.unwrap(),
                    epoch: 128,
                },
            )
            .await
            .unwrap();
            let expected = draft.revision.unwrap();
            run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::Delete {
                    record,
                    expected,
                    epoch: 126,
                },
            )
            .await
            .unwrap();
            let Output::Rows { rows, .. } = run(
                &mut engine,
                &mut reopened,
                &mut keys,
                Command::List {
                    after: None,
                    tag: None,
                },
            )
            .await
            .unwrap() else {
                panic!("rows")
            };
            assert!(rows.is_empty());
            assert!(!reopened.object(id, expected).await.unwrap().is_empty());
            run(&mut engine, &mut reopened, &mut keys, Command::Lock)
                .await
                .unwrap();
            // A valid signed head is insufficient when its parent object is absent.
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "foreign_keys", false)
                .unwrap();
            connection
                .execute(
                    "DELETE FROM objects WHERE vault=?1 AND revision=?2",
                    rusqlite::params![id, expected],
                )
                .unwrap();
            assert!(matches!(
                run(
                    &mut engine,
                    &mut reopened,
                    &mut keys,
                    Command::Unlock {
                        vault: id,
                        password: "private-password-fixture".into(),
                        key: String::new(),
                        remember: false
                    }
                )
                .await,
                Err(app::Error::Integrity)
            ));
            assert!(matches!(
                run(
                    &mut engine,
                    &mut reopened,
                    &mut keys,
                    Command::List {
                        after: None,
                        tag: None
                    }
                )
                .await,
                Err(app::Error::Locked)
            ));
        });
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for text in [
            "private-password-fixture",
            "private-title-fixture",
            "private-value-fixture",
        ] {
            assert!(
                !bytes
                    .windows(text.len())
                    .any(|window| window == text.as_bytes())
            );
        }
    }
}

#[test]
fn saving_an_open_older_revision_keeps_both_parents_and_rejects_a_newer_head() {
    let dir = tempfile::tempdir().unwrap();
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        let mut store = SqliteStore::open(&dir.path().join("revisions.sqlite")).unwrap();
        let mut keys = Keys::default();
        let mut engine = Engine::default();
        let Output::Created(created) = run(&mut engine, &mut store, &mut keys, Command::Create {
            name: "Public fixture".into(), password: "Public password".into(), remember: true,
        }).await.unwrap() else { panic!("create") };
        let id = created.info.id;
        let vault = lock::open(&store.vault(id).await.unwrap().lock, b"Public password",
            &transfer_code::decode(&created.key).unwrap().secret, kdf::REQUIRED_MEMORY).unwrap();
        let mut original = app::new_record().unwrap();
        original.title = "Original".into();
        original.fields.push(app::field("password/v1").unwrap());
        let record = original.record;
        run(&mut engine, &mut store, &mut keys, Command::Save { draft: original, epoch: 1 }).await.unwrap();
        let Output::Draft(mut draft) = run(&mut engine, &mut store, &mut keys, Command::Open { record }).await.unwrap() else { panic!("open") };
        let base = draft.revision.unwrap();
        let base_wire = store.object(id, base).await.unwrap();
        let mut remote = draft.clone();
        remote.title = "Remote content".into();
        run(&mut engine, &mut store, &mut keys, Command::Save { draft: remote, epoch: 2 }).await.unwrap();
        draft.title = "My unsaved content".into();
        draft.fields[0].values.insert("password".into(), "Public unsaved value".into());
        for deleted in [false, true] {
            let before = store.head(id, record).await.unwrap().unwrap().revision;
            if deleted {
                run(&mut engine, &mut store, &mut keys, Command::Delete { record, expected: before, epoch: 4 }).await.unwrap();
            }
            let parent = store.head(id, record).await.unwrap().unwrap().revision;
            let parent_wire = store.object(id, parent).await.unwrap();
            assert!(matches!(run(&mut engine, &mut store, &mut keys, Command::RecordHead { record }).await.unwrap(),
                Output::RecordHead { revision: Some(revision), .. } if revision == parent));
            run(&mut engine, &mut store, &mut keys, Command::SaveRevision { draft: draft.clone(), parent, epoch: 6 }).await.unwrap();
            let head = store.head(id, record).await.unwrap().unwrap().revision;
            let wire = store.object(id, head).await.unwrap();
            let opened = envelope::open(&wire, vault.keys(), vault.anchor(), Some(&head), MAX_OPEN_MEMORY).unwrap();
            let parents = &opened.revision.header().parents;
            assert_eq!(parents.len(), 2);
            assert!(parents.contains(&parent) && parents.contains(&base));
            assert_eq!(store.object(id, parent).await.unwrap(), parent_wire);
            assert_eq!(store.object(id, base).await.unwrap(), base_wire);
            let Output::Draft(saved) = run(&mut engine, &mut store, &mut keys, Command::Open { record }).await.unwrap() else { panic!("saved") };
            assert_eq!(saved.title, "My unsaved content");
            assert_eq!(saved.fields[0].values["password"], "Public unsaved value");
            assert!(matches!(run(&mut engine, &mut store, &mut keys, Command::SaveRevision { draft: draft.clone(), parent, epoch: 7 }).await,
                Err(app::Error::Storage(confidex_storage::Error::Conflict))));
            assert_eq!(store.head(id, record).await.unwrap().unwrap().revision, head);
        }
        run(&mut engine, &mut store, &mut keys, Command::Lock).await.unwrap();
        run(&mut engine, &mut store, &mut keys, Command::Unlock {
            vault: id, password: "Public password".into(), key: String::new(), remember: true,
        }).await.unwrap();
        assert!(matches!(run(&mut engine, &mut store, &mut keys, Command::RecordHead { record: [0;16] }).await.unwrap(),
            Output::RecordHead { revision: None, .. }));
    });
}
