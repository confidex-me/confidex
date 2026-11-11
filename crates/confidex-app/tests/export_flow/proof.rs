//! Shared real-Store proof. All keys, values and files are public synthetic data.
use confidex_app::{
    self as app, Command, DeviceKeys, Engine, Output, Request, export, export_flow as flow,
};
use confidex_storage::{Head, Store, VaultId};
use confidex_vault::{
    envelope::{self, EventKind, Options},
    kdf, lock,
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
    transfer_code,
};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;
#[path = "storage_failure.rs"]
mod storage_failure;
#[cfg(not(target_arch = "wasm32"))]
pub use storage_failure::Stage as StorageFailureStage;
pub use storage_failure::run as storage_failure;
#[cfg(not(feature = "export-check"))]
#[path = "csv.rs"]
mod csv;
#[cfg(not(feature = "export-check"))]
pub use csv::run as csv_factory;
#[cfg(not(feature = "export-check"))]
#[path = "load.rs"]
mod load;
#[cfg(not(feature = "export-check"))]
pub use load::run as load;
#[cfg(all(not(feature = "export-check"), target_arch = "wasm32"))]
pub use load::seed as seed_load;
#[cfg(not(feature = "export-check"))]
#[path = "load_faults.rs"]
mod load_faults;
#[cfg(not(feature = "export-check"))]
pub use load_faults::run as load_faults;
#[cfg(not(feature = "export-check"))]
#[path = "reverse.rs"]
mod reverse;
#[cfg(not(feature = "export-check"))]
pub use reverse::run as reverse_exports;

const PASSWORD: &str = "public-export-contract-password";
pub struct Keys;
impl DeviceKeys for Keys {
    async fn remove(&mut self, _: VaultId) -> bool {
        true
    }
    async fn load(&mut self, _: VaultId) -> Option<String> {
        None
    }
    async fn save(&mut self, _: VaultId, _: &str) -> bool {
        false
    }
}
pub async fn command(store: &mut impl Store, engine: &mut Engine, command: Command) -> Output {
    engine
        .execute(
            store,
            &mut Keys,
            &mut Request {
                generation: 1,
                command,
            },
        )
        .await
        .result
        .unwrap()
}
pub struct Fixture {
    pub engine: Engine,
    pub created: app::Created,
    pub vault: lock::OpenedVault,
    pub head: Head,
}
pub fn content() -> Record {
    let password = |text: &str| Entry {
        name: "".into(),
        type_name: "password/v1".into(),
        value: Mapping::from([("password".into(), text.into())]),
        extra: Mapping::from([("protected".into(), true.into())]),
    };
    Record {
        entries: vec![
            password("old public password"),
            password("deleted public password"),
            Entry {
                name: "passport photo".into(),
                type_name: "file/v1".into(),
                value: Mapping::from([
                    ("filename".into(), "公開.dat".into()),
                    (
                        "data".into(),
                        Value::Binary((0..600_001).map(|i| (i % 251) as u8).collect()),
                    ),
                ]),
                extra: Mapping::new(),
            },
            Entry {
                name: "".into(),
                type_name: "future/v17".into(),
                value: Mapping::from([("unknown".into(), Value::Ext(42, vec![9, 7, 5]))]),
                extra: Mapping::from([("future-property".into(), Value::Nil)]),
            },
        ],
        tags: vec!["demo".into(), "旅行".into()],
        extra: Mapping::from([
            ("confidex.title".into(), "公開".repeat(100).into()),
            (
                "source-context".into(),
                "old public password; deleted public password".into(),
            ),
            ("unknown-property".into(), Value::Nil),
        ]),
    }
}
pub async fn append(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    record: [u8; 16],
    previous: Option<[u8; 32]>,
    content: &Record,
    epoch: u64,
) -> Head {
    let parents: Vec<_> = previous.into_iter().collect();
    let wire = envelope::seal(
        content,
        vault.keys(),
        Options {
            vault_id: vault.vault_id(),
            record_id: record,
            parents: &parents,
            epoch,
            kind: EventKind::Content,
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let revision = envelope::verify(&wire, vault.anchor(), None, MAX_OPEN_MEMORY)
        .unwrap()
        .id();
    let head = Head { record, revision };
    store
        .append(vault.vault_id(), &head, previous, &wire, &content.tags)
        .await
        .unwrap();
    head
}
pub async fn fixture(store: &mut impl Store) -> Fixture {
    let mut engine = Engine::default();
    let Output::Created(created) = command(
        store,
        &mut engine,
        Command::Create {
            name: "Public export proof".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await
    else {
        panic!("created");
    };
    let saved = store.vault(created.info.id).await.unwrap();
    let code = transfer_code::decode(&created.key).unwrap();
    let vault = lock::open(
        &saved.lock,
        PASSWORD.as_bytes(),
        &code.secret,
        kdf::REQUIRED_MEMORY,
    )
    .unwrap();
    let mut record = content();
    let old = append(store, &vault, [1; 16], None, &record, 1).await;
    record.entries.remove(1);
    record.entries[0]
        .value
        .insert("password".into(), "current public password\n第二行".into());
    let head = append(store, &vault, old.record, Some(old.revision), &record, 2).await;
    Fixture {
        engine,
        created,
        vault,
        head,
    }
}
pub async fn snapshot(store: &mut impl Store, vault: VaultId) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(&store.snapshot(vault).await.unwrap()).unwrap())
}
#[derive(Clone, Copy)]
pub enum Mode {
    Full,
    Text,
    Fail,
    Blocked,
}
pub struct Writer {
    pub mode: Mode,
    pub calls: Arc<AtomicUsize>,
}
impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::Csv
    }
    fn file(&self) -> export::File {
        export::File {
            name: "synthetic-contract.bin",
            media_type: "application/octet-stream",
            encrypted: false,
        }
    }
    fn review(
        &self,
        record: &Record,
        review: &mut export::Review<'_>,
    ) -> Result<(), export::Error> {
        for (index, entry) in record.entries.iter().enumerate() {
            if matches!(self.mode, Mode::Text | Mode::Blocked) {
                review.issue(
                    Some(index),
                    if matches!(self.mode, Mode::Blocked) {
                        export::Severity::Blocked
                    } else {
                        export::Severity::Loss
                    },
                    if entry.type_name == "password/v1" {
                        export::Code::Protection
                    } else {
                        export::Code::UnsupportedField
                    },
                )?;
            } else {
                review.preserved(index)?;
            }
        }
        if matches!(self.mode, Mode::Text | Mode::Blocked) {
            if !record.tags.is_empty() {
                review.issue(None, export::Severity::Loss, export::Code::Tags)?;
            }
            if !record.extra.is_empty() {
                review.issue(None, export::Severity::Loss, export::Code::SourceContext)?;
            }
        }
        review.tags();
        review.metadata();
        Ok(())
    }
    fn write(
        &self,
        records: &export::Records,
        output: &mut export::Output<'_>,
    ) -> Result<(), export::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        for (index, record) in records.iter().enumerate() {
            output.checkpoint(index, records.len())?;
            if matches!(self.mode, Mode::Fail) {
                output.write_all(b"partial public value")?;
                return Err(export::Error::Writer);
            }
            if matches!(self.mode, Mode::Text) {
                for entry in &record.entries {
                    if entry.type_name == "password/v1" {
                        output.write_all(entry.value["password"].as_str().unwrap().as_bytes())?;
                        output.write_all(b"\n")?;
                    }
                }
            } else {
                let _scratch = output.reserve(16 << 20)?;
                let content = record.encode_content(16 << 20).unwrap();
                output.write_all(&(content.bytes.len() as u32).to_le_bytes())?;
                output.write_all(&content.bytes)?;
            }
        }
        Ok(())
    }
}
pub fn writer(mode: Mode) -> (Box<dyn export::Writer>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Box::new(Writer {
            mode,
            calls: calls.clone(),
        }),
        calls,
    )
}
pub async fn prepare(store: &mut impl Store, fixture: &mut Fixture, mode: Mode) -> flow::Review {
    fixture
        .engine
        .prepare_export(
            store,
            &flow::Selection::All,
            writer(mode).0,
            export::Limits::default(),
            &mut |_| true,
        )
        .await
        .unwrap()
}
fn download(engine: &Engine, ready: &flow::Ready) -> Zeroizing<Vec<u8>> {
    let mut result = Zeroizing::new(Vec::new());
    let mut offset = 0;
    loop {
        let chunk = engine.export_chunk(ready.token, offset).unwrap();
        assert_eq!(chunk.offset, offset);
        assert!(chunk.bytes.len() <= flow::CHUNK_BYTES);
        let encoded = Zeroizing::new(serde_json::to_vec(&chunk).unwrap());
        let decoded: flow::Chunk = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(&*decoded.bytes, &*chunk.bytes);
        result.extend_from_slice(&chunk.bytes);
        if let Some(next) = chunk.next {
            assert_eq!(next, offset + chunk.bytes.len());
            offset = next;
        } else {
            break;
        }
    }
    assert_eq!(result.len(), ready.bytes);
    result
}
pub async fn current_records(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let id = fixture.created.info.id;
    let before = snapshot(store, id).await;
    let review = prepare(store, &mut fixture, Mode::Full).await;
    assert_eq!((review.records, review.losses, review.blocked), (1, 0, 0));
    let rows = fixture.engine.export_rows(review.token, 0).unwrap();
    assert_eq!(rows.items.len(), 1);
    assert_eq!(rows.items[0].head, fixture.head);
    assert_eq!(rows.items[0].fields, 3);
    assert_eq!(rows.items[0].title.chars().count(), 128);
    assert!(
        fixture
            .engine
            .export_issues(review.token, 0)
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(
        fixture.engine.export_rows(review.token, 2).err(),
        Some(flow::Error::InvalidSelection)
    );
    let ready = fixture
        .engine
        .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
            true
        })
        .await
        .unwrap();
    assert_ne!(ready.token, review.token);
    assert!(!ready.file.encrypted);
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    let bytes = download(&fixture.engine, &ready);
    let size = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(size + 4, bytes.len());
    let current = Record::decode_content(&bytes[4..], MAX_OPEN_MEMORY)
        .unwrap()
        .record;
    assert_eq!(current.entries.len(), 3);
    assert_eq!(
        current.entries[0].value["password"].as_str(),
        Some("current public password\n第二行")
    );
    assert_eq!(
        current.entries[2].value["unknown"],
        Value::Ext(42, vec![9, 7, 5])
    );
    let wire = store.object(id, fixture.head.revision).await.unwrap();
    let opened = envelope::open(
        &wire,
        fixture.vault.keys(),
        fixture.vault.anchor(),
        Some(&fixture.head.revision),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    assert_eq!(
        &*opened.record.encode_content(MAX_OPEN_MEMORY).unwrap().bytes,
        &bytes[4..]
    );
    assert_eq!(
        fixture
            .engine
            .export_chunk(ready.token, ready.bytes + 1)
            .err(),
        Some(flow::Error::InvalidSelection)
    );
    fixture.engine.finish_export(ready.token).unwrap();
    assert_eq!(
        fixture.engine.export_chunk(ready.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    assert_eq!(*snapshot(store, id).await, *before);
}
pub async fn consent_and_failures(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let id = fixture.created.info.id;
    let before = snapshot(store, id).await;
    let review = prepare(store, &mut fixture, Mode::Text).await;
    assert!(review.losses >= 5);
    let issues = fixture.engine.export_issues(review.token, 0).unwrap();
    assert_eq!(issues.items[0].field_name.as_deref(), Some(""));
    assert_eq!(
        fixture
            .engine
            .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
                true
            })
            .await
            .err(),
        Some(flow::Error::Export(export::Error::Losses))
    );
    assert!(fixture.engine.export_rows(review.token, 0).is_ok());
    let ready = fixture
        .engine
        .generate_export(
            store,
            review.token,
            export::Consent::AllowLosses,
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!(
        &*download(&fixture.engine, &ready),
        "current public password\n第二行\n".as_bytes()
    );
    fixture.engine.cancel_export(Some(ready.token)).unwrap();
    for (mode, expected) in [
        (Mode::Fail, export::Error::Writer),
        (Mode::Blocked, export::Error::Blocked),
    ] {
        let review = prepare(store, &mut fixture, mode).await;
        assert_eq!(
            fixture
                .engine
                .generate_export(
                    store,
                    review.token,
                    export::Consent::AllowLosses,
                    &mut |_| true
                )
                .await
                .err(),
            Some(flow::Error::Export(expected))
        );
        assert_eq!(
            fixture.engine.export_chunk(review.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
        fixture.engine.cancel_export(None).unwrap();
    }
    assert_eq!(*snapshot(store, id).await, *before);
}
pub async fn invalidation(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let id = fixture.created.info.id;
    let before = snapshot(store, id).await;
    let review = prepare(store, &mut fixture, Mode::Full).await;
    let mut wrong = review.token;
    wrong[0] ^= 1;
    assert_eq!(
        fixture.engine.cancel_export(Some(wrong)),
        Err(flow::Error::InvalidSession)
    );
    assert!(fixture.engine.export_rows(review.token, 0).is_ok());
    command(store, &mut fixture.engine, Command::Lock).await;
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    command(
        store,
        &mut fixture.engine,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: fixture.created.key.clone(),
            remember: false,
        },
    )
    .await;
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    let review = prepare(store, &mut fixture, Mode::Full).await;
    let ready = fixture
        .engine
        .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
            true
        })
        .await
        .unwrap();
    fixture.engine.begin_import().unwrap();
    assert_eq!(
        fixture.engine.export_chunk(ready.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    let review = prepare(store, &mut fixture, Mode::Full).await;
    let ready = fixture
        .engine
        .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
            true
        })
        .await
        .unwrap();
    command(store, &mut fixture.engine, Command::Lock).await;
    assert_eq!(
        fixture.engine.export_chunk(ready.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    command(
        store,
        &mut fixture.engine,
        Command::Unlock {
            vault: id,
            password: PASSWORD.into(),
            key: fixture.created.key.clone(),
            remember: false,
        },
    )
    .await;
    let review = prepare(store, &mut fixture, Mode::Full).await;
    assert_eq!(
        fixture
            .engine
            .prepare_export(
                store,
                &flow::Selection::Records(vec![fixture.head.clone(), fixture.head.clone()]),
                writer(Mode::Full).0,
                export::Limits::default(),
                &mut |_| true
            )
            .await
            .err(),
        Some(flow::Error::InvalidSelection)
    );
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    let review = prepare(store, &mut fixture, Mode::Full).await;
    let _other = command(
        store,
        &mut fixture.engine,
        Command::Create {
            name: "Other public vault".into(),
            password: PASSWORD.into(),
            remember: false,
        },
    )
    .await;
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    assert_eq!(*snapshot(store, id).await, *before);
}
pub async fn changed_heads(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let review = prepare(store, &mut fixture, Mode::Full).await;
    let mut changed = content();
    changed.entries[0]
        .value
        .insert("password".into(), "later public password".into());
    fixture.head = append(
        store,
        &fixture.vault,
        fixture.head.record,
        Some(fixture.head.revision),
        &changed,
        3,
    )
    .await;
    let after_change = snapshot(store, fixture.created.info.id).await;
    assert_eq!(
        fixture
            .engine
            .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
                true
            })
            .await
            .err(),
        Some(flow::Error::Changed)
    );
    assert_eq!(
        *snapshot(store, fixture.created.info.id).await,
        *after_change
    );
    let review = prepare(store, &mut fixture, Mode::Full).await;
    append(store, &fixture.vault, [2; 16], None, &content(), 4).await;
    assert_eq!(
        fixture
            .engine
            .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
                true
            })
            .await
            .err(),
        Some(flow::Error::Changed)
    );
    let review = fixture
        .engine
        .prepare_export(
            store,
            &flow::Selection::Records(vec![fixture.head.clone()]),
            writer(Mode::Full).0,
            export::Limits::default(),
            &mut |_| true,
        )
        .await
        .unwrap();
    append(store, &fixture.vault, [3; 16], None, &content(), 5).await;
    let ready = fixture
        .engine
        .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
            true
        })
        .await
        .unwrap();
    assert!(!download(&fixture.engine, &ready).is_empty());
    fixture.engine.finish_export(ready.token).unwrap();
}
pub async fn cancellation(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let before = snapshot(store, fixture.created.info.id).await;
    for phase in [
        export::Phase::Read,
        export::Phase::Check,
        export::Phase::Review,
    ] {
        let previous = prepare(store, &mut fixture, Mode::Full).await;
        assert_eq!(
            fixture
                .engine
                .prepare_export(
                    store,
                    &flow::Selection::All,
                    writer(Mode::Full).0,
                    export::Limits::default(),
                    &mut |progress: export::Progress| progress.phase != phase
                )
                .await
                .err(),
            Some(flow::Error::Export(export::Error::Canceled))
        );
        assert_eq!(
            fixture.engine.export_rows(previous.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
    }
    let review = prepare(store, &mut fixture, Mode::Full).await;
    assert_eq!(
        fixture
            .engine
            .generate_export(
                store,
                review.token,
                export::Consent::Lossless,
                &mut |progress: export::Progress| progress.phase != export::Phase::Write
            )
            .await
            .err(),
        Some(flow::Error::Export(export::Error::Canceled))
    );
    struct Late;
    impl flow::Control for Late {
        async fn checkpoint(&mut self, progress: export::Progress) -> bool {
            progress.phase != export::Phase::Write
        }
        fn computing(&mut self, _: export::Progress) -> bool {
            true
        }
    }
    let (writer, calls) = writer(Mode::Full);
    let review = fixture
        .engine
        .prepare_export(
            store,
            &flow::Selection::All,
            writer,
            export::Limits::default(),
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .engine
            .generate_export(store, review.token, export::Consent::Lossless, &mut Late)
            .await
            .err(),
        Some(flow::Error::Export(export::Error::Canceled))
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture.engine.export_chunk(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
}

pub async fn tombstones(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let second = append(store, &fixture.vault, [2; 16], None, &content(), 3).await;
    let pending = prepare(store, &mut fixture, Mode::Full).await;
    let ready = fixture
        .engine
        .generate_export(store, pending.token, export::Consent::Lossless, &mut |_| {
            true
        })
        .await
        .unwrap();
    command(
        store,
        &mut fixture.engine,
        Command::Delete {
            record: second.record,
            expected: second.revision,
            epoch: 4,
        },
    )
    .await;
    assert_eq!(
        fixture.engine.export_chunk(ready.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    let deleted = store
        .head(fixture.created.info.id, second.record)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture
            .engine
            .export_fields(store, &deleted, 0, &mut |_| true)
            .await
            .err(),
        Some(flow::Error::InvalidSelection)
    );
    let page = fixture
        .engine
        .export_selection(store, None, &mut |_| true)
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].head, fixture.head);
    let before = snapshot(store, fixture.created.info.id).await;
    let review = prepare(store, &mut fixture, Mode::Full).await;
    assert_eq!(review.records, 1);
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).unwrap().items[0].head,
        fixture.head
    );
    assert_eq!(
        fixture
            .engine
            .prepare_export(
                store,
                &flow::Selection::Records(vec![deleted]),
                writer(Mode::Full).0,
                export::Limits::default(),
                &mut |_| true
            )
            .await
            .err(),
        Some(flow::Error::InvalidSelection)
    );
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
}

async fn call(
    store: &mut impl Store,
    engine: &mut Engine,
    command: flow::Command,
) -> Result<flow::Reply, flow::Error> {
    let request = Request {
        generation: 91,
        command: Command::VendorExport(command),
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&request).unwrap());
    let mut request: Request = serde_json::from_slice(&bytes).unwrap();
    let response = engine.execute(store, &mut Keys, &mut request).await;
    assert_eq!(response.generation, 91);
    let bytes = Zeroizing::new(serde_json::to_vec(&response).unwrap());
    let decoded: app::Response = serde_json::from_slice(&bytes).unwrap();
    let Output::VendorExport(reply) = decoded.result.unwrap() else {
        panic!("export reply");
    };
    reply
}

pub fn field_source_record() -> Record {
    let mut record = content();
    record.entries.remove(1);
    for n in 0..70 {
        record.entries.push(Entry {
            name: if n % 2 == 0 {
                "Repeated".into()
            } else {
                String::new()
            },
            type_name: "text/v1".into(),
            value: Mapping::from([("text".into(), format!("PUBLIC-UNSENT-{n}").into())]),
            extra: Mapping::new(),
        });
    }
    record.entries.push(Entry {
        name: "公開".repeat(200),
        type_name: "card/v1".into(),
        value: Mapping::from([
            ("holder".into(), "PUBLIC-UNSENT-HOLDER".into()),
            ("number".into(), "4111111111111111".into()),
        ]),
        extra: Mapping::new(),
    });
    record.entries.push(Entry {
        name: "公".repeat(2000),
        type_name: "text/v1".into(),
        value: Mapping::from([("text".into(), "PUBLIC-UNSENT-LONG-NAME".into())]),
        extra: Mapping::new(),
    });
    for _ in 0..3 {
        record.entries.push(Entry {
            name: String::new(),
            type_name: "text/v1".into(),
            value: Mapping::from([("text".into(), "PUBLIC-UNSENT-PAD".into())]),
            extra: Mapping::new(),
        });
    }
    for _ in 0..16 {
        record.entries.push(Entry {
            name: "\0".repeat(4096),
            type_name: "x".repeat(64),
            value: Mapping::from([("\0".repeat(1024), "PUBLIC-UNSENT-WORST".into())]),
            extra: Mapping::new(),
        });
    }
    for (type_name, key) in [
        ("x".repeat(65), "text".into()),
        ("text/v1".into(), String::new()),
    ] {
        record.entries.push(Entry {
            name: "Unsupported binding size".into(),
            type_name,
            value: Mapping::from([(key, "PUBLIC-UNSENT-EXCLUDED".into())]),
            extra: Mapping::new(),
        });
    }
    record
}

pub async fn field_sources(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let id = fixture.created.info.id;
    let initial = fixture.head.clone();
    let before = snapshot(store, id).await;
    let flow::Reply::Fields {
        operation,
        vault,
        head,
        start,
        fields,
    } = call(
        store,
        &mut fixture.engine,
        flow::Command::Fields {
            operation: 501,
            head: initial.clone(),
            start: 0,
        },
    )
    .await
    .unwrap()
    else {
        panic!("field sources");
    };
    assert_eq!(
        (operation, vault, head, start),
        (501, id, initial.clone(), 0)
    );
    assert_eq!(fields.next, None);
    let actual: Vec<_> = fields
        .items
        .iter()
        .map(|field| {
            (
                field.index,
                field.name.as_str(),
                field.type_name.as_str(),
                field.key.as_str(),
            )
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            (0, "", "password/v1", "password"),
            (1, "passport photo", "file/v1", "data"),
            (1, "passport photo", "file/v1", "filename"),
            (2, "", "future/v17", "unknown")
        ]
    );
    let encoded = Zeroizing::new(serde_json::to_string(&fields).unwrap());
    for value in [
        "current public password",
        "old public password",
        "deleted public password",
        "公開.dat",
    ] {
        assert!(!encoded.contains(value));
    }
    assert_eq!(*snapshot(store, id).await, *before);
    let record = field_source_record();
    let current = append(
        store,
        &fixture.vault,
        initial.record,
        Some(initial.revision),
        &record,
        3,
    )
    .await;
    fixture.head = current.clone();
    let before = snapshot(store, id).await;
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Fields {
                operation: 502,
                head: initial,
                start: 0
            }
        )
        .await
        .err(),
        Some(flow::Error::Changed)
    );
    let mut start = 0;
    let mut total = 0;
    let mut largest_reply = 0;
    loop {
        let flow::Reply::Fields { fields, .. } = call(
            store,
            &mut fixture.engine,
            flow::Command::Fields {
                operation: 503,
                head: current.clone(),
                start,
            },
        )
        .await
        .unwrap() else {
            panic!("page");
        };
        assert!(fields.items.len() <= flow::SOURCE_PAGE_SIZE);
        for field in &fields.items {
            let entry = &record.entries[field.index];
            assert_eq!(
                field.name,
                if entry.name.len() > 4096 {
                    "公".repeat(1365)
                } else {
                    entry.name.clone()
                }
            );
            assert_eq!(field.type_name, entry.type_name);
            assert!(entry.value.contains_key(&field.key));
            let config = export::Csv {
                profile: None,
                delimiter: b',',
                header: true,
                columns: vec![export::Column {
                    heading: field.name.clone(),
                    source: export::Source::Field {
                        index: field.index,
                        type_name: field.type_name.clone(),
                        key: field.key.clone(),
                    },
                }],
            };
            config.validate().unwrap();
        }
        let encoded = Zeroizing::new(serde_json::to_string(&fields).unwrap());
        assert!(encoded.len() <= 1 << 20);
        largest_reply = largest_reply.max(encoded.len());
        assert!(!encoded.contains("PUBLIC-UNSENT") && !encoded.contains("4111111111111111"));
        total += fields.items.len();
        match fields.next {
            Some(next) => {
                assert_eq!(next, total);
                start = next;
            }
            None => break,
        }
    }
    assert_eq!(total, 96);
    assert!(largest_reply >= 450_000);
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Fields {
                operation: 504,
                head: current.clone(),
                start: usize::MAX
            }
        )
        .await
        .err(),
        Some(flow::Error::InvalidSelection)
    );
    assert_eq!(
        fixture
            .engine
            .export_fields(store, &current, 0, &mut |_| false)
            .await
            .err(),
        Some(flow::Error::Export(export::Error::Canceled))
    );
    let review = prepare(store, &mut fixture, Mode::Full).await;
    call(
        store,
        &mut fixture.engine,
        flow::Command::Fields {
            operation: 0,
            head: current.clone(),
            start: 0,
        },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        fixture.engine.export_rows(review.token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    command(store, &mut fixture.engine, Command::Lock).await;
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Fields {
                operation: 505,
                head: current,
                start: 0
            }
        )
        .await
        .err(),
        Some(flow::Error::App(app::Error::Locked))
    );
    assert_eq!(*snapshot(store, id).await, *before);
}

#[cfg(not(feature = "export-check"))]
pub async fn bitwarden_profiles(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let before = snapshot(store, fixture.created.info.id).await;
    let Output::VendorExport(Ok(flow::Reply::Begun { formats, .. })) = command(
        store,
        &mut fixture.engine,
        Command::VendorExport(flow::Command::Begin),
    )
    .await
    else {
        panic!("catalog");
    };
    assert!(
        formats
            .iter()
            .any(|item| item.format == export::Format::BitwardenJson)
    );
    let mut old = None;
    for organization in [false, true] {
        let Output::VendorExport(Ok(flow::Reply::Reviewed { review, .. })) = command(
            store,
            &mut fixture.engine,
            Command::VendorExport(flow::Command::Prepare {
                operation: 201 + u32::from(organization),
                created_at: 1_735_689_600,
                format: export::Format::BitwardenJson,
                options: export::Options::Bitwarden {
                    organization,
                    password: None,
                },
                selection: flow::Selection::All,
            }),
        )
        .await
        else {
            panic!("review");
        };
        assert_eq!(review.records, 1);
        assert!(!review.file.encrypted);
        assert!(review.losses > 0);
        assert_eq!(review.blocked, 0);
        if let Some(old) = old {
            assert!(fixture.engine.export_chunk(old, 0).is_err());
        }
        let issues = fixture.engine.export_issues(review.token, 0).unwrap();
        assert!(
            issues
                .items
                .iter()
                .any(|row| row.issue.code == export::Code::Attachments)
        );
        assert_eq!(
            issues
                .items
                .iter()
                .any(|row| row.issue.code == export::Code::Tags),
            !organization
        );
        let Output::VendorExport(Ok(flow::Reply::Ready { ready, .. })) = command(
            store,
            &mut fixture.engine,
            Command::VendorExport(flow::Command::Generate {
                operation: 203 + u32::from(organization),
                token: review.token,
                consent: export::Consent::AllowLosses,
            }),
        )
        .await
        else {
            panic!("ready");
        };
        let mut bytes = Zeroizing::new(Vec::new());
        let mut offset = 0;
        loop {
            let Output::VendorExport(Ok(flow::Reply::Chunk { chunk, .. })) = command(
                store,
                &mut fixture.engine,
                Command::VendorExport(flow::Command::Chunk {
                    token: ready.token,
                    offset,
                }),
            )
            .await
            else {
                panic!("chunk");
            };
            bytes.extend_from_slice(&chunk.bytes);
            match chunk.next {
                Some(next) => offset = next,
                None => break,
            }
        }
        assert_eq!(bytes.len(), ready.bytes);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            json["items"][0]["login"]["password"],
            "current public password\n第二行"
        );
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains("deleted public password")
        );
        assert_eq!(
            json[if organization {
                "collections"
            } else {
                "folders"
            }]
            .as_array()
            .unwrap()
            .len(),
            if organization { 2 } else { 1 }
        );
        old = Some(ready.token);
    }
    assert!(matches!(
        command(store, &mut fixture.engine, Command::Lock).await,
        Output::Locked
    ));
    assert!(fixture.engine.export_chunk(old.unwrap(), 0).is_err());
    assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
}

#[cfg(not(feature = "export-check"))]
pub async fn plain_formats(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let id = fixture.created.info.id;
    let before = snapshot(store, id).await;
    for format in [
        export::Format::BitwardenZip,
        export::Format::KeepassXml,
        export::Format::Onepassword1pux,
    ] {
        let flow::Reply::Reviewed { review, .. } = call(
            store,
            &mut fixture.engine,
            flow::Command::Prepare {
                operation: 401,
                created_at: 1_735_689_600,
                format,
                options: export::Options::Plain,
                selection: flow::Selection::All,
            },
        )
        .await
        .unwrap() else {
            panic!("plain format review");
        };
        assert_eq!(review.format, format);
        assert!(!review.file.encrypted && review.losses > 0 && review.blocked == 0);
        assert_eq!(
            call(
                store,
                &mut fixture.engine,
                flow::Command::Generate {
                    operation: 402,
                    token: review.token,
                    consent: export::Consent::Lossless,
                }
            )
            .await
            .err(),
            Some(flow::Error::Export(export::Error::Losses))
        );
        let flow::Reply::Ready { ready, .. } = call(
            store,
            &mut fixture.engine,
            flow::Command::Generate {
                operation: 403,
                token: review.token,
                consent: export::Consent::AllowLosses,
            },
        )
        .await
        .unwrap() else {
            panic!("plain format ready");
        };
        let bytes = download(&fixture.engine, &ready);
        let parsed = app::import::prepare(
            format,
            &bytes,
            &app::import::Options::default(),
            app::import::Limits::default(),
            &mut |_| true,
            match format {
                export::Format::BitwardenZip => app::import::formats::bitwarden_zip::parse,
                export::Format::KeepassXml => app::import::formats::keepass_xml::parse,
                export::Format::Onepassword1pux => app::import::formats::onepassword_1pux::parse,
                _ => unreachable!(),
            },
        )
        .unwrap();
        assert_eq!(parsed.items.len(), 1);
        let record = parsed.items[0].record(MAX_OPEN_MEMORY).unwrap();
        let password = record
            .entries
            .iter()
            .find(|entry| entry.type_name == "password/v1")
            .unwrap();
        assert_eq!(
            password.value["password"].as_str(),
            Some("current public password\n第二行")
        );
        let file = record
            .entries
            .iter()
            .find(|entry| entry.type_name == "file/v1")
            .unwrap();
        assert_eq!(file.value["filename"].as_str(), Some("公開.dat"));
        let data = file.value["data"].as_slice().unwrap();
        assert_eq!(data.len(), 600_001);
        assert!(
            data.iter()
                .enumerate()
                .all(|(i, &byte)| byte == (i % 251) as u8)
        );
        call(
            store,
            &mut fixture.engine,
            flow::Command::Finish { token: ready.token },
        )
        .await
        .unwrap();
        assert_eq!(
            fixture.engine.export_chunk(ready.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
        assert_eq!(*snapshot(store, id).await, *before);
    }
}

#[cfg(feature = "export-check")]
pub async fn protocol(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let before = snapshot(store, fixture.created.info.id).await;
    let flow::Reply::Begun { vault, formats } =
        call(store, &mut fixture.engine, flow::Command::Begin)
            .await
            .unwrap()
    else {
        panic!("catalog");
    };
    assert_eq!(vault, fixture.created.info.id);
    assert_eq!(formats.len(), 3);
    let flow::Reply::Listed {
        vault, after, page, ..
    } = call(
        store,
        &mut fixture.engine,
        flow::Command::List {
            operation: 90,
            after: None,
        },
    )
    .await
    .unwrap()
    else {
        panic!("selection rows");
    };
    assert_eq!(vault, fixture.created.info.id);
    assert_eq!(after, None);
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].head, fixture.head);
    assert_eq!(page.rows[0].fields, 3);
    assert_eq!(page.rows[0].title.chars().count(), 128);
    assert!(!page.more);
    assert_eq!(page.next, Some(fixture.head.clone()));
    let bytes = Zeroizing::new(serde_json::to_string(&page).unwrap());
    assert!(!bytes.contains("current public password"));
    let flow::Reply::Listed { page, .. } = call(
        store,
        &mut fixture.engine,
        flow::Command::List {
            operation: 89,
            after: Some(fixture.head.clone()),
        },
    )
    .await
    .unwrap() else {
        panic!("selection end");
    };
    assert!(page.rows.is_empty());
    assert!(!page.more);
    assert_eq!(page.next, None);

    let flow::Reply::Reviewed { review, .. } = call(
        store,
        &mut fixture.engine,
        flow::Command::Prepare {
            created_at: 1_735_689_600,
            operation: 1,
            format: export::Format::KeepassXml,
            options: export::Options::Plain,
            selection: flow::Selection::All,
        },
    )
    .await
    .unwrap() else {
        panic!("review");
    };
    let flow::Reply::Rows { rows, .. } = call(
        store,
        &mut fixture.engine,
        flow::Command::Rows {
            token: review.token,
            start: 0,
        },
    )
    .await
    .unwrap() else {
        panic!("rows");
    };
    assert_eq!(rows.items[0].fields, 3);
    assert!(matches!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Issues {
                token: review.token,
                start: 0
            }
        )
        .await
        .unwrap(),
        flow::Reply::Issues { .. }
    ));
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Prepare {
                created_at: 1_735_689_600,
                operation: 2,
                format: export::Format::Csv,
                options: export::Options::Plain,
                selection: flow::Selection::All
            }
        )
        .await
        .err(),
        Some(flow::Error::Export(export::Error::UnsupportedFormat))
    );
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Rows {
                token: review.token,
                start: 0
            }
        )
        .await
        .err(),
        Some(flow::Error::InvalidSession)
    );
    for (index, (password, keyfile)) in [
        (Some("public export password"), None),
        (None, Some(vec![9])),
        (Some("public export password"), Some(vec![9])),
        (Some(""), None),
        (Some(""), Some(vec![])),
    ]
    .into_iter()
    .enumerate()
    {
        let flow::Reply::Reviewed { review, .. } = call(
            store,
            &mut fixture.engine,
            flow::Command::Prepare {
                created_at: 1_735_689_600,
                operation: 10 + index as u32,
                format: export::Format::Kdbx,
                options: export::Options::Password {
                    password: password.map(str::to_owned),
                    keyfile,
                },
                selection: flow::Selection::All,
            },
        )
        .await
        .unwrap() else {
            panic!("credentials");
        };
        let flow::Reply::Ready { ready, .. } = call(
            store,
            &mut fixture.engine,
            flow::Command::Generate {
                operation: 20 + index as u32,
                token: review.token,
                consent: export::Consent::Lossless,
            },
        )
        .await
        .unwrap() else {
            panic!("ready");
        };
        assert_eq!(
            call(
                store,
                &mut fixture.engine,
                flow::Command::Rows {
                    token: review.token,
                    start: 0
                }
            )
            .await
            .err(),
            Some(flow::Error::InvalidSession)
        );
        let mut bytes = Zeroizing::new(Vec::new());
        let mut offset = 0;
        loop {
            let flow::Reply::Chunk { chunk, .. } = call(
                store,
                &mut fixture.engine,
                flow::Command::Chunk {
                    token: ready.token,
                    offset,
                },
            )
            .await
            .unwrap() else {
                panic!("chunk");
            };
            bytes.extend_from_slice(&chunk.bytes);
            if let Some(next) = chunk.next {
                offset = next;
            } else {
                break;
            }
        }
        assert_eq!(bytes.len(), ready.bytes);
        assert_eq!(
            Record::decode_content(&bytes[4..], MAX_OPEN_MEMORY)
                .unwrap()
                .record
                .entries
                .len(),
            3
        );
        assert!(matches!(
            call(
                store,
                &mut fixture.engine,
                flow::Command::Finish { token: ready.token }
            )
            .await
            .unwrap(),
            flow::Reply::Finished
        ));
        assert_eq!(
            call(
                store,
                &mut fixture.engine,
                flow::Command::Chunk {
                    token: ready.token,
                    offset: 0
                }
            )
            .await
            .err(),
            Some(flow::Error::InvalidSession)
        );
    }
    let flow::Reply::Reviewed { review, .. } = call(
        store,
        &mut fixture.engine,
        flow::Command::Prepare {
            created_at: 1_735_689_600,
            operation: 41,
            format: export::Format::BitwardenJson,
            options: export::Options::Plain,
            selection: flow::Selection::All,
        },
    )
    .await
    .unwrap() else {
        panic!("blocked review");
    };
    assert!(review.blocked > 0);
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Generate {
                operation: 42,
                token: review.token,
                consent: export::Consent::AllowLosses
            }
        )
        .await
        .err(),
        Some(flow::Error::Export(export::Error::Blocked))
    );
    assert!(matches!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Cancel {
                token: Some(review.token)
            }
        )
        .await
        .unwrap(),
        flow::Reply::Canceled
    ));
    assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
}

#[cfg(not(feature = "export-check"))]
pub async fn kdbx_registry(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let before = snapshot(store, fixture.created.info.id).await;
    let flow::Reply::Begun { formats, .. } = call(store, &mut fixture.engine, flow::Command::Begin)
        .await
        .unwrap()
    else {
        panic!("catalog")
    };
    assert!(
        formats
            .iter()
            .any(|item| item.format == export::Format::Kdbx)
    );
    let key = [7; 32];
    let mut previous = None;
    for (password, keyfile) in [
        (Some("PUBLIC-EXPORT"), None),
        (None, Some(key.as_slice())),
        (Some("PUBLIC-EXPORT"), Some(key.as_slice())),
        (Some(""), None),
        (Some(""), Some(key.as_slice())),
    ] {
        let flow::Reply::Reviewed { review, .. } = call(
            store,
            &mut fixture.engine,
            flow::Command::Prepare {
                operation: 1,
                created_at: 1_735_689_600,
                format: export::Format::Kdbx,
                options: export::Options::Password {
                    password: password.map(str::to_owned),
                    keyfile: keyfile.map(<[u8]>::to_vec),
                },
                selection: flow::Selection::All,
            },
        )
        .await
        .unwrap() else {
            panic!("review")
        };
        if let Some(token) = previous {
            assert_eq!(
                fixture.engine.export_chunk(token, 0).err(),
                Some(flow::Error::InvalidSession)
            );
        }
        assert_eq!(review.records, 1);
        assert!(review.file.encrypted && review.losses > 0 && review.blocked == 0);
        assert_eq!(
            call(
                store,
                &mut fixture.engine,
                flow::Command::Generate {
                    operation: 2,
                    token: review.token,
                    consent: export::Consent::Lossless
                }
            )
            .await
            .err(),
            Some(flow::Error::Export(export::Error::Losses))
        );
        let flow::Reply::Ready { ready, .. } = call(
            store,
            &mut fixture.engine,
            flow::Command::Generate {
                operation: 3,
                token: review.token,
                consent: export::Consent::AllowLosses,
            },
        )
        .await
        .unwrap() else {
            panic!("file")
        };
        assert_eq!(ready.file.name, "confidex.kdbx");
        let bytes = download(&fixture.engine, &ready);
        let options = app::import::Options {
            password: password.unwrap_or_default().into(),
            keyfile: keyfile.unwrap_or_default().to_vec(),
            password_present: password.is_some(),
            keyfile_present: keyfile.is_some(),
            source_instance: None,
            include_archived: false,
            include_deleted: false,
            csv: None,
        };
        let parsed = app::import::prepare(
            export::Format::Kdbx,
            &bytes,
            &options,
            app::import::Limits::default(),
            &mut |_| true,
            app::import::formats::kdbx::parse,
        )
        .unwrap();
        // 2025-01-01 00:00 UTC, supplied by the host.
        let attributes = parsed.items[0].source_attributes(MAX_OPEN_MEMORY).unwrap();
        assert!(
            attributes["times"]
                .as_str()
                .unwrap()
                .contains("<CreationTime>gHwG3w4AAAA=</CreationTime>")
        );
        let record = parsed.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(record.entries.len(), 2);
        assert_eq!(
            record.entries[0].value["password"].as_str(),
            Some("current public password\n第二行")
        );
        assert_eq!(
            record.entries[1].value["data"].as_slice().unwrap().len(),
            600_001
        );
        previous = Some(ready.token);
    }
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Prepare {
                operation: 4,
                created_at: u64::MAX,
                format: export::Format::Kdbx,
                options: export::Options::Password {
                    password: Some("public".into()),
                    keyfile: None
                },
                selection: flow::Selection::All
            }
        )
        .await
        .err(),
        Some(flow::Error::Export(export::Error::InvalidOptions))
    );
    assert_eq!(
        fixture.engine.export_chunk(previous.unwrap(), 0).err(),
        Some(flow::Error::InvalidSession)
    );
    command(store, &mut fixture.engine, Command::Lock).await;
    assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
}

/// Exercise profile credentials, current records, and Store cleanup.
pub async fn encrypted_records(store: &mut impl Store) {
    use app::import::formats::{bitwarden_encrypted_json, bitwarden_json::Profile};
    const EXPORT_PASSWORD: &str = "PUBLIC-ENCRYPTED-STORE";
    async fn preview(
        store: &mut impl Store,
        fixture: &mut Fixture,
        profile: Profile,
    ) -> flow::Review {
        #[cfg(not(feature = "export-check"))]
        {
            let flow::Reply::Reviewed { review, .. } = call(
                store,
                &mut fixture.engine,
                flow::Command::Prepare {
                    operation: 301,
                    created_at: 1_735_689_600,
                    format: export::Format::BitwardenEncryptedJson,
                    options: export::Options::Bitwarden {
                        organization: matches!(profile, Profile::Organization),
                        password: Some(EXPORT_PASSWORD.into()),
                    },
                    selection: flow::Selection::All,
                },
            )
            .await
            .unwrap() else {
                panic!("encrypted review");
            };
            review
        }
        #[cfg(feature = "export-check")]
        fixture
            .engine
            .prepare_export(
                store,
                &flow::Selection::All,
                Box::new(
                    bitwarden_encrypted_json::Writer::new(
                        profile,
                        export::Options::Password {
                            password: Some(EXPORT_PASSWORD.into()),
                            keyfile: None,
                        },
                    )
                    .unwrap(),
                ),
                export::Limits::default(),
                &mut |_| true,
            )
            .await
            .unwrap()
    }
    for profile in [Profile::Personal, Profile::Organization] {
        let mut fixture = fixture(store).await;
        let id = fixture.created.info.id;
        let before = snapshot(store, id).await;
        let review = preview(store, &mut fixture, profile).await;
        assert_eq!(review.format, export::Format::BitwardenEncryptedJson);
        assert!(
            review.file.encrypted
                && review.records == 1
                && review.losses > 0
                && review.blocked == 0
        );
        assert_eq!(
            fixture.engine.export_rows(review.token, 0).unwrap().items[0].head,
            fixture.head
        );
        assert_eq!(
            fixture
                .engine
                .generate_export(store, review.token, export::Consent::Lossless, &mut |_| {
                    true
                })
                .await
                .err(),
            Some(flow::Error::Export(export::Error::Losses))
        );
        let ready = fixture
            .engine
            .generate_export(
                store,
                review.token,
                export::Consent::AllowLosses,
                &mut |_| true,
            )
            .await
            .unwrap();
        assert!(ready.file.encrypted);
        let bytes = download(&fixture.engine, &ready);
        let mut options = app::import::Options::default();
        options.password = EXPORT_PASSWORD.into();
        let restored = app::import::prepare(
            export::Format::BitwardenEncryptedJson,
            &bytes,
            &options,
            app::import::Limits::default(),
            &mut |_| true,
            bitwarden_encrypted_json::parse,
        )
        .unwrap();
        assert_eq!(restored.items.len(), 1);
        let record = restored.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(record.entries.len(), 1);
        assert_eq!(record.entries[0].type_name, "password/v1");
        assert_eq!(
            record.tags.len(),
            if matches!(profile, Profile::Organization) {
                2
            } else {
                1
            }
        );
        assert_eq!(
            record.entries[0].value["password"].as_str(),
            Some("current public password\n第二行")
        );
        fixture.engine.finish_export(ready.token).unwrap();
        assert_eq!(
            fixture.engine.export_chunk(ready.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
        assert_eq!(*snapshot(store, id).await, *before);

        let review = preview(store, &mut fixture, profile).await;
        let mut writing = 0;
        let result = fixture
            .engine
            .generate_export(
                store,
                review.token,
                export::Consent::AllowLosses,
                &mut |p: export::Progress| {
                    if p.phase == export::Phase::Write {
                        writing += 1;
                    }
                    writing < 3
                },
            )
            .await;
        assert_eq!(
            result.err(),
            Some(flow::Error::Export(export::Error::Canceled))
        );
        assert_eq!(writing, 3);
        assert_eq!(
            fixture.engine.export_rows(review.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
        assert_eq!(*snapshot(store, id).await, *before);

        let review = preview(store, &mut fixture, profile).await;
        let ready = fixture
            .engine
            .generate_export(
                store,
                review.token,
                export::Consent::AllowLosses,
                &mut |_| true,
            )
            .await
            .unwrap();
        fixture.engine.cancel_export(Some(ready.token)).unwrap();
        assert_eq!(
            fixture.engine.export_chunk(ready.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
        let review = preview(store, &mut fixture, profile).await;
        command(store, &mut fixture.engine, Command::Lock).await;
        assert_eq!(
            fixture.engine.export_rows(review.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
        command(
            store,
            &mut fixture.engine,
            Command::Unlock {
                vault: id,
                password: PASSWORD.into(),
                key: fixture.created.key.clone(),
                remember: false,
            },
        )
        .await;
        let review = preview(store, &mut fixture, profile).await;
        let ready = fixture
            .engine
            .generate_export(
                store,
                review.token,
                export::Consent::AllowLosses,
                &mut |_| true,
            )
            .await
            .unwrap();
        command(store, &mut fixture.engine, Command::Lock).await;
        assert_eq!(
            fixture.engine.export_chunk(ready.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
        assert_eq!(*snapshot(store, id).await, *before);
    }
}
