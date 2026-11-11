//! Explicit calibration of real storage, all writers and their emitted records.
use super::*;
use confidex_storage::{BatchCommit, HeadChange, StoredObject};

pub(super) const COUNT: usize = 10_000;
const EXPORT_PASSWORD: &str = "PUBLIC-export-calibration-password";

#[derive(serde::Serialize)]
pub struct Run {
    format: export::Format,
    output_bytes: usize,
    losses: usize,
    read_review_ms: f64,
    generate_ms: f64,
    transfer_ms: f64,
    verify_ms: f64,
}
#[derive(serde::Serialize)]
pub struct Report {
    records: usize,
    seed_ms: f64,
    commit_ms: f64,
    total_ms: f64,
    runs: Vec<Run>,
}
pub(super) fn options(format: export::Format) -> export::Options {
    match format {
        export::Format::Kdbx => export::Options::Password {
            password: Some(EXPORT_PASSWORD.into()),
            keyfile: None,
        },
        export::Format::BitwardenEncryptedJson => export::Options::Bitwarden {
            organization: false,
            password: Some(EXPORT_PASSWORD.into()),
        },
        export::Format::Csv => export::Options::Csv(export::Csv {
            profile: Some("chromium".into()),
            delimiter: b',',
            header: true,
            columns: Vec::new(),
        }),
        _ => export::Options::Plain,
    }
}
pub(super) async fn heads(store: &mut impl Store, vault: VaultId) -> Vec<Head> {
    let mut heads = Vec::new();
    loop {
        let page = store
            .heads(vault, heads.last().map(|head: &Head| head.record))
            .await
            .unwrap();
        if page.is_empty() {
            return heads;
        }
        heads.extend(page);
    }
}
pub async fn seed(store: &mut impl Store, now: impl Fn() -> f64) -> (Fixture, f64, f64, f64) {
    let fixture = fixture(store).await;
    let started = now();
    let mut batch = BatchCommit {
        previous: vec![fixture.head.clone()],
        objects: Vec::with_capacity(COUNT),
        heads: Vec::with_capacity(COUNT),
    };
    for index in 0..COUNT {
        let mut record = Record::default();
        record
            .extra
            .insert("confidex.title".into(), format!("Public {index}").into());
        for (name, type_name, key, value) in [
            (
                "Username",
                "username/v1",
                "username",
                format!("public-user-{index}"),
            ),
            (
                "Password",
                "password/v1",
                "password",
                format!("PUBLIC-current-{index}"),
            ),
            (
                "URL",
                "url/v1",
                "url",
                format!("https://example.invalid/{index}"),
            ),
            (
                "Notes",
                "secure-note/v1",
                "text",
                format!("Public note {index}"),
            ),
        ] {
            record.entries.push(Entry {
                name: name.into(),
                type_name: type_name.into(),
                value: Mapping::from([(key.into(), value.into())]),
                extra: Mapping::new(),
            });
        }
        let mut record_id = [0; 16];
        record_id[8..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        if index == 0 {
            record_id = fixture.head.record;
        }
        let previous = (index == 0).then_some(fixture.head.revision);
        let wire = envelope::seal(
            &record,
            fixture.vault.keys(),
            Options {
                vault_id: fixture.created.info.id,
                record_id,
                parents: &previous.into_iter().collect::<Vec<_>>(),
                epoch: index as u64 + 10,
                kind: EventKind::Content,
            },
            MAX_OPEN_MEMORY,
        )
        .unwrap();
        let revision = envelope::verify(&wire, fixture.vault.anchor(), None, MAX_OPEN_MEMORY)
            .unwrap()
            .id();
        let head = Head {
            record: record_id,
            revision,
        };
        batch.heads.push(HeadChange {
            head: head.clone(),
            expected: previous,
        });
        batch.objects.push(StoredObject {
            head,
            wire,
            tags: Vec::new(),
        });
    }
    let sealed = now();
    store
        .batch_commit(fixture.created.info.id, &batch)
        .await
        .unwrap();
    drop(batch);
    let committed = now();
    (fixture, started, sealed, committed)
}
pub async fn run(store: &mut impl Store, now: impl Fn() -> f64) -> Report {
    let (mut fixture, started, sealed, committed) = seed(store, &now).await;
    let before = heads(store, fixture.created.info.id).await;
    assert_eq!(before.len(), COUNT);
    let mut report = Report {
        records: COUNT,
        seed_ms: sealed - started,
        commit_ms: committed - sealed,
        total_ms: 0.0,
        runs: Vec::new(),
    };
    for format in [
        export::Format::BitwardenJson,
        export::Format::BitwardenZip,
        export::Format::KeepassXml,
        export::Format::Onepassword1pux,
        export::Format::Csv,
        export::Format::BitwardenEncryptedJson,
        export::Format::Kdbx,
    ] {
        let reading = now();
        let writer = export::writer(format, options(format), 1_735_689_600).unwrap();
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
        assert_eq!((review.records, review.blocked), (COUNT, 0), "{format:?}");
        let reviewed = now();
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
        let generated = now();
        let bytes = download(&fixture.engine, &ready);
        fixture.engine.finish_export(ready.token).unwrap();
        let transferred = now();
        let mut options = app::import::Options::default();
        if matches!(
            format,
            export::Format::Kdbx | export::Format::BitwardenEncryptedJson
        ) {
            options.password = EXPORT_PASSWORD.into();
            options.password_present = true;
        }
        if format == export::Format::Csv {
            use app::import::formats::csv;
            let header =
                csv::header(&bytes, b',', app::import::Limits::default(), &mut |_| true).unwrap();
            options.csv = Some(csv::Profile::Chromium.mapping(&header).unwrap());
        }
        let parsed = app::import::prepare(
            format,
            &bytes,
            &options,
            app::import::Limits::default(),
            &mut |_| true,
            match format {
                export::Format::BitwardenJson => app::import::formats::bitwarden_json::parse,
                export::Format::BitwardenZip => app::import::formats::bitwarden_zip::parse,
                export::Format::KeepassXml => app::import::formats::keepass_xml::parse,
                export::Format::Onepassword1pux => app::import::formats::onepassword_1pux::parse,
                export::Format::Csv => app::import::formats::csv::parse,
                export::Format::BitwardenEncryptedJson => {
                    app::import::formats::bitwarden_encrypted_json::parse
                }
                export::Format::Kdbx => app::import::formats::kdbx::parse,
            },
        )
        .unwrap();
        assert_eq!(parsed.items.len(), COUNT, "{format:?}");
        let mut seen = std::collections::BTreeSet::new();
        for item in &parsed.items {
            let record = item.record(MAX_OPEN_MEMORY).unwrap();
            let index: usize = record.extra["confidex.title"]
                .as_str()
                .unwrap()
                .strip_prefix("Public ")
                .unwrap()
                .parse()
                .unwrap();
            assert!(index < COUNT && seen.insert(index));
            for (kind, key, expected) in [
                ("username/v1", "username", format!("public-user-{index}")),
                ("password/v1", "password", format!("PUBLIC-current-{index}")),
                ("url/v1", "url", format!("https://example.invalid/{index}")),
                ("secure-note/v1", "text", format!("Public note {index}")),
            ] {
                let field = record
                    .entries
                    .iter()
                    .find(|entry| entry.type_name == kind)
                    .unwrap();
                assert_eq!(field.value[key].as_str(), Some(expected.as_str()));
            }
        }
        assert_eq!(heads(store, fixture.created.info.id).await, before);
        report.runs.push(Run {
            format,
            output_bytes: bytes.len(),
            losses: review.losses,
            read_review_ms: reviewed - reading,
            generate_ms: generated - reviewed,
            transfer_ms: transferred - generated,
            verify_ms: now() - transferred,
        });
    }
    report.total_ms = now() - started;
    report
}
