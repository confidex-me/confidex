//! Public captured source, current edits, and genuine cross-format output.
use super::{append, fixture, snapshot};
use confidex_app::{export, export_flow as flow, import, import_apply};
use confidex_storage::Store;
use confidex_vault::{
    envelope,
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
};
#[path = "../import_integration/cases.rs"]
mod cases;

#[derive(Clone, Copy)]
enum Source {
    Producer,
    Imported(&'static cases::Case),
    Native,
}
impl Source {
    fn name(self) -> &'static str {
        match self {
            Self::Producer => "bitwarden-producer",
            Self::Imported(case) => case.name,
            Self::Native => "native",
        }
    }
    fn origin(self) -> Option<&'static str> {
        match self {
            Self::Producer => Some("bitwarden-json"),
            Self::Imported(case) => Some(case.origin),
            Self::Native => None,
        }
    }
    fn plan(self) -> Option<import::Plan> {
        match self {
            Self::Producer => Some(source()),
            Self::Imported(case) => Some(case.plan()),
            Self::Native => None,
        }
    }
    fn protected_url(self) -> bool {
        matches!(self, Self::Imported(case) if matches!(case.format, import::Format::KeepassXml | import::Format::Kdbx))
    }
}

pub const PASSWORD: &str = "PUBLIC-reverse-export-password";
pub const FORMATS: [export::Format; 7] = [
    export::Format::BitwardenJson,
    export::Format::Kdbx,
    export::Format::BitwardenEncryptedJson,
    export::Format::BitwardenZip,
    export::Format::KeepassXml,
    export::Format::Onepassword1pux,
    export::Format::Csv,
];

fn source() -> import::Plan {
    let mut options = import::Options::default();
    options.source_instance = Some("public-captured-bitwarden-reverse".into());
    import::prepare(
        import::Format::BitwardenJson,
        include_bytes!("../import_fixtures/bitwarden_json/producer-personal.json"),
        &options,
        import::Limits::default(),
        &mut |_| true,
        import::formats::bitwarden_json::parse,
    )
    .unwrap()
}
fn edited(mut record: Record, source: Source) -> Record {
    let origin = record.extra.get("confidex.import.origin").map(|value| {
        value
            .as_map()
            .unwrap()
            .iter()
            .find(|(key, _)| key.as_str() == Some("format"))
            .unwrap()
            .1
            .as_str()
            .unwrap()
    });
    assert_eq!(origin, source.origin());
    let had_otp = record
        .entries
        .iter()
        .any(|entry| entry.type_name == "totp/v1");
    let had_second_url = record
        .entries
        .iter()
        .filter(|entry| entry.type_name == "url/v1")
        .count()
        > 1;
    let old = std::mem::take(&mut record.entries);
    let mut remaining: Vec<Option<Entry>> = old.into_iter().map(Some).collect();
    for (name, kind, key, value) in [
        (
            "Username",
            "username/v1",
            "username",
            "current-user@example.invalid",
        ),
        (
            "Password",
            "password/v1",
            "password",
            "PUBLIC-current-password\n第二行",
        ),
        (
            "URL",
            "url/v1",
            "url",
            "https://current.example.invalid/edited?q=1&v=2",
        ),
        ("One-time code", "totp/v1", "", ""),
        (
            "Notes",
            "secure-note/v1",
            "text",
            "PUBLIC-current-note\n\nLast line",
        ),
    ] {
        let mut entry = remaining
            .iter_mut()
            .find(|entry| {
                entry.as_ref().is_some_and(|entry| {
                    entry.type_name == kind
                        || (kind == "secure-note/v1" && entry.type_name == "note/v1")
                })
            })
            .and_then(Option::take)
            .unwrap_or_else(|| Entry {
                name: String::new(),
                type_name: kind.into(),
                value: Mapping::new(),
                extra: Mapping::new(),
            });
        if kind == "url/v1" {
            let protected = entry
                .extra
                .get("metadata")
                .and_then(Value::as_map)
                .is_some_and(|map| {
                    map.iter().any(|(key, value)| {
                        key.as_str() == Some("protected") && value.as_bool() == Some(true)
                    })
                });
            assert_eq!(
                protected,
                source.protected_url(),
                "{} URL protection",
                source.name()
            );
        }
        entry.name = name.into();
        entry.type_name = kind.into();
        entry.value = if kind == "totp/v1" {
            Mapping::from([
                ("secret".into(), Value::Binary(b"foobar".to_vec())),
                ("algorithm".into(), "SHA512".into()),
                ("digits".into(), 8u64.into()),
                ("period".into(), 60u64.into()),
                ("t0".into(), 0u64.into()),
            ])
        } else {
            Mapping::from([(key.into(), value.into())])
        };
        record.entries.push(entry);
    }
    // Absence enables legacy hints; an empty layout explicitly clears sections.
    record.extra.insert(
        "confidex.sections".into(),
        Value::Map(vec![
            ("version".into(), 1u64.into()),
            ("groups".into(), Value::Array(Vec::new())),
        ]),
    );
    record.entries.extend([
        Entry {
            name: "Secondary URL".into(),
            type_name: "url/v1".into(),
            value: Mapping::from([("url".into(), "https://added.example.invalid/".into())]),
            extra: Mapping::new(),
        },
        Entry {
            name: "Current attachment".into(),
            type_name: "file/v1".into(),
            value: Mapping::from([
                ("filename".into(), "current.bin".into()),
                ("data".into(), Value::Binary(vec![0, 255, 4, 2])),
            ]),
            extra: Mapping::new(),
        },
    ]);
    record
        .extra
        .insert("confidex.title".into(), "PUBLIC-current-title".into());
    record.tags = vec!["Current group".into()];
    let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    for (retained, stale) in [
        (had_otp, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        (
            had_second_url
                && matches!(
                    source,
                    Source::Producer
                        | Source::Imported(cases::Case {
                            format: import::Format::BitwardenJson,
                            ..
                        })
                ),
            "https://second.example.invalid",
        ),
    ] {
        if retained {
            assert!(
                encoded
                    .bytes
                    .windows(stale.len())
                    .any(|bytes| bytes == stale.as_bytes()),
                "{} stale metadata",
                source.name()
            );
        }
    }
    record
}

fn options(format: export::Format) -> export::Options {
    match format {
        export::Format::Kdbx => export::Options::Password {
            password: Some(PASSWORD.into()),
            keyfile: None,
        },
        export::Format::BitwardenEncryptedJson => export::Options::Bitwarden {
            organization: false,
            password: Some(PASSWORD.into()),
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

#[derive(serde::Serialize)]
pub struct Output {
    pub name: String,
    pub bytes: Vec<u8>,
}
pub async fn run(store: &mut impl Store) -> Vec<Output> {
    let mut outputs = Vec::new();
    for source in std::iter::once(Source::Producer)
        .chain(cases::CASES.iter().chain(cases::KDBX).map(Source::Imported))
        .chain(std::iter::once(Source::Native))
    {
        let mut fixture = fixture(store).await;
        let id = fixture.created.info.id;
        let head = if let Some(plan) = source.plan() {
            let review = fixture
                .engine
                .review_import(store, id, plan, &mut |_| true)
                .await
                .unwrap();
            let selection = import_apply::Selection {
                choices: review
                    .items
                    .iter()
                    .enumerate()
                    .map(|(index, _)| import_apply::Choice {
                        action: if index == 0 {
                            import_apply::Action::Create
                        } else {
                            import_apply::Action::Skip
                        },
                        reviewed: true,
                    })
                    .collect(),
                container_reviewed: true,
            };
            let report = fixture
                .engine
                .apply_import(store, review.token, &selection, 3, &mut |_| true)
                .await
                .unwrap();
            assert_eq!(report.added, 1);
            store
                .heads(id, None)
                .await
                .unwrap()
                .into_iter()
                .find(|head| head.record != fixture.head.record)
                .unwrap()
        } else {
            fixture.head.clone()
        };
        let wire = store.object(id, head.revision).await.unwrap();
        let record = envelope::verify(
            &wire,
            fixture.vault.anchor(),
            Some(&head.revision),
            MAX_OPEN_MEMORY,
        )
        .unwrap()
        .open(fixture.vault.keys(), MAX_OPEN_MEMORY)
        .unwrap();
        let head = append(
            store,
            &fixture.vault,
            head.record,
            Some(head.revision),
            &edited(record, source),
            4,
        )
        .await;
        let before = snapshot(store, id).await;
        for format in FORMATS {
            let review = fixture
                .engine
                .prepare_export(
                    store,
                    &flow::Selection::Records(vec![head.clone()]),
                    export::writer(format, options(format), 1_735_689_600).unwrap(),
                    export::Limits::default(),
                    &mut |_| true,
                )
                .await
                .unwrap();
            assert_eq!((review.records, review.blocked), (1, 0));
            assert!(review.losses > 0);
            if matches!(
                format,
                export::Format::BitwardenJson
                    | export::Format::BitwardenEncryptedJson
                    | export::Format::BitwardenZip
                    | export::Format::Csv
            ) {
                let mut issues = Vec::new();
                let mut start = 0;
                loop {
                    let page = fixture.engine.export_issues(review.token, start).unwrap();
                    issues.extend(page.items);
                    if let Some(next) = page.next {
                        start = next;
                    } else {
                        break;
                    }
                }
                for field in [Some(4), source.protected_url().then_some(2)]
                    .into_iter()
                    .flatten()
                {
                    assert!(
                        issues.iter().any(|row| row.issue.field == Some(field)
                            && row.issue.code == export::Code::Protection
                            && row.issue.severity == export::Severity::Loss),
                        "{} {format:?}: missing field protection loss",
                        source.name()
                    );
                }
            }
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
            let bytes = super::download(&fixture.engine, &ready);
            outputs.push(Output {
                name: format!("{}/{}", source.name(), ready.file.name),
                bytes: bytes.to_vec(),
            });
            fixture.engine.finish_export(ready.token).unwrap();
            assert_eq!(*snapshot(store, id).await, *before);
        }
    }
    outputs
}
