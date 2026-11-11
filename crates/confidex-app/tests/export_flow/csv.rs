//! Exercise the real CSV factory before the translated form joins the catalog.
use super::*;
use export::{Column, Csv, Format, Source};

fn manual(delimiter: u8, header: bool) -> Csv {
    let field = |index, type_name: &str, key: &str| Source::Field {
        index,
        type_name: type_name.into(),
        key: key.into(),
    };
    Csv {
        profile: None,
        delimiter,
        header,
        columns: [
            ("", field(4, "url/v1", "url")),
            ("Name\r\n名", Source::Title),
            ("Same", field(0, "password/v1", "password")),
            ("Same", field(3, "url/v1", "url")),
            ("Empty", field(5, "text/v1", "text")),
        ]
        .into_iter()
        .map(|(heading, source)| Column {
            heading: heading.into(),
            source,
        })
        .collect(),
    }
}
fn expected(config: &Csv) -> String {
    let title = "\"Public, \"\"title\"\"\r\n公開\"";
    let password = "\"current public password\n第二行\"";
    let url = "\"https://one.example/a?x=1&y=2\"";
    let (headings, cells): (Vec<&str>, Vec<&str>) = match config.profile.as_deref() {
        None => (
            vec![
                "\"\"",
                "\"Name\r\n名\"",
                "\"Same\"",
                "\"Same\"",
                "\"Empty\"",
            ],
            vec!["\"https://two.example/\"", title, password, url, "\"\""],
        ),
        Some("chromium") => (
            vec![
                "\"name\"",
                "\"url\"",
                "\"username\"",
                "\"password\"",
                "\"note\"",
            ],
            vec![title, url, "\"\"", password, "\"\""],
        ),
        Some("firefox") => (
            vec![
                "\"url\"",
                "\"username\"",
                "\"password\"",
                "\"httpRealm\"",
                "\"formActionOrigin\"",
                "\"guid\"",
                "\"timeCreated\"",
                "\"timeLastUsed\"",
                "\"timePasswordChanged\"",
            ],
            vec![url, "\"\"", password, "", "", "", "", "", ""],
        ),
        Some("apple-passwords") => (
            vec![
                "\"Title\"",
                "\"URL\"",
                "\"Username\"",
                "\"Password\"",
                "\"Notes\"",
                "\"OTPAuth\"",
            ],
            vec![title, url, "\"\"", password, "\"\"", "\"\""],
        ),
        _ => unreachable!(),
    };
    let delimiter = char::from(config.delimiter).to_string();
    let mut result = if config.header {
        headings.join(&delimiter) + "\r\n"
    } else {
        String::new()
    };
    result.push_str(&cells.join(&delimiter));
    result.push_str("\r\n");
    result
}
pub async fn run(store: &mut impl Store) {
    let mut fixture = fixture(store).await;
    let mut record = content();
    record.entries.remove(1);
    record.entries[0]
        .value
        .insert("password".into(), "current public password\n第二行".into());
    record
        .extra
        .insert("confidex.title".into(), "Public, \"title\"\r\n公開".into());
    for (type_name, key, value) in [
        ("url/v1", "url", "https://one.example/a?x=1&y=2"),
        ("url/v1", "url", "https://two.example/"),
        ("text/v1", "text", ""),
    ] {
        record.entries.push(Entry {
            name: "Same".into(),
            type_name: type_name.into(),
            value: Mapping::from([(key.into(), value.into())]),
            extra: Mapping::new(),
        });
    }
    fixture.head = append(
        store,
        &fixture.vault,
        fixture.head.record,
        Some(fixture.head.revision),
        &record,
        3,
    )
    .await;
    append(store, &fixture.vault, [2; 16], None, &Record::default(), 4).await;
    let before = snapshot(store, fixture.created.info.id).await;
    assert!(
        !export::catalog()
            .iter()
            .any(|info| info.format == Format::Csv)
    );
    assert_eq!(
        call(
            store,
            &mut fixture.engine,
            flow::Command::Prepare {
                operation: 601,
                created_at: 0,
                format: Format::Csv,
                options: export::Options::Csv(manual(b',', true)),
                selection: flow::Selection::All,
            }
        )
        .await
        .err(),
        Some(flow::Error::Export(export::Error::UnsupportedFormat))
    );
    let mut configs = Vec::new();
    for delimiter in *b",;\t|" {
        for header in [false, true] {
            configs.push(manual(delimiter, header));
        }
    }
    for profile in ["chromium", "firefox", "apple-passwords"] {
        configs.push(Csv {
            profile: Some(profile.into()),
            delimiter: b',',
            header: true,
            columns: vec![],
        });
    }
    for config in configs {
        let expected = Zeroizing::new(expected(&config));
        let options = Zeroizing::new(serde_json::to_vec(&export::Options::Csv(config)).unwrap());
        let writer =
            export::writer(Format::Csv, serde_json::from_slice(&options).unwrap(), 0).unwrap();
        let review = fixture
            .engine
            .prepare_export(
                store,
                &flow::Selection::Records(vec![fixture.head.clone()]),
                writer,
                export::Limits::default(),
                &mut |_| true,
            )
            .await
            .unwrap();
        assert_eq!(
            (review.format, review.records, review.blocked),
            (Format::Csv, 1, 0)
        );
        assert!(review.losses > 0 && !review.file.encrypted);
        assert_eq!(review.file.media_type, "text/csv");
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
        let bytes = download(&fixture.engine, &ready);
        assert_eq!(&*bytes, expected.as_bytes());
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains("deleted public password")
        );
        fixture.engine.finish_export(ready.token).unwrap();
        assert_eq!(
            fixture.engine.export_chunk(ready.token, 0).err(),
            Some(flow::Error::InvalidSession)
        );
    }
    let writer = export::writer(Format::Csv, export::Options::Csv(manual(b',', true)), 0).unwrap();
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
    assert!(review.blocked > 0);
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
        Some(flow::Error::Export(export::Error::Blocked))
    );
    fixture.engine.cancel_export(None).unwrap();
    assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
}
