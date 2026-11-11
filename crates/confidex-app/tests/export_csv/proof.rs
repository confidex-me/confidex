//! Public current-value checks shared by native, WASI and the browser Worker.
use confidex_app::{
    export::{self, Column, Consent, Csv, Records, Source},
    import::{self, CsvColumn, CsvMapping, Format, Options, formats::csv},
};
use confidex_vault::{
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
};

pub fn field(name: &str, kind: &str, key: &str, value: &str) -> Entry {
    Entry {
        name: name.into(),
        type_name: kind.into(),
        value: [(key.into(), value.into())].into(),
        extra: Mapping::new(),
    }
}
pub fn fixture() -> Record {
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "公開 / café\r\nTitle".into());
    record.entries.extend([
        field("Repeated", "username/v1", "username", " public-user "),
        field("Repeated", "password/v1", "password", "=1+2"),
        field("", "url/v1", "url", "https://one.invalid/?a=1&b=2"),
        field("", "url/v1", "url", "custom://公開/second"),
        field(
            "\u{feff}Text",
            "text/v1",
            "text",
            "line one\r\n\"two\"\\公開\rfinal\n",
        ),
        field("秘密", "secret/v1", "secret", ""),
        field("Notes", "secure-note/v1", "text", "  keep spaces  "),
    ]);
    let mut otp = import::totp::entry("otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45").unwrap();
    otp.name = "OTP".into();
    record.entries.push(otp);
    record
}
pub fn profile(name: &str) -> Csv {
    Csv {
        profile: Some(name.into()),
        delimiter: b',',
        header: true,
        columns: Vec::new(),
    }
}
pub fn login() -> Record {
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "公開 / Public".into());
    record.entries.extend([
        field(
            "URL",
            "url/v1",
            "url",
            "https://www.example.invalid/?a=1&b=2",
        ),
        field("Username", "username/v1", "username", "public-user"),
        field("Password", "password/v1", "password", "PUBLIC-CURRENT"),
        field("Notes", "secure-note/v1", "text", "line one\n\"two\"\\公開"),
    ]);
    let mut otp = confidex_app::import::totp::entry("otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45").unwrap();
    otp.name = "OTPAuth".into();
    record.entries.push(otp);
    record
}
pub fn config(delimiter: u8, header: bool) -> Csv {
    let record = fixture();
    let mut columns = vec![Column {
        heading: "Record title".into(),
        source: Source::Title,
    }];
    for (index, entry) in record.entries.iter().enumerate() {
        columns.push(Column {
            heading: entry.name.clone(),
            source: Source::Field {
                index,
                type_name: entry.type_name.clone(),
                key: key(&entry.type_name).into(),
            },
        });
    }
    Csv {
        profile: None,
        delimiter,
        header,
        columns,
    }
}
fn key(kind: &str) -> &'static str {
    match kind {
        "username/v1" => "username",
        "password/v1" => "password",
        "url/v1" => "url",
        "text/v1" | "note/v1" | "secure-note/v1" => "text",
        _ => "secret",
    }
}
pub fn mapping(config: &Csv) -> CsvMapping {
    CsvMapping {
        delimiter: config.delimiter,
        header: config.header,
        columns: config
            .columns
            .iter()
            .enumerate()
            .map(|(index, c)| CsvColumn {
                index,
                name: c.heading.clone(),
                target: match &c.source {
                    Source::Title => "title".into(),
                    Source::Tags => "secret/v1".into(),
                    Source::Field { type_name, .. } => type_name.clone(),
                },
            })
            .collect(),
    }
}
pub fn plan(
    records: Vec<Record>,
    config: Csv,
    limits: export::Limits,
) -> (export::Plan, import::Memory) {
    let mut snapshot = Records::new(limits).unwrap();
    for record in records {
        snapshot.push(record).unwrap();
    }
    let memory = snapshot.memory().clone();
    let plan = export::prepare(
        snapshot,
        Box::new(csv::Writer::new(config).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    (plan, memory)
}
pub fn imported(bytes: &[u8], mapping: CsvMapping) -> import::Plan {
    let mut options = Options::default();
    options.csv = Some(mapping);
    import::prepare(
        Format::Csv,
        bytes,
        &options,
        import::Limits::default(),
        &mut |_| true,
        csv::parse,
    )
    .unwrap()
}
pub fn firefox_record() -> Record {
    let input = b"url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\r\n\"https://www.example.invalid/\",\"public-user\",\"PUBLIC-OLD-REMOVED\",,\"\",\"{public-guid}\",\"1735689600000\",\"1735689601000\",\"1735689602000\"\r\n";
    let header = csv::header(input, b',', import::Limits::default(), &mut |_| true).unwrap();
    let plan = imported(input, csv::Profile::Firefox.mapping(&header).unwrap());
    let mut record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let attributes = plan.items[0].source_attributes(MAX_OPEN_MEMORY).unwrap();
    let container = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    let map = |fields: Mapping| {
        Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    };
    record.extra.insert(
        "confidex.import.origin".into(),
        Value::Map(vec![
            ("version".into(), 1u64.into()),
            ("format".into(), "csv".into()),
            ("attributes".into(), map(attributes)),
            ("container".into(), map(container)),
        ]),
    );
    record
}
pub fn run() {
    for delimiter in *b",;\t|" {
        for header in [false, true] {
            let config = config(delimiter, header);
            let import_mapping = mapping(&config);
            let expected = fixture();
            let (plan, memory) = plan(vec![fixture()], config, export::Limits::default());
            assert!(plan.issues().is_empty(), "{:?}", plan.issues());
            let mut previous = 0;
            let artifact = plan
                .write(Consent::Lossless, &mut |p| {
                    assert!(p.current >= previous && p.current <= p.total);
                    previous = p.current;
                    true
                })
                .unwrap();
            assert_eq!(artifact.file.media_type, "text/csv");
            assert!(!artifact.file.encrypted);
            let imported = imported(artifact.bytes(), import_mapping);
            assert_eq!(imported.items.len(), 1);
            let actual = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
            assert_eq!(
                actual.extra["confidex.title"],
                expected.extra["confidex.title"]
            );
            assert_eq!(actual.entries.len(), expected.entries.len());
            for (actual, expected) in actual.entries.iter().zip(&expected.entries) {
                assert_eq!(actual.name, expected.name);
                assert_eq!(actual.type_name, expected.type_name);
                assert_eq!(actual.value, expected.value);
            }
            drop(artifact);
            assert_eq!(memory.available(), MAX_OPEN_MEMORY);
        }
    }
    for p in [
        csv::Profile::Chromium,
        csv::Profile::Firefox,
        csv::Profile::ApplePasswords,
    ] {
        let (plan, memory) = plan(vec![login()], profile(p.id()), export::Limits::default());
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let header = csv::header(
            artifact.bytes(),
            b',',
            import::Limits::default(),
            &mut |_| true,
        )
        .unwrap();
        assert_eq!(header.profiles(), [p]);
        let roundtrip = imported(artifact.bytes(), p.mapping(&header).unwrap());
        let record = roundtrip.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert!(record.entries.iter().any(|e| {
            e.value
                .get("password")
                .and_then(confidex_vault::record::Value::as_str)
                == Some("PUBLIC-CURRENT")
        }));
        drop(artifact);
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
    let mut firefox = firefox_record();
    firefox.entries[2]
        .value
        .insert("password".into(), "PUBLIC-CURRENT".into());
    firefox.entries[5]
        .value
        .insert("secret".into(), "{current-guid}".into());
    firefox.entries.swap(0, 8);
    let (firefox_plan, memory) = plan(vec![firefox], profile("firefox"), export::Limits::default());
    let artifact = firefox_plan
        .write(Consent::AllowLosses, &mut |_| true)
        .unwrap();
    let text = std::str::from_utf8(artifact.bytes()).unwrap();
    assert!(!text.contains("PUBLIC-OLD-REMOVED"));
    assert!(text.contains("\"PUBLIC-CURRENT\",,\"\",\"{current-guid}\""));
    drop(artifact);
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    for cancel in [false, true] {
        let mut record = Record::default();
        record
            .entries
            .push(field("Public", "text/v1", "text", &"x\"".repeat(400_000)));
        let config = Csv {
            profile: None,
            delimiter: b',',
            header: true,
            columns: vec![Column {
                heading: "Public".into(),
                source: Source::Field {
                    index: 0,
                    type_name: "text/v1".into(),
                    key: "text".into(),
                },
            }],
        };
        let limits = export::Limits {
            output_bytes: if cancel { 2 << 20 } else { 128 << 10 },
            ..export::Limits::default()
        };
        let (plan, memory) = plan(vec![record], config, limits);
        let mut callbacks = 0;
        let result = plan.write(Consent::Lossless, &mut |_| {
            callbacks += 1;
            !cancel || callbacks < 100
        });
        assert_eq!(
            result.err(),
            Some(if cancel {
                export::Error::Canceled
            } else {
                export::Error::Limit
            })
        );
        if cancel {
            assert_eq!(callbacks, 100);
        }
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
}
