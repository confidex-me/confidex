//! Public fixtures shared by native, WASI, and the real browser worker.
use confidex_app::{
    export::{self, Consent, Records},
    import::{self, Format, Options, Status, formats::bitwarden_zip},
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
pub fn file(name: &str, bytes: &[u8]) -> Entry {
    Entry {
        name: name.into(),
        type_name: "file/v1".into(),
        value: Mapping::from([
            ("filename".into(), name.into()),
            ("mime".into(), "application/octet-stream".into()),
            ("data".into(), Value::Binary(bytes.to_vec())),
        ]),
        extra: Mapping::new(),
    }
}
pub fn fixture() -> Vec<Record> {
    let mut first = Record::default();
    first
        .extra
        .insert("confidex.title".into(), "Почта / 東京".into());
    first.tags = vec!["Shared".into()];
    first.entries.extend([
        field("Username", "username/v1", "username", "public-user"),
        field("Password", "password/v1", "password", "PUBLIC-CURRENT"),
        field("URL", "url/v1", "url", "https://one.invalid/?a=1&b=2"),
        field("", "text/v1", "text", ""),
        field("Repeated", "text/v1", "text", "line one\n\"two\"\\公開"),
        field("Repeated", "secret/v1", "secret", "PUBLIC-HIDDEN"),
        file("same.bin", &[0, 255, 7]),
        file("empty.bin", &[]),
        file("scan.part.txt", b"PUBLIC-DOTS"),
        file("公開 café.bin", b"PUBLIC-UNICODE"),
    ]);
    let mut second = Record::default();
    second
        .extra
        .insert("confidex.title".into(), "Second".into());
    second.entries.extend([
        field("Password", "password/v1", "password", "PUBLIC-SECOND"),
        file("same.bin", &[42]),
    ]);
    vec![first, second]
}
pub fn plan(items: Vec<Record>, limits: export::Limits) -> (export::Plan, import::Memory) {
    let mut records = Records::new(limits).unwrap();
    for item in items {
        records.push(item).unwrap();
    }
    let memory = records.memory().clone();
    let plan = export::prepare(
        records,
        Box::new(bitwarden_zip::Writer::new().unwrap()),
        &mut |_| true,
    )
    .unwrap();
    (plan, memory)
}
pub fn imported(bytes: &[u8]) -> import::Plan {
    let mut options = Options::default();
    options.source_instance = Some("public-zip-worker".into());
    import::prepare(
        Format::BitwardenZip,
        bytes,
        &options,
        import::Limits::default(),
        &mut |_| true,
        bitwarden_zip::parse,
    )
    .unwrap()
}
pub fn run() {
    let (plan, memory) = plan(fixture(), export::Limits::default());
    assert!(plan.issues().is_empty(), "{:?}", plan.issues());
    let mut previous = (0, 1);
    let artifact = plan
        .write(Consent::Lossless, &mut |progress| {
            assert!(progress.current <= progress.total);
            assert!(progress.current * previous.1 >= previous.0 * progress.total);
            previous = (progress.current, progress.total);
            true
        })
        .unwrap();
    assert_eq!(previous.0, previous.1);
    assert!(!artifact.file.encrypted);
    assert_eq!(&artifact.bytes()[..4], b"PK\x03\x04");
    let imported = imported(artifact.bytes());
    // The official archive cannot attest the producer's complete attachment inventory.
    assert_eq!(imported.container_status, Status::Review);
    assert_eq!(imported.items.len(), 2);
    let expected = fixture();
    let mut ids = std::collections::BTreeSet::new();
    for (item, expected) in imported.items.iter().zip(expected.iter()) {
        assert_ne!(item.status, Status::Blocked);
        assert!(ids.insert(item.source.item.as_deref().unwrap()));
        let actual = item.record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            actual.extra["confidex.title"],
            expected.extra["confidex.title"]
        );
        assert_eq!(actual.tags, expected.tags);
        assert_eq!(actual.entries.len(), expected.entries.len());
        for (actual, expected) in actual.entries.iter().zip(expected.entries.iter()) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.type_name, expected.type_name);
            assert_eq!(actual.value, expected.value);
        }
    }
    drop(artifact);
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    for cancel in [false, true] {
        let limits = export::Limits {
            output_bytes: if cancel { 2 << 20 } else { 128 << 10 },
            ..export::Limits::default()
        };
        let mut record = Record::default();
        record.extra.insert("confidex.title".into(), "Large".into());
        record.entries.push(file("large.bin", &vec![7; 900_000]));
        let (plan, memory) = self::plan(vec![record], limits);
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
