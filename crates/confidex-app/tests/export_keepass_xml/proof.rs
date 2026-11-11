//! Public fixtures for the same writer in pure tests and a browser worker.
use confidex_app::{
    export::{self, Consent, Records},
    import::{self, Format, Options, Status, formats::keepass_xml},
};
use confidex_vault::{record::Record, resources::MAX_OPEN_MEMORY};

pub(super) use super::keepass_common as common;
pub use common::{file, fixture};
pub fn plan(record: Record, limits: export::Limits) -> (export::Plan, import::Memory) {
    let mut records = Records::new(limits).unwrap();
    records.push(record).unwrap();
    let memory = records.memory().clone();
    let plan = export::prepare(
        records,
        Box::new(keepass_xml::Writer::new(1_735_689_600).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    (plan, memory)
}
pub fn imported(bytes: &[u8]) -> import::Plan {
    let mut options = Options::default();
    options.source_instance = Some("public-xml-worker".into());
    import::prepare(
        Format::KeepassXml,
        bytes,
        &options,
        import::Limits::default(),
        &mut |_| true,
        keepass_xml::parse,
    )
    .unwrap()
}
pub fn run() {
    let (plan, memory) = plan(fixture(), export::Limits::default());
    assert_eq!(
        plan.issues()
            .iter()
            .map(|i| (i.field, i.code))
            .collect::<Vec<_>>(),
        [
            (None, export::Code::FieldOrder),
            (Some(6), export::Code::UnknownValue)
        ]
    );
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Losses)
    );
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    let (plan, memory) = self::plan(fixture(), export::Limits::default());
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert!(!artifact.file.encrypted);
    let xml = std::str::from_utf8(artifact.bytes()).unwrap();
    assert!(xml.contains("ProtectInMemory=\"True\""));
    assert!(!xml.contains("Protected="));
    for key in ["UserName", "Password", "URL", "Notes", "Hidden", "otp"] {
        assert!(xml.contains(&format!("<Key>{key}</Key><Value ProtectInMemory=\"True\">")));
    }
    assert!(xml.contains("&amp;") && xml.contains("&#13;") && xml.contains("&lt;"));
    let imported = imported(artifact.bytes());
    assert_eq!(imported.items.len(), 1);
    assert_ne!(imported.items[0].status, Status::Blocked);
    let actual = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let expected = fixture();
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
    for index in [0, 2] {
        assert!(
            actual.entries[index].extra["metadata"]
                .as_map()
                .unwrap()
                .iter()
                .any(|(k, v)| k.as_str() == Some("protected") && v.as_bool() == Some(true))
        );
    }
    drop(artifact);
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    for cancel in [false, true] {
        let limits = export::Limits {
            output_bytes: if cancel { 64 << 20 } else { 128 },
            ..export::Limits::default()
        };
        let (plan, memory) = self::plan(fixture(), limits);
        let mut callbacks = 0;
        let result = plan.write(Consent::AllowLosses, &mut |_| {
            callbacks += 1;
            !cancel || callbacks < 60
        });
        assert_eq!(
            result.err(),
            Some(if cancel {
                export::Error::Canceled
            } else {
                export::Error::Limit
            })
        );
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
    large_files();
}

fn large_files() {
    let mut record = Record::default();
    let expected: Vec<Vec<u8>> = [3071, 3072, 3073, 6144, 6145]
        .into_iter()
        .map(|length| (0..length).map(|n| n as u8).collect())
        .collect();
    for bytes in &expected {
        record
            .entries
            .push(file(&format!("f{}.bin", bytes.len()), bytes));
    }
    let (plan, _) = plan(record, export::Limits::default());
    assert!(plan.issues().is_empty());
    let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    let imported = imported(artifact.bytes());
    let actual = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    for (entry, expected) in actual.entries.iter().zip(expected.iter()) {
        assert_eq!(entry.value["data"].as_slice(), Some(expected.as_slice()));
    }
    assert_eq!(actual.entries.len(), expected.len());
    for cancel in [false, true] {
        let limits = export::Limits {
            output_bytes: if cancel { 2 << 20 } else { 128 << 10 },
            ..export::Limits::default()
        };
        let mut record = Record::default();
        record.entries.push(file("large.bin", &vec![7; 900_000]));
        let (plan, memory) = self::plan(record, limits);
        let mut callbacks = 0;
        assert_eq!(
            plan.write(Consent::Lossless, &mut |_| {
                callbacks += 1;
                !cancel || callbacks < 100
            })
            .err(),
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
