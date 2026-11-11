//! Public fixtures shared by native, WASI, and the actual browser worker.
use confidex_app::{
    export::{self, Consent, Records},
    import::{self, Format, Options, Status, formats::onepassword_1pux},
};
use confidex_vault::{
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
};

fn scalar(kind: &str, key: &str, value: &str, hidden: bool) -> Entry {
    Entry {
        name: "Repeated".into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), value.into())]),
        extra: if hidden {
            Mapping::from([(
                "metadata".into(),
                Value::Map(vec![("protected".into(), true.into())]),
            )])
        } else {
            Mapping::new()
        },
    }
}
fn member<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .unwrap()
        .1
}
pub fn fixture() -> Record {
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "Public worker".into());
    record.tags = vec!["public".into(), "旅行".into()];
    record.entries.extend([
        scalar("text/v1", "text", "PUBLIC-HIDDEN-TEXT", true),
        scalar("username/v1", "username", "PUBLIC-HIDDEN-USER", true),
        scalar("url/v1", "url", "https://private.invalid/", true),
        scalar("secure-note/v1", "text", "line one\nline two", false),
        scalar("text/v1", "text", "", false),
    ]);
    record.entries.push(import::totp::entry("otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45").unwrap());
    for bytes in [vec![0, 255, 7], vec![]] {
        record.entries.push(Entry {
            name: "Repeated".into(),
            type_name: "file/v1".into(),
            value: Mapping::from([
                ("filename".into(), "same.bin".into()),
                ("data".into(), Value::Binary(bytes)),
            ]),
            extra: Mapping::new(),
        });
    }
    record.extra.insert(
        "confidex.sections".into(),
        Value::Map(vec![
            ("version".into(), 1u64.into()),
            (
                "groups".into(),
                Value::Array(
                    [("Empty", 0u64, 0u64), ("Repeated", 0, 8), ("Empty", 8, 0)]
                        .into_iter()
                        .map(|(name, start, count)| {
                            Value::Map(vec![
                                ("name".into(), name.into()),
                                ("start".into(), start.into()),
                                ("count".into(), count.into()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    );
    record
}
fn prepare(limits: export::Limits) -> (export::Plan, import::Memory) {
    let mut records = Records::new(limits).unwrap();
    records.push(fixture()).unwrap();
    let memory = records.memory().clone();
    let plan = export::prepare(
        records,
        Box::new(onepassword_1pux::Writer::new(1_735_689_600).unwrap()),
        &mut |_| true,
    )
    .unwrap();
    (plan, memory)
}

pub fn run() {
    let (plan, memory) = prepare(export::Limits::default());
    assert_eq!(plan.issues().len(), 3);
    for (index, issue) in plan.issues().iter().enumerate() {
        assert_eq!(issue.field, Some(index));
        assert_eq!(issue.code, export::Code::UnsupportedField);
    }
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Losses)
    );
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    let (plan, memory) = prepare(export::Limits::default());
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert_eq!(&artifact.bytes()[..4], b"PK\x03\x04");
    assert!(!artifact.file.encrypted);
    let mut options = Options::default();
    options.source_instance = Some("public-onepassword-worker".into());
    let imported = import::prepare(
        Format::Onepassword1pux,
        artifact.bytes(),
        &options,
        import::Limits::default(),
        &mut |_| true,
        onepassword_1pux::parse,
    )
    .unwrap();
    assert_eq!(imported.container_status, Status::Ready);
    assert_eq!(imported.items.len(), 1);
    assert_ne!(imported.items[0].status, Status::Blocked);
    let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.tags, ["public", "旅行"]);
    assert_eq!(record.entries.len(), 8);
    let layout = &record.extra["confidex.sections"];
    assert_eq!(member(layout, "version").as_u64(), Some(1));
    let groups: Vec<_> = member(layout, "groups")
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            (
                member(group, "name").as_str().unwrap(),
                member(group, "start").as_u64().unwrap(),
                member(group, "count").as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        groups,
        [("Empty", 0, 0), ("Repeated", 0, 8), ("Empty", 8, 0)]
    );
    for (index, value) in [
        "PUBLIC-HIDDEN-TEXT",
        "PUBLIC-HIDDEN-USER",
        "https://private.invalid/",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(record.entries[index].type_name, "secret/v1");
        assert_eq!(record.entries[index].value["secret"].as_str(), Some(*value));
    }
    assert_eq!(record.entries[3].type_name, "secure-note/v1");
    assert_eq!(
        record.entries[3].value["text"].as_str(),
        Some("line one\nline two")
    );
    assert_eq!(record.entries[4].value["text"].as_str(), Some(""));
    assert_eq!(record.entries[5].value, fixture().entries[5].value);
    assert_eq!(
        record.entries[6].value["data"].as_slice(),
        Some(&[0, 255, 7][..])
    );
    assert_eq!(record.entries[7].value["data"].as_slice(), Some(&[][..]));
    for index in [6, 7] {
        assert_eq!(
            record.entries[index].value["filename"].as_str(),
            Some("same.bin")
        );
    }
    drop(artifact);
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);

    let (plan, memory) = prepare(export::Limits::default());
    let mut started = false;
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |p| {
            if p.total == 2 && p.current == 1 {
                started = true;
                return false;
            }
            true
        })
        .err(),
        Some(export::Error::Canceled)
    );
    assert!(started);
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);

    let limits = export::Limits {
        output_bytes: 128,
        ..export::Limits::default()
    };
    let (plan, memory) = prepare(limits);
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true).err(),
        Some(export::Error::Limit)
    );
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
}
