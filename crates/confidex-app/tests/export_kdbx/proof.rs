//! Current public records through the same writer on native, WASI and browser.
pub(super) use super::keepass_common as common;
use confidex_app::{
    export::{self, Consent},
    import::{self, Format, Options, formats::kdbx},
};
use confidex_vault::{
    record::{Record, Value},
    resources::MAX_OPEN_MEMORY,
};
pub const PASSWORD: &str = "PUBLIC-KDBX-EXPORT";
pub const KEY: [u8; 32] = [7; 32];

pub fn fixture() -> Record {
    let mut record = common::fixture();
    record
        .extra
        .insert("confidex.title".into(), "Public KDBX".into());
    record.entries[9].extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    record.entries[7].extra.insert("confidex.import.totp".into(),Value::Map(vec![("uri".into(),
        "otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45".into())]));
    record
}
pub fn credentials(mode: usize) -> export::Options {
    export::Options::Password {
        password: match mode {
            1 => None,
            3 | 4 => Some(String::new()),
            _ => Some(PASSWORD.into()),
        },
        keyfile: matches!(mode, 1 | 2 | 4).then(|| KEY.to_vec()),
    }
}
pub fn plan(record: Record, mode: usize, limits: export::Limits) -> (export::Plan, import::Memory) {
    let mut records = export::Records::new(limits).unwrap();
    records.push(record).unwrap();
    let memory = records.memory().clone();
    (
        export::prepare(
            records,
            Box::new(kdbx::Writer::new(1_735_689_600, credentials(mode)).unwrap()),
            &mut |_| true,
        )
        .unwrap(),
        memory,
    )
}
pub fn imported(bytes: &[u8], mode: usize) -> import::Plan {
    let export::Options::Password { password, keyfile } = &credentials(mode) else {
        unreachable!()
    };
    let options = Options {
        password: password.clone().unwrap_or_default(),
        keyfile: keyfile.clone().unwrap_or_default(),
        password_present: password.is_some(),
        keyfile_present: keyfile.is_some(),
        source_instance: Some("public-kdbx-writer".into()),
        include_archived: false,
        include_deleted: false,
        csv: None,
    };
    import::prepare(
        Format::Kdbx,
        bytes,
        &options,
        import::Limits::default(),
        &mut |_| true,
        kdbx::parse,
    )
    .unwrap()
}
pub fn run() {
    drop(artifact(0).unwrap());
    for mode in 0..5 {
        let expected = fixture();
        let (plan, memory) = plan(fixture(), mode, export::Limits::default());
        assert!(
            !plan
                .issues()
                .iter()
                .any(|i| i.severity == export::Severity::Blocked)
        );
        let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
        assert!(artifact.file.encrypted);
        assert_eq!(artifact.file.name, "confidex.kdbx");
        assert!(
            !artifact
                .bytes()
                .windows(b"PUBLIC-PASSWORD".len())
                .any(|part| part == b"PUBLIC-PASSWORD")
        );
        let result = imported(artifact.bytes(), mode);
        assert_eq!(result.items.len(), 1);
        let current = result.items[0].record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            current.extra["confidex.title"],
            expected.extra["confidex.title"]
        );
        assert_eq!(current.tags, expected.tags);
        assert_eq!(current.entries.len(), expected.entries.len());
        for (actual, expected) in current.entries.iter().zip(&expected.entries) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.type_name, expected.type_name);
            assert_eq!(actual.value, expected.value);
        }
        for index in [0, 2, 9] {
            assert!(
                current.entries[index].extra["metadata"]
                    .as_map()
                    .unwrap()
                    .iter()
                    .any(|(k, v)| k.as_str() == Some("protected") && v.as_bool() == Some(true))
            );
        }
        drop(artifact);
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
    for (output_bytes, cancel_at) in [(128, usize::MAX), (64 << 20, 3), (64 << 20, 15)] {
        let (plan, memory) = plan(
            fixture(),
            0,
            export::Limits {
                output_bytes,
                ..export::Limits::default()
            },
        );
        let mut callbacks = 0;
        let result = plan.write(Consent::AllowLosses, &mut |_| {
            callbacks += 1;
            callbacks < cancel_at
        });
        assert_eq!(
            result.err(),
            Some(if cancel_at == usize::MAX {
                export::Error::Limit
            } else {
                export::Error::Canceled
            })
        );
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
}

pub fn artifact(mode: usize) -> Result<export::Artifact, export::Error> {
    let mut records = export::Records::new(export::Limits::default())?;
    records.push(fixture())?;
    let memory = records.memory().clone();
    let result = (move || {
        let writer = kdbx::Writer::new(1_735_689_600, credentials(mode))?;
        export::prepare(records, Box::new(writer), &mut |_| true)?
            .write(Consent::AllowLosses, &mut |_| true)
    })();
    if result.is_err() {
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
    result
}
