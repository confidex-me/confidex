//! Public current records, shared by native, WASI and browser checks.
use confidex_app::{
    export::{self, Consent, Records},
    import::{
        self, Format, Options,
        formats::{
            bitwarden_encrypted_json,
            bitwarden_json::{self, Profile},
        },
    },
};
use confidex_vault::{
    record::{Entry, Mapping, Record},
    resources::MAX_OPEN_MEMORY,
};
pub const PASSWORD: &str = " Public export 密码 é e\u{301} ";
pub fn options() -> export::Options {
    export::Options::Password {
        password: Some(PASSWORD.into()),
        keyfile: None,
    }
}
pub fn field(name: &str, kind: &str, key: &str, text: &str) -> Entry {
    Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), text.into())]),
        extra: Mapping::new(),
    }
}
pub fn records() -> Vec<Record> {
    let imported = import::prepare(
        Format::BitwardenJson,
        include_bytes!("../export_fixtures/bitwarden_json/card-identity.input.json"),
        &Options::default(),
        import::Limits::default(),
        &mut |_| true,
        bitwarden_json::parse,
    )
    .unwrap();
    let card = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    let mut identity = imported.items[1].record(MAX_OPEN_MEMORY).unwrap();
    identity
        .entries
        .iter_mut()
        .find(|e| e.name == "Email")
        .unwrap()
        .value
        .insert("text".into(), "current@example.invalid".into());
    identity.entries.retain(|e| e.name != "Passport number");
    identity.extra.insert(
        "confidex.import.origin".into(),
        "PUBLIC-OLD-ID old@example.invalid".into(),
    );
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "Public current login".into());
    record.tags = vec!["Shared".into(), "Second".into()];
    record.entries = vec![
        field("Username","username/v1","username","public-user"),
        field("Password","password/v1","password","PUBLIC-CURRENT\r\n第二行"),
        field("URL","url/v1","url","https://one.invalid/"),
        field("URL","url/v1","url","https://two.invalid/?a=1&b=2"),
        import::totp::entry("otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45").unwrap(),
        field("Notes","secure-note/v1","text","Public notes\r\n<&>"),
        field("","text/v1","text",""),
        field("Same","text/v1","text","line one\n\"line two\"\\公開"),
        field("Same","secret/v1","secret","PUBLIC-HIDDEN"),
    ];
    vec![card, identity, record]
}
pub fn plan(
    profile: Profile,
    values: Vec<Record>,
    limits: export::Limits,
) -> (export::Plan, import::Memory) {
    let mut records = Records::new(limits).unwrap();
    for record in values {
        records.push(record).unwrap();
    }
    let memory = records.memory().clone();
    (
        export::prepare(
            records,
            Box::new(bitwarden_encrypted_json::Writer::new(profile, options()).unwrap()),
            &mut |_| true,
        )
        .unwrap(),
        memory,
    )
}
pub fn imported(bytes: &[u8], password: &str) -> Result<import::Plan, import::Error> {
    let mut options = Options::default();
    options.password = password.into();
    options.source_instance = Some("public-encrypted-export".into());
    import::prepare(
        Format::BitwardenEncryptedJson,
        bytes,
        &options,
        import::Limits::default(),
        &mut |_| true,
        bitwarden_encrypted_json::parse,
    )
}
pub fn artifact(profile: Profile) -> Result<Vec<u8>, export::Error> {
    let (plan, memory) = plan(profile, records(), export::Limits::default());
    let result = plan
        .write(Consent::AllowLosses, &mut |_| true)
        .map(|a| a.bytes().to_vec());
    assert_eq!(memory.available(), export::Limits::default().memory_bytes);
    result
}
pub fn run() {
    for profile in [Profile::Personal, Profile::Organization] {
        let (encrypted, memory) = plan(profile, records(), export::Limits::default());
        let mut snapshot = Records::new(export::Limits::default()).unwrap();
        for record in records() {
            snapshot.push(record).unwrap();
        }
        let plain = export::prepare(
            snapshot,
            Box::new(bitwarden_json::Writer::new(profile)),
            &mut |_| true,
        )
        .unwrap();
        assert_eq!(encrypted.issues(), plain.issues());
        assert!(encrypted.file().encrypted && !plain.file().encrypted);
        let mut previous = 0;
        let encrypted = encrypted
            .write(Consent::AllowLosses, &mut |p| {
                assert!(p.current >= previous);
                previous = p.current;
                true
            })
            .unwrap();
        let plain = plain.write(Consent::AllowLosses, &mut |_| true).unwrap();
        let restored = imported(encrypted.bytes(), PASSWORD).unwrap();
        let expected = import::prepare(
            Format::BitwardenJson,
            plain.bytes(),
            &Options::default(),
            import::Limits::default(),
            &mut |_| true,
            bitwarden_json::parse,
        )
        .unwrap();
        assert_eq!(restored.items.len(), 3);
        for (actual, expected) in restored.items.iter().zip(expected.items.iter()) {
            assert_eq!(actual.record_bytes(), expected.record_bytes());
            assert_eq!(
                actual.source_attributes_bytes(),
                expected.source_attributes_bytes()
            );
            assert_eq!(actual.status, expected.status);
            assert_eq!(actual.diagnostics, expected.diagnostics);
        }
        drop(encrypted);
        assert_eq!(memory.available(), export::Limits::default().memory_bytes);
    }
}
