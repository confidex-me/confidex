//! Public record fields shared by the XML and KDBX writer checks.
use confidex_app::import;
use confidex_vault::record::{Entry, Mapping, Record, Value};

pub fn field(name: &str, kind: &str, key: &str, value: &str) -> Entry {
    Entry {
        name: name.into(),
        type_name: kind.into(),
        value: Mapping::from([(key.into(), value.into())]),
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
pub fn fixture() -> Record {
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "Public XML".into());
    record.tags = vec!["Work".into(), "旅行".into()];
    record.entries.extend([
        field("UserName", "username/v1", "username", "public-user"),
        field("Password", "password/v1", "password", "PUBLIC-PASSWORD"),
        field("URL", "url/v1", "url", "https://one.invalid/?a=1&b=2"),
        field("Notes", "secure-note/v1", "text", "line one\r\n<&>\"'公開"),
        field("Hidden", "secret/v1", "secret", "PUBLIC-HIDDEN"),
        field("Empty", "text/v1", "text", ""),
        field("Unicode <&>", "text/v1", "text", "\tCR\rLF\n🙂"),
    ]);
    let mut otp = import::totp::entry("otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45").unwrap();
    otp.name = "otp".into();
    record.entries.push(otp);
    record
        .entries
        .push(field("", "text/v1", "text", "PUBLIC-EMPTY-NAME"));
    for (name, bytes) in [("sample.bin", &[0, 255, 7][..]), ("empty.bin", &[][..])] {
        record.entries.push(file(name, bytes));
    }
    for index in [0, 2] {
        record.entries[index].extra.insert(
            "metadata".into(),
            Value::Map(vec![("protected".into(), true.into())]),
        );
    }
    record
}
