use confidex_app::import::{self, Format, Limits, Options, formats};
use confidex_vault::{
    record::{Entry, Value},
    resources::MAX_OPEN_MEMORY,
};

fn protected(entry: &Entry) -> bool {
    entry
        .extra
        .get("metadata")
        .and_then(Value::as_map)
        .is_some_and(|pairs| {
            pairs
                .iter()
                .any(|(k, v)| k.as_str() == Some("protected") && v.as_bool() == Some(true))
        })
}

#[test]
fn xml_pool_inline_and_reference_protection_reach_active_fields() {
    let source = br#"<KeePassFile><Meta><Binaries>
      <Binary ID="0" ProtectInMemory="True">AP8=</Binary>
      <Binary ID="1">AQI=</Binary></Binaries></Meta><Root><Group>
      <UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Name>Public</Name><Entry>
      <UUID>AgICAgICAgICAgICAgICAg==</UUID>
      <Binary><Key>pool.bin</Key><Value Ref="0"/></Binary>
      <Binary><Key>reference.bin</Key><Value Ref="1" ProtectInMemory="True"/></Binary>
      <Binary><Key>inline.bin</Key><Value ProtectInMemory="True">AwQ=</Value></Binary>
      <Binary><Key>ordinary.bin</Key><Value>BQY=</Value></Binary>
      </Entry></Group></Root></KeePassFile>"#;
    let plan = import::prepare(
        Format::KeepassXml,
        source,
        &Options::default(),
        Limits::default(),
        &mut |_| true,
        formats::keepass_xml::parse,
    )
    .unwrap();
    let record = plan.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries.len(), 4);
    for (entry, (bytes, hidden)) in record.entries.iter().zip([
        ([0, 255], true),
        ([1, 2], true),
        ([3, 4], true),
        ([5, 6], false),
    ]) {
        assert_eq!(entry.value["data"].as_slice(), Some(bytes.as_slice()));
        assert_eq!(protected(entry), hidden);
    }
}

#[test]
fn kdbx_pool_protection_reaches_active_fields() {
    let source = include_bytes!("../../../vendor/keepass/tests/resources/bounded/argon2d-aes.kdbx");
    let mut options = Options::default();
    options.password_present = true;
    options.password = "PUBLIC-VARIANT-DATABASE".into();
    let raw = keepass::bounded::Raw::open(
        source,
        Some(&options.password),
        None,
        keepass::bounded::Limits::default(),
        &mut |_, _| true,
    )
    .unwrap();
    let plan = import::prepare(
        Format::Kdbx,
        source,
        &options,
        Limits::default(),
        &mut |_| true,
        formats::kdbx::parse,
    )
    .unwrap();
    let mut hidden = 0;
    for item in &plan.items {
        let record = item.record(MAX_OPEN_MEMORY).unwrap();
        for entry in record.entries.iter().filter(|e| e.type_name == "file/v1") {
            let bytes = entry.value["data"].as_slice().unwrap();
            let binary = (0..raw.binary_count())
                .map(|i| raw.binary(i).unwrap())
                .find(|b| b.bytes == bytes)
                .unwrap();
            assert_eq!(protected(entry), binary.protected);
            hidden += usize::from(binary.protected);
        }
    }
    assert!(hidden > 0);
}
