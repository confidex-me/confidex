use confidex_app::import::{self, CsvColumn, CsvMapping, Format, Limits, Options, Plan};
pub const ROWS: usize = 10_000;
pub fn source() -> String {
    use std::fmt::Write;
    let mut source = String::with_capacity(4 << 20);
    source.push_str("Title,URL,Username,Password,Notes,Extra,Extra,,otp,Public,Custom\r\n");
    for index in 0..ROWS {
        write!(source,"Public {index},https://example.invalid/a?x={index}&x=2,user{index},PASSWORD{index},\"Примечание {index}\r\nSecond line\",public{index},HIDDEN{index},,GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ,\"He said \"\"hello\"\", {index}\",SECRET{index}\r\n").unwrap();
    }
    source.shrink_to_fit();
    source
}
pub fn plan(input: &[u8]) -> Plan {
    plan_with(input, &mut |_| true)
}
pub fn plan_with(input: &[u8], callback: &mut dyn FnMut(import::Progress) -> bool) -> Plan {
    let options = Options {
        source_instance: Some("public-fixture-source".into()),
        password: String::new(),
        keyfile: Vec::new(),
        password_present: false,
        keyfile_present: false,
        include_archived: false,
        include_deleted: false,
        csv: Some(CsvMapping {
            delimiter: b',',
            header: true,
            columns: [
                (0, "title", ""),
                (1, "url/v1", "URL"),
                (2, "username/v1", "User"),
                (3, "password/v1", "Password"),
                (4, "secure-note/v1", "Notes"),
                (5, "text/v1", "Extra"),
                (6, "secret/v1", "Extra"),
                (7, "text/v1", ""),
                (8, "totp/v1", "otp"),
                (9, "note/v1", "Public"),
                (10, "secret/v1", "Custom"),
            ]
            .into_iter()
            .map(|(index, target, name)| CsvColumn {
                index,
                target: target.into(),
                name: name.into(),
            })
            .collect(),
        }),
    };
    import::prepare(
        Format::Csv,
        input,
        &options,
        Limits::default(),
        callback,
        import::formats::csv::parse,
    )
    .unwrap()
}
