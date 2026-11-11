use crate::import::{Code, Diagnostic, Error, ErrorKind, Item, Location, Source, Status};
use confidex_vault::record::{Entry, Mapping, Record, Value};

pub const TARGETS: &[&str] = &[
    "title",
    "username/v1",
    "password/v1",
    "url/v1",
    "text/v1",
    "secret/v1",
    "note/v1",
    "secure-note/v1",
    "totp/v1",
];
pub(super) fn key(target: &str) -> Option<&'static str> {
    Some(match target {
        "username/v1" => "username",
        "password/v1" => "password",
        "url/v1" => "url",
        "text/v1" | "note/v1" | "secure-note/v1" => "text",
        "secret/v1" | "totp/v1" => "secret",
        _ => return None,
    })
}
pub(super) fn item(index: usize, row: usize, span: std::ops::Range<usize>) -> Item {
    Item {
        source: Source {
            instance: None,
            account: None,
            vault: None,
            item: None,
            locator: index,
        },
        record: Record {
            extra: Mapping::from([("confidex.title".into(), "Imported record".into())]),
            entries: Vec::new(),
            tags: Vec::new(),
        },
        source_attributes: Mapping::from([
            ("row".into(), (row as u64).into()),
            (
                "span".into(),
                Value::Array(vec![(span.start as u64).into(), (span.end as u64).into()]),
            ),
        ]),
        status: Status::Ready,
        diagnostics: Vec::new(),
    }
}
pub(super) fn field(
    item: &mut Item,
    column: usize,
    target: &str,
    name: &str,
    value: &str,
    explicit: bool,
) -> Result<(), Error> {
    if target == "title" {
        item.record
            .extra
            .insert("confidex.title".into(), value.into());
        return Ok(());
    }
    let mut entry = if target == "totp/v1" {
        if value.is_empty() {
            let empty = item
                .source_attributes
                .entry("empty_totp_columns".into())
                .or_insert_with(|| Value::Array(Vec::new()));
            let Value::Array(columns) = empty else {
                unreachable!()
            };
            columns.push((column as u64).into());
            return Ok(());
        }
        if let Some(mut entry) = crate::import::totp::entry(value) {
            entry.name = name.into();
            entry
        } else {
            issue(item, Code::UnsupportedFeature, column);
            issue(item, Code::SourceDataPreserved, column);
            crate::import::protected_original(name, value)
        }
    } else {
        let key = key(target).ok_or(ErrorKind::InvalidOptions)?;
        Entry {
            name: name.into(),
            type_name: target.into(),
            value: Mapping::from([(key.into(), value.into())]),
            extra: Mapping::new(),
        }
    };
    if target == "secret/v1" {
        entry.extra.insert(
            "metadata".into(),
            Value::Map(vec![("protected".into(), true.into())]),
        );
    }
    entry
        .extra
        .insert("confidex.import.csv.column".into(), (column as u64).into());
    item.record.entries.push(entry);
    if !explicit {
        issue(item, Code::SourceDataPreserved, column);
    }
    Ok(())
}
fn issue(item: &mut Item, code: Code, column: usize) {
    item.status = Status::Review;
    item.diagnostics.push(Diagnostic {
        code,
        location: Location {
            item: Some(item.source.locator),
            field: Some(column),
            offset: None,
        },
    });
}
