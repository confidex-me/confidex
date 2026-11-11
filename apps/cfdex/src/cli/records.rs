use super::{call, json, safe};
use crate::{
    protocol::{Code, Failure, Field, MAX_HEADER, Operation, Record, Reply},
    runtime::{self, Location},
};
use clap::Args;
use confidex_storage::VaultId;
use serde::Serialize;
use std::{
    io::{self, Write},
    path::PathBuf,
};

#[derive(Args)]
pub struct RecordArgs {
    /// Record ID or exact title.
    record: String,
    /// Select a specific branch by revision ID.
    #[arg(long)]
    revision: Option<String>,
}

impl RecordArgs {
    fn parse(self) -> Result<Record, Failure> {
        Ok(Record {
            selector: self.record,
            revision: self
                .revision
                .map(|text| {
                    runtime::id::<32>(&text).ok_or(Failure {
                        code: Code::Input,
                        message: "A revision ID must contain 64 hexadecimal digits.".into(),
                    })
                })
                .transpose()?,
        })
    }
}

#[derive(Args)]
#[group(id = "field_selector", required = true, multiple = false)]
struct Selector {
    #[arg(long)]
    field: Option<String>,
    #[arg(long)]
    field_index: Option<usize>,
}

#[derive(Args)]
pub struct Get {
    #[command(flatten)]
    record: RecordArgs,
    #[command(flatten)]
    selector: Selector,
    /// Select one key of a structured field.
    #[arg(long)]
    value: Option<String>,
    /// Write binary data to a new private file.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Serialize)]
struct Row<'a> {
    id: String,
    revision: String,
    title: &'a str,
    fields: usize,
    tags: &'a [String],
}

pub(super) fn list(
    location: &Location,
    vault: VaultId,
    query: Option<String>,
    tag: Option<String>,
    structured: bool,
) -> Result<(), Failure> {
    let mut result = Vec::new();
    let mut bytes = 0;
    let mut after = None;
    let mut refresh = true;
    loop {
        let (reply, _) = call(
            location,
            Some(vault),
            Operation::List {
                query: query.clone(),
                tag: tag.clone(),
                after: after.clone(),
                refresh,
            },
        )?;
        refresh = false;
        match reply {
            Reply::Indexing {} => continue,
            Reply::Rows { rows, more, next } => {
                for row in &rows {
                    bytes += std::mem::size_of_val(row)
                        + row.title.len()
                        + row
                            .tags
                            .iter()
                            .map(|tag| std::mem::size_of_val(tag) + tag.len())
                            .sum::<usize>();
                    if bytes > MAX_HEADER {
                        return Err(Failure {
                            code: Code::Input,
                            message: "The list exceeds the output limit. Narrow the query or filter by tag.".into(),
                        });
                    }
                }
                result.extend(rows);
                if !more {
                    break;
                }
                if next.is_none() || next <= after {
                    return Err(unexpected());
                }
                after = next;
            }
            _ => return Err(unexpected()),
        }
    }
    if structured {
        let rows: Vec<_> = result
            .iter()
            .map(|row| Row {
                id: runtime::hex(&row.head.record),
                revision: runtime::hex(&row.head.revision),
                title: &row.title,
                fields: row.fields,
                tags: &row.tags,
            })
            .collect();
        return json(&rows);
    }
    let mut stdout = io::stdout().lock();
    for row in result {
        writeln!(
            stdout,
            "{}\t{}\t{}",
            runtime::hex(&row.head.record),
            runtime::hex(&row.head.revision),
            safe(&row.title)
        )
        .map_err(runtime::io_failure)?;
    }
    Ok(())
}

pub(super) fn fields(
    location: &Location,
    vault: VaultId,
    record: RecordArgs,
    structured: bool,
) -> Result<(), Failure> {
    let (reply, _) = call(
        location,
        Some(vault),
        Operation::Fields {
            record: record.parse()?,
        },
    )?;
    let Reply::Fields { fields } = reply else {
        return Err(unexpected());
    };
    if structured {
        return json(&fields);
    }
    let mut stdout = io::stdout().lock();
    for field in fields {
        let keys: Vec<_> = field.keys.iter().map(|key| safe(key)).collect();
        writeln!(
            stdout,
            "{}\t{}\t{}\t{}",
            field.index,
            safe(&field.name),
            safe(&field.type_name),
            keys.join(", ")
        )
        .map_err(runtime::io_failure)?;
    }
    Ok(())
}

pub(super) fn get(
    location: &Location,
    vault: VaultId,
    options: Get,
    structured: bool,
) -> Result<(), Failure> {
    let field = match options.selector.field {
        Some(name) => Field::Name(name),
        None => Field::Index(
            options
                .selector
                .field_index
                .expect("required field selector"),
        ),
    };
    let (reply, payload) = call(
        location,
        Some(vault),
        Operation::Get {
            record: options.record.parse()?,
            field,
            value: options.value,
        },
    )?;
    let Reply::Value { binary, length } = reply else {
        return Err(unexpected());
    };
    match (binary, options.output) {
        (true, Some(path)) => {
            let mut file = runtime::private_file(&path).map_err(runtime::io_failure)?;
            file.write_all(&payload)
                .and_then(|()| file.sync_all())
                .map_err(runtime::io_failure)?;
            if structured {
                json(&serde_json::json!({"bytes": length}))
            } else {
                Ok(())
            }
        }
        (false, None) => {
            if structured {
                json(&std::str::from_utf8(&payload).map_err(|_| unexpected())?)
            } else {
                let mut stdout = io::stdout().lock();
                stdout
                    .write_all(&payload)
                    .and_then(|()| stdout.flush())
                    .map_err(runtime::io_failure)
            }
        }
        _ => Err(Failure {
            code: Code::Input,
            message: "Use --output only for a selected binary value.".into(),
        }),
    }
}

fn unexpected() -> Failure {
    Failure {
        code: Code::Protocol,
        message: "Unexpected record response.".into(),
    }
}
