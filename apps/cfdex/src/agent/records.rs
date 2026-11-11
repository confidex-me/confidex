use super::{Agent, ClientKeys, failure};
use crate::{
    protocol::{Code, Failure, Field, FieldInfo, MAX_PAYLOAD, Operation, Record, Reply},
    runtime,
};
use confidex_app::{Command, Draft, Engine, Output};
use confidex_storage::{SqliteStore, VaultId};
use std::{collections::BTreeSet, time::Instant};
use zeroize::Zeroizing;

impl Agent {
    pub(super) async fn records(
        &mut self,
        vault: VaultId,
        operation: &mut Operation,
        payload: &mut Zeroizing<Vec<u8>>,
    ) -> Result<Reply, Failure> {
        let session = self
            .sessions
            .get_mut(&vault)
            .ok_or_else(|| failure(confidex_app::Error::Locked))?;
        let engine = &mut session.engine;
        let store = &mut self.store;
        let reply = match operation {
            Operation::List {
                query,
                tag,
                after,
                refresh,
            } => {
                let (tag, after) = (tag.take(), after.take());
                let command = match query.take() {
                    Some(query) => Command::Search {
                        query,
                        tag,
                        after,
                        refresh: *refresh,
                    },
                    None => Command::List { tag, after },
                };
                match execute(engine, store, command).await? {
                    Output::Rows { rows, more, next } => Reply::Rows { rows, more, next },
                    Output::Indexing => Reply::Indexing {},
                    _ => unreachable!(),
                }
            }
            Operation::Fields { record } => {
                let draft = open(engine, store, record).await?;
                let fields = draft
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(index, field)| {
                        let mut keys: Vec<_> = field.values.keys().cloned().collect();
                        if let Some(key) = binary_key(field) {
                            keys.push(key.into());
                        }
                        FieldInfo {
                            index,
                            name: field.name.clone(),
                            type_name: field.type_name.clone(),
                            keys,
                            binary: field.data.is_some(),
                            opaque: field.opaque,
                        }
                    })
                    .collect();
                Reply::Fields { fields }
            }
            Operation::Get {
                record,
                field,
                value,
            } => {
                let draft = open(engine, store, record).await?;
                let (bytes, binary) = selected_value(&draft, field, value.as_deref())?;
                if bytes.len() > MAX_PAYLOAD {
                    return Err(problem(
                        Code::Input,
                        "The selected value exceeds the transfer limit.",
                    ));
                }
                payload.extend_from_slice(bytes);
                Reply::Value {
                    binary,
                    length: bytes.len(),
                }
            }
            _ => unreachable!(),
        };
        session.used = Instant::now();
        Ok(reply)
    }
}

async fn execute(
    engine: &mut Engine,
    store: &mut SqliteStore,
    command: Command,
) -> Result<Output, Failure> {
    engine
        .execute(
            store,
            &mut ClientKeys,
            &mut confidex_app::Request {
                generation: 0,
                command,
            },
        )
        .await
        .result
        .map_err(failure)
}

async fn open(
    engine: &mut Engine,
    store: &mut SqliteStore,
    record: &Record,
) -> Result<Draft, Failure> {
    let missing = || problem(Code::NotFound, "The record or revision was not found.");
    let id = match runtime::id::<16>(&record.selector) {
        Some(id) => id,
        None => {
            let mut ids = BTreeSet::new();
            let mut after = None;
            loop {
                let Output::Rows { rows, more, next } =
                    execute(engine, store, Command::List { after, tag: None }).await?
                else {
                    unreachable!()
                };
                for row in rows.iter().filter(|row| row.title == record.selector) {
                    ids.insert(row.head.record);
                    if ids.len() == 16 {
                        break;
                    }
                }
                if !more || ids.len() == 16 {
                    break;
                }
                after = next;
            }
            if ids.len() > 1 {
                let candidates: Vec<_> = ids.iter().map(|id| runtime::hex(id)).collect();
                return Err(Failure {
                    code: Code::Ambiguous,
                    message: format!(
                        "Several records have that title. Use a record ID. Candidates (up to 16): {}",
                        candidates.join(", ")
                    ),
                });
            }
            ids.pop_first().ok_or_else(missing)?
        }
    };
    let command = match record.revision {
        Some(revision) => Command::OpenRevision {
            record: id,
            revision,
        },
        None => Command::Open { record: id },
    };
    match execute(engine, store, command).await {
        Ok(Output::Draft(draft)) => Ok(draft),
        Ok(_) => unreachable!(),
        Err(error) if error.code == Code::Input => Err(missing()),
        Err(error) => Err(error),
    }
}

fn binary_key(field: &confidex_app::Field) -> Option<&'static str> {
    field.data.as_ref()?;
    confidex_app::data_key(&field.type_name)
}

fn selected_value<'a>(
    draft: &'a Draft,
    selector: &Field,
    key: Option<&str>,
) -> Result<(&'a [u8], bool), Failure> {
    let missing = || problem(Code::NotFound, "The field or value was not found.");
    let field = match selector {
        Field::Index(index) => draft.fields.get(*index).ok_or_else(missing)?,
        Field::Name(name) if !name.is_empty() => {
            let mut matches = draft.fields.iter().filter(|field| &field.name == name);
            let field = matches.next().ok_or_else(missing)?;
            if matches.next().is_some() {
                return Err(problem(
                    Code::Ambiguous,
                    "Several fields have that name. Specify --field-index.",
                ));
            }
            field
        }
        Field::Name(_) => {
            return Err(problem(
                Code::Input,
                "Specify --field-index for an unnamed field.",
            ));
        }
    };
    let binary = binary_key(field);
    let key = match key {
        Some(key) => key,
        None => match field.values.len() + usize::from(binary.is_some()) {
            0 => return Err(problem(Code::Input, "This field has no supported value.")),
            1 => field
                .values
                .keys()
                .next()
                .map(String::as_str)
                .or(binary)
                .unwrap(),
            _ => {
                return Err(problem(
                    Code::Input,
                    "This field has several value keys. Specify --value.",
                ));
            }
        },
    };
    if binary == Some(key) {
        Ok((field.data.as_ref().unwrap(), true))
    } else {
        let text = field.values.get(key).ok_or_else(missing)?;
        Ok((text.as_bytes(), false))
    }
}

fn problem(code: Code, message: &str) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}
