use crate::{
    protocol::{self, Code, Failure, Operation, Reply, Request},
    runtime::{self, Location},
};
use clap::{Parser, Subcommand};
use std::{
    io::{self, Write},
    path::PathBuf,
};

mod records;
mod sync;

#[derive(Parser)]
#[command(name = "cfdex", version = confidex_app::BUILD_VERSION, about = "Read local Confidex vaults without the GUI", color = clap::ColorChoice::Never)]
pub struct Args {
    #[arg(long, global = true)]
    pub database: Option<PathBuf>,
    #[arg(long, global = true)]
    pub vault: Option<String>,
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Action,
}
#[derive(Subcommand)]
pub enum Action {
    /// List local vaults without secret values.
    Vaults,
    /// Select, create, or connect a vault.
    Init(crate::setup::Init),
    /// Show the selected vault's CLI session state.
    Status,
    /// Lock the selected CLI session.
    Lock,
    /// Unlock with hidden terminal input or explicit JSON credentials.
    Unlock {
        #[arg(long)]
        credentials_stdin: bool,
    },
    /// List or search local records.
    List {
        query: Option<String>,
        #[arg(long)]
        tag: Option<String>,
    },
    /// List a record's field names, types, and value keys.
    Fields(records::RecordArgs),
    /// Read one explicitly selected field value.
    Get(records::Get),
    /// Synchronize the selected unlocked vault.
    Sync,
    #[command(hide = true)]
    Agent {
        #[arg(long)]
        stop: bool,
        #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..=900))]
        idle_timeout: u64,
    },
}

fn request(vault: Option<confidex_storage::VaultId>, command: Operation) -> Request {
    Request {
        version: protocol::VERSION,
        id: 1,
        vault,
        command,
    }
}

pub(crate) fn call(
    location: &Location,
    vault: Option<confidex_storage::VaultId>,
    command: Operation,
) -> Result<(Reply, zeroize::Zeroizing<Vec<u8>>), Failure> {
    let (response, payload) = location
        .call(&request(vault, command), true)
        .map_err(runtime::protocol_failure)?;
    Ok((response.result?, payload))
}

pub fn run(args: Args) -> Result<(), Failure> {
    let database = args
        .database
        .map(Ok)
        .unwrap_or_else(confidex_native::database_path)
        .map_err(runtime::io_failure)?;
    let location = Location::new(database).map_err(runtime::io_failure)?;
    if let Action::Agent { stop, idle_timeout } = args.command {
        if !stop {
            return crate::agent::serve(location, std::time::Duration::from_secs(idle_timeout))
                .map_err(runtime::io_failure);
        }
        return match location.call(&request(None, Operation::Stop {}), false) {
            Ok((response, _)) => response.result.map(|_| ()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(runtime::protocol_failure(error)),
        };
    }
    let (response, _) = location
        .call(&request(None, Operation::Vaults {}), true)
        .map_err(runtime::protocol_failure)?;
    let Reply::Vaults { vaults } = response.result? else {
        return Err(Failure {
            code: Code::Protocol,
            message: "Unexpected catalog response.".into(),
        });
    };
    if matches!(args.command, Action::Vaults) {
        if args.json {
            let rows: Vec<_> = vaults
                .iter()
                .map(|vault| serde_json::json!({"id":runtime::hex(&vault.id),"name":vault.name}))
                .collect();
            return json(&rows);
        }
        let mut stdout = io::stdout().lock();
        for vault in vaults {
            writeln!(stdout, "{}\t{}", runtime::hex(&vault.id), safe(&vault.name))
                .map_err(runtime::io_failure)?;
        }
        return Ok(());
    }
    if let Action::Init(options) = args.command {
        return crate::setup::init(&location, &vaults, options, args.json);
    }
    let selected = match args.vault {
        Some(selector) => crate::setup::select(&vaults, &selector)?,
        None => crate::setup::read_default(&location)?,
    };
    let operation = match args.command {
        Action::List { query, tag } => {
            return records::list(&location, selected, query, tag, args.json);
        }
        Action::Fields(record) => {
            return records::fields(&location, selected, record, args.json);
        }
        Action::Get(options) => return records::get(&location, selected, options, args.json),
        Action::Sync => return sync::run(&location, selected, args.json),
        Action::Status => Operation::Status {},
        Action::Lock => Operation::Lock {},
        Action::Unlock { credentials_stdin } => Operation::Unlock {
            credentials: crate::credentials::unlock(selected, credentials_stdin)?,
        },
        _ => unreachable!(),
    };
    let (response, _) = location
        .call(&request(Some(selected), operation), true)
        .map_err(runtime::protocol_failure)?;
    match response.result? {
        Reply::Status { unlocked } => {
            if args.json {
                json(&serde_json::json!({"unlocked":unlocked}))
            } else {
                writeln!(
                    io::stdout().lock(),
                    "{}",
                    if unlocked { "unlocked" } else { "locked" }
                )
                .map_err(runtime::io_failure)
            }
        }
        Reply::Locked { .. } | Reply::Opened { .. } => {
            if args.json {
                json(&serde_json::json!({"ok":true}))
            } else {
                Ok(())
            }
        }
        _ => Err(Failure {
            code: Code::Protocol,
            message: "Unexpected agent response.".into(),
        }),
    }
}

pub fn json(result: &impl serde::Serialize) -> Result<(), Failure> {
    #[derive(serde::Serialize)]
    struct Envelope<'a, T: serde::Serialize> {
        version: u8,
        result: &'a T,
    }
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &Envelope { version: 1, result }).map_err(|_| Failure {
        code: Code::Io,
        message: "Cannot write output.".into(),
    })?;
    writeln!(stdout).map_err(runtime::io_failure)
}
pub fn safe(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            result.extend(ch.escape_default());
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_preserves_unicode_and_escapes_terminal_control_characters() {
        let safe = safe("Русский vault\t\x1b[31m\n");
        assert!(safe.starts_with("Русский vault"));
        assert!(!safe.chars().any(char::is_control));
        assert!(safe.contains("\\t"));
        assert!(safe.contains("\\n"));
    }
}
