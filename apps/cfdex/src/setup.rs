use crate::{
    agent::DEFAULT_SERVER,
    cli, credentials,
    protocol::{Code, Credentials, Failure, Operation, Reply},
    runtime::{self, Location},
};
use confidex_app::DeviceKeys;
use confidex_storage::{VaultId, VaultInfo};
use std::{
    fs::File,
    io::{self, BufRead, IsTerminal, Read, Write},
    path::PathBuf,
};

#[derive(clap::Args)]
pub struct Init {
    #[arg(long, group = "setup_action")]
    select: Option<String>,
    #[arg(long, group = "setup_action")]
    create: Option<String>,
    #[arg(long, group = "setup_action")]
    connect: Option<String>,
    #[arg(long, requires = "create")]
    key_output: Option<PathBuf>,
    #[arg(long, requires = "connect")]
    server: Option<String>,
    #[arg(long, conflicts_with = "select")]
    credentials_stdin: bool,
}

enum Action {
    Select(String),
    Create { name: String, key_output: PathBuf },
    Connect { name: String, server: String },
}

pub fn init(
    location: &Location,
    vaults: &[VaultInfo],
    options: Init,
    json: bool,
) -> Result<(), Failure> {
    let interactive = io::stdin().is_terminal() && !options.credentials_stdin;
    let action = if let Some(selector) = options.select {
        Action::Select(selector)
    } else if let Some(name) = options.create {
        let key_output = match options.key_output {
            Some(path) => path,
            None if interactive => line("Separate secret key file")?.into(),
            None => return Err(input("Specify --key-output PATH when creating a vault.")),
        };
        Action::Create { name, key_output }
    } else if let Some(name) = options.connect {
        Action::Connect {
            name,
            server: options.server.unwrap_or_else(|| DEFAULT_SERVER.into()),
        }
    } else if interactive {
        wizard(vaults)?
    } else {
        return Err(input("Specify --select, --create, or --connect."));
    };
    let (id, remembered) = match action {
        Action::Select(selector) => (select(vaults, &selector)?, None),
        Action::Create { name, key_output } => {
            let credentials = setup_credentials(options.credentials_stdin, true)?;
            let key_output = std::path::absolute(key_output).map_err(runtime::io_failure)?;
            let (reply, key) = cli::call(
                location,
                None,
                Operation::Create {
                    name,
                    credentials,
                    key_output,
                },
            )?;
            let Reply::Created { vault, .. } = reply else {
                return Err(unexpected());
            };
            let key = std::str::from_utf8(&key).map_err(|_| unexpected())?;
            (vault.id, Some(remember(vault.id, key)?))
        }
        Action::Connect { name, server } => {
            if !cfg!(feature = "sync") {
                return Err(crate::agent::failure(confidex_app::Error::SyncDisabled));
            }
            let credentials = setup_credentials(options.credentials_stdin, false)?;
            let key = credentials
                .secret_key
                .as_ref()
                .ok_or_else(|| input("A secret_key is required to connect."))?;
            let remember_key = crate::protocol::Secret(key.0.clone());
            let (reply, _) = cli::call(
                location,
                None,
                Operation::Connect {
                    name,
                    server,
                    credentials,
                },
            )?;
            let Reply::Opened { vault } = reply else {
                return Err(unexpected());
            };
            (vault.id, Some(remember(vault.id, &remember_key.0)?))
        }
    };
    write_default(location, id)?;
    if json {
        cli::json(&serde_json::json!({"id":runtime::hex(&id),"remembered":remembered}))
    } else {
        if remembered == Some(false) {
            let _ = writeln!(
                io::stderr().lock(),
                "The device could not save the key. Keep your separate key copy."
            );
        }
        writeln!(io::stdout().lock(), "{}", runtime::hex(&id)).map_err(runtime::io_failure)
    }
}

fn setup_credentials(stdin: bool, create: bool) -> Result<Credentials, Failure> {
    if stdin {
        let credentials = credentials::from_stdin()?;
        if create && credentials.secret_key.is_some() {
            return Err(input("Creation generates a new secret key."));
        }
        return Ok(credentials);
    }
    let secret_key = if create {
        None
    } else {
        Some(credentials::prompt("Secret key")?)
    };
    let password = credentials::prompt("Master password")?;
    if create && password.0 != credentials::prompt("Confirm master password")?.0 {
        return Err(input("The passwords do not match."));
    }
    Ok(Credentials {
        password,
        secret_key,
    })
}

fn remember(vault: VaultId, key: &str) -> Result<bool, Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(runtime::io_failure)?;
    Ok(runtime.block_on(confidex_native::Credentials.save(vault, key)))
}

fn wizard(vaults: &[VaultInfo]) -> Result<Action, Failure> {
    writeln!(
        io::stderr().lock(),
        "1. Select a local vault\n2. Create a new vault\n3. Connect to a server"
    )
    .map_err(runtime::io_failure)?;
    match line("Action")?.as_str() {
        "1" => {
            if vaults.is_empty() {
                return Err(input("There are no local vaults."));
            }
            for vault in vaults {
                writeln!(
                    io::stderr().lock(),
                    "{}\t{}",
                    runtime::hex(&vault.id),
                    cli::safe(&vault.name)
                )
                .map_err(runtime::io_failure)?;
            }
            Ok(Action::Select(line("Vault ID or name")?))
        }
        "2" => Ok(Action::Create {
            name: line("Vault name")?,
            key_output: line("Separate secret key file")?.into(),
        }),
        "3" => Ok(Action::Connect {
            name: line("Vault name")?,
            server: line("Server URL")?,
        }),
        _ => Err(input("Select 1, 2, or 3.")),
    }
}

fn line(label: &str) -> Result<String, Failure> {
    {
        let mut stderr = io::stderr().lock();
        write!(stderr, "{label}: ")
            .and_then(|_| stderr.flush())
            .map_err(runtime::io_failure)?;
    }
    let mut text = String::new();
    io::stdin()
        .lock()
        .take(4097)
        .read_line(&mut text)
        .map_err(runtime::io_failure)?;
    if text.len() > 4096 {
        return Err(input("Input exceeds the limit."));
    }
    let text = text.trim();
    if text.is_empty() {
        return Err(Failure {
            code: Code::Cancelled,
            message: "Setup was cancelled.".into(),
        });
    }
    Ok(text.into())
}

fn input(message: &str) -> Failure {
    Failure {
        code: Code::Input,
        message: message.into(),
    }
}
fn unexpected() -> Failure {
    Failure {
        code: Code::Protocol,
        message: "Unexpected setup response.".into(),
    }
}

pub fn select(vaults: &[VaultInfo], selector: &str) -> Result<VaultId, Failure> {
    let id = runtime::id::<16>(selector);
    let mut matches = vaults
        .iter()
        .filter(|vault| id.map_or(vault.name == selector, |id| vault.id == id));
    let first = matches.next().ok_or(Failure {
        code: Code::NotFound,
        message: "The selected vault was not found.".into(),
    })?;
    if matches.next().is_some() {
        return Err(Failure {
            code: Code::Ambiguous,
            message: "Several vaults match. Use a vault ID from cfdex vaults.".into(),
        });
    }
    Ok(first.id)
}

fn default_path(location: &Location) -> PathBuf {
    let mut path = location.database.as_os_str().to_owned();
    path.push(".cfdex-default");
    PathBuf::from(path)
}

pub fn read_default(location: &Location) -> Result<VaultId, Failure> {
    let file = File::open(default_path(location)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Failure {
                code: Code::Input,
                message: "Select a vault with cfdex init or --vault.".into(),
            }
        } else {
            runtime::io_failure(error)
        }
    })?;
    let mut text = String::new();
    file.take(34)
        .read_to_string(&mut text)
        .map_err(runtime::io_failure)?;
    text.strip_suffix('\n')
        .filter(|id| id.len() == 32)
        .and_then(runtime::id::<16>)
        .ok_or(Failure {
            code: Code::Input,
            message: "The saved vault selection is invalid. Run cfdex init.".into(),
        })
}

pub fn write_default(location: &Location, id: VaultId) -> Result<(), Failure> {
    let path = default_path(location);
    let parent = path.parent().ok_or(Failure {
        code: Code::Io,
        message: "The database directory is unavailable.".into(),
    })?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(runtime::io_failure)?;
    writeln!(file, "{}", runtime::hex(&id)).map_err(runtime::io_failure)?;
    file.as_file().sync_all().map_err(runtime::io_failure)?;
    file.persist(path)
        .map_err(|error| runtime::io_failure(error.error))?;
    Ok(())
}
