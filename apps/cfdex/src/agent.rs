use crate::{
    protocol::{self, Code, Failure, Operation, Reply, Request, Response},
    runtime::Location,
};
use confidex_app::{Command, Engine, Output};
use confidex_storage::{SqliteStore, Store, VaultId};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

mod records;
mod sync;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub(crate) const DEFAULT_SERVER: &str = "https://sync.confidex.me/";
const MAX_SESSIONS: usize = 16;

struct Session {
    engine: Engine,
    used: Instant,
}
// The client reads Keychain so an OS prompt cannot block session expiry.
struct ClientKeys;
impl confidex_app::DeviceKeys for ClientKeys {
    async fn remove(&mut self, _: VaultId) -> bool {
        false
    }
    async fn load(&mut self, _: VaultId) -> Option<String> {
        None
    }
    async fn save(&mut self, _: VaultId, _: &str) -> bool {
        false
    }
}
pub struct Agent {
    store: SqliteStore,
    keys: ClientKeys,
    sessions: BTreeMap<VaultId, Session>,
    timeout: Duration,
    #[cfg(feature = "sync")]
    net: Option<confidex_native::sync_transport::Net>,
}

pub fn failure(error: confidex_app::Error) -> Failure {
    use confidex_app::Error;
    let (code, message) = match error {
        Error::Storage(confidex_storage::Error::NotFound) => {
            (Code::NotFound, "The vault or record was not found.")
        }
        Error::Storage(confidex_storage::Error::Conflict) => (
            Code::Ambiguous,
            "Several revisions exist. Specify --revision.",
        ),
        Error::Storage(confidex_storage::Error::Removing) => {
            (Code::Input, "Vault removal is in progress.")
        }
        Error::Storage(_) => (Code::Io, "The database operation failed."),
        Error::Locked => (Code::Locked, "The vault is locked. Run cfdex unlock."),
        Error::Auth | Error::Credentials => {
            (Code::Auth, "Authentication or credential access failed.")
        }
        Error::Key => (Code::Input, "The secret key is invalid."),
        Error::PasswordRequired => (Code::Auth, "Enter the vault password."),
        Error::Input | Error::RecordLimit => {
            (Code::Input, "The input is invalid or exceeds a limit.")
        }
        Error::Integrity => (Code::Auth, "Vault verification failed."),
        Error::Network | Error::Server(_) => (Code::Network, "Synchronization failed."),
        Error::SyncDisabled => (Code::Network, "Synchronization is not available."),
    };
    Failure {
        code,
        message: message.into(),
    }
}

impl Agent {
    pub fn new(store: SqliteStore, timeout: Duration) -> Self {
        Self {
            store,
            keys: ClientKeys,
            sessions: BTreeMap::new(),
            timeout,
            #[cfg(feature = "sync")]
            net: None,
        }
    }
    fn expire(&mut self) {
        self.sessions
            .retain(|_, session| session.used.elapsed() < self.timeout);
    }
    fn remaining(&self) -> Duration {
        self.sessions
            .values()
            .map(|session| self.timeout.saturating_sub(session.used.elapsed()))
            .min()
            .unwrap_or(Duration::from_secs(60))
            .min(Duration::from_secs(60))
    }
    pub async fn dispatch(&mut self, request: &mut Request) -> (Response, Zeroizing<Vec<u8>>) {
        self.expire();
        let mut payload = Zeroizing::new(Vec::new());
        let result = self.execute(request, &mut payload).await;
        (
            Response {
                version: protocol::VERSION,
                id: request.id,
                vault: request.vault,
                result,
            },
            payload,
        )
    }

    async fn execute(
        &mut self,
        request: &mut Request,
        payload: &mut Zeroizing<Vec<u8>>,
    ) -> Result<Reply, Failure> {
        if matches!(request.command, Operation::Stop { .. }) {
            self.sessions.clear();
            return Ok(Reply::Stopped {});
        }
        if matches!(request.command, Operation::Vaults { .. }) {
            return Ok(Reply::Vaults {
                vaults: self
                    .store
                    .vaults()
                    .await
                    .map_err(|error| failure(error.into()))?,
            });
        }
        match &mut request.command {
            Operation::Create {
                name,
                credentials,
                key_output,
            } => {
                let (reply, key) = self
                    .create(std::mem::take(name), credentials, key_output)
                    .await?;
                *payload = key;
                return Ok(reply);
            }
            Operation::Connect {
                name,
                server,
                credentials,
            } => {
                return self
                    .connect(std::mem::take(name), std::mem::take(server), credentials)
                    .await;
            }
            _ => (),
        }
        let vault = request.vault.ok_or(Failure {
            code: Code::Input,
            message: "A vault is required.".into(),
        })?;
        let info = match self.store.vault(vault).await {
            Ok(stored) => stored.info,
            Err(error) => {
                self.sessions.remove(&vault);
                return Err(failure(error.into()));
            }
        };
        match &mut request.command {
            Operation::Status { .. } => Ok(Reply::Status {
                unlocked: self.sessions.contains_key(&vault),
            }),
            Operation::Lock { .. } => {
                if let Some(mut session) = self.sessions.remove(&vault) {
                    session
                        .engine
                        .execute(
                            &mut self.store,
                            &mut self.keys,
                            &mut confidex_app::Request {
                                generation: 0,
                                command: Command::Lock,
                            },
                        )
                        .await
                        .result
                        .map_err(failure)?;
                }
                Ok(Reply::Locked {})
            }
            Operation::Unlock { credentials } => {
                if !self.sessions.contains_key(&vault) && self.sessions.len() >= MAX_SESSIONS {
                    return Err(Failure {
                        code: Code::Input,
                        message: "Too many open vaults. Lock a vault first.".into(),
                    });
                }
                let mut engine = Engine::default();
                let supplied_key = credentials.secret_key.is_some();
                let output = engine
                    .execute(
                        &mut self.store,
                        &mut self.keys,
                        &mut confidex_app::Request {
                            generation: 0,
                            command: Command::Unlock {
                                vault,
                                password: std::mem::take(&mut credentials.password.0),
                                key: credentials
                                    .secret_key
                                    .as_mut()
                                    .map(|key| std::mem::take(&mut key.0))
                                    .unwrap_or_default(),
                                remember: false,
                            },
                        },
                    )
                    .await
                    .result
                    .map_err(|error| {
                        if error == confidex_app::Error::Key && !supplied_key {
                            Failure {
                                code: Code::Locked,
                                message: "A saved secret key is unavailable. Enter the secret key."
                                    .into(),
                            }
                        } else {
                            failure(error)
                        }
                    })?;
                if !matches!(output, Output::Opened { .. }) {
                    return Err(Failure {
                        code: Code::Protocol,
                        message: "Unexpected vault response.".into(),
                    });
                }
                self.sessions.insert(
                    vault,
                    Session {
                        engine,
                        used: Instant::now(),
                    },
                );
                Ok(Reply::Opened { vault: info })
            }
            Operation::List { .. } | Operation::Fields { .. } | Operation::Get { .. } => {
                self.records(vault, &mut request.command, payload).await
            }
            Operation::Sync { folder } => self.synchronize(vault, *folder).await,
            _ => unreachable!(),
        }
    }

    fn check_capacity(&self) -> Result<(), Failure> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Failure {
                code: Code::Input,
                message: "Too many open vaults. Lock a vault first.".into(),
            });
        }
        Ok(())
    }

    async fn create(
        &mut self,
        name: String,
        credentials: &mut protocol::Credentials,
        key_output: &std::path::Path,
    ) -> Result<(Reply, Zeroizing<Vec<u8>>), Failure> {
        self.check_capacity()?;
        if !key_output.is_absolute() || credentials.secret_key.is_some() {
            return Err(failure(confidex_app::Error::Input));
        }
        let mut staging = SqliteStore::open(std::path::Path::new(":memory:"))
            .map_err(|error| failure(error.into()))?;
        let mut engine = Engine::default();
        let Output::Created(mut created) = engine
            .execute(
                &mut staging,
                &mut self.keys,
                &mut confidex_app::Request {
                    generation: 0,
                    command: Command::Create {
                        name,
                        password: std::mem::take(&mut credentials.password.0),
                        remember: false,
                    },
                },
            )
            .await
            .result
            .map_err(failure)?
        else {
            return Err(Failure {
                code: Code::Protocol,
                message: "Unexpected creation response.".into(),
            });
        };
        let snapshot = staging
            .snapshot(created.info.id)
            .await
            .map_err(|error| failure(error.into()))?;
        let backup = (|| -> io::Result<()> {
            let mut file = crate::runtime::private_file(key_output)?;
            file.write_all(created.key.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()
        })();
        backup.map_err(|_| Failure {
            code: Code::Io,
            message: "Cannot save the separate secret key copy. No vault was added.".into(),
        })?;
        self.store
            .restore(&snapshot)
            .await
            .map_err(|error| failure(error.into()))?;
        #[cfg(feature = "sync")]
        engine
            .execute(
                &mut self.store,
                &mut self.keys,
                &mut confidex_app::Request {
                    generation: 0,
                    command: Command::SyncConfig {
                        server: Some(DEFAULT_SERVER.into()),
                    },
                },
            )
            .await
            .result
            .map_err(failure)?;
        self.sessions.insert(
            created.info.id,
            Session {
                engine,
                used: Instant::now(),
            },
        );
        let key = Zeroizing::new(std::mem::take(&mut created.key).into_bytes());
        Ok((
            Reply::Created {
                vault: created.info.clone(),
                remembered: false,
                length: key.len(),
            },
            key,
        ))
    }

    async fn connect(
        &mut self,
        name: String,
        server: String,
        credentials: &mut protocol::Credentials,
    ) -> Result<Reply, Failure> {
        #[cfg(feature = "sync")]
        {
            self.check_capacity()?;
            let key = credentials
                .secret_key
                .as_mut()
                .ok_or_else(|| failure(confidex_app::Error::Key))?;
            let mut transport =
                confidex_native::sync_transport::Net::new().map_err(crate::runtime::io_failure)?;
            let mut engine = Engine::default();
            let Output::Opened { info, .. } = engine
                .execute_with_transport(
                    &mut self.store,
                    &mut self.keys,
                    &mut transport,
                    &mut confidex_app::Request {
                        generation: 0,
                        command: Command::Import {
                            name,
                            server,
                            password: std::mem::take(&mut credentials.password.0),
                            key: std::mem::take(&mut key.0),
                            remember: false,
                            use_device_unlock: None,
                        },
                    },
                )
                .await
                .result
                .map_err(failure)?
            else {
                return Err(Failure {
                    code: Code::Protocol,
                    message: "Unexpected connection response.".into(),
                });
            };
            let vault = self
                .store
                .vault(info.id)
                .await
                .map_err(|error| failure(error.into()))?
                .info;
            self.sessions.insert(
                vault.id,
                Session {
                    engine,
                    used: Instant::now(),
                },
            );
            Ok(Reply::Opened { vault })
        }
        #[cfg(not(feature = "sync"))]
        {
            let _ = (name, server, credentials);
            Err(failure(confidex_app::Error::SyncDisabled))
        }
    }
}

pub fn serve(location: Location, timeout: Duration) -> io::Result<()> {
    if timeout.is_zero() || timeout > IDLE_TIMEOUT {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let _guard = match location.lock() {
        Ok(guard) => guard,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
        Err(error) => return Err(error),
    };
    let listener = match location.listener() {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
            ) && crate::socket::Connection::connect(&location.endpoint).is_ok() =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    listener.set_nonblocking(true)?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let store = confidex_native::open_store(&location.database)
        .map_err(|_| io::Error::other("database unavailable"))?;
    let mut agent = Agent::new(store, timeout);
    loop {
        agent.expire();
        let mut connection = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(agent.remaining().min(Duration::from_millis(10)));
                continue;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let remaining = agent.remaining();
        if remaining.is_zero() {
            continue;
        }
        connection.set_io_timeout(remaining.min(Duration::from_secs(1)))?;
        let mut request = match protocol::read_request(&mut connection) {
            Ok(request) => request,
            Err(_) => continue,
        };
        let stop = matches!(request.command, Operation::Stop { .. });
        let (response, payload) = executor.block_on(agent.dispatch(&mut request));
        let remaining = agent.remaining();
        if !remaining.is_zero() && connection.set_io_timeout(remaining).is_ok() {
            let _ = protocol::write_response(&mut connection, &response, &payload);
        }
        if stop {
            return Ok(());
        }
    }
}
