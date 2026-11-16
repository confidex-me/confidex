use crate::protocol::{Action, MAX_REQUEST, MAX_RESPONSE, Reply, Request, Response};
use confidex_app::{Command, DeviceKeys, Error, Output};
use confidex_browser::{BrowserStore, Net, Runtime};
use confidex_storage::{Head, Store, VaultId, VaultInfo};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

struct NoDeviceKeys;

impl DeviceKeys for NoDeviceKeys {
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

#[wasm_bindgen]
#[derive(Default)]
pub struct Session {
    runtime: Runtime<Net>,
    server: Option<String>,
    unlocked: bool,
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn execute(&mut self, input: Uint8Array) -> Result<Uint8Array, JsValue> {
        let result = if input.length() as usize > MAX_REQUEST {
            input.fill(0, 0, input.length());
            Err(Error::Input)
        } else {
            let bytes = Zeroizing::new(input.to_vec());
            input.fill(0, 0, input.length());
            let request = Request::decode(&bytes);
            drop(bytes);
            match request {
                Ok(request) => self.run(request.action).await,
                Err(error) => Err(error),
            }
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&result).map_err(|_| JsValue::from_str("Invalid session reply"))?,
        );
        if bytes.len() > MAX_RESPONSE {
            return Err(JsValue::from_str("Session reply limit"));
        }
        Ok(Uint8Array::from(bytes.as_slice()))
    }
}

impl Session {
    async fn command(&mut self, command: Command) -> Result<Output, Error> {
        self.runtime
            .execute(
                &mut NoDeviceKeys,
                &mut confidex_app::Request {
                    generation: 0,
                    command,
                },
            )
            .await
            .result
    }

    async fn vault() -> Result<Option<VaultInfo>, Error> {
        let mut vaults = BrowserStore.vaults().await?;
        if vaults.len() > 1 {
            return Err(Error::Integrity);
        }
        Ok(vaults.pop())
    }

    async fn status(&self) -> Response {
        Ok(match Self::vault().await? {
            None => Reply::Disconnected,
            Some(info) if self.unlocked => Reply::Opened {
                name: info.name,
                can_sync: self.server.is_some(),
            },
            Some(info) => Reply::Locked { name: info.name },
        })
    }

    async fn run(&mut self, action: Action) -> Response {
        match action {
            Action::Status => self.status().await,
            Action::Connect {
                name,
                server,
                mut credentials,
            } => {
                if Self::vault().await?.is_some() {
                    return Err(Error::Input);
                }
                let server = confidex_app::sync::server_url(server.trim())?;
                if !server.starts_with("https://") {
                    return Err(Error::Input);
                }
                let opened = self
                    .command(Command::Import {
                        name: name.trim().to_owned(),
                        server,
                        password: std::mem::take(&mut credentials.password),
                        key: std::mem::take(&mut credentials.key),
                        remember: false,
                        use_device_unlock: None,
                    })
                    .await?;
                self.opened(opened)
            }
            Action::Unlock(mut credentials) => {
                if self.unlocked
                    || credentials.password.len() > 4096
                    || credentials.key.len() > 1024
                {
                    return Err(Error::Input);
                }
                let vault = Self::vault().await?.ok_or(Error::Input)?;
                let opened = self
                    .command(Command::Unlock {
                        vault: vault.id,
                        password: std::mem::take(&mut credentials.password),
                        key: std::mem::take(&mut credentials.key),
                        remember: false,
                    })
                    .await?;
                self.opened(opened)
            }
            Action::Lock => {
                self.unlocked = false;
                self.server = None;
                self.command(Command::Lock).await?;
                self.status().await
            }
            Action::Sync => {
                if !self.unlocked {
                    return Err(Error::Locked);
                }
                let server = self.server.clone().ok_or(Error::SyncDisabled)?;
                let Output::Synced(report) = self.command(Command::Sync { server }).await? else {
                    return Err(Error::Integrity);
                };
                Ok(Reply::Synced {
                    conflicts: !report.conflicts.is_empty(),
                    more: report.more,
                })
            }
            Action::Logins { after } => self.logins(after).await,
        }
    }

    fn opened(&mut self, output: Output) -> Response {
        let Output::Opened { info, server, .. } = output else {
            return Err(Error::Integrity);
        };
        self.server = server.filter(|url| url.starts_with("https://"));
        self.unlocked = true;
        Ok(Reply::Opened {
            name: info.name,
            can_sync: self.server.is_some(),
        })
    }

    async fn logins(&mut self, after: Option<Head>) -> Response {
        let Output::Rows { rows, more, next } =
            self.command(Command::List { after, tag: None }).await?
        else {
            return Err(Error::Integrity);
        };
        let mut logins = Vec::new();
        let mut scanned = None;
        for row in rows {
            if logins.len() >= 128 {
                return Ok(Reply::Logins {
                    rows: logins,
                    next: scanned,
                });
            }
            scanned = Some(row.head.clone());
            let draft = match self
                .command(Command::Open {
                    record: row.head.record,
                })
                .await
            {
                Ok(Output::Draft(draft)) => draft,
                Err(Error::Storage(confidex_storage::Error::Conflict)) => continue,
                Err(error) => return Err(error),
                _ => return Err(Error::Integrity),
            };
            for username in crate::logins::usernames(&draft) {
                logins.push(crate::protocol::Login {
                    title: draft.title.chars().take(128).collect(),
                    username: username.chars().take(128).collect(),
                });
            }
        }
        Ok(Reply::Logins {
            rows: logins,
            next: if more { next } else { None },
        })
    }
}
