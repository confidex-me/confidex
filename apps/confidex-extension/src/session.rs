use crate::{
    lease::Lease,
    logins::{LOGIN_PAGE_SIZE, append_previews},
    protocol::{
        Action, FormReport, LoginCursor, MAX_REQUEST, MAX_RESPONSE, Reply, Request, Response,
    },
};
use confidex_app::{Command, DeviceKeys, Error, Output};
use confidex_browser::{BrowserStore, Net, Runtime};
use confidex_storage::{Store, VaultId, VaultInfo};
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

fn now() -> u64 {
    js_sys::Date::now() as u64
}

// Worker control can validate liveness while Engine awaits storage or the network.
#[wasm_bindgen]
pub struct SessionLease(Lease);

#[wasm_bindgen]
impl SessionLease {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(Lease::default())
    }

    pub fn remaining(&self) -> i32 {
        self.0.remaining(now())
    }

    pub fn was_locked(&self) -> bool {
        self.0.was_locked()
    }

    pub fn activity(&self) {
        self.0.activity(now());
    }

    pub fn accept_form(&self, context: &str, report: &str) -> bool {
        self.remaining() > 0 && FormReport::valid(context, report)
    }
}

#[wasm_bindgen]
pub struct Session {
    runtime: Runtime<Net>,
    server: Option<String>,
    lease: Lease,
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new(lease: &SessionLease) -> Self {
        Self {
            runtime: Runtime::default(),
            server: None,
            lease: lease.0.clone(),
        }
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
        let result = if self.lease.remaining(now()) == 0
            && !matches!(result, Ok(Reply::Locked { .. } | Reply::Disconnected))
        {
            Err(Error::Locked)
        } else {
            result
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
    fn is_open(&self) -> bool {
        self.lease.remaining(now()) > 0
    }

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
            Some(info) if self.is_open() => Reply::Opened {
                name: info.name,
                can_sync: self.server.is_some(),
            },
            Some(info) => Reply::Locked { name: info.name },
        })
    }

    async fn run(&mut self, action: Action) -> Response {
        if self.lease.remaining(now()) == 0 {
            return Err(Error::Locked);
        }
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
                if self.is_open()
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
                self.lease.retire();
                self.server = None;
                self.command(Command::Lock).await?;
                self.status().await
            }
            Action::Sync => {
                if !self.is_open() {
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
            Action::Logins { after } if self.is_open() => self.logins(after).await,
            Action::Logins { .. } => Err(Error::Locked),
        }
    }

    fn opened(&mut self, output: Output) -> Response {
        let Output::Opened { info, server, .. } = output else {
            return Err(Error::Integrity);
        };
        self.server = server.filter(|url| url.starts_with("https://"));
        self.lease.open(now());
        Ok(Reply::Opened {
            name: info.name,
            can_sync: self.server.is_some(),
        })
    }

    async fn logins(&mut self, cursor: Option<LoginCursor>) -> Response {
        let Output::Rows { rows, more, next } = self
            .command(Command::List {
                after: cursor.as_ref().map(|cursor| cursor.head.clone()),
                tag: None,
            })
            .await?
        else {
            return Err(Error::Integrity);
        };
        let mut logins = Vec::new();
        let mut scanned = None;
        let resume = cursor.filter(|cursor| cursor.offset > 0);
        for (head, offset) in resume
            .into_iter()
            .map(|cursor| (cursor.head, cursor.offset))
            .chain(rows.iter().map(|row| (row.head.clone(), 0)))
        {
            if !self.is_open() {
                return Err(Error::Locked);
            }
            if logins.len() == LOGIN_PAGE_SIZE {
                return Ok(Reply::Logins {
                    rows: logins,
                    next: scanned,
                });
            }
            let draft = match self
                .command(Command::Open {
                    record: head.record,
                })
                .await
            {
                Ok(Output::Draft(draft)) => draft,
                Err(Error::Input) if offset > 0 => continue,
                Err(Error::Storage(confidex_storage::Error::Conflict)) => continue,
                Err(error) => return Err(error),
                _ => return Err(Error::Integrity),
            };
            if draft.revision == Some(head.revision)
                && let Some(offset) = append_previews(&draft, offset, &mut logins)
            {
                return Ok(Reply::Logins {
                    rows: logins,
                    next: Some(LoginCursor { head, offset }),
                });
            }
            scanned = Some(LoginCursor { head, offset: 0 });
        }
        Ok(Reply::Logins {
            rows: logins,
            next: next
                .filter(|_| more)
                .map(|head| LoginCursor { head, offset: 0 }),
        })
    }
}
