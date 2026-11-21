use crate::{
    autofill::{Autofill, PopupReply, SiteAction, SiteReply, SiteRequest},
    lease::Lease,
    protocol::{Action, FormReport, MAX_REQUEST, MAX_RESPONSE, Reply, Request, Response},
    sync_schedule::SyncSchedule,
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
pub struct SessionLease {
    lease: Lease,
    autofill: Autofill,
}

#[wasm_bindgen]
impl SessionLease {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            lease: Lease::default(),
            autofill: Autofill::default(),
        }
    }

    pub fn remaining(&self) -> i32 {
        self.lease.remaining(now())
    }

    pub fn was_locked(&self) -> bool {
        self.lease.was_locked()
    }

    pub fn activity(&self) {
        self.lease.activity(now());
    }

    pub fn site_live(&self, operation: &str) -> bool {
        self.remaining() > 0 && (operation.is_empty() || self.autofill.live(now(), operation))
    }

    pub fn site_reset(&self) {
        self.autofill.clear();
    }

    pub fn site_navigation(&self, tab: u32, origin: Option<String>) {
        self.autofill.navigate(tab, origin.as_deref());
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
    sync: SyncSchedule,
    autofill: Autofill,
    conflicts: bool,
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new(lease: &SessionLease) -> Self {
        Self {
            runtime: Runtime::default(),
            server: None,
            lease: lease.lease.clone(),
            autofill: lease.autofill.clone(),
            sync: SyncSchedule::default(),
            conflicts: false,
        }
    }

    pub fn sync_delay(&self) -> i32 {
        if !self.is_open() {
            return -1;
        }
        self.sync.delay(now())
    }

    pub async fn sync_automatically(&mut self) -> bool {
        if self.sync_delay() != 0 {
            return false;
        }
        let previous = (self.sync.status(), self.conflicts);
        self.sync_step().await;
        self.is_open() && previous != (self.sync.status(), self.conflicts)
    }

    pub async fn execute_site(&mut self, input: Uint8Array) -> Result<Uint8Array, JsValue> {
        let result = if input.length() as usize > MAX_REQUEST || !self.is_open() {
            input.fill(0, 0, input.length());
            SiteReply::Popup(if self.is_open() {
                PopupReply::Error
            } else {
                PopupReply::Locked
            })
        } else {
            let bytes = Zeroizing::new(input.to_vec());
            input.fill(0, 0, input.length());
            match serde_json::from_slice::<SiteRequest>(&bytes) {
                Ok(request) if request.valid() => {
                    self.run_site(request).await.unwrap_or_else(|error| {
                        SiteReply::Popup(match error {
                            Error::Input | Error::Storage(confidex_storage::Error::Conflict) => {
                                PopupReply::Changed
                            }
                            Error::Locked => PopupReply::Locked,
                            _ => PopupReply::Error,
                        })
                    })
                }
                _ => SiteReply::Popup(PopupReply::Error),
            }
        };
        let result = if self.is_open() {
            result
        } else {
            SiteReply::Popup(PopupReply::Locked)
        };
        encode(&result)
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
        encode(&result)
    }
}

fn encode(result: &impl serde::Serialize) -> Result<Uint8Array, JsValue> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(result).map_err(|_| JsValue::from_str("Invalid session reply"))?,
    );
    if bytes.len() > MAX_RESPONSE {
        return Err(JsValue::from_str("Session reply limit"));
    }
    Ok(Uint8Array::from(bytes.as_slice()))
}

impl Session {
    async fn run_site(&mut self, request: SiteRequest) -> Result<SiteReply, Error> {
        let SiteRequest {
            context, action, ..
        } = request;
        match action {
            SiteAction::Find {
                operation,
                snapshot,
                mut after,
            } => {
                let forms = snapshot.choices(&context.origin);
                let mut matches = confidex_app::browser_logins::Page {
                    rows: vec![],
                    issues: Default::default(),
                    next: None,
                };
                if !forms.is_empty() {
                    loop {
                        let page = self
                            .runtime
                            .engine_mut()
                            .find_browser_logins(&mut BrowserStore, after, &context.origin)
                            .await?;
                        if !self.is_open() {
                            return Err(Error::Locked);
                        }
                        matches.issues.ambiguous |= page.issues.ambiguous;
                        matches.issues.conflicts |= page.issues.conflicts;
                        if !page.rows.is_empty() || page.next.is_none() {
                            matches.rows = page.rows;
                            matches.next = page.next;
                            break;
                        }
                        after = page.next;
                    }
                }
                matches.issues.conflicts |= self.conflicts;
                let origin = context.origin.clone();
                let preferred =
                    self.autofill
                        .issue(now(), operation.clone(), context, snapshot, &matches);
                Ok(SiteReply::Popup(PopupReply::Site {
                    operation,
                    origin,
                    forms,
                    matches,
                    sync: self.sync.status(),
                    preferred,
                }))
            }
            SiteAction::Fill {
                operation,
                form,
                target,
                snapshot,
            } => {
                let fields = self
                    .autofill
                    .consume(now(), &operation, &context, &snapshot, form, &target)
                    .ok_or(Error::Input)?;
                let login = self
                    .runtime
                    .engine_mut()
                    .prepare_browser_fill(
                        &mut BrowserStore,
                        &target,
                        &context.origin,
                        fields.username.is_some(),
                        fields.password.is_some(),
                    )
                    .await?;
                if !self.is_open() {
                    return Err(Error::Locked);
                }
                if fields.password.is_none() {
                    self.autofill
                        .begin_continuation(now(), operation, context, target);
                }
                self.lease.activity(now());
                Ok(SiteReply::Fill { fields, login })
            }
            SiteAction::Complete { operation } => {
                self.autofill.complete(&operation, &context);
                Ok(SiteReply::Popup(PopupReply::Filled))
            }
        }
    }

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
                sync: self.sync.status(),
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
            Action::Sync if self.is_open() && self.server.is_some() => {
                let more = self.sync_step().await;
                Ok(Reply::Synced {
                    sync: self.sync.status(),
                    more,
                })
            }
            Action::Sync if self.is_open() => Err(Error::SyncDisabled),
            Action::Logins { after } if self.is_open() => {
                let mut page = self
                    .runtime
                    .engine_mut()
                    .browser_logins(&mut BrowserStore, after)
                    .await?;
                page.issues.conflicts |= self.conflicts;
                Ok(Reply::Logins {
                    page,
                    sync: self.sync.status(),
                })
            }
            Action::LoginChoices { record, after } if self.is_open() => {
                let page = self
                    .runtime
                    .engine_mut()
                    .browser_login_choices(&mut BrowserStore, record, after)
                    .await?;
                Ok(Reply::LoginChoices(page))
            }
            Action::LoginEditor { target } if self.is_open() => {
                let fields = self
                    .runtime
                    .engine_mut()
                    .browser_login_editor(&mut BrowserStore, &target)
                    .await?;
                Ok(Reply::LoginEditor { target, fields })
            }
            Action::CreateLogin { record, login } if self.is_open() => {
                let head = self
                    .runtime
                    .engine_mut()
                    .create_browser_login(&mut BrowserStore, record, &login, now())
                    .await?;
                self.sync.local_change(now());
                Ok(Reply::Saved(head))
            }
            Action::UpdateLogin { target, change } if self.is_open() => {
                let head = self
                    .runtime
                    .engine_mut()
                    .update_browser_login(&mut BrowserStore, &target, &change, now())
                    .await?;
                self.sync.local_change(now());
                Ok(Reply::Saved(head))
            }
            _ => Err(Error::Locked),
        }
    }

    fn opened(&mut self, output: Output) -> Response {
        let Output::Opened { info, server, .. } = output else {
            return Err(Error::Integrity);
        };
        self.server = server.filter(|url| url.starts_with("https://"));
        let now = now();
        self.lease.open(now);
        if self.server.is_some() {
            self.sync.start(now);
        }
        Ok(Reply::Opened {
            name: info.name,
            sync: self.sync.status(),
        })
    }

    async fn sync_step(&mut self) -> bool {
        let Some(server) = self.server.clone() else {
            return false;
        };
        let result = match self.command(Command::Sync { server }).await {
            Ok(Output::Synced(report)) => {
                if !report.more {
                    self.conflicts = !report.conflicts.is_empty();
                }
                Ok(report.more)
            }
            Ok(_) => Err(Error::Integrity),
            Err(error) => Err(error),
        };
        self.sync.finish(now(), result);
        result == Ok(true)
    }
}
