use confidex_app::DeviceKeys;
pub use confidex_browser::BrowserStore;
use confidex_browser::storage::{args, call, hex};
use confidex_device_secrets::{
    AccessPolicy, DeviceSecrets, Error as KeyError, Interaction, OpenedEntry, ProtectedStore,
    Purpose, SealedEntry, SecretBytes, SecretId, platform::Protector,
};
use confidex_storage::VaultId;
use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::{JsCast, prelude::*};
use zeroize::Zeroizing;

#[wasm_bindgen(module = "/web/browser-keys.js")]
extern "C" {
    #[wasm_bindgen(js_name = attachKeyFallback)]
    pub fn attach_key_fallback(worker: &web_sys::Worker);
    #[wasm_bindgen(js_name = setKeyStorageWarning)]
    pub fn set_key_storage_warning(worker: &web_sys::Worker, message: &str);
    #[wasm_bindgen(js_name = confirmPlaintextKey)]
    async fn confirm_plaintext_key() -> bool;
    #[wasm_bindgen(js_name = offlineShell)]
    pub fn offline_shell() -> i32;
}
const KEY_NAMESPACE: &str = "me.confidex.device-secrets";

fn secret_id(vault: VaultId) -> SecretId {
    SecretId {
        vault,
        purpose: Purpose::SecretKey,
    }
}

async fn saved_key(vault: VaultId) -> Result<JsValue, JsValue> {
    call("load-key", args(&[hex(&vault)])).await
}

#[derive(Default)]
struct KeyStore {
    verified_at: Option<u64>,
    expected: Option<Uint8Array>,
}

async fn saved_device_unlock(vault: VaultId) -> Result<JsValue, JsValue> {
    call("load-device-unlock", args(&[hex(&vault)])).await
}

fn unlock_id(vault: VaultId) -> SecretId {
    SecretId {
        vault,
        purpose: Purpose::QuickUnlock,
    }
}

impl ProtectedStore for KeyStore {
    async fn read(
        &mut self,
        id: SecretId,
        _: Interaction,
    ) -> Result<Option<SealedEntry>, KeyError> {
        let value = if id.purpose == Purpose::QuickUnlock {
            let row = saved_device_unlock(id.vault)
                .await
                .map_err(|_| KeyError::Storage)?;
            if row.is_null() {
                return Ok(None);
            }
            Reflect::get(&row, &"entry".into()).map_err(|_| KeyError::InvalidData)?
        } else {
            saved_key(id.vault).await.map_err(|_| KeyError::Storage)?
        };
        if value.is_null() {
            return Ok(None);
        }
        let bytes = value
            .dyn_into::<Uint8Array>()
            .map_err(|_| KeyError::InvalidData)?;
        SealedEntry::from_bytes(bytes.to_vec()).map(Some)
    }

    async fn write(
        &mut self,
        id: SecretId,
        entry: &SealedEntry,
        _: Interaction,
    ) -> Result<(), KeyError> {
        let bytes = Uint8Array::from(entry.bytes());
        let request = if id.purpose == Purpose::QuickUnlock {
            let verified_at = self.verified_at.ok_or(KeyError::InvalidData)?;
            let expected = self
                .expected
                .as_ref()
                .map_or(JsValue::NULL, |bytes| bytes.clone().into());
            call(
                "save-device-unlock",
                args(&[
                    hex(&id.vault),
                    bytes.into(),
                    (verified_at as f64).into(),
                    expected,
                ]),
            )
            .await
        } else {
            call("save-key", args(&[hex(&id.vault), bytes.into()])).await
        };
        request.map(|_| ()).map_err(|_| KeyError::Storage)
    }

    async fn remove(&mut self, id: SecretId, _: Interaction) -> Result<(), KeyError> {
        call("remove-key", args(&[hex(&id.vault)]))
            .await
            .map(|_| ())
            .map_err(|_| KeyError::Storage)
    }
}

fn device_secrets(store: KeyStore) -> Result<DeviceSecrets<KeyStore, Protector>, KeyError> {
    DeviceSecrets::new(KEY_NAMESPACE, store, Protector::new(KEY_NAMESPACE)?)
}

#[derive(Default)]
pub struct BrowserKeys {
    opened: Option<OpenedEntry>,
}
impl DeviceKeys for BrowserKeys {
    async fn remove(&mut self, vault: VaultId) -> bool {
        KeyStore::default()
            .remove(secret_id(vault), Interaction::Forbid)
            .await
            .is_ok()
    }

    async fn has_saved_key(&mut self, vault: VaultId) -> bool {
        saved_key(vault).await.is_ok_and(|value| !value.is_null())
            || self.device_unlock_verified_at(vault).await.is_some()
    }

    async fn load(&mut self, vault: VaultId) -> Option<String> {
        let value = saved_key(vault).await.ok()?;
        if let Some(key) = value.as_string() {
            return Some(key);
        }
        if !value.is_instance_of::<Uint8Array>() {
            return None;
        }
        let key = device_secrets(KeyStore::default())
            .ok()?
            .get(secret_id(vault), Interaction::Allow)
            .await
            .ok()?;
        std::str::from_utf8(key.expose()).ok().map(str::to_owned)
    }

    async fn save(&mut self, vault: VaultId, key: &str) -> bool {
        if call("key-opt-out", args(&[hex(&vault)]))
            .await
            .ok()
            .and_then(|value| value.as_bool())
            != Some(false)
        {
            return false;
        }
        let Ok(mut secrets) = device_secrets(KeyStore::default()) else {
            return false;
        };
        let Ok(secret) = SecretBytes::new(key.as_bytes().to_vec()) else {
            return false;
        };
        match secrets
            .put(
                secret_id(vault),
                &secret,
                AccessPolicy::AuthenticatorVerified,
                Interaction::Allow,
            )
            .await
        {
            Ok(()) => true,
            Err(KeyError::Unsupported | KeyError::AccessDenied)
                if confirm_plaintext_key().await =>
            {
                call("save-key", args(&[hex(&vault), key.into()]))
                    .await
                    .is_ok()
            }
            Err(_) => false,
        }
    }

    async fn save_unprotected(&mut self, vault: VaultId, key: &str) -> bool {
        let accepted = confirm_plaintext_key().await;
        let value = if accepted { key.into() } else { JsValue::NULL };
        let result = call("set-unprotected-key", args(&[hex(&vault), value])).await;
        accepted && result.is_ok()
    }

    async fn disable_device_unlock(&mut self, vault: VaultId, key: &str) -> bool {
        if !confirm_plaintext_key().await {
            return false;
        }
        call("set-unprotected-key", args(&[hex(&vault), key.into()]))
            .await
            .is_ok()
    }

    fn device_unlock_minutes(&self) -> u16 {
        Reflect::get(&js_sys::global(), &"deviceUnlockMinutes".into())
            .ok()
            .and_then(|value| value.as_f64())
            .map_or(confidex_app::device_unlock::DEFAULT_MINUTES, |value| {
                value as u16
            })
    }

    fn now_ms(&self) -> Option<u64> {
        Some(js_sys::Date::now() as u64)
    }

    async fn device_unlock_verified_at(&mut self, vault: VaultId) -> Option<u64> {
        let row = saved_device_unlock(vault).await.ok()?;
        Reflect::get(&row, &"verifiedAt".into())
            .ok()?
            .as_f64()
            .map(|v| v as u64)
    }

    async fn load_device_unlock(&mut self, vault: VaultId) -> Option<Zeroizing<Vec<u8>>> {
        let opened = device_secrets(KeyStore::default())
            .ok()?
            .open_entry(unlock_id(vault), Interaction::Allow)
            .await
            .ok()?;
        let secret = Zeroizing::new(opened.secret.expose().to_vec());
        self.opened = Some(opened);
        Some(secret)
    }

    async fn save_device_unlock(&mut self, vault: VaultId, verified_at: u64, bytes: &[u8]) -> bool {
        let expected = self
            .opened
            .as_ref()
            .map(|entry| Uint8Array::from(entry.sealed_bytes()));
        let Ok(mut secrets) = device_secrets(KeyStore {
            verified_at: Some(verified_at),
            expected,
        }) else {
            return false;
        };
        let Ok(secret) = SecretBytes::new(bytes.to_vec()) else {
            return false;
        };
        match self.opened.take() {
            Some(entry) => secrets
                .replace_opened(entry, &secret, Interaction::Allow)
                .await
                .is_ok(),
            None => secrets
                .put(
                    unlock_id(vault),
                    &secret,
                    AccessPolicy::AuthenticatorVerified,
                    Interaction::Allow,
                )
                .await
                .is_ok(),
        }
    }
}
