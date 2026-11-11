use confidex_app::DeviceKeys;
use confidex_device_secrets::{
    AccessPolicy, DeviceSecrets, Error as KeyError, Interaction, OpenedEntry, ProtectedStore,
    Purpose, SealedEntry, SecretBytes, SecretId, platform::Protector,
};
use confidex_storage::{
    BatchCommit, Error, Head, MAX_OBJECT, RecordId, RevisionId, Snapshot, Store, StoredVault,
    SyncCommit, VaultId, VaultInfo,
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use serde::de::DeserializeOwned;
use wasm_bindgen::{JsCast, prelude::*};
use zeroize::Zeroizing;

#[wasm_bindgen(module = "/web/storage.js")]
extern "C" {
    #[wasm_bindgen(js_name = attachKeyFallback)]
    pub fn attach_key_fallback(worker: &web_sys::Worker);
    #[wasm_bindgen(js_name = setKeyStorageWarning)]
    pub fn set_key_storage_warning(worker: &web_sys::Worker, message: &str);
    #[wasm_bindgen(js_name = confirmPlaintextKey)]
    async fn confirm_plaintext_key() -> bool;
    #[wasm_bindgen(catch,js_name=dbCall)]
    async fn call(operation: &str, args: JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name=requestPersistence)]
    pub fn request_persistence();
    #[wasm_bindgen(js_name=offlineShell)]
    pub fn offline_shell() -> i32;
}
fn error(value: JsValue) -> Error {
    match value.as_string().as_deref() {
        Some("Conflict") => Error::Conflict,
        Some("Quota") => Error::Quota,
        Some("NotFound") => Error::NotFound,
        Some("Removing") => Error::Removing,
        Some("Version") => Error::Version,
        Some("Invalid") => Error::Invalid,
        Some("Limit") => Error::Limit,
        _ => Error::Storage,
    }
}
fn hex(value: &[u8]) -> JsValue {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into()
}
fn args(values: &[JsValue]) -> JsValue {
    let a = Array::new();
    for v in values {
        a.push(v);
    }
    a.into()
}
async fn decode<T: DeserializeOwned>(op: &str, values: &[JsValue]) -> Result<T, Error> {
    let value = call(op, args(values)).await.map_err(error)?;
    serde_wasm_bindgen::from_value(value).map_err(|_| Error::Invalid)
}
pub struct BrowserStore;
impl Store for BrowserStore {
    async fn branch_heads(
        &mut self,
        vault: VaultId,
        after: Option<&Head>,
        tag: Option<&str>,
    ) -> Result<Vec<Head>, Error> {
        if tag.is_some_and(|tag| tag.len() > 256) {
            return Err(Error::Limit);
        }
        decode(
            "branch-heads",
            &[
                hex(&vault),
                serde_wasm_bindgen::to_value(&after).map_err(|_| Error::Invalid)?,
                tag.map(JsValue::from_str).unwrap_or(JsValue::NULL),
            ],
        )
        .await
    }
    async fn publish_branches(&mut self, vault: VaultId, commit: &SyncCommit) -> Result<(), Error> {
        commit.validate()?;
        let value = serde_wasm_bindgen::to_value(commit).map_err(|_| Error::Invalid)?;
        call("publish-branches", args(&[hex(&vault), value]))
            .await
            .map_err(error)?;
        Ok(())
    }
    async fn batch_commit(&mut self, vault: VaultId, commit: &BatchCommit) -> Result<(), Error> {
        commit.validate()?;
        let request = Object::new();
        let set = |object: &Object, key: &str, value: &JsValue| {
            Reflect::set(object, &key.into(), value).map_err(|_| Error::Invalid)
        };
        set(
            &request,
            "previous",
            &serde_wasm_bindgen::to_value(&commit.previous).map_err(|_| Error::Invalid)?,
        )?;
        set(
            &request,
            "heads",
            &serde_wasm_bindgen::to_value(&commit.heads).map_err(|_| Error::Invalid)?,
        )?;
        let objects = Array::new();
        for object in &commit.objects {
            let item = Object::new();
            set(
                &item,
                "head",
                &serde_wasm_bindgen::to_value(&object.head).map_err(|_| Error::Invalid)?,
            )?;
            set(
                &item,
                "tags",
                &serde_wasm_bindgen::to_value(&object.tags).map_err(|_| Error::Invalid)?,
            )?;
            set(
                &item,
                "wire",
                &Uint8Array::from(object.wire.as_slice()).into(),
            )?;
            objects.push(&item);
        }
        set(&request, "objects", &objects.into())?;
        call("record-batch", args(&[hex(&vault), request.into()]))
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn rename(&mut self, vault: VaultId, expected: &str, name: &str) -> Result<(), Error> {
        call("rename", args(&[hex(&vault), expected.into(), name.into()]))
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn clear_records(&mut self, vault: VaultId) -> Result<(), Error> {
        call("clear-records", args(&[hex(&vault)]))
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn remove(&mut self, vault: VaultId) -> Result<(), Error> {
        call("remove", args(&[hex(&vault)])).await.map_err(error)?;
        Ok(())
    }

    async fn snapshot(&mut self, vault: VaultId) -> Result<Snapshot, Error> {
        let snapshot: Snapshot = decode("snapshot", &[hex(&vault)]).await?;
        snapshot.validate()?;
        Ok(snapshot)
    }
    async fn restore(&mut self, snapshot: &Snapshot) -> Result<(), Error> {
        snapshot.validate()?;
        let value = serde_wasm_bindgen::to_value(snapshot).map_err(|_| Error::Invalid)?;
        call("restore", args(&[value])).await.map_err(error)?;
        Ok(())
    }
    async fn sync_state(&mut self, vault: VaultId) -> Result<Option<Vec<u8>>, Error> {
        decode("sync-state", &[hex(&vault)]).await
    }
    async fn sync_commit(&mut self, vault: VaultId, commit: &SyncCommit) -> Result<(), Error> {
        commit.validate()?;
        let value = serde_wasm_bindgen::to_value(commit).map_err(|_| Error::Invalid)?;
        call("sync-commit", args(&[hex(&vault), value]))
            .await
            .map_err(error)?;
        Ok(())
    }
    async fn vaults(&mut self) -> Result<Vec<VaultInfo>, Error> {
        decode("vaults", &[]).await
    }
    async fn vault(&mut self, id: VaultId) -> Result<StoredVault, Error> {
        decode("vault", &[hex(&id)]).await
    }
    async fn create(&mut self, vault: &StoredVault) -> Result<(), Error> {
        let value = serde_wasm_bindgen::to_value(vault).map_err(|_| Error::Invalid)?;
        call("create", args(&[value])).await.map_err(error)?;
        Ok(())
    }
    async fn heads(&mut self, vault: VaultId, after: Option<RecordId>) -> Result<Vec<Head>, Error> {
        decode(
            "heads",
            &[
                hex(&vault),
                after.map(|id| hex(&id)).unwrap_or(JsValue::NULL),
            ],
        )
        .await
    }
    async fn head(&mut self, vault: VaultId, record: RecordId) -> Result<Option<Head>, Error> {
        decode("head", &[hex(&vault), hex(&record)]).await
    }
    async fn tagged_heads(
        &mut self,
        vault: VaultId,
        tag: &str,
        after: Option<RecordId>,
    ) -> Result<Vec<Head>, Error> {
        if tag.len() > 256 {
            return Err(Error::Limit);
        }
        decode(
            "tagged-heads",
            &[
                hex(&vault),
                tag.into(),
                after.map(|id| hex(&id)).unwrap_or(JsValue::NULL),
            ],
        )
        .await
    }
    async fn object(&mut self, vault: VaultId, revision: RevisionId) -> Result<Vec<u8>, Error> {
        let value = call("object", args(&[hex(&vault), hex(&revision)]))
            .await
            .map_err(error)?;
        let value = Uint8Array::new(&value);
        if value.length() as usize > MAX_OBJECT {
            return Err(Error::Limit);
        }
        Ok(value.to_vec())
    }
    async fn append(
        &mut self,
        vault: VaultId,
        head: &Head,
        expected: Option<RevisionId>,
        wire: &[u8],
        tags: &[String],
    ) -> Result<(), Error> {
        call(
            "append",
            args(&[
                hex(&vault),
                hex(&head.record),
                hex(&head.revision),
                expected.map(|id| hex(&id)).unwrap_or(JsValue::NULL),
                Uint8Array::from(wire).into(),
                serde_wasm_bindgen::to_value(tags).map_err(|_| Error::Invalid)?,
            ]),
        )
        .await
        .map_err(error)?;
        Ok(())
    }
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
