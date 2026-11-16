use confidex_storage::{
    BatchCommit, Error, Head, MAX_OBJECT, RecordId, RevisionId, Snapshot, Store, StoredVault,
    SyncCommit, VaultId, VaultInfo,
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/web/storage.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = dbCall)]
    pub async fn call(operation: &str, args: JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = requestPersistence)]
    pub fn request_persistence();
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
pub fn hex(value: &[u8]) -> JsValue {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into()
}
pub fn args(values: &[JsValue]) -> JsValue {
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
