use crate::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn browser_check() -> std::result::Result<String, JsValue> {
    check().await.map_err(|e| JsValue::from_str(&e.to_string()))
}
async fn check() -> Result<String> {
    let namespace = "dev.confidex.test.browser";
    let id = SecretId {
        vault: [0xa5; 16],
        purpose: Purpose::SecretKey,
    };
    let binding = Binding::new(namespace, id, AccessPolicy::UserVerified)?;
    let mut protector = platform::Protector::new(namespace)?;
    let capabilities = protector.capabilities().await?;
    assert_eq!(capabilities.protection, Protection::Authenticator);
    assert!(!capabilities.supports(AccessPolicy::DeviceBound));
    let key = Secret32::new([0x5a; 32]);
    assert!(matches!(
        protector
            .seal_key(
                &binding,
                &key,
                AccessPolicy::UserVerified,
                Interaction::Forbid
            )
            .await,
        Err(Error::InteractionRequired)
    ));
    let sealed = protector
        .seal_key(
            &binding,
            &key,
            AccessPolicy::UserVerified,
            Interaction::Allow,
        )
        .await?;
    assert_eq!(
        protector
            .unseal_key(
                &binding,
                &sealed,
                AccessPolicy::UserVerified,
                Interaction::Allow
            )
            .await?
            .expose(),
        key.expose()
    );
    let wrong = Binding::new("dev.confidex.test.other", id, AccessPolicy::UserVerified)?;
    assert!(
        protector
            .unseal_key(
                &wrong,
                &sealed,
                AccessPolicy::UserVerified,
                Interaction::Allow
            )
            .await
            .is_err()
    );
    let mut corrupted = sealed.bytes().to_vec();
    *corrupted.last_mut().ok_or(Error::InvalidData)? ^= 1;
    assert!(
        protector
            .unseal_key(
                &binding,
                &SealedKey::from_bytes(corrupted)?,
                AccessPolicy::UserVerified,
                Interaction::Allow
            )
            .await
            .is_err()
    );
    let mut bytes = MAGIC.to_vec();
    bytes.extend(id.encode());
    bytes.push(AccessPolicy::UserVerified as u8);
    bytes.extend((sealed.bytes().len() as u32).to_le_bytes());
    bytes.extend(sealed.bytes());
    bytes.extend([0; 24]);
    bytes.extend([0; 17]);
    let entry = SealedEntry::from_bytes(bytes)?;
    let mut store = platform::Store::new(namespace)?;
    store.write(id, &entry, Interaction::Forbid).await?;
    drop(store);
    let mut store = platform::Store::new(namespace)?;
    assert_eq!(
        store
            .read(id, Interaction::Forbid)
            .await?
            .ok_or(Error::NotFound)?
            .bytes(),
        entry.bytes()
    );
    store.write(id, &entry, Interaction::Forbid).await?;
    store.remove(id, Interaction::Forbid).await?;
    assert!(store.read(id, Interaction::Forbid).await?.is_none());
    let mut device = platform::system(namespace)?;
    let value = SecretBytes::new(b"public browser fixture".to_vec())?;
    assert_eq!(
        device
            .put(id, &value, AccessPolicy::DeviceBound, Interaction::Allow)
            .await
            .unwrap_err(),
        Error::Unsupported
    );
    assert_eq!(device.inspect(id).await?, EntryState::Missing);
    store.write(id, &entry, Interaction::Forbid).await?;
    Ok("PRF roundtrip, context and corruption rejection, IndexedDB persistence/replacement/removal, strict hardware refusal: pass".into())
}

#[wasm_bindgen]
pub async fn browser_finish() -> std::result::Result<String, JsValue> {
    finish()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
async fn finish() -> Result<String> {
    let namespace = "dev.confidex.test.browser";
    let id = SecretId {
        vault: [0xa5; 16],
        purpose: Purpose::SecretKey,
    };
    let mut store = platform::Store::new(namespace)?;
    let entry = store
        .read(id, Interaction::Forbid)
        .await?
        .ok_or(Error::NotFound)?;
    let (actual, policy, sealed, ..) = entry.parts()?;
    assert_eq!(actual, id);
    let binding = Binding::new(namespace, id, policy)?;
    let key = platform::Protector::new(namespace)?
        .unseal_key(
            &binding,
            &SealedKey::from_bytes(sealed.to_vec())?,
            policy,
            Interaction::Allow,
        )
        .await?;
    assert_eq!(key.expose(), &[0x5a; 32]);
    store.remove(id, Interaction::Forbid).await?;
    Ok("IndexedDB and PRF after page reload: pass".into())
}
