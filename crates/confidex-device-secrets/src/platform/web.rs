use crate::*;
use js_sys::{Array, Object, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(module = "/src/platform/web.js")]
unsafe extern "C" {
    #[wasm_bindgen(js_name = attachPasskeyHost)]
    pub fn attach_passkey_host(worker: &Object);
    #[wasm_bindgen(catch)]
    fn entry(
        operation: &str,
        namespace: &str,
        id: &str,
        bytes: &Uint8Array,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch)]
    fn capabilities() -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch, js_name = createPrf)]
    fn create_prf(
        namespace: &str,
        binding: &Uint8Array,
        verified: bool,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch, js_name = getPrf)]
    fn get_prf(
        id: &Uint8Array,
        binding: &Uint8Array,
        verified: bool,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
}
fn error(value: JsValue) -> Error {
    match value.as_string().as_deref() {
        Some("Canceled") => Error::Canceled,
        Some("AccessDenied") => Error::AccessDenied,
        Some("Unsupported") => Error::Unsupported,
        Some("Limit") => Error::Limit,
        Some("InvalidData") => Error::InvalidData,
        _ => Error::Storage,
    }
}
async fn wait(promise: std::result::Result<js_sys::Promise, JsValue>) -> Result<JsValue> {
    JsFuture::from(promise.map_err(error)?).await.map_err(error)
}
fn secret(value: JsValue) -> Result<Secret32> {
    let array = value
        .dyn_into::<Uint8Array>()
        .map_err(|_| Error::InvalidData)?;
    let result = if array.length() == 32 {
        let mut secret = Secret32::new([0; 32]);
        array.copy_to(&mut *secret.0);
        Ok(secret)
    } else {
        Err(Error::InvalidData)
    };
    array.fill(0, 0, array.length());
    result
}
pub struct Store {
    namespace: String,
}
impl Store {
    pub fn new(namespace: &str) -> Result<Self> {
        validate_namespace(namespace)?;
        Ok(Self {
            namespace: namespace.into(),
        })
    }
}
impl ProtectedStore for Store {
    async fn read(&mut self, id: SecretId, _: Interaction) -> Result<Option<SealedEntry>> {
        let value = wait(entry(
            "read",
            &self.namespace,
            &id.storage_key(),
            &Uint8Array::new_with_length(0),
        ))
        .await?;
        if value.is_null() {
            return Ok(None);
        }
        if !value.is_instance_of::<Uint8Array>() {
            return Err(Error::InvalidData);
        }
        let array = Uint8Array::new(&value);
        if array.length() as usize > MAX_ENTRY_BYTES {
            return Err(Error::Limit);
        }
        Ok(Some(SealedEntry::from_bytes(array.to_vec())?))
    }
    async fn write(&mut self, id: SecretId, value: &SealedEntry, _: Interaction) -> Result<()> {
        wait(entry(
            "write",
            &self.namespace,
            &id.storage_key(),
            &Uint8Array::from(value.bytes()),
        ))
        .await?;
        Ok(())
    }
    async fn remove(&mut self, id: SecretId, _: Interaction) -> Result<()> {
        wait(entry(
            "remove",
            &self.namespace,
            &id.storage_key(),
            &Uint8Array::new_with_length(0),
        ))
        .await?;
        Ok(())
    }
}
pub struct Protector {
    namespace: String,
}
impl Protector {
    pub fn new(namespace: &str) -> Result<Self> {
        validate_namespace(namespace)?;
        Ok(Self {
            namespace: namespace.into(),
        })
    }
}
impl KeyProtector for Protector {
    async fn capabilities(&mut self) -> Result<Capabilities> {
        wait(capabilities()).await?;
        // PRF support does not prove hardware or device binding.
        Ok(Capabilities {
            protection: Protection::Authenticator,
            user_verification: true,
        })
    }
    async fn seal_key(
        &mut self,
        binding: &Binding,
        key: &Secret32,
        policy: AccessPolicy,
        interaction: Interaction,
    ) -> Result<SealedKey> {
        if interaction == Interaction::Forbid {
            return Err(Error::InteractionRequired);
        }
        let value = wait(create_prf(
            &self.namespace,
            &Uint8Array::from(binding.bytes().as_slice()),
            policy != AccessPolicy::DeviceBound,
        ))
        .await?;
        if !Array::is_array(&value) {
            return Err(Error::InvalidData);
        }
        let values = Array::from(&value);
        let wrapping = secret(values.get(1))?;
        let raw_id = values.get(0);
        if !raw_id.is_instance_of::<Uint8Array>() {
            return Err(Error::InvalidData);
        }
        let id = Uint8Array::new(&raw_id).to_vec();
        if id.is_empty() || id.len() > 1024 {
            return Err(Error::InvalidData);
        }
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
        let mut bytes = (id.len() as u16).to_le_bytes().to_vec();
        bytes.extend(id);
        bytes.extend(nonce);
        let aad = [binding.bytes().as_slice(), &bytes].concat();
        let cipher = XChaCha20Poly1305::new(wrapping.expose().into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: key.expose(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::InvalidData)?;
        bytes.extend(cipher);
        SealedKey::from_bytes(bytes)
    }
    async fn unseal_key(
        &mut self,
        binding: &Binding,
        key: &SealedKey,
        policy: AccessPolicy,
        interaction: Interaction,
    ) -> Result<Secret32> {
        if interaction == Interaction::Forbid {
            return Err(Error::InteractionRequired);
        }
        let bytes = key.bytes();
        if bytes.len() < 75 {
            return Err(Error::InvalidData);
        }
        let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if len == 0 || len > 1024 || bytes.len() != 2 + len + 24 + 48 {
            return Err(Error::InvalidData);
        }
        let wrapping = secret(
            wait(get_prf(
                &Uint8Array::from(&bytes[2..2 + len]),
                &Uint8Array::from(binding.bytes().as_slice()),
                policy != AccessPolicy::DeviceBound,
            ))
            .await?,
        )?;
        let prefix = 2 + len + 24;
        let nonce: &[u8; 24] = bytes[2 + len..prefix]
            .try_into()
            .map_err(|_| Error::InvalidData)?;
        let aad = [binding.bytes().as_slice(), &bytes[..prefix]].concat();
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new(wrapping.expose().into())
                .decrypt(
                    nonce.into(),
                    Payload {
                        msg: &bytes[prefix..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::InvalidData)?,
        );
        Ok(Secret32::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidData)?,
        ))
    }
}
