use crate::*;
use std::{collections::HashMap, str::FromStr};
use tss_esapi::{
    Context, TctiNameConf,
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyedHashParameters, SensitiveData,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
};
use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{OwnedObjectPath, OwnedValue, Str, Type},
};

const SERVICE: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
fn dbus_error(error: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, ..) = error {
        return match name.as_str() {
            "org.freedesktop.DBus.Error.AccessDenied" => Error::AccessDenied,
            "org.freedesktop.Secret.Error.IsLocked" => Error::KeychainLocked,
            "org.freedesktop.DBus.Error.ServiceUnknown" => Error::Unsupported,
            _ => Error::Storage,
        };
    }
    Error::Storage
}
fn proxy<'a>(conn: &'a Connection, path: &'a str, interface: &'a str) -> Result<Proxy<'a>> {
    Proxy::new(conn, SERVICE, path, interface).map_err(dbus_error)
}
fn prompt(conn: &Connection, path: &OwnedObjectPath, interaction: Interaction) -> Result<()> {
    if path.as_str() == "/" {
        return Ok(());
    }
    if interaction == Interaction::Forbid {
        return Err(Error::InteractionRequired);
    }
    let p = proxy(conn, path.as_str(), "org.freedesktop.Secret.Prompt")?;
    let mut signals = p.receive_signal("Completed").map_err(dbus_error)?;
    p.call::<_, _, ()>("Prompt", &("",)).map_err(dbus_error)?;
    let message = signals.next().ok_or(Error::Canceled)?;
    let (dismissed, _): (bool, OwnedValue) = message.body().deserialize().map_err(dbus_error)?;
    if dismissed {
        Err(Error::Canceled)
    } else {
        Ok(())
    }
}
#[derive(serde::Serialize, serde::Deserialize, Type)]
struct Secret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}
struct Session {
    conn: Connection,
    path: OwnedObjectPath,
}
impl Session {
    fn open() -> Result<Self> {
        let conn = Connection::session().map_err(|_| Error::KeychainLocked)?;
        let service = proxy(&conn, ROOT, "org.freedesktop.Secret.Service")?;
        // This session sends only authenticated ciphertext to Secret Service.
        let (_, path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", OwnedValue::from(Str::from(""))))
            .map_err(dbus_error)?;
        drop(service);
        Ok(Self { conn, path })
    }
    fn collection(&self, interaction: Interaction) -> Result<OwnedObjectPath> {
        let service = proxy(&self.conn, ROOT, "org.freedesktop.Secret.Service")?;
        let path: OwnedObjectPath = service
            .call("ReadAlias", &("default",))
            .map_err(dbus_error)?;
        if path.as_str() == "/" {
            return Err(Error::KeychainLocked);
        }
        let collection = proxy(
            &self.conn,
            path.as_str(),
            "org.freedesktop.Secret.Collection",
        )?;
        if collection
            .get_property::<bool>("Locked")
            .map_err(dbus_error)?
        {
            if interaction == Interaction::Forbid {
                return Err(Error::KeychainLocked);
            }
            let (_, request): (Vec<OwnedObjectPath>, OwnedObjectPath) =
                service.call("Unlock", &(&[&path],)).map_err(dbus_error)?;
            prompt(&self.conn, &request, interaction)?;
            if collection
                .get_property::<bool>("Locked")
                .map_err(dbus_error)?
            {
                return Err(Error::KeychainLocked);
            }
        }
        drop(collection);
        Ok(path)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(p) = proxy(
            &self.conn,
            self.path.as_str(),
            "org.freedesktop.Secret.Session",
        ) {
            let _ = p.call::<_, _, ()>("Close", &());
        }
    }
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
    fn attributes<'a>(&'a self, key: &'a str) -> HashMap<&'a str, &'a str> {
        HashMap::from([
            ("application", self.namespace.as_str()),
            ("confidex-secret-id", key),
        ])
    }
}
impl ProtectedStore for Store {
    async fn read(
        &mut self,
        id: SecretId,
        interaction: Interaction,
    ) -> Result<Option<SealedEntry>> {
        let session = Session::open()?;
        let path = session.collection(interaction)?;
        let collection = proxy(
            &session.conn,
            path.as_str(),
            "org.freedesktop.Secret.Collection",
        )?;
        let paths: Vec<OwnedObjectPath> = collection
            .call("SearchItems", &(self.attributes(&id.storage_key()),))
            .map_err(dbus_error)?;
        if paths.len() > 1 {
            return Err(Error::InvalidData);
        }
        let Some(path) = paths.first() else {
            return Ok(None);
        };
        let item = proxy(&session.conn, path.as_str(), "org.freedesktop.Secret.Item")?;
        if item.get_property::<bool>("Locked").map_err(dbus_error)? {
            return Err(Error::KeychainLocked);
        }
        let secret: Secret = item
            .call("GetSecret", &(&session.path,))
            .map_err(dbus_error)?;
        if !secret.parameters.is_empty() || secret.session != session.path {
            return Err(Error::InvalidData);
        }
        Ok(Some(SealedEntry::from_bytes(secret.value)?))
    }
    async fn write(
        &mut self,
        id: SecretId,
        entry: &SealedEntry,
        interaction: Interaction,
    ) -> Result<()> {
        let session = Session::open()?;
        let path = session.collection(interaction)?;
        let collection = proxy(
            &session.conn,
            path.as_str(),
            "org.freedesktop.Secret.Collection",
        )?;
        let key = id.storage_key();
        let mut properties: HashMap<&str, OwnedValue> = HashMap::new();
        properties.insert(
            "org.freedesktop.Secret.Item.Label",
            OwnedValue::from(Str::from("Confidex protected secret")),
        );
        let attributes: HashMap<String, String> = self
            .attributes(&key)
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        properties.insert("org.freedesktop.Secret.Item.Attributes", attributes.into());
        let secret = Secret {
            session: session.path.clone(),
            parameters: vec![],
            value: entry.bytes().to_vec(),
            content_type: "application/octet-stream".into(),
        };
        let (_, request): (OwnedObjectPath, OwnedObjectPath) = collection
            .call("CreateItem", &(properties, secret, true))
            .map_err(dbus_error)?;
        prompt(&session.conn, &request, interaction)
    }
    async fn remove(&mut self, id: SecretId, interaction: Interaction) -> Result<()> {
        let session = Session::open()?;
        let path = session.collection(interaction)?;
        let collection = proxy(
            &session.conn,
            path.as_str(),
            "org.freedesktop.Secret.Collection",
        )?;
        let paths: Vec<OwnedObjectPath> = collection
            .call("SearchItems", &(self.attributes(&id.storage_key()),))
            .map_err(dbus_error)?;
        for path in paths {
            let item = proxy(&session.conn, path.as_str(), "org.freedesktop.Secret.Item")?;
            let request: OwnedObjectPath = item.call("Delete", &()).map_err(dbus_error)?;
            prompt(&session.conn, &request, interaction)?;
        }
        Ok(())
    }
}

pub struct Protector;
fn tpm_error(_: tss_esapi::Error) -> Error {
    Error::HardwareUnavailable
}
fn context() -> Result<(Context, KeyHandle)> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tpmrm0")
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => Error::AccessDenied,
            _ => Error::HardwareUnavailable,
        })?;
    let transport = TctiNameConf::from_str("device:/dev/tpmrm0").map_err(tpm_error)?;
    let mut ctx = Context::new(transport).map_err(tpm_error)?;
    let template = tss_esapi::utils::create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        Default::default(),
    )
    .map_err(tpm_error)?;
    let parent = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(tpm_error)?
        .key_handle;
    Ok((ctx, parent))
}
fn encrypted_session(
    ctx: &mut Context,
    parent: KeyHandle,
    decrypt: bool,
    encrypt: bool,
) -> Result<()> {
    let session = ctx
        .start_auth_session(
            Some(parent),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tpm_error)?
        .ok_or(Error::HardwareUnavailable)?;
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(decrypt)
        .with_encrypt(encrypt)
        .build();
    ctx.tr_sess_set_attributes(session, attributes, mask)
        .map_err(tpm_error)?;
    ctx.set_sessions((Some(session), None, None));
    Ok(())
}
fn sealed_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_user_with_auth(true)
        .build()
        .map_err(tpm_error)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .map_err(tpm_error)
}
impl Protector {
    pub fn new(namespace: &str) -> Result<Self> {
        validate_namespace(namespace)?;
        Ok(Self)
    }
    #[cfg(feature = "backend-check")]
    pub fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}
impl KeyProtector for Protector {
    async fn capabilities(&mut self) -> Result<Capabilities> {
        context()?;
        // TPM user verification needs a hardware policy, not a UI check.
        Ok(Capabilities {
            protection: Protection::HardwareDevice,
            user_verification: false,
        })
    }
    async fn seal_key(
        &mut self,
        binding: &Binding,
        key: &Secret32,
        policy: AccessPolicy,
        _: Interaction,
    ) -> Result<SealedKey> {
        if policy != AccessPolicy::DeviceBound {
            return Err(Error::Unsupported);
        }
        let (mut ctx, parent) = context()?;
        encrypted_session(&mut ctx, parent, true, false)?;
        let mut plain = Zeroizing::new(Vec::from(binding.bytes().as_slice()));
        plain.extend(key.expose());
        let sensitive =
            SensitiveData::try_from(plain.as_slice()).map_err(|_| Error::InvalidData)?;
        let result = ctx
            .create(
                parent,
                sealed_template()?,
                None,
                Some(sensitive),
                None,
                None,
            )
            .map_err(tpm_error)?;
        let private = result.out_private.value();
        let public = result.out_public.marshall().map_err(tpm_error)?;
        let mut bytes = (private.len() as u32).to_le_bytes().to_vec();
        bytes.extend(private);
        bytes.extend(public);
        SealedKey::from_bytes(bytes)
    }
    async fn unseal_key(
        &mut self,
        binding: &Binding,
        key: &SealedKey,
        policy: AccessPolicy,
        _: Interaction,
    ) -> Result<Secret32> {
        if policy != AccessPolicy::DeviceBound {
            return Err(Error::Unsupported);
        }
        let bytes = key.bytes();
        if bytes.len() < 5 {
            return Err(Error::InvalidData);
        }
        let len =
            u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::InvalidData)?) as usize;
        if len == 0 || len > bytes.len() - 5 {
            return Err(Error::InvalidData);
        }
        let private = Private::try_from(&bytes[4..4 + len]).map_err(|_| Error::InvalidData)?;
        let public = Public::unmarshall(&bytes[4 + len..]).map_err(|_| Error::InvalidData)?;
        let mut template = sealed_template()?;
        match (&public, &mut template) {
            (
                Public::KeyedHash { unique, .. },
                Public::KeyedHash {
                    unique: expected, ..
                },
            ) => *expected = unique.clone(),
            _ => return Err(Error::InvalidData),
        }
        if public != template {
            return Err(Error::InvalidData);
        }
        let (mut ctx, parent) = context()?;
        let loaded = ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.load(parent, private, public)
            })
            .map_err(|_| Error::KeyInvalidated)?;
        encrypted_session(&mut ctx, parent, false, true)?;
        let plain = ctx.unseal(loaded.into()).map_err(|_| Error::InvalidData)?;
        let bytes = plain.value();
        if bytes.len() != 64 || &bytes[..32] != binding.bytes() {
            return Err(Error::InvalidData);
        }
        Ok(Secret32::new(
            bytes[32..].try_into().map_err(|_| Error::InvalidData)?,
        ))
    }
}
