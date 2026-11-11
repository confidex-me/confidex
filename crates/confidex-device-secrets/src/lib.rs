//! Local protected secrets with a shared native and browser contract.
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

pub mod platform;
#[cfg(all(target_arch = "wasm32", feature = "backend-check"))]
mod web_check;

pub const MAX_SECRET_BYTES: usize = 1024;
pub const MAX_ENTRY_BYTES: usize = 16_384;
const MAGIC: &[u8; 8] = b"CFDXDS01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotFound,
    KeychainLocked,
    InteractionRequired,
    AccessDenied,
    Canceled,
    HardwareUnavailable,
    KeyInvalidated,
    Unsupported,
    InvalidData,
    Storage,
    Limit,
    Random,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interaction {
    Forbid,
    Allow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    SecretKey = 0,
    QuickUnlock = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretId {
    pub vault: [u8; 16],
    pub purpose: Purpose,
}
impl SecretId {
    pub fn storage_key(self) -> String {
        format!("{}-{}", hex(&self.vault), self.purpose as u8)
    }
    fn encode(self) -> [u8; 17] {
        let mut b = [0; 17];
        b[..16].copy_from_slice(&self.vault);
        b[16] = self.purpose as u8;
        b
    }
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessPolicy {
    DeviceBound = 0,
    UserVerified = 1,
    AuthenticatorVerified = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protection {
    /// Use the OS device boundary. This does not attest physical hardware.
    HardwareDevice = 0,
    /// Use an authenticator without a proven device boundary.
    Authenticator = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub protection: Protection,
    pub user_verification: bool,
}
impl Capabilities {
    pub fn supports(self, policy: AccessPolicy) -> bool {
        match policy {
            AccessPolicy::DeviceBound => self.protection == Protection::HardwareDevice,
            AccessPolicy::UserVerified => {
                self.protection == Protection::HardwareDevice && self.user_verification
            }
            AccessPolicy::AuthenticatorVerified => {
                self.protection == Protection::Authenticator && self.user_verification
            }
        }
    }
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err(Error::Limit);
        }
        Ok(Self(bytes))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
pub struct Secret32(Zeroizing<[u8; 32]>);
impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn random() -> Result<Self> {
        let mut key = Self::new([0; 32]);
        getrandom::fill(&mut *key.0).map_err(|_| Error::Random)?;
        Ok(key)
    }
}
impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32([REDACTED])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding([u8; 32]);
impl Binding {
    pub fn new(namespace: &str, id: SecretId, policy: AccessPolicy) -> Result<Self> {
        validate_namespace(namespace)?;
        let mut hash = Sha256::new();
        hash.update(b"confidex/device-secrets/binding/v1\0");
        hash.update(namespace.as_bytes());
        hash.update([0]);
        hash.update(id.encode());
        hash.update([policy as u8]);
        Ok(Self(hash.finalize().into()))
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
pub fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty()
        || namespace.len() > 128
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_".contains(&b))
    {
        Err(Error::InvalidData)
    } else {
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct SealedKey(Vec<u8>);
impl SealedKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 8192 {
            Err(Error::Limit)
        } else {
            Ok(Self(bytes))
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Debug)]
pub struct SealedEntry(Vec<u8>);
type EntryParts<'a> = (SecretId, AccessPolicy, &'a [u8], &'a [u8], &'a [u8]);
impl SealedEntry {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(Error::Limit);
        }
        let s = Self(bytes);
        s.parts()?;
        Ok(s)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn parts(&self) -> Result<EntryParts<'_>> {
        let b = &self.0;
        if b.len() < 71 || b.get(..8) != Some(MAGIC) {
            return Err(Error::InvalidData);
        }
        let id = SecretId {
            vault: b[8..24].try_into().map_err(|_| Error::InvalidData)?,
            purpose: match b[24] {
                0 => Purpose::SecretKey,
                1 => Purpose::QuickUnlock,
                _ => return Err(Error::InvalidData),
            },
        };
        let policy = match b[25] {
            0 => AccessPolicy::DeviceBound,
            1 => AccessPolicy::UserVerified,
            2 => AccessPolicy::AuthenticatorVerified,
            _ => return Err(Error::InvalidData),
        };
        if id.purpose == Purpose::QuickUnlock
            && !matches!(
                policy,
                AccessPolicy::UserVerified | AccessPolicy::AuthenticatorVerified
            )
        {
            return Err(Error::InvalidData);
        }
        let len =
            u32::from_le_bytes(b[26..30].try_into().map_err(|_| Error::InvalidData)?) as usize;
        if len == 0
            || len > 8192
            || b.len() < 30 + len + 24 + 17
            || b.len() > 30 + len + 24 + MAX_SECRET_BYTES + 16
        {
            return Err(Error::InvalidData);
        }
        Ok((
            id,
            policy,
            &b[30..30 + len],
            &b[30 + len..54 + len],
            &b[54 + len..],
        ))
    }
}

#[allow(async_fn_in_trait)]
/// Store one complete encrypted entry per ID. A failed write must keep the old entry.
/// `Forbid` must not show a prompt. Missing and locked entries must be distinct.
pub trait ProtectedStore {
    async fn read(&mut self, id: SecretId, interaction: Interaction)
    -> Result<Option<SealedEntry>>;
    async fn write(
        &mut self,
        id: SecretId,
        entry: &SealedEntry,
        interaction: Interaction,
    ) -> Result<()>;
    async fn remove(&mut self, id: SecretId, interaction: Interaction) -> Result<()>;
}
#[allow(async_fn_in_trait)]
/// Protect a data key and its binding. Do not substitute software protection.
/// `Forbid` must not show a prompt. Do not create a replacement key during unseal.
pub trait KeyProtector {
    async fn capabilities(&mut self) -> Result<Capabilities>;
    async fn seal_key(
        &mut self,
        binding: &Binding,
        key: &Secret32,
        policy: AccessPolicy,
        interaction: Interaction,
    ) -> Result<SealedKey>;
    async fn unseal_key(
        &mut self,
        binding: &Binding,
        key: &SealedKey,
        policy: AccessPolicy,
        interaction: Interaction,
    ) -> Result<Secret32>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    Missing,
    Stored { policy: AccessPolicy },
}

pub struct OpenedEntry {
    id: SecretId,
    binding: Binding,
    key: Secret32,
    entry: SealedEntry,
    pub secret: SecretBytes,
}

impl OpenedEntry {
    pub fn sealed_bytes(&self) -> &[u8] {
        self.entry.bytes()
    }
}

pub struct DeviceSecrets<S, P> {
    namespace: String,
    store: S,
    protector: P,
}
impl<S: ProtectedStore, P: KeyProtector> DeviceSecrets<S, P> {
    pub fn new(namespace: &str, store: S, protector: P) -> Result<Self> {
        validate_namespace(namespace)?;
        Ok(Self {
            namespace: namespace.into(),
            store,
            protector,
        })
    }
    pub async fn capabilities(&mut self) -> Result<Capabilities> {
        self.protector.capabilities().await
    }
    /// Read structural metadata without opening a key. This does not verify the ciphertext.
    pub async fn inspect(&mut self, id: SecretId) -> Result<EntryState> {
        let Some(entry) = self.store.read(id, Interaction::Forbid).await? else {
            return Ok(EntryState::Missing);
        };
        let (actual, policy, ..) = entry.parts()?;
        if actual != id {
            return Err(Error::InvalidData);
        };
        Ok(EntryState::Stored { policy })
    }
    pub async fn put(
        &mut self,
        id: SecretId,
        secret: &SecretBytes,
        policy: AccessPolicy,
        interaction: Interaction,
    ) -> Result<()> {
        if id.purpose == Purpose::QuickUnlock
            && !matches!(
                policy,
                AccessPolicy::UserVerified | AccessPolicy::AuthenticatorVerified
            )
        {
            return Err(Error::Unsupported);
        }
        if !self.protector.capabilities().await?.supports(policy) {
            return Err(Error::Unsupported);
        }
        let binding = Binding::new(&self.namespace, id, policy)?;
        let key = Secret32::random()?;
        let sealed = self
            .protector
            .seal_key(&binding, &key, policy, interaction)
            .await?;
        let mut header = MAGIC.to_vec();
        header.extend(id.encode());
        header.push(policy as u8);
        header.extend((sealed.bytes().len() as u32).to_le_bytes());
        header.extend(sealed.bytes());
        let entry = seal_entry(header, &binding, &key, secret)?;
        self.store.write(id, &entry, interaction).await
    }
    pub async fn get(&mut self, id: SecretId, interaction: Interaction) -> Result<SecretBytes> {
        Ok(self.open_entry(id, interaction).await?.secret)
    }
    pub async fn open_entry(
        &mut self,
        id: SecretId,
        interaction: Interaction,
    ) -> Result<OpenedEntry> {
        let entry = self
            .store
            .read(id, interaction)
            .await?
            .ok_or(Error::NotFound)?;
        let (actual, policy, sealed, nonce, cipher) = entry.parts()?;
        if actual != id {
            return Err(Error::InvalidData);
        }
        if !self.protector.capabilities().await?.supports(policy) {
            return Err(Error::Unsupported);
        }
        let binding = Binding::new(&self.namespace, id, policy)?;
        let key = self
            .protector
            .unseal_key(
                &binding,
                &SealedKey::from_bytes(sealed.to_vec())?,
                policy,
                interaction,
            )
            .await?;
        let prefix = entry.0.len() - cipher.len();
        let nonce: &[u8; 24] = nonce.try_into().map_err(|_| Error::InvalidData)?;
        let plain = XChaCha20Poly1305::new(key.expose().into())
            .decrypt(
                nonce.into(),
                Payload {
                    msg: cipher,
                    aad: &[binding.bytes().as_slice(), &entry.0[..prefix]].concat(),
                },
            )
            .map_err(|_| Error::InvalidData)?;
        Ok(OpenedEntry {
            id,
            binding,
            key,
            entry,
            secret: SecretBytes::new(plain)?,
        })
    }
    pub async fn replace_opened(
        &mut self,
        opened: OpenedEntry,
        secret: &SecretBytes,
        interaction: Interaction,
    ) -> Result<()> {
        let (_, policy, sealed, ..) = opened.entry.parts()?;
        if Binding::new(&self.namespace, opened.id, policy)? != opened.binding {
            return Err(Error::InvalidData);
        }
        let header = opened.entry.bytes()[..30 + sealed.len()].to_vec();
        let entry = seal_entry(header, &opened.binding, &opened.key, secret)?;
        self.store.write(opened.id, &entry, interaction).await
    }
    pub async fn remove(&mut self, id: SecretId, interaction: Interaction) -> Result<()> {
        self.store.remove(id, interaction).await
    }
    pub fn into_backends(self) -> (S, P) {
        (self.store, self.protector)
    }
}

fn seal_entry(
    mut header: Vec<u8>,
    binding: &Binding,
    key: &Secret32,
    secret: &SecretBytes,
) -> Result<SealedEntry> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
    header.extend(nonce);
    let cipher = XChaCha20Poly1305::new(key.expose().into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret.expose(),
                aad: &[binding.bytes().as_slice(), &header].concat(),
            },
        )
        .map_err(|_| Error::InvalidData)?;
    header.extend(cipher);
    SealedEntry::from_bytes(header)
}
