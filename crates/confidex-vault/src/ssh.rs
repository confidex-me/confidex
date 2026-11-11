use crate::{
    record::{Mapping, Value},
    resources::MAX_OPEN_MEMORY,
};
use ed25519_dalek::{Signer, Verifier};
use ssh_encoding::{Decode, Reader};
use ssh_key::{Algorithm, EcdsaCurve, Kdf, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

pub const MAX_KEY: usize = 65_536;
pub const MAX_MESSAGE: usize = 32_768;
pub const REQUIRED_MEMORY: usize = 8 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Invalid,
    Unsupported,
    PassphraseRequired,
    Authentication,
    Signature,
}
pub struct Key {
    inner: PrivateKey,
}

fn admit(input_len: usize, memory_budget: usize) -> Result<(), Error> {
    if input_len > MAX_KEY || !(REQUIRED_MEMORY..=MAX_OPEN_MEMORY).contains(&memory_budget) {
        return Err(Error::Limit);
    }
    Ok(())
}
impl Key {
    pub fn import(
        pem: &[u8],
        passphrase: Option<&[u8]>,
        memory_budget: usize,
    ) -> Result<Self, Error> {
        admit(pem.len(), memory_budget)?;
        if passphrase.is_some_and(|p| p.len() > 4096) {
            return Err(Error::Limit);
        }
        let mut key = PrivateKey::from_openssh(pem).map_err(|_| Error::Invalid)?;
        Self::algorithm(&key)?;
        if key.is_encrypted() {
            if key.cipher() != ssh_key::Cipher::Aes256Ctr {
                return Err(Error::Unsupported);
            }
            match key.kdf() {
                Kdf::Bcrypt { salt, rounds }
                    if salt.len() <= 64 && !salt.is_empty() && (1..=64).contains(rounds) => {}
                _ => return Err(Error::Limit),
            }
            key = key
                .decrypt(passphrase.ok_or(Error::PassphraseRequired)?)
                .map_err(|_| Error::Authentication)?;
        }
        Self::checked(key)
    }
    pub fn from_value(value: &Mapping, memory_budget: usize) -> Result<Self, Error> {
        let Some(Value::Binary(bytes)) = value.get("private_key") else {
            return Err(Error::Invalid);
        };
        admit(bytes.len(), memory_budget)?;
        let key = PrivateKey::from_bytes(bytes).map_err(|_| Error::Invalid)?;
        if key.is_encrypted() {
            return Err(Error::Unsupported);
        }
        Self::checked(key)
    }
    fn algorithm(key: &PrivateKey) -> Result<(), Error> {
        match key.algorithm() {
            Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => Ok(()),
            _ => Err(Error::Unsupported),
        }
    }
    fn checked(inner: PrivateKey) -> Result<Self, Error> {
        Self::algorithm(&inner)?;
        if inner.comment().as_bytes().len() > 1024 {
            return Err(Error::Limit);
        }
        let key = Self { inner };
        // Verify a fixed challenge to detect mismatched public and private components.
        key.sign(b"confidex/ssh/import-check/v1")?;
        Ok(key)
    }
    pub fn to_value(&self) -> Result<Mapping, Error> {
        let bytes = self.inner.to_bytes().map_err(|_| Error::Invalid)?;
        Ok(Mapping::from([(
            "private_key".into(),
            Value::Binary(bytes.to_vec()),
        )]))
    }
    pub fn public_blob(&self) -> Result<Vec<u8>, Error> {
        self.inner
            .public_key()
            .to_bytes()
            .map_err(|_| Error::Invalid)
    }
    pub fn public_text(&self) -> Result<String, Error> {
        self.inner
            .public_key()
            .to_openssh()
            .map_err(|_| Error::Invalid)
    }
    pub fn private_text(&self) -> Result<Zeroizing<String>, Error> {
        self.inner
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|_| Error::Invalid)
    }
    pub fn key_type(&self) -> &'static str {
        match self.inner.algorithm() {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => "ECDSA P-256",
            _ => unreachable!("checked key algorithm"),
        }
    }
    pub fn fingerprint(&self) -> String {
        self.inner
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    }
    pub fn sign(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if message.len() > MAX_MESSAGE {
            return Err(Error::Limit);
        }
        let signature: Signature = self.inner.try_sign(message).map_err(|_| Error::Signature)?;
        Verifier::verify(self.inner.public_key(), message, &signature)
            .map_err(|_| Error::Signature)?;
        Ok(Zeroizing::new(
            Vec::<u8>::try_from(signature).map_err(|_| Error::Signature)?,
        ))
    }
}
pub fn verify(public_blob: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_blob.len() > 4096 || message.len() > MAX_MESSAGE || signature.len() > 1024 {
        return Err(Error::Limit);
    }
    let public = PublicKey::from_bytes(public_blob).map_err(|_| Error::Invalid)?;
    match public.algorithm() {
        Algorithm::Ed25519
        | Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => (),
        _ => return Err(Error::Unsupported),
    }
    let mut bytes = signature;
    let signature = Signature::decode(&mut bytes).map_err(|_| Error::Invalid)?;
    bytes.finish(()).map_err(|_| Error::Invalid)?;
    Verifier::verify(&public, message, &signature).map_err(|_| Error::Signature)
}
