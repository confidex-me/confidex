use ed25519_dalek::{Signature, VerifyingKey};

use crate::crypto::VaultKeys;

#[derive(Debug, PartialEq, Eq)]
pub enum TrustError {
    UnknownKey,
    InvalidKey,
    KeyMismatch,
    WrongVault,
    InvalidSignature,
}

pub struct TrustAnchor {
    vault_id: [u8; 16],
    key: VerifyingKey,
}

impl TrustAnchor {
    pub fn from_opened_lock(
        vault_id: [u8; 16],
        keys: &VaultKeys,
        authenticated_header_key: &[u8; 32],
    ) -> Result<Self, TrustError> {
        let derived = keys.signing_key().verifying_key();
        if derived.as_bytes() != authenticated_header_key {
            return Err(TrustError::KeyMismatch);
        }
        Ok(Self {
            vault_id,
            key: derived,
        })
    }

    pub fn from_local_pin(
        vault_id: [u8; 16],
        pinned_key: Option<&[u8; 32]>,
    ) -> Result<Self, TrustError> {
        let bytes = pinned_key.ok_or(TrustError::UnknownKey)?;
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| TrustError::InvalidKey)?;
        if key.is_weak() || key.to_edwards().compress().as_bytes() != bytes {
            return Err(TrustError::InvalidKey);
        }
        Ok(Self { vault_id, key })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }

    pub fn verify(
        &self,
        vault_id: &[u8; 16],
        signed_bytes: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), TrustError> {
        if vault_id != &self.vault_id {
            return Err(TrustError::WrongVault);
        }
        self.key
            .verify_strict(signed_bytes, &Signature::from_bytes(signature))
            .map_err(|_| TrustError::InvalidSignature)
    }
}
