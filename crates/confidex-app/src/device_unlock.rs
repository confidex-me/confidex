use crate::{DeviceKeys, Error, audit};
use confidex_storage::{Store, StoredVault, VaultId};
use confidex_vault::{kdf, lock};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const DEFAULT_MINUTES: u16 = 36 * 60;
pub const MINUTE_OPTIONS: [u16; 7] = [5, 30, 60, 6 * 60, 12 * 60, 24 * 60, DEFAULT_MINUTES];

pub fn password_is_current(verified_at: u64, now: u64, minutes: u16) -> bool {
    let minutes = if MINUTE_OPTIONS.contains(&minutes) {
        minutes
    } else {
        DEFAULT_MINUTES
    };
    verified_at != 0
        && now
            .checked_sub(verified_at)
            .is_some_and(|age| age < u64::from(minutes) * 60_000)
}
const ENTRY_SIZE: usize = 105;

struct SavedUnlock<'a> {
    verified_at: u64,
    lock_hash: &'a [u8; 32],
    secret_key: &'a [u8; 32],
    unlock_key: &'a [u8; 32],
}

impl<'a> SavedUnlock<'a> {
    fn decode(bytes: &'a [u8]) -> Option<Self> {
        let bytes: &[u8; ENTRY_SIZE] = bytes.try_into().ok()?;
        if bytes[0] != 1 {
            return None;
        }
        Some(Self {
            verified_at: u64::from_le_bytes(bytes[1..9].try_into().ok()?),
            lock_hash: bytes[9..41].try_into().ok()?,
            secret_key: bytes[41..73].try_into().ok()?,
            unlock_key: bytes[73..105].try_into().ok()?,
        })
    }

    fn current(&self, now: u64, minutes: u16, wire: &[u8]) -> bool {
        password_is_current(self.verified_at, now, minutes)
            && Sha256::digest(wire).as_slice() == self.lock_hash
    }
}

pub(crate) async fn remember<K: DeviceKeys>(
    keys: &mut K,
    vault: VaultId,
    wire: &[u8],
    secret_key: &[u8; 32],
    unlock_key: &[u8; 32],
) -> Option<u64> {
    let now = keys.now_ms()?;
    let mut value = Zeroizing::new([0u8; ENTRY_SIZE]);
    value[0] = 1;
    value[1..9].copy_from_slice(&now.to_le_bytes());
    value[9..41].copy_from_slice(&Sha256::digest(wire));
    value[41..73].copy_from_slice(secret_key);
    value[73..].copy_from_slice(unlock_key);
    keys.save_device_unlock(vault, now, value.as_slice())
        .await
        .then_some(now)
}

pub(crate) async fn open<S: Store, K: DeviceKeys>(
    store: &mut S,
    keys: &mut K,
    stored: &StoredVault,
    password: &str,
) -> Result<(lock::OpenedVault, Option<u64>), Error> {
    if password.len() > 4096 {
        return Err(Error::Input);
    }
    let id = stored.info.id;
    let value = keys.load_device_unlock(id).await.ok_or(Error::Key)?;
    let saved = SavedUnlock::decode(&value).ok_or(Error::Key)?;
    let now = keys.now_ms().ok_or(Error::PasswordRequired)?;
    if password.is_empty() {
        if !saved.current(now, keys.device_unlock_minutes(), &stored.lock) {
            return Err(Error::PasswordRequired);
        }
        let opened = lock::open_with_saved_key(&stored.lock, saved.unlock_key, saved.secret_key)
            .map_err(|_| Error::Key)?;
        if opened.vault_id() != id {
            return Err(Error::Integrity);
        }
        audit(store, &opened).await?;
        return Ok((opened, Some(saved.verified_at)));
    }
    let (opened, unlock_key) = lock::open_with_unlock_key(
        &stored.lock,
        password.as_bytes(),
        saved.secret_key,
        kdf::REQUIRED_MEMORY,
    )
    .map_err(|_| Error::Auth)?;
    if opened.vault_id() != id {
        return Err(Error::Integrity);
    }
    audit(store, &opened).await?;
    let verified_at = remember(keys, id, &stored.lock, saved.secret_key, &unlock_key).await;
    Ok((opened, verified_at.or(Some(0))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_unlock_is_bound_to_the_lock_and_password_interval() {
        let interval = u64::from(DEFAULT_MINUTES) * 60_000;
        let verified_at = interval;
        let wire = b"public lock fixture";
        let hash = Sha256::digest(wire).into();
        let saved = SavedUnlock {
            verified_at,
            lock_hash: &hash,
            secret_key: &[1; 32],
            unlock_key: &[2; 32],
        };
        assert!(saved.current(verified_at, DEFAULT_MINUTES, wire));
        assert!(saved.current(verified_at + interval - 1, DEFAULT_MINUTES, wire));
        assert!(!saved.current(verified_at + interval, DEFAULT_MINUTES, wire));
        assert!(!saved.current(verified_at - 1, DEFAULT_MINUTES, wire));
        assert!(!saved.current(verified_at, DEFAULT_MINUTES, b"other lock"));
        for minutes in MINUTE_OPTIONS {
            let expires = verified_at + u64::from(minutes) * 60_000;
            assert!(saved.current(expires - 1, minutes, wire));
            assert!(!saved.current(expires, minutes, wire));
        }
    }
}
