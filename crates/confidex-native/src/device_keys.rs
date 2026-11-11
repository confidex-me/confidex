use confidex_app::DeviceKeys;
use confidex_device_secrets::{
    AccessPolicy, Error, Interaction, Purpose, SecretBytes, SecretId, platform,
};
use confidex_storage::VaultId;

#[cfg(not(test))]
const NAMESPACE: &str = "me.confidex.device-secrets";
#[cfg(test)]
const NAMESPACE: &str = "dev.confidex.test.integration";

pub struct Credentials;

#[derive(Debug)]
pub struct DeviceKeyError;

/// Ask for the secret key if this function returns no key or an error.
pub fn load_key(id: VaultId, allow_interaction: bool) -> Result<Option<String>, DeviceKeyError> {
    let interaction = if allow_interaction {
        Interaction::Allow
    } else {
        Interaction::Forbid
    };
    futures_executor::block_on(read(id, interaction))
}

fn secret_id(vault: VaultId) -> SecretId {
    SecretId {
        vault,
        purpose: Purpose::SecretKey,
    }
}

#[cfg(target_os = "macos")]
fn unlock_id(vault: VaultId) -> SecretId {
    SecretId {
        vault,
        purpose: Purpose::QuickUnlock,
    }
}

async fn read(id: VaultId, interaction: Interaction) -> Result<Option<String>, DeviceKeyError> {
    let mut secrets = platform::system(NAMESPACE).map_err(|_| DeviceKeyError)?;
    match secrets.get(secret_id(id), interaction).await {
        Ok(key) => std::str::from_utf8(key.expose())
            .map(|text| Some(text.to_owned()))
            .map_err(|_| DeviceKeyError),
        Err(Error::NotFound) => Ok(None),
        Err(_) => Err(DeviceKeyError),
    }
}

impl DeviceKeys for Credentials {
    async fn load(&mut self, id: VaultId) -> Option<String> {
        read(id, Interaction::Forbid).await.ok().flatten()
    }

    async fn save(&mut self, id: VaultId, key: &str) -> bool {
        let Ok(mut secrets) = platform::system(NAMESPACE) else {
            return false;
        };
        let slot = secret_id(id);
        let interaction = Interaction::Forbid;
        if secrets
            .get(slot, interaction)
            .await
            .is_ok_and(|saved| saved.expose() == key.as_bytes())
        {
            return true;
        }
        let Ok(key_bytes) = SecretBytes::new(key.as_bytes().to_vec()) else {
            return false;
        };
        secrets
            .put(slot, &key_bytes, AccessPolicy::DeviceBound, interaction)
            .await
            .is_ok()
            && secrets
                .get(slot, interaction)
                .await
                .is_ok_and(|saved| saved.expose() == key_bytes.expose())
    }

    async fn remove(&mut self, id: VaultId) -> bool {
        let Ok(mut secrets) = platform::system(NAMESPACE) else {
            return false;
        };
        #[cfg(target_os = "macos")]
        if secrets
            .remove(unlock_id(id), Interaction::Forbid)
            .await
            .is_err()
        {
            return false;
        }
        secrets
            .remove(secret_id(id), Interaction::Forbid)
            .await
            .is_ok()
    }
}

#[cfg(target_os = "macos")]
pub use touch_id::TouchIdKeys;

#[cfg(target_os = "macos")]
mod touch_id {
    use super::*;
    use confidex_device_secrets::{DeviceSecrets, OpenedEntry};
    use std::time::SystemTime;

    pub struct TouchIdKeys {
        minutes: u16,
        available: bool,
        opened: Option<(OpenedEntry, u64)>,
    }

    impl TouchIdKeys {
        pub fn new(minutes: u16, available: bool) -> Self {
            Self {
                minutes,
                available,
                opened: None,
            }
        }

        pub fn available() -> bool {
            platform::system(NAMESPACE).ok().is_some_and(|mut secrets| {
                futures_executor::block_on(secrets.capabilities())
                    .is_ok_and(|capabilities| capabilities.supports(AccessPolicy::UserVerified))
            })
        }
    }

    impl DeviceKeys for TouchIdKeys {
        async fn load(&mut self, vault: VaultId) -> Option<String> {
            Credentials.load(vault).await
        }

        async fn save(&mut self, vault: VaultId, key: &str) -> bool {
            Credentials.save(vault, key).await
        }

        async fn remove(&mut self, vault: VaultId) -> bool {
            Credentials.remove(vault).await
        }

        async fn has_saved_key(&mut self, vault: VaultId) -> bool {
            Credentials.has_saved_key(vault).await
                || self.device_unlock_verified_at(vault).await.is_some()
        }

        fn device_unlock_minutes(&self) -> u16 {
            self.minutes
        }

        fn now_ms(&self) -> Option<u64> {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()?
                .as_millis()
                .try_into()
                .ok()
        }

        async fn device_unlock_verified_at(&mut self, vault: VaultId) -> Option<u64> {
            if !self.available {
                return None;
            }
            platform::Store::new(NAMESPACE)
                .ok()?
                .verified_at(unlock_id(vault))
                .ok()
                .flatten()
        }

        async fn load_device_unlock(
            &mut self,
            vault: VaultId,
        ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
            let previous = self.device_unlock_verified_at(vault).await?;
            let entry = platform::system(NAMESPACE)
                .ok()?
                .open_entry(unlock_id(vault), Interaction::Allow)
                .await
                .ok()?;
            let value = zeroize::Zeroizing::new(entry.secret.expose().to_vec());
            self.opened = Some((entry, previous));
            Some(value)
        }

        async fn save_device_unlock(
            &mut self,
            vault: VaultId,
            verified_at: u64,
            bytes: &[u8],
        ) -> bool {
            if !self.available {
                return false;
            }
            let Ok(store) = platform::Store::new(NAMESPACE) else {
                return false;
            };
            let previous = self.opened.as_ref().map(|(_, previous)| *previous);
            let store = store.with_verification(verified_at, previous);
            let Ok(protector) = platform::Protector::new(NAMESPACE) else {
                return false;
            };
            let Ok(mut secrets) = DeviceSecrets::new(NAMESPACE, store, protector) else {
                return false;
            };
            let Ok(value) = SecretBytes::new(bytes.to_vec()) else {
                return false;
            };
            match self.opened.take() {
                Some((entry, _)) => secrets
                    .replace_opened(entry, &value, Interaction::Allow)
                    .await
                    .is_ok(),
                None => secrets
                    .put(
                        unlock_id(vault),
                        &value,
                        AccessPolicy::UserVerified,
                        Interaction::Allow,
                    )
                    .await
                    .is_ok(),
            }
        }

        async fn disable_device_unlock(&mut self, vault: VaultId, key: &str) -> bool {
            if !Credentials.save(vault, key).await {
                return false;
            }
            let Ok(mut secrets) = platform::system(NAMESPACE) else {
                return false;
            };
            secrets
                .remove(unlock_id(vault), Interaction::Allow)
                .await
                .is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidex_app::{Command, Engine, Error as AppError, Output, Request};
    use confidex_device_secrets::{ProtectedStore, SealedEntry};
    use confidex_storage::SqliteStore;
    use futures_executor::block_on;

    struct Fixture(VaultId);
    impl Drop for Fixture {
        fn drop(&mut self) {
            block_on(Credentials.remove(self.0));
        }
    }

    #[test]
    #[ignore = "requires an available system keychain and hardware protector"]
    fn unreadable_saved_key_requires_manual_key() {
        let mut store = SqliteStore::open(std::path::Path::new(":memory:")).unwrap();
        let mut engine = Engine::default();
        let password = "public-device-key-integration";
        let run = |engine: &mut Engine, store: &mut SqliteStore, command| {
            block_on(engine.execute(
                store,
                &mut Credentials,
                &mut Request {
                    generation: 0,
                    command,
                },
            ))
            .result
        };
        let Output::Created(created) = run(
            &mut engine,
            &mut store,
            Command::Create {
                name: "Public hardware storage fixture".into(),
                password: password.into(),
                remember: true,
            },
        )
        .unwrap() else {
            panic!("expected a new vault")
        };
        let vault = created.info.id;
        let _fixture = Fixture(vault);
        assert!(created.remembered);
        assert!(
            load_key(vault, false)
                .unwrap()
                .is_some_and(|saved| saved == created.key)
        );

        block_on(async {
            let mut store = platform::Store::new(NAMESPACE).unwrap();
            let id = secret_id(vault);
            let entry = store.read(id, Interaction::Forbid).await.unwrap().unwrap();
            let mut bytes = entry.bytes().to_vec();
            *bytes.last_mut().unwrap() ^= 1;
            store
                .write(
                    id,
                    &SealedEntry::from_bytes(bytes).unwrap(),
                    Interaction::Forbid,
                )
                .await
                .unwrap();
        });

        assert!(matches!(
            run(&mut engine, &mut store, Command::Select { vault }),
            Ok(Output::Selected {
                remembered: false,
                ..
            })
        ));
        let unlock = |key: String, remember| Command::Unlock {
            vault,
            password: password.into(),
            key,
            remember,
        };
        assert!(matches!(
            run(&mut engine, &mut store, unlock(String::new(), true)),
            Err(AppError::Key)
        ));
        assert!(matches!(
            run(&mut engine, &mut store, unlock(created.key.clone(), false)),
            Ok(Output::Opened {
                remembered: false,
                ..
            })
        ));
        assert!(load_key(vault, false).is_err());
        assert!(matches!(
            run(&mut engine, &mut store, unlock(created.key.clone(), true)),
            Ok(Output::Opened {
                remembered: true,
                ..
            })
        ));
        assert!(
            load_key(vault, false)
                .unwrap()
                .is_some_and(|saved| saved == created.key)
        );
        assert!(block_on(Credentials.remove(vault)));
        assert!(load_key(vault, false).unwrap().is_none());
    }
}
