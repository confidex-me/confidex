use confidex_device_secrets::*;
use futures_executor::block_on;
use std::collections::BTreeMap;

const NAMESPACE: &str = "dev.confidex.test.contract";
const ID: SecretId = SecretId {
    vault: [1; 16],
    purpose: Purpose::SecretKey,
};
#[derive(Default)]
struct MemoryStore {
    entries: BTreeMap<String, SealedEntry>,
    fail_write: bool,
    locked: bool,
}
impl ProtectedStore for MemoryStore {
    async fn read(&mut self, id: SecretId, _: Interaction) -> Result<Option<SealedEntry>> {
        if self.locked {
            return Err(Error::KeychainLocked);
        }
        Ok(self.entries.get(&id.storage_key()).cloned())
    }
    async fn write(&mut self, id: SecretId, entry: &SealedEntry, _: Interaction) -> Result<()> {
        if self.fail_write {
            return Err(Error::Storage);
        }
        if self.locked {
            return Err(Error::KeychainLocked);
        }
        self.entries.insert(id.storage_key(), entry.clone());
        Ok(())
    }
    async fn remove(&mut self, id: SecretId, _: Interaction) -> Result<()> {
        if self.locked {
            return Err(Error::KeychainLocked);
        }
        self.entries.remove(&id.storage_key());
        Ok(())
    }
}
struct TestProtector {
    keys: Vec<(Binding, Secret32, AccessPolicy)>,
    capabilities: Capabilities,
    unavailable: bool,
    opens: usize,
}
impl Default for TestProtector {
    fn default() -> Self {
        Self {
            keys: vec![],
            capabilities: Capabilities {
                protection: Protection::HardwareDevice,
                user_verification: true,
            },
            unavailable: false,
            opens: 0,
        }
    }
}
impl KeyProtector for TestProtector {
    async fn capabilities(&mut self) -> Result<Capabilities> {
        if self.unavailable {
            Err(Error::HardwareUnavailable)
        } else {
            Ok(self.capabilities)
        }
    }
    async fn seal_key(
        &mut self,
        binding: &Binding,
        key: &Secret32,
        policy: AccessPolicy,
        _: Interaction,
    ) -> Result<SealedKey> {
        self.keys
            .push((binding.clone(), Secret32::new(*key.expose()), policy));
        SealedKey::from_bytes((self.keys.len() as u64).to_le_bytes().to_vec())
    }
    async fn unseal_key(
        &mut self,
        binding: &Binding,
        key: &SealedKey,
        policy: AccessPolicy,
        interaction: Interaction,
    ) -> Result<Secret32> {
        if policy == AccessPolicy::UserVerified && interaction == Interaction::Forbid {
            return Err(Error::InteractionRequired);
        }
        self.opens += 1;
        let id =
            u64::from_le_bytes(key.bytes().try_into().map_err(|_| Error::InvalidData)?) as usize;
        let (saved_binding, key, saved_policy) = self
            .keys
            .get(id.checked_sub(1).ok_or(Error::InvalidData)?)
            .ok_or(Error::KeyInvalidated)?;
        if saved_binding != binding || *saved_policy != policy {
            return Err(Error::InvalidData);
        }
        Ok(Secret32::new(*key.expose()))
    }
}
fn device() -> DeviceSecrets<MemoryStore, TestProtector> {
    DeviceSecrets::new(NAMESPACE, MemoryStore::default(), TestProtector::default()).unwrap()
}
fn fixture() -> SecretBytes {
    SecretBytes::new(b"public contract fixture".to_vec()).unwrap()
}

#[test]
fn roundtrip_reopen_and_addressed_removal() {
    block_on(async {
        let mut device = device();
        device
            .put(
                ID,
                &fixture(),
                AccessPolicy::DeviceBound,
                Interaction::Forbid,
            )
            .await
            .unwrap();
        let other = SecretId {
            vault: [2; 16],
            ..ID
        };
        device
            .put(
                other,
                &fixture(),
                AccessPolicy::DeviceBound,
                Interaction::Forbid,
            )
            .await
            .unwrap();
        let (store, protector) = device.into_backends();
        let mut device = DeviceSecrets::new(NAMESPACE, store, protector).unwrap();
        assert_eq!(
            device.get(ID, Interaction::Forbid).await.unwrap().expose(),
            fixture().expose()
        );
        device.remove(ID, Interaction::Forbid).await.unwrap();
        device.remove(ID, Interaction::Forbid).await.unwrap();
        assert_eq!(device.inspect(ID).await.unwrap(), EntryState::Missing);
        assert_eq!(
            device.get(ID, Interaction::Forbid).await.unwrap_err(),
            Error::NotFound
        );
        assert_eq!(
            device
                .get(other, Interaction::Forbid)
                .await
                .unwrap()
                .expose(),
            fixture().expose()
        );
    });
}

#[test]
fn replacement_failure_keeps_previous_entry() {
    block_on(async {
        let mut device = device();
        device
            .put(
                ID,
                &fixture(),
                AccessPolicy::DeviceBound,
                Interaction::Forbid,
            )
            .await
            .unwrap();
        let (mut store, protector) = device.into_backends();
        store.fail_write = true;
        let before = store
            .entries
            .get(&ID.storage_key())
            .unwrap()
            .bytes()
            .to_vec();
        let mut device = DeviceSecrets::new(NAMESPACE, store, protector).unwrap();
        assert_eq!(
            device
                .put(
                    ID,
                    &SecretBytes::new(b"replacement".to_vec()).unwrap(),
                    AccessPolicy::DeviceBound,
                    Interaction::Forbid
                )
                .await
                .unwrap_err(),
            Error::Storage
        );
        assert_eq!(
            device.get(ID, Interaction::Forbid).await.unwrap().expose(),
            fixture().expose()
        );
        let (store, _) = device.into_backends();
        assert_eq!(store.entries[&ID.storage_key()].bytes(), before);
    });
}

#[test]
fn fresh_ciphertext_and_redacted_secrets() {
    block_on(async {
        let mut device = device();
        device
            .put(
                ID,
                &fixture(),
                AccessPolicy::DeviceBound,
                Interaction::Forbid,
            )
            .await
            .unwrap();
        let (store, protector) = device.into_backends();
        let first = store.entries[&ID.storage_key()].bytes().to_vec();
        let mut device = DeviceSecrets::new(NAMESPACE, store, protector).unwrap();
        device
            .put(
                ID,
                &fixture(),
                AccessPolicy::DeviceBound,
                Interaction::Forbid,
            )
            .await
            .unwrap();
        let (store, _) = device.into_backends();
        let second = store.entries[&ID.storage_key()].bytes();
        assert_ne!(first, second);
        assert!(
            !second
                .windows(fixture().expose().len())
                .any(|w| w == fixture().expose())
        );
        assert_eq!(format!("{:?}", fixture()), "SecretBytes([REDACTED])");
        assert_eq!(
            format!("{:?}", Secret32::new([7; 32])),
            "Secret32([REDACTED])"
        );
    });
}

#[test]
fn every_changed_byte_is_rejected() {
    block_on(async {
        let mut device = device();
        device
            .put(
                ID,
                &fixture(),
                AccessPolicy::DeviceBound,
                Interaction::Forbid,
            )
            .await
            .unwrap();
        let (mut store, protector) = device.into_backends();
        let saved = store.entries[&ID.storage_key()].bytes().to_vec();
        let mut protector = protector;
        for index in 0..saved.len() {
            let mut changed = saved.clone();
            changed[index] ^= 1;
            let Ok(entry) = SealedEntry::from_bytes(changed) else {
                continue;
            };
            store.entries.insert(ID.storage_key(), entry);
            let mut device = DeviceSecrets::new(NAMESPACE, store, protector).unwrap();
            assert!(
                device.get(ID, Interaction::Forbid).await.is_err(),
                "byte {index}"
            );
            (store, protector) = device.into_backends();
        }
    });
}

#[test]
fn namespace_and_address_are_bound() {
    block_on(async {
        let mut device = device();
        device
            .put(
                ID,
                &fixture(),
                AccessPolicy::DeviceBound,
                Interaction::Forbid,
            )
            .await
            .unwrap();
        let (mut store, protector) = device.into_backends();
        let another = SecretId {
            vault: [9; 16],
            ..ID
        };
        store.entries.insert(
            another.storage_key(),
            store.entries[&ID.storage_key()].clone(),
        );
        let mut device = DeviceSecrets::new("dev.confidex.test.other", store, protector).unwrap();
        assert!(device.get(ID, Interaction::Forbid).await.is_err());
        assert_eq!(
            device.get(another, Interaction::Forbid).await.unwrap_err(),
            Error::InvalidData
        );
    });
}

#[test]
fn inspect_never_opens_a_hardware_key() {
    block_on(async {
        let mut device = device();
        let id = SecretId {
            purpose: Purpose::QuickUnlock,
            ..ID
        };
        device
            .put(
                id,
                &fixture(),
                AccessPolicy::UserVerified,
                Interaction::Allow,
            )
            .await
            .unwrap();
        assert_eq!(
            device.inspect(id).await.unwrap(),
            EntryState::Stored {
                policy: AccessPolicy::UserVerified
            }
        );
        assert_eq!(
            device.get(id, Interaction::Forbid).await.unwrap_err(),
            Error::InteractionRequired
        );
        let (store, protector) = device.into_backends();
        assert_eq!(protector.opens, 0);
        let mut device = DeviceSecrets::new(NAMESPACE, store, protector).unwrap();
        assert_eq!(
            device.get(id, Interaction::Allow).await.unwrap().expose(),
            fixture().expose()
        );
    });
}

#[test]
fn quick_unlock_requires_verified_policy() {
    block_on(async {
        let mut device = device();
        let id = SecretId {
            purpose: Purpose::QuickUnlock,
            ..ID
        };
        assert_eq!(
            device
                .put(
                    id,
                    &fixture(),
                    AccessPolicy::DeviceBound,
                    Interaction::Allow
                )
                .await
                .unwrap_err(),
            Error::Unsupported
        );
        let (store, protector) = device.into_backends();
        assert!(store.entries.is_empty());
        assert!(protector.keys.is_empty());
    });
}

#[test]
fn no_hardware_means_no_new_copy() {
    block_on(async {
        for capabilities in [
            Capabilities {
                protection: Protection::Authenticator,
                user_verification: true,
            },
            Capabilities {
                protection: Protection::HardwareDevice,
                user_verification: false,
            },
        ] {
            let protector = TestProtector {
                capabilities,
                ..Default::default()
            };
            let mut device =
                DeviceSecrets::new(NAMESPACE, MemoryStore::default(), protector).unwrap();
            assert_eq!(
                device
                    .put(
                        ID,
                        &fixture(),
                        AccessPolicy::UserVerified,
                        Interaction::Allow
                    )
                    .await
                    .unwrap_err(),
                Error::Unsupported
            );
            let (store, protector) = device.into_backends();
            assert!(store.entries.is_empty());
            assert!(protector.keys.is_empty());
        }
    });
}

#[test]
fn locked_store_is_not_missing() {
    block_on(async {
        let mut device = DeviceSecrets::new(
            NAMESPACE,
            MemoryStore {
                locked: true,
                ..Default::default()
            },
            TestProtector::default(),
        )
        .unwrap();
        assert_eq!(device.inspect(ID).await.unwrap_err(), Error::KeychainLocked);
        assert_eq!(
            device.get(ID, Interaction::Forbid).await.unwrap_err(),
            Error::KeychainLocked
        );
    });
}

#[test]
fn limits_and_unknown_versions_are_rejected() {
    assert_eq!(SecretBytes::new(vec![]).unwrap_err(), Error::Limit);
    assert_eq!(
        SecretBytes::new(vec![0; MAX_SECRET_BYTES + 1]).unwrap_err(),
        Error::Limit
    );
    assert!(SecretBytes::new(vec![0; MAX_SECRET_BYTES]).is_ok());
    assert_eq!(
        SealedEntry::from_bytes(vec![0; MAX_ENTRY_BYTES + 1]).unwrap_err(),
        Error::Limit
    );
    for len in 0..100 {
        assert!(SealedEntry::from_bytes(vec![0; len]).is_err());
    }
    for namespace in ["", "x/y", "x\0y", "é", "Confidex", &"a".repeat(129)] {
        assert!(validate_namespace(namespace).is_err());
    }
}
