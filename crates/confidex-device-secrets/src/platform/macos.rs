use crate::*;
use core_foundation::{
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryRef},
    string::{CFString, CFStringRef},
};
use security_framework_sys::{
    item::*,
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate},
};
use std::ptr;
// The binding crate does not expose these Security constants.
unsafe extern "C" {
    static kSecAttrGeneric: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
    static kSecUseAuthenticationUIAllow: CFStringRef;
}
fn cf(key: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(key) }
}
fn dict(values: &[(CFString, CFType)]) -> CFDictionary<CFString, CFType> {
    CFDictionary::from_CFType_pairs(values)
}
fn status(code: i32) -> Error {
    match code {
        -25300 => Error::NotFound,
        -25293 => Error::AccessDenied,
        -128 => Error::Canceled,
        -25308 => Error::InteractionRequired,
        -25291 => Error::KeychainLocked,
        -34018 => Error::AccessDenied,
        -4 => Error::HardwareUnavailable,
        -50 => Error::InvalidData,
        _ => Error::Storage,
    }
}
fn ui(interaction: Interaction) -> (CFString, CFType) {
    unsafe {
        (
            cf(kSecUseAuthenticationUI),
            cf(if interaction == Interaction::Forbid {
                kSecUseAuthenticationUIFail
            } else {
                kSecUseAuthenticationUIAllow
            })
            .as_CFType(),
        )
    }
}
fn query(namespace: &str, id: SecretId, interaction: Interaction) -> Vec<(CFString, CFType)> {
    unsafe {
        vec![
            (cf(kSecClass), cf(kSecClassGenericPassword).as_CFType()),
            (cf(kSecAttrService), CFString::new(namespace).as_CFType()),
            (
                cf(kSecAttrAccount),
                CFString::new(&id.storage_key()).as_CFType(),
            ),
            ui(interaction),
        ]
    }
}
fn found(q: &[(CFString, CFType)]) -> Result<Option<CFType>> {
    let mut value: CFTypeRef = ptr::null();
    let code = unsafe {
        SecItemCopyMatching(dict(q).as_concrete_TypeRef() as CFDictionaryRef, &mut value)
    };
    match code {
        0 => {
            if value.is_null() {
                return Err(Error::InvalidData);
            };
            Ok(Some(unsafe { CFType::wrap_under_create_rule(value) }))
        }
        -25300 => Ok(None),
        _ => Err(status(code)),
    }
}
pub struct Store {
    namespace: String,
    verified_at: Option<u64>,
    previous: Option<u64>,
}
impl Store {
    pub fn new(namespace: &str) -> Result<Self> {
        validate_namespace(namespace)?;
        Ok(Self {
            namespace: namespace.into(),
            verified_at: None,
            previous: None,
        })
    }

    pub fn with_verification(mut self, verified_at: u64, previous: Option<u64>) -> Self {
        self.verified_at = Some(verified_at);
        self.previous = previous;
        self
    }

    pub fn verified_at(&self, id: SecretId) -> Result<Option<u64>> {
        let mut q = query(&self.namespace, id, Interaction::Forbid);
        unsafe {
            q.push((
                cf(kSecReturnAttributes),
                CFBoolean::true_value().as_CFType(),
            ));
        }
        let Some(value) = found(&q)? else {
            return Ok(None);
        };
        let untyped = value.downcast::<CFDictionary>().ok_or(Error::InvalidData)?;
        let attributes = unsafe {
            CFDictionary::<CFString, CFType>::wrap_under_get_rule(untyped.as_concrete_TypeRef())
        };
        let key = unsafe { cf(kSecAttrGeneric) };
        let Some(value) = attributes.find(&key) else {
            return Ok(None);
        };
        let bytes = value.downcast::<CFData>().ok_or(Error::InvalidData)?;
        Ok(Some(u64::from_le_bytes(
            bytes.bytes().try_into().map_err(|_| Error::InvalidData)?,
        )))
    }
}

fn verification_attribute(value: u64) -> (CFString, CFType) {
    (
        unsafe { cf(kSecAttrGeneric) },
        CFData::from_buffer(&value.to_le_bytes()).as_CFType(),
    )
}
impl ProtectedStore for Store {
    async fn read(
        &mut self,
        id: SecretId,
        interaction: Interaction,
    ) -> Result<Option<SealedEntry>> {
        let mut q = query(&self.namespace, id, interaction);
        unsafe {
            q.push((cf(kSecReturnData), CFBoolean::true_value().as_CFType()));
        }
        let Some(value) = found(&q)? else {
            return Ok(None);
        };
        let bytes = value.downcast::<CFData>().ok_or(Error::InvalidData)?;
        if bytes.len() > MAX_ENTRY_BYTES as isize {
            return Err(Error::Limit);
        }
        Ok(Some(SealedEntry::from_bytes(bytes.to_vec())?))
    }
    async fn write(
        &mut self,
        id: SecretId,
        entry: &SealedEntry,
        interaction: Interaction,
    ) -> Result<()> {
        let mut q = query(&self.namespace, id, interaction);
        let mut values = vec![(
            unsafe { cf(kSecValueData) },
            CFData::from_buffer(entry.bytes()).as_CFType(),
        )];
        if id.purpose == Purpose::QuickUnlock {
            if let Some(previous) = self.previous {
                q.push(verification_attribute(previous));
            }
            if let Some(verified_at) = self.verified_at {
                values.push(verification_attribute(verified_at));
            }
        }
        let attrs = dict(&values);
        let code = unsafe {
            SecItemUpdate(
                dict(&q).as_concrete_TypeRef() as _,
                attrs.as_concrete_TypeRef() as _,
            )
        };
        let code = if code == -25300 && self.previous.is_none() {
            q.extend(values);
            let code = unsafe { SecItemAdd(dict(&q).as_concrete_TypeRef() as _, ptr::null_mut()) };
            if code == -25299 {
                unsafe {
                    SecItemUpdate(
                        dict(&query(&self.namespace, id, interaction)).as_concrete_TypeRef() as _,
                        attrs.as_concrete_TypeRef() as _,
                    )
                }
            } else {
                code
            }
        } else {
            code
        };
        if code == 0 { Ok(()) } else { Err(status(code)) }
    }
    async fn remove(&mut self, id: SecretId, interaction: Interaction) -> Result<()> {
        let code = unsafe {
            SecItemDelete(dict(&query(&self.namespace, id, interaction)).as_concrete_TypeRef() as _)
        };
        if code == 0 || code == -25300 {
            Ok(())
        } else {
            Err(status(code))
        }
    }
}
unsafe extern "C" {
    fn confidex_enclave_capabilities() -> i32;
    fn confidex_enclave_seal(
        binding: *const u8,
        key: *const u8,
        verified: u8,
        interaction: u8,
        out: *mut u8,
        capacity: usize,
        size: *mut usize,
    ) -> i32;
    fn confidex_enclave_unseal(
        binding: *const u8,
        bytes: *const u8,
        count: usize,
        interaction: u8,
        out: *mut u8,
        capacity: usize,
        size: *mut usize,
    ) -> i32;
}
pub struct Protector;
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
        match unsafe { confidex_enclave_capabilities() } {
            code @ (1 | 2) => Ok(Capabilities {
                protection: Protection::HardwareDevice,
                user_verification: code == 2,
            }),
            code => Err(status(code)),
        }
    }
    async fn seal_key(
        &mut self,
        binding: &Binding,
        key: &Secret32,
        policy: AccessPolicy,
        interaction: Interaction,
    ) -> Result<SealedKey> {
        let mut output = vec![0; 8192];
        let mut size = 0;
        let code = unsafe {
            confidex_enclave_seal(
                binding.bytes().as_ptr(),
                key.expose().as_ptr(),
                (policy == AccessPolicy::UserVerified) as u8,
                (interaction == Interaction::Allow) as u8,
                output.as_mut_ptr(),
                output.len(),
                &mut size,
            )
        };
        if code != 0 {
            return Err(status(code));
        }
        if size > output.len() {
            return Err(Error::InvalidData);
        }
        output.truncate(size);
        SealedKey::from_bytes(output)
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
        let mut output = Secret32::new([0; 32]);
        let mut size = 0;
        let code = unsafe {
            confidex_enclave_unseal(
                binding.bytes().as_ptr(),
                key.bytes().as_ptr(),
                key.bytes().len(),
                (interaction == Interaction::Allow) as u8,
                output.0.as_mut_ptr(),
                32,
                &mut size,
            )
        };
        if code != 0 {
            return Err(status(code));
        }
        if size != 32 {
            return Err(Error::InvalidData);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_executor::block_on;

    #[test]
    #[ignore = "requires an available login Keychain"]
    fn device_unlock_keychain_updates_entry_and_verification_together() {
        const NAMESPACE: &str = "dev.confidex.test.touch-id";
        let mut vault = [0; 16];
        getrandom::fill(&mut vault).unwrap();
        let id = SecretId {
            vault,
            purpose: Purpose::QuickUnlock,
        };
        struct Cleanup(SecretId);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let mut store = Store::new(NAMESPACE).unwrap();
                block_on(store.remove(self.0, Interaction::Forbid)).unwrap();
            }
        }
        let _cleanup = Cleanup(id);
        let fixture = |value| {
            let policy = AccessPolicy::UserVerified;
            let binding = Binding::new(NAMESPACE, id, policy).unwrap();
            let mut header = MAGIC.to_vec();
            header.extend(id.encode());
            header.push(policy as u8);
            header.extend(1u32.to_le_bytes());
            header.push(42);
            seal_entry(
                header,
                &binding,
                &Secret32::new([0; 32]),
                &SecretBytes::new(vec![value]).unwrap(),
            )
            .unwrap()
        };
        let first = fixture(1);
        let second = fixture(2);
        let mut store = Store::new(NAMESPACE).unwrap().with_verification(10, None);
        block_on(store.write(id, &first, Interaction::Forbid)).unwrap();
        assert_eq!(store.verified_at(id).unwrap(), Some(10));

        let mut store = store.with_verification(20, Some(10));
        block_on(store.write(id, &second, Interaction::Forbid)).unwrap();
        let mut stale = Store::new(NAMESPACE)
            .unwrap()
            .with_verification(30, Some(10));
        assert!(block_on(stale.write(id, &first, Interaction::Forbid)).is_err());
        assert_eq!(store.verified_at(id).unwrap(), Some(20));
        let current = block_on(store.read(id, Interaction::Forbid))
            .unwrap()
            .unwrap();
        assert_eq!(current.bytes(), second.bytes());
    }
}
