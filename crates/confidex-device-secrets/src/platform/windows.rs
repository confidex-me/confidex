use crate::*;
use std::{ffi::c_void, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Credentials::*, Cryptography::*},
};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn status(code: i32) -> Error {
    match code {
        NTE_BAD_KEYSET => Error::KeyInvalidated,
        NTE_SILENT_CONTEXT => Error::InteractionRequired,
        NTE_USER_CANCELLED => Error::Canceled,
        NTE_PERM => Error::AccessDenied,
        NTE_NOT_SUPPORTED => Error::Unsupported,
        NTE_DEVICE_NOT_READY => Error::HardwareUnavailable,
        NTE_BAD_DATA => Error::InvalidData,
        _ => Error::Storage,
    }
}
fn check(code: i32) -> Result<()> {
    if code == 0 { Ok(()) } else { Err(status(code)) }
}
fn storage_error() -> Error {
    match unsafe { GetLastError() } {
        ERROR_NOT_FOUND => Error::NotFound,
        ERROR_NO_SUCH_LOGON_SESSION => Error::KeychainLocked,
        ERROR_ACCESS_DENIED => Error::AccessDenied,
        _ => Error::Storage,
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
    fn target(&self, id: SecretId) -> Vec<u16> {
        wide(&format!("{}/{}", self.namespace, id.storage_key()))
    }
}
struct Credential(*mut CREDENTIALW);
impl Drop for Credential {
    fn drop(&mut self) {
        unsafe { CredFree(self.0.cast()) }
    }
}
impl ProtectedStore for Store {
    async fn read(&mut self, id: SecretId, _: Interaction) -> Result<Option<SealedEntry>> {
        let mut raw = ptr::null_mut();
        if unsafe { CredReadW(self.target(id).as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
            return match storage_error() {
                Error::NotFound => Ok(None),
                e => Err(e),
            };
        }
        if raw.is_null() {
            return Err(Error::InvalidData);
        }
        let guard = Credential(raw);
        let item = unsafe { &*guard.0 };
        let size = item.CredentialBlobSize as usize;
        if size == 0 || size > MAX_ENTRY_BYTES || item.CredentialBlob.is_null() {
            return Err(Error::InvalidData);
        }
        let bytes = unsafe { std::slice::from_raw_parts(item.CredentialBlob, size) };
        Ok(Some(SealedEntry::from_bytes(bytes.to_vec())?))
    }
    async fn write(&mut self, id: SecretId, entry: &SealedEntry, _: Interaction) -> Result<()> {
        if entry.bytes().len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            return Err(Error::Limit);
        }
        let mut target = self.target(id);
        let item = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: entry.bytes().len() as u32,
            CredentialBlob: entry.bytes().as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        if unsafe { CredWriteW(&item, 0) } == 0 {
            Err(storage_error())
        } else {
            Ok(())
        }
    }
    async fn remove(&mut self, id: SecretId, _: Interaction) -> Result<()> {
        if unsafe { CredDeleteW(self.target(id).as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(());
        }
        match storage_error() {
            Error::NotFound => Ok(()),
            e => Err(e),
        }
    }
}

struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}
fn property(handle: usize, name: *const u16) -> Result<u32> {
    let mut value = 0u32;
    let mut size = 0;
    check(unsafe {
        NCryptGetProperty(
            handle,
            name,
            (&mut value as *mut u32).cast(),
            4,
            &mut size,
            0,
        )
    })?;
    if size != 4 {
        return Err(Error::InvalidData);
    }
    Ok(value)
}
fn set(handle: usize, name: *const u16, value: u32) -> Result<()> {
    check(unsafe { NCryptSetProperty(handle, name, value.to_le_bytes().as_ptr(), 4, 0) })
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
    fn provider(&self) -> Result<Handle> {
        let mut raw = 0;
        check(unsafe { NCryptOpenStorageProvider(&mut raw, MS_PLATFORM_CRYPTO_PROVIDER, 0) })?;
        let handle = Handle(raw);
        if property(raw, NCRYPT_IMPL_TYPE_PROPERTY)? & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
            return Err(Error::HardwareUnavailable);
        }
        Ok(handle)
    }
    fn name(&self) -> Vec<u16> {
        wide(&format!("{}.hardware.0", self.namespace))
    }
    fn key(&self, create: bool) -> Result<Handle> {
        let _guard = super::key_lock(&self.namespace)?;
        let provider = self.provider()?;
        let mut raw = 0;
        let code = unsafe {
            NCryptOpenKey(
                provider.0,
                &mut raw,
                self.name().as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        };
        if code == 0 {
            let handle = Handle(raw);
            if property(raw, NCRYPT_EXPORT_POLICY_PROPERTY)? != 0
                || property(raw, NCRYPT_LENGTH_PROPERTY)? != 2048
            {
                return Err(Error::InvalidData);
            }
            return Ok(handle);
        }
        if code != NTE_BAD_KEYSET || !create {
            return Err(status(code));
        }
        check(unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut raw,
                NCRYPT_RSA_ALGORITHM,
                self.name().as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        let handle = Handle(raw);
        set(raw, NCRYPT_LENGTH_PROPERTY, 2048)?;
        set(raw, NCRYPT_EXPORT_POLICY_PROPERTY, 0)?;
        set(raw, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_DECRYPT_FLAG)?;
        check(unsafe { NCryptFinalizeKey(raw, NCRYPT_SILENT_FLAG) })?;
        if property(raw, NCRYPT_EXPORT_POLICY_PROPERTY)? != 0 {
            return Err(Error::InvalidData);
        }
        Ok(handle)
    }
    #[cfg(feature = "backend-check")]
    pub fn cleanup(&mut self) -> Result<()> {
        if !self.namespace.starts_with("dev.confidex.test.") {
            return Err(Error::AccessDenied);
        }
        match self.key(false) {
            Ok(mut key) => {
                check(unsafe { NCryptDeleteKey(key.0, 0) })?;
                key.0 = 0;
                Ok(())
            }
            Err(Error::KeyInvalidated) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
fn crypt(key: &Handle, input: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    let padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: ptr::null_mut(),
        cbLabel: 0,
    };
    let operation = if decrypt {
        NCryptDecrypt
    } else {
        NCryptEncrypt
    };
    let mut size = 0;
    let flags = NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG;
    let mut output = Zeroizing::new(vec![0; 256]);
    check(unsafe {
        operation(
            key.0,
            input.as_ptr(),
            input.len() as u32,
            (&padding as *const BCRYPT_OAEP_PADDING_INFO).cast::<c_void>(),
            output.as_mut_ptr(),
            output.len() as u32,
            &mut size,
            flags,
        )
    })?;
    if size == 0 || size as usize > output.len() {
        return Err(Error::InvalidData);
    }
    output.truncate(size as usize);
    Ok(output)
}
impl KeyProtector for Protector {
    async fn capabilities(&mut self) -> Result<Capabilities> {
        self.provider()?;
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
        let mut plain = Zeroizing::new(Vec::from(binding.bytes().as_slice()));
        plain.extend(key.expose());
        let output = crypt(&self.key(true)?, &plain, false)?;
        SealedKey::from_bytes(output.to_vec())
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
        if key.bytes().len() != 256 {
            return Err(Error::InvalidData);
        }
        let output = crypt(&self.key(false)?, key.bytes(), true)?;
        if output.len() != 64 || &output[..32] != binding.bytes() {
            return Err(Error::InvalidData);
        }
        Ok(Secret32::new(
            output[32..].try_into().map_err(|_| Error::InvalidData)?,
        ))
    }
}
