//! Bounded serialization uses the library's existing KDBX4 key and cipher path.
use super::{Binary, Error, Limits};
use crate::{
    config::{
        CompressionConfig, DatabaseConfig, DatabaseVersion, InnerCipherConfig, KdfConfig,
        OuterCipherConfig,
    },
    crypt::ciphers::Cipher,
    db::DatabaseSaveError,
    format::kdbx4::Prepared,
    DatabaseKey,
};
use std::convert::TryFrom;
use std::{
    cell::{Cell, RefCell},
    io::{self, Write},
    ops::Deref,
};
use zeroize::Zeroizing;

const HEADER_WORK: usize = 8 << 20;
const SCRATCH: usize = 1 << 20;
const CHUNK: usize = 65_536;

/// Counts contain no values, names or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveEvent {
    /// Total resident library work, reported before allocation and after release.
    Memory(usize),
    /// KDF work checkpoint. Argon2 checks only before and after its library call.
    Kdf(u64),
    /// Uncompressed inner payload bytes.
    Serialize(usize),
    /// Final output bytes written so far.
    Write(usize),
}
/// Save failures do not include input values.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    /// Resource, credential, format or cancellation failure.
    #[error(transparent)]
    Boundary(#[from] Error),
    /// No weak randomness is used when the platform source fails.
    #[error("KDBX secure randomness failed")]
    Random,
}
fn io_error(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted => Error::Canceled,
        io::ErrorKind::FileTooLarge => Error::Limit,
        io::ErrorKind::OutOfMemory => Error::Allocation,
        _ => Error::Malformed,
    }
}
fn io_fail(error: Error) -> io::Error {
    match error {
        Error::Canceled => io::ErrorKind::ConnectionAborted,
        Error::Limit => io::ErrorKind::FileTooLarge,
        Error::Allocation => io::ErrorKind::OutOfMemory,
        _ => io::ErrorKind::InvalidData,
    }
    .into()
}
fn save_error(error: DatabaseSaveError) -> SaveError {
    let error = match error {
        DatabaseSaveError::Random(_) => return SaveError::Random,
        DatabaseSaveError::UnsupportedVersion => Error::Unsupported,
        DatabaseSaveError::Cryptography(crate::crypt::CryptographyError::Boundary(error)) => error,
        DatabaseSaveError::Io(error) => io_error(error),
        DatabaseSaveError::Key(_) => Error::Credentials,
        _ => Error::Malformed,
    };
    error.into()
}
struct Budget<'a> {
    limits: Limits,
    used: Cell<usize>,
    check: RefCell<&'a mut dyn FnMut(SaveEvent) -> bool>,
}
impl<'a> Budget<'a> {
    fn event(&self, event: SaveEvent) -> Result<(), Error> {
        if (self.check.borrow_mut())(event) {
            Ok(())
        } else {
            Err(Error::Canceled)
        }
    }
    fn claim(&self, bytes: usize) -> Result<Charge<'_, 'a>, Error> {
        let used = self
            .used
            .get()
            .checked_add(bytes)
            .filter(|n| *n <= self.limits.memory_bytes)
            .ok_or(Error::Limit)?;
        if let Err(error) = self.event(SaveEvent::Memory(used)) {
            let _ = self.event(SaveEvent::Memory(self.used.get()));
            return Err(error);
        }
        self.used.set(used);
        Ok(Charge {
            budget: self,
            bytes,
        })
    }
}
struct Charge<'b, 'a> {
    budget: &'b Budget<'a>,
    bytes: usize,
}
impl Drop for Charge<'_, '_> {
    fn drop(&mut self) {
        let used = self.budget.used.get() - self.bytes;
        self.budget.used.set(used);
        let _ = self.budget.event(SaveEvent::Memory(used));
    }
}
/// Ciphertext for one protected XML value. Its charge follows its lifetime.
pub struct Encrypted<'b, 'a> {
    bytes: Zeroizing<Vec<u8>>,
    _charge: Charge<'b, 'a>,
}
impl Deref for Encrypted<'_, '_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
/// One inner stream, consumed in the serializer's physical XML order.
pub struct Encoder<'b, 'a> {
    cipher: &'b mut dyn Cipher,
    budget: &'b Budget<'a>,
}
impl<'b, 'a> Encoder<'b, 'a> {
    /// Encrypt current bytes with the existing checked stream cipher.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Encrypted<'b, 'a>, Error> {
        let budget = self.budget;
        let charge = budget.claim(plaintext.len())?;
        let bytes = Zeroizing::new(self.cipher.encrypt(plaintext).map_err(
            |error| match error {
                crate::crypt::CryptographyError::Boundary(error) => error,
                _ => Error::Malformed,
            },
        )?);
        Ok(Encrypted {
            bytes,
            _charge: charge,
        })
    }
}
struct Buffer<'b, 'a> {
    bytes: Zeroizing<Vec<u8>>,
    charge: Charge<'b, 'a>,
    budget: &'b Budget<'a>,
}
impl<'b, 'a> Buffer<'b, 'a> {
    fn new(budget: &'b Budget<'a>) -> Result<Self, Error> {
        Ok(Self {
            bytes: Zeroizing::new(Vec::new()),
            charge: budget.claim(0)?,
            budget,
        })
    }
    fn grow(&mut self, end: usize) -> Result<(), Error> {
        if end <= self.bytes.capacity() {
            return Ok(());
        }
        let capacity = end
            .next_power_of_two()
            .max(CHUNK)
            .min(self.budget.limits.input_bytes);
        let charge = self.budget.claim(capacity)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(&self.bytes);
        let old = std::mem::replace(&mut self.bytes, bytes);
        let old_charge = std::mem::replace(&mut self.charge, charge);
        drop(old);
        drop(old_charge);
        Ok(())
    }
}
impl Write for Buffer<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.budget.limits.input_bytes)
            .ok_or_else(|| io_fail(Error::Limit))?;
        self.grow(end).map_err(io_fail)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Checked<'w, 'b, 'a> {
    output: &'w mut dyn Write,
    budget: &'b Budget<'a>,
    bytes: usize,
    inner: bool,
}
impl Write for Checked<'_, '_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(CHUNK);
        let limit = if self.inner {
            self.budget.limits.unpacked_bytes
        } else {
            self.budget.limits.input_bytes
        };
        let end = self
            .bytes
            .checked_add(count)
            .filter(|n| *n <= limit)
            .ok_or_else(|| io_fail(Error::Limit))?;
        self.budget
            .event(if self.inner {
                SaveEvent::Serialize(self.bytes)
            } else {
                SaveEvent::Write(self.bytes)
            })
            .map_err(io_fail)?;
        let written = self.output.write(
            bytes
                .get(..count)
                .ok_or_else(|| io_fail(Error::Malformed))?,
        )?;
        if written > count {
            return Err(io_fail(Error::Malformed));
        }
        self.bytes = end - (count - written);
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

/// Seal caller-serialized XML without constructing the library's database model.
///
/// Supports KDBX4.1, AES256, ChaCha20 inner protection and no compression. The caller
/// owns XML semantics and must emit Base64 from Encoder for each Protected=True
/// value in physical order. Binary refs address the supplied iterator's order.
/// Limits include library buffers and KDF work, excluding borrowed inputs and
/// the caller's destination. Memory events allow one shared caller budget.
/// A failing destination can contain partial bytes; publish only after success.
pub fn save<'data>(
    config: &DatabaseConfig,
    credentials: (Option<&str>, Option<&[u8]>),
    limits: Limits,
    output: &mut dyn Write,
    binaries: impl IntoIterator<Item = Binary<'data>>,
    serialize: impl FnOnce(&mut Encoder<'_, '_>, &mut dyn Write) -> io::Result<()>,
    check: &mut dyn FnMut(SaveEvent) -> bool,
) -> Result<(), SaveError> {
    let (password, keyfile) = credentials;
    limits.validate()?;
    if config.version != DatabaseVersion::KDB4(1)
        || config.outer_cipher_config != OuterCipherConfig::AES256
        || config.inner_cipher_config != InnerCipherConfig::ChaCha20
        || config.compression_config != CompressionConfig::None
        || config.public_custom_data.is_some()
    {
        return Err(Error::Unsupported.into());
    }
    if password.is_none() && keyfile.is_none()
        || password.is_some_and(|p| p.len() > 4096)
        || keyfile.is_some_and(|k| k.len() > 1 << 20)
    {
        return Err(Error::Credentials.into());
    }
    limits.admit_kdf(&config.kdf_config, &[0; 32])?;
    let budget = Budget {
        limits,
        used: Cell::new(0),
        check: RefCell::new(check),
    };
    let _headers = budget.claim(HEADER_WORK)?;
    let mut key = DatabaseKey::new();
    if let Some(password) = password {
        key = key.with_password(password);
    }
    if let Some(mut bytes) = keyfile {
        key = key
            .with_keyfile(&mut bytes)
            .map_err(|_| Error::Credentials)?;
    }
    let kdf_memory = match config.kdf_config {
        KdfConfig::Aes { .. } => 8192,
        KdfConfig::Argon2 { memory, .. } | KdfConfig::Argon2id { memory, .. } => {
            usize::try_from(memory)
                .map_err(|_| Error::Limit)?
                .checked_add(SCRATCH)
                .ok_or(Error::Limit)?
        }
    };
    let arena = budget.claim(kdf_memory)?;
    let mut prepared = Prepared::new(config, &key, &limits, &mut |work| {
        budget.event(SaveEvent::Kdf(work)).is_ok()
    })
    .map_err(save_error)?;
    drop(arena);
    let mut buffer = Buffer::new(&budget)?;
    let produce = |output: &mut dyn Write| -> Result<(), SaveError> {
        let mut output = Checked {
            output,
            budget: &budget,
            bytes: 0,
            inner: true,
        };
        let failed = Cell::new(false);
        let binaries = Binaries {
            source: binaries.into_iter(),
            maximum: limits.blocks,
            seen: 0,
            failed: &failed,
        };
        prepared
            .inner_header
            .dump_binaries(binaries, &mut output)
            .map_err(save_error)?;
        if failed.get() {
            return Err(Error::Limit.into());
        }
        let mut encoder = Encoder {
            cipher: &mut *prepared.inner_cipher,
            budget: &budget,
        };
        serialize(&mut encoder, &mut output).map_err(io_error)?;
        budget.event(SaveEvent::Serialize(output.bytes))?;
        Ok(())
    };
    // Compressor history does not provide a zeroization contract.
    produce(&mut buffer)?;
    let length = prepared.encrypted_length(buffer.bytes.len())?;
    if prepared
        .output_length(length)
        .is_none_or(|n| n > limits.input_bytes)
    {
        return Err(Error::Limit.into());
    }
    let _cipher = budget.claim(length)?;
    let encrypted = prepared.encrypt(&buffer.bytes).map_err(save_error)?;
    drop(buffer);
    let mut output = Checked {
        output,
        budget: &budget,
        bytes: 0,
        inner: false,
    };
    prepared
        .finish(&encrypted, &mut output)
        .map_err(save_error)?;
    budget.event(SaveEvent::Write(output.bytes))?;
    Ok(())
}

struct Binaries<'b, I> {
    source: I,
    maximum: usize,
    seen: usize,
    failed: &'b Cell<bool>,
}
impl<'a, I: Iterator<Item = Binary<'a>>> Iterator for Binaries<'_, I> {
    type Item = Binary<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.source.next()?;
        if self.seen == self.maximum {
            self.failed.set(true);
            return None;
        }
        self.seen += 1;
        Some(item)
    }
}

#[cfg(test)]
#[path = "save_tests.rs"]
mod tests;
