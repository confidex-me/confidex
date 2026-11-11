use super::{
    header::{read32, take, HEADER_WORK},
    inflate, Error, Header, Limits,
};
use crate::{
    config::{CompressionConfig, InnerCipherConfig},
    crypt::{calculate_sha256, calculate_sha512, ciphers::Cipher, CryptographyError},
    format::{
        hmac_block_stream::{get_hmac_block_key, HMAC_KEY_END},
        DatabaseVersion,
    },
    DatabaseKey,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use hybrid_array::{typenum::U32, Array};
use quick_xml::{events::Event, Reader};
use sha2::Sha256;
use std::{convert::TryFrom, io, mem::size_of, ops::Range};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Cancellation checkpoints in the raw decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Inspect public file metadata.
    Header,
    /// Derive the composite key.
    Kdf,
    /// Verify encrypted block integrity.
    Authenticate,
    /// Decrypt the outer payload.
    Decrypt,
    /// Decompress the payload.
    Inflate,
    /// Inspect the inner header or KDBX3 header binding.
    Inner,
}

struct BinaryRange {
    bytes: Range<usize>,
    protected: bool,
}

/// A borrowed, outer-decrypted KDBX4 binary pool entry.
pub struct Binary<'a> {
    /// Exact attachment bytes.
    pub bytes: &'a [u8],
    /// The source's in-memory protection flag.
    pub protected: bool,
}

/// Verified raw KDBX data. XML protected values still use the inner stream.
/// This type has no Debug implementation and clears its owned buffers on drop.
pub struct Raw {
    data: Zeroizing<Vec<u8>>,
    xml: Range<usize>,
    header: Zeroizing<Vec<u8>>,
    binaries: Vec<BinaryRange>,
    inner: Option<Box<dyn Cipher>>,
    version: DatabaseVersion,
    limits: Limits,
}

/// Owned inner-stream state. Consume every protected node in document order.
/// It can be taken once so the caller can borrow Raw XML while decoding values.
pub struct Protected {
    cipher: Option<Box<dyn Cipher>>,
    consumed: usize,
    total_limit: usize,
    output_limit: usize,
}

impl Raw {
    /// Open locally without constructing the library's lossy XML model.
    /// Memory limits exclude borrowed input/keyfile and caller-owned outputs.
    /// Argon2 cancellation is checked before and after its library call.
    pub fn open(
        input: &[u8],
        password: Option<&str>,
        keyfile: Option<&[u8]>,
        limits: Limits,
        check: &mut dyn FnMut(Phase, u64) -> bool,
    ) -> Result<Self, Error> {
        if password.is_some_and(|value| value.len() > 4096)
            || keyfile.is_some_and(|value| value.len() > 1_048_576)
        {
            return Err(Error::Limit);
        }
        let header = Header::inspect(input, &limits, &mut |n| check(Phase::Header, n as u64))?;
        let available = limits
            .memory_bytes
            .checked_sub(HEADER_WORK)
            .ok_or(Error::Limit)?;
        if input
            .len()
            .checked_mul(2)
            .is_none_or(|size| size > available)
        {
            return Err(Error::Limit);
        }
        let transformed = derive(
            &header,
            password,
            keyfile,
            &Limits {
                memory_bytes: available,
                ..limits
            },
            check,
        )?;
        let master_seed = header.field(4).ok_or(Error::Malformed)?;
        let master = Zeroizing::new(calculate_sha256(&[master_seed, transformed.as_slice()]));
        let compressed = if let Some(mac) = header.header_mac() {
            let hmac_key = Zeroizing::new(calculate_sha512(&[
                master_seed,
                transformed.as_slice(),
                &HMAC_KEY_END,
            ]));
            let key = Zeroizing::new(get_hmac_block_key(u64::MAX, &hmac_key));
            verify_mac(&[header.raw()], &key, mac)?;
            let encrypted =
                authenticated_blocks(header.encrypted(), &hmac_key, limits.blocks, check)?;
            checkpoint(check, Phase::Decrypt, 0)?;
            let decrypted = Zeroizing::new(
                header
                    .cipher()
                    .get_cipher(&master, header.field(7).ok_or(Error::Malformed)?)
                    .map_err(crypto_error)?
                    .decrypt(&encrypted)
                    .map_err(crypto_error)?,
            );
            drop(encrypted);
            decrypted
        } else {
            checkpoint(check, Phase::Decrypt, 0)?;
            let decrypted = Zeroizing::new(
                header
                    .cipher()
                    .get_cipher(&master, header.field(7).ok_or(Error::Malformed)?)
                    .map_err(crypto_error)?
                    .decrypt(header.encrypted())
                    .map_err(crypto_error)?,
            );
            if !bool::from(
                decrypted
                    .get(..32)
                    .ok_or(Error::Credentials)?
                    .ct_eq(header.field(9).ok_or(Error::Malformed)?),
            ) {
                return Err(Error::Credentials);
            }
            let blocks = hashed_blocks(
                decrypted.get(32..).ok_or(Error::Malformed)?,
                limits.blocks,
                check,
            )?;
            drop(decrypted);
            blocks
        };
        drop(master);
        drop(transformed);
        checkpoint(check, Phase::Decrypt, compressed.len() as u64)?;
        let data = if *header.compression() == CompressionConfig::GZip {
            let budget = available
                .checked_sub(compressed.capacity())
                .ok_or(Error::Limit)?;
            let output = inflate(&compressed, limits.unpacked_bytes, budget, &mut |n| {
                check(Phase::Inflate, n as u64)
            })
            .map_err(io_error)?;
            drop(compressed);
            output
        } else {
            if compressed.len() > limits.unpacked_bytes {
                return Err(Error::Limit);
            }
            compressed
        };
        let (inner, binaries, start) = if header.header_mac().is_some() {
            inner_header(&data, limits.blocks, check)?
        } else {
            bind_header(&data, header.raw(), check)?;
            let cipher =
                InnerCipherConfig::try_from(read32(header.field(10).ok_or(Error::Malformed)?)?)
                    .map_err(|_| Error::Unsupported)?;
            (
                cipher
                    .get_cipher(header.field(8).ok_or(Error::Malformed)?)
                    .map_err(crypto_error)?,
                Vec::new(),
                0,
            )
        };
        if start >= data.len() {
            return Err(Error::Malformed);
        }
        let mut saved_header = bytes(header.raw().len())?;
        saved_header.extend_from_slice(header.raw());
        let result = Self {
            xml: start..data.len(),
            data,
            header: saved_header,
            binaries,
            inner: Some(inner),
            version: header.version().clone(),
            limits,
        };
        if result.memory_bytes() > limits.memory_bytes {
            return Err(Error::Limit);
        }
        checkpoint(check, Phase::Inner, result.data.len() as u64)?;
        Ok(result)
    }

    /// Exact XML bytes; decrypt protected nodes in physical document order.
    #[allow(clippy::indexing_slicing)] // The constructor sets the range; the payload is immutable.
    pub fn xml(&self) -> &[u8] {
        &self.data[self.xml.clone()]
    }
    /// Exact authenticated public outer header bytes.
    pub fn header(&self) -> &[u8] {
        &self.header
    }
    /// The accepted KDBX version.
    pub fn version(&self) -> &DatabaseVersion {
        &self.version
    }
    /// Number of KDBX4 binary entries. KDBX3 binaries remain in XML.
    pub fn binary_count(&self) -> usize {
        self.binaries.len()
    }
    /// Get an original pool entry without copying it.
    pub fn binary(&self, index: usize) -> Option<Binary<'_>> {
        let binary = self.binaries.get(index)?;
        Some(Binary {
            bytes: self.data.get(binary.bytes.clone())?,
            protected: binary.protected,
        })
    }
    /// Account for retained capacities, including a conservative cipher allowance.
    pub fn memory_bytes(&self) -> usize {
        self.data.capacity()
            + self.header.capacity()
            + self.binaries.capacity() * size_of::<BinaryRange>()
            + 16_384
    }
    /// Take the stream once; this does not copy or modify the XML or binary pool.
    pub fn take_protected(&mut self) -> Result<Protected, Error> {
        let cipher = self.inner.take().ok_or(Error::Malformed)?;
        Ok(Protected {
            cipher: Some(cipher),
            consumed: 0,
            total_limit: self.limits.unpacked_bytes,
            output_limit: self
                .limits
                .memory_bytes
                .checked_sub(self.memory_bytes())
                .ok_or(Error::Limit)?,
        })
    }
}

impl Protected {
    /// Decode the next base64-decoded protected value, including unknown/history nodes.
    /// On error the stream is discarded. Callers account for retained outputs.
    pub fn decrypt(&mut self, value: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut cipher = self.cipher.take().ok_or(Error::Malformed)?;
        let total = self
            .consumed
            .checked_add(value.len())
            .filter(|&n| n <= self.total_limit)
            .ok_or(Error::Limit)?;
        if value.len() > self.output_limit {
            return Err(Error::Limit);
        }
        let output = Zeroizing::new(cipher.decrypt(value).map_err(crypto_error)?);
        self.cipher = Some(cipher);
        self.consumed = total;
        Ok(output)
    }
}

fn derive(
    header: &Header<'_>,
    password: Option<&str>,
    keyfile: Option<&[u8]>,
    limits: &Limits,
    check: &mut dyn FnMut(Phase, u64) -> bool,
) -> Result<Zeroizing<Array<u8, U32>>, Error> {
    let mut key = DatabaseKey::new();
    if let Some(password) = password {
        key = key.with_password(password);
    }
    if let Some(mut file) = keyfile {
        key = key
            .with_keyfile(&mut file)
            .map_err(|_| Error::Credentials)?;
    }
    let elements = key.get_key_elements().map_err(|_| Error::Credentials)?;
    let borrowed: Vec<&[u8]> = elements.iter().map(|element| element.as_slice()).collect();
    let composite = Zeroizing::new(calculate_sha256(&borrowed));
    let output = header
        .kdf()
        .get_kdf_seeded(header.seed())
        .transform_key_checked(&composite, limits, &mut |n| check(Phase::Kdf, n))
        .map_err(crypto_error)?;
    Ok(Zeroizing::new(output))
}
fn checkpoint(
    check: &mut dyn FnMut(Phase, u64) -> bool,
    phase: Phase,
    count: u64,
) -> Result<(), Error> {
    if check(phase, count) {
        Ok(())
    } else {
        Err(Error::Canceled)
    }
}
fn bytes(capacity: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Allocation)?;
    Ok(output)
}
fn crypto_error(error: CryptographyError) -> Error {
    match error {
        CryptographyError::Boundary(error) => error,
        _ => Error::Credentials,
    }
}
fn io_error(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::Interrupted => Error::Canceled,
        io::ErrorKind::OutOfMemory | io::ErrorKind::FileTooLarge => Error::Limit,
        _ => Error::Malformed,
    }
}
fn verify_mac(parts: &[&[u8]], key: &[u8], tag: &[u8]) -> Result<(), Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Malformed)?;
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(tag).map_err(|_| Error::Credentials)
}

fn authenticated_blocks(
    input: &[u8],
    key: &Array<u8, hybrid_array::typenum::U64>,
    max: usize,
    check: &mut dyn FnMut(Phase, u64) -> bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut output = bytes(input.len())?;
    let mut pos = 0;
    for index in 0..max {
        checkpoint(check, Phase::Authenticate, pos as u64)?;
        let tag = take(input, &mut pos, 32, input.len())?;
        let size = take(input, &mut pos, 4, input.len())?;
        let block = take(input, &mut pos, read32(size)? as usize, input.len())?;
        let key = Zeroizing::new(get_hmac_block_key(index as u64, key));
        verify_mac(&[&(index as u64).to_le_bytes(), size, block], &key, tag)?;
        if block.is_empty() {
            return if pos == input.len() {
                Ok(output)
            } else {
                Err(Error::Malformed)
            };
        }
        output.extend_from_slice(block);
    }
    Err(Error::Limit)
}

fn hashed_blocks(
    input: &[u8],
    max: usize,
    check: &mut dyn FnMut(Phase, u64) -> bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut output = bytes(input.len())?;
    let mut pos = 0;
    for index in 0..max {
        checkpoint(check, Phase::Authenticate, pos as u64)?;
        if read32(take(input, &mut pos, 4, input.len())?)? as usize != index {
            return Err(Error::Malformed);
        }
        let hash = take(input, &mut pos, 32, input.len())?;
        let size = read32(take(input, &mut pos, 4, input.len())?)? as usize;
        let block = take(input, &mut pos, size, input.len())?;
        if size == 0 {
            return if hash == [0; 32] && pos == input.len() {
                Ok(output)
            } else {
                Err(Error::Malformed)
            };
        }
        if hash != calculate_sha256(&[block]).as_slice() {
            return Err(Error::Credentials);
        }
        output.extend_from_slice(block);
    }
    Err(Error::Limit)
}

#[allow(clippy::type_complexity)]
fn inner_header(
    input: &[u8],
    max: usize,
    check: &mut dyn FnMut(Phase, u64) -> bool,
) -> Result<(Box<dyn Cipher>, Vec<BinaryRange>, usize), Error> {
    let (mut stream, mut key) = (None, None);
    let mut binaries = Vec::new();
    binaries
        .try_reserve_exact(max)
        .map_err(|_| Error::Allocation)?;
    let mut pos = 0;
    loop {
        checkpoint(check, Phase::Inner, pos as u64)?;
        let id = *take(input, &mut pos, 1, input.len())?
            .first()
            .ok_or(Error::Malformed)?;
        let size = read32(take(input, &mut pos, 4, input.len())?)? as usize;
        let start = pos;
        let value = take(input, &mut pos, size, input.len())?;
        match id {
            0 => {
                if size != 0 {
                    return Err(Error::Malformed);
                }
                let cipher: InnerCipherConfig = stream.ok_or(Error::Malformed)?;
                return Ok((
                    cipher
                        .get_cipher(key.ok_or(Error::Malformed)?)
                        .map_err(crypto_error)?,
                    binaries,
                    pos,
                ));
            }
            1 if stream.is_none() => {
                stream = Some(
                    InnerCipherConfig::try_from(read32(value)?).map_err(|_| Error::Unsupported)?,
                )
            }
            2 if key.is_none() && !value.is_empty() && value.len() <= 1024 => key = Some(value),
            3 => {
                if binaries.len() == max {
                    return Err(Error::Limit);
                }
                let flag = *value.first().ok_or(Error::Malformed)?;
                if flag > 1 {
                    return Err(Error::Unsupported);
                }
                binaries.push(BinaryRange {
                    bytes: start + 1..pos,
                    protected: flag == 1,
                });
            }
            _ => return Err(Error::Unsupported),
        }
    }
}

fn bind_header(
    input: &[u8],
    header: &[u8],
    check: &mut dyn FnMut(Phase, u64) -> bool,
) -> Result<(), Error> {
    #[derive(Clone, Copy, PartialEq)]
    enum Tag {
        Root,
        Meta,
        Hash,
        Other,
    }
    let xml = std::str::from_utf8(input).map_err(|_| Error::Malformed)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut stack = Vec::with_capacity(64);
    let mut root = false;
    let mut seen = false;
    let mut encoded = Zeroizing::new(String::new());
    let mut events = 0;
    loop {
        events += 1;
        if events > 1_000_000 {
            return Err(Error::Limit);
        }
        if events % 1024 == 1 {
            checkpoint(check, Phase::Inner, reader.buffer_position())?;
        }
        match reader.read_event().map_err(|_| Error::Malformed)? {
            Event::Start(event) => {
                let tag = match (stack.as_slice(), event.name().as_ref()) {
                    ([], "KeePassFile") if !root => {
                        root = true;
                        Tag::Root
                    }
                    ([], _) => return Err(Error::Malformed),
                    ([Tag::Root], "Meta") => Tag::Meta,
                    ([Tag::Root, Tag::Meta], "HeaderHash") if !seen => {
                        seen = true;
                        Tag::Hash
                    }
                    ([Tag::Root, Tag::Meta], "HeaderHash") => return Err(Error::Malformed),
                    _ => Tag::Other,
                };
                if stack.len() == 64 {
                    return Err(Error::Limit);
                }
                stack.push(tag);
            }
            Event::End(_) => {
                stack.pop().ok_or(Error::Malformed)?;
            }
            Event::Text(value) if stack.last() == Some(&Tag::Hash) => {
                if encoded.len() + value.len() > 128 {
                    return Err(Error::Limit);
                }
                encoded.push_str(value.as_ref());
            }
            Event::GeneralRef(_) | Event::CData(_) if stack.last() == Some(&Tag::Hash) => {
                return Err(Error::Malformed)
            }
            Event::DocType(_) => return Err(Error::Unsupported),
            Event::Eof => break,
            _ => (),
        }
    }
    if !root || !seen || !stack.is_empty() {
        return Err(Error::Malformed);
    }
    let mut decoded = Zeroizing::new([0; 64]);
    let length = STANDARD
        .decode_slice(encoded.trim().as_bytes(), &mut decoded[..])
        .map_err(|_| Error::Malformed)?;
    if length != 32 || decoded.get(..32) != Some(calculate_sha256(&[header]).as_slice()) {
        return Err(Error::Credentials);
    }
    Ok(())
}

#[cfg(test)]
#[path = "raw_tests.rs"]
mod tests;
