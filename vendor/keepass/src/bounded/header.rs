use super::{Error, Limits};
use crate::{
    config::{CompressionConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    crypt::calculate_sha256,
    format::{
        variant_dictionary::{VariantDictionary, VariantDictionaryError},
        DatabaseVersion,
    },
};
use std::convert::{TryFrom, TryInto};
use zeroize::Zeroizing;

pub(crate) const HEADER_WORK: usize = 8 << 20;

/// Inspected public header. This has not authenticated credentials or payload.
pub struct Header<'a> {
    raw: &'a [u8],
    encrypted: &'a [u8],
    mac: Option<&'a [u8]>,
    fields: [Option<&'a [u8]>; 13],
    version: DatabaseVersion,
    cipher: OuterCipherConfig,
    compression: CompressionConfig,
    kdf: KdfConfig,
    seed: Zeroizing<Vec<u8>>,
}

impl<'a> Header<'a> {
    /// Check the full header, KDF cost and encrypted framing before key work.
    pub fn inspect(
        input: &'a [u8],
        limits: &Limits,
        check: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if input.len() > limits.input_bytes || limits.memory_bytes < HEADER_WORK {
            return Err(Error::Limit);
        }
        if !check(0) {
            return Err(Error::Canceled);
        }
        if input.len() < 12 {
            return Err(Error::Malformed);
        }
        let version = DatabaseVersion::parse(input).map_err(|_| Error::Unsupported)?;
        let v4 = match version {
            DatabaseVersion::KDB3(1) => false,
            DatabaseVersion::KDB4(0 | 1) => true,
            _ => return Err(Error::Unsupported),
        };
        let mut fields = [None; 13];
        let mut pos = 12;
        loop {
            if !check(pos) {
                return Err(Error::Canceled);
            }
            let id = *take(input, &mut pos, 1, limits.header_bytes)?
                .first()
                .ok_or(Error::Malformed)?;
            let size = if v4 {
                read32(take(input, &mut pos, 4, limits.header_bytes)?)? as usize
            } else {
                u16::from_le_bytes(
                    take(input, &mut pos, 2, limits.header_bytes)?
                        .try_into()
                        .map_err(|_| Error::Malformed)?,
                ) as usize
            };
            let value = take(input, &mut pos, size, limits.header_bytes)?;
            if id == 0 {
                if value != b"\r\n\r\n" {
                    return Err(Error::Malformed);
                }
                break;
            }
            if id > 12 || (v4 && matches!(id, 5 | 6 | 8 | 9 | 10)) || (!v4 && id > 10) {
                return Err(Error::Unsupported);
            }
            let field = fields.get_mut(usize::from(id)).ok_or(Error::Malformed)?;
            if field.replace(value).is_some() {
                return Err(Error::Malformed);
            }
        }
        let field = |id: usize| fields.get(id).copied().flatten().ok_or(Error::Malformed);
        let cipher = OuterCipherConfig::try_from(field(2)?).map_err(|_| Error::Unsupported)?;
        let compression =
            CompressionConfig::try_from(read32(field(3)?)?).map_err(|_| Error::Unsupported)?;
        exact(field(4)?, 32)?;
        exact(
            field(7)?,
            if cipher == OuterCipherConfig::ChaCha20 {
                12
            } else {
                16
            },
        )?;
        let (kdf, seed) = if v4 {
            let dictionary = VariantDictionary::parse(field(11)?).map_err(dictionary_error)?;
            let (config, seed): (KdfConfig, Vec<u8>) = dictionary
                .clone()
                .try_into()
                .map_err(|_| Error::Unsupported)?;
            let allowed: &[&str] = match config {
                KdfConfig::Aes { .. } => &["$UUID", "S", "R"],
                _ => &["$UUID", "S", "M", "I", "P", "V"],
            };
            if dictionary
                .keys()
                .any(|key| !allowed.contains(&key.as_str()))
            {
                return Err(Error::Unsupported);
            }
            if let Some(data) = fields.get(12).copied().flatten() {
                VariantDictionary::parse(data).map_err(dictionary_error)?;
            }
            (config, seed)
        } else {
            exact(field(5)?, 32)?;
            exact(field(8)?, 32)?;
            exact(field(9)?, 32)?;
            InnerCipherConfig::try_from(read32(field(10)?)?).map_err(|_| Error::Unsupported)?;
            (
                KdfConfig::Aes {
                    rounds: read64(field(6)?)?,
                },
                field(5)?.to_vec(),
            )
        };
        limits.admit_kdf(&kdf, &seed)?;
        let raw = input.get(..pos).ok_or(Error::Malformed)?;
        let mac = if v4 {
            if take(input, &mut pos, 32, input.len())? != calculate_sha256(&[raw]).as_slice() {
                return Err(Error::Malformed);
            }
            Some(take(input, &mut pos, 32, input.len())?)
        } else {
            None
        };
        let encrypted = input.get(pos..).ok_or(Error::Malformed)?;
        let encrypted_size = if v4 {
            frames(encrypted, limits.blocks, check)?
        } else {
            encrypted.len()
        };
        if encrypted_size == 0
            || (cipher != OuterCipherConfig::ChaCha20 && encrypted_size % 16 != 0)
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            raw,
            encrypted,
            mac,
            fields,
            version,
            cipher,
            compression,
            kdf,
            seed: Zeroizing::new(seed),
        })
    }

    /// Exact public header bytes for later authentication and provenance.
    pub fn raw(&self) -> &[u8] {
        self.raw
    }
    /// Encrypted bytes; KDBX4 includes HMAC block framing.
    pub fn encrypted(&self) -> &[u8] {
        self.encrypted
    }
    /// Header HMAC for KDBX4; absent in KDBX3.1.
    pub fn header_mac(&self) -> Option<&[u8]> {
        self.mac
    }
    /// An original public header field, identified by its KDBX tag.
    pub fn field(&self, id: usize) -> Option<&[u8]> {
        self.fields.get(id).copied().flatten()
    }
    /// Accepted format version.
    pub fn version(&self) -> &DatabaseVersion {
        &self.version
    }
    /// Outer cipher configuration.
    pub fn cipher(&self) -> &OuterCipherConfig {
        &self.cipher
    }
    /// Payload compression configuration.
    pub fn compression(&self) -> &CompressionConfig {
        &self.compression
    }
    /// Admitted KDF parameters.
    pub fn kdf(&self) -> &KdfConfig {
        &self.kdf
    }
    /// Public KDF salt or transform seed.
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }
}

fn dictionary_error(error: VariantDictionaryError) -> Error {
    match error {
        VariantDictionaryError::Limit => Error::Limit,
        _ => Error::Malformed,
    }
}

pub(crate) fn take<'a>(
    input: &'a [u8],
    pos: &mut usize,
    size: usize,
    limit: usize,
) -> Result<&'a [u8], Error> {
    let end = pos
        .checked_add(size)
        .filter(|&end| end <= limit)
        .ok_or(Error::Limit)?;
    let value = input.get(*pos..end).ok_or(Error::Malformed)?;
    *pos = end;
    Ok(value)
}
fn exact(input: &[u8], size: usize) -> Result<(), Error> {
    if input.len() != size {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
pub(crate) fn read32(input: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        input.try_into().map_err(|_| Error::Malformed)?,
    ))
}
fn read64(input: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        input.try_into().map_err(|_| Error::Malformed)?,
    ))
}
fn frames(input: &[u8], max: usize, check: &mut dyn FnMut(usize) -> bool) -> Result<usize, Error> {
    let mut pos = 0;
    let mut size = 0;
    for _ in 0..max {
        if !check(pos) {
            return Err(Error::Canceled);
        }
        take(input, &mut pos, 32, input.len())?;
        let length = read32(take(input, &mut pos, 4, input.len())?)? as usize;
        take(input, &mut pos, length, input.len())?;
        if length == 0 {
            return if pos == input.len() {
                Ok(size)
            } else {
                Err(Error::Malformed)
            };
        }
        size += length;
    }
    Err(Error::Limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    const V4: &[u8] =
        include_bytes!("../../../../crates/confidex-app/tests/import_fixtures/kdbx/password.kdbx");
    const V3: &[u8] = include_bytes!("../../tests/resources/test_db_with_password.kdbx");

    #[test]
    fn actual_versions_and_budgets() -> Result<(), Error> {
        for input in [V3, V4] {
            let header = Header::inspect(input, &Limits::default(), &mut |_| true)?;
            assert!(header.raw().len() < 1024);
            assert_eq!(header.seed().len(), 32);
            assert_eq!(header.cipher(), &OuterCipherConfig::AES256);
            assert!(matches!(header.kdf(), KdfConfig::Aes { .. }));
        }
        let limits = Limits {
            aes_rounds: 1,
            ..Limits::default()
        };
        assert!(matches!(
            Header::inspect(V4, &limits, &mut |_| true),
            Err(Error::KdfLimit)
        ));
        assert!(matches!(
            Header::inspect(V4, &Limits::default(), &mut |_| false),
            Err(Error::Canceled)
        ));
        Ok(())
    }

    #[test]
    fn truncated_framing_and_trailing_data() -> Result<(), Error> {
        let header = Header::inspect(V4, &Limits::default(), &mut |_| true)?;
        for end in 0..header.raw().len() + 65 {
            assert!(Header::inspect(
                V4.get(..end).ok_or(Error::Malformed)?,
                &Limits::default(),
                &mut |_| true
            )
            .is_err());
        }
        for end in V4.len() - 40..V4.len() {
            assert!(Header::inspect(
                V4.get(..end).ok_or(Error::Malformed)?,
                &Limits::default(),
                &mut |_| true
            )
            .is_err());
        }
        let mut input = V4.to_vec();
        input.push(0);
        assert!(Header::inspect(&input, &Limits::default(), &mut |_| true).is_err());
        let limits = Limits {
            blocks: 1,
            ..Limits::default()
        };
        assert!(matches!(
            Header::inspect(V4, &limits, &mut |_| true),
            Err(Error::Limit)
        ));
        Ok(())
    }

    #[test]
    fn header_fields_have_fixed_lengths_and_unique_tags() -> Result<(), Error> {
        let header = Header::inspect(V4, &Limits::default(), &mut |_| true)?;
        let end = header.raw().len();
        let mut input = V4.to_vec();
        *input.get_mut(end + 1).ok_or(Error::Malformed)? ^= 1;
        assert!(matches!(
            Header::inspect(&input, &Limits::default(), &mut |_| true),
            Err(Error::Malformed)
        ));
        let mut pos = 12;
        while pos < end - 9 {
            let start = pos;
            let id = *take(V4, &mut pos, 1, end)?
                .first()
                .ok_or(Error::Malformed)?;
            let length = read32(take(V4, &mut pos, 4, end)?)? as usize;
            take(V4, &mut pos, length, end)?;
            if matches!(id, 3 | 4 | 7) {
                let mut corrupt = V4.to_vec();
                *corrupt.get_mut(start + 1).ok_or(Error::Malformed)? = 1;
                assert!(Header::inspect(&corrupt, &Limits::default(), &mut |_| true).is_err());
                let mut repeated = V4.get(..start).ok_or(Error::Malformed)?.to_vec();
                repeated.extend_from_slice(V4.get(start..pos).ok_or(Error::Malformed)?);
                repeated.extend_from_slice(V4.get(start..).ok_or(Error::Malformed)?);
                assert!(matches!(
                    Header::inspect(&repeated, &Limits::default(), &mut |_| true),
                    Err(Error::Malformed)
                ));
            }
        }
        Ok(())
    }
}
