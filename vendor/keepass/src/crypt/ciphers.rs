use std::convert::TryInto;
use zeroize::Zeroizing;

use aes::Aes256;
#[cfg(feature = "save_kdbx4")]
use cipher::BlockModeEncrypt;
use cipher::{block_padding::Pkcs7, BlockModeDecrypt};
use hybrid_array::Array as GenericArray;
use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    Salsa20,
};

use crate::crypt::{calculate_sha256, CryptographyError};

pub(crate) trait Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError>;

    #[cfg(feature = "save_kdbx4")]
    /// The number of bytes expected by the cipher as an initialization vector.
    fn iv_size() -> usize
    where
        Self: Sized;

    #[cfg(feature = "save_kdbx4")]
    /// The number of bytes expected by the cipher as a key.
    fn key_size() -> usize
    where
        Self: Sized;
}

#[cfg(feature = "save_kdbx4")]
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
pub(crate) struct AES256Cipher {
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
}

impl AES256Cipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(AES256Cipher {
            key: Zeroizing::new(Vec::from(key)),
            iv: Zeroizing::new(Vec::from(iv)),
        })
    }
}

impl Cipher for AES256Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = Aes256CbcEncryptor::new_from_slices(&self.key, &self.iv)?;

        let size = padded_length(plaintext.len())?;
        let mut ciphertext = buffer(size)?;
        ciphertext.resize(size, 0);
        cipher
            .encrypt_padded_b2b::<Pkcs7>(plaintext, &mut ciphertext)
            .map_err(|_| crate::bounded::Error::Malformed)?;
        Ok(std::mem::take(&mut *ciphertext))
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut out = buffer(ciphertext.len())?;
        out.resize(ciphertext.len(), 0);

        let cipher = Aes256CbcDecryptor::new_from_slices(&self.key[..], &self.iv[..])?;

        let len = cipher
            .decrypt_padded_b2b::<Pkcs7>(ciphertext, &mut out)?
            .len();

        out.truncate(len);

        Ok(std::mem::take(&mut *out))
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        16
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

#[cfg(feature = "save_kdbx4")]
type TwofishCbcEncryptor = cbc::Encryptor<twofish::Twofish>;
type TwofishCbcDecryptor = cbc::Decryptor<twofish::Twofish>;
pub(crate) struct TwofishCipher {
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
}

impl TwofishCipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(TwofishCipher {
            key: Zeroizing::new(Vec::from(key)),
            iv: Zeroizing::new(Vec::from(iv)),
        })
    }
}

impl Cipher for TwofishCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = TwofishCbcEncryptor::new_from_slices(&self.key, &self.iv)?;

        let size = padded_length(plaintext.len())?;
        let mut ciphertext = buffer(size)?;
        ciphertext.resize(size, 0);
        cipher
            .encrypt_padded_b2b::<twofish::cipher::block_padding::Pkcs7>(plaintext, &mut ciphertext)
            .map_err(|_| crate::bounded::Error::Malformed)?;
        Ok(std::mem::take(&mut *ciphertext))
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = TwofishCbcDecryptor::new_from_slices(&self.key, &self.iv)?;

        let mut buf = buffer(ciphertext.len())?;
        buf.extend_from_slice(ciphertext);
        let length = cipher
            .decrypt_padded::<twofish::cipher::block_padding::Pkcs7>(&mut buf)?
            .len();
        buf.truncate(length);
        Ok(std::mem::take(&mut *buf))
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        16
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct Salsa20Cipher {
    cipher: salsa20::Salsa20,
}

impl Salsa20Cipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self, CryptographyError> {
        let key = Zeroizing::new(calculate_sha256(&[key]));
        let iv = GenericArray::from([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);

        Ok(Salsa20Cipher {
            cipher: Salsa20::new(&key, &iv),
        })
    }
}

impl Cipher for Salsa20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        self.decrypt(plaintext)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = buffer(ciphertext.len())?;
        buffer.extend_from_slice(ciphertext);
        self.cipher
            .try_apply_keystream(&mut buffer)
            .map_err(|_| crate::bounded::Error::Limit)?;
        Ok(std::mem::take(&mut *buffer))
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        // or 16
        32
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct ChaCha20Cipher {
    cipher: chacha20::ChaCha20,
}

impl ChaCha20Cipher {
    /// Create as an inner cipher by splitting up a SHA512 hash
    #[allow(clippy::indexing_slicing)] // Slicing is safe because SHA512 output is always 64 bytes
    pub(crate) fn new(key: &[u8]) -> Result<Self, CryptographyError> {
        let iv = Zeroizing::new(crate::crypt::calculate_sha512(&[key]));

        let key = Zeroizing::new(
            iv[0..32]
                .try_into()
                .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?,
        );
        let nonce = Zeroizing::new(
            iv[32..44]
                .try_into()
                .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?,
        );

        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new(&key, &nonce),
        })
    }

    /// Create as an outer cipher by separately-specified key and iv
    pub(crate) fn new_key_iv(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new_from_slices(key, iv)?,
        })
    }
}

impl Cipher for ChaCha20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        self.decrypt(plaintext)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = buffer(ciphertext.len())?;
        buffer.extend_from_slice(ciphertext);
        self.cipher
            .try_apply_keystream(&mut buffer)
            .map_err(|_| crate::bounded::Error::Limit)?;
        Ok(std::mem::take(&mut *buffer))
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        12
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct PlainCipher;
impl PlainCipher {
    pub(crate) fn new(_: &[u8]) -> Result<Self, CryptographyError> {
        Ok(PlainCipher)
    }
}
impl Cipher for PlainCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        self.decrypt(plaintext)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = buffer(ciphertext.len())?;
        buffer.extend_from_slice(ciphertext);
        Ok(std::mem::take(&mut *buffer))
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        1
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        1
    }
}

#[cfg(feature = "save_kdbx4")]
fn padded_length(length: usize) -> Result<usize, CryptographyError> {
    length
        .checked_add(16)
        .map(|size| size / 16 * 16)
        .ok_or_else(|| crate::bounded::Error::Limit.into())
}

fn buffer(size: usize) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    let mut value = Zeroizing::new(Vec::new());
    value
        .try_reserve_exact(size)
        .map_err(|_| crate::bounded::Error::Allocation)?;
    Ok(value)
}

#[cfg(all(test, feature = "save_kdbx4"))]
mod tests {
    use super::*;
    use crate::config::{InnerCipherConfig, OuterCipherConfig};

    #[test]
    fn padded_sizes_include_an_empty_block_and_reject_overflow() -> Result<(), CryptographyError> {
        for (input, expected) in [(0, 16), (1, 16), (15, 16), (16, 32), (17, 32)] {
            assert_eq!(padded_length(input)?, expected);
        }
        assert!(matches!(
            padded_length(usize::MAX),
            Err(CryptographyError::Boundary(crate::bounded::Error::Limit))
        ));
        Ok(())
    }

    #[test]
    fn cbc_returns_only_unpadded_plaintext_and_rejects_short_blocks(
    ) -> Result<(), CryptographyError> {
        for config in [OuterCipherConfig::AES256, OuterCipherConfig::Twofish] {
            for length in [0, 1, 15, 16, 17, 1024] {
                let plaintext = vec![7; length];
                let ciphertext = config.get_cipher(&[9; 32], &[3; 16])?.encrypt(&plaintext)?;
                let result = config
                    .get_cipher(&[9; 32], &[3; 16])?
                    .decrypt(&ciphertext)?;
                assert_eq!(result, plaintext);
                for end in 1..ciphertext.len().min(17) {
                    if end % 16 != 0 {
                        assert!(config
                            .get_cipher(&[9; 32], &[3; 16])?
                            .decrypt(
                                ciphertext
                                    .get(..end)
                                    .ok_or(crate::bounded::Error::Malformed)?
                            )
                            .is_err());
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn inner_stream_retains_position_across_empty_and_large_values() -> Result<(), CryptographyError>
    {
        for config in [
            InnerCipherConfig::Plain,
            InnerCipherConfig::Salsa20,
            InnerCipherConfig::ChaCha20,
        ] {
            let mut encrypt = config.get_cipher(&[9; 64])?;
            let mut decrypt = config.get_cipher(&[9; 64])?;
            for length in [0, 1, 65_537, 0, 3] {
                let plaintext = vec![7; length];
                assert_eq!(decrypt.decrypt(&encrypt.encrypt(&plaintext)?)?, plaintext);
            }
        }
        Ok(())
    }
}
