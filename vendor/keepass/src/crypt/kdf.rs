use super::CryptographyError;
use crate::{
    bounded::{Error, Limits},
    config::KdfConfig,
};
use aes::Aes256;
use argon2::{Argon2, Block, Params};
use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::{typenum::U32, Array as GenericArray};
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use zeroize::Zeroizing;

pub(crate) trait Kdf {
    fn transform_key(
        &self,
        key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        self.transform_key_checked(key, &Limits::default(), &mut |_| true)
    }
    fn transform_key_checked(
        &self,
        key: &GenericArray<u8, U32>,
        limits: &Limits,
        check: &mut dyn FnMut(u64) -> bool,
    ) -> Result<GenericArray<u8, U32>, CryptographyError>;
}

pub struct AesKdf {
    pub seed: Vec<u8>,
    pub rounds: u64,
}

impl Kdf for AesKdf {
    fn transform_key_checked(
        &self,
        key: &GenericArray<u8, U32>,
        limits: &Limits,
        check: &mut dyn FnMut(u64) -> bool,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        limits.admit_kdf(
            &KdfConfig::Aes {
                rounds: self.rounds,
            },
            &self.seed,
        )?;
        if !check(0) {
            return Err(Error::Canceled.into());
        }
        let seed = Zeroizing::new(
            self.seed
                .as_slice()
                .try_into()
                .map_err(|_| cipher::InvalidLength)?,
        );
        let cipher = Aes256::new(&seed);
        let mut block1 = Zeroizing::new(
            GenericArray::try_from(key.get(..16).ok_or(Error::Malformed)?)
                .map_err(|_| cipher::InvalidLength)?,
        );
        let mut block2 = Zeroizing::new(
            GenericArray::try_from(key.get(16..).ok_or(Error::Malformed)?)
                .map_err(|_| cipher::InvalidLength)?,
        );
        for round in 0..self.rounds {
            if round % 1024 == 0 && !check(round) {
                return Err(Error::Canceled.into());
            }
            cipher.encrypt_block(&mut block1);
            cipher.encrypt_block(&mut block2);
        }
        if !check(self.rounds) {
            return Err(Error::Canceled.into());
        }
        let mut digest = Sha256::new();
        digest.update(block1.as_slice());
        digest.update(block2.as_slice());
        Ok(digest.finalize())
    }
}

pub struct Argon2Kdf {
    pub memory: u64,
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub parallelism: u32,
    pub version: argon2::Version,
    pub variant: argon2::Algorithm,
}

impl Kdf for Argon2Kdf {
    fn transform_key_checked(
        &self,
        key: &GenericArray<u8, U32>,
        limits: &Limits,
        check: &mut dyn FnMut(u64) -> bool,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        let config = match self.variant {
            argon2::Algorithm::Argon2d => KdfConfig::Argon2 {
                memory: self.memory,
                iterations: self.iterations,
                parallelism: self.parallelism,
                version: self.version,
            },
            argon2::Algorithm::Argon2id => KdfConfig::Argon2id {
                memory: self.memory,
                iterations: self.iterations,
                parallelism: self.parallelism,
                version: self.version,
            },
            _ => return Err(Error::Unsupported.into()),
        };
        limits.admit_kdf(&config, &self.salt)?;
        if !check(0) {
            return Err(Error::Canceled.into());
        }
        let memory = (self.memory / 1024).try_into().map_err(|_| Error::Limit)?;
        let iterations = self.iterations.try_into().map_err(|_| Error::Limit)?;
        let params = Params::new(memory, iterations, self.parallelism, Some(32))?;
        let mut blocks = Zeroizing::new(Vec::new());
        blocks
            .try_reserve_exact(params.block_count())
            .map_err(|_| Error::Allocation)?;
        blocks.resize(params.block_count(), Block::default());
        let mut output = Zeroizing::new([0; 32]);
        // RustCrypto owns one derivation call; cancellation resumes when it returns.
        Argon2::new(self.variant, self.version, params).hash_password_into_with_memory(
            key,
            &self.salt,
            &mut output[..],
            &mut blocks[..],
        )?;
        if !check(self.iterations) {
            return Err(Error::Canceled.into());
        }
        Ok(GenericArray::from(*output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        Algorithm::{Argon2d, Argon2id},
        Version::{V0x10, V0x13},
    };

    #[test]
    fn independent_argon2_vectors() -> Result<(), CryptographyError> {
        // rust-argon2 3.0.0: public input [7;32], salt [9;32], 64 KiB, two passes.
        for (variant, version, parallelism, expected) in [
            (
                Argon2d,
                V0x10,
                1,
                "23e1dd1fce57d59559164b99ff242db9cf8af58091a046b9094441d02fb79946",
            ),
            (
                Argon2d,
                V0x10,
                2,
                "550ec11f4a912e8e40adf7211e99f0d330cc10b7c403bce7891090f3f66d1f93",
            ),
            (
                Argon2d,
                V0x13,
                1,
                "bb2114f59af799592f5d1017c0f8d3830d5a04f3f6140c748866954a23797dd1",
            ),
            (
                Argon2d,
                V0x13,
                2,
                "05f2c56b2ea27a9559ed970b01400f885b49cb19e59438cd48346b7f04c5f937",
            ),
            (
                Argon2id,
                V0x10,
                1,
                "786cc5b2f0ac5e26f60757e92aeee674ca27c0d546c8059610dd4ffb6c187c0e",
            ),
            (
                Argon2id,
                V0x10,
                2,
                "5091fba1c3de3d5c79b84e4639e2cc56a9445dc619478b248dc5eec24262f7ae",
            ),
            (
                Argon2id,
                V0x13,
                1,
                "3a1d53298481cf348c277293fe01c95ac5cf7548a43ab582915e103eace79260",
            ),
            (
                Argon2id,
                V0x13,
                2,
                "69b4c2e195396b9d3a3cdd7c193f1b4745986c5f5923531e2264e7bd956b5add",
            ),
        ] {
            let kdf = Argon2Kdf {
                memory: 64 * 1024,
                salt: vec![9; 32],
                iterations: 2,
                parallelism,
                version,
                variant,
            };
            let output = kdf.transform_key(&GenericArray::from([7; 32]))?;
            assert_eq!(hex::encode(output), expected);
        }
        Ok(())
    }

    #[test]
    fn admission_and_cancellation_before_and_after_work() {
        let key = GenericArray::from([7; 32]);
        let mut calls = 0;
        let mut check = |_| {
            calls += 1;
            true
        };
        let oversized = AesKdf {
            seed: vec![9; 32],
            rounds: u64::MAX,
        };
        assert!(matches!(
            oversized.transform_key_checked(&key, &Limits::default(), &mut check),
            Err(CryptographyError::Boundary(Error::KdfLimit))
        ));
        assert_eq!(calls, 0);
        let aes = AesKdf {
            seed: vec![9; 32],
            rounds: 2048,
        };
        assert!(matches!(
            aes.transform_key_checked(&key, &Limits::default(), &mut |round| round < 1024),
            Err(CryptographyError::Boundary(Error::Canceled))
        ));
        let mut argon = Argon2Kdf {
            memory: 64 * 1024,
            salt: vec![9; 32],
            iterations: 2,
            parallelism: 1,
            version: V0x13,
            variant: Argon2id,
        };
        assert!(matches!(
            argon.transform_key_checked(&key, &Limits::default(), &mut |_| false),
            Err(CryptographyError::Boundary(Error::Canceled))
        ));
        assert!(matches!(
            argon.transform_key_checked(&key, &Limits::default(), &mut |pass| pass == 0),
            Err(CryptographyError::Boundary(Error::Canceled))
        ));
        for memory in [u64::MAX, 0, 8193, 65 << 20] {
            argon.memory = memory;
            assert!(argon.transform_key(&key).is_err());
        }
        argon.memory = 64 << 20;
        argon.iterations = Limits::default().argon_work / argon.memory + 1;
        assert!(matches!(
            argon.transform_key(&key),
            Err(CryptographyError::Boundary(Error::KdfLimit))
        ));
        let limits = Limits {
            aes_rounds: u64::MAX,
            ..Limits::default()
        };
        assert_eq!(
            limits.admit_kdf(&KdfConfig::Aes { rounds: 1 }, &[9; 32]),
            Err(Error::Limit)
        );
    }
}
