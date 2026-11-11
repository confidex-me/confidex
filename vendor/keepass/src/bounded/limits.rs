use crate::config::KdfConfig;
use thiserror::Error;

/// A decoder failure that does not include source values or credentials.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A declared or observed resource cost is too large.
    #[error("KDBX resource limit")]
    Limit,
    /// A fallible allocation failed.
    #[error("KDBX allocation failed")]
    Allocation,
    /// The input is incomplete or invalid.
    #[error("Invalid KDBX data")]
    Malformed,
    /// The input requests an unsupported format or algorithm.
    #[error("Unsupported KDBX data")]
    Unsupported,
    /// The caller stopped the operation.
    #[error("KDBX operation canceled")]
    Canceled,
    /// Credential verification failed.
    #[error("KDBX credentials or integrity check failed")]
    Credentials,
    /// The key derivation parameters exceed the resource budget.
    #[error("KDBX key derivation limit")]
    KdfLimit,
}

/// Resource ceilings. Callers may reduce the defaults, but may not raise them.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum borrowed file size.
    pub input_bytes: usize,
    /// Maximum outer header size.
    pub header_bytes: usize,
    /// Maximum decoder working memory, excluding the borrowed input.
    pub memory_bytes: usize,
    /// Maximum decompressed payload size, including attachments.
    pub unpacked_bytes: usize,
    /// Maximum encrypted blocks or binary pool entries.
    pub blocks: usize,
    /// Maximum AES transform rounds.
    pub aes_rounds: u64,
    /// Maximum Argon2 memory in bytes.
    pub argon_memory: u64,
    /// Maximum Argon2 passes.
    pub argon_iterations: u64,
    /// Maximum Argon2 lanes.
    pub argon_lanes: u32,
    /// Maximum Argon2 memory-bytes multiplied by passes.
    pub argon_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 64 << 20,
            header_bytes: 1 << 20,
            memory_bytes: 192 << 20,
            unpacked_bytes: 64 << 20,
            blocks: 16_384,
            aes_rounds: 25_000_000,
            argon_memory: 64 << 20,
            argon_iterations: 1024,
            argon_lanes: 16,
            argon_work: 16 << 30,
        }
    }
}

impl Limits {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let max = Self::default();
        if self.input_bytes > max.input_bytes
            || self.header_bytes > max.header_bytes
            || self.memory_bytes > max.memory_bytes
            || self.unpacked_bytes > max.unpacked_bytes
            || self.blocks > max.blocks
            || self.aes_rounds > max.aes_rounds
            || self.argon_memory > max.argon_memory
            || self.argon_iterations > max.argon_iterations
            || self.argon_lanes > max.argon_lanes
            || self.argon_work > max.argon_work
        {
            return Err(Error::Limit);
        }
        Ok(())
    }

    /// Admit the KDF before a transform or a work-memory allocation.
    pub fn admit_kdf(&self, config: &KdfConfig, seed: &[u8]) -> Result<(), Error> {
        self.validate()?;
        match config {
            KdfConfig::Aes { rounds } => {
                if seed.len() != 32 {
                    return Err(Error::Malformed);
                }
                if *rounds > self.aes_rounds || self.memory_bytes < 8192 {
                    return Err(Error::KdfLimit);
                }
            }
            KdfConfig::Argon2 {
                memory,
                iterations,
                parallelism,
                ..
            }
            | KdfConfig::Argon2id {
                memory,
                iterations,
                parallelism,
                ..
            } => {
                if !(8..=1024).contains(&seed.len())
                    || *iterations == 0
                    || *parallelism == 0
                    || *memory < u64::from(*parallelism) * 8192
                    || memory % 1024 != 0
                {
                    return Err(Error::Malformed);
                }
                if *memory > self.argon_memory
                    || *iterations > self.argon_iterations
                    || *parallelism > self.argon_lanes
                    || memory
                        .checked_mul(*iterations)
                        .is_none_or(|work| work > self.argon_work)
                    || memory
                        .checked_add(1 << 20)
                        .is_none_or(|peak| peak > self.memory_bytes as u64)
                {
                    return Err(Error::KdfLimit);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_pass_profiles_keep_a_bounded_work_budget() {
        let limits = Limits::default();
        for iterations in [121, 256, 257] {
            let config = KdfConfig::Argon2id {
                memory: 64 << 20,
                iterations,
                parallelism: 4,
                version: argon2::Version::V0x13,
            };
            assert_eq!(
                limits.admit_kdf(&config, &[9; 32]),
                if iterations <= 256 {
                    Ok(())
                } else {
                    Err(Error::KdfLimit)
                }
            );
            assert_eq!(
                Limits {
                    argon_work: 512 << 20,
                    ..limits
                }
                .admit_kdf(&config, &[9; 32]),
                Err(Error::KdfLimit)
            );
        }
    }
}
