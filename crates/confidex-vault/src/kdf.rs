//! Fixed Argon2id profile and fallible resource admission.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub algorithm: u64,
    pub version: u64,
    pub memory_kib: u64,
    pub passes: u64,
    pub lanes: u64,
    pub output_bytes: u64,
}

pub const CREATION: Parameters = Parameters {
    algorithm: 2,
    version: 19,
    memory_kib: 65_536,
    passes: 3,
    lanes: 4,
    output_bytes: 32,
};
pub const REQUIRED_MEMORY: usize = 68 * 1024 * 1024;
pub const MAX_PASSWORD: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedProfile,
    InputLength,
    ResourceLimit,
    Allocation,
    Derivation,
}

pub fn admit(
    parameters: Parameters,
    password_len: usize,
    salt_len: usize,
    budget: usize,
) -> Result<(), Error> {
    if parameters != CREATION {
        return Err(Error::UnsupportedProfile);
    }
    if password_len > MAX_PASSWORD || salt_len != 16 {
        return Err(Error::InputLength);
    }
    if budget < REQUIRED_MEMORY {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}

pub fn password_key(
    parameters: Parameters,
    password: &[u8],
    salt: &[u8],
    budget: usize,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    admit(parameters, password.len(), salt.len(), budget)?;
    let params = Params::new(65_536, 3, 4, Some(32)).map_err(|_| Error::UnsupportedProfile)?;
    hash(params, password, salt)
}

fn hash(params: Params, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut blocks = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(params.block_count())
        .map_err(|_| Error::Allocation)?;
    blocks.resize(params.block_count(), Block::default());
    let mut output = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, &mut output[..], &mut blocks[..])
        .map_err(|_| Error::Derivation)?;
    Ok(output)
}
