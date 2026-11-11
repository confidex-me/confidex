//! Portable password-protected exports use the common Bitwarden JSON mapper.
use super::super::{Context, Error, ErrorKind, Memory, Phase, Reservation, json};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::{Engine, prelude::BASE64_STANDARD};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use confidex_vault::record::{Mapping, Value};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod writer;
pub use writer::Writer;

struct Kdf {
    kind: u32,
    iterations: u32,
    memory: u32,
    lanes: u32,
}
struct Ciphertext {
    iv: [u8; 16],
    mac: [u8; 32],
    bytes: Zeroizing<Vec<u8>>,
    _memory: Reservation,
}

/// InvalidOptions means no password; Checksum combines password and integrity errors.
/// Account-restricted exports return UnsupportedFormat without deriving a key.
pub fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    let (kdf, salt, mut validation, mut data) = {
        let document = json::Document::parse(input, context)?;
        let root = json::owned(document.raw(), context)?;
        let object = root.as_object().ok_or(ErrorKind::Malformed)?;
        if root.get("encrypted").and_then(Json::as_bool) != Some(true) {
            return Err(ErrorKind::UnsupportedFormat.into());
        }
        match root.get("passwordProtected") {
            None | Some(Json::Bool(false)) => return Err(ErrorKind::UnsupportedFormat.into()),
            Some(Json::Bool(true)) => (),
            _ => return Err(ErrorKind::Malformed.into()),
        }
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "encrypted"
                    | "passwordProtected"
                    | "salt"
                    | "kdfType"
                    | "kdfIterations"
                    | "kdfMemory"
                    | "kdfParallelism"
                    | "encKeyValidation_DO_NOT_EDIT"
                    | "data"
            )
        }) {
            return Err(ErrorKind::UnsupportedVersion.into());
        }
        let kdf = Kdf::read(&root)?;
        let salt = text(&root, "salt")?;
        // The KDF uses this Base64 text, not its decoded salt bytes.
        fixed::<16>(salt)?;
        let salt = Zeroizing::new(salt.to_owned());
        let validation =
            Ciphertext::read(text(&root, "encKeyValidation_DO_NOT_EDIT")?, 64, context)?;
        let data = Ciphertext::read(text(&root, "data")?, context.limits.unpacked_bytes, context)?;
        (kdf, salt, validation, data)
    };
    if context.options.password.is_empty() {
        return Err(ErrorKind::InvalidOptions.into());
    }
    context.checkpoint(Phase::Read, 0, 3)?;
    let key = kdf.derive(
        context.options.password.as_bytes(),
        salt.as_bytes(),
        context.memory(),
    )?;
    context.checkpoint(Phase::Read, 1, 3)?;
    validation.open(&key)?;
    let check = std::str::from_utf8(&validation.bytes).map_err(|_| ErrorKind::Checksum)?;
    if check.len() != 36
        || !check.bytes().enumerate().all(|(at, b)| {
            if matches!(at, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(ErrorKind::Checksum.into());
    }
    drop(validation);
    data.open(&key)?;
    drop(key);
    drop(salt);
    if data.bytes.len() > context.limits.unpacked_bytes {
        return Err(ErrorKind::Limit.into());
    }
    context.checkpoint(Phase::Read, 2, 3)?;
    let mut parameters = Mapping::from([
        ("kdfType".into(), Value::from(kdf.kind)),
        ("kdfIterations".into(), Value::from(kdf.iterations)),
    ]);
    if kdf.kind == 1 {
        parameters.insert("kdfMemory".into(), kdf.memory.into());
        parameters.insert("kdfParallelism".into(), kdf.lanes.into());
    }
    super::bitwarden_json::parse_with(
        &data.bytes,
        context,
        Mapping::from([(
            "bitwarden.encryption".into(),
            Value::Map(parameters.into_iter().map(|(k, v)| (k.into(), v)).collect()),
        )]),
        &mut |_, _, _| Ok(Vec::new()),
    )
}

fn text<'a>(root: &'a Json, name: &str) -> Result<&'a str, Error> {
    root.get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| ErrorKind::Malformed.into())
}
fn number(root: &Json, name: &str) -> Result<u32, Error> {
    root.get(name)
        .and_then(Json::as_u64)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| ErrorKind::UnsupportedVersion.into())
}
fn fixed<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    if BASE64_STANDARD
        .decode_slice(text, &mut bytes)
        .map_err(|_| ErrorKind::Malformed)?
        != N
    {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(bytes)
}
impl Kdf {
    fn read(root: &Json) -> Result<Self, Error> {
        let kind = number(root, "kdfType")?;
        let iterations = number(root, "kdfIterations")?;
        match kind {
            0 => {
                if !(5_000..=2_000_000).contains(&iterations) {
                    return Err(ErrorKind::Limit.into());
                }
                if ["kdfMemory", "kdfParallelism"]
                    .iter()
                    .any(|k| root.get(k).is_some_and(|v| !v.is_null()))
                {
                    return Err(ErrorKind::UnsupportedVersion.into());
                }
                Ok(Self {
                    kind,
                    iterations,
                    memory: 0,
                    lanes: 0,
                })
            }
            1 => {
                let memory = number(root, "kdfMemory")?;
                let lanes = number(root, "kdfParallelism")?;
                if !(2..=10).contains(&iterations)
                    || !(16..=1024).contains(&memory)
                    || !(1..=16).contains(&lanes)
                {
                    return Err(ErrorKind::Limit.into());
                }
                Ok(Self {
                    kind,
                    iterations,
                    memory,
                    lanes,
                })
            }
            _ => Err(ErrorKind::UnsupportedVersion.into()),
        }
    }
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        memory: &Memory,
    ) -> Result<Zeroizing<[u8; 64]>, Error> {
        let mut material = Zeroizing::new([0; 32]);
        if self.kind == 0 {
            pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, self.iterations, &mut material[..]);
        } else {
            let params = Params::new(self.memory * 1024, self.iterations, self.lanes, Some(32))
                .map_err(|_| ErrorKind::UnsupportedVersion)?;
            let count = params.block_count();
            let _memory = memory.reserve(count * std::mem::size_of::<Block>() + (1 << 20))?;
            let mut blocks = Zeroizing::new(Vec::new());
            blocks
                .try_reserve_exact(count)
                .map_err(|_| ErrorKind::Allocation)?;
            blocks.resize(count, Block::default());
            let salt_hash = Sha256::digest(salt);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into_with_memory(
                    password,
                    &salt_hash,
                    &mut material[..],
                    &mut blocks[..],
                )
                .map_err(|_| ErrorKind::Checksum)?;
        }
        let hkdf =
            hkdf::Hkdf::<Sha256>::from_prk(&material[..]).map_err(|_| ErrorKind::Checksum)?;
        let mut key = Zeroizing::new([0; 64]);
        hkdf.expand(b"enc", &mut key[..32])
            .map_err(|_| ErrorKind::Checksum)?;
        hkdf.expand(b"mac", &mut key[32..])
            .map_err(|_| ErrorKind::Checksum)?;
        Ok(key)
    }
}
impl Ciphertext {
    fn read(text: &str, limit: usize, context: &Context<'_>) -> Result<Self, Error> {
        let text = text
            .strip_prefix("2.")
            .ok_or(ErrorKind::UnsupportedVersion)?;
        let mut parts = text.split('|');
        let iv = fixed(parts.next().ok_or(ErrorKind::Malformed)?)?;
        let encoded = parts.next().ok_or(ErrorKind::Malformed)?;
        let mac = fixed(parts.next().ok_or(ErrorKind::Malformed)?)?;
        if parts.next().is_some() || encoded.len() % 4 != 0 {
            return Err(ErrorKind::Malformed.into());
        }
        let capacity = encoded
            .len()
            .checked_div(4)
            .and_then(|n| n.checked_mul(3))
            .ok_or(ErrorKind::Limit)?;
        if capacity == 0 || capacity > limit.saturating_add(18) {
            return Err(ErrorKind::Limit.into());
        }
        let memory = context.memory().reserve(capacity)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ErrorKind::Allocation)?;
        bytes.resize(capacity, 0);
        let size = BASE64_STANDARD
            .decode_slice(encoded, &mut bytes)
            .map_err(|_| ErrorKind::Malformed)?;
        bytes.truncate(size);
        if size == 0 || size % 16 != 0 || size > limit.saturating_add(16) {
            return Err(ErrorKind::Malformed.into());
        }
        Ok(Self {
            iv,
            mac,
            bytes,
            _memory: memory,
        })
    }
    fn open(&mut self, key: &[u8; 64]) -> Result<(), Error> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|_| ErrorKind::Checksum)?;
        mac.update(&self.iv);
        mac.update(&self.bytes);
        mac.verify_slice(&self.mac)
            .map_err(|_| ErrorKind::Checksum)?;
        let length = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key[..32], &self.iv)
            .map_err(|_| ErrorKind::Checksum)?
            .decrypt_padded::<Pkcs7>(&mut self.bytes)
            .map_err(|_| ErrorKind::Checksum)?
            .len();
        self.bytes.truncate(length);
        Ok(())
    }
}
