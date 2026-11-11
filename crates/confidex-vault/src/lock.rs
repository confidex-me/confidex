use crate::{crypto, encoding, entropy, kdf, resources, trust};
use rmpv::ValueRef;
use zeroize::Zeroizing;

pub const MAX_LOCK: usize = 344;
const HEADER_LIMITS: encoding::Limits = encoding::Limits {
    bytes: 256,
    depth: 2,
    nodes: 16,
    string: 0,
    binary: 32,
    key: 0,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Version,
    Limit,
    Allocation,
    Kdf(kdf::Error),
    Crypto(crypto::Error),
    Trust(trust::TrustError),
    Entropy(entropy::EntropyError),
}

pub struct OpenedVault {
    vault_id: [u8; 16],
    keys: crypto::VaultKeys,
    anchor: trust::TrustAnchor,
}
impl OpenedVault {
    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }
    pub fn keys(&self) -> &crypto::VaultKeys {
        &self.keys
    }
    pub fn anchor(&self) -> &trust::TrustAnchor {
        &self.anchor
    }
    pub fn rewrap(&self, new_password: &[u8], memory_budget: usize) -> Result<Vec<u8>, Error> {
        budget(memory_budget)?;
        kdf::admit(kdf::CREATION, new_password.len(), 16, memory_budget).map_err(Error::Kdf)?;
        protect(&self.vault_id, &self.keys, new_password, memory_budget)
    }
}

pub struct CreatedVault {
    pub lock: Vec<u8>,
    pub vault: OpenedVault,
}

pub struct Header {
    pub vault_id: [u8; 16],
    pub public_key: [u8; 32],
    parameters: kdf::Parameters,
    salt: [u8; 16],
}
fn budget(budget: usize) -> Result<(), Error> {
    if budget > resources::MAX_OPEN_MEMORY {
        return Err(Error::Limit);
    }
    Ok(())
}
fn take_bin<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len = rmp::decode::read_bin_len(input).map_err(|_| Error::Invalid)? as usize;
    let (value, rest) = input.split_at_checked(len).ok_or(Error::Invalid)?;
    *input = rest;
    Ok(value)
}
fn array<'a, 'b>(v: &'b ValueRef<'a>, count: usize) -> Result<&'b [ValueRef<'a>], Error> {
    match v {
        ValueRef::Array(v) if v.len() == count => Ok(v),
        _ => Err(Error::Invalid),
    }
}
fn number(v: &ValueRef<'_>) -> Result<u64, Error> {
    v.as_u64().ok_or(Error::Invalid)
}
fn binary<const N: usize>(v: &ValueRef<'_>) -> Result<[u8; N], Error> {
    match v {
        ValueRef::Binary(b) => (*b).try_into().map_err(|_| Error::Invalid),
        _ => Err(Error::Invalid),
    }
}
fn header(input: &[u8]) -> Result<Header, Error> {
    encoding::validate_messagepack(input, HEADER_LIMITS).map_err(|e| match e {
        encoding::EncodingError::Invalid => Error::Invalid,
        encoding::EncodingError::Limit => Error::Limit,
        encoding::EncodingError::Allocation => Error::Allocation,
    })?;
    let root = rmpv::decode::read_value_ref(&mut &*input).map_err(|_| Error::Invalid)?;
    let h = array(&root, 4)?;
    if number(&h[0])? != 1 {
        return Err(Error::Version);
    }
    let k = array(&h[3], 7)?;
    Ok(Header {
        vault_id: binary(&h[1])?,
        public_key: binary(&h[2])?,
        salt: binary(&k[6])?,
        parameters: kdf::Parameters {
            algorithm: number(&k[0])?,
            version: number(&k[1])?,
            memory_kib: number(&k[2])?,
            passes: number(&k[3])?,
            lanes: number(&k[4])?,
            output_bytes: number(&k[5])?,
        },
    })
}

fn parse(mut wire: &[u8]) -> Result<(Header, &[u8], &[u8]), Error> {
    if wire.len() > MAX_LOCK {
        return Err(Error::Limit);
    }
    if rmp::decode::read_array_len(&mut wire).map_err(|_| Error::Invalid)? != 2 {
        return Err(Error::Invalid);
    }
    let h = take_bin(&mut wire)?;
    let packet = take_bin(&mut wire)?;
    if packet.len() != 73 || !wire.is_empty() {
        return Err(Error::Invalid);
    }
    Ok((header(h)?, h, packet))
}

/// Read the public header. This does not authenticate or decrypt the lock.
pub fn inspect(wire: &[u8]) -> Result<Header, Error> {
    let (parsed, _, _) = parse(wire)?;
    kdf::admit(
        parsed.parameters,
        0,
        parsed.salt.len(),
        kdf::REQUIRED_MEMORY,
    )
    .map_err(Error::Kdf)?;
    Ok(parsed)
}

pub fn open(
    wire: &[u8],
    password: &[u8],
    secret_key: &[u8; 32],
    memory_budget: usize,
) -> Result<OpenedVault, Error> {
    open_with_unlock_key(wire, password, secret_key, memory_budget).map(|(opened, _)| opened)
}

pub fn open_with_unlock_key(
    wire: &[u8],
    password: &[u8],
    secret_key: &[u8; 32],
    memory_budget: usize,
) -> Result<(OpenedVault, Zeroizing<[u8; 32]>), Error> {
    budget(memory_budget)?;
    let (parsed, h, packet) = parse(wire)?;
    let p = kdf::password_key(parsed.parameters, password, &parsed.salt, memory_budget)
        .map_err(Error::Kdf)?;
    let key = crypto::lock_key(&p, secret_key);
    let opened = open_parsed(parsed, h, packet, &key, secret_key)?;
    Ok((opened, key))
}

pub fn open_with_saved_key(
    wire: &[u8],
    key: &[u8; 32],
    secret_key: &[u8; 32],
) -> Result<OpenedVault, Error> {
    let (parsed, h, packet) = parse(wire)?;
    open_parsed(parsed, h, packet, key, secret_key)
}

fn open_parsed(
    parsed: Header,
    header: &[u8],
    packet: &[u8],
    key: &[u8; 32],
    secret_key: &[u8; 32],
) -> Result<OpenedVault, Error> {
    let keys =
        crypto::open_lock_with_key(key, secret_key, packet, header).map_err(Error::Crypto)?;
    let anchor = trust::TrustAnchor::from_opened_lock(parsed.vault_id, &keys, &parsed.public_key)
        .map_err(Error::Trust)?;
    Ok(OpenedVault {
        vault_id: parsed.vault_id,
        keys,
        anchor,
    })
}

fn encode_header(
    vault_id: &[u8; 16],
    keys: &crypto::VaultKeys,
    salt: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let mut h = Vec::new();
    h.try_reserve_exact(HEADER_LIMITS.bytes)
        .map_err(|_| Error::Allocation)?;
    macro_rules! write {
        ($e:expr) => {
            $e.map_err(|_| Error::Invalid)?
        };
    }
    write!(rmp::encode::write_array_len(&mut h, 4));
    write!(rmp::encode::write_uint(&mut h, 1));
    for value in [
        vault_id.as_slice(),
        keys.signing_key().verifying_key().as_bytes().as_slice(),
    ] {
        write!(rmp::encode::write_bin(&mut h, value));
    }
    write!(rmp::encode::write_array_len(&mut h, 7));
    let p = kdf::CREATION;
    for value in [
        p.algorithm,
        p.version,
        p.memory_kib,
        p.passes,
        p.lanes,
        p.output_bytes,
    ] {
        write!(rmp::encode::write_uint(&mut h, value));
    }
    write!(rmp::encode::write_bin(&mut h, salt));
    Ok(h)
}
fn protect(
    vault_id: &[u8; 16],
    keys: &crypto::VaultKeys,
    password: &[u8],
    memory_budget: usize,
) -> Result<Vec<u8>, Error> {
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    entropy::fill_random(&mut salt).map_err(Error::Entropy)?;
    entropy::fill_random(&mut nonce).map_err(Error::Entropy)?;
    let h = encode_header(vault_id, keys, &salt)?;
    let p = kdf::password_key(kdf::CREATION, password, &salt, memory_budget).map_err(Error::Kdf)?;
    let packet =
        crypto::seal_lock(keys, &p, &keys.secret_key(), &nonce, &h).map_err(Error::Crypto)?;
    let mut wire = Vec::new();
    wire.try_reserve_exact(MAX_LOCK)
        .map_err(|_| Error::Allocation)?;
    rmp::encode::write_array_len(&mut wire, 2).map_err(|_| Error::Invalid)?;
    for value in [h.as_slice(), packet.as_slice()] {
        rmp::encode::write_bin(&mut wire, value).map_err(|_| Error::Invalid)?;
    }
    Ok(wire)
}

pub fn create(password: &[u8], memory_budget: usize) -> Result<CreatedVault, Error> {
    budget(memory_budget)?;
    kdf::admit(kdf::CREATION, password.len(), 16, memory_budget).map_err(Error::Kdf)?;
    let mut random_material = Zeroizing::new([0; 32]);
    entropy::fill_random(&mut random_material[..]).map_err(Error::Entropy)?;
    let material = crypto::clamp_material(*random_material);
    let keys = crypto::VaultKeys::from_material(1, &material[..]).map_err(Error::Crypto)?;
    let mut vault_id = [0; 16];
    entropy::fill_random(&mut vault_id).map_err(Error::Entropy)?;
    let lock = protect(&vault_id, &keys, password, memory_budget)?;
    let anchor = trust::TrustAnchor::from_opened_lock(
        vault_id,
        &keys,
        &keys.signing_key().verifying_key().to_bytes(),
    )
    .map_err(Error::Trust)?;
    Ok(CreatedVault {
        lock,
        vault: OpenedVault {
            vault_id,
            keys,
            anchor,
        },
    })
}
