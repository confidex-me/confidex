use crate::{crypto, encoding, entropy, record, resources, trust};
use ed25519_dalek::Signer;
use hpke::rand_core::SeedableRng;
use std::io::Write;
use zeroize::Zeroizing;

mod header;
pub use header::{EventKind, Header, Metadata, Options};

pub const MAX_PACKET: usize = resources::MAX_COMPRESSED + 48;
pub const MAX_ENVELOPE: usize = 4_065_668;
const WORK_MEMORY: usize = 24 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Version,
    Limit,
    Allocation,
    UnexpectedRevision,
    ValueSizes,
    Trust(trust::TrustError),
    Crypto(crypto::Error),
    Content(record::Error),
    Compression(resources::ResourceError),
    Entropy(entropy::EntropyError),
}

pub struct VerifiedRevision<'a> {
    header: Header,
    header_bytes: &'a [u8],
    ciphertext: &'a [u8],
    id: [u8; 32],
    wire_bytes: usize,
    verifying_key: [u8; 32],
}

pub struct OpenedRevision<'a> {
    pub revision: VerifiedRevision<'a>,
    pub record: record::Record,
}

pub(crate) fn admit(budget: usize) -> Result<usize, Error> {
    if !(WORK_MEMORY..=resources::MAX_OPEN_MEMORY).contains(&budget) {
        return Err(Error::Limit);
    }
    Ok(budget - WORK_MEMORY)
}

fn scan(bytes: &[u8], limits: encoding::Limits) -> Result<(), Error> {
    encoding::validate_messagepack(bytes, limits).map_err(|e| match e {
        encoding::EncodingError::Invalid => Error::Invalid,
        encoding::EncodingError::Limit => Error::Limit,
        encoding::EncodingError::Allocation => Error::Allocation,
    })
}

fn take_bin<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len = rmp::decode::read_bin_len(input).map_err(|_| Error::Invalid)? as usize;
    let (value, rest) = input.split_at_checked(len).ok_or(Error::Invalid)?;
    *input = rest;
    Ok(value)
}

fn framed(header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            crypto::RECORD_SIGNATURE_DOMAIN.len() + 16 + header.len() + ciphertext.len(),
        )
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(crypto::RECORD_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&(header.len() as u64).to_be_bytes());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    bytes.extend_from_slice(ciphertext);
    Ok(bytes)
}

pub fn verify<'a>(
    mut wire: &'a [u8],
    anchor: &trust::TrustAnchor,
    expected_id: Option<&[u8; 32]>,
    memory_budget: usize,
) -> Result<VerifiedRevision<'a>, Error> {
    admit(memory_budget)?;
    let wire_bytes = wire.len();
    if wire.len() > MAX_ENVELOPE {
        return Err(Error::Limit);
    }
    if rmp::decode::read_array_len(&mut wire).map_err(|_| Error::Invalid)? != 3 {
        return Err(Error::Invalid);
    }
    let h = take_bin(&mut wire)?;
    let c = take_bin(&mut wire)?;
    let signature: &[u8; 64] = take_bin(&mut wire)?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    if !wire.is_empty() || c.len() < 48 {
        return Err(Error::Invalid);
    }
    if c.len() > MAX_PACKET {
        return Err(Error::Limit);
    }
    let header = header::decode(h)?;
    anchor
        .verify(&header.vault_id, &framed(h, c)?, signature)
        .map_err(Error::Trust)?;
    let id = crypto::revision_id(h, c);
    if expected_id.is_some_and(|expected| *expected != id) {
        return Err(Error::UnexpectedRevision);
    }
    Ok(VerifiedRevision {
        header,
        header_bytes: h,
        ciphertext: c,
        id,
        wire_bytes,
        verifying_key: anchor.public_key(),
    })
}

impl VerifiedRevision<'_> {
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn encoded_len(&self) -> usize {
        self.wire_bytes
    }
    pub fn verifying_key(&self) -> [u8; 32] {
        self.verifying_key
    }
    pub fn same_payload(&self, other: &Self) -> bool {
        self.header_bytes == other.header_bytes && self.ciphertext == other.ciphertext
    }

    pub fn open(
        &self,
        keys: &crypto::VaultKeys,
        memory_budget: usize,
    ) -> Result<record::Record, Error> {
        let available = admit(memory_budget)?;
        let compressed = keys
            .open_record(self.ciphertext, self.header_bytes)
            .map_err(Error::Crypto)?;
        let output_limit = resources::MAX_DECOMPRESSED.min(available / 2);
        let raw = resources::decompress_content(&compressed, output_limit, available)
            .map_err(Error::Compression)?;
        drop(compressed);
        // Charge unused capacity as well as the raw bytes counted by the content decoder.
        let decode_budget = available
            .checked_sub(raw.capacity() - raw.len())
            .ok_or(Error::Limit)?;
        let decoded =
            record::Record::decode_content(&raw, decode_budget).map_err(Error::Content)?;
        if decoded.value_sizes != self.header.metadata.value_sizes {
            return Err(Error::ValueSizes);
        }
        if self.header.kind == EventKind::Deletion && !decoded.record.entries.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(decoded.record)
    }
}

pub fn open<'a>(
    wire: &'a [u8],
    keys: &crypto::VaultKeys,
    anchor: &trust::TrustAnchor,
    expected_id: Option<&[u8; 32]>,
    memory_budget: usize,
) -> Result<OpenedRevision<'a>, Error> {
    let revision = verify(wire, anchor, expected_id, memory_budget)?;
    let record = revision.open(keys, memory_budget)?;
    Ok(OpenedRevision { revision, record })
}

struct BoundedOutput {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl BoundedOutput {
    fn new(limit: usize) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| Error::Allocation)?;
        Ok(Self { bytes, limit })
    }
}
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn compress(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let output = BoundedOutput::new(resources::MAX_COMPRESSED)?;
    let mut encoder = flate2::write::ZlibEncoder::new(output, flate2::Compression::new(6));
    encoder.write_all(bytes).map_err(|_| Error::Limit)?;
    Ok(encoder.finish().map_err(|_| Error::Limit)?.bytes)
}

pub fn compressed_size(record: &record::Record, memory_budget: usize) -> Result<usize, Error> {
    let content = record
        .encode_content(admit(memory_budget)?)
        .map_err(Error::Content)?;
    Ok(compress(&content.bytes)?.len())
}

pub fn seal(
    record: &record::Record,
    keys: &crypto::VaultKeys,
    options: Options<'_>,
    memory_budget: usize,
) -> Result<Vec<u8>, Error> {
    let available = admit(memory_budget)?;
    options.validate(record.entries.is_empty())?;
    let content = record.encode_content(available).map_err(Error::Content)?;
    let h = header::encode(options, &content.value_sizes)?;
    let compressed = compress(&content.bytes)?;
    drop(content);
    let mut seed = Zeroizing::new([0; 32]);
    entropy::fill_random(&mut seed[..]).map_err(Error::Entropy)?;
    let mut rng = chacha20::ChaCha20Rng::from_seed(*seed);
    let c = crypto::seal_record(&keys.secret_key(), &compressed, &h, &mut rng)
        .map_err(Error::Crypto)?;
    let signature = keys.signing_key().sign(&framed(&h, &c)?).to_bytes();
    let mut output = BoundedOutput::new(1 + 5 + h.len() + 5 + c.len() + 2 + 64)?;
    rmp::encode::write_array_len(&mut output, 3).map_err(|_| Error::Invalid)?;
    for value in [h.as_slice(), c.as_slice(), signature.as_slice()] {
        rmp::encode::write_bin_len(&mut output, value.len() as u32).map_err(|_| Error::Invalid)?;
        output.write_all(value).map_err(|_| Error::Invalid)?;
    }
    Ok(std::mem::take(&mut *output.bytes))
}
