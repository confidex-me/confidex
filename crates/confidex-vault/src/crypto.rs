use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub type VaultKem = hpke::kem::X25519HkdfSha256;
pub const DERIVATION_VERSION: u8 = 1;
pub const SIGNING_SALT: &[u8] = b"confidex/vault/extract/v1";
pub const SIGNING_INFO: &[u8] = b"confidex/vault/ed25519/v1";
pub const RECORD_INFO: &[u8] = b"confidex/record/hpke/v1";
pub const LOCK_SALT: &[u8] = b"confidex/lock/extract/v1";
pub const LOCK_INFO: &[u8] = b"confidex/lock/wrap/v1";
pub const LOCK_AAD_DOMAIN: &[u8] = b"confidex/lock/aad/v1";
pub const RECORD_SIGNATURE_DOMAIN: &[u8] = b"confidex/record/sign/v1";
pub const REVISION_ID_DOMAIN: &[u8] = b"confidex/revision/id/v1";

pub fn revision_id(header: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(REVISION_ID_DOMAIN);
    hash.update((header.len() as u64).to_be_bytes());
    hash.update(header);
    hash.update((ciphertext.len() as u64).to_be_bytes());
    hash.update(ciphertext);
    hash.finalize().into()
}

pub fn signed_record_bytes(header: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    [
        RECORD_SIGNATURE_DOMAIN,
        &(header.len() as u64).to_be_bytes(),
        header,
        &(ciphertext.len() as u64).to_be_bytes(),
        ciphertext,
    ]
    .concat()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidMaterial,
    UnsupportedVersion,
    InvalidCiphertext,
    Authentication,
}

pub struct VaultKeys {
    material: Zeroizing<[u8; 32]>,
    signing: SigningKey,
}

pub fn clamp_material(mut entropy: [u8; 32]) -> Zeroizing<[u8; 32]> {
    entropy[0] &= 248;
    entropy[31] = (entropy[31] & 127) | 64;
    Zeroizing::new(entropy)
}

impl VaultKeys {
    pub fn from_material(version: u8, material: &[u8]) -> Result<Self, Error> {
        if version != DERIVATION_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if material.len() != 32 || material[0] & 7 != 0 || material[31] & 192 != 64 {
            return Err(Error::InvalidMaterial);
        }
        let mut bytes = Zeroizing::new([0; 32]);
        bytes.copy_from_slice(material);
        let mut seed = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(SIGNING_SALT), &bytes[..])
            .expand(SIGNING_INFO, &mut seed[..])
            .expect("32 bytes fit the HKDF output limit");
        Ok(Self {
            material: bytes,
            signing: SigningKey::from_bytes(&seed),
        })
    }

    fn private_key(&self) -> <VaultKem as Kem>::PrivateKey {
        <VaultKem as Kem>::PrivateKey::from_bytes(&self.material[..])
            .expect("the material has 32 bytes")
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn secret_key(&self) -> Zeroizing<[u8; 32]> {
        let mut bytes = Zeroizing::new([0; 32]);
        VaultKem::sk_to_pk(&self.private_key()).write_exact(&mut bytes[..]);
        bytes
    }

    pub fn lock_plaintext(&self) -> Zeroizing<[u8; 33]> {
        let mut bytes = Zeroizing::new([0; 33]);
        bytes[0] = DERIVATION_VERSION;
        bytes[1..].copy_from_slice(&self.material[..]);
        bytes
    }

    pub fn open_record(&self, packet: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if packet.len() < 48 {
            return Err(Error::InvalidCiphertext);
        }
        let enc = <VaultKem as Kem>::EncappedKey::from_bytes(&packet[..32])
            .map_err(|_| Error::InvalidCiphertext)?;
        hpke::single_shot_open::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, VaultKem>(
            &OpModeR::Base,
            &self.private_key(),
            &enc,
            RECORD_INFO,
            &packet[32..],
            aad,
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
    }
}

pub fn seal_record(
    secret_key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut impl hpke::rand_core::CryptoRng,
) -> Result<Vec<u8>, Error> {
    let public =
        <VaultKem as Kem>::PublicKey::from_bytes(secret_key).map_err(|_| Error::InvalidMaterial)?;
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<
        hpke::aead::ChaCha20Poly1305,
        hpke::kdf::HkdfSha256,
        VaultKem,
    >(&OpModeS::Base, &public, RECORD_INFO, plaintext, aad, rng)
    .map_err(|_| Error::Authentication)?;
    let mut packet = Vec::with_capacity(32 + ciphertext.len());
    packet.extend_from_slice(&enc.to_bytes());
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

pub fn lock_key(password_key: &[u8; 32], secret_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0; 64]);
    ikm[..32].copy_from_slice(secret_key);
    ikm[32..].copy_from_slice(password_key);
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(LOCK_SALT), &ikm[..])
        .expand(LOCK_INFO, &mut key[..])
        .expect("32 bytes fit the HKDF output limit");
    key
}

fn lock_aad(header: &[u8]) -> Vec<u8> {
    [LOCK_AAD_DOMAIN, header].concat()
}

pub fn seal_lock(
    keys: &VaultKeys,
    password_key: &[u8; 32],
    secret_key: &[u8; 32],
    nonce: &[u8; 24],
    header: &[u8],
) -> Result<Vec<u8>, Error> {
    if !bool::from(keys.secret_key().ct_eq(secret_key)) {
        return Err(Error::Authentication);
    }
    let key = lock_key(password_key, secret_key);
    let plaintext = keys.lock_plaintext();
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: &plaintext[..],
                aad: &lock_aad(header),
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok([nonce.as_slice(), &ciphertext].concat())
}

pub fn open_lock(
    password_key: &[u8; 32],
    secret_key: &[u8; 32],
    packet: &[u8],
    header: &[u8],
) -> Result<VaultKeys, Error> {
    open_lock_with_key(
        &lock_key(password_key, secret_key),
        secret_key,
        packet,
        header,
    )
}

pub(crate) fn open_lock_with_key(
    key: &[u8; 32],
    secret_key: &[u8; 32],
    packet: &[u8],
    header: &[u8],
) -> Result<VaultKeys, Error> {
    if packet.len() != 73 {
        return Err(Error::InvalidCiphertext);
    }
    let nonce: &[u8; 24] = packet[..24]
        .try_into()
        .map_err(|_| Error::InvalidCiphertext)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                nonce.into(),
                Payload {
                    msg: &packet[24..],
                    aad: &lock_aad(header),
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let keys = VaultKeys::from_material(plaintext[0], &plaintext[1..])?;
    if !bool::from(keys.secret_key().ct_eq(secret_key)) {
        return Err(Error::Authentication);
    }
    Ok(keys)
}
