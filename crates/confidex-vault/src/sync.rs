//! Public sync identity and signed lock bytes. No client secrets cross this boundary.

use sha1::{Digest, Sha1};

pub const LOCK_SIGNATURE_DOMAIN: &[u8] = b"confidex/sync/lock/v1\0";
const OID_NAMESPACE: [u8; 16] = [
    0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
];

/// UUIDv5 uses SHA-1 as specified by RFC 9562, not as a signature hash.
pub fn id(public_key: &[u8; 32]) -> [u8; 16] {
    let mut hash = Sha1::new();
    hash.update(OID_NAMESPACE);
    hash.update(public_key);
    let digest = hash.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 15) | 0x50;
    id[8] = (id[8] & 63) | 0x80;
    id
}

pub fn lock_signature_bytes(wire: &[u8], previous: &str) -> Vec<u8> {
    [
        LOCK_SIGNATURE_DOMAIN,
        &(previous.len() as u64).to_be_bytes(),
        previous.as_bytes(),
        &(wire.len() as u64).to_be_bytes(),
        wire,
    ]
    .concat()
}
