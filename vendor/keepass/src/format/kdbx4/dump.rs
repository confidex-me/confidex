use std::convert::TryFrom;
use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

use crate::{
    crypt,
    db::{Database, DatabaseSaveError, Value},
    format::{
        hmac_block_stream,
        io::WriteLengthTaggedExt,
        kdbx4::{
            KDBX4InnerHeader, KDBX4OuterHeader, HEADER_COMPRESSION_ID, HEADER_ENCRYPTION_IV,
            HEADER_END, HEADER_KDF_PARAMS, HEADER_MASTER_SEED, HEADER_MASTER_SEED_SIZE,
            HEADER_OUTER_ENCRYPTION_ID, INNER_HEADER_BINARY_ATTACHMENTS, INNER_HEADER_END,
            INNER_HEADER_RANDOM_STREAM_ID, INNER_HEADER_RANDOM_STREAM_KEY,
        },
        variant_dictionary::VariantDictionary,
        DatabaseVersion,
    },
    key::DatabaseKey,
};

use super::HEADER_PUBLIC_CUSTOM_DATA;
use crate::{
    bounded::Limits,
    config::{DatabaseConfig, OuterCipherConfig},
    crypt::ciphers::Cipher,
};
use hybrid_array::{
    typenum::{U32, U64},
    Array,
};
use zeroize::Zeroizing;

/// Prepared library keys and header, shared by model and bounded serializers.
pub(crate) struct Prepared {
    pub(crate) inner_cipher: Box<dyn Cipher>,
    pub(crate) inner_header: KDBX4InnerHeader,
    cipher: OuterCipherConfig,
    iv: Vec<u8>,
    master: Zeroizing<Array<u8, U32>>,
    hmac: Zeroizing<Array<u8, U64>>,
    header: Vec<u8>,
}
impl Prepared {
    pub(crate) fn new(
        config: &DatabaseConfig,
        db_key: &DatabaseKey,
        limits: &Limits,
        check: &mut dyn FnMut(u64) -> bool,
    ) -> Result<Self, DatabaseSaveError> {
        if !matches!(config.version, DatabaseVersion::KDB4(1)) {
            return Err(DatabaseSaveError::UnsupportedVersion);
        }
        let mut master_seed = vec![0; HEADER_MASTER_SEED_SIZE];
        getrandom::fill(&mut master_seed)?;
        let mut outer_iv = vec![0; config.outer_cipher_config.get_iv_size()];
        getrandom::fill(&mut outer_iv)?;
        let mut inner_key = Zeroizing::new(vec![0; config.inner_cipher_config.get_key_size()]);
        getrandom::fill(&mut inner_key)?;
        let (kdf, kdf_seed) = config.kdf_config.get_kdf_and_seed()?;
        limits
            .admit_kdf(&config.kdf_config, &kdf_seed)
            .map_err(crypt::CryptographyError::from)?;
        #[cfg(feature = "challenge_response")]
        let db_key = db_key.clone().perform_challenge(&kdf_seed)?;
        let mut header = Vec::new();
        config.version.dump(&mut header)?;
        KDBX4OuterHeader {
            outer_cipher_config: config.outer_cipher_config.clone(),
            compression_config: config.compression_config.clone(),
            master_seed: master_seed.clone(),
            outer_iv: outer_iv.clone(),
            kdf_config: config.kdf_config.clone(),
            kdf_seed,
            public_custom_data: config.public_custom_data.clone(),
        }
        .dump(&mut header)?;
        if header.len() > limits.header_bytes {
            return Err(crypt::CryptographyError::from(crate::bounded::Error::Limit).into());
        }
        let sha = crypt::calculate_sha256(&[&header]);
        let elements = db_key.get_key_elements()?;
        let borrowed: Vec<&[u8]> = elements.iter().map(|element| element.as_slice()).collect();
        let composite = Zeroizing::new(crypt::calculate_sha256(&borrowed));
        let transformed = Zeroizing::new(kdf.transform_key_checked(&composite, limits, check)?);
        let master = Zeroizing::new(crypt::calculate_sha256(&[
            &master_seed,
            transformed.as_slice(),
        ]));
        let hmac = Zeroizing::new(crypt::calculate_sha512(&[
            &master_seed,
            transformed.as_slice(),
            &hmac_block_stream::HMAC_KEY_END,
        ]));
        let header_key = Zeroizing::new(hmac_block_stream::get_hmac_block_key(u64::MAX, &hmac));
        let mac = crypt::calculate_hmac(&[&header], &header_key)
            .map_err(crypt::CryptographyError::from)?;
        header.extend_from_slice(&sha);
        header.extend_from_slice(&mac);
        let inner_cipher = config.inner_cipher_config.get_cipher(&inner_key)?;
        Ok(Self {
            inner_cipher,
            inner_header: KDBX4InnerHeader {
                inner_random_stream: config.inner_cipher_config.clone(),
                inner_random_stream_key: std::mem::take(&mut *inner_key),
            },
            cipher: config.outer_cipher_config.clone(),
            iv: outer_iv,
            master,
            hmac,
            header,
        })
    }
    pub(crate) fn encrypted_length(&self, length: usize) -> Result<usize, crate::bounded::Error> {
        match self.cipher {
            OuterCipherConfig::ChaCha20 => Ok(length),
            _ => length
                .checked_add(16)
                .map(|n| n / 16 * 16)
                .ok_or(crate::bounded::Error::Limit),
        }
    }
    pub(crate) fn encrypt(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, DatabaseSaveError> {
        Ok(Zeroizing::new(
            self.cipher
                .get_cipher(&self.master, &self.iv)?
                .encrypt(bytes)?,
        ))
    }
    pub(crate) fn output_length(&self, encrypted: usize) -> Option<usize> {
        encrypted
            .checked_add(encrypted.div_ceil(65_536).checked_add(1)?.checked_mul(36)?)?
            .checked_add(self.header.len())
    }
    pub(crate) fn finish(
        &self,
        encrypted: &[u8],
        output: &mut dyn Write,
    ) -> Result<(), DatabaseSaveError> {
        output.write_all(&self.header)?;
        hmac_block_stream::write_hmac_block_stream_to(encrypted, &self.hmac, output)?;
        Ok(())
    }
}

/// Dump a KeePass database using the key elements.
pub fn dump_kdbx4(
    db: &Database,
    db_key: &DatabaseKey,
    writer: &mut dyn Write,
) -> Result<(), DatabaseSaveError> {
    let mut prepared = Prepared::new(&db.config, db_key, &Limits::default(), &mut |_| true)?;
    let (xml, attachments) = crate::format::xml_db::to_xml(db, &mut *prepared.inner_cipher)?;
    let xml = Zeroizing::new(xml);
    let mut payload = Zeroizing::new(Vec::new());
    prepared.inner_header.dump(&attachments, &mut *payload)?;
    payload.extend_from_slice(&xml);
    let compressed = Zeroizing::new(
        db.config
            .compression_config
            .get_compression()
            .compress(&payload)?,
    );
    let encrypted = prepared.encrypt(&compressed)?;
    prepared.finish(&encrypted, writer)
}

impl KDBX4OuterHeader {
    fn dump(&self, writer: &mut dyn Write) -> Result<(), DatabaseSaveError> {
        writer.write_u8(HEADER_OUTER_ENCRYPTION_ID)?;
        writer.write_with_len(&self.outer_cipher_config.dump())?;

        writer.write_u8(HEADER_COMPRESSION_ID)?;
        writer.write_with_len(&self.compression_config.dump())?;

        writer.write_u8(HEADER_ENCRYPTION_IV)?;
        writer.write_with_len(&self.outer_iv)?;

        writer.write_u8(HEADER_MASTER_SEED)?;
        writer.write_with_len(&self.master_seed)?;

        let vd: VariantDictionary = self.kdf_config.to_variant_dictionary(&self.kdf_seed);
        let mut vd_buffer = Vec::new();
        vd.dump(&mut vd_buffer)?;

        writer.write_u8(HEADER_KDF_PARAMS)?;
        writer.write_with_len(&vd_buffer)?;

        if let Some(pcd) = &self.public_custom_data {
            let mut vd_buffer = Vec::new();
            pcd.dump(&mut vd_buffer)?;

            writer.write_u8(HEADER_PUBLIC_CUSTOM_DATA)?;
            writer.write_with_len(&vd_buffer)?;
        }

        writer.write_u8(HEADER_END)?;
        writer.write_with_len(b"\r\n\r\n")?;

        Ok(())
    }
}

impl KDBX4InnerHeader {
    fn dump(
        &self,
        header_attachments: &[Value<Vec<u8>>],
        writer: &mut dyn Write,
    ) -> Result<(), DatabaseSaveError> {
        self.dump_binaries(
            header_attachments
                .iter()
                .map(|data| crate::bounded::Binary {
                    bytes: data.get(),
                    protected: data.is_protected(),
                }),
            writer,
        )
    }
    pub(crate) fn dump_binaries<'a>(
        &self,
        binaries: impl IntoIterator<Item = crate::bounded::Binary<'a>>,
        writer: &mut dyn Write,
    ) -> Result<(), DatabaseSaveError> {
        writer.write_all(&[INNER_HEADER_RANDOM_STREAM_ID])?;
        writer.write_u32::<LittleEndian>(4)?;
        writer.write_u32::<LittleEndian>(self.inner_random_stream.dump())?;

        writer.write_u8(INNER_HEADER_RANDOM_STREAM_KEY)?;
        writer.write_with_len(&self.inner_random_stream_key)?;

        for attachment in binaries {
            writer.write_u8(INNER_HEADER_BINARY_ATTACHMENTS)?;
            let length = attachment
                .bytes
                .len()
                .checked_add(1)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::FileTooLarge))?;
            writer.write_u32::<LittleEndian>(length)?;
            writer.write_u8(if attachment.protected { 0x01 } else { 0x00 })?;
            for chunk in attachment.bytes.chunks(65_536) {
                writer.write_all(chunk)?;
            }
        }

        writer.write_u8(INNER_HEADER_END)?;
        writer.write_with_len(&[])?;

        Ok(())
    }
}
