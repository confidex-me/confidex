//! Encrypt the shared JSON stream without retaining a plaintext document.
use super::Kdf;
use crate::{
    export::{self, Error, Output, Records, Review, Sink},
    import::{
        ErrorKind,
        formats::bitwarden_json::{self, Profile},
    },
};
use base64::{Engine, prelude::BASE64_STANDARD, write::EncoderWriter};
use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use confidex_vault::{entropy, record::Record};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    cell::RefCell,
    io::{self, Write},
};
use zeroize::{Zeroize, Zeroizing};

const KDF: Kdf = Kdf {
    kind: 1,
    iterations: 3,
    memory: 64,
    lanes: 4,
};
const CHUNK: usize = 16 << 10;

pub struct Writer {
    json: bitwarden_json::Writer,
    options: export::Options,
}
impl Writer {
    pub fn new(profile: Profile, options: export::Options) -> Result<Self, Error> {
        options.validate(export::Format::BitwardenEncryptedJson)?;
        if !matches!(&options, export::Options::Password { password: Some(text), keyfile: None } if !text.is_empty())
        {
            return Err(Error::InvalidOptions);
        }
        Ok(Self {
            json: bitwarden_json::Writer::new(profile),
            options,
        })
    }
}
impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::BitwardenEncryptedJson
    }
    fn file(&self) -> export::File {
        export::File {
            name: "bitwarden-encrypted.json",
            media_type: "application/json",
            encrypted: true,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        self.json.review(record, review)
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        let export::Options::Password {
            password: Some(password),
            ..
        } = &self.options
        else {
            return Err(Error::InvalidOptions);
        };
        let _credentials = output.reserve(password.capacity())?;
        let _scratch = output.reserve(CHUNK + 4096)?;
        let total = records.len();
        output.checkpoint(0, total)?;
        let mut salt = [0; 16];
        entropy::fill_random(&mut salt).map_err(|_| Error::Writer)?;
        let salt = BASE64_STANDARD.encode(salt);
        let key = KDF
            .derive(password.as_bytes(), salt.as_bytes(), records.memory())
            .map_err(|error| match error.kind {
                ErrorKind::Limit => Error::Limit,
                ErrorKind::Allocation => Error::Allocation,
                _ => Error::Writer,
            })?;
        output.checkpoint(0, total)?;
        write!(
            output,
            "{{\"encrypted\":true,\"passwordProtected\":true,\"salt\":\"{salt}\",\"kdfType\":1,\"kdfIterations\":3,\"kdfMemory\":64,\"kdfParallelism\":4,\"encKeyValidation_DO_NOT_EDIT\":\""
        )?;
        let mut validation = Zeroizing::new([0; 16]);
        entropy::fill_random(&mut *validation).map_err(|_| Error::Writer)?;
        validation[6] = (validation[6] & 0x0f) | 0x40;
        validation[8] = (validation[8] & 0x3f) | 0x80;
        {
            let mut cipher = Cipher::new(&mut *output, &key)?;
            for (index, byte) in validation.iter().enumerate() {
                if matches!(index, 4 | 6 | 8 | 10) {
                    cipher.write_all(b"-")?;
                }
                write!(cipher, "{byte:02x}")?;
            }
            cipher.finish()?;
        }
        output.write_all(b"\",\"data\":\"")?;
        let context = RefCell::new(output);
        let mut cipher = Cipher::new(Sink(&context), &key)?;
        self.json
            .write_to(records, &context, &mut cipher, &[], total)?;
        cipher.finish()?;
        context.borrow_mut().write_all(b"\"}")?;
        context.borrow_mut().checkpoint(total, total)
    }
}

struct Cipher<W: Write> {
    sink: EncoderWriter<'static, base64::engine::GeneralPurpose, W>,
    cipher: cbc::Encryptor<aes::Aes256>,
    mac: Hmac<Sha256>,
    pending: Zeroizing<[u8; CHUNK]>,
    used: usize,
}
impl<W: Write> Cipher<W> {
    fn new(mut sink: W, key: &[u8; 64]) -> Result<Self, Error> {
        let mut iv = [0; 16];
        entropy::fill_random(&mut iv).map_err(|_| Error::Writer)?;
        sink.write_all(b"2.")?;
        write!(sink, "{}|", BASE64_STANDARD.encode(iv))?;
        let cipher = cbc::Encryptor::new_from_slices(&key[..32], &iv).map_err(|_| Error::Writer)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|_| Error::Writer)?;
        mac.update(&iv);
        Ok(Self {
            sink: EncoderWriter::new(sink, &BASE64_STANDARD),
            cipher,
            mac,
            pending: Zeroizing::new([0; CHUNK]),
            used: 0,
        })
    }
    fn finish(mut self) -> Result<(), Error> {
        let bytes = self
            .cipher
            .encrypt_padded::<Pkcs7>(&mut self.pending[..], self.used)
            .map_err(|_| Error::Writer)?;
        self.mac.update(bytes);
        self.sink.write_all(bytes)?;
        let mut sink = self.sink.finish()?;
        write!(
            sink,
            "|{}",
            BASE64_STANDARD.encode(self.mac.finalize().into_bytes())
        )?;
        Ok(())
    }
}
impl<W: Write> Write for Cipher<W> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let size = bytes.len();
        while !bytes.is_empty() {
            let take = (CHUNK - self.used).min(bytes.len());
            self.pending[self.used..self.used + take].copy_from_slice(&bytes[..take]);
            self.used += take;
            bytes = &bytes[take..];
            if self.used == CHUNK {
                for block in self.pending.as_mut_slice().as_chunks_mut::<16>().0 {
                    self.cipher.encrypt_block(block.into());
                }
                self.mac.update(self.pending.as_slice());
                self.sink.write_all(self.pending.as_slice())?;
                self.pending.zeroize();
                self.used = 0;
            }
        }
        Ok(size)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_blocks_and_padding_match_one_shot_at_every_boundary() {
        for size in [
            0,
            1,
            15,
            16,
            17,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            2 * CHUNK + 17,
        ] {
            let input: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            for chunk in [1, 7, CHUNK + 3] {
                let mut encoded = Vec::new();
                let key = [3; 64];
                let mut stream = Cipher::new(&mut encoded, &key).unwrap();
                for bytes in input.chunks(chunk) {
                    stream.write_all(bytes).unwrap();
                }
                stream.finish().unwrap();
                let encoded = std::str::from_utf8(&encoded).unwrap();
                let parts: Vec<_> = encoded.strip_prefix("2.").unwrap().split('|').collect();
                assert_eq!(parts.len(), 3);
                let iv = BASE64_STANDARD.decode(parts[0]).unwrap();
                let actual = BASE64_STANDARD.decode(parts[1]).unwrap();
                let mut expected = input.clone();
                expected.resize(size + 16, 0);
                let expected = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key[..32], &iv)
                    .unwrap()
                    .encrypt_padded::<Pkcs7>(&mut expected, size)
                    .unwrap();
                assert_eq!(&actual, expected);
                let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).unwrap();
                mac.update(&iv);
                mac.update(&actual);
                mac.verify_slice(&BASE64_STANDARD.decode(parts[2]).unwrap())
                    .unwrap();
            }
        }
    }
}
