//! Seal the shared KeePass XML mapping through the bounded library writer.
use super::super::keepass_xml::{
    self,
    writer::{base64, blob},
};
use crate::export::{self, Error, Output, Records, Review, Sink};
use confidex_vault::record::Record;
use keepass::{
    bounded::{self, Binary, SaveError, SaveEvent},
    config::{CompressionConfig, DatabaseConfig, KdfConfig},
};
use std::{
    cell::{Cell, RefCell},
    fmt,
};
use zeroize::Zeroizing;

pub struct Writer {
    xml: keepass_xml::Writer,
    options: export::Options,
}
impl Writer {
    /// Write KDBX4.1 using explicit password/keyfile presence and bounded Argon2id.
    pub fn new(created_at: u64, options: export::Options) -> Result<Self, Error> {
        options.validate(export::Format::Kdbx)?;
        if matches!(&options, export::Options::Password { keyfile: Some(bytes), .. } if bytes.is_empty())
        {
            return Err(Error::InvalidOptions);
        }
        Ok(Self {
            xml: keepass_xml::Writer::new(created_at)?,
            options,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    #[test]
    fn protected_formatting_never_grows_beyond_its_admitted_capacity() {
        let mut bytes = Zeroizing::new(String::with_capacity(4));
        let mut text = Text {
            bytes: &mut bytes,
            maximum: 4,
        };
        text.write_str("AB").unwrap();
        assert!(text.write_str("CDE").is_err());
        assert_eq!(bytes.as_str(), "AB");
    }
}
fn library_error(error: SaveError) -> Error {
    match error {
        SaveError::Boundary(bounded::Error::Limit | bounded::Error::KdfLimit) => Error::Limit,
        SaveError::Boundary(bounded::Error::Allocation) => Error::Allocation,
        SaveError::Boundary(bounded::Error::Canceled) => Error::Canceled,
        SaveError::Boundary(bounded::Error::Credentials) => Error::InvalidOptions,
        SaveError::Boundary(bounded::Error::Unsupported) => Error::UnsupportedFormat,
        _ => Error::Writer,
    }
}
struct Text<'a> {
    bytes: &'a mut String,
    maximum: usize,
}
impl fmt::Write for Text<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self
            .bytes
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.maximum)
        {
            return Err(fmt::Error);
        }
        self.bytes.push_str(value);
        Ok(())
    }
}
impl export::Writer for Writer {
    fn format(&self) -> export::Format {
        export::Format::Kdbx
    }
    fn file(&self) -> export::File {
        export::File {
            name: "confidex.kdbx",
            media_type: "application/x-keepass2",
            encrypted: true,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        self.xml.review_with(record, review, true)
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        let export::Options::Password { password, keyfile } = &self.options else {
            return Err(Error::InvalidOptions);
        };
        let _credentials = output.reserve(
            password
                .as_ref()
                .map_or(0, String::capacity)
                .checked_add(keyfile.as_ref().map_or(0, Vec::capacity))
                .ok_or(Error::Limit)?,
        )?;
        let mut work = output.reserve(0)?;
        let limit = output.limit();
        output.checkpoint(0, records.len() + 2)?;
        let context = RefCell::new(output);
        let failure = Cell::new(None);
        let mut config = DatabaseConfig::default();
        config.compression_config = CompressionConfig::None;
        config.kdf_config = KdfConfig::Argon2id {
            memory: 64 << 20,
            iterations: 3,
            parallelism: 1,
            version: argon2::Version::V0x13,
        };
        let binaries = records.iter().flat_map(|r| &r.entries).filter_map(|entry| {
            blob(entry).map(|(_, bytes)| Binary {
                bytes,
                protected: crate::field_protected(entry),
            })
        });
        let result = bounded::save(
            &config,
            (password.as_deref(), keyfile.as_deref()),
            bounded::Limits {
                input_bytes: limit,
                ..bounded::Limits::default()
            },
            &mut Sink(&context),
            binaries,
            |encoder, destination| {
                let result = self.xml.write_to(
                    records,
                    destination,
                    &mut |current, total| context.borrow_mut().checkpoint(current + 1, total + 2),
                    &|bytes| context.borrow().reserve(bytes),
                    Some(&mut |destination, text, maximum| {
                        let _memory = context
                            .borrow()
                            .reserve(maximum.checked_add(4096).ok_or(Error::Limit)?)?;
                        let mut bytes = Zeroizing::new(String::new());
                        bytes
                            .try_reserve_exact(maximum)
                            .map_err(|_| Error::Allocation)?;
                        fmt::write(
                            &mut Text {
                                bytes: &mut bytes,
                                maximum,
                            },
                            text,
                        )
                        .map_err(|_| Error::Writer)?;
                        let encrypted = encoder
                            .encrypt(bytes.as_bytes())
                            .map_err(|error| library_error(error.into()))?;
                        base64(destination, &encrypted)
                    }),
                );
                result.map_err(|error| {
                    if failure.get().is_none() {
                        failure.set(Some(error));
                    }
                    std::io::Error::from(std::io::ErrorKind::Other)
                })
            },
            &mut |event| {
                if let SaveEvent::Memory(bytes) = event
                    && work.resize(bytes).is_err()
                    && failure.get().is_none()
                {
                    failure.set(Some(Error::Limit));
                }
                if failure.get().is_none()
                    && let Err(error) = context.borrow_mut().poll()
                {
                    failure.set(Some(error));
                }
                failure.get().is_none()
            },
        );
        if let Some(error) = failure.get() {
            return Err(error);
        }
        result.map_err(library_error)?;
        context
            .borrow_mut()
            .checkpoint(records.len() + 2, records.len() + 2)
    }
}
