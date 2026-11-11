use super::{Error, Format, Options, Writer};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
pub struct FormatInfo {
    pub format: Format,
    pub label: String,
}

pub fn catalog() -> Vec<FormatInfo> {
    #[cfg(feature = "export-check")]
    return check::catalog();
    #[cfg(not(feature = "export-check"))]
    vec![
        FormatInfo {
            format: Format::BitwardenJson,
            label: "Bitwarden JSON".into(),
        },
        FormatInfo {
            format: Format::Kdbx,
            label: "KeePass KDBX".into(),
        },
        FormatInfo {
            format: Format::BitwardenEncryptedJson,
            label: "Bitwarden JSON (password-protected)".into(),
        },
        FormatInfo {
            format: Format::BitwardenZip,
            label: "Bitwarden ZIP".into(),
        },
        FormatInfo {
            format: Format::KeepassXml,
            label: "KeePass XML".into(),
        },
        FormatInfo {
            format: Format::Onepassword1pux,
            label: "1Password 1PUX".into(),
        },
    ]
}
pub fn writer(format: Format, options: Options, created_at: u64) -> Result<Box<dyn Writer>, Error> {
    options.validate(format)?;
    if created_at > 253_402_300_799 {
        return Err(Error::InvalidOptions);
    }
    #[cfg(feature = "export-check")]
    return check::writer(format, options);
    #[cfg(not(feature = "export-check"))]
    match format {
        Format::Csv => {
            let mut options = options;
            let Options::Csv(config) = &mut options else {
                return Err(Error::InvalidOptions);
            };
            Ok(Box::new(crate::import::formats::csv::Writer::new(
                super::Csv {
                    profile: config.profile.take(),
                    delimiter: config.delimiter,
                    header: config.header,
                    columns: std::mem::take(&mut config.columns),
                },
            )?))
        }
        Format::BitwardenZip => Ok(Box::new(
            crate::import::formats::bitwarden_zip::Writer::new()?,
        )),
        Format::KeepassXml => Ok(Box::new(crate::import::formats::keepass_xml::Writer::new(
            created_at,
        )?)),
        Format::Onepassword1pux => Ok(Box::new(
            crate::import::formats::onepassword_1pux::Writer::new(created_at)?,
        )),
        Format::Kdbx => Ok(Box::new(crate::import::formats::kdbx::Writer::new(
            created_at, options,
        )?)),
        Format::BitwardenJson | Format::BitwardenEncryptedJson => {
            use crate::import::formats::bitwarden_json::{Profile, Writer};
            let profile = match &options {
                Options::Bitwarden {
                    organization: true, ..
                } => Profile::Organization,
                _ => Profile::Personal,
            };
            if format == Format::BitwardenJson {
                Ok(Box::new(Writer::new(profile)))
            } else {
                let mut options = options;
                let credentials = match &mut options {
                    Options::Bitwarden { password, .. } => Options::Password {
                        password: password.take(),
                        keyfile: None,
                    },
                    _ => options,
                };
                Ok(Box::new(
                    crate::import::formats::bitwarden_encrypted_json::Writer::new(
                        profile,
                        credentials,
                    )?,
                ))
            }
        }
    }
}
#[cfg(feature = "export-check")]
mod check {
    use super::*;
    use std::io::Write;
    pub fn catalog() -> Vec<FormatInfo> {
        [
            (Format::KeepassXml, "Synthetic binary — public test only"),
            (
                Format::BitwardenJson,
                "Synthetic blocked — public test only",
            ),
            (Format::Kdbx, "Synthetic credentials — public test only"),
        ]
        .into_iter()
        .map(|(format, label)| FormatInfo {
            format,
            label: label.into(),
        })
        .collect()
    }
    pub fn writer(format: Format, options: Options) -> Result<Box<dyn Writer>, Error> {
        if !catalog().iter().any(|info| info.format == format) {
            return Err(Error::UnsupportedFormat);
        }
        Ok(Box::new(Check {
            format,
            _options: options,
        }))
    }
    struct Check {
        format: Format,
        _options: Options,
    }
    impl Writer for Check {
        fn format(&self) -> Format {
            self.format
        }
        fn file(&self) -> super::super::File {
            super::super::File {
                name: "public-synthetic-export.bin",
                media_type: "application/octet-stream",
                encrypted: false,
            }
        }
        fn review(
            &self,
            record: &confidex_vault::record::Record,
            review: &mut super::super::Review<'_>,
        ) -> Result<(), Error> {
            for index in 0..record.entries.len() {
                if self.format == Format::BitwardenJson {
                    review.issue(
                        Some(index),
                        super::super::Severity::Blocked,
                        super::super::Code::UnsupportedField,
                    )?;
                } else if index == 0
                    && record
                        .extra
                        .get("export-ui-loss")
                        .and_then(|value| value.as_bool())
                        == Some(true)
                {
                    // The public UI fixture opts into a synthetic loss report.
                    review.issue(
                        Some(index),
                        super::super::Severity::Loss,
                        super::super::Code::Protection,
                    )?;
                } else {
                    review.preserved(index)?;
                }
            }
            review.tags();
            review.metadata();
            Ok(())
        }
        fn write(
            &self,
            records: &super::super::Records,
            output: &mut super::super::Output<'_>,
        ) -> Result<(), Error> {
            for (index, record) in records.iter().enumerate() {
                output.checkpoint(index, records.len())?;
                let _scratch = output.reserve(16 << 20)?;
                let bytes = record.encode_content(16 << 20).map_err(|_| Error::Limit)?;
                output.write_all(&(bytes.bytes.len() as u32).to_le_bytes())?;
                output.write_all(&bytes.bytes)?;
            }
            Ok(())
        }
    }
}
