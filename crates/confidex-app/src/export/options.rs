use super::{Error, Format};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const MAX_PASSWORD: usize = 65536;
pub const MAX_KEYFILE: usize = 1 << 20;
const MAX_CSV_TEXT: usize = 256 << 10;

#[derive(Default, Serialize, Deserialize)]
pub enum Options {
    #[default]
    Plain,
    Bitwarden {
        organization: bool,
        password: Option<String>,
    },
    Password {
        password: Option<String>,
        keyfile: Option<Vec<u8>>,
    },
    Csv(Csv),
}
impl Drop for Options {
    fn drop(&mut self) {
        match self {
            Self::Bitwarden { password, .. } => password.zeroize(),
            Self::Password { password, keyfile } => {
                password.zeroize();
                keyfile.zeroize();
            }
            _ => {}
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Csv {
    pub profile: Option<String>,
    pub delimiter: u8,
    pub header: bool,
    pub columns: Vec<Column>,
}
impl Drop for Csv {
    fn drop(&mut self) {
        self.profile.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub struct Column {
    pub heading: String,
    pub source: Source,
}
impl Drop for Column {
    fn drop(&mut self) {
        self.heading.zeroize();
    }
}
#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source {
    Title,
    Tags,
    Field {
        index: usize,
        type_name: String,
        key: String,
    },
}
impl Drop for Source {
    fn drop(&mut self) {
        if let Self::Field { type_name, key, .. } = self {
            type_name.zeroize();
            key.zeroize();
        }
    }
}
impl Options {
    pub fn keyfile_mut(&mut self) -> Option<&mut Vec<u8>> {
        match self {
            Self::Password {
                keyfile: Some(bytes),
                ..
            } => Some(bytes),
            _ => None,
        }
    }
    pub fn validate(&self, format: Format) -> Result<(), Error> {
        let valid = match (format, self) {
            (
                Format::BitwardenJson
                | Format::Onepassword1pux
                | Format::KeepassXml
                | Format::BitwardenZip,
                Self::Plain,
            ) => true,
            (Format::BitwardenJson, Self::Bitwarden { password: None, .. }) => true,
            (
                Format::BitwardenEncryptedJson,
                Self::Bitwarden {
                    password: Some(password),
                    ..
                },
            ) => !password.is_empty() && password.len() <= MAX_PASSWORD,
            (
                Format::Kdbx | Format::BitwardenEncryptedJson,
                Self::Password { password, keyfile },
            ) => {
                password.as_ref().is_none_or(|text| {
                    text.len()
                        <= if format == Format::Kdbx {
                            4096
                        } else {
                            MAX_PASSWORD
                        }
                }) && keyfile
                    .as_ref()
                    .is_none_or(|bytes| bytes.len() <= MAX_KEYFILE)
                    && (password.is_some() || keyfile.is_some())
                    && (format == Format::Kdbx || (password.is_some() && keyfile.is_none()))
            }
            (Format::Csv, Self::Csv(csv)) => return csv.validate(),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidOptions)
        }
    }
}

impl Csv {
    pub fn validate(&self) -> Result<(), Error> {
        let mut text_bytes = self.profile.as_ref().map_or(0, String::len);
        let mut valid = matches!(self.delimiter, b',' | b';' | b'\t' | b'|')
            && self.columns.len() <= confidex_vault::record::MAX_ENTRIES
            && match &self.profile {
                Some(profile) => {
                    !profile.is_empty() && profile.len() <= 64 && self.columns.is_empty()
                }
                None => !self.columns.is_empty(),
            };
        for column in &self.columns {
            text_bytes = text_bytes.saturating_add(column.heading.len());
            valid &= column.heading.len() <= 4096;
            if let Source::Field {
                index,
                type_name,
                key,
            } = &column.source
            {
                text_bytes = text_bytes
                    .saturating_add(type_name.len())
                    .saturating_add(key.len());
                valid &= *index < confidex_vault::record::MAX_ENTRIES
                    && !type_name.is_empty()
                    && type_name.len() <= 64
                    && !key.is_empty()
                    && key.len() <= 4096;
            }
        }
        if valid && text_bytes <= MAX_CSV_TEXT {
            Ok(())
        } else {
            Err(Error::InvalidOptions)
        }
    }
}
