use crate::Field;
use confidex_vault::ssh::{self, Key};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(test)]
mod tests;

pub const MAX_KEY: usize = ssh::MAX_KEY;
pub const ROWS: &[&str] = &["public_key", "fingerprint", "private_key", "key_type"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    Limit,
    Invalid,
    Unsupported,
    PassphraseRequired,
    Authentication,
}
impl From<ssh::Error> for Error {
    fn from(error: ssh::Error) -> Self {
        match error {
            ssh::Error::Limit => Self::Limit,
            ssh::Error::Unsupported => Self::Unsupported,
            ssh::Error::PassphraseRequired => Self::PassphraseRequired,
            ssh::Error::Authentication => Self::Authentication,
            ssh::Error::Invalid | ssh::Error::Signature => Self::Invalid,
        }
    }
}

fn values(key: &Key) -> Result<BTreeMap<String, String>, Error> {
    let public = key.public_text()?;
    let mut private = key.private_text()?;
    Ok([
        ("public_key", public),
        ("fingerprint", key.fingerprint()),
        ("private_key", std::mem::take(&mut *private)),
        ("key_type", key.key_type().into()),
    ]
    .into_iter()
    .map(|(name, value)| (name.into(), value))
    .collect())
}

pub(crate) fn read(data: &[u8]) -> Result<BTreeMap<String, String>, Error> {
    let mut record = confidex_vault::record::Record::default();
    record.extra.insert(
        "private_key".into(),
        confidex_vault::record::Value::Binary(data.to_vec()),
    );
    values(&Key::from_value(&record.extra, ssh::REQUIRED_MEMORY)?)
}

pub fn import(data: &[u8], password: Option<&str>) -> Result<Field, Error> {
    let key = Key::import(data, password.map(str::as_bytes), ssh::REQUIRED_MEMORY)?;
    let mut field = crate::field("ssh/v1").map_err(|_| Error::Invalid)?;
    field.values = values(&key)?;
    let mut value = key.to_value()?;
    let Some(confidex_vault::record::Value::Binary(bytes)) = value.remove("private_key") else {
        return Err(Error::Invalid);
    };
    field.data = Some(bytes.into());
    Ok(field)
}
