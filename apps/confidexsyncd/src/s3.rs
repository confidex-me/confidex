use crate::{Error, Result};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::time::Duration;

pub struct S3 {
    bucket: Bucket,
    credentials: Credentials,
}
impl S3 {
    pub fn from_env(index: usize, mut get: impl FnMut(&str) -> Result<String>) -> Result<Self> {
        Self::from_url(
            &get(&format!("BACKEND_S3_URL_{index}"))?,
            get(&format!("BACKEND_S3_ACCESS_KEY_{index}"))?,
            get(&format!("BACKEND_S3_SECRET_KEY_{index}"))?,
        )
    }
    pub fn from_url(value: &str, key: String, secret: String) -> Result<Self> {
        let mut url = url::Url::parse(value).map_err(|_| Error::Storage)?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(Error::Storage);
        }
        let pairs: Vec<_> = url.query_pairs().collect();
        if pairs.len() > 1 || pairs.iter().any(|(k, v)| k != "region" || v.is_empty()) {
            return Err(Error::Storage);
        }
        let region = pairs
            .first()
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| "auto".to_owned());
        let bucket = url
            .path_segments()
            .and_then(|mut s| s.next_back())
            .filter(|s| !s.is_empty())
            .ok_or(Error::Storage)?
            .to_owned();
        if !bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
            || bucket == "."
            || bucket == ".."
        {
            return Err(Error::Storage);
        }
        url.set_query(None);
        url.path_segments_mut().map_err(|_| Error::Storage)?.pop();
        Self::new(url.as_str(), bucket, region, key, secret)
    }
    pub fn new(
        endpoint: &str,
        bucket: String,
        region: String,
        key: String,
        secret: String,
    ) -> Result<Self> {
        let bucket = Bucket::new(
            endpoint.parse().map_err(|_| Error::Storage)?,
            UrlStyle::Path,
            bucket,
            region,
        )
        .map_err(|_| Error::Storage)?;
        Ok(Self {
            bucket,
            credentials: Credentials::new(key, secret),
        })
    }
    pub fn url(&self, blob: crate::storage::BlobRef<'_>, put: bool) -> Result<String> {
        let key = blob.digest;
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Storage);
        }
        let vault = uuid::Uuid::parse_str(blob.vault).map_err(|_| Error::Storage)?;
        if vault.to_string() != blob.vault {
            return Err(Error::Storage);
        }
        let hex = vault.simple().to_string();
        let vault = format!("{}/{}/{vault}", &hex[..2], &hex[2..4]);
        let key = if blob.lock {
            format!("{vault}/locks/{key}.sealed")
        } else {
            format!("{vault}/{}/{}/{}", &key[..2], &key[2..4], &key[4..])
        };
        let duration = Duration::from_secs(60);
        Ok(if put {
            self.bucket
                .put_object(Some(&self.credentials), &key)
                .sign(duration)
                .to_string()
        } else {
            self.bucket
                .get_object(Some(&self.credentials), &key)
                .sign(duration)
                .to_string()
        })
    }
}

pub fn sections(names: impl IntoIterator<Item = String>, prefix: &str) -> Result<Vec<usize>> {
    let mut indices = std::collections::BTreeSet::new();
    for name in names {
        if let Some(rest) = name.strip_prefix(prefix) {
            let (_, index) = rest.rsplit_once('_').ok_or(Error::Storage)?;
            indices.insert(index.parse().map_err(|_| Error::Storage)?);
        }
    }
    Ok(indices.into_iter().collect())
}
