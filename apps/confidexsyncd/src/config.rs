use crate::{native::Blobs, s3::S3};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub index: IndexConfig,
    pub listen: Listen,
    pub backend: Backends,
    #[serde(default)]
    pub limits: crate::Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexConfig {
    pub url: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    pub address: IpAddr,
    pub port: u16,
}
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Backends {
    pub posix: Vec<PathConfig>,
    pub git: Vec<PathConfig>,
    pub s3: Vec<S3Config>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathConfig {
    pub path: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    pub url: String,
    pub access_key: String,
    pub secret_key: String,
}
impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let names: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
        let mut backend = Backends::default();
        for (kind, prefix) in [
            ("posix", "BACKEND_POSIX_"),
            ("git", "BACKEND_GIT_"),
            ("s3", "BACKEND_S3_"),
        ] {
            for i in crate::s3::sections(names.clone(), prefix)
                .map_err(|_| "Invalid backend section suffix")?
            {
                let get = |field: &str| std::env::var(format!("{prefix}{field}_{i}"));
                match kind {
                    "posix" => backend.posix.push(PathConfig {
                        path: get("PATH")?.into(),
                    }),
                    "git" => backend.git.push(PathConfig {
                        path: get("PATH")?.into(),
                    }),
                    _ => backend.s3.push(S3Config {
                        url: get("URL")?,
                        access_key: get("ACCESS_KEY")?,
                        secret_key: get("SECRET_KEY")?,
                    }),
                }
            }
        }
        Ok(Self {
            limits: crate::Limits::from_env(std::env::var("LIMITS_BODY_BYTES").ok())
                .map_err(|_| "LIMITS_BODY_BYTES must be between 1 and 8000000")?,
            index: IndexConfig {
                url: std::env::var("INDEX_URL").unwrap_or_else(|_| "confidexsyncd.sqlite".into()),
            },
            listen: Listen {
                address: std::env::var("LISTEN_ADDRESS")
                    .unwrap_or_else(|_| "127.0.0.1".into())
                    .parse()?,
                port: std::env::var("LISTEN_PORT")
                    .unwrap_or_else(|_| "8080".into())
                    .parse()?,
            },
            backend,
        })
    }
    pub fn socket(&self) -> SocketAddr {
        SocketAddr::new(self.listen.address, self.listen.port)
    }
    pub fn destinations(self) -> crate::Result<Vec<Blobs>> {
        let mut destinations = Vec::new();
        for c in self.backend.posix {
            destinations.push(Blobs::posix(c.path)?);
        }
        for c in self.backend.git {
            destinations.push(Blobs::git(c.path)?);
        }
        for c in self.backend.s3 {
            destinations.push(Blobs::s3(S3::from_url(
                &c.url,
                c.access_key,
                c.secret_key,
            )?)?);
        }
        if destinations.is_empty() {
            return Err(crate::Error::Storage);
        }
        Ok(destinations)
    }
}
