//! Directory-sync messages are portable; filesystem operations are native only.
use crate::Error as AppError;
use confidex_storage::{VaultId, VaultInfo};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::{locks, synchronize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    App(AppError),
    Unavailable,
    Canceled,
}
impl From<AppError> for Error {
    fn from(value: AppError) -> Self {
        Self::App(value)
    }
}
impl From<confidex_storage::Error> for Error {
    fn from(value: confidex_storage::Error) -> Self {
        Self::App(value.into())
    }
}
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Report {
    pub downloaded: usize,
    pub uploaded: usize,
    pub pending: usize,
}

#[derive(Serialize, Deserialize)]
pub enum Command {
    Status,
    Configure {
        path: Option<String>,
    },
    Sync,
    Import {
        name: String,
        password: String,
        key: String,
        path: String,
        remember: bool,
    },
}
impl Drop for Command {
    fn drop(&mut self) {
        if let Self::Import { password, key, .. } = self {
            password.zeroize();
            key.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
pub enum Reply {
    State {
        vault: VaultId,
        path: Option<String>,
    },
    Synced {
        vault: VaultId,
        report: Report,
    },
    Opened {
        info: VaultInfo,
        remembered: bool,
        server: Option<String>,
    },
}
