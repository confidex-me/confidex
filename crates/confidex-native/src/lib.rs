//! Native storage, device credentials, and optional sync transport shared by clients.
use confidex_storage::SqliteStore;
use std::path::{Path, PathBuf};

mod device_keys;
#[cfg(target_os = "macos")]
pub use device_keys::TouchIdKeys;
pub use device_keys::{Credentials, DeviceKeyError, load_key};

#[cfg(feature = "sync")]
pub mod sync_transport;

pub fn database_path() -> Result<PathBuf, std::io::Error> {
    directories::ProjectDirs::from("dev", "Confidex", "ConfidexPrototype")
        .map(|dirs| dirs.data_local_dir().join("vaults.sqlite"))
        .ok_or_else(|| std::io::Error::other("data directory unavailable"))
}

pub fn open_store(path: &Path) -> Result<SqliteStore, confidex_storage::Error> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory).map_err(|_| confidex_storage::Error::Storage)?;
    SqliteStore::open(path)
}
