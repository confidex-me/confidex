#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{Protector, Store};
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{Protector, Store};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Protector, Store};
#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::{Protector, Store, attach_passkey_host};

#[cfg(target_os = "windows")]
pub(crate) fn key_lock(namespace: &str) -> crate::Result<std::fs::File> {
    use std::fs::{self, OpenOptions};
    let root = directories::ProjectDirs::from("dev", "Confidex", "DeviceSecrets")
        .ok_or(crate::Error::Storage)?
        .data_local_dir()
        .to_owned();
    fs::create_dir_all(&root).map_err(|_| crate::Error::Storage)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(root.join(crate::hex(&sha2::Sha256::digest(namespace.as_bytes()))))
        .map_err(|_| crate::Error::Storage)?;
    file.lock().map_err(|_| crate::Error::Storage)?;
    Ok(file)
}
#[cfg(target_os = "windows")]
use sha2::Digest;

pub fn system(namespace: &str) -> crate::Result<crate::DeviceSecrets<Store, Protector>> {
    crate::DeviceSecrets::new(
        namespace,
        Store::new(namespace)?,
        Protector::new(namespace)?,
    )
}
