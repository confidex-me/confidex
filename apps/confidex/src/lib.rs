#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod browser;
#[cfg(any(all(target_arch = "wasm32", target_os = "unknown"), test))]
mod browser_input;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod browser_store;
#[cfg(all(
    feature = "export-ui-check",
    target_arch = "wasm32",
    target_os = "unknown"
))]
mod export_check;
#[cfg(all(
    feature = "import-check",
    target_arch = "wasm32",
    target_os = "unknown"
))]
mod import_check;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(target_os = "macos")]
pub mod native_quit;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod passwords;

pub mod backup_files;
pub mod export_files;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod image_exports;
pub mod image_files;
pub mod import_files;
pub mod motion;
pub mod sync_defaults;
#[cfg(feature = "sync")]
pub mod sync_transport;

#[cfg(any(target_arch = "wasm32", test))]
mod browser_wire;
