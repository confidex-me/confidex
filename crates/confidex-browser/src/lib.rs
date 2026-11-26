//! Shared browser storage, transport and Engine host.
pub const DEFAULT_SYNC_SERVER: &str = "https://sync.confidex.me/";

#[cfg(feature = "wire")]
pub mod wire;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod runtime;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod storage;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod transport;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use {runtime::Runtime, storage::BrowserStore, transport::Net};
