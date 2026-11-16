#[cfg(not(target_arch = "wasm32"))]
pub use confidex_native::sync_transport::Net;
