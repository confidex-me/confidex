//! Portable vault operations. docs/FORMAT.md defines the wire format.

/// Release tag and source revision supplied by the release builder.
pub const BUILD_VERSION: &str = match option_env!("CONFIDEX_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

pub mod crypto;
pub mod date;
pub mod encoding;
pub mod entropy;
pub mod envelope;
pub mod kdf;
pub mod location;
pub mod lock;
pub mod photo;
pub mod record;
pub mod records_list;
pub mod resources;
pub mod revisions;
pub mod secret_key_text;
pub mod ssh;
pub mod sync;
pub mod totp;
pub mod transfer_code;
pub mod trust;
pub mod wifi;
