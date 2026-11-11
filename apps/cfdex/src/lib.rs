//! Headless command-line client and local agent support.
pub mod agent;
pub mod cli;
mod credentials;
pub mod protocol;
pub mod runtime;
mod setup;
#[cfg(unix)]
pub mod socket;
#[cfg(windows)]
#[path = "socket_windows.rs"]
pub mod socket;
