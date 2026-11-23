#[cfg(any(
    test,
    all(feature = "session", target_arch = "wasm32", target_os = "unknown")
))]
mod lease;

#[cfg(any(test, feature = "session", feature = "ui"))]
mod protocol;

#[cfg(all(feature = "session", target_arch = "wasm32", target_os = "unknown"))]
mod session;

#[cfg(all(feature = "ui", target_arch = "wasm32", target_os = "unknown"))]
mod ui;

#[cfg(any(
    test,
    all(feature = "session", target_arch = "wasm32", target_os = "unknown")
))]
mod sync_schedule;

#[cfg(any(test, feature = "session", feature = "ui"))]
mod autofill;

#[cfg(all(feature = "ui", target_arch = "wasm32", target_os = "unknown"))]
mod popup;

#[cfg(any(test, feature = "session", feature = "ui"))]
mod autosave;

#[cfg(all(feature = "ui", target_arch = "wasm32", target_os = "unknown"))]
mod save_ui;
