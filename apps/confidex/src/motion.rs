//! Hosts provide the OS preference; UI-kit owns the transition.
pub fn install(ctx: &eframe::egui::Context) {
    #[cfg(target_os = "macos")]
    let reduced = std::process::Command::new("/usr/bin/defaults")
        .args(["read", "com.apple.universalaccess", "reduceMotion"])
        .output()
        .ok()
        .is_some_and(|output| output.status.success() && output.stdout.starts_with(b"1"));
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    let reduced = browser_preference().unwrap_or(false);
    #[cfg(not(any(
        target_os = "macos",
        all(target_arch = "wasm32", target_os = "unknown")
    )))]
    let reduced = false;
    confidex_ui::ui_kit::layout::set_reduced_motion(ctx, reduced);
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn browser_preference() -> Option<bool> {
    use wasm_bindgen::JsCast;
    let window = web_sys::window()?;
    let function = js_sys::Reflect::get(&window, &"matchMedia".into())
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    let media = function
        .call1(&window, &"(prefers-reduced-motion: reduce)".into())
        .ok()?;
    js_sys::Reflect::get(&media, &"matches".into())
        .ok()?
        .as_bool()
}
