#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen::prelude::*;

// The bootstrap smoke test supplies the isolated world's document.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[wasm_bindgen]
pub fn has_password_field(document: &web_sys::Document) -> Result<bool, JsValue> {
    document
        .query_selector("input[type=password]")
        .map(|input| input.is_some())
}
