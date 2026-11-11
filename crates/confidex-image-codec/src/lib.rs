//! Isolated WebP encoder for the browser image worker.
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn image_compress(bytes: &[u8], quality: u8, keep_exif: bool) -> Result<Vec<u8>, JsValue> {
    confidex_ui::compress_image(bytes, quality, keep_exif).map_err(|e| JsValue::from_str(&e))
}
