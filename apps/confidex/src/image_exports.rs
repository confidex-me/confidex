use wasm_bindgen::prelude::*;
#[wasm_bindgen]
pub fn image_job(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    confidex_ui::process_image_job(bytes).map_err(|error| JsValue::from_str(&error))
}
#[wasm_bindgen]
pub fn image_metadata(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let info = confidex_ui::image_metadata(bytes).map_err(|e| JsValue::from_str(&e))?;
    let value = js_sys::Object::new();
    for (key, data) in [
        ("width", info.width.into()),
        ("height", info.height.into()),
        ("orientation", info.orientation.into()),
        ("large", info.large.into()),
        ("webp", info.webp.into()),
        (
            "exif",
            js_sys::Uint8Array::from(info.exif.as_slice()).into(),
        ),
    ] {
        js_sys::Reflect::set(&value, &key.into(), &data)?;
    }
    Ok(value.into())
}
#[wasm_bindgen]
pub fn image_work(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let (kind, quality, exif, file) =
        confidex_ui::browser_image_work(bytes).map_err(|e| JsValue::from_str(&e))?;
    let value = js_sys::Object::new();
    for (key, data) in [
        ("kind", (kind as u32).into()),
        ("quality", quality.into()),
        ("keepExif", exif.into()),
        ("name", file.name.into()),
        (
            "bytes",
            js_sys::Uint8Array::from(file.bytes.as_slice()).into(),
        ),
    ] {
        js_sys::Reflect::set(&value, &key.into(), &data)?;
    }
    Ok(value.into())
}
#[wasm_bindgen]
pub fn image_import_result(work: &[u8], bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    confidex_ui::finish_image_import(work, bytes).map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn image_preview_result(
    rgba: &[u8],
    width: u32,
    height: u32,
    natural_width: u32,
    natural_height: u32,
) -> Result<Vec<u8>, JsValue> {
    confidex_ui::finish_image_preview(rgba, width, height, natural_width, natural_height)
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn image_full_result() -> Result<Vec<u8>, JsValue> {
    confidex_ui::image_full_result().map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn image_download_result() -> Result<Vec<u8>, JsValue> {
    confidex_ui::image_download_result().map_err(|e| JsValue::from_str(&e))
}
