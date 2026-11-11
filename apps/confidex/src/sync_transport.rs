#[cfg(target_arch = "wasm32")]
use confidex_app::{
    Error,
    sync::{MAX_BODY, Reply, Transport},
};
#[cfg(not(target_arch = "wasm32"))]
pub use confidex_native::sync_transport::Net;

#[cfg(target_arch = "wasm32")]
#[derive(Default)]
pub struct Net;
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(module = "/web/storage.js")]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name=syncFetch)]
    async fn fetch(
        url: &str,
        method: &str,
        content_type: &str,
        body: js_sys::Uint8Array,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}
#[cfg(target_arch = "wasm32")]
impl Transport for Net {
    async fn send(
        &mut self,
        url: &str,
        method: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Reply, Error> {
        if body.len() > MAX_BODY {
            return Err(Error::Input);
        }
        #[derive(serde::Deserialize)]
        struct Response {
            status: u16,
            content_type: String,
            etag: Option<String>,
            cursor: Option<String>,
            max_body: Option<usize>,
            body: Vec<u8>,
        }
        let response = fetch(
            url,
            method,
            content_type,
            js_sys::Uint8Array::from(body.as_slice()),
        )
        .await
        .map_err(|_| Error::Network)?;
        let response: Response =
            serde_wasm_bindgen::from_value(response).map_err(|_| Error::Integrity)?;
        if response.body.len() > MAX_BODY {
            return Err(Error::Integrity);
        }
        Ok(Reply {
            status: response.status,
            content_type: response.content_type,
            etag: response.etag,
            cursor: response.cursor,
            max_body: response.max_body,
            body: response.body,
        })
    }
}
