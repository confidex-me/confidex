use confidex_ui::ui_kit::password::{Evaluator, Report, assess};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/web/passwords.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    fn runPasswordWork(bytes: &[u8]) -> Result<js_sys::Promise, JsValue>;
}
pub fn install(evaluator: &mut Evaluator) {
    evaluator.set_worker(|prefix, done| {
        let promise = runPasswordWork(prefix.as_bytes());
        drop(prefix);
        match promise {
            Err(_) => done(Err(())),
            Ok(promise) => wasm_bindgen_futures::spawn_local(async move {
                let result = wasm_bindgen_futures::JsFuture::from(promise)
                    .await
                    .ok()
                    .and_then(|value| serde_wasm_bindgen::from_value::<Report>(value).ok())
                    .filter(|report| report.valid())
                    .ok_or(());
                done(result);
            }),
        }
    });
}
#[wasm_bindgen]
pub fn assess_password(mut bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    let result = (|| {
        if bytes.len() > 400 {
            return Err(JsValue::NULL);
        }
        let password = std::str::from_utf8(&bytes).map_err(|_| JsValue::NULL)?;
        serde_wasm_bindgen::to_value(&assess(password)).map_err(|_| JsValue::NULL)
    })();
    bytes.fill(0);
    result
}
