use crate::browser_store::BrowserStore;
use confidex_storage::Store;
use wasm_bindgen::prelude::*;
#[path = "performance.rs"]
mod performance;
#[path = "proof.rs"]
mod proof;

#[wasm_bindgen]
pub async fn check_csv() -> Result<String, JsValue> {
    let created = {
        let mut store = BrowserStore;
        proof::first(&mut store).await
    };
    let mut store = BrowserStore;
    proof::reopened(&mut store, &created).await;
    store.remove(created.info.id).await.unwrap();
    Ok(
        "preview,2 sealed records,exact fields,reopen,duplicate skip,row reorder,protected search"
            .into(),
    )
}

#[wasm_bindgen]
pub async fn check_csv_load() -> Result<String, JsValue> {
    std::panic::set_hook(Box::new(|info| load_panic(&info.to_string())));
    let created = {
        let mut store = BrowserStore;
        proof::first_load(&mut store, &mut load_phase).await
    };
    let mut store = BrowserStore;
    proof::reopened_load(&mut store, &created, &mut load_phase).await;
    store.remove(created.info.id).await.unwrap();
    Ok("10000 records,parse,review,seal,commit,search,reopen,duplicate skip".into())
}

#[wasm_bindgen]
pub async fn check_csv_profile() -> Result<String, JsValue> {
    std::panic::set_hook(Box::new(|info| load_panic(&info.to_string())));
    let mut store = BrowserStore;
    let (created, report) = performance::first(&mut store, &mut load_phase).await;
    proof::reopened_load(&mut store, &created, &mut load_phase).await;
    store.remove(created.info.id).await.unwrap();
    Ok(serde_json::to_string(&report).unwrap())
}
#[wasm_bindgen(
    inline_js = "export function load_phase(phase) { self.postMessage({phase,at:performance.now()}); } export function load_panic(error) { self.postMessage({error}); }"
)]
extern "C" {
    fn load_phase(phase: &str);
    fn load_panic(error: &str);
}
