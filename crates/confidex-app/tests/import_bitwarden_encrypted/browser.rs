use crate::browser_store::BrowserStore;
use confidex_storage::Store;
use wasm_bindgen::prelude::*;
mod proof;

#[wasm_bindgen]
pub async fn check_encrypted() -> String {
    let created = proof::first(&mut BrowserStore).await;
    proof::reopened(&mut BrowserStore, &created).await;
    BrowserStore.remove(created.info.id).await.unwrap();
    "authenticated preview,3 sealed records,exact fields,reopen,duplicate skip,protected search"
        .into()
}
