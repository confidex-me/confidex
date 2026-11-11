use confidex_ui::{ImportFile, ImportFileReply, ImportFileRequest, VaultApp};

#[cfg(not(target_arch = "wasm32"))]
pub fn install(app: &mut VaultApp) {
    app.set_import_file_handler(|kind, done| {
        std::thread::spawn(move || done(native(kind)));
    });
}
#[cfg(not(target_arch = "wasm32"))]
fn native(kind: ImportFileRequest) -> ImportFileReply {
    use std::io::Read;
    let dialog = rfd::FileDialog::new();
    let dialog = if kind == ImportFileRequest::Records {
        dialog.add_filter(
            "JSON / XML / KDBX / 1PUX / ZIP / CSV",
            &["json", "xml", "kdbx", "1pux", "zip", "csv"],
        )
    } else {
        dialog
    };
    let Some(path) = dialog.pick_file() else {
        return ImportFileReply::Canceled;
    };
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut file = ImportFile {
        name,
        bytes: Vec::new(),
    };
    let result = std::fs::File::open(path).and_then(|source| {
        source
            .take(kind.limit() as u64 + 1)
            .read_to_end(&mut file.bytes)
    });
    match result {
        Ok(_) if file.bytes.len() <= kind.limit() => ImportFileReply::Selected(file),
        Ok(_) => ImportFileReply::TooLarge,
        Err(_) => ImportFileReply::Failed,
    }
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(module = "/web/import.js")]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name=pickImport)]
    async fn pick_import(
        limit: u32,
        keyfile: bool,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}
#[cfg(target_arch = "wasm32")]
pub fn install(app: &mut VaultApp) {
    app.set_import_file_handler(|kind, done| {
        wasm_bindgen_futures::spawn_local(async move {
            let result =
                match pick_import(kind.limit() as u32, kind == ImportFileRequest::Keyfile).await {
                    Ok(value) if value.is_null() => ImportFileReply::Canceled,
                    Ok(value) => {
                        use wasm_bindgen::JsCast;
                        let name = js_sys::Reflect::get(&value, &"name".into())
                            .ok()
                            .and_then(|name| name.as_string());
                        let bytes = js_sys::Reflect::get(&value, &"bytes".into())
                            .ok()
                            .and_then(|bytes| bytes.dyn_into::<js_sys::Uint8Array>().ok());
                        match (name, bytes) {
                            (Some(name), Some(bytes)) => {
                                let file = ImportFile {
                                    name,
                                    bytes: bytes.to_vec(),
                                };
                                bytes.fill(0, 0, bytes.length());
                                ImportFileReply::Selected(file)
                            }
                            (_, Some(bytes)) => {
                                bytes.fill(0, 0, bytes.length());
                                ImportFileReply::Failed
                            }
                            _ => ImportFileReply::Failed,
                        }
                    }
                    Err(value) if value.as_string().as_deref() == Some("Limit") => {
                        ImportFileReply::TooLarge
                    }
                    Err(_) => ImportFileReply::Failed,
                };
            done(result);
        })
    });
}
