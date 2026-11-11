use confidex_storage::MAX_BACKUP_BYTES;
use confidex_ui::{BackupFileReply, BackupFileRequest, VaultApp};

#[cfg(not(target_arch = "wasm32"))]
pub fn install(app: &mut VaultApp) {
    app.set_backup_file_handler(|request, done| {
        std::thread::spawn(move || {
            done(native(request));
        });
    });
}
#[cfg(not(target_arch = "wasm32"))]
fn native(request: BackupFileRequest) -> BackupFileReply {
    use std::io::{Read, Write};
    match request {
        BackupFileRequest::Open => {
            let Some(path) = rfd::FileDialog::new()
                .add_filter("ZIP", &["zip"])
                .pick_file()
            else {
                return BackupFileReply::Cancelled;
            };
            let bytes = (|| -> std::io::Result<Vec<u8>> {
                let file = std::fs::File::open(path)?;
                let mut bytes = Vec::new();
                file.take(MAX_BACKUP_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                Ok(bytes)
            })();
            match bytes {
                Ok(bytes) if bytes.len() <= MAX_BACKUP_BYTES => BackupFileReply::Opened(bytes),
                Ok(_) => BackupFileReply::TooLarge,
                Err(_) => BackupFileReply::Failed,
            }
        }
        BackupFileRequest::Save(bytes) => {
            let Some(path) = rfd::FileDialog::new()
                .add_filter("ZIP", &["zip"])
                .set_file_name("confidex-backup.zip")
                .save_file()
            else {
                return BackupFileReply::Cancelled;
            };
            let result = (|| -> std::io::Result<()> {
                let mut file = tempfile::NamedTempFile::new_in(
                    path.parent().unwrap_or(std::path::Path::new(".")),
                )?;
                file.write_all(&bytes)?;
                file.as_file().sync_all()?;
                file.persist(path).map_err(|e| e.error)?;
                Ok(())
            })();
            if result.is_ok() {
                BackupFileReply::Saved
            } else {
                BackupFileReply::Failed
            }
        }
    }
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(module = "/web/backup.js")]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name=pickBackup)]
    async fn pick_backup(limit: u32) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name=saveBackup)]
    fn save_backup(bytes: &js_sys::Uint8Array) -> Result<(), wasm_bindgen::JsValue>;
}
#[cfg(target_arch = "wasm32")]
pub fn install(app: &mut VaultApp) {
    app.set_backup_file_handler(
        |request, done: confidex_ui::BackupFileCompletion| match request {
            BackupFileRequest::Open => wasm_bindgen_futures::spawn_local(async move {
                done(match pick_backup(MAX_BACKUP_BYTES as u32).await {
                    Ok(value) if value.is_null() => BackupFileReply::Cancelled,
                    Ok(value) => BackupFileReply::Opened(js_sys::Uint8Array::new(&value).to_vec()),
                    Err(value) if value.as_string().as_deref() == Some("Limit") => {
                        BackupFileReply::TooLarge
                    }
                    Err(_) => BackupFileReply::Failed,
                });
            }),
            BackupFileRequest::Save(bytes) => {
                done(
                    if save_backup(&js_sys::Uint8Array::from(bytes.as_slice())).is_ok() {
                        BackupFileReply::DownloadStarted
                    } else {
                        BackupFileReply::Failed
                    },
                );
            }
        },
    );
}
