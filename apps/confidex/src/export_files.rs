use confidex_app::export_flow::Transfer;
use confidex_ui::{ExportFileCompletion, ExportFileReply};

#[cfg(not(target_arch = "wasm32"))]
pub fn save(transfer: Transfer, done: ExportFileCompletion) {
    std::thread::spawn(move || {
        if !transfer.available() {
            done(ExportFileReply::Canceled);
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(&transfer.file().name)
            .save_file()
        else {
            transfer.cancel();
            done(ExportFileReply::Canceled);
            return;
        };
        let result = save_to(&transfer, &path);
        transfer.cancel();
        done(match result {
            Ok(()) => ExportFileReply::Saved,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionAborted => {
                ExportFileReply::Canceled
            }
            Err(_) => ExportFileReply::Failed,
        });
    });
}
#[cfg(not(target_arch = "wasm32"))]
fn save_to(transfer: &Transfer, path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .prefix(".confidex-export-")
        .tempfile_in(path.parent().unwrap_or(std::path::Path::new(".")))?;
    let mut offset = 0;
    while offset < transfer.len() {
        let bytes = transfer.read(offset)?;
        file.write_all(&bytes)?;
        offset += bytes.len();
    }
    file.as_file().sync_all()?;
    transfer.publish(|_| file.persist(path).map(|_| ()).map_err(|e| e.error))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(module = "/web/export.js")]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name=saveExport)]
    fn save_export(
        bytes: &js_sys::Uint8Array,
        name: &str,
        media_type: &str,
    ) -> Result<(), wasm_bindgen::JsValue>;
}
#[cfg(target_arch = "wasm32")]
pub fn save(transfer: Transfer, done: ExportFileCompletion) {
    let result = transfer.publish(|bytes| {
        let bytes = js_sys::Uint8Array::from(bytes);
        let result = save_export(&bytes, &transfer.file().name, &transfer.file().media_type);
        bytes.fill(0, 0, bytes.length());
        result.map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))
    });
    done(match result {
        Ok(()) => ExportFileReply::DownloadStarted,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionAborted => {
            ExportFileReply::Canceled
        }
        Err(_) => ExportFileReply::Failed,
    });
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    fn transfer() -> Transfer {
        let transfer = Transfer::new(&confidex_app::export_flow::Ready {
            token: [1; 16],
            bytes: (300 << 10) + 4,
            file: confidex_app::export_flow::File {
                name: "test.json".into(),
                media_type: "application/json".into(),
                encrypted: false,
            },
        })
        .unwrap();
        transfer
            .append(0, &vec![b'a'; 256 << 10], Some(256 << 10))
            .unwrap();
        let mut last = vec![b'b'; 44 << 10];
        last.extend_from_slice(b"tail");
        transfer.append(256 << 10, &last, None).unwrap();
        transfer
    }
    #[test]
    fn native_save_replaces_atomically_and_leaves_no_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.json");
        std::fs::write(&path, b"previous").unwrap();
        let transfer = transfer();
        save_to(&transfer, &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), transfer.len());
        assert_eq!(&bytes[bytes.len() - 4..], b"tail");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        assert!(!transfer.available());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn cancel_and_io_failure_preserve_destination_and_remove_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.json");
        std::fs::write(&path, b"previous").unwrap();
        let transfer = transfer();
        transfer.cancel();
        assert_eq!(
            save_to(&transfer, &path).unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        let transfer = self::transfer();
        let blocked = directory.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        assert!(save_to(&transfer, &blocked).is_err());
        transfer.cancel();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }
    #[test]
    #[ignore = "requires independently checked public load downloads"]
    fn native_save_calibration_for_public_downloads() {
        let source = std::path::PathBuf::from(
            std::env::var_os("CONFIDEX_EXPORT_SAVE_FIXTURES")
                .expect("set CONFIDEX_EXPORT_SAVE_FIXTURES to a public load UI output directory"),
        );
        let directory = tempfile::tempdir().unwrap();
        let mut report = Vec::new();
        for (name, media_type, encrypted) in [
            ("bitwarden-personal.json", "application/json", false),
            ("confidex.kdbx", "application/x-keepass2", true),
            ("bitwarden-encrypted.json", "application/json", true),
            ("bitwarden-personal.zip", "application/zip", false),
            ("confidex.xml", "application/xml", false),
            ("confidex.1pux", "application/zip", false),
        ] {
            let bytes = std::fs::read(source.join(format!("10000-{name}"))).unwrap();
            assert!(bytes.len() > 1 << 20);
            let started = std::time::Instant::now();
            let transfer = Transfer::new(&confidex_app::export_flow::Ready {
                token: [1; 16],
                bytes: bytes.len(),
                file: confidex_app::export_flow::File {
                    name: name.into(),
                    media_type: media_type.into(),
                    encrypted,
                },
            })
            .unwrap();
            let mut offset = 0;
            for chunk in bytes.chunks(confidex_app::export_flow::CHUNK_BYTES) {
                let end = offset + chunk.len();
                transfer
                    .append(offset, chunk, (end < bytes.len()).then_some(end))
                    .unwrap();
                offset = end;
            }
            let assembled = started.elapsed().as_secs_f64() * 1000.0;
            let path = directory.path().join(name);
            std::fs::write(&path, b"previous").unwrap();
            let saving = std::time::Instant::now();
            save_to(&transfer, &path).unwrap();
            let save_ms = saving.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(!transfer.available());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            report.push(serde_json::json!({
                "file": name, "bytes": bytes.len(),
                "assemble_ms": assembled, "save_ms": save_ms,
            }));
        }
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 6);
        println!(
            "export-host-save {}",
            serde_json::to_string(&report).unwrap()
        );
    }
}
