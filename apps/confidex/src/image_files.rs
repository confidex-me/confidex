#[cfg(not(target_arch = "wasm32"))]
use confidex_ui::ImageCompletion;
use confidex_ui::{ImageFile, ImageHost, ImageReply, ImageRequest, MAX_IMAGE_SOURCE_BYTES};

#[cfg(not(target_arch = "wasm32"))]
pub fn install(app: &mut impl ImageHost) {
    app.set_image_handler(|request, done| {
        std::thread::spawn(move || native(request, done));
    });
}
#[cfg(not(target_arch = "wasm32"))]
fn native(request: ImageRequest, done: ImageCompletion) {
    use std::io::Write;
    let reply = match request {
        ImageRequest::Discard { .. } | ImageRequest::Download => ImageReply::Cancelled,
        ImageRequest::Dropped { file, bytes, .. } => {
            read_file(file.path(), bytes.min(MAX_IMAGE_SOURCE_BYTES))
        }
        ImageRequest::Open | ImageRequest::OpenFile | ImageRequest::OpenLimited { .. } => {
            let limit = match request {
                ImageRequest::OpenLimited { bytes } => bytes.min(MAX_IMAGE_SOURCE_BYTES),
                _ => MAX_IMAGE_SOURCE_BYTES,
            };
            let dialog = rfd::FileDialog::new();
            let dialog = if matches!(request, ImageRequest::Open) {
                dialog.add_filter("JPEG / PNG / WebP", &["jpg", "jpeg", "png", "webp"])
            } else {
                dialog
            };
            let path = dialog.pick_file();
            match path {
                None => ImageReply::Cancelled,
                Some(path) => read_file(&path, limit),
            }
        }
        ImageRequest::Save(file) => {
            match rfd::FileDialog::new().set_file_name(&file.name).save_file() {
                None => ImageReply::Cancelled,
                Some(path) => {
                    let save = || -> std::io::Result<()> {
                        let mut temporary = tempfile::NamedTempFile::new_in(
                            path.parent().ok_or(std::io::ErrorKind::InvalidInput)?,
                        )?;
                        temporary.write_all(&file.bytes)?;
                        temporary.as_file().sync_all()?;
                        temporary.persist(path).map_err(|error| error.error)?;
                        Ok(())
                    };
                    if save().is_ok() {
                        ImageReply::Saved
                    } else {
                        ImageReply::Failed
                    }
                }
            }
        }
    };
    done(reply);
}

#[cfg(not(target_arch = "wasm32"))]
fn read_file(path: &std::path::Path, limit: usize) -> ImageReply {
    use std::io::Read;
    let read = || -> std::io::Result<ImageFile> {
        if !std::fs::metadata(path)?.is_file() {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let input = std::fs::File::open(path)?;
        if input.metadata()?.len() > limit as u64 {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        input.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        Ok(ImageFile {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            bytes,
        })
    };
    match read() {
        Ok(file) => ImageReply::Opened(file),
        Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => ImageReply::TooLarge,
        Err(_) => ImageReply::Failed,
    }
}

#[cfg(target_arch = "wasm32")]
use confidex_ui::MAX_IMAGE_BYTES;
#[cfg(target_arch = "wasm32")]
pub fn install(app: &mut impl ImageHost) {
    use wasm_bindgen::{JsCast, JsValue, prelude::*};
    #[wasm_bindgen(module = "/web/image-host.js")]
    extern "C" {
        fn discardImage(source: bool);
        #[wasm_bindgen(catch)]
        fn downloadImage() -> Result<(), JsValue>;
        #[wasm_bindgen(catch)]
        fn pickImage(max: usize) -> Result<js_sys::Promise, JsValue>;
        #[wasm_bindgen(catch)]
        fn pickFile(max: usize) -> Result<js_sys::Promise, JsValue>;
        #[wasm_bindgen(catch)]
        fn readImage(file: &JsValue, max: usize) -> Result<js_sys::Promise, JsValue>;
        #[wasm_bindgen(catch)]
        fn readFile(file: &JsValue, max: usize) -> Result<js_sys::Promise, JsValue>;
        #[wasm_bindgen(catch)]
        fn saveImage(name: &str, bytes: &[u8]) -> Result<(), JsValue>;
        #[wasm_bindgen(catch)]
        fn runImageWork(bytes: &[u8]) -> Result<js_sys::Promise, JsValue>;
    }
    app.set_image_handler(|request, done| match request {
        ImageRequest::Discard { source } => {
            discardImage(source);
            done(ImageReply::Cancelled);
        }
        ImageRequest::Download => done(if downloadImage().is_ok() {
            ImageReply::DownloadStarted
        } else {
            ImageReply::Failed
        }),
        ImageRequest::Open
        | ImageRequest::OpenFile
        | ImageRequest::OpenLimited { .. }
        | ImageRequest::Dropped { .. } => {
            let limit = match request {
                ImageRequest::OpenLimited { bytes } | ImageRequest::Dropped { bytes, .. } => {
                    bytes.min(MAX_IMAGE_SOURCE_BYTES)
                }
                _ => MAX_IMAGE_SOURCE_BYTES,
            };
            let file = !matches!(
                request,
                ImageRequest::Open | ImageRequest::Dropped { image: true, .. }
            );
            match match request {
                ImageRequest::Dropped { file: source, .. } => source
                    .web_file()
                    .ok_or_else(|| JsValue::from_str("dropped file unavailable"))
                    .and_then(|source| {
                        if file {
                            readFile(source.as_ref(), limit)
                        } else {
                            readImage(source.as_ref(), limit)
                        }
                    }),
                _ if file => pickFile(limit),
                _ => pickImage(limit),
            } {
                Err(_) => done(ImageReply::Failed),
                Ok(promise) => wasm_bindgen_futures::spawn_local(async move {
                    let reply = match wasm_bindgen_futures::JsFuture::from(promise).await {
                        Ok(value) if value.is_null() => ImageReply::Cancelled,
                        Ok(value)
                            if js_sys::Reflect::get(&value, &"tooLarge".into())
                                .ok()
                                .and_then(|b| b.as_bool())
                                == Some(true) =>
                        {
                            ImageReply::TooLarge
                        }
                        Ok(value)
                            if js_sys::Reflect::get(&value, &"large".into())
                                .ok()
                                .and_then(|v| v.as_bool())
                                == Some(true) =>
                        {
                            let name = js_sys::Reflect::get(&value, &"name".into())
                                .ok()
                                .and_then(|v| v.as_string());
                            let exif = js_sys::Reflect::get(&value, &"exif".into())
                                .ok()
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            match name {
                                Some(name) if name.len() <= 1024 => ImageReply::Large {
                                    name,
                                    has_exif: exif,
                                    webp: js_sys::Reflect::get(&value, &"webp".into())
                                        .ok()
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false),
                                },
                                _ => ImageReply::Failed,
                            }
                        }
                        Ok(value) => {
                            let name = js_sys::Reflect::get(&value, &"name".into())
                                .ok()
                                .and_then(|n| n.as_string());
                            let bytes = js_sys::Reflect::get(&value, &"bytes".into())
                                .ok()
                                .and_then(|b| b.dyn_into::<js_sys::Uint8Array>().ok());
                            match (name, bytes) {
                                (Some(name), Some(bytes))
                                    if bytes.length() as usize
                                        <= if file { limit } else { MAX_IMAGE_BYTES } =>
                                {
                                    let file = ImageFile {
                                        name,
                                        bytes: bytes.to_vec().into(),
                                    };
                                    bytes.fill(0, 0, bytes.length());
                                    ImageReply::Opened(file)
                                }
                                _ => ImageReply::Failed,
                            }
                        }
                        Err(_) => ImageReply::Failed,
                    };
                    done(reply);
                }),
            }
        }
        ImageRequest::Save(file) => done(if saveImage(&file.name, &file.bytes).is_ok() {
            ImageReply::DownloadStarted
        } else {
            ImageReply::Failed
        }),
    });
    app.set_image_worker(|bytes, done| {
        let work = ImageFile {
            name: String::new(),
            bytes: bytes.into(),
        };
        match runImageWork(&work.bytes) {
            Err(_) => done(Err("image worker unavailable".into())),
            Ok(promise) => wasm_bindgen_futures::spawn_local(async move {
                let result = wasm_bindgen_futures::JsFuture::from(promise)
                    .await
                    .ok()
                    .and_then(|value| value.dyn_into::<js_sys::Uint8Array>().ok())
                    .filter(|bytes| bytes.length() as usize <= 2 * MAX_IMAGE_BYTES + 65_536)
                    .map(|bytes| {
                        let data = bytes.to_vec();
                        bytes.fill(0, 0, bytes.length());
                        data
                    })
                    .ok_or_else(|| "image worker failed".into());
                done(result);
            }),
        }
    });
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, mpsc},
    };

    #[derive(Debug)]
    struct Source(PathBuf);
    impl eframe::egui::DroppedFile for Source {
        fn path(&self) -> &Path {
            &self.0
        }
        fn bytes(&self) -> Result<Vec<u8>, String> {
            panic!("Use the bounded file reader");
        }
    }
    fn drop_file(path: &Path, limit: usize) -> ImageReply {
        let (sender, receiver) = mpsc::channel();
        native(
            ImageRequest::Dropped {
                file: Arc::new(Source(path.into())),
                image: false,
                bytes: limit,
            },
            Box::new(move |reply| {
                sender.send(reply).ok();
            }),
        );
        receiver.recv().unwrap()
    }
    #[test]
    fn dropped_files_use_the_picker_reader_and_check_size_before_reading() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public-license.txt");
        std::fs::write(&path, b"public license fixture").unwrap();
        match drop_file(&path, 64) {
            ImageReply::Opened(file) => {
                assert_eq!(file.name, "public-license.txt");
                assert_eq!(&*file.bytes, b"public license fixture");
            }
            _ => panic!("file did not open"),
        }
        assert!(matches!(drop_file(&path, 4), ImageReply::TooLarge));
        assert!(matches!(
            drop_file(directory.path(), 64),
            ImageReply::Failed
        ));
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_IMAGE_SOURCE_BYTES as u64 + 1)
            .unwrap();
        assert!(matches!(drop_file(&path, usize::MAX), ImageReply::TooLarge));
    }
}
