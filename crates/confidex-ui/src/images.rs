//! Bounded image import, compression, preview and export.
use confidex_vault::{
    record::{Entry, Mapping, Record, Value},
    resources,
};
use eframe::egui;
use image::{DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, ImageReader};
use std::io::{Cursor, Write};
use zeroize::{Zeroize, Zeroizing};
mod worker;
pub use worker::{
    browser_image_work, finish_image_import, finish_image_preview, image_download_result,
    image_full_result, process_image_job,
};

pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_IMAGE_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PIXELS: u64 = 8_388_608;
const MAX_SOURCE_PIXELS: u64 = 50_000_000;
const PREVIEW_SIDE: u32 = 2048;

#[derive(Clone)]
pub struct ImageFile {
    pub name: String,
    pub bytes: Zeroizing<Vec<u8>>,
}
pub enum ImageRequest {
    Open,
    OpenFile,
    OpenLimited {
        bytes: usize,
    },
    Dropped {
        file: egui::DroppedFileHandle,
        image: bool,
        bytes: usize,
    },
    Save(ImageFile),
    Discard {
        source: bool,
    },
    Download,
}
pub enum ImageReply {
    Opened(ImageFile),
    Large {
        name: String,
        has_exif: bool,
        webp: bool,
    },
    Saved,
    DownloadStarted,
    Cancelled,
    TooLarge,
    Failed,
}
pub type ImageCompletion = Box<dyn FnOnce(ImageReply) + Send>;
pub trait ImageHost {
    fn set_image_handler(&mut self, handler: impl FnMut(ImageRequest, ImageCompletion) + 'static);
    fn set_image_worker(&mut self, worker: impl FnMut(Vec<u8>, ImageWorkCompletion) + 'static);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Error {
    Format,
    Corrupt,
    Limit,
    Precision,
    Full,
    Processing,
}
impl Error {
    fn message(self) -> &'static str {
        match self {
            Self::Format => "gallery-image-format-error",
            Self::Corrupt => "gallery-image-corrupt",
            Self::Limit => "gallery-image-resource",
            Self::Precision => "gallery-image-precision",
            Self::Full => "gallery-image-full",
            Self::Processing => "gallery-image-processing-error",
        }
    }
}
enum Event {
    Import(Result<(ImageFile, usize), (Error, Option<ImageFile>)>),
    Preview(Result<(DynamicImage, [u32; 2]), Error>),
    Export(Result<ImageFile, Error>),
    DownloadReady,
    ChooseQuality(ImageFile),
}
pub type ImageWorkCompletion = Box<dyn FnOnce(Result<Vec<u8>, String>) + Send>;
pub enum ImageJobReply {
    Imported(ImageFile),
    Preview(DynamicImage, [u32; 2]),
    Exported(ImageFile),
    DownloadReady,
    Quality(ImageFile),
    Error(&'static str, Option<ImageFile>),
}
pub fn image_job_request(
    kind: u64,
    file: ImageFile,
    quality: u8,
    keep_exif: bool,
) -> Result<Vec<u8>, String> {
    worker::encode_work(Work {
        kind,
        quality,
        keep_exif,
        files: vec![],
        file,
    })
    .map_err(|error| error.message().into())
}
pub fn image_job_reply(bytes: &[u8]) -> Result<ImageJobReply, String> {
    job_reply(worker::decode_result(bytes).map_err(|error| error.message().to_owned())?)
}
pub fn run_image_job(
    kind: u64,
    file: ImageFile,
    quality: u8,
    keep_exif: bool,
) -> Result<ImageJobReply, String> {
    job_reply(
        Work {
            kind,
            file,
            quality,
            keep_exif,
            files: vec![],
        }
        .run(),
    )
}
fn job_reply(event: Event) -> Result<ImageJobReply, String> {
    Ok(match event {
        Event::Import(Ok((file, _))) => ImageJobReply::Imported(file),
        Event::Import(Err((error, file))) => ImageJobReply::Error(error.message(), file),
        Event::Preview(Ok((image, natural))) => ImageJobReply::Preview(image, natural),
        Event::Export(Ok(file)) => ImageJobReply::Exported(file),
        Event::DownloadReady => ImageJobReply::DownloadReady,
        Event::ChooseQuality(file) => ImageJobReply::Quality(file),
        Event::Preview(Err(error)) | Event::Export(Err(error)) => {
            ImageJobReply::Error(error.message(), None)
        }
    })
}

struct Work {
    kind: u64,
    quality: u8,
    keep_exif: bool,
    files: Vec<ImageFile>,
    file: ImageFile,
}
impl Work {
    fn run(self) -> Event {
        match self.kind {
            0 if source_is_large(&self.file).unwrap_or(false)
                && format(&self.file.bytes) != Ok(ImageFormat::WebP) =>
            {
                Event::ChooseQuality(self.file)
            }
            0 => prepare(self.files, self.file, false),
            1 if self.quality == 101 => prepare(self.files, self.file, self.keep_exif),
            1 => match webp(&self.file, self.quality as f32, self.keep_exif) {
                Ok(file) => prepare_stored(self.files, file),
                Err(error) => Event::Import(Err((error, None))),
            },
            2 => Event::Preview(preview(&self.file)),
            _ => Event::Export(export(&self.file, self.kind == 4)),
        }
    }
}
fn format(bytes: &[u8]) -> Result<ImageFormat, Error> {
    match image::guess_format(bytes) {
        Ok(f @ (ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP)) => Ok(f),
        _ => Err(Error::Format),
    }
}
fn decode_error(error: image::ImageError) -> Error {
    if matches!(error, image::ImageError::Limits(_)) {
        Error::Limit
    } else {
        Error::Corrupt
    }
}
fn decoder(file: &ImageFile) -> Result<impl ImageDecoder + '_, Error> {
    if file.bytes.len() > MAX_IMAGE_SOURCE_BYTES {
        return Err(Error::Limit);
    }
    let mut reader = ImageReader::with_format(Cursor::new(&file.bytes[..]), format(&file.bytes)?);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16383);
    limits.max_image_height = Some(16383);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    reader.into_decoder().map_err(decode_error)
}
fn decode_source(
    file: &ImageFile,
    keep_exif: bool,
) -> Result<(DynamicImage, Option<Vec<u8>>), Error> {
    let mut decoder = decoder(file)?;
    let (width, height) = decoder.dimensions();
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_SOURCE_PIXELS {
        return Err(Error::Limit);
    }
    let decoder_exif = decoder
        .exif_metadata()
        .map_err(decode_error)?
        .filter(|data| !data.is_empty());
    let orientation = decoder.orientation().map_err(|_| Error::Corrupt)?;
    let mut image = DynamicImage::from_decoder(decoder).map_err(decode_error)?;
    let exif = decoder_exif;
    if !keep_exif {
        image.apply_orientation(orientation);
    }
    Ok((image, exif.filter(|_| keep_exif)))
}
fn decode(file: &ImageFile) -> Result<DynamicImage, Error> {
    decode_source(file, false).map(|(image, _)| image)
}
fn source_is_large(file: &ImageFile) -> Result<bool, Error> {
    let (w, h) = decoder(file)?.dimensions();
    if w == 0 || h == 0 || u64::from(w) * u64::from(h) > MAX_SOURCE_PIXELS {
        return Err(Error::Limit);
    }
    Ok(file.bytes.len() > MAX_IMAGE_BYTES || u64::from(w) * u64::from(h) > MAX_PIXELS)
}
fn preview(file: &ImageFile) -> Result<(DynamicImage, [u32; 2]), Error> {
    let image = decode(file)?;
    let natural = [image.width(), image.height()];
    let image = if natural[0].max(natural[1]) > PREVIEW_SIDE {
        image.resize(
            PREVIEW_SIDE,
            PREVIEW_SIDE,
            image::imageops::FilterType::Triangle,
        )
    } else {
        image
    };
    Ok((image, natural))
}
pub struct ImageMetadata {
    pub width: u32,
    pub height: u32,
    pub orientation: u8,
    pub exif: Vec<u8>,
    pub large: bool,
    pub webp: bool,
}
/// Reads bounded headers. This does not decode source pixels.
pub fn image_metadata(bytes: &[u8]) -> Result<ImageMetadata, String> {
    if bytes.len() > MAX_IMAGE_SOURCE_BYTES {
        return Err("gallery-image-resource".into());
    }
    let read = || -> Result<ImageMetadata, Error> {
        let file = ImageFile {
            name: String::new(),
            bytes: bytes.to_vec().into(),
        };
        let large = source_is_large(&file)?;
        let mut decoder = decoder(&file)?;
        let (width, height) = decoder.dimensions();
        if decoder.color_type().bits_per_pixel() / u16::from(decoder.color_type().channel_count())
            > 8
        {
            return Err(Error::Precision);
        }
        Ok(ImageMetadata {
            width,
            height,
            orientation: decoder.orientation().map_err(decode_error)?.to_exif(),
            exif: decoder
                .exif_metadata()
                .map_err(decode_error)?
                .unwrap_or_default(),
            large,
            webp: format(bytes)? == ImageFormat::WebP,
        })
    };
    read().map_err(|e| e.message().into())
}
#[cfg(test)]
fn has_exif(file: &ImageFile) -> bool {
    decoder(file)
        .ok()
        .and_then(|mut d| d.exif_metadata().ok().flatten())
        .is_some_and(|data| !data.is_empty())
}
fn name_with_extension(name: &str, extension: &str) -> String {
    let name = name.rsplit(['/', '\\']).next().unwrap_or("image");
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    format!(
        "{}.{extension}",
        if stem.is_empty() { "image" } else { stem }
    )
}
fn webp(file: &ImageFile, quality: f32, keep_exif: bool) -> Result<ImageFile, Error> {
    let (image, exif) = decode_source(file, keep_exif)?;
    encode_webp(file, image, Some(quality), exif.as_deref())
}
/// Encodes a source with the shared Rust codec, without UI or file operations.
pub fn compress_image(bytes: &[u8], quality: u8, keep_exif: bool) -> Result<Vec<u8>, String> {
    if bytes.len() > MAX_IMAGE_SOURCE_BYTES || !(1..=100).contains(&quality) {
        return Err("gallery-image-resource".into());
    }
    let file = ImageFile {
        name: String::new(),
        bytes: bytes.to_vec().into(),
    };
    webp(&file, f32::from(quality), keep_exif)
        .map(|mut image| std::mem::take(&mut *image.bytes))
        .map_err(|e| e.message().into())
}
fn encode_webp(
    file: &ImageFile,
    image: DynamicImage,
    quality: Option<f32>,
    exif: Option<&[u8]>,
) -> Result<ImageFile, Error> {
    if image.color().bits_per_pixel() / u16::from(image.color().channel_count()) > 8 {
        return Err(Error::Precision);
    }
    let (width, height) = (image.width() as usize, image.height() as usize);
    let mut input = webp_rust::ImageBuffer {
        width,
        height,
        rgba: image.into_rgba8().into_raw(),
    };
    let encoded = if let Some(quality) = quality {
        // Method 4 fails its internal filter check on valid images in version 0.3.2.
        webp_rust::encode_lossy_with_config(
            &input,
            &webp_rust::LossyEncodingConfig {
                quality,
                method: 1,
                ..Default::default()
            },
            exif,
        )
    } else {
        webp_rust::encode_lossless_with_config(&input, &Default::default(), exif)
    }
    .map_err(|_| Error::Corrupt);
    input.rgba.zeroize();
    let bytes = Zeroizing::new(encoded?);
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(Error::Full);
    }
    Ok(ImageFile {
        name: name_with_extension(&file.name, "webp"),
        bytes,
    })
}
struct Size(usize);
impl Write for Size {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        if self.0 > resources::MAX_COMPRESSED {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn record_size(files: &[ImageFile], extra: Option<&ImageFile>) -> Result<usize, Error> {
    let files = files.iter().chain(extra);
    if files.clone().map(|f| f.bytes.len()).sum::<usize>() > MAX_IMAGE_BYTES {
        return Err(Error::Limit);
    }
    let mut record = Record::default();
    record.extra.insert(
        "title".into(),
        Value::from("Travel documents · public demo"),
    );
    for file in files {
        record.entries.push(Entry {
            name: file.name.clone(),
            type_name: "photo/v1".into(),
            value: Mapping::from([("data".into(), Value::Binary(file.bytes.to_vec()))]),
            extra: Mapping::from([(
                "metadata".into(),
                Value::Map(vec![(Value::from("protected"), Value::from(true))]),
            )]),
        });
    }
    let content = record
        .encode_content(resources::MAX_OPEN_MEMORY)
        .map_err(|_| Error::Limit)?;
    let mut compressor = flate2::write::ZlibEncoder::new(Size(0), flate2::Compression::new(6));
    compressor
        .write_all(&content.bytes)
        .map_err(|_| Error::Full)?;
    Ok(compressor.finish().map_err(|_| Error::Full)?.0)
}
fn prepare(files: Vec<ImageFile>, file: ImageFile, keep_exif: bool) -> Event {
    if file.name.len() > 1024 || files.len() >= 64 {
        return Event::Import(Err((Error::Limit, None)));
    }
    let (image, exif) = match decode_source(&file, keep_exif) {
        Ok(decoded) => decoded,
        Err(e) => return Event::Import(Err((e, None))),
    };
    let stored = if format(&file.bytes) == Ok(ImageFormat::WebP)
        && (keep_exif
            || decoder(&file)
                .ok()
                .and_then(|mut d| d.exif_metadata().ok().flatten())
                .is_none())
    {
        file.clone()
    } else {
        match encode_webp(&file, image, None, exif.as_deref()) {
            Ok(stored) => stored,
            Err(e) => return Event::Import(Err((e, Some(file)))),
        }
    };
    prepare_stored(files, stored)
}
fn prepare_stored(files: Vec<ImageFile>, stored: ImageFile) -> Event {
    if files.len() >= 64
        || stored.name.len() > 1024
        || format(&stored.bytes) != Ok(ImageFormat::WebP)
        || source_is_large(&stored).is_err()
    {
        return Event::Import(Err((Error::Limit, None)));
    }
    match record_size(&files, Some(&stored)) {
        Ok(size) => Event::Import(Ok((stored, size))),
        Err(e) => Event::Import(Err((e, Some(stored)))),
    }
}
fn export(file: &ImageFile, jpeg: bool) -> Result<ImageFile, Error> {
    let (image, exif) = decode_source(file, true)?;
    if jpeg && image.color().bits_per_pixel() / u16::from(image.color().channel_count()) > 8 {
        return Err(Error::Precision);
    }
    let mut output = Cursor::new(Vec::new());
    if jpeg {
        let mut rgba = image.into_rgba8();
        for p in rgba.pixels_mut() {
            let a = u16::from(p[3]);
            for c in &mut p.0[..3] {
                *c = ((u16::from(*c) * a + 255 * (255 - a) + 127) / 255) as u8;
            }
            p[3] = 255;
        }
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut output, 90);
        if let Some(exif) = exif {
            encoder
                .set_exif_metadata(exif)
                .map_err(|_| Error::Corrupt)?;
        }
        encoder
            .encode_image(&DynamicImage::ImageRgba8(rgba).into_rgb8())
            .map_err(|_| Error::Corrupt)?;
    } else {
        let mut encoder = image::codecs::png::PngEncoder::new(&mut output);
        if let Some(exif) = exif {
            encoder
                .set_exif_metadata(exif)
                .map_err(|_| Error::Corrupt)?;
        }
        encoder
            .write_image(
                image.as_bytes(),
                image.width(),
                image.height(),
                image.color().into(),
            )
            .map_err(|_| Error::Corrupt)?;
    }
    Ok(ImageFile {
        name: name_with_extension(&file.name, if jpeg { "jpg" } else { "png" }),
        bytes: Zeroizing::new(output.into_inner()),
    })
}
#[cfg(test)]
fn samples() -> Vec<ImageFile> {
    (0..3)
        .map(|n| {
            let pixels = image::RgbaImage::from_fn(320, 220, |x, y| {
                let tile = ((x / 20 + y / 20) % 2) as u8;
                image::Rgba([
                    40 + (x / 2) as u8,
                    70 + (y / 2) as u8,
                    110 + n * 35,
                    if x < 100 && y < 60 {
                        0
                    } else if tile == 0 {
                        180
                    } else {
                        255
                    },
                ])
            });
            let source = ImageFile {
                name: [
                    "passport-public-sample.webp",
                    "photo-front-public-sample.webp",
                    "photo-back-public-sample.webp",
                ][n as usize]
                    .into(),
                bytes: Zeroizing::new(Vec::new()),
            };
            encode_webp(&source, DynamicImage::ImageRgba8(pixels), None, None).unwrap()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn noise(name: &str, width: u32, height: u32) -> ImageFile {
        let mut seed = 0x12345678u32;
        let pixels = image::RgbaImage::from_fn(width, height, |_, _| {
            let mut rgba = [0; 4];
            for c in &mut rgba {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *c = seed as u8;
            }
            image::Rgba(rgba)
        });
        let mut output = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(pixels)
            .write_to(&mut output, ImageFormat::Png)
            .unwrap();
        ImageFile {
            name: name.into(),
            bytes: output.into_inner().into(),
        }
    }
    #[test]
    fn formats_alpha_exports_and_resource_limits() {
        let file = samples().remove(0);
        let original = decode(&file).unwrap().to_rgba8();
        for quality in [75., 60., 45., 30., 25.] {
            let compressed = webp(&file, quality, false).unwrap();
            assert_eq!(format(&compressed.bytes), Ok(ImageFormat::WebP));
            image::load_from_memory(&compressed.bytes).expect("independent WebP decode");
            let decoded = decode(&compressed).unwrap().to_rgba8();
            assert_eq!(original.dimensions(), decoded.dimensions());
            for (before, after) in original.pixels().zip(decoded.pixels()) {
                assert_eq!(before[3], after[3]);
            }
        }
        let png = export(&file, false).unwrap();
        assert_eq!(decode(&png).unwrap().to_rgba8(), original);
        let jpeg = export(&file, true).unwrap();
        assert_eq!(format(&jpeg.bytes), Ok(ImageFormat::Jpeg));
        assert_eq!(
            (
                decode(&jpeg).unwrap().width(),
                decode(&jpeg).unwrap().height()
            ),
            original.dimensions()
        );
        for bytes in [b"GIF89a".to_vec(), b"\0\0\0\x20ftypavif".to_vec()] {
            assert!(matches!(
                decode(&ImageFile {
                    name: "fake.png".into(),
                    bytes: bytes.into()
                }),
                Err(Error::Format)
            ));
        }
        assert!(matches!(
            decode(&ImageFile {
                name: "bad.png".into(),
                bytes: b"\x89PNG\r\n\x1a\n".to_vec().into()
            }),
            Err(Error::Corrupt)
        ));
        let pixels = image::RgbaImage::new(16384, 1);
        let mut bytes = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(pixels)
            .write_to(&mut bytes, ImageFormat::Png)
            .unwrap();
        assert!(
            decode(&ImageFile {
                name: "wide.png".into(),
                bytes: bytes.into_inner().into()
            })
            .is_err()
        );
        let sixteen =
            image::ImageBuffer::from_pixel(2, 2, image::Rgba([0u16, 12345, 65535, 12345]));
        let mut bytes = Cursor::new(Vec::new());
        DynamicImage::ImageRgba16(sixteen)
            .write_to(&mut bytes, ImageFormat::Png)
            .unwrap();
        let file = ImageFile {
            name: "16bit.png".into(),
            bytes: bytes.into_inner().into(),
        };
        assert!(matches!(webp(&file, 75., false), Err(Error::Precision)));
        assert_eq!(
            decode(&export(&file, false).unwrap()).unwrap().color(),
            image::ColorType::Rgba16
        );
    }
    #[test]
    fn complete_record_limit_and_explicit_compression_preserve_other_files() {
        let existing: Vec<_> = [noise("first.png", 800, 500), noise("second.png", 800, 500)]
            .into_iter()
            .map(|file| encode_webp(&file, decode(&file).unwrap(), None, None).unwrap())
            .collect();
        let before: Vec<_> = existing.iter().map(|f| f.bytes.clone()).collect();
        assert!(record_size(&existing, None).unwrap() < resources::MAX_COMPRESSED);
        let candidate = noise("new.png", 800, 500);
        assert!(matches!(
            prepare(existing.clone(), candidate.clone(), false),
            Event::Import(Err((Error::Full, Some(_))))
        ));
        let compressed = webp(&candidate, 45., false).unwrap();
        assert!(matches!(
            prepare(existing.clone(), compressed, false),
            Event::Import(Ok(_))
        ));
        assert_eq!(
            before,
            existing.iter().map(|f| f.bytes.clone()).collect::<Vec<_>>()
        );
    }
    #[test]
    fn imports_store_only_webp_without_silent_pixel_changes() {
        let sample = samples().remove(0);
        for file in [
            sample.clone(),
            export(&sample, false).unwrap(),
            export(&sample, true).unwrap(),
        ] {
            let before = decode(&file).unwrap().to_rgba8();
            let Event::Import(Ok((stored, _))) = prepare(Vec::new(), file.clone(), false) else {
                panic!("import failed")
            };
            assert_eq!(format(&stored.bytes), Ok(ImageFormat::WebP));
            assert!(stored.name.ends_with(".webp"));
            assert_eq!(decode(&stored).unwrap().to_rgba8(), before);
            if format(&file.bytes) == Ok(ImageFormat::WebP) {
                assert_eq!(stored.bytes, file.bytes);
            }
        }
    }
    #[test]
    fn palms_full_resolution_compression_and_bounded_preview() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/palms.jpeg"
        ))
        .expect("git lfs pull");
        assert_eq!(bytes.len(), 32_704_142, "git lfs pull");
        let file = ImageFile {
            name: "palms.jpeg".into(),
            bytes: bytes.into(),
        };
        let info = image_metadata(&file.bytes).unwrap();
        assert!(info.large);
        assert_eq!([info.width, info.height], [7198, 5384]);
        let Event::ChooseQuality(file) = (Work {
            kind: 0,
            quality: 60,
            keep_exif: false,
            files: Vec::new(),
            file,
        })
        .run() else {
            panic!("quality choice missing")
        };
        let Event::Import(Ok((stored, size))) = (Work {
            kind: 1,
            quality: 60,
            keep_exif: false,
            files: Vec::new(),
            file,
        })
        .run() else {
            panic!("compression failed")
        };
        assert!(size <= resources::MAX_COMPRESSED);
        assert!(stored.bytes.len() < 3_000_000);
        assert_eq!(decoder(&stored).unwrap().dimensions(), (7198, 5384));
        assert!(!has_exif(&stored));
        let (preview, natural) = preview(&stored).unwrap();
        assert_eq!(natural, [7198, 5384]);
        assert!(preview.width().max(preview.height()) <= PREVIEW_SIDE);
        for jpeg in [false, true] {
            let exported = export(&stored, jpeg).unwrap();
            assert_eq!(decoder(&exported).unwrap().dimensions(), (7198, 5384));
            assert!(!has_exif(&exported));
        }
    }
    #[test]
    fn exif_is_opt_in_and_exports_restore_orientation_once() {
        let exif = vec![
            73, 73, 42, 0, 8, 0, 0, 0, 1, 0, 18, 1, 3, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0,
        ];
        let pixels = image::RgbaImage::from_fn(2, 3, |x, y| {
            image::Rgba([x as u8 * 90, y as u8 * 60, 120, 255])
        });
        let mut bytes = Vec::new();
        let mut encoder = image::codecs::png::PngEncoder::new(&mut bytes);
        encoder.set_exif_metadata(exif.clone()).unwrap();
        encoder
            .write_image(pixels.as_raw(), 2, 3, image::ExtendedColorType::Rgba8)
            .unwrap();
        let source = ImageFile {
            name: "oriented.png".into(),
            bytes: bytes.into(),
        };
        let expected = decode(&source).unwrap().to_rgba8();
        assert_eq!(expected.dimensions(), (3, 2));
        assert!(has_exif(&source));
        for keep in [false, true] {
            let Event::Import(Ok((stored, _))) = prepare(Vec::new(), source.clone(), keep) else {
                panic!("EXIF import failed")
            };
            assert_eq!(has_exif(&stored), keep);
            assert_eq!(decode(&stored).unwrap().to_rgba8(), expected);
            for jpeg in [false, true] {
                let exported = export(&stored, jpeg).unwrap();
                assert_eq!(has_exif(&exported), keep);
                assert_eq!(decode(&exported).unwrap().to_rgba8().dimensions(), (3, 2));
                if keep {
                    assert_eq!(
                        decoder(&exported)
                            .unwrap()
                            .exif_metadata()
                            .unwrap()
                            .unwrap(),
                        exif
                    );
                }
            }
        }
    }
}
