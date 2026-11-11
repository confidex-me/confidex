//! Bounded messages for the image worker.
use super::*;

fn pack(files: Vec<ImageFile>, extra: Mapping) -> Result<Vec<u8>, Error> {
    let record = Record {
        tags: Vec::new(),
        entries: files
            .into_iter()
            .map(|mut file| Entry {
                name: std::mem::take(&mut file.name),
                type_name: "file/v1".into(),
                value: Mapping::from([(
                    "data".into(),
                    Value::Binary(std::mem::take(&mut *file.bytes)),
                )]),
                extra: Mapping::new(),
            })
            .collect(),
        extra,
    };
    let mut encoded = record
        .encode_content(resources::MAX_OPEN_MEMORY)
        .map_err(|_| Error::Limit)?
        .bytes;
    Ok(std::mem::take(&mut *encoded))
}
fn unpack(bytes: &[u8]) -> Result<(Vec<ImageFile>, Mapping), Error> {
    if bytes.len() > 2 * MAX_IMAGE_BYTES + 65_536 {
        return Err(Error::Limit);
    }
    let mut record = Record::decode_content(bytes, resources::MAX_OPEN_MEMORY)
        .map_err(|_| Error::Corrupt)?
        .record;
    if record.entries.len() > 65 {
        return Err(Error::Limit);
    }
    let files = record
        .entries
        .iter_mut()
        .map(|entry| {
            if entry.name.len() > 1024 {
                return Err(Error::Limit);
            }
            let Some(Value::Binary(bytes)) = entry.value.remove("data") else {
                return Err(Error::Corrupt);
            };
            Ok(ImageFile {
                name: std::mem::take(&mut entry.name),
                bytes: bytes.into(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((files, std::mem::take(&mut record.extra)))
}
fn number(extra: &Mapping, key: &str) -> Result<u64, Error> {
    extra.get(key).and_then(Value::as_u64).ok_or(Error::Corrupt)
}
fn error_code(error: Error) -> u64 {
    match error {
        Error::Format => 0,
        Error::Corrupt => 1,
        Error::Limit => 2,
        Error::Precision => 3,
        Error::Full => 4,
        Error::Processing => 5,
    }
}
fn read_error(extra: &Mapping) -> Result<Error, Error> {
    Ok(match number(extra, "error")? {
        0 => Error::Format,
        1 => Error::Corrupt,
        2 => Error::Limit,
        3 => Error::Precision,
        4 => Error::Full,
        5 => Error::Processing,
        _ => return Err(Error::Corrupt),
    })
}
pub(super) fn encode_work(work: Work) -> Result<Vec<u8>, Error> {
    let mut files = work.files;
    files.push(work.file);
    pack(
        files,
        Mapping::from([
            ("kind".into(), work.kind.into()),
            ("quality".into(), work.quality.into()),
            ("exif".into(), u64::from(work.keep_exif).into()),
        ]),
    )
}
fn decode_work(bytes: &[u8]) -> Result<Work, Error> {
    let (mut files, extra) = unpack(bytes)?;
    let kind = number(&extra, "kind")?;
    let quality = number(&extra, "quality")?;
    if kind > 4
        || !(1..=101).contains(&quality)
        || files.iter().any(|f| f.bytes.len() > MAX_IMAGE_BYTES)
    {
        return Err(Error::Limit);
    }
    let file = files.pop().ok_or(Error::Corrupt)?;
    Ok(Work {
        kind,
        quality: quality as u8,
        keep_exif: number(&extra, "exif")? == 1,
        files,
        file,
    })
}
fn encode_result(event: Event) -> Result<Vec<u8>, Error> {
    let mut extra = Mapping::new();
    let (kind, files) = match event {
        Event::Import(Ok((file, size))) => {
            extra.insert("size".into(), (size as u64).into());
            (0, vec![file])
        }
        Event::Import(Err((error, file))) => {
            extra.insert("error".into(), error_code(error).into());
            (1, file.into_iter().collect())
        }
        Event::Preview(Ok((image, natural))) => {
            extra.insert("width".into(), image.width().into());
            extra.insert("height".into(), image.height().into());
            extra.insert("natural_width".into(), natural[0].into());
            extra.insert("natural_height".into(), natural[1].into());
            (
                2,
                vec![ImageFile {
                    name: String::new(),
                    bytes: image.into_rgba8().into_raw().into(),
                }],
            )
        }
        Event::Preview(Err(error)) => {
            extra.insert("error".into(), error_code(error).into());
            (3, vec![])
        }
        Event::Export(Ok(file)) => (4, vec![file]),
        Event::Export(Err(error)) => {
            extra.insert("error".into(), error_code(error).into());
            (5, vec![])
        }
        Event::DownloadReady => (6, vec![]),
        Event::ChooseQuality(file) => (7, vec![file]),
    };
    extra.insert("kind".into(), Value::from(kind));
    pack(files, extra)
}
pub(super) fn decode_result(bytes: &[u8]) -> Result<Event, Error> {
    let (mut files, extra) = unpack(bytes)?;
    let event = match number(&extra, "kind")? {
        0 => {
            let size = usize::try_from(number(&extra, "size")?).map_err(|_| Error::Limit)?;
            let file = files.pop().ok_or(Error::Corrupt)?;
            if size > resources::MAX_COMPRESSED
                || file.bytes.len() > MAX_IMAGE_BYTES
                || format(&file.bytes)? != ImageFormat::WebP
            {
                return Err(Error::Limit);
            }
            Event::Import(Ok((file, size)))
        }
        1 => Event::Import(Err((read_error(&extra)?, files.pop()))),
        2 => {
            let width = u32::try_from(number(&extra, "width")?).map_err(|_| Error::Limit)?;
            let height = u32::try_from(number(&extra, "height")?).map_err(|_| Error::Limit)?;
            if width == 0 || height == 0 || width > PREVIEW_SIDE || height > PREVIEW_SIDE {
                return Err(Error::Limit);
            }
            let mut file = files.pop().ok_or(Error::Corrupt)?;
            if file.bytes.len() != width as usize * height as usize * 4 {
                return Err(Error::Corrupt);
            }
            let pixels =
                image::RgbaImage::from_raw(width, height, std::mem::take(&mut *file.bytes))
                    .ok_or(Error::Corrupt)?;
            let natural = [
                number(&extra, "natural_width")?,
                number(&extra, "natural_height")?,
            ];
            if natural.contains(&0)
                || natural.iter().any(|&n| n > 16383)
                || natural[0] * natural[1] > MAX_SOURCE_PIXELS
            {
                return Err(Error::Limit);
            }
            Event::Preview(Ok((
                DynamicImage::ImageRgba8(pixels),
                [natural[0] as u32, natural[1] as u32],
            )))
        }
        3 => Event::Preview(Err(read_error(&extra)?)),
        4 => Event::Export(Ok(files.pop().ok_or(Error::Corrupt)?)),
        5 => Event::Export(Err(read_error(&extra)?)),
        6 => Event::DownloadReady,
        7 => {
            let file = files.pop().ok_or(Error::Corrupt)?;
            source_is_large(&file)?;
            Event::ChooseQuality(file)
        }
        _ => return Err(Error::Corrupt),
    };
    if !files.is_empty() {
        return Err(Error::Corrupt);
    }
    Ok(event)
}
/// Runs one gallery codec job. It does not use UI or filesystem APIs.
pub fn process_image_job(bytes: &[u8]) -> Result<Vec<u8>, String> {
    decode_work(bytes)
        .and_then(|work| encode_result(work.run()))
        .map_err(|_| "invalid image job".into())
}
pub fn browser_image_work(bytes: &[u8]) -> Result<(u64, u8, bool, ImageFile), String> {
    decode_work(bytes)
        .map(|work| (work.kind, work.quality, work.keep_exif, work.file))
        .map_err(|_| "invalid image job".into())
}
pub fn finish_image_import(work: &[u8], bytes: &[u8]) -> Result<Vec<u8>, String> {
    let run = || -> Result<Vec<u8>, Error> {
        let work = decode_work(work)?;
        if work.kind != 1 || bytes.len() > MAX_IMAGE_BYTES {
            return Err(Error::Limit);
        }
        let file = ImageFile {
            name: name_with_extension(&work.file.name, "webp"),
            bytes: bytes.to_vec().into(),
        };
        encode_result(prepare_stored(work.files, file))
    };
    run().map_err(|_| "invalid encoded image".into())
}
pub fn finish_image_preview(
    rgba: &[u8],
    width: u32,
    height: u32,
    natural_width: u32,
    natural_height: u32,
) -> Result<Vec<u8>, String> {
    if width == 0
        || height == 0
        || width > PREVIEW_SIDE
        || height > PREVIEW_SIDE
        || rgba.len() != width as usize * height as usize * 4
        || natural_width == 0
        || natural_height == 0
        || natural_width > 16383
        || natural_height > 16383
        || u64::from(natural_width) * u64::from(natural_height) > MAX_SOURCE_PIXELS
    {
        return Err("invalid preview".into());
    }
    let image =
        image::RgbaImage::from_raw(width, height, rgba.to_vec()).ok_or("invalid preview")?;
    let bytes = encode_result(Event::Preview(Ok((
        DynamicImage::ImageRgba8(image),
        [natural_width, natural_height],
    ))))
    .map_err(|_| "invalid preview")?;
    Ok(bytes)
}
pub fn image_full_result() -> Result<Vec<u8>, String> {
    encode_result(Event::Import(Err((Error::Full, None)))).map_err(|_| "invalid overflow".into())
}
pub fn image_download_result() -> Result<Vec<u8>, String> {
    encode_result(Event::DownloadReady).map_err(|_| "invalid download".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_results_keep_natural_size_and_reject_invalid_bounds() {
        let rgba = [255; 4 * 8 * 6];
        let result = finish_image_preview(&rgba, 8, 6, 7198, 5384).unwrap();
        let Event::Preview(Ok((image, natural))) = decode_result(&result).unwrap() else {
            panic!("preview missing")
        };
        assert_eq!([image.width(), image.height()], [8, 6]);
        assert_eq!(natural, [7198, 5384]);
        for dimensions in [(0, 5384), (16384, 1), (10000, 10000)] {
            assert!(finish_image_preview(&rgba, 8, 6, dimensions.0, dimensions.1).is_err());
        }
        assert!(finish_image_preview(&rgba[..4], 8, 6, 7198, 5384).is_err());
        assert!(matches!(
            decode_result(&image_download_result().unwrap()),
            Ok(Event::DownloadReady)
        ));
        let sample = samples().remove(0);
        let work = encode_work(Work {
            kind: 1,
            quality: 60,
            keep_exif: false,
            files: Vec::new(),
            file: ImageFile {
                name: "original.jpeg".into(),
                bytes: Vec::new().into(),
            },
        })
        .unwrap();
        assert!(matches!(
            decode_result(&finish_image_import(&work, &sample.bytes).unwrap()),
            Ok(Event::Import(Ok(_)))
        ));
        assert!(
            finish_image_import(&work, b"invalid WebP")
                .is_ok_and(|b| matches!(decode_result(&b), Ok(Event::Import(Err(_)))))
        );
    }
    #[test]
    fn worker_roundtrip_and_invalid_messages() {
        let file = samples().remove(0);
        for kind in [0, 1, 2, 3, 4] {
            let input = encode_work(Work {
                kind,
                quality: 60,
                keep_exif: false,
                files: Vec::new(),
                file: file.clone(),
            })
            .unwrap();
            let reply = process_image_job(&input).unwrap();
            assert!(decode_result(&reply).is_ok());
            assert!(process_image_job(&input[..input.len() - 1]).is_err());
        }
        assert!(process_image_job(&[0; 16]).is_err());
        assert!(decode_result(&[0; 16]).is_err());
    }
}
