use confidex_vault::{
    photo::{self, Error, Format, Output},
    record::{Entry, Mapping, Record, Value},
    resources::MAX_OPEN_MEMORY,
};
use std::io::Write;

fn png(w: u32, h: u32, color: png::ColorType, depth: png::BitDepth, pixels: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, w, h);
        encoder.set_color(color);
        encoder.set_depth(depth);
        let mut writer = encoder.write_header().unwrap();
        let mut stream = writer.stream_writer_with_size(65536).unwrap();
        stream.write_all(pixels).unwrap();
        stream.finish().unwrap();
        writer.finish().unwrap();
    }
    bytes
}
fn jpeg(w: u16, h: u16, pixels: &[u8], progressive: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = jpeg_encoder::Encoder::new(&mut bytes, 90);
    encoder.set_progressive(progressive);
    encoder
        .encode(pixels, w, h, jpeg_encoder::ColorType::Rgb)
        .unwrap();
    bytes
}
fn chunk(ty: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(ty);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32fast::hash(&out[4..]).to_be_bytes());
    out
}
fn header(w: u32, h: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&w.to_be_bytes());
    data.extend_from_slice(&h.to_be_bytes());
    data.extend_from_slice(&[8, 6, 0, 0, 0]);
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &data));
    out
}

#[test]
fn png_preserves_samples_and_expands_palettes_without_losing_16_bit_precision() {
    for (color, depth, pixels) in [
        (
            png::ColorType::Rgba,
            png::BitDepth::Eight,
            vec![1, 2, 3, 255, 7, 8, 9, 50],
        ),
        (
            png::ColorType::Grayscale,
            png::BitDepth::Sixteen,
            vec![0x12, 0x34, 0xab, 0xcd],
        ),
    ] {
        let source = png(2, 1, color, depth, &pixels);
        let saved = source.clone();
        let decoded = photo::decode(&source, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(decoded.pixels(), pixels);
        assert_eq!(decoded.info().bit_depth, depth as u8);
        let encoded = decoded.encode(Output::Png, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(encoded.format, Format::Png);
        assert_eq!(
            photo::decode(&encoded.bytes, MAX_OPEN_MEMORY)
                .unwrap()
                .pixels(),
            pixels
        );
        assert_eq!(source, saved);
    }
    let mut palette = Vec::new();
    {
        let mut e = png::Encoder::new(&mut palette, 2, 1);
        e.set_color(png::ColorType::Indexed);
        e.set_depth(png::BitDepth::Eight);
        e.set_palette(vec![255, 0, 0, 0, 0, 255]);
        e.set_trns(vec![255, 0]);
        e.write_header().unwrap().write_image_data(&[0, 1]).unwrap();
    }
    let decoded = photo::decode(&palette, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(decoded.pixels(), [255, 0, 0, 255, 0, 0, 255, 0]);
    assert_eq!(decoded.info().channels, 4);
}

#[test]
fn sequential_and_progressive_jpeg_can_be_validated_and_converted_explicitly() {
    let pixels = [200, 30, 10].repeat(16 * 16);
    for progressive in [false, true] {
        let source = jpeg(16, 16, &pixels, progressive);
        let info = photo::validate(&source, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            (info.format, info.width, info.height, info.channels),
            (Format::Jpeg, 16, 16, 3)
        );
        let output = photo::transcode(&source, Output::Png, MAX_OPEN_MEMORY).unwrap();
        let decoded = photo::decode(&output.bytes, MAX_OPEN_MEMORY).unwrap();
        assert_eq!(decoded.info().format, Format::Png);
        assert_eq!(decoded.pixels().len(), pixels.len());
        assert!(
            decoded
                .pixels()
                .iter()
                .zip(&pixels)
                .all(|(a, b)| a.abs_diff(*b) <= 5)
        );
        let encoded = decoded
            .encode(Output::Jpeg { quality: 95 }, MAX_OPEN_MEMORY)
            .unwrap();
        assert_eq!(
            photo::validate(&encoded.bytes, MAX_OPEN_MEMORY)
                .unwrap()
                .format,
            Format::Jpeg
        );
    }
}

#[test]
fn byte_geometry_pixel_and_memory_limits_fail_before_codec_materialization() {
    assert_eq!(
        photo::validate(&vec![0; photo::MAX_INPUT + 1], MAX_OPEN_MEMORY),
        Err(Error::Limit)
    );
    for (w, h) in [(0, 1), (1, 0), (8193, 1), (4096, 2049)] {
        let bytes = header(w, h);
        let error = if w == 0 || h == 0 {
            Error::Invalid
        } else {
            Error::Limit
        };
        assert_eq!(photo::validate(&bytes, MAX_OPEN_MEMORY), Err(error));
    }
    let source = png(
        4096,
        2048,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &vec![0; photo::MAX_PIXELS],
    );
    let info = photo::validate(&source, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        info.width as usize * info.height as usize,
        photo::MAX_PIXELS
    );
    for budget in [0, 64 * 1024 * 1024, MAX_OPEN_MEMORY + 1] {
        assert_eq!(photo::validate(&source, budget), Err(Error::Limit));
    }
    let small = jpeg(2, 2, &[30, 50, 80].repeat(4), false);
    let mut boundary = Vec::with_capacity(photo::MAX_INPUT);
    boundary.extend_from_slice(&small[..2]);
    let mut padding = photo::MAX_INPUT - small.len();
    while padding != 0 {
        let mut length = padding.min(65_537);
        if (1..=3).contains(&(padding - length)) {
            length -= 4 - (padding - length);
        }
        boundary.extend_from_slice(&[255, 239]);
        boundary.extend_from_slice(&((length - 2) as u16).to_be_bytes());
        boundary.resize(boundary.len() + length - 4, 0);
        padding -= length;
    }
    boundary.extend_from_slice(&small[2..]);
    assert_eq!(boundary.len(), photo::MAX_INPUT);
    assert_eq!(
        photo::validate(&boundary, MAX_OPEN_MEMORY).unwrap().width,
        2
    );
    boundary.push(0);
    assert_eq!(
        photo::validate(&boundary, MAX_OPEN_MEMORY),
        Err(Error::Limit)
    );
}

#[test]
fn truncated_corrupt_trailing_animated_and_oversized_pixel_streams_are_rejected() {
    let source = png(
        1,
        1,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &[1, 2, 3, 255],
    );
    for end in 0..source.len() {
        assert!(photo::validate(&source[..end], MAX_OPEN_MEMORY).is_err());
    }
    let mut bad = source.clone();
    bad[20] ^= 1;
    assert_eq!(photo::validate(&bad, MAX_OPEN_MEMORY), Err(Error::Invalid));
    let mut trailing = source.clone();
    trailing.push(0);
    assert_eq!(
        photo::validate(&trailing, MAX_OPEN_MEMORY),
        Err(Error::Invalid)
    );
    let mut animated = source[..33].to_vec();
    animated.extend(chunk(b"acTL", &[0, 0, 0, 1, 0, 0, 0, 0]));
    animated.extend_from_slice(&source[33..]);
    assert_eq!(
        photo::validate(&animated, MAX_OPEN_MEMORY),
        Err(Error::Unsupported)
    );
    let mut deflate = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    deflate.write_all(&vec![0; 1024 * 1024]).unwrap();
    let compressed = deflate.finish().unwrap();
    let mut bomb = header(1, 1);
    bomb.extend(chunk(b"IDAT", &compressed));
    bomb.extend(chunk(b"IEND", &[]));
    assert_eq!(photo::validate(&bomb, MAX_OPEN_MEMORY), Err(Error::Limit));
    let jpeg = jpeg(2, 2, &[40, 80, 120].repeat(4), false);
    for end in 0..jpeg.len() {
        assert!(photo::validate(&jpeg[..end], MAX_OPEN_MEMORY).is_err());
    }
    for offset in 0..jpeg.len() {
        let mut mutated = jpeg.clone();
        mutated[offset] ^= 128;
        let _ = photo::validate(&mutated, MAX_OPEN_MEMORY);
    }
    let mut bad = jpeg.clone();
    bad.push(0);
    assert_eq!(photo::validate(&bad, MAX_OPEN_MEMORY), Err(Error::Invalid));
}

#[test]
fn alpha_precision_and_quality_require_explicit_supported_output_choices() {
    let alpha = png(
        1,
        1,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &[1, 2, 3, 10],
    );
    assert!(matches!(
        photo::transcode(&alpha, Output::Jpeg { quality: 90 }, MAX_OPEN_MEMORY),
        Err(Error::Unsupported)
    ));
    let wide = png(
        1,
        1,
        png::ColorType::Grayscale,
        png::BitDepth::Sixteen,
        &[0x12, 0x34],
    );
    assert!(matches!(
        photo::transcode(&wide, Output::Jpeg { quality: 90 }, MAX_OPEN_MEMORY),
        Err(Error::Unsupported)
    ));
    for quality in [0, 101, 255] {
        assert!(matches!(
            photo::transcode(&alpha, Output::Jpeg { quality }, MAX_OPEN_MEMORY),
            Err(Error::Invalid)
        ));
    }
    let opaque = png(
        1,
        1,
        png::ColorType::GrayscaleAlpha,
        png::BitDepth::Eight,
        &[40, 255],
    );
    let result = photo::transcode(&opaque, Output::Jpeg { quality: 100 }, MAX_OPEN_MEMORY).unwrap();
    assert_eq!(
        photo::validate(&result.bytes, MAX_OPEN_MEMORY)
            .unwrap()
            .format,
        Format::Jpeg
    );
}

#[test]
fn record_shape_validation_and_reading_do_not_run_an_image_decoder() {
    let entry = Entry {
        name: "photo".into(),
        type_name: "photo/v1".into(),
        value: Mapping::from([
            ("data".into(), Value::Binary(b"not an image".to_vec())),
            ("mime".into(), "image/png".into()),
        ]),
        extra: Mapping::new(),
    };
    entry.validate_value().unwrap();
    let record = Record {
        tags: Vec::new(),
        entries: vec![entry],
        extra: Mapping::new(),
    };
    let encoded = record.encode_content(MAX_OPEN_MEMORY).unwrap();
    let decoded = Record::decode_content(&encoded.bytes, MAX_OPEN_MEMORY).unwrap();
    let Value::Binary(data) = &decoded.record.entries[0].value["data"] else {
        unreachable!()
    };
    assert_eq!(data, b"not an image");
    assert_eq!(
        photo::validate(data, MAX_OPEN_MEMORY),
        Err(Error::Unsupported)
    );
}

#[test]
fn output_size_and_container_work_counters_are_bounded() {
    let source = png(1, 1, png::ColorType::Grayscale, png::BitDepth::Eight, &[0]);
    let mut count = 0;
    let mut p = 8;
    while p < source.len() {
        count += 1;
        p += 12 + u32::from_be_bytes(source[p..p + 4].try_into().unwrap()) as usize;
    }
    for target in [1024, 1025] {
        let mut data = source[..33].to_vec();
        for _ in count..target {
            data.extend(chunk(b"tEXt", &[]));
        }
        data.extend_from_slice(&source[33..]);
        assert_eq!(
            photo::validate(&data, MAX_OPEN_MEMORY).is_ok(),
            target == 1024
        );
    }
    let mut scans = vec![255, 216, 255, 192, 0, 11, 8, 0, 1, 0, 1, 1, 1, 0x11, 0];
    for _ in 0..65 {
        scans.extend_from_slice(&[255, 218, 0, 8, 1, 1, 0, 0, 63, 0, 0]);
    }
    scans.extend_from_slice(&[255, 217]);
    assert_eq!(photo::validate(&scans, MAX_OPEN_MEMORY), Err(Error::Limit));
    let mut pixels = vec![0; 1024 * 2048 * 3];
    let mut state = 7u32;
    for b in &mut pixels {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *b = state as u8;
    }
    let source = jpeg(1024, 2048, &pixels, false);
    assert!(source.len() < photo::MAX_INPUT);
    assert!(matches!(
        photo::transcode(&source, Output::Png, MAX_OPEN_MEMORY),
        Err(Error::Limit)
    ));
}

#[test]
fn encoded_photos_remain_inside_encrypted_record_values() {
    use confidex_vault::{
        crypto::{VaultKeys, clamp_material},
        envelope::{self, EventKind, Options},
        trust::TrustAnchor,
    };
    let source = png(
        2,
        2,
        png::ColorType::Rgb,
        png::BitDepth::Eight,
        &[50, 80, 100].repeat(4),
    );
    let record = Record {
        tags: Vec::new(),
        entries: vec![Entry {
            name: "document scan".into(),
            type_name: "photo/v1".into(),
            value: Mapping::from([
                ("data".into(), Value::Binary(source.clone())),
                ("mime".into(), "image/png".into()),
            ]),
            extra: Mapping::new(),
        }],
        extra: Mapping::new(),
    };
    let keys = VaultKeys::from_material(1, &clamp_material([3; 32])[..]).unwrap();
    let pin = TrustAnchor::from_local_pin(
        [7; 16],
        Some(&keys.signing_key().verifying_key().to_bytes()),
    )
    .unwrap();
    let wire = envelope::seal(
        &record,
        &keys,
        Options {
            vault_id: [7; 16],
            record_id: [8; 16],
            parents: &[],
            epoch: 0,
            kind: EventKind::Content,
        },
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    let opened = envelope::open(&wire, &keys, &pin, None, MAX_OPEN_MEMORY).unwrap();
    opened.record.entries[0].validate_value().unwrap();
    let Value::Binary(data) = &opened.record.entries[0].value["data"] else {
        unreachable!()
    };
    assert_eq!(data, &source);
    assert_eq!(photo::validate(data, MAX_OPEN_MEMORY).unwrap().width, 2);
}

#[test]
fn compressed_text_and_icc_metadata_are_never_expanded() {
    let source = png(1, 1, png::ColorType::Rgb, png::BitDepth::Eight, &[1, 2, 3]);
    let mut compressor = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    compressor.write_all(&vec![0; 32 * 1024 * 1024]).unwrap();
    let compressed = compressor.finish().unwrap();
    let mut metadata = b"opaque\0\0".to_vec();
    metadata.extend_from_slice(&compressed);
    let mut with_metadata = source[..33].to_vec();
    with_metadata.extend(chunk(b"zTXt", &metadata));
    with_metadata.extend(chunk(b"iCCP", &metadata));
    with_metadata.extend_from_slice(&source[33..]);
    assert_eq!(
        photo::decode(&with_metadata, 21 * 1024 * 1024)
            .unwrap()
            .pixels(),
        [1, 2, 3]
    );
}
