#![cfg(not(target_arch = "wasm32"))]

use image::{DynamicImage, GenericImageView, ImageFormat, RgbImage, RgbaImage};
use std::io::Cursor;
use webp_rust::{ImageBuffer, LosslessEncodingConfig, LossyEncodingConfig};

fn pixels() -> ImageBuffer {
    let mut rgba = Vec::new();
    for y in 0..32 {
        for x in 0..32 {
            rgba.extend_from_slice(&[
                (x * 43 + y * 7) as u8,
                (x * 11 + y * 29) as u8,
                (x * 17 + y * 13) as u8,
                (30 + (x * 7 + y * 11) % 200) as u8,
            ]);
        }
    }
    rgba[3] = 0;
    rgba[7] = 255;
    ImageBuffer {
        width: 32,
        height: 32,
        rgba,
    }
}

#[test]
fn webp_lossless_preserves_pixels_and_lossy_preserves_alpha_with_an_independent_decoder() {
    let source = pixels();
    let bytes =
        webp_rust::encode_lossless_with_config(&source, &LosslessEncodingConfig::default(), None)
            .unwrap();
    let decoded = image::load_from_memory(&bytes).unwrap().to_rgba8();
    assert_eq!(decoded.as_raw(), &source.rgba);
    assert_eq!(webp_rust::decode(&bytes).unwrap(), source);
    let mut sizes = Vec::new();
    for quality in [75., 45.] {
        let config = LossyEncodingConfig {
            quality,
            ..Default::default()
        };
        let bytes = webp_rust::encode_lossy_with_config(&source, &config, None).unwrap();
        let decoded = image::load_from_memory(&bytes).unwrap().to_rgba8();
        assert_eq!(decoded.dimensions(), (32, 32));
        assert!(
            decoded
                .as_raw()
                .as_chunks::<4>()
                .0
                .iter()
                .zip(source.rgba.as_chunks::<4>().0)
                .all(|(a, b)| a[3] == b[3])
        );
        sizes.push(bytes.len());
    }
    assert!(sizes[1] < sizes[0], "{sizes:?}");
}

#[test]
fn native_png_and_jpeg_codecs_support_import_and_export() {
    let source = pixels();
    let rgba = RgbaImage::from_raw(32, 32, source.rgba).unwrap();
    let mut png = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(rgba.clone())
        .write_to(&mut png, ImageFormat::Png)
        .unwrap();
    assert_eq!(
        image::load_from_memory(png.get_ref()).unwrap().to_rgba8(),
        rgba
    );
    let rgb = DynamicImage::ImageRgb8(RgbImage::from_pixel(16, 16, image::Rgb([90, 140, 180])));
    let mut jpeg = Cursor::new(Vec::new());
    rgb.write_to(&mut jpeg, ImageFormat::Jpeg).unwrap();
    assert_eq!(
        image::load_from_memory(jpeg.get_ref())
            .unwrap()
            .dimensions(),
        (16, 16)
    );
}
