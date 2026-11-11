# Image codec dependencies

The application has these codecs available for later image import, protected
preview and export. Supported formats are JPEG, PNG and WebP on both native
and browser hosts. This change does not add those UI flows or convert stored
images. Import must use this allowlist even if a platform decoder accepts more
formats.

| Dependency | Targets | Purpose |
| --- | --- | --- |
| `webp-rust` 0.3.2 | Native and browser WASM | Pure Rust lossless/lossy WebP encoding and decoding, including alpha |
| `image` 0.25.10 | Native | PNG, JPEG and WebP decoding; PNG/JPEG encoding |

`tests/image_codecs.rs` checks WebP output with the independent `image` decoder,
including lossless pixels and unchanged alpha at lossy quality 75 and 45. It
also checks PNG/JPEG round trips. Browser decoding can use platform APIs. WebP
encoding remains available in Rust so a caller can request true lossless encoding.

These dependencies are not an input-validation boundary. Import and reveal must
apply dimensions, decoded-byte and work limits before allocation, and the full
Record must still fit its own compressed size limit. The core `photo` profile
continues to validate only its existing PNG/JPEG subset.

Native exports must account for transparency: PNG can preserve it; JPEG needs
an explicit background. Lossy encoding quality is not a percentage of bytes
saved, and changing quality does not reduce pixel dimensions.

The image storage policy is WebP for every Record image. The UI gallery now
exercises this policy with JPEG/PNG/WebP import, protected reveal, explicit
lossy quality slider, and WebP/PNG/JPEG export. JPEG/PNG first become
lossless WebP; no lossy conversion happens without a user's choice. Lossless is
the default when the complete Record fits; otherwise the initial quality is
approximated. EXIF retention is opt-in and preserved metadata returns on export. The working
vault application's attachment flow remains separate. See the
[image implementation](../../../crates/confidex-ui/src/images.rs) for its
resource profile, browser processing limit and fixture commands.

The gallery uses encoder method1. Method4 in webp-rust0.3.2 fails its internal
filter check on a valid public gradient fixture; method1 passes independent
decoding and alpha checks. Encoding failures leave existing attachments unchanged.
