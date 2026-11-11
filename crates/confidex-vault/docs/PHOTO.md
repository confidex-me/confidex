# Explicit photo operations

Store `photo/v1` as a value mapping with `data: bin` and optional `mime: str`.
Additional value/entry fields remain intact. `Entry::validate_value` checks this
storage shape only. Record reading never runs an image decoder. Call
`photo::validate(bytes, budget)` explicitly to decode and validate the pixels;
the returned Info reports the format, dimensions, channels, and bit depth from
the bytes. A stored MIME hint does not select a decoder.

`photo::decode` returns owned, zeroizing pixels with read-only access. PNG palette
and low-bit samples expand to 8-bit channels; 16-bit PNG samples retain their
big-endian bytes and precision. `photo::transcode(input, output, budget)` or
`decoded.encode(output, budget)` returns a separate zeroizing encoded buffer.
Choose lossless PNG or JPEG with an explicit quality from 1 through 100. JPEG
output accepts 8-bit grayscale/RGB; fully opaque alpha may be removed, while
transparency and 16-bit input require another output choice. Inputs are borrowed
and remain unchanged on success and failure.

Transcoding uses raw encoded pixel order, omits ancillary/EXIF/color-profile
metadata, and does not apply orientation or color management. The application
chooses whether to keep the original or request conversion. No automatic resize,
file replacement, photo import, or filesystem access occurs in this API.

## Decoder profile 1

| Quantity | Inclusive ceiling |
| --- | ---: |
| Encoded decoder input | 16 MiB |
| Width and height | 8,192 each |
| Pixels | 8,388,608 |
| PNG chunks | 1,024 |
| PNG frames | 1, non-interlaced |
| JPEG non-restart markers after SOI | 1,024 |
| JPEG scans | 64 |
| Encoded conversion output | 4,000,000 bytes |
| Operation live-memory budget | 192 MiB |

Supported PNG color/depth combinations include grayscale, RGB, alpha, and indexed
palettes with their standard depths. APNG/Adam7 are outside this profile. JPEG
supports 8-bit, one- or three-component Huffman DCT, sequential or progressive.
CMYK, higher precision/lossless JPEG, additional frames, and other file formats
return Unsupported. A resource failure does not prove that the image is corrupt.
These decoder/conversion ceilings are separate from the Record limit: the whole
serialized compressed Record must still fit its own 4,000,000-byte ceiling when
sealed, including all entries and mapping overhead.

Before codec construction, a nonallocating framing pass checks CRCs/chunk counts,
single-file consumption, supported PNG IHDR fields, JPEG frames/segments/scans,
and dimensions. PNG IDAT is independently inflated into a fixed 64 KiB scratch
buffer, checking the exact filtered-raster length, checksum, stream end, and no
extra stream/data. Excess raster output stops before allocating pixels. Text and
ICC metadata are opaque and never decompressed; their CRC bytes are still checked.

Admission reserves `16*(width+31)*(height+31) + 3*input_bytes + 4,000,000 + 16 MiB`
within the caller budget before decoding. Padding bounds JPEG component/MCU
geometry; the raster allowance covers progressive coefficients, component planes,
and output, or PNG raw/expanded samples. Input copies/metadata and fixed codec/row
scratch have separate allowances. Decoder output size and dimensions are checked
again. PNG also receives a 16 MiB internal working limit; JPEG gets an explicit
output-buffer cap. Limits apply together, so some combinations of maximum input
and geometry exceed the memory budget and return Limit.

Encoding separately charges pixel capacity, any alpha-to-RGB copy, bounded output,
and 16 MiB working space. PNG uses a streaming encoder with 64 KiB chunks rather
than accumulating an unbounded compressed image. JPEG uses the selected baseline
encoder defaults. The checked Write sink caps output even during encoding.

The selected pure Rust codecs are pinned: png 0.18.1, jpeg-decoder 0.3.2 with
Rayon disabled and platform-independent decoding, and jpeg-encoder 0.7.1 without
SIMD features. Review geometry/allocation paths and feature unification when
upgrading. Core-owned pixels/encoded buffers are cleared on drop; codec-owned
temporary pixel/DEFLATE scratch is not guaranteed to be zeroized by upstream.
Allocator bookkeeping, process exhaustion, and WASM retained pages remain the
platform limitations described in the resource profile. Caller-owned input,
unrelated Records, and concurrent operations must fit the application's memory.
