use crate::resources::MAX_OPEN_MEMORY;
use std::io::{self, Cursor, Write};
use zeroize::Zeroizing;
mod preflight;

pub const MAX_INPUT: usize = 16 * 1024 * 1024;
pub const MAX_OUTPUT: usize = 4_000_000;
pub const MAX_DIMENSION: u32 = 8192;
pub const MAX_PIXELS: usize = 8 * 1024 * 1024;
const SCRATCH: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Png,
    Jpeg,
}
impl Format {
    pub fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    Png,
    Jpeg { quality: u8 },
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
    Limit,
    Allocation,
    Codec,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub format: Format,
    pub width: u32,
    pub height: u32,
    pub channels: u8,
    pub bit_depth: u8,
}
pub struct Decoded {
    info: Info,
    pixels: Zeroizing<Vec<u8>>,
    color: png::ColorType,
    depth: png::BitDepth,
}
pub struct Encoded {
    pub format: Format,
    pub bytes: Zeroizing<Vec<u8>>,
}
fn admission(w: u32, h: u32, input: usize, budget: usize) -> Result<(), Error> {
    preflight::geometry(w, h)?;
    let required = (w as usize + 31)
        .checked_mul(h as usize + 31)
        .and_then(|n| n.checked_mul(16))
        .and_then(|n| input.checked_mul(3)?.checked_add(n))
        .and_then(|n| n.checked_add(MAX_OUTPUT + SCRATCH))
        .ok_or(Error::Limit)?;
    if budget > MAX_OPEN_MEMORY || required > budget {
        return Err(Error::Limit);
    }
    Ok(())
}
fn zeroed(len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(len).map_err(|_| Error::Allocation)?;
    out.resize(len, 0);
    Ok(out)
}
fn png_error(e: png::DecodingError) -> Error {
    match e {
        png::DecodingError::LimitsExceeded => Error::Limit,
        _ => Error::Codec,
    }
}

pub fn decode(input: &[u8], memory_budget: usize) -> Result<Decoded, Error> {
    if !(MAX_OUTPUT + SCRATCH..=MAX_OPEN_MEMORY).contains(&memory_budget) {
        return Err(Error::Limit);
    }
    let (format, w, h) = preflight::inspect(input)?;
    admission(w, h, input.len(), memory_budget)?;
    let (pixels, color, depth) = match format {
        Format::Png => {
            preflight::png_stream(input)?;
            let mut decoder =
                png::Decoder::new_with_limits(Cursor::new(input), png::Limits { bytes: SCRATCH });
            decoder.set_ignore_text_chunk(true);
            decoder.set_ignore_iccp_chunk(true);
            decoder.set_transformations(png::Transformations::EXPAND);
            let mut reader = decoder.read_info().map_err(png_error)?;
            if reader.info().width != w || reader.info().height != h {
                return Err(Error::Invalid);
            }
            let size = reader.output_buffer_size().ok_or(Error::Limit)?;
            if size > MAX_PIXELS * 8 {
                return Err(Error::Limit);
            }
            let mut pixels = zeroed(size)?;
            let result = reader.next_frame(&mut pixels).map_err(png_error)?;
            reader.finish().map_err(png_error)?;
            pixels.truncate(result.buffer_size());
            (pixels, result.color_type, result.bit_depth)
        }
        Format::Jpeg => {
            let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(input));
            decoder.set_max_decoding_buffer_size(MAX_PIXELS * 3);
            decoder.read_info().map_err(|_| Error::Codec)?;
            let info = decoder.info().ok_or(Error::Invalid)?;
            if u32::from(info.width) != w || u32::from(info.height) != h {
                return Err(Error::Invalid);
            }
            let color = match info.pixel_format {
                jpeg_decoder::PixelFormat::L8 => png::ColorType::Grayscale,
                jpeg_decoder::PixelFormat::RGB24 => png::ColorType::Rgb,
                _ => return Err(Error::Unsupported),
            };
            // shortcut: upstream pixel scratch is not zeroized; revisit for a hardened decoder.
            let pixels = Zeroizing::new(decoder.decode().map_err(|_| Error::Codec)?);
            if pixels.len() != w as usize * h as usize * color.samples() {
                return Err(Error::Invalid);
            }
            (pixels, color, png::BitDepth::Eight)
        }
    };
    if !matches!(depth, png::BitDepth::Eight | png::BitDepth::Sixteen)
        || color == png::ColorType::Indexed
    {
        return Err(Error::Unsupported);
    }
    let info = Info {
        format,
        width: w,
        height: h,
        channels: color.samples() as u8,
        bit_depth: depth as u8,
    };
    Ok(Decoded {
        info,
        pixels,
        color,
        depth,
    })
}
pub fn validate(input: &[u8], memory_budget: usize) -> Result<Info, Error> {
    Ok(decode(input, memory_budget)?.info)
}
pub fn transcode(input: &[u8], output: Output, memory_budget: usize) -> Result<Encoded, Error> {
    if matches!(output, Output::Jpeg { quality } if !(1..=100).contains(&quality)) {
        return Err(Error::Invalid);
    }
    decode(input, memory_budget)?.encode(output, memory_budget)
}

struct Sink {
    bytes: Zeroizing<Vec<u8>>,
    exceeded: bool,
}
impl Sink {
    fn new() -> Result<Self, Error> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(MAX_OUTPUT)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            bytes,
            exceeded: false,
        })
    }
}
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > MAX_OUTPUT - self.bytes.len() {
            self.exceeded = true;
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Decoded {
    pub fn info(&self) -> Info {
        self.info
    }
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
    pub fn encode(&self, output: Output, memory_budget: usize) -> Result<Encoded, Error> {
        let extra = if matches!(output, Output::Jpeg { .. })
            && matches!(
                self.color,
                png::ColorType::GrayscaleAlpha | png::ColorType::Rgba
            ) {
            self.info.width as usize * self.info.height as usize * 3
        } else {
            0
        };
        let required = self
            .pixels
            .capacity()
            .checked_add(extra)
            .and_then(|n| n.checked_add(MAX_OUTPUT + SCRATCH))
            .ok_or(Error::Limit)?;
        if memory_budget > MAX_OPEN_MEMORY || required > memory_budget {
            return Err(Error::Limit);
        }
        if let Output::Jpeg { quality } = output {
            if !(1..=100).contains(&quality) {
                return Err(Error::Invalid);
            }
            if self.depth != png::BitDepth::Eight {
                return Err(Error::Unsupported);
            }
        }
        let mut sink = Sink::new()?;
        let result = match output {
            Output::Png => {
                let mut encoder = png::Encoder::new(&mut sink, self.info.width, self.info.height);
                encoder.set_color(self.color);
                encoder.set_depth(self.depth);
                encoder.set_compression(png::Compression::Balanced);
                (|| {
                    let mut writer = encoder.write_header().map_err(|_| Error::Codec)?;
                    let mut stream = writer
                        .stream_writer_with_size(65_536)
                        .map_err(|_| Error::Codec)?;
                    stream.write_all(&self.pixels).map_err(|_| Error::Codec)?;
                    stream.finish().map_err(|_| Error::Codec)?;
                    writer.finish().map_err(|_| Error::Codec)
                })()
            }
            Output::Jpeg { quality } => {
                let mut rgb = Zeroizing::new(Vec::new());
                let (data, color) = match self.color {
                    png::ColorType::Grayscale => (&self.pixels[..], jpeg_encoder::ColorType::Luma),
                    png::ColorType::Rgb => (&self.pixels[..], jpeg_encoder::ColorType::Rgb),
                    png::ColorType::GrayscaleAlpha | png::ColorType::Rgba => {
                        rgb.try_reserve_exact(extra)
                            .map_err(|_| Error::Allocation)?;
                        for pixel in self.pixels.chunks_exact(self.color.samples()) {
                            if pixel[pixel.len() - 1] != 255 {
                                return Err(Error::Unsupported);
                            }
                            if pixel.len() == 2 {
                                rgb.extend_from_slice(&[pixel[0]; 3]);
                            } else {
                                rgb.extend_from_slice(&pixel[..3]);
                            }
                        }
                        (&rgb[..], jpeg_encoder::ColorType::Rgb)
                    }
                    _ => return Err(Error::Unsupported),
                };
                jpeg_encoder::Encoder::new(&mut sink, quality)
                    .encode(data, self.info.width as u16, self.info.height as u16, color)
                    .map_err(|_| Error::Codec)
            }
        };
        if sink.exceeded {
            return Err(Error::Limit);
        }
        result?;
        Ok(Encoded {
            format: match output {
                Output::Png => Format::Png,
                Output::Jpeg { .. } => Format::Jpeg,
            },
            bytes: sink.bytes,
        })
    }
}
