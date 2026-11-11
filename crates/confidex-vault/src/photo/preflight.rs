use super::{Error, Format, MAX_DIMENSION, MAX_INPUT, MAX_PIXELS};

pub(super) fn geometry(w: u32, h: u32) -> Result<(), Error> {
    if w == 0 || h == 0 {
        return Err(Error::Invalid);
    }
    if w > MAX_DIMENSION || h > MAX_DIMENSION || u64::from(w) * u64::from(h) > MAX_PIXELS as u64 {
        return Err(Error::Limit);
    }
    Ok(())
}
pub(super) fn inspect(input: &[u8]) -> Result<(Format, u32, u32), Error> {
    if input.len() > MAX_INPUT {
        return Err(Error::Limit);
    }
    if input.starts_with(b"\x89PNG\r\n\x1a\n") {
        png(input).map(|(w, h)| (Format::Png, w, h))
    } else if input.starts_with(&[255, 216]) {
        jpeg(input).map(|(w, h)| (Format::Jpeg, w, h))
    } else {
        Err(Error::Unsupported)
    }
}
fn png(input: &[u8]) -> Result<(u32, u32), Error> {
    let mut rest = &input[8..];
    let mut dimensions = None;
    let mut idat = false;
    let mut closed = false;
    for index in 0..1024 {
        let prefix = rest.get(..8).ok_or(Error::Invalid)?;
        let len = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize;
        let (chunk, tail) = rest
            .split_at_checked(12usize.checked_add(len).ok_or(Error::Limit)?)
            .ok_or(Error::Invalid)?;
        let ty = &chunk[4..8];
        let data = &chunk[8..8 + len];
        let crc = u32::from_be_bytes(chunk[8 + len..].try_into().unwrap());
        if crc32fast::hash(&chunk[4..8 + len]) != crc {
            return Err(Error::Invalid);
        }
        if index == 0 && ty != b"IHDR" {
            return Err(Error::Invalid);
        }
        match ty {
            b"IHDR" => {
                if index != 0 || len != 13 {
                    return Err(Error::Invalid);
                }
                let legal = match data[9] {
                    0 => matches!(data[8], 1 | 2 | 4 | 8 | 16),
                    2 | 4 | 6 => matches!(data[8], 8 | 16),
                    3 => matches!(data[8], 1 | 2 | 4 | 8),
                    _ => false,
                };
                if !legal || data[10] != 0 || data[11] != 0 {
                    return Err(Error::Invalid);
                }
                if data[12] != 0 {
                    return Err(Error::Unsupported);
                }
                let w = u32::from_be_bytes(data[..4].try_into().unwrap());
                let h = u32::from_be_bytes(data[4..8].try_into().unwrap());
                geometry(w, h)?;
                dimensions = Some((w, h));
            }
            b"acTL" | b"fcTL" | b"fdAT" => return Err(Error::Unsupported),
            b"IDAT" => {
                if closed {
                    return Err(Error::Invalid);
                }
                idat = true;
            }
            b"IEND" => {
                if len != 0 || !idat || !tail.is_empty() {
                    return Err(Error::Invalid);
                }
                return dimensions.ok_or(Error::Invalid);
            }
            _ => {
                if idat {
                    closed = true;
                }
            }
        }
        rest = tail;
    }
    Err(Error::Limit)
}
fn jpeg(input: &[u8]) -> Result<(u32, u32), Error> {
    let mut pos = 2;
    let mut dimensions = None;
    let mut entropy = false;
    let mut markers = 0;
    let mut scans = 0;
    while pos < input.len() {
        if entropy {
            pos += input[pos..]
                .iter()
                .position(|b| *b == 255)
                .ok_or(Error::Invalid)?;
        } else if input[pos] != 255 {
            return Err(Error::Invalid);
        }
        while input.get(pos) == Some(&255) {
            pos += 1;
        }
        let marker = *input.get(pos).ok_or(Error::Invalid)?;
        pos += 1;
        if entropy && (marker == 0 || (0xd0..=0xd7).contains(&marker)) {
            continue;
        }
        entropy = false;
        markers += 1;
        if markers > 1024 {
            return Err(Error::Limit);
        }
        match marker {
            0xd9 => {
                if pos != input.len() || scans == 0 {
                    return Err(Error::Invalid);
                }
                return dimensions.ok_or(Error::Invalid);
            }
            0 | 0xd8 | 0xd0..=0xd7 => return Err(Error::Invalid),
            0x01 => continue,
            0xdc | 0xde | 0xdf => return Err(Error::Unsupported),
            0xc0..=0xcf if !matches!(marker, 0xc0 | 0xc1 | 0xc2 | 0xc4 | 0xcc) => {
                return Err(Error::Unsupported);
            }
            _ => (),
        }
        let length = input.get(pos..pos + 2).ok_or(Error::Invalid)?;
        let length = u16::from_be_bytes(length.try_into().unwrap()) as usize;
        if length < 2 {
            return Err(Error::Invalid);
        }
        let segment = input
            .get(pos + 2..pos.checked_add(length).ok_or(Error::Limit)?)
            .ok_or(Error::Invalid)?;
        pos += length;
        if matches!(marker, 0xc0..=0xc2) {
            if dimensions.is_some() || segment.len() < 6 {
                return Err(Error::Invalid);
            }
            if segment[0] != 8 || !matches!(segment[5], 1 | 3) {
                return Err(Error::Unsupported);
            }
            if segment.len() != 6 + 3 * usize::from(segment[5]) {
                return Err(Error::Invalid);
            }
            let h = u32::from(u16::from_be_bytes(segment[1..3].try_into().unwrap()));
            let w = u32::from(u16::from_be_bytes(segment[3..5].try_into().unwrap()));
            geometry(w, h)?;
            dimensions = Some((w, h));
        }
        if marker == 0xda {
            if dimensions.is_none() {
                return Err(Error::Invalid);
            }
            scans += 1;
            if scans > 64 {
                return Err(Error::Limit);
            }
            entropy = true;
        }
    }
    Err(Error::Invalid)
}

// The framing pass has checked every chunk range and the fixed IHDR fields.
pub(super) fn png_stream(input: &[u8]) -> Result<(), Error> {
    use flate2::{Decompress, FlushDecompress, Status};
    use zeroize::Zeroizing;
    let w = u32::from_be_bytes(input[16..20].try_into().unwrap()) as usize;
    let h = u32::from_be_bytes(input[20..24].try_into().unwrap()) as usize;
    let channels = match input[25] {
        0 | 3 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => return Err(Error::Invalid),
    };
    let expected = ((w * channels * usize::from(input[24])).div_ceil(8) + 1) * h;
    let mut decoder = Decompress::new(true);
    let mut scratch = Zeroizing::new([0; 65_536]);
    let mut output = 0;
    let mut ended = false;
    let mut rest = &input[8..];
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        if &rest[4..8] == b"IDAT" {
            let data = &rest[8..8 + len];
            if ended && !data.is_empty() {
                return Err(Error::Invalid);
            }
            let mut consumed = 0;
            while !ended {
                let before_in = decoder.total_in();
                let before_out = decoder.total_out();
                let room = scratch.len().min(expected - output + 1);
                let status = decoder
                    .decompress(
                        &data[consumed..],
                        &mut scratch[..room],
                        FlushDecompress::None,
                    )
                    .map_err(|_| Error::Codec)?;
                let read = (decoder.total_in() - before_in) as usize;
                let written = (decoder.total_out() - before_out) as usize;
                if written > expected - output {
                    return Err(Error::Limit);
                }
                consumed += read;
                output += written;
                if status == Status::StreamEnd {
                    if consumed != data.len() || output != expected {
                        return Err(Error::Invalid);
                    }
                    ended = true;
                } else if read == 0 && written == 0 {
                    if consumed != data.len() {
                        return Err(Error::Codec);
                    }
                    break;
                }
            }
        }
        rest = &rest[12 + len..];
    }
    if !ended {
        return Err(Error::Codec);
    }
    Ok(())
}
