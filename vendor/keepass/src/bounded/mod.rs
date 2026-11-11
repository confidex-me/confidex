//! Resource boundaries for the Confidex raw decoder extension.
mod limits;
pub use limits::{Error, Limits};
mod header;
pub use header::Header;
mod raw;
pub use raw::{Binary, Phase, Protected, Raw};
#[cfg(feature = "save_kdbx4")]
mod save;
#[cfg(feature = "save_kdbx4")]
pub use save::{save, Encoder, Encrypted, SaveError, SaveEvent};

use flate2::bufread::GzDecoder;
use std::{
    convert::TryInto,
    io::{self, Read},
};
use zeroize::Zeroizing;

const SCRATCH: usize = 1 << 20;
const CHUNK: usize = 65_536;
const HEADER: usize = 65_536;

fn error(kind: io::ErrorKind) -> io::Error {
    io::Error::from(kind)
}
fn header(input: &[u8]) -> io::Result<()> {
    let flags = *input
        .get(3)
        .ok_or_else(|| error(io::ErrorKind::InvalidData))?;
    if input.len() < 10 || input.get(..3) != Some(&[0x1f, 0x8b, 8]) || flags & 0xe0 != 0 {
        return Err(error(io::ErrorKind::InvalidData));
    }
    let mut at = 10usize;
    if flags & 4 != 0 {
        let size = input
            .get(at..at + 2)
            .ok_or_else(|| error(io::ErrorKind::InvalidData))?;
        at += 2 + u16::from_le_bytes(
            size.try_into()
                .map_err(|_| error(io::ErrorKind::InvalidData))?,
        ) as usize;
    }
    for flag in [8, 16] {
        if flags & flag != 0 {
            let stop = input.len().min(HEADER);
            let tail = input
                .get(at..stop)
                .ok_or_else(|| error(io::ErrorKind::FileTooLarge))?;
            at += tail.iter().position(|&b| b == 0).ok_or_else(|| {
                error(if stop == HEADER {
                    io::ErrorKind::FileTooLarge
                } else {
                    io::ErrorKind::InvalidData
                })
            })? + 1;
        }
    }
    if flags & 2 != 0 {
        at += 2;
    }
    if at > HEADER {
        return Err(error(io::ErrorKind::FileTooLarge));
    }
    if at > input.len() {
        return Err(error(io::ErrorKind::InvalidData));
    }
    Ok(())
}

/// Bound the output, decoder scratch, and both allocations during vector growth.
/// The caller accounts for the borrowed compressed input separately.
pub(crate) fn inflate(
    input: &[u8],
    output_limit: usize,
    memory_limit: usize,
    check: &mut dyn FnMut(usize) -> bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    if memory_limit < SCRATCH {
        return Err(error(io::ErrorKind::OutOfMemory));
    }
    if !check(0) {
        return Err(error(io::ErrorKind::Interrupted));
    }
    // Gzip optional strings are parsed before the first payload read.
    header(input)?;
    let mut decoder = GzDecoder::new(input);
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    loop {
        if !check(bytes.len()) {
            return Err(error(io::ErrorKind::Interrupted));
        }
        let count = CHUNK.min(output_limit.saturating_sub(bytes.len()).saturating_add(1));
        let count = decoder.read(
            chunk
                .get_mut(..count)
                .ok_or_else(|| error(io::ErrorKind::InvalidData))?,
        )?;
        if count == 0 {
            break;
        }
        let length = bytes
            .len()
            .checked_add(count)
            .filter(|&n| n <= output_limit)
            .ok_or_else(|| error(io::ErrorKind::FileTooLarge))?;
        if length > bytes.capacity() {
            let capacity = length.max(
                CHUNK
                    .max(bytes.capacity().saturating_mul(2))
                    .min(output_limit),
            );
            let peak = bytes
                .capacity()
                .checked_add(capacity)
                .and_then(|n| n.checked_add(SCRATCH))
                .ok_or_else(|| error(io::ErrorKind::OutOfMemory))?;
            if peak > memory_limit {
                return Err(error(io::ErrorKind::OutOfMemory));
            }
            let additional = capacity - bytes.len();
            bytes
                .try_reserve_exact(additional)
                .map_err(|_| error(io::ErrorKind::OutOfMemory))?;
        }
        bytes.extend_from_slice(
            chunk
                .get(..count)
                .ok_or_else(|| error(io::ErrorKind::InvalidData))?,
        );
    }
    // KDBX compression is one gzip member, not a concatenation or suffix channel.
    if !decoder.into_inner().is_empty() {
        return Err(error(io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn gzip(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        out.write_all(bytes)?;
        out.finish()
    }
    #[test]
    fn output_and_growth_memory_are_admitted_before_allocation() -> io::Result<()> {
        let source = vec![17u8; 2 << 20];
        let compressed = gzip(&source)?;
        assert_eq!(
            *inflate(&compressed, source.len(), 8 << 20, &mut |_| true)?,
            source
        );
        assert!(
            matches!(inflate(&compressed, source.len() - 1, 8 << 20, &mut |_| true), Err(e) if e.kind() == io::ErrorKind::FileTooLarge)
        );
        assert!(
            matches!(inflate(&compressed, source.len(), SCRATCH + CHUNK, &mut |_| true), Err(e) if e.kind() == io::ErrorKind::OutOfMemory)
        );
        let empty = gzip(&[])?;
        assert!(inflate(&empty, 0, SCRATCH, &mut |_| true)?.is_empty());
        Ok(())
    }
    #[test]
    fn cancel_is_checked_between_chunks() -> io::Result<()> {
        let compressed = gzip(&vec![2u8; 2 << 20])?;
        let mut checked = 0;
        let error = inflate(&compressed, 2 << 20, 8 << 20, &mut |n| {
            checked = n;
            n < CHUNK
        });
        assert!(matches!(error, Err(e) if e.kind() == io::ErrorKind::Interrupted));
        assert!(checked >= CHUNK);
        Ok(())
    }
    #[test]
    fn checksum_truncation_and_trailing_members_are_rejected() -> io::Result<()> {
        let original = gzip(b"public bounded gzip fixture")?;
        for end in 0..original.len() {
            assert!(inflate(
                original
                    .get(..end)
                    .ok_or_else(|| error(io::ErrorKind::InvalidData))?,
                1024,
                4 << 20,
                &mut |_| true
            )
            .is_err());
        }
        let mut corrupt = original.clone();
        let crc = corrupt.len() - 8;
        *corrupt
            .get_mut(crc)
            .ok_or_else(|| error(io::ErrorKind::InvalidData))? ^= 1;
        assert!(inflate(&corrupt, 1024, 4 << 20, &mut |_| true).is_err());
        for suffix in [original.as_slice(), b"\0".as_slice()] {
            let mut joined = original.clone();
            joined.extend_from_slice(suffix);
            assert!(
                matches!(inflate(&joined, 1024, 4 << 20, &mut |_| true), Err(e) if e.kind() == io::ErrorKind::InvalidData)
            );
        }
        Ok(())
    }
    #[test]
    fn huge_gzip_metadata_is_refused_before_decoder_creation() -> io::Result<()> {
        let ordinary = gzip(b"public optional-header fixture")?;
        let mut optional = ordinary
            .get(..10)
            .ok_or_else(|| error(io::ErrorKind::InvalidData))?
            .to_vec();
        *optional
            .get_mut(3)
            .ok_or_else(|| error(io::ErrorKind::InvalidData))? = 4 | 8 | 16;
        optional.extend_from_slice(&[2, 0, 1, 2]);
        optional.extend_from_slice(b"fixture.bin\0public comment\0");
        optional.extend_from_slice(
            ordinary
                .get(10..)
                .ok_or_else(|| error(io::ErrorKind::InvalidData))?,
        );
        assert_eq!(
            *inflate(&optional, 1024, 4 << 20, &mut |_| true)?,
            b"public optional-header fixture"
        );
        let mut input = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 0];
        input.resize(2 << 20, b'a');
        assert!(
            matches!(inflate(&input, 1024, 4 << 20, &mut |_| true), Err(e) if e.kind() == io::ErrorKind::FileTooLarge)
        );
        *input
            .get_mut(3)
            .ok_or_else(|| error(io::ErrorKind::InvalidData))? = 0x20;
        assert!(
            matches!(inflate(&input, 1024, 4 << 20, &mut |_| true), Err(e) if e.kind() == io::ErrorKind::InvalidData)
        );
        Ok(())
    }
}
