use byteorder::{ByteOrder, LittleEndian};
use hex_literal::hex;
use hybrid_array::{typenum::U64, Array as GenericArray};
#[cfg(feature = "save_kdbx4")]
use std::io::{self, Write};
use thiserror::Error;
#[cfg(feature = "save_kdbx4")]
use zeroize::Zeroizing;

pub const HMAC_KEY_END: [u8; 1] = hex!("01");

/// Read from a HMAC block stream into a raw buffer
pub(crate) fn read_hmac_block_stream(
    data: &[u8],
    key: &GenericArray<u8, U64>,
) -> Result<Vec<u8>, BlockStreamError> {
    // keepassxc src/streams/HmacBlockStream.cpp

    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index: u64 = 0;

    while pos < data.len() {
        let hmac = data.get(pos..(pos + 32)).ok_or(BlockStreamError::Eof)?;
        let size_bytes = data
            .get((pos + 32)..(pos + 36))
            .ok_or(BlockStreamError::Eof)?;
        let size = LittleEndian::read_u32(size_bytes) as usize;
        let block = data
            .get((pos + 36)..(pos + 36 + size))
            .ok_or(BlockStreamError::Eof)?;

        // verify block hmac
        let hmac_block_key = get_hmac_block_key(block_index, key);
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index);

        #[allow(clippy::expect_used)]
        // Block stream key is always correctly sized, so this can't fail
        if hmac
            != crate::crypt::calculate_hmac(&[&block_index_buf, size_bytes, block], &hmac_block_key)
                .expect("Block stream key always correctly sized")
                .as_slice()
        {
            return Err(BlockStreamError::BlockHashMismatch { block_index });
        }

        pos += 36 + size;
        block_index += 1;

        if size == 0 {
            break;
        }

        out.extend_from_slice(block);
    }

    Ok(out)
}

#[cfg(all(test, feature = "save_kdbx4"))]
/// Write a raw buffer as a HMAC block stream
pub(crate) fn write_hmac_block_stream(
    data: &[u8],
    key: &GenericArray<u8, U64>,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    write_hmac_block_stream_to(data, key, &mut out)?;
    Ok(out)
}

#[cfg(feature = "save_kdbx4")]
pub(crate) fn write_hmac_block_stream_to(
    data: &[u8],
    key: &GenericArray<u8, U64>,
    output: &mut dyn Write,
) -> io::Result<()> {
    for (index, block) in data
        .chunks(65_536)
        .chain(std::iter::once(&[][..]))
        .enumerate()
    {
        let key = Zeroizing::new(get_hmac_block_key(index as u64, key));
        let size = (block.len() as u32).to_le_bytes();
        let hmac =
            crate::crypt::calculate_hmac(&[&(index as u64).to_le_bytes(), &size, block], &key)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        output.write_all(&hmac)?;
        output.write_all(&size)?;
        output.write_all(block)?;
    }
    Ok(())
}

pub(crate) fn get_hmac_block_key(
    block_index: u64,
    key: &GenericArray<u8, U64>,
) -> GenericArray<u8, U64> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, block_index);
    crate::crypt::calculate_sha512(&[&buf, key])
}

/// Errors reading from the HMAC block stream
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BlockStreamError {
    /// The HMAC of a block did not match the expected value, indicating that the data may be
    /// corrupted or tampered with.
    #[error("Block hash mismatch for block {}", block_index)]
    BlockHashMismatch {
        /// The index of the block that failed the HMAC verification
        block_index: u64,
    },

    /// The end of the file was reached unexpectedly while reading a block, indicating that the
    /// data may be incomplete or corrupted.
    #[error("unexpected end of file")]
    Eof,
}

#[cfg(all(test, feature = "save_kdbx4"))]
mod tests {
    use super::*;

    #[test]
    fn output_uses_bounded_sequential_blocks_and_one_authenticated_terminator(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = GenericArray::from([7; 64]);
        for length in [0, 1, 65_535, 65_536, 65_537, 131_075] {
            let data = vec![19; length];
            let encoded = write_hmac_block_stream(&data, &key)?;
            assert_eq!(read_hmac_block_stream(&encoded, &key)?, data);
            let mut position = 0;
            for (index, expected) in data
                .chunks(65_536)
                .chain(std::iter::once(&[][..]))
                .enumerate()
            {
                let size = encoded
                    .get(position + 32..position + 36)
                    .ok_or(BlockStreamError::Eof)?;
                let size = LittleEndian::read_u32(size) as usize;
                assert_eq!(size, expected.len());
                assert!(size <= 65_536);
                let block_key = Zeroizing::new(get_hmac_block_key(index as u64, &key));
                let mac = crate::crypt::calculate_hmac(
                    &[
                        &(index as u64).to_le_bytes(),
                        &(size as u32).to_le_bytes(),
                        expected,
                    ],
                    &block_key,
                )?;
                assert_eq!(encoded.get(position..position + 32), Some(mac.as_slice()));
                position += 36 + size;
            }
            assert_eq!(position, encoded.len());
        }
        Ok(())
    }

    #[test]
    fn destination_failure_stops_before_another_block() {
        struct Fails {
            calls: usize,
        }
        impl Write for Fails {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 3 {
                    Err(io::ErrorKind::ConnectionAborted.into())
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut output = Fails { calls: 0 };
        let result = write_hmac_block_stream_to(
            &vec![1; 131_072],
            &GenericArray::from([7; 64]),
            &mut output,
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::ConnectionAborted));
        assert_eq!(output.calls, 3);
    }
}
