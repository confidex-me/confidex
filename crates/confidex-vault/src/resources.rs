use flate2::{Decompress, FlushDecompress, Status};
use zeroize::Zeroizing;

pub const MAX_COMPRESSED: usize = 4_000_000;
pub const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;
pub const MAX_OPEN_MEMORY: usize = 192 * 1024 * 1024;
pub const INFLATE_SCRATCH: usize = 256 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceError {
    Limit,
    Invalid,
    Allocation,
}

pub fn decompress_content(
    input: &[u8],
    output_limit: usize,
    memory_budget: usize,
) -> Result<Zeroizing<Vec<u8>>, ResourceError> {
    if input.len() > MAX_COMPRESSED
        || output_limit > MAX_DECOMPRESSED
        || memory_budget > MAX_OPEN_MEMORY
        || output_limit + INFLATE_SCRATCH + input.len() > memory_budget
    {
        return Err(ResourceError::Limit);
    }
    let size = inflate(input, output_limit, None)?;
    let mut output = Zeroizing::new(Vec::new());
    // Reserve once at the measured size so growth does not leave plaintext copies.
    output
        .try_reserve_exact(size)
        .map_err(|_| ResourceError::Allocation)?;
    if inflate(input, size, Some(&mut output))? != size {
        return Err(ResourceError::Invalid);
    }
    Ok(output)
}

fn inflate(
    input: &[u8],
    output_limit: usize,
    mut output: Option<&mut Vec<u8>>,
) -> Result<usize, ResourceError> {
    let mut scratch = Zeroizing::new([0u8; 65_536]);
    let mut decoder = Decompress::new(true);
    let mut consumed = 0;
    let mut produced = 0;
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let room = scratch.len().min(output_limit - produced + 1);
        let status = decoder
            .decompress(
                &input[consumed..],
                &mut scratch[..room],
                FlushDecompress::None,
            )
            .map_err(|_| ResourceError::Invalid)?;
        let read = (decoder.total_in() - before_in) as usize;
        let written = (decoder.total_out() - before_out) as usize;
        consumed += read;
        if written > output_limit - produced {
            return Err(ResourceError::Limit);
        }
        produced += written;
        if let Some(output) = output.as_mut() {
            output.extend_from_slice(&scratch[..written]);
        }
        if status == Status::StreamEnd {
            return if consumed == input.len() {
                Ok(produced)
            } else {
                Err(ResourceError::Invalid)
            };
        }
        if read == 0 && written == 0 {
            return Err(ResourceError::Invalid);
        }
    }
}
