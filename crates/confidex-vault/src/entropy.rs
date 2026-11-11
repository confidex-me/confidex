use zeroize::Zeroize;

pub const MAX_REQUEST: usize = 65_536;

#[derive(Debug, PartialEq, Eq)]
pub enum EntropyError {
    Unavailable,
    RequestTooLarge,
}

pub fn fill_random(output: &mut [u8]) -> Result<(), EntropyError> {
    fill_with(output, |bytes| {
        #[cfg(any(
            not(all(target_arch = "wasm32", target_os = "unknown")),
            feature = "browser"
        ))]
        {
            getrandom::fill(bytes).map_err(|_| EntropyError::Unavailable)
        }
        #[cfg(all(
            target_arch = "wasm32",
            target_os = "unknown",
            not(feature = "browser")
        ))]
        {
            let _ = bytes;
            Err(EntropyError::Unavailable)
        }
    })
}

fn fill_with(
    output: &mut [u8],
    source: impl FnOnce(&mut [u8]) -> Result<(), EntropyError>,
) -> Result<(), EntropyError> {
    if output.len() > MAX_REQUEST {
        output.zeroize();
        return Err(EntropyError::RequestTooLarge);
    }
    if let Err(error) = source(output) {
        output.zeroize();
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_failure_wipes_partial_output() {
        let mut output = [77; 32];
        assert_eq!(
            fill_with(&mut output, |bytes| {
                bytes[..5].fill(11);
                Err(EntropyError::Unavailable)
            }),
            Err(EntropyError::Unavailable)
        );
        assert_eq!(output, [0; 32]);
    }

    #[test]
    fn oversized_request_never_calls_source() {
        let mut output = vec![77; MAX_REQUEST + 1];
        assert_eq!(
            fill_with(&mut output, |_| panic!("source must not run")),
            Err(EntropyError::RequestTooLarge)
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }

    #[test]
    #[cfg(any(
        not(all(target_arch = "wasm32", target_os = "unknown")),
        feature = "browser"
    ))]
    fn platform_source_and_request_boundary_work() {
        let mut output = vec![0; MAX_REQUEST];
        fill_random(&mut output).unwrap();
        assert!(output.iter().any(|byte| *byte != 0));
        let mut other = [0; 32];
        fill_random(&mut other).unwrap();
        assert_ne!(&output[..32], &other);
    }
}
