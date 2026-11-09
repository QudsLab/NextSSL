//! Adapter: `getrandom` (operating-system CSPRNG) -> nextssl `EntropySource`.
//! Any OS failure is `Error::EntropyFailure`; a failed call never reports success and never
//! returns a partially filled buffer as good.

use nextssl_core::{EntropySource, Error, Params, Result};

struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        getrandom::fill(out).map_err(map_os_error)
    }
}

fn map_os_error(_: getrandom::Error) -> Error {
    Error::EntropyFailure("operating system RNG failed")
}

/// Registry constructor. The OS RNG takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn EntropySource>> {
    Ok(Box::new(OsEntropy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> serde_json::Value {
        serde_json::from_str(include_str!("kat/os-entropy-behaviour.json")).unwrap()
    }

    #[test]
    fn fills_requested_lengths() {
        let mut r = new(&Params::new()).unwrap();
        for n in doc()["fill_lens_ok"].as_array().unwrap() {
            let n = n.as_u64().unwrap() as usize;
            let mut buf = vec![0u8; n];
            r.fill(&mut buf).unwrap();
            assert_eq!(buf.len(), n);
        }
        // 4096 zero bytes from a working RNG is 2^-32768; treat as failure.
        let mut big = vec![0u8; 4096];
        r.fill(&mut big).unwrap();
        assert!(big.iter().any(|&b| b != 0));
    }

    #[test]
    fn two_outputs_differ() {
        let n = doc()["distinct_pair_len"].as_u64().unwrap() as usize;
        let mut r = new(&Params::new()).unwrap();
        let (mut a, mut b) = (vec![0u8; n], vec![0u8; n]);
        r.fill(&mut a).unwrap();
        r.fill(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn os_error_maps_to_entropy_failure() {
        assert!(matches!(
            map_os_error(getrandom::Error::UNSUPPORTED),
            Error::EntropyFailure(_)
        ));
    }
}
