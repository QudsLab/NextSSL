//! Adapter: sha3 `Keccak512` -> nextssl `Hash` (fixed 64-byte output, no parameters).

use nextssl_core::{Error, Hash, Params, Result};
use sha3::{Digest, Keccak512};

const OUT_LEN: usize = 64;

struct Impl;

impl Hash for Impl {
    fn output_len(&self) -> usize {
        OUT_LEN
    }

    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != OUT_LEN {
            return Err(Error::BadOutputLen {
                expected: OUT_LEN,
                got: out.len(),
            });
        }
        out.copy_from_slice(Keccak512::digest(data).as_slice());
        Ok(())
    }
}

/// Registry constructor. This algorithm takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_output_length_is_refused() {
        let h = new(&Params::new()).unwrap();
        let n = h.output_len();
        let mut short = vec![0u8; n - 1];
        assert!(matches!(
            h.digest(b"abc", &mut short),
            Err(Error::BadOutputLen { .. })
        ));
        let mut long = vec![0u8; n + 1];
        assert!(matches!(
            h.digest(b"abc", &mut long),
            Err(Error::BadOutputLen { .. })
        ));
    }
}
