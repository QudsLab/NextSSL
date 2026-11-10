//! Adapter: RustCrypto `fsb` `Fsb160` -> nextssl `Hash` (fixed 20-byte output, no parameters).

use nextssl_core::{Error, Hash, Params, Result};
use fsb::{Digest, Fsb160};

const OUT_LEN: usize = 20;

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
        out.copy_from_slice(Fsb160::digest(data).as_slice());
        Ok(())
    }
}

/// Registry constructor. This algorithm takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(Impl))
}
