//! Adapter: RustCrypto `belt_hash` `BeltHash` -> nextssl `Hash` (fixed 32-byte output, no parameters).

use nextssl_core::{Error, Hash, Params, Result};
use belt_hash::{Digest, BeltHash};

const OUT_LEN: usize = 32;

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
        out.copy_from_slice(BeltHash::digest(data).as_slice());
        Ok(())
    }
}

/// Registry constructor. This algorithm takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(Impl))
}
