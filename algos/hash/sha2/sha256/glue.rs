//! Adapter: RustCrypto `sha2` -> nextssl `Hash`.

use nextssl_core::{Error, Hash, Params, Result};
use sha2::{Digest, Sha256};

const OUT_LEN: usize = 32;

struct Sha256Hash;

impl Hash for Sha256Hash {
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
        out.copy_from_slice(Sha256::digest(data).as_slice());
        Ok(())
    }
}

/// Registry constructor. SHA-256 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(Sha256Hash))
}
