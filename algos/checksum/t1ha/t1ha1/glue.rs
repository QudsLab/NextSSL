//! Adapter: `t1ha` crate (t1ha1_le (64-bit, little-endian reads)) -> nextssl `Checksum`. NON-CRYPTOGRAPHIC, root only. Seed fixed to 0.
//! Output: 8 bytes, big-endian. The crate has its own build script (rustc_version); checked in Docker with --network none.

use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const OUT: usize = 8;

struct Impl;

impl Checksum for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: Some(Len::fixed(OUT)),
            ..Sizes::NONE
        }
    }

    fn checksum(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(OUT).check("out", out.len())?;
        out.copy_from_slice(&t1ha::t1ha1_le(data, 0).to_be_bytes());
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Checksum>> {
    Ok(Box::new(Impl))
}
