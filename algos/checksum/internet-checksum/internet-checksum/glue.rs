//! Adapter: internet-checksum `checksum` (RFC 1071 16-bit ones-complement sum) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC hash for accidental-corruption detection and hash tables only; it is
//! reachable through the root API only. RFC 1071 checksum; the crate returns the two bytes in network order. Output: 2 bytes, big-endian.

use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const OUT: usize = 2;

fn compute(data: &[u8]) -> [u8; OUT] {
    internet_checksum::checksum(data)
}

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
        out.copy_from_slice(&compute(data));
        Ok(())
    }
}

/// Registry constructor. No parameters (fixed seed).
pub fn new(_params: &Params) -> Result<Box<dyn Checksum>> {
    Ok(Box::new(Impl))
}
