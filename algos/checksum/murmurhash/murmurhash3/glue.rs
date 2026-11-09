//! Adapter: simplehash `MurmurHasher32` (MurmurHash3 x86_32, seed 0) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC hash for accidental-corruption detection and hash tables only; it is
//! reachable through the root API only. MurmurHash3 x86_32, seed 0. Output: 4 bytes, big-endian.

use nextssl_core::{Checksum, Len, Params, Result, Sizes};
use std::hash::Hasher;

const OUT: usize = 4;

fn compute(data: &[u8]) -> [u8; OUT] {
    let mut h = simplehash::MurmurHasher32::new(0);
    h.write(data);
    h.finish_u32().to_be_bytes()
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
