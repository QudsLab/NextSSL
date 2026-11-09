//! Adapter: wyhash `final3::WyHash` (wyhash final version 3, default seed and secret) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC hash for accidental-corruption detection and hash tables only; it is
//! reachable through the root API only. wyhash final3 with the crate default secret. Output: 8 bytes, big-endian.

use nextssl_core::{Checksum, Len, Params, Result, Sizes};
use std::hash::Hasher;

const OUT: usize = 8;

fn compute(data: &[u8]) -> [u8; OUT] {
    let mut h = wyhash::final3::WyHash::default();
    h.write(data);
    h.finish().to_be_bytes()
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
