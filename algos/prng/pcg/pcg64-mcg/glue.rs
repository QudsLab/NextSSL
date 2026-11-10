//! Adapter: rand_pcg `Mcg128Xsl64` (PCG-XSL-RR 128/64 MCG) -> nextssl `Prng`.
//!
//! NOT A CRYPTOGRAPHIC GENERATOR. Deterministic and predictable from a few outputs; reachable through the
//! root API only. Use it for reproducible simulation and test data, never for keys, nonces, salts or tokens.
//! Seed: exactly 16 bytes, supplied by the caller (public by contract). Output: the upstream `fill_bytes`
//! stream (little-endian words), 1 byte to 256 MiB per call, a shorter request is a prefix of a longer one.
//! Seed: 16 bytes state; upstream forces the low bit (multiplicative generator).

use nextssl_core::{Len, Params, Prng, Result, Sizes, Zeroize};
use rand_core::{Rng, SeedableRng};
use rand_pcg::Mcg128Xsl64;

const SEED_LEN: usize = 16;
const MAX_OUT: usize = 1 << 28;

struct Impl;

impl Prng for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            seed: Some(Len::fixed(SEED_LEN)),
            out: Some(Len::range(1, MAX_OUT)),
            ..Sizes::NONE
        }
    }

    fn generate(&self, seed: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(SEED_LEN).check("seed", seed.len())?;
        Len::range(1, MAX_OUT).check("out", out.len())?;
        let mut s = <Mcg128Xsl64 as SeedableRng>::Seed::default();
        s.as_mut().copy_from_slice(seed);
        let mut rng = Mcg128Xsl64::from_seed(s.clone());
        rng.fill_bytes(out);
        s.as_mut().zeroize();
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Prng>> {
    Ok(Box::new(Impl))
}
