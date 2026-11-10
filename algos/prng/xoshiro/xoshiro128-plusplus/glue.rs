//! Adapter: rand_xoshiro `Xoshiro128PlusPlus` -> nextssl `Prng`.
//!
//! NOT A CRYPTOGRAPHIC GENERATOR. Deterministic and predictable from a few outputs; reachable through the
//! root API only. Use it for reproducible simulation and test data, never for keys, nonces, salts or tokens.
//! Seed: exactly 16 bytes, supplied by the caller (public by contract). Output: the upstream `fill_bytes`
//! stream (little-endian words), 1 byte to 256 MiB per call, a shorter request is a prefix of a longer one.
//! All-zero seeds are refused (upstream would substitute one).

use nextssl_core::{Error, Len, Params, Prng, Result, Sizes, Zeroize};
use rand_core::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro128PlusPlus;

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
        if seed.iter().all(|&b| b == 0) {
            // The upstream constructor would silently replace an all-zero seed; refuse it instead.
            return Err(Error::InvalidInput("all-zero seed is not allowed for this generator"));
        }
        let mut s = <Xoshiro128PlusPlus as SeedableRng>::Seed::default();
        s.as_mut().copy_from_slice(seed);
        let mut rng = Xoshiro128PlusPlus::from_seed(s.clone());
        rng.fill_bytes(out);
        s.as_mut().zeroize();
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Prng>> {
    Ok(Box::new(Impl))
}
