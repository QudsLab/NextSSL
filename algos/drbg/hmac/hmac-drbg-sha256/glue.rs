//! Adapter: Cryspen `libcrux-hmac-drbg` (SP 800-90A Rev. 1 HMAC_DRBG, HMAC-SHA-256) -> nextssl
//! `Drbg`.
//!
//! Limits enforced here (all explicit errors, nothing truncated):
//! entropy input 32..=1024 bytes, nonce 16..=128 bytes, personalization / additional input
//! 0..=65536 bytes, request 1..=65536 bytes, reseed interval 2^48 (enforced upstream).
//!
//! Upstream keeps `K`/`V` in plain arrays without a `Drop` wipe, so this adapter owns the state
//! in a `Box` and overwrites it in place with a public all-zero-seeded instance on
//! `uninstantiate` and on drop (best effort: upstream's short-lived stack temporaries are not
//! reachable from here).

use libcrux_hmac_drbg::{GenerateError, HmacDrbgSha256, MAX_GENERATE_BYTES, MIN_ENTROPY_BYTES};
use nextssl_core::{Drbg, Error, Len, Params, Result, Sizes};
use std::hint::black_box;
use std::sync::atomic::{compiler_fence, Ordering};

const SEED_MAX: usize = 1024;
const NONCE_MIN: usize = 16;
const NONCE_MAX: usize = 128;
const AUX_MAX: usize = 65_536;
const STRENGTH_BITS: usize = 256;

struct HmacDrbg256 {
    state: Option<Box<HmacDrbgSha256>>,
}

fn check(what: &'static str, min: usize, max: usize, got: usize) -> Result<()> {
    Len::range(min, max).check(what, got)
}

fn check_entropy(entropy: &[u8]) -> Result<()> {
    check("entropy", MIN_ENTROPY_BYTES, SEED_MAX, entropy.len())
}

impl HmacDrbg256 {
    /// Overwrites the live state in place with a public constant state, then drops it.
    fn wipe(&mut self) {
        if let Some(mut s) = self.state.take() {
            if let Ok(blank) =
                HmacDrbgSha256::new(&[0u8; MIN_ENTROPY_BYTES], &[0u8; NONCE_MIN], &[])
            {
                *s = blank;
            }
            compiler_fence(Ordering::SeqCst);
            black_box(&*s);
        }
    }
}

impl Drop for HmacDrbg256 {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Drbg for HmacDrbg256 {
    fn sizes(&self) -> Sizes {
        Sizes {
            seed: Some(Len::range(MIN_ENTROPY_BYTES, SEED_MAX)),
            ..Sizes::NONE
        }
    }

    fn security_strength(&self) -> usize {
        STRENGTH_BITS
    }

    fn max_request_len(&self) -> usize {
        MAX_GENERATE_BYTES
    }

    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<()> {
        check_entropy(entropy)?;
        check("nonce", NONCE_MIN, NONCE_MAX, nonce.len())?;
        check("personalization", 0, AUX_MAX, personalization.len())?;
        let d = HmacDrbgSha256::new(entropy, nonce, personalization)
            .map_err(|_| Error::Backend("hmac-drbg instantiate failed"))?;
        self.wipe();
        self.state = Some(Box::new(d));
        Ok(())
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()> {
        let d = self.state.as_mut().ok_or(Error::NotInstantiated)?;
        check_entropy(entropy)?;
        check("additional", 0, AUX_MAX, additional.len())?;
        d.reseed(entropy, additional)
            .map_err(|_| Error::Backend("hmac-drbg reseed failed"))
    }

    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()> {
        let d = self.state.as_mut().ok_or(Error::NotInstantiated)?;
        check("request", 1, MAX_GENERATE_BYTES, out.len())?;
        check("additional", 0, AUX_MAX, additional.len())?;
        d.generate(out, additional).map_err(|e| match e {
            GenerateError::ReseedRequired => Error::ReseedRequired,
            _ => Error::Backend("hmac-drbg generate failed"),
        })
    }

    fn uninstantiate(&mut self) {
        self.wipe();
    }
}

/// Registry constructor. Takes no parameters; the DRBG starts uninstantiated.
pub fn new(_params: &Params) -> Result<Box<dyn Drbg>> {
    Ok(Box::new(HmacDrbg256 { state: None }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn cavp_hmac_drbg_sha256_no_reseed() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("kat/cavp-hmac-drbg-sha256.json")).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 15);
        for v in vectors {
            let f = |k: &str| unhex(v[k].as_str().unwrap());
            let mut d = new(&Params::new()).unwrap();
            d.instantiate(&f("entropy_hex"), &f("nonce_hex"), &f("pers_hex"))
                .unwrap();
            let want = f("returned_hex");
            let mut discard = vec![0u8; want.len()];
            d.generate(&f("add1_hex"), &mut discard).unwrap();
            let mut got = vec![0u8; want.len()];
            d.generate(&f("add2_hex"), &mut got).unwrap();
            assert_eq!(got, want, "vector {}", v["id"]);
        }
    }

    #[test]
    fn lifecycle_and_limits() {
        let mut d = new(&Params::new()).unwrap();
        let mut out = [0u8; 8];
        assert_eq!(d.generate(&[], &mut out), Err(Error::NotInstantiated));
        assert_eq!(d.reseed(&[1; 32], &[]), Err(Error::NotInstantiated));
        assert!(matches!(
            d.instantiate(&[1; 31], &[2; 16], &[]),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            d.instantiate(&[1; 32], &[2; 15], &[]),
            Err(Error::InvalidLength { .. })
        ));
        d.instantiate(&[1; 32], &[2; 16], b"p").unwrap();
        assert!(matches!(
            d.generate(&[], &mut []),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            d.generate(&[], &mut vec![0u8; MAX_GENERATE_BYTES + 1]),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            d.reseed(&[3; 31], &[]),
            Err(Error::InvalidLength { .. })
        ));
        d.reseed(&[3; 32], b"a").unwrap();
        d.generate(b"x", &mut out).unwrap();
        d.uninstantiate();
        assert_eq!(d.generate(&[], &mut out), Err(Error::NotInstantiated));
    }
}
