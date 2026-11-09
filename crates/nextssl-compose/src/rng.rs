//! `rng` arguments of the keygen functions: `"os-entropy"` (or any registered `rng` id), a
//! registered DRBG id (`hmac-drbg-sha256`), or a composed DRBG (`hmac-drbg(sha512)`).
//!
//! A DRBG is instantiated from OS entropy (entropy input of the DRBG's strength, a nonce, and a
//! fixed personalization string) and reseeded from the OS every 2^16 generate calls and
//! whenever it reports `ReseedRequired` (the SP 800-90A limit is 2^48 calls).

use crate::{compose, Built};
use nextssl_core::{Drbg, EntropySource, Error, Kind, Params, Result, Zeroizing};
use nextssl_registry::{all, lookup_in, new_drbg_in, new_rng_in, Policy};

const PERSONALIZATION: &[u8] = b"nextssl-rng-v1";
const RESEED_CALLS: u64 = 1 << 16;
const NONCE_MAX: usize = 128;

fn os() -> Result<Box<dyn EntropySource>> {
    new_rng_in(all(), Policy::Any, "os-entropy", &Params::new())
}

/// A DRBG seeded from the OS, exposed as an [`EntropySource`].
pub struct DrbgRng {
    drbg: Box<dyn Drbg>,
    os: Box<dyn EntropySource>,
    entropy_len: usize,
    calls: u64,
}

impl DrbgRng {
    pub fn new(mut drbg: Box<dyn Drbg>) -> Result<Self> {
        let seed = drbg.sizes().seed.ok_or(Error::Unsupported)?;
        let strength = drbg.security_strength() / 8;
        let entropy_len = strength.max(seed.min()).min(seed.max());
        let nonce_len = (strength / 2).clamp(16, NONCE_MAX);
        let mut os = os()?;
        let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);
        let mut nonce = Zeroizing::new(vec![0u8; nonce_len]);
        os.fill(&mut entropy)?;
        os.fill(&mut nonce)?;
        drbg.instantiate(&entropy, &nonce, PERSONALIZATION)?;
        Ok(Self {
            drbg,
            os,
            entropy_len,
            calls: 0,
        })
    }

    fn reseed(&mut self) -> Result<()> {
        let mut entropy = Zeroizing::new(vec![0u8; self.entropy_len]);
        self.os.fill(&mut entropy)?;
        self.drbg.reseed(&entropy, PERSONALIZATION)?;
        self.calls = 0;
        Ok(())
    }
}

impl EntropySource for DrbgRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        let max = self.drbg.max_request_len();
        for chunk in out.chunks_mut(max) {
            if self.calls >= RESEED_CALLS {
                self.reseed()?;
            }
            match self.drbg.generate(&[], chunk) {
                Err(Error::ReseedRequired) => {
                    self.reseed()?;
                    self.drbg.generate(&[], chunk)?;
                }
                other => other?,
            }
            self.calls += 1;
        }
        Ok(())
    }
}

impl Drop for DrbgRng {
    fn drop(&mut self) {
        self.drbg.uninstantiate();
    }
}

/// Opens the randomness source named by `spec` under `policy`.
pub fn open(spec: &str, policy: Policy) -> Result<Box<dyn EntropySource>> {
    if spec.contains('(') {
        return match compose(spec, policy)?.into_built() {
            Built::Drbg(d) => Ok(Box::new(DrbgRng::new(d)?)),
            _ => Err(Error::WrongKind),
        };
    }
    let info = lookup_in(all(), spec).ok_or(Error::UnknownAlgorithm)?;
    match info.kind {
        Kind::Rng => new_rng_in(all(), policy, info.id, &info.smoke_params()),
        Kind::Drbg => {
            let d = new_drbg_in(all(), policy, info.id, &info.smoke_params())?;
            Ok(Box::new(DrbgRng::new(d)?))
        }
        _ => Err(Error::WrongKind),
    }
}
