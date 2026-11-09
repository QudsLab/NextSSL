//! Adapter: `sharks` 0.5.0 (Shamir secret sharing over GF(256), byte by byte) -> nextssl `Threshold`.
//! A share is `t (1 byte) || x (1 byte) || y (secret length bytes)`: the crate does not store the threshold, so the adapter
//! records it and `combine` refuses fewer than `t` distinct shares or mixed thresholds (the crate would otherwise interpolate
//! a wrong secret silently). 1 <= t <= n <= 255, secret 1..=1024 bytes. Plain Shamir has no share authentication: a corrupted
//! share gives a wrong secret, not an error.

use nextssl_core::{EntropySource, Error, Len, Params, Result, Share, Threshold, Zeroizing};
use rand_core::{CryptoRng, RngCore};
use sharks::{Share as UpShare, Sharks};

/// Bridges nextssl's `EntropySource` to rand_core 0.6. The upstream traits are infallible, so a failing
/// source aborts the operation with a panic that `with_rng` turns into `Error::EntropyFailure`; zeros are never used.
struct Rng<'a> {
    src: &'a mut dyn EntropySource,
    failed: bool,
}
impl Rng<'_> {
    fn fill(&mut self, dst: &mut [u8]) {
        if self.src.fill(dst).is_err() {
            self.failed = true;
            panic!("entropy source failed");
        }
    }
}
impl RngCore for Rng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.fill(dst);
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill(dst);
        Ok(())
    }
}
impl CryptoRng for Rng<'_> {}

/// Runs `f` with an upstream-compatible RNG drawing from `src`.
fn with_rng<T>(src: &mut dyn EntropySource, f: impl FnOnce(&mut Rng<'_>) -> T) -> Result<T> {
    let mut r = Rng { src, failed: false };
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut r)));
    match out {
        Ok(v) if !r.failed => Ok(v),
        _ if r.failed => Err(Error::EntropyFailure("entropy source failed")),
        _ => Err(Error::Backend("panic inside the upstream crate")),
    }
}

const MAX_N: usize = 255;
const SECRET_MAX: usize = 1024;
const SHARE: Len = Len::range(3, 2 + SECRET_MAX);

struct Alg;

impl Threshold for Alg {
    fn max_parties(&self) -> usize {
        MAX_N
    }

    fn split(
        &self,
        secret: &[u8],
        t: usize,
        n: usize,
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<Share>> {
        nextssl_core::check_threshold(t, n, MAX_N)?;
        nextssl_core::check_len("secret", secret.len(), 1, SECRET_MAX)?;
        let dealer = Sharks(t as u8);
        let shares: Vec<UpShare> =
            with_rng(rng, |r| dealer.dealer_rng(secret, r).take(n).collect())?;
        if shares.len() != n {
            return Err(Error::Backend(
                "sharks produced fewer shares than requested",
            ));
        }
        shares
            .iter()
            .map(|s| {
                let body = Zeroizing::new(Vec::<u8>::from(s));
                let mut v = Zeroizing::new(vec![t as u8]);
                v.extend_from_slice(&body);
                Share::from_bytes(&v, SHARE)
            })
            .collect()
    }

    fn combine(&self, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
        let first = shares.first().ok_or(Error::InvalidInput("no shares"))?;
        let t = first.as_bytes()[0] as usize;
        let len = first.len();
        let mut up: Vec<UpShare> = Vec::with_capacity(shares.len());
        for s in shares {
            SHARE.check("share", s.len())?;
            if s.len() != len || s.as_bytes()[0] as usize != t {
                return Err(Error::InvalidInput("shares differ in threshold or length"));
            }
            up.push(
                UpShare::try_from(&s.as_bytes()[1..])
                    .map_err(|_| Error::InvalidInput("malformed share"))?,
            );
        }
        if t == 0 {
            return Err(Error::InvalidInput("share records threshold 0"));
        }
        // fewer than t shares is an error, and so are repeated ids (counted by the crate as one share)
        Sharks(t as u8)
            .recover(&up)
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidInput("not enough distinct shares"))
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Threshold>> {
    Ok(Box::new(Alg))
}
