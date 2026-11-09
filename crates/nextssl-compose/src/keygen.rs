//! Key generation with a caller-chosen randomness source.
//!
//! - [`random_bytes`]: `n` bytes from `rng` (`1..=16 MiB`).
//! - [`random_key`]: a key of the right length for an AEAD, MAC, stream cipher, block cipher or
//!   block mode. A fixed key size gives that size; for a range the key is `min(max, 64)` bytes,
//!   but never below the range minimum.
//! - [`keygen_with_rng`]: a key pair for a signature, KEM or key-exchange algorithm.
//!
//! `rng` is `"os-entropy"`, a registered DRBG id or a composed DRBG (see [`crate::rng`]). With
//! `Policy::Safe` only safe/standard sources and algorithms are accepted. Choosing a DRBG makes
//! the key pair a deterministic function of the OS entropy it was seeded with; the plain
//! `keygen` functions draw from the OS directly.

use crate::rng;
use nextssl_core::{Error, Kind, Len, PrivateKey, PublicKey, Result, SymmetricKey, Zeroizing};
use nextssl_registry::{all, allowed, lookup_in, new_kem_in, new_kex_in, new_sign_in, Policy};

pub const RANDOM_MAX: usize = 1 << 24;

pub fn random_bytes(n: usize, rng_spec: &str, policy: Policy) -> Result<Zeroizing<Vec<u8>>> {
    Len::range(1, RANDOM_MAX).check("length", n)?;
    let mut src = rng::open(rng_spec, policy)?;
    let mut out = Zeroizing::new(vec![0u8; n]);
    src.fill(&mut out)?;
    Ok(out)
}

pub fn random_key(alg: &str, rng_spec: &str, policy: Policy) -> Result<SymmetricKey> {
    let info = lookup_in(all(), alg).ok_or(Error::UnknownAlgorithm)?;
    if !allowed(info.tier, policy) {
        return Err(Error::TierNotAllowed(info.tier));
    }
    if !matches!(
        info.kind,
        Kind::Aead | Kind::Mac | Kind::StreamCipher | Kind::BlockCipher | Kind::BlockMode
    ) {
        return Err(Error::WrongKind);
    }
    let want = info.sizes.key.ok_or(Error::Unsupported)?;
    let n = want.min().max(want.max().min(64));
    let bytes = random_bytes(n, rng_spec, policy)?;
    SymmetricKey::from_bytes(&bytes, Len::fixed(n))
}

pub fn keygen_with_rng(
    alg: &str,
    rng_spec: &str,
    policy: Policy,
) -> Result<(PublicKey, PrivateKey)> {
    let info = lookup_in(all(), alg).ok_or(Error::UnknownAlgorithm)?;
    let p = info.smoke_params();
    match info.kind {
        Kind::Sign => {
            let a = new_sign_in(all(), policy, info.id, &p)?;
            a.keygen(&mut *rng::open(rng_spec, policy)?)
        }
        Kind::Kem => {
            let a = new_kem_in(all(), policy, info.id, &p)?;
            a.keygen(&mut *rng::open(rng_spec, policy)?)
        }
        Kind::Kex => {
            let a = new_kex_in(all(), policy, info.id, &p)?;
            a.keypair(&mut *rng::open(rng_spec, policy)?)
        }
        _ => Err(Error::WrongKind),
    }
}
