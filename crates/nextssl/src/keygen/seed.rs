//! Seed engine: deterministic key pairs from a caller-supplied seed.
//!
//! - [`SeedMode::Native`]: the seed IS the algorithm's native seed (ML-KEM `d||z`, ML-DSA `xi`,
//!   Ed25519 seed, X25519 secret) and must have exactly the declared length.
//! - [`SeedMode::Expand`]: any seed of 16..=4096 bytes is expanded to the native length with
//!   HKDF-SHA256 or SHAKE256. Every length and counter is encoded at fixed width and the input
//!   carries a domain label and the target algorithm id, so different algorithms (or lengths)
//!   never derive related keys from the same seed.
//!
//! Nothing is truncated or padded: a wrong native length is an error.

use nextssl_core::{
    Error, Len, Params, PrivateKey, PublicKey, Result, Seed, SymmetricKey, Zeroizing,
};
use nextssl_registry::{instantiate_in, new_kdf_in, new_xof_in, AlgoInfo, Instance, Policy};

/// Domain separation label for every expansion.
pub const DOMAIN: &[u8] = b"NextSSL keygen seed v1";
/// Accepted seed lengths for [`SeedMode::Expand`].
pub const EXPAND_SEED_LEN: Len = Len::range(16, 4096);
/// Bytes produced per counter value (HKDF path); longer outputs use more counters.
const CHUNK: usize = 1024;
const MAX_EXPANDED: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expander {
    HkdfSha256,
    Shake256,
}

impl Expander {
    pub const fn id(self) -> &'static str {
        match self {
            Expander::HkdfSha256 => "hkdf-sha256",
            Expander::Shake256 => "shake256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedMode {
    Native,
    Expand(Expander),
}

/// `u16` big-endian length prefix then the bytes.
fn push_field(buf: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let n = u16::try_from(field.len()).map_err(|_| Error::InvalidInput("label too long"))?;
    buf.extend_from_slice(&n.to_be_bytes());
    buf.extend_from_slice(field);
    Ok(())
}

/// Context shared by both expanders: `field(DOMAIN) || field(expander) || field(alg) ||
/// u32be(out_len) || u32be(counter)`.
fn context(expander: Expander, alg_id: &str, out_len: usize, counter: u32) -> Result<Vec<u8>> {
    let mut c = Vec::new();
    push_field(&mut c, DOMAIN)?;
    push_field(&mut c, expander.id().as_bytes())?;
    push_field(&mut c, alg_id.as_bytes())?;
    let n = u32::try_from(out_len).map_err(|_| Error::InvalidInput("output too long"))?;
    c.extend_from_slice(&n.to_be_bytes());
    c.extend_from_slice(&counter.to_be_bytes());
    Ok(c)
}

/// Expands `seed` to `out_len` bytes for algorithm `alg_id`.
pub fn expand_seed_in(
    table: &[AlgoInfo],
    policy: Policy,
    expander: Expander,
    alg_id: &str,
    seed: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    EXPAND_SEED_LEN.check("seed", seed.len())?;
    Len::range(1, MAX_EXPANDED).check("expanded seed", out_len)?;
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    match expander {
        Expander::HkdfSha256 => {
            let kdf = new_kdf_in(table, policy, expander.id(), &Params::new())?;
            let ikm = SymmetricKey::from_bytes(seed, EXPAND_SEED_LEN)?;
            for (i, chunk) in out.chunks_mut(CHUNK).enumerate() {
                let counter = u32::try_from(i).map_err(|_| Error::InvalidInput("counter"))?;
                let info = context(expander, alg_id, out_len, counter)?;
                kdf.derive(&ikm, &[], &info, chunk)?;
            }
        }
        Expander::Shake256 => {
            let xof = new_xof_in(table, policy, expander.id(), &Params::new())?;
            // Single squeeze (counter 0); the seed length is bound in as a u64 prefix.
            let mut input = Zeroizing::new(context(expander, alg_id, out_len, 0)?);
            input.extend_from_slice(&(seed.len() as u64).to_be_bytes());
            input.extend_from_slice(seed);
            xof.squeeze(&input, &mut out)?;
        }
    }
    Ok(out)
}

/// Deterministic key pair for the KEM, signature or key-exchange algorithm `alg_id`.
pub fn keypair_from_seed_in(
    table: &[AlgoInfo],
    policy: Policy,
    alg_id: &str,
    seed: &[u8],
    mode: SeedMode,
) -> Result<(PublicKey, PrivateKey)> {
    let inst = instantiate_in(table, policy, alg_id, &Params::new())?;
    let seed_len = match &inst {
        Instance::Kem(k) => k.sizes().seed,
        Instance::Sign(s) => s.sizes().seed,
        Instance::Kex(k) => k.sizes().seed,
        _ => return Err(Error::WrongKind),
    }
    .and_then(|l| l.as_fixed())
    .filter(|n| *n > 0)
    .ok_or(Error::Unsupported)?;
    let native = match mode {
        SeedMode::Native => Seed::from_bytes(seed, Len::fixed(seed_len))?,
        SeedMode::Expand(e) => {
            let x = expand_seed_in(table, policy, e, alg_id, seed, seed_len)?;
            Seed::from_bytes(&x, Len::fixed(seed_len))?
        }
    };
    match inst {
        Instance::Kem(k) => k.keygen_from_seed(&native),
        Instance::Sign(s) => s.keygen_from_seed(&native),
        Instance::Kex(k) => k.keypair_from_seed(&native),
        _ => Err(Error::WrongKind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_registry::all;

    const ALGS: [(&str, usize); 4] = [
        ("ml-kem-768", 64),
        ("ml-dsa-65", 32),
        ("ed25519", 32),
        ("x25519", 32),
    ];

    #[test]
    fn native_seed_is_deterministic_and_exact_length() {
        for (alg, n) in ALGS {
            let seed = vec![7u8; n];
            let a =
                keypair_from_seed_in(all(), Policy::Safe, alg, &seed, SeedMode::Native).unwrap();
            let b =
                keypair_from_seed_in(all(), Policy::Safe, alg, &seed, SeedMode::Native).unwrap();
            assert_eq!(a.0, b.0, "{alg}");
            assert_eq!(a.1, b.1, "{alg}");
            for bad in [n - 1, n + 1, 0] {
                let r = keypair_from_seed_in(
                    all(),
                    Policy::Safe,
                    alg,
                    &vec![7u8; bad],
                    SeedMode::Native,
                );
                assert!(matches!(r, Err(Error::InvalidLength { .. })), "{alg} {bad}");
            }
        }
    }

    #[test]
    fn expansion_is_deterministic_separated_and_length_checked() {
        for e in [Expander::HkdfSha256, Expander::Shake256] {
            let ex = |alg: &str, seed: &[u8], n: usize| {
                expand_seed_in(all(), Policy::Safe, e, alg, seed, n)
            };
            let seed = [1u8; 20];
            let a = ex("ed25519", &seed, 32).unwrap();
            assert_eq!(*a, *ex("ed25519", &seed, 32).unwrap());
            assert_ne!(
                *a,
                *ex("x25519", &seed, 32).unwrap(),
                "algorithm id is bound in"
            );
            assert_ne!(
                a[..],
                ex("ed25519", &seed, 33).unwrap()[..32],
                "length is bound in"
            );
            assert_ne!(*a, *ex("ed25519", &[2u8; 20], 32).unwrap());
            assert!(ex("ed25519", &[1u8; 15], 32).is_err());
            assert!(ex("ed25519", &vec![1u8; 4097], 32).is_err());
            assert!(ex("ed25519", &seed, 0).is_err());
        }
        // Output longer than one chunk uses a second counter, so the blocks differ.
        let h = expand_seed_in(
            all(),
            Policy::Safe,
            Expander::HkdfSha256,
            "x",
            &[1; 16],
            2000,
        )
        .unwrap();
        assert_eq!(h.len(), 2000);
        assert_ne!(h[..976], h[1024..]);
        // The two expanders are independent.
        let a =
            expand_seed_in(all(), Policy::Safe, Expander::HkdfSha256, "x", &[1; 16], 32).unwrap();
        let b = expand_seed_in(all(), Policy::Safe, Expander::Shake256, "x", &[1; 16], 32).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn expanded_keypairs_work_for_every_seed_algorithm() {
        for (alg, _) in ALGS {
            for e in [Expander::HkdfSha256, Expander::Shake256] {
                let m = SeedMode::Expand(e);
                let s = b"a short seed.....";
                let a = keypair_from_seed_in(all(), Policy::Safe, alg, s, m).unwrap();
                let b = keypair_from_seed_in(all(), Policy::Safe, alg, s, m).unwrap();
                assert_eq!(a.0, b.0, "{alg}");
            }
        }
        let r = keypair_from_seed_in(all(), Policy::Safe, "sha256", &[0; 32], SeedMode::Native);
        assert_eq!(r.err(), Some(Error::WrongKind));
    }
}
