//! Adapter: RustCrypto `k256` Schnorr (BIP 340, secp256k1 x-only keys) -> nextssl `Sign`.
//!
//! sk = the 32-byte big-endian secret scalar d (1 <= d < n; the sign of the public point is
//! handled inside the upstream as BIP 340 requires), pk = the 32-byte x-only public key, sig =
//! `r || s` (64 bytes). Messages are arbitrary length (BIP 340 as amended in 2022). There is no
//! context string (`ctx` size 0): a non-empty `ctx` is an error. Signing mixes 32 bytes of
//! auxiliary randomness from the caller's `EntropySource` (BIP 340 default signing); the nonce
//! never depends on randomness alone. `keygen_from_seed` takes d as the seed.

use k256::schnorr::{Signature as UpSig, SigningKey, VerifyingKey};
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign,
    Signature as NxSignature, Sizes, Zeroize,
};

const PK: usize = 32;
const SK: usize = 32;
const SIG: usize = 64;
const SEED: usize = 32;
const AUX: usize = 32;

struct Bip340;

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn no_ctx(ctx: &[u8]) -> Result<()> {
    nextssl_core::check_len("ctx", ctx.len(), 0, 0)
}

fn signing_key(bytes: &[u8], what: &'static str) -> Result<SigningKey> {
    check(what, bytes.len(), SK)?;
    SigningKey::from_slice(bytes).map_err(|_| Error::InvalidInput("bip340 secret key out of range"))
}

impl Sign for Bip340 {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            sig: Some(Len::fixed(SIG)),
            seed: Some(Len::fixed(SEED)),
            ctx: Some(Len::fixed(0)),
            ..Sizes::NONE
        }
    }

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        let key = signing_key(seed.as_bytes(), "seed")?;
        Ok((
            PublicKey::from_bytes(key.verifying_key().to_bytes().as_slice(), Len::fixed(PK))?,
            PrivateKey::from_bytes(seed.as_bytes(), Len::fixed(SK))?,
        ))
    }

    fn sign(
        &self,
        sk: &PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<NxSignature> {
        no_ctx(ctx)?;
        let key = signing_key(sk.as_bytes(), "sk")?;
        let mut aux = [0u8; AUX];
        rng.fill(&mut aux)?;
        let sig = key.sign_raw(msg, &aux);
        aux.zeroize();
        let sig = sig.map_err(|_| Error::Backend("bip340 sign failed"))?;
        NxSignature::from_bytes(sig.to_bytes().as_slice(), Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        no_ctx(ctx)?;
        check("pk", pk.len(), PK)?;
        check("sig", sig.len(), SIG)?;
        let vk = VerifyingKey::from_slice(pk.as_bytes())
            .map_err(|_| Error::InvalidInput("bip340 public key is not a valid x coordinate"))?;
        let s = UpSig::from_slice(sig.as_bytes())
            .map_err(|_| Error::InvalidInput("bip340 signature r or s out of range"))?;
        Ok(vk.verify_raw(msg, &s).is_ok())
    }
}

/// Registry constructor. BIP 340 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(Bip340))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;
    use serde_json::Value as J;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hx(v: &J, k: &str) -> Vec<u8> {
        unhex(v[k].as_str().unwrap_or_else(|| panic!("missing {k}")))
    }
    fn any() -> Len {
        Len::range(0, usize::MAX)
    }
    fn pk(b: &[u8]) -> PublicKey {
        PublicKey::from_bytes(b, any()).unwrap()
    }
    fn sk(b: &[u8]) -> PrivateKey {
        PrivateKey::from_bytes(b, any()).unwrap()
    }
    fn sg(b: &[u8]) -> NxSignature {
        NxSignature::from_bytes(b, any()).unwrap()
    }
    fn alg() -> Box<dyn Sign> {
        new(&Params::new()).unwrap()
    }

    #[test]
    fn bip340_test_vectors() {
        let j: J = serde_json::from_str(include_str!("kat/bip340-test-vectors.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 19);
        let (mut signed, mut accepted, mut rejected) = (0, 0, 0);
        for t in v {
            let id = &t["index"];
            if let Some(sec) = t["secret key"].as_str().filter(|s| !s.is_empty()) {
                // signing vector: key derivation and the exact signature
                let seed = Seed::from_bytes(&unhex(sec), any()).unwrap();
                let (p, s) = alg().keygen_from_seed(&seed).unwrap();
                assert_eq!(p.as_bytes(), hx(t, "public key"), "pk index {id}");
                let mut rng = FixedEntropy::new(&hx(t, "aux_rand"));
                let sig = alg().sign(&s, &hx(t, "message"), b"", &mut rng).unwrap();
                assert_eq!(sig.as_bytes(), hx(t, "signature"), "sig index {id}");
                assert_eq!(rng.remaining(), 0);
                signed += 1;
            }
            let r = alg().verify(
                &pk(&hx(t, "public key")),
                &hx(t, "message"),
                b"",
                &sg(&hx(t, "signature")),
            );
            if t["verification result"] == "TRUE" {
                assert!(matches!(r, Ok(true)), "should verify, index {id}");
                accepted += 1;
            } else {
                assert!(!matches!(r, Ok(true)), "must reject, index {id}");
                rejected += 1;
            }
        }
        assert_eq!((signed, accepted, rejected), (8, 9, 10));
    }

    #[test]
    fn validation() {
        let a = alg();
        let seed = Seed::from_bytes(&[7u8; 32], any()).unwrap();
        let (p, s) = a.keygen_from_seed(&seed).unwrap();
        let mut rng = FixedEntropy::new(&[1u8; 64]);
        let sig = a.sign(&s, b"msg", b"", &mut rng).unwrap();
        assert!(a.verify(&p, b"msg", b"", &sig).unwrap());
        assert!(!a.verify(&p, b"msh", b"", &sig).unwrap());
        // an empty message signs and verifies
        let e = a.sign(&s, b"", b"", &mut rng).unwrap();
        assert!(a.verify(&p, b"", b"", &e).unwrap());
        let bad_len = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        assert!(bad_len(a.sign(&s, b"m", b"ctx", &mut rng).map(|_| ())));
        assert!(bad_len(a.verify(&p, b"m", b"ctx", &sig).map(|_| ())));
        assert!(bad_len(
            a.sign(&sk(&[1u8; 31]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&pk(&p.as_bytes()[1..]), b"m", b"", &sig)
                .map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&p, b"m", b"", &sg(&sig.as_bytes()[1..]))
                .map(|_| ())
        ));
        let bad_in = |r: Result<()>| matches!(r, Err(Error::InvalidInput(_)));
        assert!(bad_in(
            a.sign(&sk(&[0u8; 32]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_in(
            a.sign(&sk(&[0xFFu8; 32]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_in(
            a.verify(&pk(&[0xFFu8; 32]), b"m", b"", &sig).map(|_| ())
        ));
        // exhausted entropy is an error, never a signature
        let mut dry = FixedEntropy::new(&[]);
        assert!(matches!(
            a.sign(&s, b"m", b"", &mut dry),
            Err(Error::EntropyFailure(_))
        ));
    }
}
