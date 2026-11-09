//! Adapter: RustCrypto `slh-dsa` (FIPS 205) -> nextssl `Sign`, parameter set SLH-DSA-SHAKE-256f.
//!
//! sk = the FIPS 205 private key `SK.seed || SK.prf || PK.seed || PK.root` (128 bytes), pk =
//! `PK.seed || PK.root` (64 bytes), sig = the FIPS 205 signature (49856 bytes). The seed is
//! `SK.seed || SK.prf || PK.seed` (96 bytes, `slh_keygen_internal`). `ctx` is the FIPS 205
//! context string (0..=255 bytes; longer is an error). Signing is hedged by default (the optional
//! randomness is 32 bytes from the caller's `EntropySource`); parameter `deterministic = 1`
//! selects the deterministic variant (randomness = `PK.seed`, reads nothing). HashSLH-DSA
//! (pre-hash) is a separate algorithm id. The upstream does not check that `PK.root` in a stored
//! sk matches the seeds (that needs a full tree computation): a forged sk can only produce
//! signatures that do not verify.

use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign,
    Signature as NxSignature, Sizes, Zeroize,
};
use slh_dsa::{Shake256f, Signature as UpSig, SigningKey, VerifyingKey};

const N: usize = 32;
const PK: usize = 64;
const SK: usize = 128;
const SIG: usize = 49856;
const SEED: usize = 96;
const CTX_MAX: usize = 255;

struct SlhDsa {
    deterministic: bool,
}

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn check_ctx(ctx: &[u8]) -> Result<()> {
    nextssl_core::check_len("ctx", ctx.len(), 0, CTX_MAX)
}

fn signing_key(sk: &PrivateKey) -> Result<SigningKey<Shake256f>> {
    check("sk", sk.len(), SK)?;
    SigningKey::<Shake256f>::try_from(sk.as_bytes()).map_err(|_| Error::InvalidInput("slh-dsa sk"))
}

impl Sign for SlhDsa {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            sig: Some(Len::fixed(SIG)),
            seed: Some(Len::fixed(SEED)),
            ctx: Some(Len::range(0, CTX_MAX)),
            ..Sizes::NONE
        }
    }

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        check("seed", seed.len(), SEED)?;
        let s = seed.as_bytes();
        let key = SigningKey::<Shake256f>::slh_keygen_internal(&s[..N], &s[N..2 * N], &s[2 * N..]);
        let vk: &VerifyingKey<Shake256f> = key.as_ref();
        let pk = vk.to_bytes();
        let mut sk = key.to_bytes();
        let out = (
            PublicKey::from_bytes(pk.as_slice(), Len::fixed(PK)),
            PrivateKey::from_bytes(sk.as_slice(), Len::fixed(SK)),
        );
        sk.as_mut_slice().zeroize();
        Ok((out.0?, out.1?))
    }

    fn sign(
        &self,
        sk: &PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<NxSignature> {
        check_ctx(ctx)?;
        let key = signing_key(sk)?;
        let sig: UpSig<Shake256f> = if self.deterministic {
            key.try_sign_with_context(msg, ctx, None)
        } else {
            let mut r = [0u8; N];
            rng.fill(&mut r)?;
            let s = key.try_sign_with_context(msg, ctx, Some(&r));
            r.zeroize();
            s
        }
        .map_err(|_| Error::Backend("slh-dsa sign failed"))?;
        NxSignature::from_bytes(sig.to_bytes().as_slice(), Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        check("pk", pk.len(), PK)?;
        check("sig", sig.len(), SIG)?;
        check_ctx(ctx)?;
        let vk = VerifyingKey::<Shake256f>::try_from(pk.as_bytes())
            .map_err(|_| Error::InvalidInput("slh-dsa pk"))?;
        let sigma = UpSig::<Shake256f>::try_from(sig.as_bytes())
            .map_err(|_| Error::InvalidInput("malformed slh-dsa signature encoding"))?;
        Ok(vk.try_verify_with_context(msg, ctx, &sigma).is_ok())
    }
}

/// Registry constructor. Parameter `deterministic` (0 = hedged, default; 1 = deterministic).
pub fn new(params: &Params) -> Result<Box<dyn Sign>> {
    let deterministic = match params.get_u32("deterministic") {
        None | Some(0) => false,
        Some(1) => true,
        Some(_) => return Err(Error::ParamOutOfRange("deterministic")),
    };
    Ok(Box::new(SlhDsa { deterministic }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;
    use nextssl_core::Value;
    use serde_json::Value as J;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hx(v: &J, k: &str) -> Vec<u8> {
        unhex(v[k].as_str().unwrap_or_else(|| panic!("missing {k}")))
    }
    fn alg(det: bool) -> Box<dyn Sign> {
        new(&Params::new().with("deterministic", Value::U32(det as u32))).unwrap()
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
    fn nxseed(b: &[u8]) -> Seed {
        Seed::from_bytes(b, any()).unwrap()
    }

    #[test]
    fn acvp_keygen() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-keygen.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 5);
        for t in v {
            let s = [hx(t, "skSeed"), hx(t, "skPrf"), hx(t, "pkSeed")].concat();
            let (p, k) = alg(false).keygen_from_seed(&nxseed(&s)).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "pk"), "pk tcId {}", t["tcId"]);
            assert_eq!(k.as_bytes(), hx(t, "sk"), "sk tcId {}", t["tcId"]);
        }
    }

    #[test]
    fn acvp_siggen_external_pure() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-siggen.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 2);
        let (mut det, mut hedged) = (0, 0);
        for t in v {
            let deterministic = t["deterministic"].as_bool().unwrap();
            let mut rng = if deterministic {
                FixedEntropy::new(&[])
            } else {
                FixedEntropy::new(&hx(t, "additionalRandomness"))
            };
            let s = alg(deterministic)
                .sign(
                    &sk(&hx(t, "sk")),
                    &hx(t, "message"),
                    &hx(t, "context"),
                    &mut rng,
                )
                .unwrap();
            assert_eq!(s.as_bytes(), hx(t, "signature"), "sig tcId {}", t["tcId"]);
            assert_eq!(
                rng.remaining(),
                0,
                "randomness consumed, tcId {}",
                t["tcId"]
            );
            if deterministic {
                det += 1
            } else {
                hedged += 1
            }
        }
        assert_eq!((det, hedged), (1, 1));
    }

    #[test]
    fn acvp_sigver_external_pure() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-sigver.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 7);
        let (mut pass, mut fail) = (0, 0);
        for t in v {
            let r = alg(false).verify(
                &pk(&hx(t, "pk")),
                &hx(t, "message"),
                &hx(t, "context"),
                &sg(&hx(t, "signature")),
            );
            if t["testPassed"].as_bool().unwrap() {
                assert!(matches!(r, Ok(true)), "should verify, tcId {}", t["tcId"]);
                pass += 1;
            } else {
                assert!(
                    !matches!(r, Ok(true)),
                    "must be rejected, tcId {} ({})",
                    t["tcId"],
                    t["reason"]
                );
                fail += 1;
            }
        }
        assert_eq!((pass, fail), (1, 6));
    }

    #[test]
    fn sign_verify_roundtrip_both_modes() {
        let (p, s) = alg(false).keygen_from_seed(&nxseed(&[9u8; SEED])).unwrap();
        let mut dry = FixedEntropy::new(&[]);
        let d1 = alg(true).sign(&s, b"m", b"ctx", &mut dry).unwrap();
        // deterministic mode never reads the rng (the empty source would fail otherwise)
        let mut r = FixedEntropy::new(&[5u8; N]);
        let h = alg(false).sign(&s, b"m", b"ctx", &mut r).unwrap();
        assert_eq!(r.remaining(), 0);
        assert_ne!(h, d1);
        for sig in [&d1, &h] {
            assert!(alg(false).verify(&p, b"m", b"ctx", sig).unwrap());
            assert!(!alg(false).verify(&p, b"m", b"other", sig).unwrap());
            assert!(!alg(false).verify(&p, b"x", b"ctx", sig).unwrap());
        }
        let mut empty = FixedEntropy::new(&[]);
        assert!(matches!(
            alg(false).sign(&s, b"m", b"", &mut empty),
            Err(Error::EntropyFailure(_))
        ));
    }

    #[test]
    fn context_and_length_validation() {
        let a = alg(true);
        let (p, s) = a.keygen_from_seed(&nxseed(&[1u8; SEED])).unwrap();
        let mut rng = FixedEntropy::new(&[]);
        let sig = a.sign(&s, b"m", &[7u8; 255], &mut rng).unwrap();
        assert!(a.verify(&p, b"m", &[7u8; 255], &sig).unwrap());
        let bad_len = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        assert!(bad_len(a.sign(&s, b"m", &[7u8; 256], &mut rng).map(|_| ())));
        assert!(bad_len(a.verify(&p, b"m", &[7u8; 256], &sig).map(|_| ())));
        assert!(bad_len(
            a.sign(&sk(&[0u8; SK - 1]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_len(
            a.sign(&sk(&[0u8; SK + 1]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&pk(&p.as_bytes()[1..]), b"m", b"", &sig)
                .map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&p, b"m", b"", &sg(&sig.as_bytes()[1..]))
                .map(|_| ())
        ));
        assert!(bad_len(
            a.keygen_from_seed(&nxseed(&[0u8; SEED + 1])).map(|_| ())
        ));
        assert!(bad_len(
            a.keygen_from_seed(&nxseed(&[0u8; SEED - 1])).map(|_| ())
        ));
        assert!(matches!(
            new(&Params::new().with("deterministic", Value::U32(2))),
            Err(Error::ParamOutOfRange(_))
        ));
        let mut bad = sig.as_bytes().to_vec();
        bad[SIG / 2] ^= 1;
        assert!(!matches!(
            a.verify(&p, b"m", &[7u8; 255], &sg(&bad)),
            Ok(true)
        ));
    }
}
