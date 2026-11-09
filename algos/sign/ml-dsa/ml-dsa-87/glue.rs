//! Adapter: RustCrypto `ml-dsa` (FIPS 204) -> nextssl `Sign`, parameter set ML-DSA-87.
//!
//! The private key is the 32-byte seed xi (never the expanded 4896-byte form: the upstream
//! decoder for that form is documented as able to panic on malformed input). The public key
//! and signature use the FIPS 204 encodings (2592 / 4627 bytes). `ctx` is the FIPS 204
//! context string (0..=255 bytes; longer is an error). Signing is hedged by default
//! (randomness from the caller's `EntropySource`); parameter `deterministic = 1` selects the
//! deterministic variant. HashML-DSA (pre-hash) is a separate algorithm id.

use ml_dsa::{
    signature::rand_core::{TryCryptoRng, TryRng},
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, Keypair, MlDsa87, Seed, Signature,
    SigningKey, VerifyingKey,
};
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed as NxSeed, Sign,
    Signature as NxSignature, Sizes, Zeroize,
};

const PK: usize = 2592;
const SK: usize = 32;
const SIG: usize = 4627;
const SEED: usize = 32;
const CTX_MAX: usize = 255;

/// Bridges nextssl's `EntropySource` to the upstream's rng trait and remembers the real error.
struct Rng<'a> {
    src: &'a mut dyn EntropySource,
    err: Option<Error>,
}

#[derive(Debug)]
struct RngFailed;
impl core::fmt::Display for RngFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("entropy source failed")
    }
}
impl core::error::Error for RngFailed {}

impl TryRng for Rng<'_> {
    type Error = RngFailed;
    fn try_next_u32(&mut self) -> core::result::Result<u32, RngFailed> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, RngFailed> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), RngFailed> {
        self.src.fill(dst).map_err(|e| {
            self.err = Some(e);
            RngFailed
        })
    }
}
impl TryCryptoRng for Rng<'_> {}

struct MlDsa87Sign {
    deterministic: bool,
}

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn check_ctx(ctx: &[u8]) -> Result<()> {
    nextssl_core::check_len("ctx", ctx.len(), 0, CTX_MAX)
}

fn expand(sk: &PrivateKey) -> Result<ExpandedSigningKey<MlDsa87>> {
    check("sk", sk.len(), SK)?;
    let mut xi: Seed = Seed::try_from(sk.as_bytes()).map_err(|_| Error::InvalidInput("sk"))?;
    let esk = ExpandedSigningKey::<MlDsa87>::from_seed(&xi);
    xi.as_mut_slice().zeroize();
    Ok(esk)
}

/// Signs with an already expanded key. Shared by `Sign::sign` and the ACVP test (which
/// supplies NIST's expanded sk for trusted vectors).
fn sign_with(
    esk: &ExpandedSigningKey<MlDsa87>,
    msg: &[u8],
    ctx: &[u8],
    deterministic: bool,
    rng: &mut dyn EntropySource,
) -> Result<NxSignature> {
    check_ctx(ctx)?;
    let sig = if deterministic {
        esk.sign_deterministic(msg, ctx)
            .map_err(|_| Error::Backend("ml-dsa deterministic sign failed"))?
    } else {
        let mut r = Rng {
            src: rng,
            err: None,
        };
        match esk.sign_randomized(msg, ctx, &mut r) {
            Ok(s) => s,
            Err(_) => return Err(r.err.take().unwrap_or(Error::Backend("ml-dsa sign failed"))),
        }
    };
    NxSignature::from_bytes(sig.encode().as_slice(), Len::fixed(SIG))
}

impl Sign for MlDsa87Sign {
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

    fn keygen_from_seed(&self, seed: &NxSeed) -> Result<(PublicKey, PrivateKey)> {
        check("seed", seed.len(), SEED)?;
        let mut xi: Seed =
            Seed::try_from(seed.as_bytes()).map_err(|_| Error::InvalidInput("seed"))?;
        let key = SigningKey::<MlDsa87>::from_seed(&xi);
        xi.as_mut_slice().zeroize();
        let pk = key.verifying_key().encode();
        Ok((
            PublicKey::from_bytes(pk.as_slice(), Len::fixed(PK))?,
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
        check_ctx(ctx)?;
        let esk = expand(sk)?;
        sign_with(&esk, msg, ctx, self.deterministic, rng)
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        check("pk", pk.len(), PK)?;
        check("sig", sig.len(), SIG)?;
        check_ctx(ctx)?;
        let vk_enc = EncodedVerifyingKey::<MlDsa87>::try_from(pk.as_bytes())
            .map_err(|_| Error::InvalidInput("pk"))?;
        let sig_enc = EncodedSignature::<MlDsa87>::try_from(sig.as_bytes())
            .map_err(|_| Error::InvalidInput("sig"))?;
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
        let sigma = Signature::<MlDsa87>::decode(&sig_enc)
            .ok_or(Error::InvalidInput("malformed ml-dsa signature encoding"))?;
        Ok(vk.verify_with_context(msg, ctx, &sigma))
    }
}

/// Registry constructor. Parameter `deterministic` (0 = hedged, default; 1 = deterministic).
pub fn new(params: &Params) -> Result<Box<dyn Sign>> {
    let deterministic = match params.get_u32("deterministic") {
        None | Some(0) => false,
        Some(1) => true,
        Some(_) => return Err(Error::ParamOutOfRange("deterministic")),
    };
    Ok(Box::new(MlDsa87Sign { deterministic }))
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
    fn nxseed(b: &[u8]) -> NxSeed {
        NxSeed::from_bytes(b, any()).unwrap()
    }

    #[test]
    fn acvp_keygen() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-keygen.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 25);
        for t in v {
            let s = nxseed(&hx(t, "seed"));
            let (p, k) = alg(false).keygen_from_seed(&s).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "pk"), "pk tcId {}", t["tcId"]);
            assert_eq!(k.as_bytes(), s.as_bytes());
            // NIST's expanded sk must equal the upstream expansion of the same seed.
            let xi = Seed::try_from(s.as_bytes()).unwrap();
            let esk = ExpandedSigningKey::<MlDsa87>::from_seed(&xi);
            #[allow(deprecated)]
            let enc = esk.to_expanded();
            assert_eq!(enc.as_slice(), hx(t, "sk"), "sk tcId {}", t["tcId"]);
        }
    }

    #[test]
    fn acvp_siggen_external_pure() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-siggen.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 30);
        let (mut det, mut hedged) = (0, 0);
        for t in v {
            let deterministic = t["deterministic"].as_bool().unwrap();
            let enc = hx(t, "sk");
            assert_eq!(enc.len(), 4896);
            let enc = ml_dsa::ExpandedSigningKeyBytes::<MlDsa87>::try_from(enc.as_slice()).unwrap();
            // Trusted NIST vector only; never done on caller input.
            #[allow(deprecated)]
            let esk = ExpandedSigningKey::<MlDsa87>::from_expanded(&enc);
            let mut rng = if deterministic {
                FixedEntropy::new(&[])
            } else {
                FixedEntropy::new(&hx(t, "rnd"))
            };
            let s = sign_with(
                &esk,
                &hx(t, "message"),
                &hx(t, "context"),
                deterministic,
                &mut rng,
            )
            .unwrap();
            assert_eq!(s.as_bytes(), hx(t, "signature"), "sig tcId {}", t["tcId"]);
            assert_eq!(
                rng.remaining(),
                0,
                "all rnd bytes consumed, tcId {}",
                t["tcId"]
            );
            if deterministic {
                det += 1
            } else {
                hedged += 1
            }
        }
        assert_eq!((det, hedged), (15, 15));
    }

    #[test]
    fn acvp_sigver_external_pure() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-sigver.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 15);
        let (mut pass, mut fail) = (0, 0);
        for t in v {
            let expect = t["testPassed"].as_bool().unwrap();
            let r = alg(false).verify(
                &pk(&hx(t, "pk")),
                &hx(t, "message"),
                &hx(t, "context"),
                &sg(&hx(t, "signature")),
            );
            if expect {
                assert!(matches!(r, Ok(true)), "should verify, tcId {}", t["tcId"]);
                pass += 1;
            } else {
                assert!(
                    !matches!(r, Ok(true)),
                    "must be rejected, tcId {}",
                    t["tcId"]
                );
                fail += 1;
            }
        }
        assert_eq!((pass, fail), (3, 12));
    }

    #[test]
    fn sign_verify_roundtrip_both_modes() {
        let (p, s) = alg(false).keygen_from_seed(&nxseed(&[9u8; 32])).unwrap();
        let mut dry = FixedEntropy::new(&[]);
        let d1 = alg(true).sign(&s, b"m", b"ctx", &mut dry).unwrap();
        let d2 = alg(true).sign(&s, b"m", b"ctx", &mut dry).unwrap();
        assert_eq!(
            d1, d2,
            "deterministic mode is deterministic and never reads rng"
        );
        let mut r = FixedEntropy::new(&[5u8; 32]);
        let h = alg(false).sign(&s, b"m", b"ctx", &mut r).unwrap();
        assert_eq!(r.remaining(), 0);
        for sig in [&d1, &h] {
            assert!(alg(false).verify(&p, b"m", b"ctx", sig).unwrap());
            assert!(!alg(false).verify(&p, b"m", b"other", sig).unwrap());
            assert!(!alg(false).verify(&p, b"x", b"ctx", sig).unwrap());
        }
        // hedged signing with exhausted entropy returns the entropy error, not a signature.
        let mut empty = FixedEntropy::new(&[]);
        assert!(matches!(
            alg(false).sign(&s, b"m", b"", &mut empty),
            Err(Error::EntropyFailure(_))
        ));
    }

    #[test]
    fn context_and_length_validation() {
        let a = alg(true);
        let (p, s) = a.keygen_from_seed(&nxseed(&[1u8; 32])).unwrap();
        let mut rng = FixedEntropy::new(&[]);
        let ok255 = a.sign(&s, b"m", &[7u8; 255], &mut rng).unwrap();
        assert!(a.verify(&p, b"m", &[7u8; 255], &ok255).unwrap());
        let bad_len = |r: Result<_>| matches!(r, Err(Error::InvalidLength { .. }));
        assert!(bad_len(a.sign(&s, b"m", &[7u8; 256], &mut rng).map(|_| ())));
        assert!(bad_len(a.verify(&p, b"m", &[7u8; 256], &ok255).map(|_| ())));
        assert!(bad_len(
            a.sign(&sk(&[0u8; 31]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_len(
            a.sign(&sk(&[0u8; 4896]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&pk(&p.as_bytes()[1..]), b"m", b"", &ok255)
                .map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&p, b"m", b"", &sg(&ok255.as_bytes()[1..]))
                .map(|_| ())
        ));
        assert!(bad_len(a.keygen_from_seed(&nxseed(&[0u8; 33])).map(|_| ())));
        assert!(matches!(
            new(&Params::new().with("deterministic", Value::U32(2))),
            Err(Error::ParamOutOfRange(_))
        ));
        // a flipped signature byte never verifies as true
        let mut bad = ok255.as_bytes().to_vec();
        bad[100] ^= 1;
        assert!(!matches!(
            a.verify(&p, b"m", &[7u8; 255], &sg(&bad)),
            Ok(true)
        ));
    }
}
