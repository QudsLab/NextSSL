//! Adapter: RustCrypto `ed448-goldilocks` (RFC 8032 pure Ed448) -> nextssl `Sign`.
//!
//! sk = the 57-byte RFC 8032 secret seed, pk = 57 bytes, sig = R || S (114 bytes). `ctx` is the
//! RFC 8032 context string (0..=255 bytes; longer is an error); an empty context is plain Ed448.
//! Ed448ph is a separate algorithm id. Signing is deterministic and does not read `rng`.
//! The upstream verifier rejects a non-canonical or zero S, an identity R and an identity key.

use ed448_goldilocks::{Signature, SigningKey, VerifyingKey};
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign,
    Signature as NxSignature, Sizes,
};

const PK: usize = 57;
const SK: usize = 57;
const SIG: usize = 114;
const SEED: usize = 57;
const CTX_MAX: usize = 255;

struct Ed448;

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn check_ctx(ctx: &[u8]) -> Result<()> {
    nextssl_core::check_len("ctx", ctx.len(), 0, CTX_MAX)
}

fn signing_key(bytes: &[u8], what: &'static str) -> Result<SigningKey> {
    check(what, bytes.len(), SK)?;
    SigningKey::try_from(bytes).map_err(|_| Error::InvalidInput("ed448 secret key"))
}

impl Sign for Ed448 {
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
        let key = signing_key(seed.as_bytes(), "seed")?;
        Ok((
            PublicKey::from_bytes(key.verifying_key().as_bytes().as_slice(), Len::fixed(PK))?,
            PrivateKey::from_bytes(seed.as_bytes(), Len::fixed(SK))?,
        ))
    }

    fn sign(
        &self,
        sk: &PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<NxSignature> {
        check_ctx(ctx)?;
        let key = signing_key(sk.as_bytes(), "sk")?;
        let sig = key
            .sign_ctx(ctx, msg)
            .map_err(|_| Error::Backend("ed448 sign failed"))?;
        NxSignature::from_bytes(sig.to_bytes().as_slice(), Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        check_ctx(ctx)?;
        check("pk", pk.len(), PK)?;
        check("sig", sig.len(), SIG)?;
        // RFC 8032 5.2.3: bits 448..=454 of an encoded point (R or A) are unused and must be
        // zero; the upstream ignores them, so reject here instead of accepting a malleated R.
        if pk.as_bytes()[PK - 1] & 0x7F != 0 {
            return Err(Error::InvalidInput(
                "ed448 public key has non-zero unused bits",
            ));
        }
        if sig.as_bytes()[PK - 1] & 0x7F != 0 {
            return Err(Error::InvalidInput(
                "ed448 signature R has non-zero unused bits",
            ));
        }
        let mut pk_arr = [0u8; PK];
        pk_arr.copy_from_slice(pk.as_bytes());
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|_| Error::InvalidInput("ed448 public key is not a valid point"))?;
        let sig = Signature::from_slice(sig.as_bytes())
            .map_err(|_| Error::InvalidInput("ed448 signature encoding"))?;
        Ok(vk.verify_ctx(&sig, ctx, msg).is_ok())
    }
}

/// Registry constructor. Ed448 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(Ed448))
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
    fn hxo(v: &J, k: &str) -> Vec<u8> {
        v[k].as_str().map(unhex).unwrap_or_default()
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
    fn alg() -> Box<dyn Sign> {
        new(&Params::new()).unwrap()
    }

    #[test]
    fn rfc8032_section_7_4() {
        let j: J = serde_json::from_str(include_str!("kat/rfc8032-7.4.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 9);
        let mut rng = FixedEntropy::new(&[]);
        for t in v {
            let (p, s) = alg().keygen_from_seed(&nxseed(&hx(t, "sk"))).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "pk"), "pk {}", t["id"]);
            let (msg, ctx) = (hx(t, "msg"), hxo(t, "ctx"));
            let sig = alg().sign(&s, &msg, &ctx, &mut rng).unwrap();
            assert_eq!(sig.as_bytes(), hx(t, "sig"), "sig {}", t["id"]);
            assert!(alg().verify(&p, &msg, &ctx, &sig).unwrap());
            assert!(!alg().verify(&p, b"tampered", &ctx, &sig).unwrap());
        }
    }

    #[test]
    fn wycheproof_ed448() {
        let j: J = serde_json::from_str(include_str!("kat/wycheproof-ed448_test.json")).unwrap();
        assert_eq!(j["numberOfTests"], 87);
        let (mut valid, mut invalid) = (0, 0);
        for g in j["testGroups"].as_array().unwrap() {
            let key = unhex(g["publicKey"]["pk"].as_str().unwrap());
            for t in g["tests"].as_array().unwrap() {
                let r = alg().verify(&pk(&key), &hx(t, "msg"), b"", &sg(&hx(t, "sig")));
                let id = &t["tcId"];
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        assert!(matches!(r, Ok(true)), "valid rejected: tcId {id}");
                        valid += 1;
                    }
                    "invalid" => {
                        assert!(!matches!(r, Ok(true)), "invalid accepted: tcId {id}");
                        invalid += 1;
                    }
                    other => panic!("unexpected result {other}"),
                }
            }
        }
        assert_eq!((valid, invalid), (17, 70));
    }

    #[test]
    fn acvp_eddsa_ed448() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-eddsa-ed448.json")).unwrap();
        let kg = j["keygen"].as_array().unwrap();
        assert_eq!(kg.len(), 3);
        for t in kg {
            let (p, s) = alg().keygen_from_seed(&nxseed(&hx(t, "d"))).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "q"), "keygen tcId {}", t["tcId"]);
            assert_eq!(s.as_bytes(), hx(t, "d"));
        }
        let sgn = j["siggen"].as_array().unwrap();
        assert_eq!(sgn.len(), 42);
        let mut rng = FixedEntropy::new(&[]);
        for t in sgn {
            let (p, s) = alg().keygen_from_seed(&nxseed(&hx(t, "d"))).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "q"), "siggen key tcId {}", t["tcId"]);
            let (msg, ctx) = (hx(t, "message"), hxo(t, "context"));
            let sig = alg().sign(&s, &msg, &ctx, &mut rng).unwrap();
            assert_eq!(
                sig.as_bytes(),
                hx(t, "signature"),
                "siggen tcId {}",
                t["tcId"]
            );
        }
        let sv = j["sigver"].as_array().unwrap();
        assert_eq!(sv.len(), 5);
        let (mut pass, mut fail) = (0, 0);
        for t in sv {
            let (p, _) = alg().keygen_from_seed(&nxseed(&hx(t, "d"))).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "q"));
            let r = alg().verify(&p, &hx(t, "message"), b"", &sg(&hx(t, "signature")));
            if t["testPassed"].as_bool().unwrap() {
                assert!(matches!(r, Ok(true)), "sigver tcId {}", t["tcId"]);
                pass += 1;
            } else {
                assert!(!matches!(r, Ok(true)), "sigver reject tcId {}", t["tcId"]);
                fail += 1;
            }
        }
        assert!(pass > 0 && fail > 0);
    }

    #[test]
    fn validation() {
        let a = alg();
        let mut rng = FixedEntropy::new(&[]);
        let (p, s) = a.keygen_from_seed(&nxseed(&[3u8; SEED])).unwrap();
        let sig = a.sign(&s, b"m", b"", &mut rng).unwrap();
        let bad = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        let ok255 = a.sign(&s, b"m", &[7u8; 255], &mut rng).unwrap();
        assert!(a.verify(&p, b"m", &[7u8; 255], &ok255).unwrap());
        assert!(!a.verify(&p, b"m", &[7u8; 254], &ok255).unwrap());
        assert!(bad(a.sign(&s, b"m", &[7u8; 256], &mut rng).map(|_| ())));
        assert!(bad(a.verify(&p, b"m", &[7u8; 256], &sig).map(|_| ())));
        assert!(bad(a
            .sign(&sk(&[0u8; SK - 1]), b"m", b"", &mut rng)
            .map(|_| ())));
        assert!(bad(a
            .keygen_from_seed(&nxseed(&[0u8; SEED + 1]))
            .map(|_| ())));
        assert!(bad(a
            .verify(&pk(&p.as_bytes()[1..]), b"m", b"", &sig)
            .map(|_| ())));
        assert!(bad(a
            .verify(&p, b"m", b"", &sg(&sig.as_bytes()[..SIG - 1]))
            .map(|_| ())));
        let mut flipped = sig.as_bytes().to_vec();
        flipped[0] ^= 1;
        assert!(!matches!(a.verify(&p, b"m", b"", &sg(&flipped)), Ok(true)));
        // a point that does not decode is an error, not Ok(false).
        let mut notpoint = [0xFFu8; PK];
        notpoint[PK - 1] = 0;
        assert!(matches!(
            a.verify(&pk(&notpoint), b"m", b"", &sig),
            Err(Error::InvalidInput(_))
        ));
        // keygen() draws exactly one 57-byte seed from the entropy source.
        let mut e = FixedEntropy::new(&[3u8; SEED]);
        let (p2, _) = a.keygen(&mut e).unwrap();
        assert_eq!(p2, p);
        assert_eq!(e.remaining(), 0);
    }
}
