//! Adapter: `ed25519-dalek` (RFC 8032 pure Ed25519) -> nextssl `Sign`.
//!
//! sk = the 32-byte RFC 8032 secret seed, pk = 32 bytes, sig = R || S (64 bytes). Ed25519 has no
//! context string (`ctx` size 0): a non-empty `ctx` is an error, never ignored. Ed25519ctx and
//! Ed25519ph are separate algorithm ids. Signing is deterministic and does not read `rng`.
//! Verification uses the upstream `verify_strict`: it rejects non-canonical S and small-order
//! R or A (RFC 8032 section 8.4 and 5.1.7 malleability checks).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign,
    Signature as NxSignature, Sizes, Zeroize,
};

const PK: usize = 32;
const SK: usize = 32;
const SIG: usize = 64;
const SEED: usize = 32;

struct Ed25519;

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn no_ctx(ctx: &[u8]) -> Result<()> {
    // Sizes::ctx is 0, i.e. contexts are unsupported.
    nextssl_core::check_len("ctx", ctx.len(), 0, 0)
}

fn signing_key(bytes: &[u8], what: &'static str) -> Result<SigningKey> {
    check(what, bytes.len(), SK)?;
    let mut arr = [0u8; SK];
    arr.copy_from_slice(bytes);
    let key = SigningKey::from_bytes(&arr);
    arr.zeroize();
    Ok(key)
}

impl Sign for Ed25519 {
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
            PublicKey::from_bytes(&key.verifying_key().to_bytes(), Len::fixed(PK))?,
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
        no_ctx(ctx)?;
        let key = signing_key(sk.as_bytes(), "sk")?;
        let sig = key.sign(msg);
        NxSignature::from_bytes(&sig.to_bytes(), Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        no_ctx(ctx)?;
        check("pk", pk.len(), PK)?;
        check("sig", sig.len(), SIG)?;
        let mut pk_arr = [0u8; PK];
        pk_arr.copy_from_slice(pk.as_bytes());
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|_| Error::InvalidInput("ed25519 public key is not a valid point"))?;
        let mut sig_arr = [0u8; SIG];
        sig_arr.copy_from_slice(sig.as_bytes());
        let sig = Signature::from_bytes(&sig_arr);
        Ok(vk.verify_strict(msg, &sig).is_ok())
    }
}

/// Registry constructor. Ed25519 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(Ed25519))
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
    fn sg(b: &[u8]) -> NxSignature {
        NxSignature::from_bytes(b, any()).unwrap()
    }
    fn alg() -> Box<dyn Sign> {
        new(&Params::new()).unwrap()
    }

    #[test]
    fn rfc8032_section_7_1() {
        let j: J = serde_json::from_str(include_str!("kat/rfc8032-7.1.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 5);
        let mut rng = FixedEntropy::new(&[]);
        for t in v {
            let seed = Seed::from_bytes(&hx(t, "sk"), any()).unwrap();
            let (p, s) = alg().keygen_from_seed(&seed).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "pk"), "pk {}", t["id"]);
            let sig = alg().sign(&s, &hx(t, "msg"), b"", &mut rng).unwrap();
            assert_eq!(sig.as_bytes(), hx(t, "sig"), "sig {}", t["id"]);
            assert!(alg().verify(&p, &hx(t, "msg"), b"", &sig).unwrap());
            assert!(!alg().verify(&p, b"tampered", b"", &sig).unwrap());
        }
    }

    #[test]
    fn wycheproof_ed25519() {
        let j: J = serde_json::from_str(include_str!("kat/wycheproof-ed25519_test.json")).unwrap();
        assert_eq!(j["numberOfTests"], 210);
        let (mut valid, mut invalid, mut acceptable, mut acc_accepted) = (0, 0, 0, 0);
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
                    "acceptable" => {
                        // Torsion keys: either answer is allowed by Wycheproof. verify_strict must
                        // still reject every small-order public key.
                        acceptable += 1;
                        if matches!(r, Ok(true)) {
                            acc_accepted += 1;
                            assert!(
                                !t["flags"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .any(|f| f == "SmallOrderPublicKey"),
                                "small-order key accepted: tcId {id}"
                            );
                        }
                    }
                    other => panic!("unknown result {other}"),
                }
            }
        }
        assert_eq!((valid, invalid, acceptable), (117, 64, 29));
        // Mixed-order (non-small-order torsion) keys that satisfy the cofactored equation are
        // accepted by verify_strict; Wycheproof marks them acceptable. Pin the observed count.
        assert_eq!(acc_accepted, 21);
    }

    #[test]
    fn validation() {
        let a = alg();
        let mut rng = FixedEntropy::new(&[]);
        let seed = Seed::from_bytes(&[3u8; 32], any()).unwrap();
        let (p, s) = a.keygen_from_seed(&seed).unwrap();
        let sig = a.sign(&s, b"m", b"", &mut rng).unwrap();
        let bad = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        assert!(bad(a.sign(&s, b"m", b"ctx", &mut rng).map(|_| ())));
        assert!(bad(a.verify(&p, b"m", b"ctx", &sig).map(|_| ())));
        assert!(bad(a
            .sign(
                &PrivateKey::from_bytes(&[0u8; 31], any()).unwrap(),
                b"m",
                b"",
                &mut rng
            )
            .map(|_| ())));
        assert!(bad(a
            .keygen_from_seed(&Seed::from_bytes(&[0u8; 33], any()).unwrap())
            .map(|_| ())));
        assert!(bad(a.verify(&pk(&[0u8; 31]), b"m", b"", &sig).map(|_| ())));
        assert!(bad(a
            .verify(&p, b"m", b"", &sg(&sig.as_bytes()[..63]))
            .map(|_| ())));
        let mut flipped = sig.as_bytes().to_vec();
        flipped[0] ^= 1;
        assert!(!matches!(a.verify(&p, b"m", b"", &sg(&flipped)), Ok(true)));
        // y = 2 is not on the curve: a malformed key is an error, not Ok(false).
        let mut notpoint = [0u8; 32];
        notpoint[0] = 2;
        assert!(matches!(
            a.verify(&pk(&notpoint), b"m", b"", &sig),
            Err(Error::InvalidInput(_))
        ));
        // keygen() draws exactly one 32-byte seed from the entropy source.
        let mut e = FixedEntropy::new(&[3u8; 32]);
        let (p2, _) = a.keygen(&mut e).unwrap();
        assert_eq!(p2, p);
        assert_eq!(e.remaining(), 0);
    }
}
