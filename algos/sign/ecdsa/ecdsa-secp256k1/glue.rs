//! Adapter: RustCrypto `k256` + `ecdsa` (FIPS 186-5 / SEC 1, RFC 6979) -> nextssl `Sign`,
//! curve secp256k1 with SHA-256.
//!
//! sk = the big-endian private scalar `d` (32 bytes, 1 <= d < n; anything else is an error),
//! pk = the SEC 1 uncompressed point `04 || x || y` (65 bytes, validated to be on the curve),
//! sig = fixed-width `r || s` (64 bytes, IEEE P1363). `keygen_from_seed` takes the scalar as
//! the seed (same bytes as sk); `keygen` draws field-size strings and keeps the first valid scalar
//! (FIPS 186-5 B.4.2 rejection sampling, top bits masked on P-521). The hash is fixed by the curve (COSE fully-specified ids); there is no
//! context string (`ctx` size 0). The nonce is hedged RFC 6979 by default; parameter
//! `deterministic = 1` selects plain RFC 6979 (no randomness read). High-S signatures verify
//! (plain ECDSA); produced signatures are low-S on secp256k1 and as RFC 6979 gives elsewhere.

use k256::ecdsa::{
    signature::{
        rand_core::{TryCryptoRng, TryRng},
        RandomizedSigner, Signer, Verifier,
    },
    Signature as UpSig, SigningKey, VerifyingKey,
};
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign,
    Signature as NxSignature, Sizes,
};

const PK: usize = 65;
const SK: usize = 32;
const SIG: usize = 64;
const SEED: usize = 32;
const TOP_MASK: u8 = 0xFF;
const KEYGEN_TRIES: usize = 64;

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

struct Ecdsa {
    deterministic: bool,
}

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn no_ctx(ctx: &[u8]) -> Result<()> {
    nextssl_core::check_len("ctx", ctx.len(), 0, 0)
}

fn signing_key(bytes: &[u8], what: &'static str) -> Result<SigningKey> {
    check(what, bytes.len(), SK)?;
    SigningKey::from_slice(bytes).map_err(|_| Error::InvalidInput("secp256k1 scalar out of range"))
}

fn pack(key: &SigningKey) -> Result<(PublicKey, PrivateKey)> {
    let point = key.verifying_key().to_sec1_point(false);
    let sk = key.to_bytes();
    Ok((
        PublicKey::from_bytes(point.as_bytes(), Len::fixed(PK))?,
        PrivateKey::from_bytes(sk.as_slice(), Len::fixed(SK))?,
    ))
}

impl Sign for Ecdsa {
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
        pack(&key)
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        // FIPS 186-5 B.4.2 (testing candidates): draw a field-size string, clear the bits above
        // the order's bit length, accept if 1 <= d < n, otherwise draw again.
        let mut buf = nextssl_core::Zeroizing::new([0u8; SEED]);
        for _ in 0..KEYGEN_TRIES {
            rng.fill(&mut buf[..])?;
            buf[0] &= TOP_MASK;
            if let Ok(key) = SigningKey::from_slice(&buf[..]) {
                return pack(&key);
            }
        }
        Err(Error::Backend(
            "ecdsa keygen: no valid scalar after 64 draws",
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
        let sig: UpSig = if self.deterministic {
            key.try_sign(msg)
                .map_err(|_| Error::Backend("ecdsa sign failed"))?
        } else {
            let mut r = Rng {
                src: rng,
                err: None,
            };
            match key.try_sign_with_rng(&mut r, msg) {
                Ok(s) => s,
                Err(_) => return Err(r.err.take().unwrap_or(Error::Backend("ecdsa sign failed"))),
            }
        };
        NxSignature::from_bytes(sig.to_bytes().as_slice(), Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        no_ctx(ctx)?;
        check("pk", pk.len(), PK)?;
        check("sig", sig.len(), SIG)?;
        if pk.as_bytes()[0] != 0x04 {
            return Err(Error::InvalidInput(
                "secp256k1 public key must be an uncompressed point",
            ));
        }
        let vk = VerifyingKey::from_sec1_bytes(pk.as_bytes())
            .map_err(|_| Error::InvalidInput("secp256k1 public key is not a valid point"))?;
        let s = UpSig::from_slice(sig.as_bytes())
            .map_err(|_| Error::InvalidInput("secp256k1 signature r or s out of range"))?;
        // Upstream curves may reject high-S (secp256k1 does); plain ECDSA accepts both forms, so
        // verify the equivalent low-S form (a high-S signature is valid iff its low-S twin is).
        Ok(vk.verify(msg, &s.normalize_s()).is_ok())
    }
}

/// Registry constructor. Parameter `deterministic` (0 = hedged RFC 6979, default; 1 = RFC 6979).
pub fn new(params: &Params) -> Result<Box<dyn Sign>> {
    let deterministic = match params.get_u32("deterministic") {
        None | Some(0) => false,
        Some(1) => true,
        Some(_) => return Err(Error::ParamOutOfRange("deterministic")),
    };
    Ok(Box::new(Ecdsa { deterministic }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;
    use nextssl_core::Value;
    use serde_json::Value as J;

    fn unhex(s: &str) -> Vec<u8> {
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hx(v: &J, k: &str) -> Vec<u8> {
        unhex(v[k].as_str().unwrap_or_else(|| panic!("missing {k}")))
    }
    /// Left-pads an ACVP integer to the field size.
    #[allow(dead_code)]
    fn fe(v: &J, k: &str) -> Vec<u8> {
        let b = hx(v, k);
        if b.len() > SK {
            return b; // out-of-range coordinate: keep as is (the key must be rejected)
        }
        let mut out = vec![0u8; SK - b.len()];
        out.extend_from_slice(&b);
        out
    }
    #[allow(dead_code)]
    fn point(v: &J) -> Vec<u8> {
        [&[4u8][..], &fe(v, "qx"), &fe(v, "qy")].concat()
    }
    #[allow(dead_code)]
    fn rs(v: &J) -> Vec<u8> {
        [fe(v, "r"), fe(v, "s")].concat()
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
    /// A valid scalar for every curve (top byte 0, so below n even on P-521).
    fn good(fill: u8) -> Vec<u8> {
        let mut v = vec![fill; SEED];
        v[0] = 0;
        v
    }

    #[test]
    fn wycheproof_p1363() {
        let j: J = serde_json::from_str(include_str!(
            "kat/wycheproof-ecdsa_secp256k1_sha256_p1363_test.json"
        ))
        .unwrap();
        assert_eq!(j["numberOfTests"], 252);
        let (mut valid, mut invalid) = (0, 0);
        for g in j["testGroups"].as_array().unwrap() {
            let key = unhex(g["publicKey"]["uncompressed"].as_str().unwrap());
            for t in g["tests"].as_array().unwrap() {
                let r = alg(false).verify(&pk(&key), &hx(t, "msg"), b"", &sg(&hx(t, "sig")));
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
        assert_eq!((valid, invalid), (167, 85));
    }

    #[test]
    fn sign_verify_roundtrip_both_modes() {
        let (p, s) = alg(false).keygen_from_seed(&nxseed(&good(9))).unwrap();
        let mut dry = FixedEntropy::new(&[]);
        let d1 = alg(true).sign(&s, b"m", b"", &mut dry).unwrap();
        let d2 = alg(true).sign(&s, b"m", b"", &mut dry).unwrap();
        assert_eq!(d1, d2, "deterministic mode never reads the rng");
        let mut r = FixedEntropy::new(&[5u8; SK]);
        let h = alg(false).sign(&s, b"m", b"", &mut r).unwrap();
        assert_eq!(
            r.remaining(),
            0,
            "hedged mode reads exactly one field element"
        );
        assert_ne!(h, d1);
        for sig in [&d1, &h] {
            assert!(alg(false).verify(&p, b"m", b"", sig).unwrap());
            assert!(!alg(false).verify(&p, b"x", b"", sig).unwrap());
        }
        let mut empty = FixedEntropy::new(&[]);
        assert!(matches!(
            alg(false).sign(&s, b"m", b"", &mut empty),
            Err(Error::EntropyFailure(_))
        ));
        // keygen() with an exhausted source is an error, not a key.
        assert!(alg(false).keygen(&mut empty).is_err());
    }

    #[test]
    fn validation() {
        let a = alg(true);
        let (p, s) = a.keygen_from_seed(&nxseed(&good(1))).unwrap();
        let mut rng = FixedEntropy::new(&[]);
        let sig = a.sign(&s, b"m", b"", &mut rng).unwrap();
        let bad_len = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        let bad_in = |r: Result<()>| matches!(r, Err(Error::InvalidInput(_)));
        assert!(bad_len(a.sign(&s, b"m", b"ctx", &mut rng).map(|_| ())));
        assert!(bad_len(a.verify(&p, b"m", b"ctx", &sig).map(|_| ())));
        assert!(bad_len(
            a.sign(&sk(&[1u8; SK - 1]), b"m", b"", &mut rng).map(|_| ())
        ));
        assert!(bad_len(
            a.keygen_from_seed(&nxseed(&[1u8; SEED + 1])).map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&pk(&p.as_bytes()[1..]), b"m", b"", &sig)
                .map(|_| ())
        ));
        assert!(bad_len(
            a.verify(&p, b"m", b"", &sg(&sig.as_bytes()[1..]))
                .map(|_| ())
        ));
        // zero scalar and scalar >= n are errors, never keys.
        assert!(bad_in(
            a.keygen_from_seed(&nxseed(&[0u8; SEED])).map(|_| ())
        ));
        assert!(bad_in(
            a.keygen_from_seed(&nxseed(&[0xFFu8; SEED])).map(|_| ())
        ));
        assert!(bad_in(
            a.sign(&sk(&[0u8; SK]), b"m", b"", &mut rng).map(|_| ())
        ));
        // not a point / compressed tag
        let mut nop = p.as_bytes().to_vec();
        nop[PK - 1] ^= 1;
        assert!(bad_in(a.verify(&pk(&nop), b"m", b"", &sig).map(|_| ())));
        let mut comp = p.as_bytes().to_vec();
        comp[0] = 2;
        assert!(bad_in(a.verify(&pk(&comp), b"m", b"", &sig).map(|_| ())));
        // r = 0 is malformed
        let mut zero_r = sig.as_bytes().to_vec();
        zero_r[..SK].fill(0);
        assert!(bad_in(a.verify(&p, b"m", b"", &sg(&zero_r)).map(|_| ())));
        assert!(matches!(
            new(&Params::new().with("deterministic", Value::U32(2))),
            Err(Error::ParamOutOfRange(_))
        ));
        let mut flipped = sig.as_bytes().to_vec();
        flipped[SIG - 1] ^= 1;
        assert!(!matches!(a.verify(&p, b"m", b"", &sg(&flipped)), Ok(true)));
    }
}
