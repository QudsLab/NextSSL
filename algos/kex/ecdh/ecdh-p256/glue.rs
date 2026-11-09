//! Adapter: RustCrypto `p256` ECDH (SEC 1 / NIST SP 800-56A cofactor-free ECDH, NIST P-256)
//! -> nextssl `Kex`.
//!
//! sk = the big-endian private scalar (32 bytes, 1 <= d < n), pk = the SEC 1 uncompressed point
//! `04 || x || y` (65 bytes, validated to be on the curve; compressed and hybrid encodings are
//! errors), ss = the raw x-coordinate (32 bytes, not hashed). `keypair_from_seed` takes a
//! seed of 32..=32 bytes, read as a big-endian scalar left-padded with zeros (sk is the padded
//! scalar); a zero or out-of-range scalar is an error. `keypair` draws a uniformly random scalar
//! by rejection sampling (top bits masked on P-521).

use nextssl_core::{
    EntropySource, Error, Kex, Len, Params, PrivateKey, PublicKey, Result, Seed, SharedSecret,
    Sizes, Zeroize, Zeroizing,
};
use p256::elliptic_curve::{ecdh::diffie_hellman, sec1::ToSec1Point};
use p256::{PublicKey as UpPublic, SecretKey as UpSecret};

const PK: usize = 65;
const SK: usize = 32;
const SS: usize = 32;
const SEED_MIN: usize = 32;
const SEED_MAX: usize = 32;
const TOP_MASK: u8 = 0xFF;
const KEYGEN_TRIES: usize = 64;

struct Ecdh;

fn secret_from_padded(bytes: &[u8], what: &'static str) -> Result<UpSecret> {
    nextssl_core::check_len(what, bytes.len(), 1, SK)?;
    let mut buf = [0u8; SK];
    buf[SK - bytes.len()..].copy_from_slice(bytes);
    let r = UpSecret::from_slice(&buf)
        .map_err(|_| Error::InvalidInput("NIST P-256 scalar is zero or out of range"));
    buf.zeroize();
    r
}

fn pack(key: &UpSecret) -> Result<(PublicKey, PrivateKey)> {
    let point = key.public_key().to_sec1_point(false);
    let mut sk = key.to_bytes();
    let out = (
        PublicKey::from_bytes(point.as_bytes(), Len::fixed(PK)),
        PrivateKey::from_bytes(sk.as_slice(), Len::fixed(SK)),
    );
    sk.as_mut_slice().zeroize();
    Ok((out.0?, out.1?))
}

impl Kex for Ecdh {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            ss: Some(Len::fixed(SS)),
            seed: Some(Len::range(SEED_MIN, SEED_MAX)),
            ..Sizes::NONE
        }
    }

    fn keypair_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        nextssl_core::check_len("seed", seed.len(), SEED_MIN, SEED_MAX)?;
        let key = secret_from_padded(seed.as_bytes(), "seed")?;
        pack(&key)
    }

    fn keypair(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        // FIPS 186-5 B.4.2 style rejection sampling: draw a field-size string, clear the bits
        // above the order's bit length, accept if 1 <= d < n, otherwise draw again.
        let mut buf = Zeroizing::new([0u8; SK]);
        for _ in 0..KEYGEN_TRIES {
            rng.fill(&mut buf[..])?;
            buf[0] &= TOP_MASK;
            if let Ok(key) = UpSecret::from_slice(&buf[..]) {
                return pack(&key);
            }
        }
        Err(Error::Backend(
            "ecdh keygen: no valid scalar after 64 draws",
        ))
    }

    fn agree(&self, sk: &PrivateKey, peer_pk: &PublicKey) -> Result<SharedSecret> {
        nextssl_core::check_len("sk", sk.len(), SK, SK)?;
        nextssl_core::check_len("pk", peer_pk.len(), PK, PK)?;
        if peer_pk.as_bytes()[0] != 0x04 {
            return Err(Error::InvalidInput(
                "NIST P-256 public key must be an uncompressed point",
            ));
        }
        let secret = secret_from_padded(sk.as_bytes(), "sk")?;
        let peer = UpPublic::from_sec1_bytes(peer_pk.as_bytes())
            .map_err(|_| Error::InvalidInput("NIST P-256 public key is not a valid point"))?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        SharedSecret::from_bytes(shared.raw_secret_bytes().as_slice(), Len::fixed(SS))
    }
}

/// Registry constructor. NIST P-256 ECDH takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Kex>> {
    Ok(Box::new(Ecdh))
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
    fn nxseed(b: &[u8]) -> Seed {
        Seed::from_bytes(b, any()).unwrap()
    }
    fn alg() -> Box<dyn Kex> {
        new(&Params::new()).unwrap()
    }
    /// Wycheproof private keys carry a sign byte or are shorter than the field: normalise.
    fn scalar(b: &[u8]) -> Vec<u8> {
        let mut b = b;
        while b.len() > SK && b[0] == 0 {
            b = &b[1..];
        }
        let mut out = vec![0u8; SK.saturating_sub(b.len())];
        out.extend_from_slice(b);
        out
    }

    #[test]
    fn wycheproof_ecpoint() {
        let j: J = serde_json::from_str(include_str!(
            "kat/wycheproof-ecdh_secp256r1_ecpoint_test.json"
        ))
        .unwrap();
        assert_eq!(j["numberOfTests"], 355);
        let (mut valid, mut invalid, mut compressed, mut acceptable) = (0, 0, 0, 0);
        for g in j["testGroups"].as_array().unwrap() {
            for t in g["tests"].as_array().unwrap() {
                let id = &t["tcId"];
                let public = hx(t, "public");
                let private = scalar(&hx(t, "private"));
                let r = alg().agree(&sk(&private), &pk(&public));
                match t["result"].as_str().unwrap() {
                    "valid" if public.len() == PK => {
                        let got = r.unwrap_or_else(|e| panic!("valid rejected: tcId {id}: {e:?}"));
                        assert_eq!(got.as_bytes(), hx(t, "shared"), "shared tcId {id}");
                        valid += 1;
                    }
                    "valid" => {
                        // Compressed encodings are valid for Wycheproof; this algorithm accepts
                        // uncompressed points only and says so with an explicit error.
                        assert_eq!(public.len(), 1 + SK, "unexpected encoding tcId {id}");
                        assert!(matches!(r, Err(Error::InvalidLength { .. })), "tcId {id}");
                        compressed += 1;
                    }
                    "invalid" => {
                        assert!(r.is_err(), "invalid accepted: tcId {id}");
                        invalid += 1;
                    }
                    "acceptable" => acceptable += 1,
                    other => panic!("unknown result {other}"),
                }
            }
        }
        assert_eq!((valid, invalid, compressed, acceptable), (330, 24, 0, 1));
    }

    #[test]
    fn agreement_and_seed_forms() {
        let a = alg();
        let (pa, sa) = a.keypair_from_seed(&nxseed(&[0x11u8; 32])).unwrap();
        let (pb, sb) = a.keypair_from_seed(&nxseed(&[0x22u8; 32])).unwrap();
        assert_eq!(pa.len(), PK);
        assert_eq!(sa.len(), SK);
        let s1 = a.agree(&sa, &pb).unwrap();
        let s2 = a.agree(&sb, &pa).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), SS);
        // a shorter seed is the zero-extended scalar: same key as the padded form
        let mut padded = vec![0u8; SEED_MAX - 32];
        padded.extend_from_slice(&[0x11u8; 32]);
        let (pa2, sa2) = a.keypair_from_seed(&nxseed(&padded)).unwrap();
        assert_eq!(pa2, pa);
        assert_eq!(sa2.as_bytes(), sa.as_bytes());
        // random path reads one field element
        let mut e = FixedEntropy::new(&[0x01u8; SK]);
        let (pr, _) = a.keypair(&mut e).unwrap();
        assert_eq!(pr.len(), PK);
        let mut dry = FixedEntropy::new(&[]);
        assert!(a.keypair(&mut dry).is_err());
    }

    #[test]
    fn validation() {
        let a = alg();
        let (pa, sa) = a.keypair_from_seed(&nxseed(&[0x11u8; 32])).unwrap();
        let bad_len = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        let bad_in = |r: Result<()>| matches!(r, Err(Error::InvalidInput(_)));
        assert!(bad_len(
            a.keypair_from_seed(&nxseed(&[1u8; 31])).map(|_| ())
        ));
        assert!(bad_len(
            a.keypair_from_seed(&nxseed(&[1u8; SEED_MAX + 1]))
                .map(|_| ())
        ));
        assert!(bad_in(a.keypair_from_seed(&nxseed(&[0u8; 32])).map(|_| ())));
        assert!(bad_in(
            a.keypair_from_seed(&nxseed(&[0xFFu8; SEED_MAX]))
                .map(|_| ())
        ));
        assert!(bad_len(a.agree(&sk(&[1u8; SK - 1]), &pa).map(|_| ())));
        assert!(bad_len(a.agree(&sa, &pk(&pa.as_bytes()[1..])).map(|_| ())));
        assert!(bad_in(a.agree(&sk(&[0u8; SK]), &pa).map(|_| ())));
        let mut off = pa.as_bytes().to_vec();
        off[PK - 1] ^= 1;
        assert!(bad_in(a.agree(&sa, &pk(&off)).map(|_| ())));
        let mut tag = pa.as_bytes().to_vec();
        tag[0] = 6;
        assert!(bad_in(a.agree(&sa, &pk(&tag)).map(|_| ())));
        assert!(bad_in(a.agree(&sa, &pk(&[0u8; PK])).map(|_| ())));
    }
}
