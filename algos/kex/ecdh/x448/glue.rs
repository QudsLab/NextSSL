//! Adapter: RustCrypto `x448` (RFC 7748) -> nextssl `Kex`.
//!
//! sk = the 56-byte scalar (clamped inside the upstream), pk/ss = 56-byte u-coordinates. An all-zero
//! shared secret (low-order or zero peer key, RFC 7748 section 6) is `Error::InvalidInput`, never
//! returned; the upstream also rejects low-order public keys before multiplying.
//! `keypair_from_seed` takes 32..=56 bytes and zero-extends them at the high end (RFC 7748
//! scalars are little-endian); sk is the zero-extended 56 bytes. A 56-byte seed is the scalar itself.

use nextssl_core::{
    Error, Kex, Len, Params, PrivateKey, PublicKey, Result, Seed, SharedSecret, Sizes, Zeroize,
};
use x448::{PublicKey as UpPublic, StaticSecret};

const PK: usize = 56;
const SK: usize = 56;
const SS: usize = 56;
const SEED_MIN: usize = 32;
const SEED_MAX: usize = 56;

struct X448;

fn secret(bytes: &[u8], what: &'static str) -> Result<StaticSecret> {
    nextssl_core::check_len(what, bytes.len(), 1, SK)?;
    let mut arr = [0u8; SK];
    arr[..bytes.len()].copy_from_slice(bytes);
    let s = StaticSecret::from(arr);
    arr.zeroize();
    Ok(s)
}

impl Kex for X448 {
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
        let s = secret(seed.as_bytes(), "seed")?;
        let pk = UpPublic::from(&s);
        let mut full = [0u8; SK];
        full[..seed.len()].copy_from_slice(seed.as_bytes());
        let out = PrivateKey::from_bytes(&full, Len::fixed(SK));
        full.zeroize();
        Ok((PublicKey::from_bytes(pk.as_bytes(), Len::fixed(PK))?, out?))
    }

    fn keypair(
        &self,
        rng: &mut dyn nextssl_core::EntropySource,
    ) -> Result<(PublicKey, PrivateKey)> {
        let mut buf = nextssl_core::Zeroizing::new([0u8; SK]);
        rng.fill(&mut buf[..])?;
        let seed = Seed::from_bytes(&buf[..], Len::fixed(SK))?;
        self.keypair_from_seed(&seed)
    }

    fn agree(&self, sk: &PrivateKey, peer_pk: &PublicKey) -> Result<SharedSecret> {
        nextssl_core::check_len("sk", sk.len(), SK, SK)?;
        let s = secret(sk.as_bytes(), "sk")?;
        nextssl_core::check_len("pk", peer_pk.len(), PK, PK)?;
        let peer = UpPublic::from_bytes(peer_pk.as_bytes())
            .ok_or(Error::InvalidInput("x448 public key is a low-order point"))?;
        let shared = s.diffie_hellman(&peer);
        if shared.as_bytes().iter().all(|b| *b == 0) {
            return Err(Error::InvalidInput(
                "x448 shared secret is all-zero (low-order peer key)",
            ));
        }
        SharedSecret::from_bytes(shared.as_bytes(), Len::fixed(SS))
    }
}

/// Registry constructor. X448 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Kex>> {
    Ok(Box::new(X448))
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
    fn any() -> Len {
        Len::range(0, usize::MAX)
    }
    fn pk(b: &[u8]) -> PublicKey {
        PublicKey::from_bytes(b, any()).unwrap()
    }
    fn sk(b: &[u8]) -> PrivateKey {
        PrivateKey::from_bytes(b, any()).unwrap()
    }
    fn alg() -> Box<dyn Kex> {
        new(&Params::new()).unwrap()
    }
    fn s(j: &J, k: &str) -> Vec<u8> {
        unhex(j[k].as_str().unwrap_or_else(|| panic!("missing {k}")))
    }
    const BASE: [u8; 56] = {
        let mut b = [0u8; 56];
        b[0] = 5;
        b
    };

    #[test]
    fn rfc7748_vectors() {
        let j: J = serde_json::from_str(include_str!("kat/rfc7748.json")).unwrap();
        let f = j["section_5_2_function"].as_array().unwrap();
        assert_eq!(f.len(), 2);
        for t in f {
            let r = alg().agree(&sk(&s(t, "scalar")), &pk(&s(t, "u"))).unwrap();
            assert_eq!(r.as_bytes(), s(t, "out"));
        }
        // iterated: 1 and 1000 iterations (the 1,000,000 value is recorded, not run).
        let it = &j["section_5_2_iterated"];
        let (mut k, mut u) = (s(it, "initial"), s(it, "initial"));
        for i in 1..=1000 {
            let out = alg().agree(&sk(&k), &pk(&u)).unwrap().as_bytes().to_vec();
            u = k;
            k = out;
            if i == 1 {
                assert_eq!(k, s(it, "after_1"));
            }
        }
        assert_eq!(k, s(it, "after_1000"));
        // section 6.2 Diffie-Hellman
        let d = &j["section_6_2_dh"];
        let a = Seed::from_bytes(&s(d, "alice_sk"), any()).unwrap();
        let b = Seed::from_bytes(&s(d, "bob_sk"), any()).unwrap();
        let (apk, ask) = alg().keypair_from_seed(&a).unwrap();
        let (bpk, bsk) = alg().keypair_from_seed(&b).unwrap();
        assert_eq!(apk.as_bytes(), s(d, "alice_pk"));
        assert_eq!(bpk.as_bytes(), s(d, "bob_pk"));
        assert_eq!(alg().agree(&ask, &bpk).unwrap().as_bytes(), s(d, "shared"));
        assert_eq!(alg().agree(&bsk, &apk).unwrap().as_bytes(), s(d, "shared"));
        assert_eq!(
            alg()
                .agree(&sk(&s(d, "alice_sk")), &pk(&BASE))
                .unwrap()
                .as_bytes(),
            s(d, "alice_pk")
        );
    }

    #[test]
    fn wycheproof_x448() {
        let j: J = serde_json::from_str(include_str!("kat/wycheproof-x448_test.json")).unwrap();
        assert_eq!(j["numberOfTests"], 510);
        let (mut ok, mut rejected, mut n) = (0, 0, 0);
        for g in j["testGroups"].as_array().unwrap() {
            for t in g["tests"].as_array().unwrap() {
                n += 1;
                let want = s(t, "shared");
                let public = s(t, "public");
                let r = alg().agree(&sk(&s(t, "private")), &pk(&public));
                let id = &t["tcId"];
                if want.iter().all(|b| *b == 0) || public.len() != PK {
                    // zero secret (low-order key) or a wrong-length key: explicit error.
                    assert!(r.is_err(), "zero secret / bad key accepted: tcId {id}");
                    rejected += 1;
                } else {
                    assert_eq!(r.unwrap().as_bytes(), want, "tcId {id}");
                    ok += 1;
                }
            }
        }
        assert_eq!(n, 510);
        assert_eq!((ok, rejected), (487, 23));
    }

    #[test]
    fn seeds_and_validation() {
        let a = alg();
        let (p, k) = a
            .keypair_from_seed(&Seed::from_bytes(&[5u8; 32], any()).unwrap())
            .unwrap();
        // a 32-byte seed is the scalar zero-extended at the high end
        let mut full = [5u8; 32].to_vec();
        full.extend_from_slice(&[0u8; 24]);
        let (p2, k2) = a
            .keypair_from_seed(&Seed::from_bytes(&full, any()).unwrap())
            .unwrap();
        assert_eq!(p, p2);
        assert_eq!(k.as_bytes(), k2.as_bytes());
        assert_eq!(k.len(), SK);
        assert!(matches!(
            a.agree(&k, &pk(&[0u8; 56])),
            Err(Error::InvalidInput(_))
        ));
        let mut one = [0u8; 56];
        one[0] = 1;
        assert!(matches!(
            a.agree(&k, &pk(&one)),
            Err(Error::InvalidInput(_))
        ));
        let bad = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        assert!(bad(a.agree(&k, &pk(&p.as_bytes()[1..])).map(|_| ())));
        assert!(bad(a.agree(&sk(&[0u8; 57]), &p).map(|_| ())));
        assert!(bad(a
            .keypair_from_seed(&Seed::from_bytes(&[0u8; 31], any()).unwrap())
            .map(|_| ())));
        assert!(bad(a
            .keypair_from_seed(&Seed::from_bytes(&[0u8; 57], any()).unwrap())
            .map(|_| ())));
        // keypair() draws exactly one 56-byte scalar.
        let mut e = FixedEntropy::new(
            &full[..32]
                .iter()
                .chain(&[0u8; 24])
                .copied()
                .collect::<Vec<u8>>(),
        );
        assert_eq!(a.keypair(&mut e).unwrap().0, p);
        assert_eq!(e.remaining(), 0);
        let mut dry = FixedEntropy::new(&[]);
        assert!(a.keypair(&mut dry).is_err());
    }
}
