//! Adapter: `x25519-dalek` (RFC 7748) -> nextssl `Kex`.
//!
//! sk = the 32-byte scalar (clamped inside the upstream), pk/ss = 32-byte u-coordinates.
//! An all-zero shared secret (low-order or zero peer key, RFC 7748 section 6.1) is
//! `Error::InvalidInput`, never returned.

use nextssl_core::{
    Error, Kex, Len, Params, PrivateKey, PublicKey, Result, Seed, SharedSecret, Sizes, Zeroize,
};
use x25519_dalek::{PublicKey as UpPublic, StaticSecret};

const PK: usize = 32;
const SK: usize = 32;
const SS: usize = 32;
const SEED: usize = 32;

struct X25519;

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn secret(bytes: &[u8], what: &'static str) -> Result<StaticSecret> {
    check(what, bytes.len(), SK)?;
    let mut arr = [0u8; SK];
    arr.copy_from_slice(bytes);
    let s = StaticSecret::from(arr);
    arr.zeroize();
    Ok(s)
}

impl Kex for X25519 {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            ss: Some(Len::fixed(SS)),
            seed: Some(Len::fixed(SEED)),
            ..Sizes::NONE
        }
    }

    fn keypair_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        let s = secret(seed.as_bytes(), "seed")?;
        let pk = UpPublic::from(&s);
        Ok((
            PublicKey::from_bytes(pk.as_bytes(), Len::fixed(PK))?,
            PrivateKey::from_bytes(seed.as_bytes(), Len::fixed(SK))?,
        ))
    }

    fn agree(&self, sk: &PrivateKey, peer_pk: &PublicKey) -> Result<SharedSecret> {
        let s = secret(sk.as_bytes(), "sk")?;
        check("pk", peer_pk.len(), PK)?;
        let mut pk_arr = [0u8; PK];
        pk_arr.copy_from_slice(peer_pk.as_bytes());
        let peer = UpPublic::from(pk_arr);
        let shared = s.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(Error::InvalidInput(
                "x25519 shared secret is all-zero (low-order peer key)",
            ));
        }
        let mut bytes = shared.to_bytes();
        let out = SharedSecret::from_bytes(&bytes, Len::fixed(SS));
        bytes.zeroize();
        out
    }
}

/// Registry constructor. X25519 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Kex>> {
    Ok(Box::new(X25519))
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
    const BASE: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 9;
        b
    };

    #[test]
    fn rfc7748_vectors() {
        let j: J = serde_json::from_str(include_str!("kat/rfc7748.json")).unwrap();
        // 5.2 function vectors (agree == X25519(k, u))
        let f = j["section_5_2_function"].as_array().unwrap();
        assert_eq!(f.len(), 2);
        for t in f {
            let r = alg().agree(&sk(&s(t, "scalar")), &pk(&s(t, "u"))).unwrap();
            assert_eq!(r.as_bytes(), s(t, "out"));
        }
        // 5.2 iterated: 1 and 1000 iterations (the 1,000,000 value is recorded, not run).
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
        // 6.1 Diffie-Hellman
        let d = &j["section_6_1_dh"];
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
    fn wycheproof_x25519() {
        let j: J = serde_json::from_str(include_str!("kat/wycheproof-x25519_test.json")).unwrap();
        assert_eq!(j["numberOfTests"], 518);
        let (mut ok, mut zero_rejected, mut n) = (0, 0, 0);
        for g in j["testGroups"].as_array().unwrap() {
            for t in g["tests"].as_array().unwrap() {
                n += 1;
                let want = s(t, "shared");
                let r = alg().agree(&sk(&s(t, "private")), &pk(&s(t, "public")));
                let id = &t["tcId"];
                if want.iter().all(|b| *b == 0) {
                    assert!(
                        matches!(r, Err(Error::InvalidInput(_))),
                        "zero secret returned: tcId {id}"
                    );
                    zero_rejected += 1;
                } else {
                    assert_eq!(r.unwrap().as_bytes(), want, "tcId {id}");
                    ok += 1;
                }
            }
        }
        assert_eq!(n, 518);
        assert_eq!(ok + zero_rejected, 518);
        assert_eq!(zero_rejected, 31);
    }

    #[test]
    fn rejects_zero_and_bad_lengths() {
        let a = alg();
        let (p, k) = a
            .keypair_from_seed(&Seed::from_bytes(&[5u8; 32], any()).unwrap())
            .unwrap();
        // zero point and a known small-order point both give the all-zero secret
        assert!(matches!(
            a.agree(&k, &pk(&[0u8; 32])),
            Err(Error::InvalidInput(_))
        ));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(matches!(
            a.agree(&k, &pk(&one)),
            Err(Error::InvalidInput(_))
        ));
        let bad = |r: Result<()>| matches!(r, Err(Error::InvalidLength { .. }));
        assert!(bad(a.agree(&k, &pk(&p.as_bytes()[1..])).map(|_| ())));
        assert!(bad(a.agree(&sk(&[0u8; 33]), &p).map(|_| ())));
        assert!(bad(a
            .keypair_from_seed(&Seed::from_bytes(&[0u8; 31], any()).unwrap())
            .map(|_| ())));
        let mut e = FixedEntropy::new(&[5u8; 32]);
        assert_eq!(a.keypair(&mut e).unwrap().0, p);
        assert_eq!(e.remaining(), 0);
    }
}
