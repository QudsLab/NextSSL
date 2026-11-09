//! Adapter: RustCrypto `ml-kem` (FIPS 203) -> nextssl `Kem`, parameter set ML-KEM-1024.
//!
//! `seed` is `d || z` (64 bytes), `coins` is `m` (32 bytes). The private key is the FIPS 203
//! expanded decapsulation key `dk` (3168 bytes); it is parsed with the upstream's validating
//! decoder (`Result`, no panics), which checks the embedded `ek` against its stored hash.
//! Decapsulation of a well-formed but forged ciphertext returns the implicit-rejection secret.

#![allow(deprecated)] // the FIPS 203 expanded dk encoding is deprecated upstream but is the NIST format

use ml_kem::{
    array::Array,
    ml_kem_1024::{Ciphertext as UpCiphertext, DecapsulationKey as UpDk, EncapsulationKey as UpEk},
    Decapsulate, ExpandedKeyEncoding, KeyExport,
};
use nextssl_core::{
    Ciphertext, Error, Kem, Len, Params, PrivateKey, PublicKey, Result, Seed, SharedSecret, Sizes,
    Zeroize,
};

const PK: usize = 1568;
const SK: usize = 3168;
const CT: usize = 1568;
const SS: usize = 32;
const SEED: usize = 64;
const COINS: usize = 32;

struct MlKem1024Kem;

fn parse_pk(pk: &PublicKey) -> Result<UpEk> {
    if pk.len() != PK {
        return Err(Error::InvalidLength {
            what: "pk",
            got: pk.len(),
            min: PK,
            max: PK,
        });
    }
    let key = Array::try_from(pk.as_bytes()).map_err(|_| Error::InvalidInput("pk"))?;
    UpEk::new(&key).map_err(|_| Error::InvalidInput("ml-kem-1024 public key failed validation"))
}

fn parse_sk(sk: &PrivateKey) -> Result<UpDk> {
    if sk.len() != SK {
        return Err(Error::InvalidLength {
            what: "sk",
            got: sk.len(),
            min: SK,
            max: SK,
        });
    }
    let mut enc = Array::try_from(sk.as_bytes()).map_err(|_| Error::InvalidInput("sk"))?;
    let r = <UpDk as ExpandedKeyEncoding>::from_expanded_bytes(&enc)
        .map_err(|_| Error::InvalidInput("ml-kem-1024 private key failed validation"));
    enc.as_mut_slice().zeroize();
    r
}

impl Kem for MlKem1024Kem {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            ct: Some(Len::fixed(CT)),
            ss: Some(Len::fixed(SS)),
            seed: Some(Len::fixed(SEED)),
            coins: Some(Len::fixed(COINS)),
            ..Sizes::NONE
        }
    }

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        if seed.len() != SEED {
            return Err(Error::InvalidLength {
                what: "seed",
                got: seed.len(),
                min: SEED,
                max: SEED,
            });
        }
        let mut s: ml_kem::Seed =
            Array::try_from(seed.as_bytes()).map_err(|_| Error::InvalidInput("seed"))?;
        let dk = UpDk::from_seed(s);
        s.as_mut_slice().zeroize();
        let pk = dk.encapsulation_key().to_bytes();
        let mut sk = dk.to_expanded_bytes();
        let out = (
            PublicKey::from_bytes(pk.as_slice(), Len::fixed(PK))?,
            PrivateKey::from_bytes(sk.as_slice(), Len::fixed(SK)),
        );
        sk.as_mut_slice().zeroize();
        Ok((out.0, out.1?))
    }

    fn encaps_from_coins(
        &self,
        pk: &PublicKey,
        coins: &Seed,
    ) -> Result<(Ciphertext, SharedSecret)> {
        if coins.len() != COINS {
            return Err(Error::InvalidLength {
                what: "coins",
                got: coins.len(),
                min: COINS,
                max: COINS,
            });
        }
        let ek = parse_pk(pk)?;
        let mut m: ml_kem::B32 =
            Array::try_from(coins.as_bytes()).map_err(|_| Error::InvalidInput("coins"))?;
        let (ct, mut ss) = ek.encapsulate_deterministic(&m);
        m.as_mut_slice().zeroize();
        let r = (
            Ciphertext::from_bytes(ct.as_slice(), Len::fixed(CT)),
            SharedSecret::from_bytes(ss.as_slice(), Len::fixed(SS)),
        );
        ss.as_mut_slice().zeroize();
        Ok((r.0?, r.1?))
    }

    fn decaps(&self, sk: &PrivateKey, ct: &Ciphertext) -> Result<SharedSecret> {
        if ct.len() != CT {
            return Err(Error::InvalidLength {
                what: "ct",
                got: ct.len(),
                min: CT,
                max: CT,
            });
        }
        let dk = parse_sk(sk)?;
        let ctu: UpCiphertext =
            Array::try_from(ct.as_bytes()).map_err(|_| Error::InvalidInput("ct"))?;
        let mut ss = dk.decapsulate(&ctu);
        let r = SharedSecret::from_bytes(ss.as_slice(), Len::fixed(SS));
        ss.as_mut_slice().zeroize();
        r
    }
}

/// Registry constructor. ML-KEM-1024 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Kem>> {
    Ok(Box::new(MlKem1024Kem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;
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
    fn kem() -> Box<dyn Kem> {
        new(&Params::new()).unwrap()
    }
    fn pk(b: &[u8]) -> PublicKey {
        PublicKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }
    fn sk(b: &[u8]) -> PrivateKey {
        PrivateKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }
    fn ct(b: &[u8]) -> Ciphertext {
        Ciphertext::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }
    fn seed(b: &[u8]) -> Seed {
        Seed::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn acvp_keygen() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-keygen.json")).unwrap();
        let v = j["vectors"].as_array().unwrap();
        assert_eq!(v.len(), 25);
        for t in v {
            let s = [hx(t, "d"), hx(t, "z")].concat();
            let (p, k) = kem().keygen_from_seed(&seed(&s)).unwrap();
            assert_eq!(p.as_bytes(), hx(t, "ek"), "ek tcId {}", t["tcId"]);
            assert_eq!(k.as_bytes(), hx(t, "dk"), "dk tcId {}", t["tcId"]);
        }
    }

    #[test]
    fn acvp_encapdecap() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-encapdecap.json")).unwrap();
        let (e, d) = (
            j["encapsulation"].as_array().unwrap(),
            j["decapsulation"].as_array().unwrap(),
        );
        assert_eq!((e.len(), d.len()), (25, 10));
        for t in e {
            let (c, k) = kem()
                .encaps_from_coins(&pk(&hx(t, "ek")), &seed(&hx(t, "m")))
                .unwrap();
            assert_eq!(c.as_bytes(), hx(t, "c"), "c tcId {}", t["tcId"]);
            assert_eq!(k.as_bytes(), hx(t, "k"), "k tcId {}", t["tcId"]);
        }
        for t in d {
            let k = kem().decaps(&sk(&hx(t, "dk")), &ct(&hx(t, "c"))).unwrap();
            assert_eq!(k.as_bytes(), hx(t, "k"), "decaps tcId {}", t["tcId"]);
        }
    }

    #[test]
    fn acvp_key_checks() {
        let j: J = serde_json::from_str(include_str!("kat/acvp-encapdecap.json")).unwrap();
        let coins = seed(&[7u8; 32]);
        let eks = j["encapsulationKeyCheck"].as_array().unwrap();
        let dks = j["decapsulationKeyCheck"].as_array().unwrap();
        assert_eq!((eks.len(), dks.len()), (10, 10));
        for t in eks {
            let ok = t["testPassed"].as_bool().unwrap();
            let r = kem().encaps_from_coins(&pk(&hx(t, "ek")), &coins);
            assert_eq!(r.is_ok(), ok, "ek check tcId {}", t["tcId"]);
        }
        for t in dks {
            let ok = t["testPassed"].as_bool().unwrap();
            let r = kem().decaps(&sk(&hx(t, "dk")), &ct(&[0u8; CT]));
            assert_eq!(r.is_ok(), ok, "dk check tcId {}", t["tcId"]);
        }
    }

    #[test]
    fn random_path_roundtrip_and_implicit_rejection() {
        let k = kem();
        let mut rng = FixedEntropy::new(&[[1u8; 64].as_slice(), &[2u8; 32]].concat());
        let (p, s) = k.keygen(&mut rng).unwrap();
        let (c, ss) = k.encaps(&p, &mut rng).unwrap();
        assert_eq!(rng.remaining(), 0);
        assert_eq!(k.decaps(&s, &c).unwrap(), ss);
        let mut bad = c.as_bytes().to_vec();
        bad[0] ^= 1;
        let rej = k.decaps(&s, &ct(&bad)).unwrap();
        assert_ne!(rej, ss);
        assert_eq!(rej.len(), SS);
    }

    #[test]
    fn rejects_bad_lengths() {
        let k = kem();
        let (p, s) = k.keygen_from_seed(&seed(&[0u8; 64])).unwrap();
        let c = ct(&vec![0u8; CT]);
        assert!(matches!(
            k.keygen_from_seed(&seed(&[0u8; 63])),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            k.keygen_from_seed(&seed(&[0u8; 65])),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            k.encaps_from_coins(&p, &seed(&[0u8; 31])),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            k.encaps_from_coins(&p, &seed(&[0u8; 33])),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            k.encaps_from_coins(&pk(&p.as_bytes()[1..]), &seed(&[0; 32])),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            k.decaps(&sk(&s.as_bytes()[1..]), &c),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            k.decaps(&s, &ct(&[0u8; CT - 1])),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            k.decaps(&s, &ct(&[0u8; CT + 1])),
            Err(Error::InvalidLength { .. })
        ));
        // rng with too little entropy surfaces an error, never a short/zero seed.
        let mut dry = FixedEntropy::new(&[0u8; 10]);
        assert!(k.keygen(&mut dry).is_err());
    }

    #[test]
    fn sizes_match_metadata() {
        let s = kem().sizes();
        assert_eq!(s.pk, Some(Len::fixed(PK)));
        assert_eq!(s.sk, Some(Len::fixed(SK)));
        assert_eq!(s.seed, Some(Len::fixed(SEED)));
    }
}
