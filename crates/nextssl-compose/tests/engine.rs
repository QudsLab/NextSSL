//! Composition engine tests: known answers, equivalence with the concrete registry ids, slot
//! and tier rules, DRBG CAVP replay, random keygen and hashcash.

use nextssl_compose::{
    canonical, compose, compose_with, effective_tier, keygen, rng, Built, Policy, CIPHERS, DIGESTS,
};
use nextssl_core::{Error, Len, Params, SymmetricKey, Tier, Value};
use nextssl_registry::{all, lookup_in, new_blockmode_in, new_kdf_in, new_mac_in, new_pwhash_in};
use serde_json::Value as J;
use std::path::PathBuf;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn key(bytes: &[u8]) -> SymmetricKey {
    SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
}

fn load(name: &str) -> J {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("kat")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

fn has_all() -> bool {
    cfg!(feature = "compose-all")
}

// ---- known answers --------------------------------------------------------------------

#[test]
fn hmac_rfc4231_case1() {
    let c = compose("hmac(sha256)", Policy::Safe).unwrap();
    let mut tag = vec![0u8; 32];
    c.mac()
        .unwrap()
        .tag(&key(&[0x0b; 20]), b"Hi There", &mut tag)
        .unwrap();
    assert_eq!(
        tag,
        unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

#[test]
fn hkdf_rfc5869_case1() {
    let c = compose("hkdf(sha256)", Policy::Safe).unwrap();
    let ikm = key(&[0x0b; 22]);
    let salt: Vec<u8> = (0..=0x0c).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    let mut okm = vec![0u8; 42];
    c.kdf()
        .unwrap()
        .derive(&ikm, &salt, &info, &mut okm)
        .unwrap();
    assert_eq!(
        okm,
        unhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
}

#[test]
fn pbkdf2_rfc7914_sha256() {
    let p = Params::new()
        .with("iterations", Value::U32(1))
        .with("out_len", Value::U32(64));
    let c = compose_with("pbkdf2(hmac(sha256))", &p, Policy::Safe).unwrap();
    let mut out = vec![0u8; 64];
    c.pwhash()
        .unwrap()
        .derive(b"passwd", b"salt", &mut out)
        .unwrap();
    assert_eq!(
        out,
        unhex(concat!(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        ))
    );
    // PHC round trip.
    let phc = c.pwhash().unwrap().hash(b"pw", b"saltsalt").unwrap();
    assert!(phc.starts_with("$pbkdf2-sha256$"));
    assert!(c.pwhash().unwrap().verify(b"pw", &phc).unwrap());
    assert!(!c.pwhash().unwrap().verify(b"pX", &phc).unwrap());
}

#[test]
fn cmac_rfc4493_empty() {
    let c = compose("cmac(aes-128)", Policy::Safe).unwrap();
    let mut tag = vec![0u8; 16];
    c.mac()
        .unwrap()
        .tag(
            &key(&unhex("2b7e151628aed2a6abf7158809cf4f3c")),
            b"",
            &mut tag,
        )
        .unwrap();
    assert_eq!(tag, unhex("bb1d6929e95937287fa37d129b756746"));
}

#[test]
fn cbc_sp800_38a_f21_first_block() {
    let c = compose("cbc(aes-128)", Policy::Safe).unwrap();
    let k = key(&unhex("2b7e151628aed2a6abf7158809cf4f3c"));
    let iv = unhex("000102030405060708090a0b0c0d0e0f");
    let pt = unhex("6bc1bee22e409f96e93d7e117393172a");
    let ct = c.blockmode().unwrap().encrypt(&k, &iv, &pt).unwrap();
    assert_eq!(ct, unhex("7649abac8119b246cee98e9b12e9197d"));
    let back = c.blockmode().unwrap().decrypt(&k, &iv, &ct).unwrap();
    assert_eq!(&back[..], &pt[..]);
    // padding = none refuses a non-block-multiple, never pads silently
    assert!(c.blockmode().unwrap().encrypt(&k, &iv, &pt[..15]).is_err());
}

#[test]
fn hashcash_published_stamp() {
    // sha1 is outside the default set, but the dynamic slot works through the registry.
    let c = compose("hashcash(sha1)", Policy::Any).unwrap();
    let pow = c.pow().unwrap();
    // hashcash.org: 1:20:060408:adam@cypherspace.org::1QTjaYd7niiQA/sc:ePa
    let challenge = b"060408:adam@cypherspace.org::1QTjaYd7niiQA/sc";
    assert!(pow.verify(challenge, b"ePa", 20).unwrap());
    assert!(!pow.verify(challenge, b"ePb", 20).unwrap());
    assert!(!pow.verify(challenge, b"ePa", 21).unwrap());
}

#[test]
fn hashcash_solve_verify_and_caps() {
    let c = compose("hashcash(sha256)", Policy::Any).unwrap();
    let pow = c.pow().unwrap();
    let ch = b"240101:example.org::r4nd";
    let sol = pow.solve(ch, 12, 1 << 22).unwrap();
    assert!(pow.verify(ch, &sol, 12).unwrap());
    assert!(!pow.verify(b"240101:example.org::r4nE", &sol, 16).unwrap());
    // a hostile difficulty cannot hang the caller
    assert_eq!(pow.solve(ch, 40, 50).unwrap_err(), Error::WorkLimitExceeded);
    assert_eq!(pow.difficulty(), (1, 64));
    for bad in [0, 65] {
        assert!(matches!(
            pow.solve(ch, bad, 10),
            Err(Error::ParamOutOfRange("difficulty"))
        ));
    }
    assert!(pow.solve(b"nodate", 8, 10).is_err());
    assert!(pow.solve(ch, 8, 0).is_err());
    assert!(pow.verify(ch, b"bad!", 8).is_err());
}

// ---- equivalence with the concrete registry ids ------------------------------------------

#[test]
fn concrete_ids_equal_compositions() {
    let k = key(&[7u8; 32]);
    let data = b"equivalence";
    for h in ["sha256", "sha512", "sha3-256", "sha224"] {
        let p = Params::new().with("hash", s(h));
        let reg = new_mac_in(all(), Policy::Any, "hmac", &p).unwrap();
        let mut a = vec![0u8; reg.sizes().tag.unwrap().max()];
        reg.tag(&k, data, &mut a).unwrap();
        let c = compose(&format!("hmac({h})"), Policy::Safe).unwrap();
        let mut b = vec![0u8; a.len()];
        c.mac().unwrap().tag(&k, data, &mut b).unwrap();
        assert_eq!(a, b, "hmac {h}");

        let reg = new_kdf_in(all(), Policy::Any, "hkdf", &p).unwrap();
        let (mut a, mut b) = ([0u8; 77], [0u8; 77]);
        reg.derive(&k, b"salt", b"info", &mut a).unwrap();
        let c = compose(&format!("hkdf({h})"), Policy::Safe).unwrap();
        c.kdf()
            .unwrap()
            .derive(&k, b"salt", b"info", &mut b)
            .unwrap();
        assert_eq!(a, b, "hkdf {h}");

        let pp = p
            .clone()
            .with("iterations", Value::U32(10))
            .with("out_len", Value::U32(40));
        let reg = new_pwhash_in(all(), Policy::Any, "pbkdf2", &pp).unwrap();
        let (mut a, mut b) = ([0u8; 40], [0u8; 40]);
        reg.derive(b"password", b"saltsalt", &mut a).unwrap();
        let pc = Params::new()
            .with("iterations", Value::U32(10))
            .with("out_len", Value::U32(40));
        let c = compose_with(&format!("pbkdf2(hmac({h}))"), &pc, Policy::Safe).unwrap();
        c.pwhash()
            .unwrap()
            .derive(b"password", b"saltsalt", &mut b)
            .unwrap();
        assert_eq!(a, b, "pbkdf2 {h}");
    }
    // CMAC and CBC
    for (id, composed, klen) in [
        ("aes-cmac", "cmac(aes-256)", 32usize),
        ("aes-cmac", "cmac(aes-128)", 16),
    ] {
        let reg = new_mac_in(all(), Policy::Any, id, &Params::new()).unwrap();
        let kk = key(&vec![9u8; klen]);
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        reg.tag(&kk, data, &mut a).unwrap();
        compose(composed, Policy::Safe)
            .unwrap()
            .mac()
            .unwrap()
            .tag(&kk, data, &mut b)
            .unwrap();
        assert_eq!(a, b, "{composed}");
    }
    let pad = Params::new().with("padding", s("pkcs7"));
    let reg = new_blockmode_in(all(), Policy::Any, "aes-256-cbc", &pad).unwrap();
    let iv = [3u8; 16];
    let a = reg.encrypt(&k, &iv, b"hello cbc").unwrap();
    let c = compose_with("cbc(aes-256)", &pad, Policy::Safe).unwrap();
    let b = c
        .blockmode()
        .unwrap()
        .encrypt(&k, &iv, b"hello cbc")
        .unwrap();
    assert_eq!(a, b);
}

// ---- grammar, slots and tiers ---------------------------------------------------------------

#[test]
fn aliases_resolve_to_the_canonical_form() {
    let sha256 = lookup_in(all(), "sha256").unwrap();
    for alias in sha256.aliases {
        if alias
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
        {
            assert_eq!(
                canonical(&format!("hmac({alias})")).unwrap(),
                "hmac(sha256)"
            );
        }
    }
}

#[test]
fn strict_errors_no_fallback() {
    assert_eq!(
        compose("hmac(aes-128)", Policy::Any).err(),
        Some(Error::WrongKind)
    );
    assert_eq!(
        compose("cmac(sha256)", Policy::Any).err(),
        Some(Error::WrongKind)
    );
    assert_eq!(
        compose("hmac(nope)", Policy::Any).err(),
        Some(Error::UnknownAlgorithm)
    );
    assert_eq!(
        compose("nope(sha256)", Policy::Any).err(),
        Some(Error::UnknownAlgorithm)
    );
    // registered, but no type-level digest
    assert_eq!(
        compose("hmac(blake3)", Policy::Any).err(),
        Some(Error::Unsupported)
    );
    // ctr-drbg is AES only
    assert_eq!(
        compose("ctr-drbg(sm4)", Policy::Any).err(),
        Some(Error::Unsupported)
    );
    for bad in [
        "sha256",
        "hmac(SHA256)",
        "hmac( sha256)",
        "hmac()",
        "hmac(sha256,sha256)",
        "pbkdf2(sha256)",
        "hashcash(aes-128)",
    ] {
        assert!(compose(bad, Policy::Any).is_err(), "{bad}");
    }
    assert_eq!(
        compose("pbkdf2(cmac(aes-128))", Policy::Any).err(),
        Some(Error::Unsupported)
    );
    // unknown parameter
    let p = Params::new().with("bogus", Value::U32(1));
    assert_eq!(
        compose_with("hmac(sha256)", &p, Policy::Any).err(),
        Some(Error::ParamUnknown)
    );
}

#[test]
fn effective_tier_is_the_worst_part() {
    assert_eq!(effective_tier("hmac(sha256)").unwrap(), Tier::Standard);
    assert_eq!(effective_tier("ecb(aes-128)").unwrap(), Tier::Legacy);
    assert_eq!(
        effective_tier("hmac-drbg(sha256)").unwrap(),
        Tier::Unverified
    );
    assert_eq!(effective_tier("hashcash(crc32)").unwrap(), Tier::Broken);
    if has_all() {
        assert_eq!(effective_tier("hmac(md5)").unwrap(), Tier::Broken);
        assert_eq!(effective_tier("hmac(ripemd160)").unwrap(), Tier::Legacy);
    } else {
        assert_eq!(
            compose("hmac(md5)", Policy::Any).err(),
            Some(Error::Unsupported)
        );
    }
}

#[test]
fn safe_policy_refuses_below_standard() {
    for spec in [
        "hmac-drbg(sha256)",
        "hash-drbg(sha256)",
        "ctr-drbg(aes-256)",
        "ecb(aes-128)",
        "hashcash(sha256)",
        "hashcash(crc32)",
    ] {
        assert!(
            matches!(compose(spec, Policy::Safe), Err(Error::TierNotAllowed(_))),
            "{spec}"
        );
        assert!(compose(spec, Policy::Any).is_ok(), "{spec}");
    }
    if has_all() {
        assert_eq!(
            compose("hmac(md5)", Policy::Safe).err(),
            Some(Error::TierNotAllowed(Tier::Broken))
        );
        assert!(compose("hmac(md5)", Policy::Any).is_ok());
    }
}

#[test]
fn generated_tables_are_consistent() {
    for p in DIGESTS.iter().chain(CIPHERS.iter()) {
        let reg = lookup_in(all(), p.algo).unwrap_or_else(|| panic!("{} not registered", p.algo));
        assert_eq!(reg.tier, p.tier, "{}", p.name);
    }
    for want in [
        "sha256",
        "sha512",
        "sha3-256",
        "sha3-512",
        "sha224",
        "keccak256",
    ] {
        assert!(
            DIGESTS.iter().any(|p| p.name == want && p.compiled),
            "{want}"
        );
    }
    for want in ["aes-128", "aes-192", "aes-256"] {
        assert!(
            CIPHERS.iter().any(|p| p.name == want && p.compiled),
            "{want}"
        );
    }
}

/// Every compiled digest works in every digest constructor, every compiled cipher in every
/// cipher constructor (this is what catches a bad `digest =` / `cipher =` entry).
#[test]
fn every_selectable_part_builds() {
    for p in DIGESTS.iter().filter(|p| p.compiled) {
        for ctor in ["hmac", "hkdf", "hmac-drbg", "hash-drbg"] {
            let spec = format!("{ctor}({})", p.name);
            assert!(compose(&spec, Policy::Any).is_ok(), "{spec}");
        }
        let spec = format!("pbkdf2(hmac({}))", p.name);
        assert!(compose(&spec, Policy::Any).is_ok(), "{spec}");
        let spec = format!("hashcash({})", p.algo);
        let _ = compose(&spec, Policy::Any); // dynamic slot: only id-backed digests resolve
    }
    for p in CIPHERS.iter().filter(|p| p.compiled) {
        for ctor in ["cmac", "cbc", "ecb", "cfb"] {
            let spec = format!("{ctor}({})", p.name);
            assert!(compose(&spec, Policy::Any).is_ok(), "{spec}");
        }
    }
}

// ---- DRBG CAVP -------------------------------------------------------------------------------

fn replay(file: &str, ctor: &str, df_param: bool) -> usize {
    let doc = load(file);
    let mut n = 0;
    let mut skipped = 0;
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let (spec, params) = if ctor == "ctr-drbg" {
            let param = v["param"].as_str().unwrap(); // "AES-128 use df"
            let aes = param[..7].to_lowercase();
            let df = if param.ends_with("no df") {
                "no"
            } else {
                "yes"
            };
            assert!(df_param);
            (format!("ctr-drbg({aes})"), Params::new().with("df", s(df)))
        } else {
            (
                format!("{ctor}({})", v["param"].as_str().unwrap()),
                Params::new(),
            )
        };
        let mut c = match compose_with(&spec, &params, Policy::Any) {
            Ok(c) => c,
            Err(Error::Unsupported) if !has_all() => {
                skipped += 1;
                continue;
            }
            Err(e) => panic!("{spec}: {e}"),
        };
        let d = c.drbg().unwrap();
        let f = |k: &str| unhex(v[k].as_str().unwrap());
        d.instantiate(&f("entropy_hex"), &f("nonce_hex"), &f("pers_hex"))
            .unwrap();
        let want = f("returned_hex");
        let mut discard = vec![0u8; want.len()];
        d.generate(&f("add1_hex"), &mut discard).unwrap();
        let mut got = vec![0u8; want.len()];
        d.generate(&f("add2_hex"), &mut got).unwrap();
        assert_eq!(got, want, "{spec} {id}");
        n += 1;
    }
    eprintln!("{file}: {n} vectors replayed, {skipped} skipped (digest not compiled in)");
    n
}

#[test]
fn cavp_hmac_drbg() {
    assert!(replay("cavp-hmac-drbg.json", "hmac-drbg", false) >= 16);
}

#[test]
fn cavp_hash_drbg() {
    assert!(replay("cavp-hash-drbg.json", "hash-drbg", false) >= 16);
}

#[test]
fn cavp_ctr_drbg() {
    assert_eq!(replay("cavp-ctr-drbg.json", "ctr-drbg", true), 48);
}

#[test]
fn composed_hmac_drbg_matches_the_libcrux_id_on_cavp() {
    let doc = load("cavp-hmac-drbg.json");
    let mut n = 0;
    for v in doc["vectors"].as_array().unwrap() {
        if v["param"] != "sha256" {
            continue;
        }
        let f = |k: &str| unhex(v[k].as_str().unwrap());
        let mut reg =
            nextssl_registry::new_drbg_in(all(), Policy::Any, "hmac-drbg-sha256", &Params::new())
                .unwrap();
        let mut c = compose("hmac-drbg(sha256)", Policy::Any).unwrap();
        let mine = c.drbg().unwrap();
        reg.instantiate(&f("entropy_hex"), &f("nonce_hex"), &f("pers_hex"))
            .unwrap();
        mine.instantiate(&f("entropy_hex"), &f("nonce_hex"), &f("pers_hex"))
            .unwrap();
        let (mut a, mut b) = (vec![0u8; 77], vec![0u8; 77]);
        reg.generate(&f("add1_hex"), &mut a).unwrap();
        mine.generate(&f("add1_hex"), &mut b).unwrap();
        assert_eq!(a, b);
        reg.reseed(&[5u8; 32], b"more").unwrap();
        mine.reseed(&[5u8; 32], b"more").unwrap();
        reg.generate(&[], &mut a).unwrap();
        mine.generate(&[], &mut b).unwrap();
        assert_eq!(a, b);
        n += 1;
    }
    assert!(n >= 8);
}

#[test]
fn drbg_lifecycle_and_limits() {
    for spec in [
        "hmac-drbg(sha256)",
        "hash-drbg(sha512)",
        "ctr-drbg(aes-128)",
    ] {
        let mut c = compose(spec, Policy::Any).unwrap();
        let strength = c.drbg().unwrap().security_strength() / 8;
        let d = c.drbg().unwrap();
        let mut out = [0u8; 8];
        assert_eq!(
            d.generate(&[], &mut out),
            Err(Error::NotInstantiated),
            "{spec}"
        );
        assert_eq!(
            d.reseed(&[1; 64], &[]),
            Err(Error::NotInstantiated),
            "{spec}"
        );
        assert!(matches!(
            d.instantiate(&vec![1; strength - 1], &[2; 16], &[]),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            d.instantiate(&vec![1; strength], &[2; 3], &[]),
            Err(Error::InvalidLength { .. })
        ));
        d.instantiate(&vec![1; strength], &[2; 16], b"p").unwrap();
        assert!(matches!(
            d.generate(&[], &mut []),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            d.generate(&[], &mut vec![0u8; d.max_request_len() + 1]),
            Err(Error::InvalidLength { .. })
        ));
        d.generate(b"x", &mut out).unwrap();
        d.uninstantiate();
        assert_eq!(d.generate(&[], &mut out), Err(Error::NotInstantiated));
    }
}

// ---- random keygen -----------------------------------------------------------------------------

#[test]
fn random_bytes_and_keys() {
    assert_eq!(
        keygen::random_bytes(33, "os-entropy", Policy::Safe)
            .unwrap()
            .len(),
        33
    );
    let a = keygen::random_bytes(64, "hmac-drbg-sha256", Policy::Safe).unwrap();
    let b = keygen::random_bytes(64, "hmac-drbg-sha256", Policy::Safe).unwrap();
    assert_ne!(&a[..], &b[..], "independently seeded DRBGs must differ");
    assert_eq!(
        keygen::random_key("aes-256-gcm", "os-entropy", Policy::Safe)
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        keygen::random_key("hmac", "hmac-drbg-sha256", Policy::Safe)
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        keygen::random_key("aes-128-gcm", "hmac-drbg-sha256", Policy::Safe)
            .unwrap()
            .len(),
        16
    );
    // composed DRBG: root only
    assert_eq!(
        keygen::random_bytes(200, "hmac-drbg(sha512)", Policy::Any)
            .unwrap()
            .len(),
        200
    );
    assert_eq!(
        keygen::random_bytes(70_000, "ctr-drbg(aes-256)", Policy::Any)
            .unwrap()
            .len(),
        70_000
    );
    assert!(matches!(
        keygen::random_bytes(8, "hmac-drbg(sha512)", Policy::Safe),
        Err(Error::TierNotAllowed(Tier::Unverified))
    ));
    assert!(keygen::random_bytes(0, "os-entropy", Policy::Any).is_err());
    assert_eq!(
        keygen::random_bytes(8, "sha256", Policy::Any).err(),
        Some(Error::WrongKind)
    );
    assert_eq!(
        keygen::random_bytes(8, "no-such", Policy::Any).err(),
        Some(Error::UnknownAlgorithm)
    );
    assert_eq!(
        keygen::random_key("sha256", "os-entropy", Policy::Any).err(),
        Some(Error::WrongKind)
    );
}

#[test]
fn keygen_with_chosen_rng() {
    let (pk, sk) = keygen::keygen_with_rng("ed25519", "hmac-drbg-sha256", Policy::Safe).unwrap();
    assert_eq!(pk.len(), 32);
    assert!(!sk.is_empty());
    let (pk, _sk) = keygen::keygen_with_rng("ml-kem-768", "os-entropy", Policy::Safe).unwrap();
    assert_eq!(pk.len(), 1184);
    assert!(keygen::keygen_with_rng("ed25519", "hash-drbg(sha256)", Policy::Safe).is_err());
    assert!(keygen::keygen_with_rng("ed25519", "hash-drbg(sha256)", Policy::Any).is_ok());
    assert_eq!(
        keygen::keygen_with_rng("sha256", "os-entropy", Policy::Any).err(),
        Some(Error::WrongKind)
    );
    let mut r = rng::open("os-entropy", Policy::Safe).unwrap();
    let mut buf = [0u8; 16];
    r.fill(&mut buf).unwrap();
}

#[test]
fn built_kind_matches() {
    let c = compose("hmac(sha256)", Policy::Safe).unwrap();
    assert!(matches!(c.built(), Built::Mac(_)));
    assert!(c.kdf().is_err());
    assert_eq!(c.canonical(), "hmac(sha256)");
}
