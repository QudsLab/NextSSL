//! Safe API tests: round trips, tamper, downgrade, limits, wrong password, critical headers.

use coset::cbor::value::Value;
use coset::{
    CoseEncrypt0Builder, HeaderBuilder, RegisteredLabelWithPrivate, TaggedCborSerializable,
};
use nextssl::envelope::{self, Limits};
use nextssl::{AeadAlg, Error, SignAlg, SymmetricKey, Tier};
use nextssl_core::testing::FixedEntropy;
use nextssl_core::{Aead, Kind, Len, Params, Result, Sizes, Status, Zeroizing};
use nextssl_registry::{AlgoInfo, Ctor, Policy};

fn key() -> SymmetricKey {
    SymmetricKey::from_bytes(&[0x42; 32], Len::fixed(32)).unwrap()
}

/// Cheap Argon2 cost so password tests stay fast in debug builds.
fn cheap() -> Params {
    Params::new()
        .with("m_kib", nextssl::Value::U32(8))
        .with("t", nextssl::Value::U32(1))
}

fn flip_each_byte_is_rejected(env: &[u8], mut accept: impl FnMut(&[u8]) -> bool) {
    for i in 0..env.len() {
        let mut bad = env.to_vec();
        bad[i] ^= 0x01;
        assert!(
            !accept(&bad),
            "flipping byte {i} of {} was accepted",
            env.len()
        );
    }
}

#[test]
fn encrypt_with_key_round_trip_both_aeads_and_records_the_algorithm() {
    for alg in [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256Gcm] {
        let env = nextssl::encrypt_with_key(&key(), b"hello envelope", b"ctx", alg).unwrap();
        let pt = nextssl::decrypt(&key(), &env, b"ctx").unwrap();
        assert_eq!(&pt[..], b"hello envelope");
        // tagged COSE_Encrypt0 (tag 16), alg recorded in the header
        assert_eq!(env[0], 0xd0);
        // wrong key / wrong aad
        let other = SymmetricKey::from_bytes(&[1; 32], Len::fixed(32)).unwrap();
        assert_eq!(
            nextssl::decrypt(&other, &env, b"ctx").err(),
            Some(Error::AuthenticationFailed)
        );
        assert_eq!(
            nextssl::decrypt(&key(), &env, b"other").err(),
            Some(Error::AuthenticationFailed)
        );
        // empty plaintext works
        let e = nextssl::encrypt_with_key(&key(), b"", b"", alg).unwrap();
        assert!(nextssl::decrypt(&key(), &e, b"").unwrap().is_empty());
    }
    assert_eq!(AeadAlg::default(), AeadAlg::XChaCha20Poly1305);
    assert_eq!(SignAlg::default(), SignAlg::MlDsa65);
}

#[test]
fn nonces_are_fresh_per_call() {
    let a = nextssl::encrypt_with_key(&key(), b"x", b"", AeadAlg::default()).unwrap();
    let b = nextssl::encrypt_with_key(&key(), b"x", b"", AeadAlg::default()).unwrap();
    assert_ne!(a, b);
}

#[test]
fn wrong_key_length_is_an_error() {
    let short = SymmetricKey::from_bytes(&[1; 16], Len::fixed(16)).unwrap();
    assert!(nextssl::encrypt_with_key(&short, b"x", b"", AeadAlg::default()).is_err());
    let env = nextssl::encrypt_with_key(&key(), b"x", b"", AeadAlg::default()).unwrap();
    assert!(nextssl::decrypt(&short, &env, b"").is_err());
}

#[test]
fn tamper_any_byte_of_an_encrypted_envelope_fails() {
    for alg in [AeadAlg::XChaCha20Poly1305, AeadAlg::Aes256Gcm] {
        let env = nextssl::encrypt_with_key(&key(), b"tamper me", b"a", alg).unwrap();
        flip_each_byte_is_rejected(&env, |b| nextssl::decrypt(&key(), b, b"a").is_ok());
        // truncation and extension
        for n in 0..env.len() {
            assert!(nextssl::decrypt(&key(), &env[..n], b"a").is_err());
        }
        let mut longer = env.clone();
        longer.push(0);
        assert!(nextssl::decrypt(&key(), &longer, b"a").is_err());
    }
}

#[test]
fn tamper_any_byte_of_a_password_envelope_fails() {
    let env = nextssl::encrypt_with_password(b"pw", b"secret", b"", AeadAlg::default(), &cheap())
        .unwrap();
    assert_eq!(
        &nextssl::decrypt_with_password(b"pw", &env, b"").unwrap()[..],
        b"secret"
    );
    flip_each_byte_is_rejected(&env, |b| {
        nextssl::decrypt_with_password(b"pw", b, b"").is_ok()
    });
}

#[test]
fn password_envelope_wrong_password_and_confusion() {
    let env = nextssl::encrypt_with_password(b"right", b"data", b"", AeadAlg::Aes256Gcm, &cheap())
        .unwrap();
    assert_eq!(
        nextssl::decrypt_with_password(b"wrong", &env, b"").err(),
        Some(Error::AuthenticationFailed)
    );
    // a password envelope is not a key envelope, and vice versa
    assert!(nextssl::decrypt(&key(), &env, b"").is_err());
    let keyed = nextssl::encrypt_with_key(&key(), b"d", b"", AeadAlg::default()).unwrap();
    assert!(nextssl::decrypt_with_password(b"right", &keyed, b"").is_err());
    // bad KDF params are refused before any work
    let bad = Params::new().with("m_kib", nextssl::Value::U32(7));
    assert!(nextssl::encrypt_with_password(b"p", b"d", b"", AeadAlg::default(), &bad).is_err());
    let unknown = Params::new().with("bogus", nextssl::Value::U32(1));
    assert!(nextssl::encrypt_with_password(b"p", b"d", b"", AeadAlg::default(), &unknown).is_err());
    // KDF cost above the decoder's caps is refused
    let strict = Limits {
        kdf: nextssl::KdfCaps {
            max_m_kib: 4,
            max_t: 1,
        },
        ..Limits::default()
    };
    assert_eq!(
        nextssl::decrypt_with_password_with_limits(b"right", &env, b"", &strict).err(),
        Some(Error::ParamOutOfRange("m_kib"))
    );
}

#[test]
fn sign_verify_round_trip_and_tamper() {
    for alg in [SignAlg::MlDsa65, SignAlg::Ed25519] {
        let (pk, sk) = nextssl::sign_keygen(alg).unwrap();
        let env = nextssl::sign(alg, &sk, b"signed message", b"aad").unwrap();
        assert_eq!(env[0], 0xd2, "tagged COSE_Sign1");
        assert_eq!(
            nextssl::verify(alg, &pk, &env, b"aad").unwrap(),
            b"signed message"
        );
        assert!(nextssl::verify(alg, &pk, &env, b"other").is_err());
        let (pk2, _) = nextssl::sign_keygen(alg).unwrap();
        assert!(nextssl::verify(alg, &pk2, &env, b"aad").is_err());
        // Every single-byte flip is rejected (slow for ML-DSA, so sample every 7th byte there).
        let step = if alg == SignAlg::MlDsa65 { 7 } else { 1 };
        for i in (0..env.len()).step_by(step) {
            let mut bad = env.clone();
            bad[i] ^= 1;
            assert!(
                nextssl::verify(alg, &pk, &bad, b"aad").is_err(),
                "{alg:?} byte {i}"
            );
        }
    }
}

#[test]
fn verify_refuses_an_envelope_naming_another_algorithm() {
    let (pk, sk) = nextssl::sign_keygen(SignAlg::Ed25519).unwrap();
    let env = nextssl::sign(SignAlg::Ed25519, &sk, b"m", b"").unwrap();
    assert!(nextssl::verify(SignAlg::MlDsa65, &pk, &env, b"").is_err());
    // an encrypt0 is not a sign1
    let enc = nextssl::encrypt_with_key(&key(), b"m", b"", AeadAlg::default()).unwrap();
    assert!(nextssl::verify(SignAlg::Ed25519, &pk, &enc, b"").is_err());
    assert!(nextssl::decrypt(&key(), &env, b"").is_err());
}

#[test]
fn kem_round_trip() {
    let (pk, sk) = nextssl::kem_keygen().unwrap();
    let (ct, ss) = nextssl::encapsulate(&pk).unwrap();
    assert_eq!(nextssl::decapsulate(&sk, &ct).unwrap(), ss);
    let (ct2, ss2) = nextssl::encapsulate(&pk).unwrap();
    assert_ne!(ct, ct2);
    assert_ne!(ss, ss2);
    let short = nextssl::Ciphertext::from_vec(vec![0; 10], Len::fixed(10)).unwrap();
    assert!(nextssl::decapsulate(&sk, &short).is_err());
}

#[test]
fn hash_mac_kdf_password_hash_encode_decode() {
    assert_eq!(nextssl::hash("sha256", b"abc").unwrap().len(), 32);
    let k = key();
    let tag = nextssl::mac("hmac-sha256", &k, b"data").unwrap();
    assert_eq!(tag.len(), 32);
    assert!(nextssl::mac_verify("hmac-sha256", &k, b"data", &tag).unwrap());
    assert!(!nextssl::mac_verify("hmac-sha256", &k, b"datb", &tag).unwrap());
    let okm = nextssl::kdf("hkdf-sha256", &k, b"salt", b"info", 42).unwrap();
    assert_eq!(okm.len(), 42);
    assert!(nextssl::kdf("hkdf-sha256", &k, b"", b"", 0).is_err());
    assert!(nextssl::kdf("hkdf-sha256", &k, b"", b"", 8161).is_err());
    assert_eq!(
        nextssl::mac("sha256", &k, b"x").err(),
        Some(Error::WrongKind)
    );

    let phc = nextssl::password_hash(b"hunter2").unwrap();
    assert!(phc.starts_with("$argon2id$v=19$"));
    assert!(nextssl::password_verify(b"hunter2", &phc).unwrap());
    assert!(!nextssl::password_verify(b"hunter3", &phc).unwrap());
    assert!(nextssl::password_verify(b"x", "$argon2id$v=19$m=4294967295,t=1,p=1$AA$AA").is_err());

    let e = nextssl::encode("base64", b"foobar").unwrap();
    assert_eq!(e, b"Zm9vYmFy");
    assert_eq!(nextssl::decode("base64", &e).unwrap(), b"foobar");
}

#[test]
fn text_form_round_trip_and_strictness() {
    let env = nextssl::encrypt_with_key(&key(), b"text", b"", AeadAlg::default()).unwrap();
    let text = nextssl::to_text(&env);
    assert!(text.starts_with("nxs1."));
    assert!(!text.contains(['=', '+', '/']));
    let l = Limits::default();
    assert_eq!(nextssl::from_text(&text, &l).unwrap(), env);
    assert!(
        nextssl::from_text(&text[5..], &l).is_err(),
        "prefix required"
    );
    assert!(nextssl::from_text(&text.replace("nxs1.", "nxs2."), &l).is_err());
    assert!(
        nextssl::from_text(&format!("{text}="), &l).is_err(),
        "padding"
    );
    assert!(
        nextssl::from_text(&format!("{text} "), &l).is_err(),
        "whitespace"
    );
    assert!(nextssl::from_text(&text.replace('-', "+"), &l).is_err() || !text.contains('-'));
    let tiny = Limits { max_input: 16, ..l };
    assert!(nextssl::from_text(&text, &tiny).is_err());
}

#[test]
fn oversize_and_hostile_cbor_are_refused() {
    let env = nextssl::encrypt_with_key(&key(), &vec![7u8; 5000], b"", AeadAlg::default()).unwrap();
    let small = Limits {
        max_input: 1024,
        ..Limits::default()
    };
    assert!(matches!(
        nextssl::decrypt_with_limits(&key(), &env, b"", &small),
        Err(Error::InvalidLength {
            what: "envelope",
            ..
        })
    ));
    assert!(nextssl::decrypt_with_limits(&key(), &env, b"", &Limits::default()).is_ok());
    // a 1 MiB input against the 64 MiB default is fine to look at; 65 MiB is not
    let huge = vec![0xd0u8; (64 << 20) + 1];
    assert!(matches!(
        nextssl::decrypt(&key(), &huge, b""),
        Err(Error::InvalidLength { .. })
    ));
    // nesting bomb: tag + 100k nested arrays
    let mut bomb = vec![0xd0u8];
    bomb.extend(std::iter::repeat(0x81u8).take(100_000));
    bomb.push(0);
    assert!(nextssl::decrypt(&key(), &bomb, b"").is_err());
    // claimed gigantic lengths
    assert!(nextssl::decrypt(
        &key(),
        &[0xd0, 0x83, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        b""
    )
    .is_err());
    // indefinite length
    assert!(nextssl::decrypt(&key(), &[0xd0, 0x9f, 0xff], b"").is_err());
    // item-count amplification
    let mut wide = vec![0xd0, 0x83, 0x40, 0x99, 0x10, 0x00];
    wide.extend(std::iter::repeat(0u8).take(4096));
    assert!(nextssl::decrypt(&key(), &wide, b"").is_err());
    for junk in [&b""[..], &[0xd0][..], &[0xd0, 0x83][..], &[0xff; 32][..]] {
        assert!(nextssl::decrypt(&key(), junk, b"").is_err());
        assert!(nextssl::decrypt_with_password(b"p", junk, b"").is_err());
        let (pk, _) = nextssl::sign_keygen(SignAlg::Ed25519).unwrap();
        assert!(nextssl::verify(SignAlg::Ed25519, &pk, junk, b"").is_err());
    }
}

#[test]
fn unknown_critical_headers_and_unprotected_alg_are_refused() {
    let alg = RegisteredLabelWithPrivate::PrivateUse(-65800);
    let build = |prot: coset::Header, unprot: coset::Header| {
        CoseEncrypt0Builder::new()
            .protected(prot)
            .unprotected(unprot)
            .ciphertext(vec![0u8; 40])
            .build()
            .to_tagged_vec()
            .unwrap()
    };
    let iv = HeaderBuilder::new().iv(vec![0; 24]).build();
    // baseline parses to an authentication failure (not a header error)
    let ok = build(
        HeaderBuilder::new().algorithm_label(alg.clone()).build(),
        iv.clone(),
    );
    assert_eq!(
        nextssl::decrypt(&key(), &ok, b"").err(),
        Some(Error::AuthenticationFailed)
    );
    // unknown critical header
    let crit = HeaderBuilder::new()
        .algorithm_label(alg.clone())
        .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(-65999))
        .value(-65999, Value::Null)
        .build();
    let e = nextssl::decrypt(&key(), &build(crit, iv.clone()), b"").err();
    assert_eq!(e, Some(Error::InvalidInput("unknown critical header")));
    // crit naming a label that is absent
    let ghost = HeaderBuilder::new()
        .algorithm_label(alg.clone())
        .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(-65999))
        .build();
    assert!(nextssl::decrypt(&key(), &build(ghost, iv.clone()), b"").is_err());
    // no alg at all / alg in the unprotected header only
    assert!(nextssl::decrypt(
        &key(),
        &build(HeaderBuilder::new().build(), iv.clone()),
        b""
    )
    .is_err());
    let un = HeaderBuilder::new()
        .algorithm_label(alg.clone())
        .iv(vec![0; 24])
        .build();
    assert!(nextssl::decrypt(
        &key(),
        &build(HeaderBuilder::new().build(), un.clone()),
        b""
    )
    .is_err());
    assert!(nextssl::decrypt(
        &key(),
        &build(
            HeaderBuilder::new().algorithm_label(alg.clone()).build(),
            un
        ),
        b""
    )
    .is_err());
    // unregistered algorithm id, alg = none style values, text algorithm
    for id in [-65801i64, -65999, 0, -1] {
        let a = HeaderBuilder::new()
            .algorithm_label(RegisteredLabelWithPrivate::PrivateUse(id))
            .build();
        assert!(
            nextssl::decrypt(&key(), &build(a, iv.clone()), b"").is_err(),
            "{id}"
        );
    }
    let text = HeaderBuilder::new()
        .algorithm_label(RegisteredLabelWithPrivate::Text("none".into()))
        .build();
    assert!(nextssl::decrypt(&key(), &build(text, iv.clone()), b"").is_err());
    // wrong IV length
    let bad_iv = HeaderBuilder::new().iv(vec![0; 12]).build();
    let w = build(HeaderBuilder::new().algorithm_label(alg).build(), bad_iv);
    assert!(nextssl::decrypt(&key(), &w, b"").is_err());
}

// ---- downgrade ---------------------------------------------------------------------------

/// Test-only toy AEAD (NOT cryptography): stands in for a legacy/broken algorithm so the tier
/// policy can be exercised without importing one.
struct Toy;
impl Aead for Toy {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(32)),
            nonce: Some(Len::fixed(12)),
            tag: Some(Len::fixed(1)),
            ..Sizes::NONE
        }
    }
    fn seal(&self, key: &SymmetricKey, _n: &[u8], _a: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let mut v: Vec<u8> = pt.iter().map(|b| b ^ key.as_bytes()[0]).collect();
        v.push(0xAA);
        Ok(v)
    }
    fn open(
        &self,
        key: &SymmetricKey,
        _n: &[u8],
        _a: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        match ct.split_last() {
            Some((0xAA, body)) => Ok(Zeroizing::new(
                body.iter().map(|b| b ^ key.as_bytes()[0]).collect(),
            )),
            _ => Err(Error::AuthenticationFailed),
        }
    }
}
fn toy(_: &Params) -> Result<Box<dyn Aead>> {
    Ok(Box::new(Toy))
}
fn fake(id: &'static str, tier: Tier, cose: i64) -> AlgoInfo {
    AlgoInfo {
        id,
        kind: Kind::Aead,
        category: "test",
        family: "test",
        aliases: &[],
        tier,
        status: Status::Active,
        standards: &[],
        license: "CC0-1.0",
        copyleft: false,
        c_backed: false,
        fips: false,
        cose_alg: Some(cose),
        oid: "",
        sizes: Sizes {
            key: Some(Len::fixed(32)),
            nonce: Some(Len::fixed(12)),
            tag: Some(Len::fixed(1)),
            ..Sizes::NONE
        },
        params: &[],
        test_params: &[],
        dir: "",
        kat: &[],
        smoke_skip: None,
        ctor: Ctor::Aead(toy),
    }
}

#[test]
fn envelopes_naming_legacy_or_broken_algorithms_are_rejected_by_the_safe_policy() {
    let table = [
        fake("toy-broken", Tier::Broken, -70001),
        fake("toy-legacy", Tier::Legacy, -70002),
        fake("toy-research", Tier::Research, -70003),
        fake("toy-standard", Tier::Standard, -70004),
    ];
    let l = Limits::default();
    for (name, tier) in [
        ("toy-broken", Tier::Broken),
        ("toy-legacy", Tier::Legacy),
        ("toy-research", Tier::Research),
    ] {
        let mut rng = FixedEntropy::new(&[3u8; 64]);
        // The any-tier (root) path can create and read it ...
        let env =
            envelope::encrypt_in(&table, Policy::Any, name, &key(), b"", b"old", &mut rng).unwrap();
        let pt = envelope::decrypt_in(&table, Policy::Any, &l, &key(), &env, b"").unwrap();
        assert_eq!(&pt[..], b"old");
        // ... the safe policy refuses both directions.
        assert_eq!(
            envelope::decrypt_in(&table, Policy::Safe, &l, &key(), &env, b"").err(),
            Some(Error::TierNotAllowed(tier))
        );
        let mut rng = FixedEntropy::new(&[3u8; 64]);
        assert_eq!(
            envelope::encrypt_in(&table, Policy::Safe, name, &key(), b"", b"x", &mut rng).err(),
            Some(Error::TierNotAllowed(tier))
        );
    }
    // standard tier is allowed under the safe policy
    let mut rng = FixedEntropy::new(&[3u8; 64]);
    let env = envelope::encrypt_in(
        &table,
        Policy::Safe,
        "toy-standard",
        &key(),
        b"",
        b"ok",
        &mut rng,
    )
    .unwrap();
    assert!(envelope::decrypt_in(&table, Policy::Safe, &l, &key(), &env, b"").is_ok());
    // The real safe API does not know these ids at all.
    let mut rng = FixedEntropy::new(&[3u8; 64]);
    let env = envelope::encrypt_in(
        &table,
        Policy::Any,
        "toy-broken",
        &key(),
        b"",
        b"old",
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        nextssl::decrypt(&key(), &env, b"").err(),
        Some(Error::UnknownAlgorithm)
    );
}

#[test]
fn revoked_or_importing_algorithms_are_refused_everywhere() {
    for status in [Status::Revoked, Status::Importing] {
        let mut a = fake("toy-x", Tier::Safe, -70010);
        a.status = status;
        let table = [a];
        let mut rng = FixedEntropy::new(&[3u8; 64]);
        assert!(
            envelope::encrypt_in(&table, Policy::Any, "toy-x", &key(), b"", b"x", &mut rng)
                .is_err()
        );
    }
}
