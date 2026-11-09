//! Registry-level conformance, run over EVERY registered algorithm of EVERY kind:
//!
//! 1. every `[kat] files` entry exists and is valid JSON (and names this algorithm if it says so);
//! 2. the algorithm instantiates through the registry (default params, root policy) and its
//!    instance sizes match the `algo.toml` metadata (`check_sizes`);
//! 3. a generic smoke run per kind uses only metadata-declared sizes (round trip, tamper,
//!    wrong-length rejection);
//! 4. `hash` and `encoding` KAT json files are replayed through the registry.
//!
//! Known-answer vectors of the other kinds (AEAD, KEM, signatures, ...) have per-algorithm
//! formats; they are replayed by each algorithm crate's own tests, which `cargo test
//! --workspace` (CI and `docker/test.sh`) runs. This file proves registration, metadata and
//! cross-kind behaviour, not those vectors.

use nextssl_core::{
    Ciphertext, Error, HeOp, Kind, PakeRole, PakeStep, Params, PrivateKey, PublicKey, Seed,
    SharedSecret, Signature, StatefulKey, SymmetricKey, Value,
};
use nextssl_registry::{
    all, check_sizes, decode_in, encode_in, hash_in, instantiate_in, AlgoInfo, Instance, Policy,
};
use serde_json::Value as J;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn params_of(v: &J) -> Params {
    let mut p = Params::new();
    if let Some(o) = v.get("params").and_then(J::as_object) {
        for (k, val) in o {
            if let Some(h) = k.strip_suffix("_hex") {
                p.set(h, Value::Bytes(unhex(val.as_str().unwrap())));
            } else if let Some(n) = val.as_u64() {
                p.set(k, Value::U64(n));
            } else {
                p.set(k, Value::Str(val.as_str().unwrap().to_string()));
            }
        }
    }
    p
}

/// Pure Rust but far too slow under Miri (lattice schemes take minutes per keygen). Their
/// instantiate + size checks still run under Miri; the behaviour smoke runs natively, under
/// ASan and in wasm.
#[cfg(miri)]
const MIRI_SLOW: &[&str] = &["ml-dsa-65", "ml-kem-768"];

fn algos_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../algos")
}

fn is_hash_or_encoding(a: &AlgoInfo) -> bool {
    matches!(a.kind, Kind::Hash | Kind::Encoding)
}

#[test]
fn every_kat_file_exists_and_is_json() {
    let root = algos_dir();
    for a in all() {
        assert!(!a.kat.is_empty(), "{} has no KAT files", a.id);
        for f in a.kat {
            let path = root.join(a.dir).join(f);
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            let doc: J = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            // Our own format has `vectors`; third-party files (Wycheproof) use their own `algorithm` naming.
            if let (Some(name), true) = (
                doc.get("algorithm").and_then(J::as_str),
                doc.get("vectors").is_some(),
            ) {
                assert_eq!(name, a.id, "{path:?}: algorithm mismatch");
            }
        }
    }
}

#[test]
fn hash_and_encoding_kats_replay_through_the_registry() {
    let root = algos_dir();
    let mut total = 0;
    // Triage aid: KAT_SKIP=id1,id2 leaves those algorithms out; KAT_TRACE=1 prints each id.
    let skip = std::env::var("KAT_SKIP").unwrap_or_default();
    for a in all().iter().filter(|a| is_hash_or_encoding(a)) {
        if skip.split(',').any(|s| s == a.id) {
            continue;
        }
        if std::env::var_os("KAT_TRACE").is_some() {
            println!("smoke {}", a.id);
        }
        // Miri cannot execute foreign (C/C++) functions; `AlgoInfo::c_backed` is generated from
        // algo.toml `[upstream]`. Those are covered by the native, ASan/UBSan and wasm runs.
        #[cfg(miri)]
        if a.c_backed {
            continue;
        }
        for f in a.kat {
            let path = root.join(a.dir).join(f);
            let doc: J = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(doc["algorithm"], a.id, "{path:?}: algorithm mismatch");
            for v in doc["vectors"].as_array().expect("vectors") {
                let name = v["id"].as_str().unwrap_or("?");
                let ctx = format!("{} / {f} / {name}", a.id);
                let params = params_of(v);
                match a.kind {
                    Kind::Hash => {
                        let got = hash_in(
                            all(),
                            Policy::Any,
                            a.id,
                            &params,
                            &unhex(v["msg_hex"].as_str().unwrap()),
                        )
                        .unwrap_or_else(|e| panic!("{ctx}: {e}"));
                        assert_eq!(got, unhex(v["out_hex"].as_str().unwrap()), "{ctx}");
                    }
                    _ => {
                        let data = unhex(v["data_hex"].as_str().unwrap());
                        let text = v["text"].as_str().unwrap().as_bytes();
                        let enc = encode_in(all(), Policy::Any, a.id, &params, &data).unwrap();
                        assert_eq!(enc, text, "{ctx}: encode");
                        let dec = decode_in(all(), Policy::Any, a.id, &params, text).unwrap();
                        assert_eq!(dec, data, "{ctx}: decode");
                    }
                }
                total += 1;
            }
            for bad in doc["invalid"].as_array().into_iter().flatten() {
                let text = bad["text"].as_str().unwrap().as_bytes();
                let bad_params = if bad.get("params").is_some() {
                    params_of(bad)
                } else {
                    a.smoke_params()
                };
                assert!(
                    decode_in(all(), Policy::Any, a.id, &bad_params, text).is_err(),
                    "{}: accepted invalid input {:?}",
                    a.id,
                    bad["text"]
                );
                total += 1;
            }
        }
    }
    assert!(total >= 15, "suspiciously few vectors ran: {total}");
}

/// Test-only deterministic, NON-constant entropy (splitmix64 counter expansion). A constant
/// stream starves rejection-sampling keygens (Classic McEliece, NTRU, P-521) of distinct
/// values. Capped, so a runaway keygen fails with an error instead of looping on zeros.
/// Not a CSPRNG; never use outside tests.
struct StreamEntropy {
    state: u64,
    left: usize,
}

impl nextssl_core::EntropySource for StreamEntropy {
    fn fill(&mut self, out: &mut [u8]) -> nextssl_core::Result<()> {
        if out.len() > self.left {
            return Err(Error::EntropyFailure("test entropy cap reached"));
        }
        self.left -= out.len();
        for chunk in out.chunks_mut(8) {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

fn rng() -> StreamEntropy {
    StreamEntropy {
        state: 0x5A5A_5A5A_5A5A_5A5A,
        left: 256 << 20,
    }
}

fn flip(mut v: Vec<u8>) -> Vec<u8> {
    let i = v.len() / 2;
    v[i] ^= 1;
    v
}

fn fixed(l: Option<nextssl_core::Len>) -> usize {
    l.and_then(|l| l.as_fixed()).expect("fixed size")
}

/// `preferred` clamped into the declared range; `preferred` itself when nothing is declared.
fn pick(l: Option<nextssl_core::Len>, preferred: usize) -> usize {
    match l {
        Some(l) => preferred.clamp(l.min(), l.max()),
        None => preferred,
    }
}

/// Generic behaviour per kind using only metadata sizes. Returns the kind for coverage.
fn smoke(a: &AlgoInfo, inst: &Instance) {
    let s = a.sizes;
    let ctx = a.id;
    if let Some(reason) = a.smoke_skip {
        // Declared in algo.toml (`smoke = "skip"`, zk / he / threshold only); named in the log.
        println!("SMOKE SKIP {}: {reason}", a.id);
        return;
    }
    match inst {
        Instance::Hash(h) => {
            let mut out = vec![0u8; h.output_len()];
            h.digest(b"abc", &mut out).unwrap();
            let mut again = vec![0u8; h.output_len()];
            h.digest(b"abc", &mut again).unwrap();
            assert_eq!(out, again, "{ctx}");
            assert!(h
                .digest(b"abc", &mut vec![0u8; h.output_len() + 1])
                .is_err());
        }
        Instance::Xof(x) => {
            let (mut a1, mut a2) = (vec![0u8; 16], vec![0u8; 32]);
            x.squeeze(b"abc", &mut a1).unwrap();
            x.squeeze(b"abc", &mut a2).unwrap();
            assert_eq!(a1[..], a2[..16], "{ctx}: prefix property");
            assert!(x.squeeze(b"abc", &mut []).is_err(), "{ctx}: empty out");
        }
        Instance::Mac(m) => {
            // Everything below comes from the sizes the instance declares: key length, tag
            // length and (for block-oriented MACs) the message length.
            let sz = m.sizes();
            let key_len = sz.key.map(|k| pick(Some(k), 32)).expect("mac declares key");
            let key = SymmetricKey::from_bytes(
                &vec![3u8; key_len],
                nextssl_core::Len::range(key_len, key_len),
            )
            .unwrap();
            let msg: Vec<u8> = match sz.block {
                // whole blocks only: the algorithm refuses anything else (no padding)
                Some(b) => (0..2 * pick(Some(b), 16)).map(|i| i as u8).collect(),
                None => b"msg".to_vec(),
            };
            let t = sz.tag.unwrap().max();
            let mut tag = vec![0u8; t];
            m.tag(&key, &msg, &mut tag).unwrap();
            assert!(m.verify(&key, &msg, &tag).unwrap(), "{ctx}");
            assert!(
                !m.verify(&key, &flip(msg.clone()), &tag).unwrap_or(false),
                "{ctx}"
            );
            assert!(!m.verify(&key, &msg, &flip(tag)).unwrap_or(false), "{ctx}");
            if sz.key.unwrap().min() > 0 {
                let empty = SymmetricKey::from_bytes(&[], nextssl_core::Len::range(0, 0)).unwrap();
                assert!(
                    m.tag(&empty, &msg, &mut vec![0u8; t]).is_err(),
                    "{ctx}: empty key"
                );
            }
            let min = sz.key.unwrap().min();
            if min > 1 {
                let short = SymmetricKey::from_bytes(
                    &vec![3u8; min - 1],
                    nextssl_core::Len::range(min - 1, min - 1),
                )
                .unwrap();
                assert!(
                    m.tag(&short, &msg, &mut vec![0u8; t]).is_err(),
                    "{ctx}: key shorter than declared"
                );
            }
        }
        Instance::Kdf(k) => {
            // ikm, salt, info and output lengths all come from the instance's declared sizes.
            let sz = k.sizes();
            let ikm_len = pick(sz.key, 32);
            let ikm = SymmetricKey::from_bytes(
                &vec![9u8; ikm_len],
                nextssl_core::Len::range(ikm_len, ikm_len),
            )
            .unwrap();
            let out_len = pick(sz.out, 42);
            let salt = vec![b's'; pick(sz.salt, 4)];
            let info = vec![b'i'; pick(sz.info, 4)];
            let (mut o1, mut o2) = (vec![0u8; out_len], vec![0u8; out_len]);
            k.derive(&ikm, &salt, &info, &mut o1).unwrap();
            k.derive(&ikm, &salt, &info, &mut o2).unwrap();
            assert_eq!(o1, o2, "{ctx}");
            #[allow(clippy::unnecessary_map_or)] // is_none_or needs Rust 1.82, MSRV is 1.81
            let takes_info = sz.info.map_or(true, |l| l.max() > 0);
            if takes_info {
                k.derive(&ikm, &salt, &flip(info.clone()), &mut o2).unwrap();
                assert_ne!(o1, o2, "{ctx}: info must matter");
            } else {
                assert!(
                    k.derive(&ikm, &salt, b"x", &mut o2).is_err(),
                    "{ctx}: info is not accepted, must be an error and not ignored"
                );
            }
            if sz.salt.is_some_and(|l| l.max() == 0) {
                assert!(
                    k.derive(&ikm, b"x", &info, &mut o2).is_err(),
                    "{ctx}: salt is not accepted, must be an error and not ignored"
                );
            }
            let max = sz.out.unwrap().max();
            if max < 1 << 20 {
                let mut too_long = vec![0u8; max + 1];
                assert!(
                    k.derive(&ikm, &salt, &info, &mut too_long).is_err(),
                    "{ctx}: over-long out"
                );
            }
            if sz.out.unwrap().min() > 0 {
                assert!(
                    k.derive(&ikm, &salt, &info, &mut []).is_err(),
                    "{ctx}: empty out"
                );
            }
        }
        Instance::PwHash(_) => { /* memory-hard; covered by the algorithm crate tests */ }
        Instance::Aead(c) => {
            let key = SymmetricKey::from_bytes(
                &vec![1u8; fixed(s.key)],
                nextssl_core::Len::fixed(fixed(s.key)),
            )
            .unwrap();
            let nonce = vec![2u8; fixed(s.nonce)];
            let ct = c.seal(&key, &nonce, b"aad", b"hello").unwrap();
            assert_eq!(ct.len(), 5 + fixed(s.tag), "{ctx}");
            assert_eq!(&c.open(&key, &nonce, b"aad", &ct).unwrap()[..], b"hello");
            assert_eq!(
                c.open(&key, &nonce, b"aad", &flip(ct.clone())).unwrap_err(),
                Error::AuthenticationFailed
            );
            assert!(
                c.open(&key, &nonce, b"AAD", &ct).is_err(),
                "{ctx}: aad bound"
            );
            // wrong nonce length: one byte shorter, or one byte for algorithms that take no nonce
            let bad_nonce = if nonce.is_empty() {
                vec![0u8]
            } else {
                nonce[1..].to_vec()
            };
            assert!(
                c.seal(&key, &bad_nonce, b"", b"x").is_err(),
                "{ctx}: bad nonce length"
            );
            let short = SymmetricKey::from_bytes(&[1u8; 5], nextssl_core::Len::fixed(5)).unwrap();
            assert!(
                c.seal(&short, &nonce, b"", b"x").is_err(),
                "{ctx}: short key"
            );
        }
        Instance::BlockCipher(b) => {
            // variable-key ciphers (Blowfish, Twofish, CAST, RC2): use the largest declared key up to 32 bytes
            let kl = pick(s.key, 32);
            let key =
                SymmetricKey::from_bytes(&vec![4u8; kl], nextssl_core::Len::fixed(kl)).unwrap();
            let mut blk = vec![0xA5u8; fixed(s.block)];
            let orig = blk.clone();
            b.encrypt_block(&key, &mut blk).unwrap();
            assert_ne!(blk, orig, "{ctx}");
            b.decrypt_block(&key, &mut blk).unwrap();
            assert_eq!(blk, orig, "{ctx}");
            assert!(
                b.encrypt_block(&key, &mut blk[1..]).is_err(),
                "{ctx}: bad block len"
            );
        }
        Instance::StreamCipher(c) => {
            let kl = pick(s.key, 32);
            let key =
                SymmetricKey::from_bytes(&vec![6u8; kl], nextssl_core::Len::fixed(kl)).unwrap();
            let nonce = vec![7u8; s.nonce.unwrap().min()];
            let mut data = b"stream cipher round trip".to_vec();
            let orig = data.clone();
            c.apply_keystream(&key, &nonce, &mut data).unwrap();
            assert_ne!(data, orig, "{ctx}");
            c.apply_keystream(&key, &nonce, &mut data).unwrap();
            assert_eq!(data, orig, "{ctx}");
            let mut d = orig.clone();
            // wrong nonce length: one byte shorter, or one byte for ciphers that take no nonce
            let bad_nonce = if nonce.is_empty() {
                vec![0u8]
            } else {
                nonce[1..].to_vec()
            };
            assert!(
                c.apply_keystream(&key, &bad_nonce, &mut d).is_err(),
                "{ctx}: nonce len"
            );
            assert_eq!(d, orig, "{ctx}: data untouched on error");
        }
        Instance::BlockMode(m) => {
            // Data values stay below 10 so format-preserving modes (radix 10) accept them; the
            // length is two cipher blocks, valid for block modes without padding, XTS and key wrap.
            let sz = m.sizes();
            let kl = pick(sz.key, 32);
            // distinct key bytes: XTS refuses equal key halves
            let kb: Vec<u8> = (0..kl)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(1))
                .collect();
            let key = SymmetricKey::from_bytes(&kb, nextssl_core::Len::fixed(kl)).unwrap();
            let nl = sz.nonce.unwrap().min();
            let nonce = vec![5u8; nl];
            let n = 2 * fixed(sz.block);
            let pt: Vec<u8> = (0..n).map(|i| ((i * 7) % 10) as u8).collect();
            let ct = m.encrypt(&key, &nonce, &pt).unwrap();
            assert_ne!(ct, pt, "{ctx}");
            assert_eq!(&m.decrypt(&key, &nonce, &ct).unwrap()[..], &pt[..], "{ctx}");
            let short =
                SymmetricKey::from_bytes(&vec![4u8; kl - 1], nextssl_core::Len::fixed(kl - 1))
                    .unwrap();
            assert!(m.encrypt(&short, &nonce, &pt).is_err(), "{ctx}: short key");
            assert!(
                m.encrypt(&key, &vec![5u8; sz.nonce.unwrap().max() + 1], &pt)
                    .is_err(),
                "{ctx}: long nonce/iv"
            );
        }
        Instance::Kem(k) => {
            let (pk, sk) = k.keygen(&mut rng()).unwrap();
            assert_eq!(pk.len(), fixed(s.pk), "{ctx}");
            assert_eq!(sk.len(), fixed(s.sk), "{ctx}");
            let (ct, ss) = k.encaps(&pk, &mut rng()).unwrap();
            assert_eq!(ct.len(), fixed(s.ct), "{ctx}");
            assert_eq!(ss.len(), fixed(s.ss), "{ctx}");
            assert_eq!(k.decaps(&sk, &ct).unwrap(), ss, "{ctx}");
            // implicit rejection: a flipped ciphertext decapsulates to a different secret
            let bad =
                Ciphertext::from_vec(flip(ct.into_vec()), nextssl_core::Len::fixed(fixed(s.ct)))
                    .unwrap();
            assert_ne!(k.decaps(&sk, &bad).unwrap(), ss, "{ctx}");
            let short = Ciphertext::from_vec(vec![0; 3], nextssl_core::Len::fixed(3)).unwrap();
            assert!(k.decaps(&sk, &short).is_err(), "{ctx}: short ct");
        }
        Instance::Kex(k) => {
            let (pa, sa) = k.keypair(&mut rng()).unwrap();
            let seed = Seed::from_bytes(&[0x33u8; 32], nextssl_core::Len::fixed(32)).unwrap();
            let (pb, sb) = k.keypair_from_seed(&seed).unwrap();
            assert_eq!(pa.len(), fixed(s.pk), "{ctx}");
            assert_eq!(
                k.agree(&sa, &pb).unwrap(),
                k.agree(&sb, &pa).unwrap(),
                "{ctx}"
            );
            let zero =
                PublicKey::from_vec(vec![0; fixed(s.pk)], nextssl_core::Len::fixed(fixed(s.pk)))
                    .unwrap();
            assert!(k.agree(&sa, &zero).is_err(), "{ctx}: low-order point");
        }
        Instance::Sign(g) => {
            let (pk, sk) = g.keygen(&mut rng()).unwrap();
            assert_eq!(pk.len(), fixed(s.pk), "{ctx}");
            let sig = g.sign(&sk, b"message", b"", &mut rng()).unwrap();
            assert!(g.verify(&pk, b"message", b"", &sig).unwrap(), "{ctx}");
            assert!(
                !g.verify(&pk, b"messagE", b"", &sig).unwrap_or(false),
                "{ctx}"
            );
            let bad = Signature::from_vec(
                flip(sig.clone().into_vec()),
                nextssl_core::Len::fixed(sig.len()),
            )
            .unwrap();
            assert!(
                !g.verify(&pk, b"message", b"", &bad).unwrap_or(false),
                "{ctx}"
            );
            if s.ctx.map(|c| c.max()) == Some(0) {
                assert!(
                    g.sign(&sk, b"m", b"ctx", &mut rng()).is_err(),
                    "{ctx}: ctx must not be ignored"
                );
            }
            let wrong: PrivateKey =
                PrivateKey::from_vec(vec![1; 3], nextssl_core::Len::fixed(3)).unwrap();
            assert!(
                g.sign(&wrong, b"m", b"", &mut rng()).is_err(),
                "{ctx}: bad sk length"
            );
        }
        Instance::Rng(_) | Instance::Drbg(_) | Instance::Encoding(_) => {}
        Instance::Mode(_) | Instance::Checksum(_) | Instance::Pow(_) => {}
        Instance::Pke(p) => {
            let (pk, sk) = p.keygen(&mut rng()).unwrap();
            assert!(s.pk.unwrap().contains(pk.len()), "{ctx}: pk length");
            assert!(s.sk.unwrap().contains(sk.len()), "{ctx}: sk length");
            let pt = vec![0x42u8; pick(s.out, 16)];
            let label = vec![0x4Cu8; pick(s.ctx, 5)];
            let ct = p.encrypt(&pk, &pt, &label, &mut rng()).unwrap();
            assert!(s.ct.unwrap().contains(ct.len()), "{ctx}: ct length");
            assert_eq!(&p.decrypt(&sk, &ct, &label).unwrap()[..], &pt[..], "{ctx}");
            // every failure is the one uniform error; the only alternative is implicit rejection
            // (RSA PKCS#1 v1.5): a synthetic plaintext that is never the original
            match p.decrypt(&sk, &flip(ct.clone()), &label) {
                Err(e) => assert_eq!(e, Error::AuthenticationFailed, "{ctx}: flipped ct"),
                Ok(got) => assert_ne!(
                    &got[..],
                    &pt[..],
                    "{ctx}: flipped ct decrypted to the original"
                ),
            }
            if s.ctx.map(|c| c.max()).unwrap_or(0) > 0 {
                let other = vec![0x4Du8; label.len().max(1)];
                assert_eq!(
                    p.decrypt(&sk, &ct, &other).err(),
                    Some(Error::AuthenticationFailed),
                    "{ctx}: wrong label"
                );
            } else {
                assert!(
                    p.encrypt(&pk, &pt, b"label", &mut rng()).is_err(),
                    "{ctx}: label must not be ignored"
                );
            }
            assert!(
                p.decrypt(&sk, &[0u8; 3], &label).is_err(),
                "{ctx}: short ct"
            );
            let max_pt = s.out.unwrap().max();
            if max_pt < (1 << 20) {
                assert!(
                    p.encrypt(&pk, &vec![1u8; max_pt + 1], &label, &mut rng())
                        .is_err(),
                    "{ctx}: over-long plaintext"
                );
            }
        }
        Instance::Pake(k) => {
            let pw = vec![0x70u8; pick(s.key, 13)];
            let (da, db) = run_pake(&**k, &pw, &pw);
            let (da, db) = (
                da.expect("initiator finished"),
                db.expect("responder finished"),
            );
            assert_eq!(da, db, "{ctx}: same password, same secret");
            assert!(s.ss.unwrap().contains(da.len()), "{ctx}: secret length");
            // a different password never yields equal secrets
            let mut other = pw.clone();
            other[0] ^= 1;
            let (xa, xb) = run_pake(&**k, &pw, &other);
            if let (Some(xa), Some(xb)) = (xa, xb) {
                assert_ne!(xa, xb, "{ctx}: wrong password agreed");
            }
            // a junk first message ends the exchange
            let (st, _) = k
                .start(PakeRole::Responder, &pw, b"ctx", &mut rng())
                .unwrap();
            // (SRP accepts any non-zero A and only fails at the proof, so "continues" is allowed;
            // finishing with a secret on junk is not)
            assert!(
                !matches!(st.step(&[0xFFu8; 7]), Ok(PakeStep::Done(..))),
                "{ctx}: junk message finished the exchange"
            );
            assert!(
                k.start(PakeRole::Initiator, &[], b"ctx", &mut rng())
                    .is_err()
                    || s.key.unwrap().min() == 0,
                "{ctx}: empty password"
            );
        }
        Instance::StatefulSign(g) => {
            let (pk, mut key): (PublicKey, StatefulKey) = g.keygen(&mut rng()).unwrap();
            assert_eq!(pk.len(), fixed(s.pk), "{ctx}");
            let before = g.remaining(&key).unwrap();
            assert_eq!(before, g.max_signatures(), "{ctx}");
            // a failing persist releases nothing and leaves the key as it was
            let mut fail = |_: &[u8]| -> nextssl_core::Result<()> { Err(Error::PersistFailed) };
            assert!(g.sign(&mut key, b"m", &mut fail).is_err(), "{ctx}");
            assert_eq!(g.remaining(&key).unwrap(), before, "{ctx}: state moved");
            let mut stored: Vec<u8> = Vec::new();
            let mut keep = |b: &[u8]| -> nextssl_core::Result<()> {
                stored = b.to_vec();
                Ok(())
            };
            let sig = g.sign(&mut key, b"message", &mut keep).unwrap();
            assert_eq!(
                stored,
                key.as_bytes(),
                "{ctx}: persisted state is the new state"
            );
            assert_eq!(g.remaining(&key).unwrap(), before - 1, "{ctx}");
            assert!(s.sig.unwrap().contains(sig.len()), "{ctx}");
            assert!(g.verify(&pk, b"message", &sig).unwrap(), "{ctx}");
            assert!(!g.verify(&pk, b"messagE", &sig).unwrap_or(false), "{ctx}");
            // small keys are run to exhaustion: the next call is an explicit error, no persist
            if g.max_signatures() <= 64 {
                let mut never = |_: &[u8]| -> nextssl_core::Result<()> {
                    panic!("persist called for an exhausted key")
                };
                let mut noop = |_: &[u8]| -> nextssl_core::Result<()> { Ok(()) };
                while g.remaining(&key).unwrap() > 0 {
                    g.sign(&mut key, b"x", &mut noop).unwrap();
                }
                assert_eq!(
                    g.sign(&mut key, b"x", &mut never).err(),
                    Some(Error::KeyExhausted),
                    "{ctx}"
                );
            }
        }
        Instance::Zk(z) => {
            // The statement and witness encodings are relation-specific, so the generic run only
            // checks setup and that garbage is never accepted. Heavy systems declare smoke = skip.
            let setup = z.setup(&[], &mut rng()).unwrap();
            assert!(!z.verify(&setup, &[], &[0u8; 8]).unwrap_or(false), "{ctx}");
        }
        Instance::Threshold(t) => {
            let secret = vec![0x5Au8; 32];
            let n = 3.min(t.max_parties());
            let th = 2.min(n);
            let shares = t.split(&secret, th, n, &mut rng()).unwrap();
            assert_eq!(shares.len(), n, "{ctx}");
            assert_eq!(&t.combine(&shares[..th]).unwrap()[..], &secret[..], "{ctx}");
            for (tt, nn) in [(0, n), (n + 1, n), (1, t.max_parties() + 1)] {
                assert!(
                    t.split(&secret, tt, nn, &mut rng()).is_err(),
                    "{ctx}: {tt}/{nn}"
                );
            }
            if th > 1 {
                // too few shares: an error, never the secret
                assert_ne!(
                    t.combine(&shares[..1]).ok().map(|v| v.to_vec()),
                    Some(secret.clone()),
                    "{ctx}: one share revealed the secret"
                );
            }
            let dup = [shares[0].as_bytes().to_vec(), shares[0].as_bytes().to_vec()];
            let dup: Vec<nextssl_core::Share> = dup
                .iter()
                .map(|b| {
                    nextssl_core::Share::from_bytes(b, nextssl_core::Len::range(0, 1 << 20))
                        .unwrap()
                })
                .collect();
            assert_ne!(
                t.combine(&dup).ok().map(|v| v.to_vec()),
                Some(secret.clone()),
                "{ctx}: duplicate shares reconstructed"
            );
        }
        Instance::Vdf(v) => {
            let t = 8u64.min(v.max_t());
            let (out, proof) = v.eval(b"challenge", t).unwrap();
            assert!(v.verify(b"challenge", t, &out, &proof).unwrap(), "{ctx}");
            assert!(
                !v.verify(b"challengE", t, &out, &proof).unwrap_or(false),
                "{ctx}"
            );
            assert!(
                !v.verify(b"challenge", t, &out, &flip(proof))
                    .unwrap_or(false),
                "{ctx}"
            );
            assert!(v.eval(b"challenge", 0).is_err(), "{ctx}: t = 0");
            if v.max_t() < u64::MAX {
                assert!(
                    v.eval(b"challenge", v.max_t() + 1).is_err(),
                    "{ctx}: t over cap"
                );
                assert!(
                    v.verify(b"challenge", v.max_t() + 1, &out, &[]).is_err(),
                    "{ctx}: verify t over cap"
                );
            }
        }
        Instance::He(h) => {
            let keys = h.keygen(&[], &mut rng()).unwrap();
            // convention: a one-byte unsigned integer plaintext
            let c2 = h.encrypt(&keys.public, &[2], &mut rng()).unwrap();
            let c3 = h.encrypt(&keys.public, &[3], &mut rng()).unwrap();
            assert_eq!(&h.decrypt(&keys.secret, &c2).unwrap()[..], &[2], "{ctx}");
            let all_ops = [
                HeOp::Add,
                HeOp::Sub,
                HeOp::Mul,
                HeOp::Neg,
                HeOp::And,
                HeOp::Or,
                HeOp::Xor,
                HeOp::Not,
            ];
            for op in all_ops {
                if !h.ops().contains(&op) {
                    assert_eq!(
                        h.eval(op, &[&c2, &c3], &keys.eval).err(),
                        Some(Error::Unsupported),
                        "{ctx}: undeclared op {op:?}"
                    );
                }
            }
            if h.ops().contains(&HeOp::Add) {
                let sum = h.eval(HeOp::Add, &[&c2, &c3], &keys.eval).unwrap();
                assert_eq!(&h.decrypt(&keys.secret, &sum).unwrap()[..], &[5], "{ctx}");
                assert!(
                    h.eval(HeOp::Add, &[&c2], &keys.eval).is_err(),
                    "{ctx}: operand count"
                );
            }
        }
    }
}

/// Runs a two-party exchange with an in-process message queue. Returns each side's secret when
/// it finished; a rejected message ends the run with whatever finished before.
fn run_pake(
    k: &dyn nextssl_core::Pake,
    pw_a: &[u8],
    pw_b: &[u8],
) -> (Option<SharedSecret>, Option<SharedSecret>) {
    use std::collections::VecDeque;
    let (sa, ma) = k
        .start(PakeRole::Initiator, pw_a, b"ctx", &mut rng())
        .unwrap();
    let (sb, mb) = k
        .start(PakeRole::Responder, pw_b, b"ctx", &mut rng())
        .unwrap();
    let (mut sa, mut sb) = (Some(sa), Some(sb));
    let (mut qa, mut qb): (VecDeque<Vec<u8>>, VecDeque<Vec<u8>>) =
        (VecDeque::new(), VecDeque::new());
    if !ma.is_empty() {
        qb.push_back(ma);
    }
    if !mb.is_empty() {
        qa.push_back(mb);
    }
    let (mut da, mut db) = (None, None);
    for _ in 0..64 {
        let mut progressed = false;
        if let Some(m) = qb.pop_front() {
            progressed = true;
            if let Some(st) = sb.take() {
                match st.step(&m) {
                    Ok(PakeStep::Send(n, out)) => {
                        sb = Some(n);
                        if !out.is_empty() {
                            qa.push_back(out);
                        }
                    }
                    Ok(PakeStep::Done(ss, last)) => {
                        db = Some(ss);
                        qa.extend(last.filter(|l| !l.is_empty()));
                    }
                    Err(_) => return (da, db),
                }
            }
        }
        if let Some(m) = qa.pop_front() {
            progressed = true;
            if let Some(st) = sa.take() {
                match st.step(&m) {
                    Ok(PakeStep::Send(n, out)) => {
                        sa = Some(n);
                        if !out.is_empty() {
                            qb.push_back(out);
                        }
                    }
                    Ok(PakeStep::Done(ss, last)) => {
                        da = Some(ss);
                        qb.extend(last.filter(|l| !l.is_empty()));
                    }
                    Err(_) => return (da, db),
                }
            }
        }
        if (da.is_some() && db.is_some()) || !progressed {
            break;
        }
    }
    (da, db)
}

/// Stack for the per-algorithm worker. Classic McEliece keeps multi-hundred-KB arrays on the
/// stack (need roughly 1-2 MiB, mceliece6960119/8192128 the most); the registry shim does not
/// rely on this size, the test just uses a generous one.
#[cfg_attr(target_family = "wasm", allow(dead_code))]
const WORKER_STACK: usize = 64 << 20;
/// A real hang fails after this long instead of running forever.
const PER_ALGO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

fn check_one(a: &'static AlgoInfo) {
    // Miri cannot execute foreign (C/C++) functions; `AlgoInfo::c_backed` is generated from
    // algo.toml `[upstream]`. Those are covered by the native, ASan/UBSan and wasm runs.
    #[cfg(miri)]
    if a.c_backed {
        return;
    }
    let inst = instantiate_in(all(), Policy::Any, a.id, &a.smoke_params())
        .unwrap_or_else(|e| panic!("{}: {e}", a.id));
    check_sizes(a, &inst).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(a.ctor.kind(), a.kind, "{}", a.id);
    #[cfg(miri)]
    if MIRI_SLOW.contains(&a.id) {
        return;
    }
    smoke(a, &inst);
    // Every value of every enum parameter (others at default) must instantiate, stay
    // within the declared sizes and behave; an unknown value must be an error.
    for spec in a.params {
        let nextssl_core::ParamType::Enum(values) = spec.ty else {
            return;
        };
        for v in values {
            let p = a
                .smoke_params()
                .with(spec.name, Value::Str((*v).to_string()));
            let inst = instantiate_in(all(), Policy::Any, a.id, &p)
                .unwrap_or_else(|e| panic!("{} {}={v}: {e}", a.id, spec.name));
            check_sizes(a, &inst).unwrap_or_else(|e| panic!("{} {}={v}: {e}", a.id, spec.name));
            smoke(a, &inst);
        }
        let bad = a
            .smoke_params()
            .with(spec.name, Value::Str("no-such-value".into()));
        assert!(
            instantiate_in(all(), Policy::Any, a.id, &bad).is_err(),
            "{}: unknown {} value accepted",
            a.id,
            spec.name
        );
    }
}

/// Runs `f` on a big-stack worker thread so a hang can be reported by a receive timeout.
/// WebAssembly has no threads: there `f` runs inline on the (large-stack) main thread.
#[cfg(not(target_family = "wasm"))]
fn spawn_worker(
    name: String,
    f: impl FnOnce() + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    Some(
        std::thread::Builder::new()
            .name(name)
            .stack_size(WORKER_STACK)
            .spawn(f)
            .expect("spawn"),
    )
}

#[cfg(target_family = "wasm")]
fn spawn_worker(
    _name: String,
    f: impl FnOnce() + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    f();
    None
}

fn join_worker(h: Option<std::thread::JoinHandle<()>>) {
    if let Some(h) = h {
        let _ = h.join();
    }
}

#[test]
fn every_algorithm_instantiates_with_metadata_sizes_and_behaves() {
    let mut kinds = BTreeSet::new();
    let mut failures: Vec<String> = Vec::new();
    // Triage aid: KAT_SKIP=id1,id2 leaves those algorithms out of this smoke loop (unset = none).
    let skip = std::env::var("KAT_SKIP").unwrap_or_default();
    for a in all() {
        if skip.split(',').any(|s| s == a.id) {
            continue;
        }
        if std::env::var_os("KAT_TRACE").is_some() {
            println!("smoke {}", a.id);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let h = spawn_worker(a.id.to_string(), move || {
            let r = std::panic::catch_unwind(|| check_one(a));
            let _ = tx.send(r.map_err(|e| {
                e.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panic".into())
            }));
        });
        match rx.recv_timeout(PER_ALGO_TIMEOUT) {
            Ok(Ok(())) => {
                kinds.insert(a.kind.as_str());
                join_worker(h);
            }
            Ok(Err(m)) => failures.push(format!("{}: {m}", a.id)),
            Err(_) => failures.push(format!("{}: HANG (> {:?})", a.id, PER_ALGO_TIMEOUT)),
        }
    }
    for f in &failures {
        println!("SMOKE FAIL {f}");
    }
    assert!(
        failures.is_empty(),
        "{} algorithms failed: {failures:?}",
        failures.len()
    );
    // Every kind that has a registered algorithm was instantiated; print for the test log.
    println!("kinds exercised: {kinds:?}");
    assert!(kinds.len() >= 10, "too few kinds registered: {kinds:?}");
}

/// Replays the published-vector files that carry `"replay": "registry"` (AEAD, block cipher,
/// stream cipher and signature verification). Verify-only for signatures, so no randomness is
/// needed. Every mismatch is collected and printed as `KAT FAIL <algo> / <file> / <id>` before
/// the final assert, so one bad vector never hides the others. Expected values are never edited.
fn replay_registry_vector(inst: &Instance, v: &J) -> Result<(), String> {
    let hex = |k: &str| -> Result<Vec<u8>, String> {
        v.get(k)
            .and_then(J::as_str)
            .map(unhex)
            .ok_or_else(|| format!("missing {k}"))
    };
    let skey = |b: &[u8]| {
        SymmetricKey::from_bytes(b, nextssl_core::Len::fixed(b.len())).map_err(|e| e.to_string())
    };
    match inst {
        Instance::Aead(c) => {
            let (key, nonce, aad) = (skey(&hex("key_hex")?)?, hex("nonce_hex")?, hex("aad_hex")?);
            let (pt, ct) = (hex("pt_hex")?, hex("ct_hex")?);
            let got = c
                .seal(&key, &nonce, &aad, &pt)
                .map_err(|e| format!("seal: {e}"))?;
            if got != ct {
                return Err(format!(
                    "seal mismatch: got {}",
                    got.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ));
            }
            let back = c
                .open(&key, &nonce, &aad, &ct)
                .map_err(|e| format!("open: {e}"))?;
            if back[..] != pt[..] {
                return Err("open returned a different plaintext".into());
            }
            Ok(())
        }
        Instance::BlockCipher(b) => {
            let (key, pt, ct) = (skey(&hex("key_hex")?)?, hex("pt_hex")?, hex("ct_hex")?);
            let mut blk = pt.clone();
            b.encrypt_block(&key, &mut blk)
                .map_err(|e| format!("encrypt: {e}"))?;
            if blk != ct {
                return Err(format!(
                    "encrypt mismatch: got {}",
                    blk.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ));
            }
            b.decrypt_block(&key, &mut blk)
                .map_err(|e| format!("decrypt: {e}"))?;
            if blk != pt {
                return Err("decrypt did not return the plaintext".into());
            }
            Ok(())
        }
        Instance::StreamCipher(c) => {
            let (key, nonce, data, out) = (
                skey(&hex("key_hex")?)?,
                hex("nonce_hex")?,
                hex("data_hex")?,
                hex("out_hex")?,
            );
            let mut buf = data.clone();
            c.apply_keystream(&key, &nonce, &mut buf)
                .map_err(|e| e.to_string())?;
            if buf != out {
                return Err(format!(
                    "keystream mismatch: got {}",
                    buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ));
            }
            Ok(())
        }
        Instance::Sign(g) => {
            let (pk, msg, sig) = (hex("pk_hex")?, hex("msg_hex")?, hex("sig_hex")?);
            let pk = PublicKey::from_vec(pk.clone(), nextssl_core::Len::fixed(pk.len()))
                .map_err(|e| e.to_string())?;
            let sig = Signature::from_vec(sig.clone(), nextssl_core::Len::fixed(sig.len()))
                .map_err(|e| e.to_string())?;
            match g.verify(&pk, &msg, b"", &sig) {
                Ok(true) => Ok(()),
                Ok(false) => Err("verify returned false for a published signature".into()),
                Err(e) => Err(format!("verify error: {e}")),
            }
        }
        _ => Err("kind not replayable by the registry harness".into()),
    }
}

#[test]
fn published_kats_replay_through_the_registry() {
    let root = algos_dir();
    let mut ran = 0usize;
    let mut files = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for a in all() {
        #[cfg(miri)]
        if a.c_backed {
            continue;
        }
        for f in a.kat {
            let path = root.join(a.dir).join(f);
            let doc: J = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            if doc.get("replay").and_then(J::as_str) != Some("registry") {
                continue;
            }
            files += 1;
            let vectors = doc["vectors"].as_array().expect("vectors").clone();
            let (id, file) = (a.id, f.to_string());
            let (tx, rx) = std::sync::mpsc::channel();
            let h = spawn_worker(format!("kat-{id}"), move || {
                let mut out: Vec<String> = Vec::new();
                let a = all().iter().find(|x| x.id == id).unwrap();
                for v in &vectors {
                    let name = v["id"].as_str().unwrap_or("?").to_string();
                    let params = if v.get("params").is_some() {
                        params_of(v)
                    } else {
                        a.smoke_params()
                    };
                    let r = match instantiate_in(all(), Policy::Any, a.id, &params) {
                        Ok(inst) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            replay_registry_vector(&inst, v)
                        }))
                        .unwrap_or_else(|_| Err("panic".into())),
                        Err(e) => Err(format!("instantiate: {e}")),
                    };
                    match r {
                        Ok(()) => out.push(format!("ok {name}")),
                        Err(m) => out.push(format!("KAT FAIL {} / {} / {name}: {m}", a.id, file)),
                    }
                }
                let _ = tx.send(out);
            });
            match rx.recv_timeout(PER_ALGO_TIMEOUT) {
                Ok(lines) => {
                    for l in lines {
                        if let Some(rest) = l.strip_prefix("ok ") {
                            let _ = rest;
                            ran += 1;
                        } else {
                            println!("{l}");
                            failures.push(l);
                            ran += 1;
                        }
                    }
                    join_worker(h);
                }
                Err(_) => failures.push(format!("KAT FAIL {} / {f}: HANG", a.id)),
            }
        }
    }
    println!(
        "published KATs: {files} files, {ran} vectors replayed, {} failed",
        failures.len()
    );
    assert!(files >= 20, "suspiciously few published KAT files: {files}");
    assert!(
        failures.is_empty(),
        "{} published KAT vectors failed",
        failures.len()
    );
}

#[test]
fn os_entropy_and_drbg_are_registered_and_work() {
    use nextssl_registry::{new_drbg_in, new_rng_in};
    let mut r = new_rng_in(all(), Policy::Any, "os-entropy", &Params::new()).unwrap();
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    r.fill(&mut a).unwrap();
    r.fill(&mut b).unwrap();
    assert_ne!(a, b);
    let d = new_drbg_in(all(), Policy::Any, "hmac-drbg-sha256", &Params::new()).unwrap();
    let mut d = d;
    let mut out = [0u8; 16];
    assert_eq!(d.generate(b"", &mut out), Err(Error::NotInstantiated));
    let seed_len = all()
        .iter()
        .find(|x| x.id == "hmac-drbg-sha256")
        .unwrap()
        .sizes
        .seed
        .unwrap()
        .min();
    d.instantiate(&vec![1u8; seed_len], b"nonce-nonce-nonce", b"")
        .unwrap();
    d.generate(b"", &mut out).unwrap();
    assert_ne!(out, [0u8; 16]);
}
