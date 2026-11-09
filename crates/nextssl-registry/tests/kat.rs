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
    Ciphertext, Error, Kind, Params, PrivateKey, PublicKey, Seed, Signature, SymmetricKey, Value,
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
    for a in all().iter().filter(|a| is_hash_or_encoding(a)) {
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
        Instance::Mode(_)
        | Instance::Checksum(_)
        | Instance::Pow(_)
        | Instance::Zk(_)
        | Instance::Threshold(_)
        | Instance::Vdf(_) => {}
    }
}

/// Stack for the per-algorithm worker. Classic McEliece keeps multi-hundred-KB arrays on the
/// stack (need roughly 1-2 MiB, mceliece6960119/8192128 the most); the registry shim does not
/// rely on this size, the test just uses a generous one.
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

#[test]
fn every_algorithm_instantiates_with_metadata_sizes_and_behaves() {
    let mut kinds = BTreeSet::new();
    let mut failures: Vec<String> = Vec::new();
    for a in all() {
        if std::env::var_os("KAT_TRACE").is_some() {
            println!("smoke {}", a.id);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::Builder::new()
            .name(a.id.to_string())
            .stack_size(WORKER_STACK)
            .spawn(move || {
                let r = std::panic::catch_unwind(|| check_one(a));
                let _ = tx.send(r.map_err(|e| {
                    e.downcast_ref::<String>()
                        .cloned()
                        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_else(|| "panic".into())
                }));
            })
            .expect("spawn");
        match rx.recv_timeout(PER_ALGO_TIMEOUT) {
            Ok(Ok(())) => {
                kinds.insert(a.kind.as_str());
                let _ = h.join();
            }
            Ok(Err(m)) => failures.push(format!("{}: {m}", a.id)),
            Err(_) => failures.push(format!("{}: HANG (> {:?})", a.id, PER_ALGO_TIMEOUT)),
        }
    }
    for f in &failures {
        println!("SMOKE FAIL {f}");
    }
    assert!(failures.is_empty(), "{} algorithms failed: {failures:?}", failures.len());
    // Every kind that has a registered algorithm was instantiated; print for the test log.
    println!("kinds exercised: {kinds:?}");
    assert!(kinds.len() >= 10, "too few kinds registered: {kinds:?}");
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
