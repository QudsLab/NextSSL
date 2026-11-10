//! Registry-driven sweep: one generic round trip per registered algorithm through the root C
//! ABI, using only registry metadata (sizes and smoke parameters). Native only (the sweep runs
//! every KEM, signature and password hash; it is far too slow for Miri).
//!
//! Opt-in: set `NEXTSSL_FFI_SWEEP=1` (it takes about four minutes).
//!
//! Hard failures (unknown name, wrong kind, tier, panic, null pointer, stale handle) fail the
//! test. Other errors are listed and counted, so a generic demo input that does not fit one
//! algorithm's special rules is visible rather than hidden.

#![allow(unsafe_code)]

use crate::boundary::{NextsslIn, NextsslOut};
use crate::exports::*;
use crate::*;
use nextssl_core::{Kind, Len};
use std::ffi::CString;
use std::ptr::null;

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn inp(b: &[u8]) -> NextsslIn {
    NextsslIn {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn outp(b: &mut [u8]) -> NextsslOut {
    NextsslOut {
        ptr: b.as_mut_ptr(),
        cap: b.len(),
        len: 0,
    }
}

fn grow(mut f: impl FnMut(&mut NextsslOut) -> i32) -> (i32, Vec<u8>) {
    let mut buf = vec![0u8; 8];
    loop {
        let mut o = outp(&mut buf);
        let rc = f(&mut o);
        if rc == NEXTSSL_ERR_BAD_OUTPUT_LEN {
            buf = vec![0u8; o.len];
            continue;
        }
        buf.truncate(o.len);
        return (rc, buf);
    }
}

fn chk(rc: i32) -> Result<(), i32> {
    if rc == NEXTSSL_OK {
        Ok(())
    } else {
        Err(rc)
    }
}

/// A key pair from a two-output keygen call.
fn pair(
    cap_pk: usize,
    cap_sk: usize,
    f: impl FnOnce(*mut NextsslOut, *mut NextsslOut) -> i32,
) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let (mut pk, mut sk) = (vec![0u8; cap_pk], vec![0u8; cap_sk]);
    let (mut po, mut so) = (outp(&mut pk), outp(&mut sk));
    chk(f(&mut po, &mut so))?;
    pk.truncate(po.len);
    sk.truncate(so.len);
    Ok((pk, sk))
}

#[test]
fn sweep_every_algorithm_through_the_root_abi() {
    if std::env::var_os("NEXTSSL_FFI_SWEEP").is_none() {
        eprintln!("sweep skipped: set NEXTSSL_FFI_SWEEP=1 to run it (about 4 minutes)");
        return;
    }
    let fixed = |l: Option<Len>, dflt: usize| l.map_or(dflt, |l| dflt.clamp(l.min(), l.max()));
    let mut ok = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    let mut soft: Vec<String> = Vec::new();
    for a in nextssl_registry::all() {
        let name = cs(a.id);
        let params_s = a
            .test_params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";");
        let params = (!params_s.is_empty()).then(|| cs(&params_s));
        let pp = params.as_ref().map_or(null(), |p| p.as_ptr());
        let nm = name.as_ptr();
        let s = a.sizes;
        // A key whose halves differ (XTS refuses equal halves).
        let key: Vec<u8> = (0..fixed(s.key, 32))
            .map(|i| 0x42u8.wrapping_add(i as u8))
            .collect();
        let nonce = vec![0x24u8; fixed(s.nonce, 12)];
        let data = vec![0x5au8; 64];
        // Short text-like input for kinds with tight limits (LM hash, bech32 payloads).
        let short: Vec<u8> = (0..10u8).collect();
        let (sh, digits) = (
            inp(&short),
            inp(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
                9, 0, 1, 2,
            ]),
        );
        let (k, n, d) = (inp(&key), inp(&nonce), inp(&data));
        let empty = inp(b"");
        // SAFETY (every call below): pointers refer to live locals with matching lengths.
        let r: Result<(), i32> = (|| {
            match a.kind {
                Kind::Hash => {
                    let (rc, o) = grow(|o| unsafe { nextssl_root_hash_with(nm, pp, &sh, o) });
                    chk(rc)?;
                    assert!(s.out.unwrap().contains(o.len()), "{}", a.id);
                }
                Kind::Xof => {
                    let (rc, o) = grow(|o| unsafe { nextssl_root_xof(nm, pp, &d, 40, o) });
                    chk(rc)?;
                    assert_eq!(o.len(), 40);
                }
                Kind::Checksum => {
                    let (rc, _) = grow(|o| unsafe { nextssl_root_checksum(nm, pp, &d, o) });
                    chk(rc)?;
                }
                Kind::Prng => {
                    let seed = vec![0x3cu8; fixed(s.seed, 16)];
                    let si = inp(&seed);
                    let (rc, o) = grow(|o| unsafe { nextssl_root_prng(nm, pp, &si, 40, o) });
                    chk(rc)?;
                    assert_eq!(o.len(), 40);
                }
                Kind::Encoding => {
                    let (rc, e) = grow(|o| unsafe { nextssl_root_encode_with(nm, pp, &sh, o) });
                    chk(rc)?;
                    let ei = inp(&e);
                    let (rc, back) = grow(|o| unsafe { nextssl_root_decode_with(nm, pp, &ei, o) });
                    chk(rc)?;
                    assert_eq!(back, short, "{}", a.id);
                }
                Kind::Mac => {
                    let (rc, t) = grow(|o| unsafe { nextssl_root_mac(nm, pp, &k, &d, 0, o) });
                    chk(rc)?;
                    let ti = inp(&t);
                    chk(unsafe { nextssl_root_mac_verify(nm, pp, &k, &d, &ti) })?;
                }
                Kind::Kdf => {
                    let salt = if s.salt.is_some_and(|l| l.max() == 0) {
                        vec![]
                    } else {
                        vec![1u8; 16]
                    };
                    let info = if s.info.is_some_and(|l| l.max() == 0) {
                        vec![]
                    } else {
                        vec![2u8; 8]
                    };
                    let (si, ii) = (inp(&salt), inp(&info));
                    let want = fixed(s.out, 32).clamp(1, 64);
                    let (rc, o) =
                        grow(|o| unsafe { nextssl_root_kdf(nm, pp, &k, &si, &ii, want, o) });
                    chk(rc)?;
                    assert_eq!(o.len(), want);
                }
                Kind::PwHash => {
                    let pw = inp(b"hunter2");
                    let (mut rc, mut phc) =
                        grow(|o| unsafe { nextssl_root_pwhash(nm, pp, &pw, o) });
                    if rc == NEXTSSL_ERR_INVALID_INPUT {
                        // crypt(3)-style schemes need a salt in their own alphabet.
                        let salt = b"NextSSL1";
                        let salt = inp(&salt[..s.salt.map_or(8, |l| l.max().min(8))]);
                        (rc, phc) =
                            grow(|o| unsafe { nextssl_root_pwhash_salted(nm, pp, &pw, &salt, o) });
                    }
                    chk(rc)?;
                    let pi = inp(&phc);
                    chk(unsafe { nextssl_root_pwhash_verify(nm, pp, &pw, &pi) })?;
                    let wrong = inp(b"battery");
                    assert_eq!(
                        unsafe { nextssl_root_pwhash_verify(nm, pp, &wrong, &pi) },
                        NEXTSSL_ERR_AUTHENTICATION_FAILED,
                        "{}",
                        a.id
                    );
                }
                Kind::Aead => {
                    let (rc, ct) =
                        grow(|o| unsafe { nextssl_root_aead_seal(nm, pp, &k, &n, &empty, &d, o) });
                    chk(rc)?;
                    let ci = inp(&ct);
                    let (rc, pt) =
                        grow(|o| unsafe { nextssl_root_aead_open(nm, pp, &k, &n, &empty, &ci, o) });
                    chk(rc)?;
                    assert_eq!(pt, data, "{}", a.id);
                }
                Kind::BlockCipher => {
                    let block = vec![0x11u8; s.block.unwrap().min()];
                    let bi = inp(&block);
                    let (rc, ct) =
                        grow(|o| unsafe { nextssl_root_blockcipher_encrypt(nm, pp, &k, &bi, o) });
                    chk(rc)?;
                    let ci = inp(&ct);
                    let (rc, pt) =
                        grow(|o| unsafe { nextssl_root_blockcipher_decrypt(nm, pp, &k, &ci, o) });
                    chk(rc)?;
                    assert_eq!(pt, block, "{}", a.id);
                }
                Kind::StreamCipher => {
                    let (rc, ct) =
                        grow(|o| unsafe { nextssl_root_stream_apply(nm, pp, &k, &n, &d, o) });
                    chk(rc)?;
                    let ci = inp(&ct);
                    let (rc, pt) =
                        grow(|o| unsafe { nextssl_root_stream_apply(nm, pp, &k, &n, &ci, o) });
                    chk(rc)?;
                    assert_eq!(pt, data, "{}", a.id);
                }
                Kind::BlockMode => {
                    // Format-preserving modes take one digit per byte.
                    let (di, plain) = if a.family == "aes-fpe" {
                        (
                            &digits,
                            vec![
                                1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
                                3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
                            ],
                        )
                    } else {
                        (&d, data.clone())
                    };
                    let (rc, ct) =
                        grow(|o| unsafe { nextssl_root_blockmode_encrypt(nm, pp, &k, &n, di, o) });
                    chk(rc)?;
                    let ci = inp(&ct);
                    let (rc, pt) =
                        grow(|o| unsafe { nextssl_root_blockmode_decrypt(nm, pp, &k, &n, &ci, o) });
                    chk(rc)?;
                    assert_eq!(pt, plain, "{}", a.id);
                }
                Kind::Kem => {
                    let (pk, sk) = pair(s.pk.unwrap().max(), s.sk.unwrap().max(), |p, q| unsafe {
                        nextssl_root_kem_keygen(nm, pp, p, q)
                    })?;
                    let (pki, ski) = (inp(&pk), inp(&sk));
                    let (mut ct, mut s1, mut s2) = (
                        vec![0u8; s.ct.unwrap().max()],
                        vec![0u8; s.ss.unwrap().max()],
                        vec![0u8; s.ss.unwrap().max()],
                    );
                    let (mut co, mut s1o, mut s2o) = (outp(&mut ct), outp(&mut s1), outp(&mut s2));
                    chk(unsafe { nextssl_root_kem_encaps(nm, pp, &pki, &mut co, &mut s1o) })?;
                    ct.truncate(co.len);
                    let cti = inp(&ct);
                    chk(unsafe { nextssl_root_kem_decaps(nm, pp, &ski, &cti, &mut s2o) })?;
                    assert_eq!(s1[..s1o.len], s2[..s2o.len], "{}", a.id);
                }
                Kind::Kex => {
                    let mk = || {
                        pair(s.pk.unwrap().max(), s.sk.unwrap().max(), |p, q| unsafe {
                            nextssl_root_kex_keygen(nm, pp, p, q)
                        })
                    };
                    let ((pa, sa), (pb, sb)) = (mk()?, mk()?);
                    let agree = |sk: &[u8], pk: &[u8]| {
                        let (ski, pki) = (inp(sk), inp(pk));
                        let (rc, ss) =
                            grow(|o| unsafe { nextssl_root_kex_agree(nm, pp, &ski, &pki, o) });
                        chk(rc).map(|()| ss)
                    };
                    assert_eq!(agree(&sa, &pb)?, agree(&sb, &pa)?, "{}", a.id);
                }
                Kind::Sign => {
                    let (pk, sk) = pair(s.pk.unwrap().max(), s.sk.unwrap().max(), |p, q| unsafe {
                        nextssl_root_sign_keygen(nm, pp, p, q)
                    })?;
                    let (pki, ski) = (inp(&pk), inp(&sk));
                    let (rc, sig) = grow(|o| unsafe {
                        nextssl_root_sign_detached(nm, pp, &ski, &d, &empty, o)
                    });
                    chk(rc)?;
                    let sg = inp(&sig);
                    chk(unsafe { nextssl_root_verify_detached(nm, pp, &pki, &d, &empty, &sg) })?;
                    let other = inp(b"another message");
                    assert_ne!(
                        unsafe { nextssl_root_verify_detached(nm, pp, &pki, &other, &empty, &sg) },
                        NEXTSSL_OK,
                        "{}",
                        a.id
                    );
                }
                Kind::Rng => {
                    let (rc, o) = grow(|o| unsafe { nextssl_root_rng_fill(nm, pp, 16, o) });
                    chk(rc)?;
                    assert_eq!(o.len(), 16);
                }
                Kind::Drbg => {
                    let (ent, non) = (vec![7u8; 64], vec![8u8; 16]);
                    let (e, nn) = (inp(&ent), inp(&non));
                    let mut h = 0u64;
                    chk(unsafe { nextssl_root_drbg_new(nm, pp, &e, &nn, &empty, &mut h) })?;
                    let (rc, o) = grow(|o| unsafe { nextssl_drbg_generate(h, &empty, 16, o) });
                    // SAFETY: a plain handle call.
                    unsafe { nextssl_drbg_free(h) };
                    chk(rc)?;
                    assert_eq!(o.len(), 16);
                }
                Kind::Pke => {
                    let (pk, sk) = pair(1 << 16, 1 << 16, |p, q| unsafe {
                        nextssl_root_pke_keygen(nm, pp, p, q)
                    })?;
                    let (pki, ski) = (inp(&pk), inp(&sk));
                    let msg = inp(b"pke message");
                    let (rc, ct) = grow(|o| unsafe {
                        nextssl_root_pke_encrypt(nm, pp, &pki, &msg, &empty, o)
                    });
                    chk(rc)?;
                    let ci = inp(&ct);
                    let (rc, pt) =
                        grow(|o| unsafe { nextssl_root_pke_decrypt(nm, pp, &ski, &ci, &empty, o) });
                    chk(rc)?;
                    assert_eq!(pt, b"pke message");
                }
                Kind::StatefulSign => {
                    let (pk, st) = pair(1 << 16, 1 << 20, |p, q| unsafe {
                        nextssl_root_stateful_keygen(nm, pp, p, q)
                    })?;
                    let (pki, sti) = (inp(&pk), inp(&st));
                    let (mut sig, mut ns) = (vec![0u8; 1 << 16], vec![0u8; 1 << 20]);
                    let (mut sgo, mut nso) = (outp(&mut sig), outp(&mut ns));
                    chk(unsafe {
                        nextssl_root_stateful_sign(nm, pp, &sti, &d, &mut sgo, &mut nso)
                    })?;
                    sig.truncate(sgo.len);
                    ns.truncate(nso.len);
                    let (sg, nsi) = (inp(&sig), inp(&ns));
                    chk(unsafe { nextssl_root_stateful_verify(nm, pp, &pki, &d, &sg) })?;
                    let (mut rem, mut max) = (0u64, 0u64);
                    chk(unsafe {
                        nextssl_root_stateful_remaining(nm, pp, &nsi, &mut rem, &mut max)
                    })?;
                    assert!(rem < max, "{}: state must advance", a.id);
                }
                Kind::Pake
                | Kind::Zk
                | Kind::Threshold
                | Kind::Pow
                | Kind::Vdf
                | Kind::He
                | Kind::Mode => {
                    // Interactive, heavy-setup or cipher-dependent kinds: pake has its own test;
                    // the rest are listed as not swept.
                    skipped.push(format!("{} ({})", a.id, a.kind.as_str()));
                    return Ok(());
                }
            }
            ok += 1;
            Ok(())
        })();
        if let Err(rc) = r {
            assert!(
                ![
                    NEXTSSL_ERR_UNKNOWN_ALGORITHM,
                    NEXTSSL_ERR_WRONG_KIND,
                    NEXTSSL_ERR_TIER_NOT_ALLOWED,
                    NEXTSSL_ERR_PANIC,
                    NEXTSSL_ERR_NULL_POINTER,
                    NEXTSSL_ERR_BAD_HANDLE
                ]
                .contains(&rc),
                "{} ({}): hard ABI error {rc}",
                a.id,
                a.kind.as_str()
            );
            soft.push(format!("{} ({}): code {rc}", a.id, a.kind.as_str()));
        }
    }
    eprintln!(
        "SWEEP: {ok} round trips ok, {} not swept, {} soft failures",
        skipped.len(),
        soft.len()
    );
    for s in &skipped {
        eprintln!("SWEEP not swept: {s}");
    }
    for s in &soft {
        eprintln!("SWEEP soft failure: {s}");
    }
}
