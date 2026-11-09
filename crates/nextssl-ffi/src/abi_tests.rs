//! Tests of the generic C ABI: pointer and length handling (these run under Miri), tier policy,
//! all-or-nothing outputs, handles, and one round trip per major kind.
//!
//! C-backed algorithms are skipped under Miri (it cannot call foreign code); the pointer rules
//! are exercised with pure-Rust algorithms (sha256, crc32, base64, hmac, aes-256-gcm).

#![allow(unsafe_code)]

use crate::boundary::{NextsslIn, NextsslOut};
use crate::exports::*;
use crate::*;
use core::ffi::c_char;
use std::ffi::{CStr, CString};
use std::ptr::{null, null_mut};

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

/// Calls a one-output function with a growing buffer and returns (rc, bytes).
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

fn hash(root: bool, alg: &str, data: &[u8]) -> (i32, Vec<u8>) {
    let a = cs(alg);
    let d = inp(data);
    grow(|o| {
        // SAFETY: all pointers refer to live locals with matching lengths.
        unsafe {
            if root {
                nextssl_root_hash_with(a.as_ptr(), null(), &d, o)
            } else {
                nextssl_hash_with(a.as_ptr(), null(), &d, o)
            }
        }
    })
}

#[test]
fn hash_known_answer_and_buffer_rules() {
    let (rc, d) = hash(false, "sha256", b"abc");
    assert_eq!(rc, NEXTSSL_OK);
    assert_eq!(
        d,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    // too small: explicit error, required size reported, nothing written
    let (a, data) = (cs("sha256"), inp(b"abc"));
    let mut small = [0xEEu8; 31];
    let mut o = outp(&mut small);
    // SAFETY: pointers refer to live locals.
    let rc = unsafe { nextssl_hash_with(a.as_ptr(), null(), &data, &mut o) };
    assert_eq!((rc, o.len), (NEXTSSL_ERR_BAD_OUTPUT_LEN, 32));
    assert!(small.iter().all(|&b| b == 0xEE));
    // exactly big enough
    let mut exact = [0u8; 32];
    let mut o = outp(&mut exact);
    // SAFETY: as above.
    let rc = unsafe { nextssl_hash_with(a.as_ptr(), null(), &data, &mut o) };
    assert_eq!((rc, o.len), (NEXTSSL_OK, 32));
    // zero capacity with a null buffer is the "ask for the size" call
    let mut o = NextsslOut {
        ptr: null_mut(),
        cap: 0,
        len: 99,
    };
    // SAFETY: as above.
    let rc = unsafe { nextssl_hash_with(a.as_ptr(), null(), &data, &mut o) };
    assert_eq!((rc, o.len), (NEXTSSL_ERR_BAD_OUTPUT_LEN, 32));
}

#[test]
fn null_and_bad_pointers_are_rejected() {
    let (a, data) = (cs("sha256"), inp(b"abc"));
    let mut buf = [0u8; 32];
    let mut o = outp(&mut buf);
    // SAFETY (all calls): null pointers are detected before any dereference.
    unsafe {
        assert_eq!(
            nextssl_hash_with(null(), null(), &data, &mut o),
            NEXTSSL_ERR_NULL_POINTER
        );
        assert_eq!(
            nextssl_hash_with(a.as_ptr(), null(), null(), &mut o),
            NEXTSSL_ERR_NULL_POINTER
        );
        assert_eq!(
            nextssl_hash_with(a.as_ptr(), null(), &data, null_mut()),
            NEXTSSL_ERR_NULL_POINTER
        );
    }
    // input struct with len > 0 and a null pointer
    let bad_in = NextsslIn {
        ptr: null(),
        len: 4,
    };
    // SAFETY: the struct is live; its null data pointer is rejected.
    assert_eq!(
        unsafe { nextssl_hash_with(a.as_ptr(), null(), &bad_in, &mut o) },
        NEXTSSL_ERR_NULL_POINTER
    );
    // empty input with a null pointer is fine
    let empty = NextsslIn {
        ptr: null(),
        len: 0,
    };
    // SAFETY: len 0 never reads the pointer.
    assert_eq!(
        unsafe { nextssl_hash_with(a.as_ptr(), null(), &empty, &mut o) },
        NEXTSSL_OK
    );
    // output with cap > 0 and a null pointer
    let mut bad_out = NextsslOut {
        ptr: null_mut(),
        cap: 32,
        len: 0,
    };
    // SAFETY: the struct is live; its null buffer is rejected.
    assert_eq!(
        unsafe { nextssl_hash_with(a.as_ptr(), null(), &data, &mut bad_out) },
        NEXTSSL_ERR_NULL_POINTER
    );
    // an input length no allocation can have
    let huge = NextsslIn {
        ptr: buf.as_ptr(),
        len: usize::MAX,
    };
    // SAFETY: the length is rejected before the slice is formed.
    assert_eq!(
        unsafe { nextssl_hash_with(a.as_ptr(), null(), &huge, &mut o) },
        NEXTSSL_ERR_INVALID_LENGTH
    );
    // non-UTF-8 algorithm name
    let bad_name = [0xffu8, 0xfe, 0];
    // SAFETY: NUL-terminated local.
    assert_eq!(
        unsafe { nextssl_hash_with(bad_name.as_ptr().cast(), null(), &data, &mut o) },
        NEXTSSL_ERR_INVALID_INPUT
    );
}

#[test]
fn tier_policy_is_enforced_without_fallback() {
    // md5 is legacy: safe entry refuses it, root entry runs it.
    let (rc, d) = hash(false, "md5", b"abc");
    assert_eq!((rc, d.len()), (NEXTSSL_ERR_TIER_NOT_ALLOWED, 0));
    let (rc, d) = hash(true, "md5", b"abc");
    assert_eq!((rc, d.len()), (NEXTSSL_OK, 16));
    assert_eq!(hash(false, "nope", b"").0, NEXTSSL_ERR_UNKNOWN_ALGORITHM);
    // a kem name through the hash entry is the wrong kind
    assert_eq!(hash(false, "ml-kem-768", b"").0, NEXTSSL_ERR_WRONG_KIND);
}

#[test]
fn params_are_parsed_against_the_schema() {
    let a = cs("hmac");
    let key = [7u8; 32];
    let (k, d) = (inp(&key), inp(b"m"));
    let tag = |params: Option<&str>| {
        let p = params.map(cs);
        grow(|o| {
            // SAFETY: all pointers refer to live locals.
            unsafe {
                nextssl_mac(
                    a.as_ptr(),
                    p.as_ref().map_or(null(), |p| p.as_ptr()),
                    &k,
                    &d,
                    0,
                    o,
                )
            }
        })
    };
    assert_eq!(tag(None).1.len(), 32);
    assert_eq!(tag(Some("hash=sha512")).1.len(), 64);
    assert_eq!(tag(Some("hash=md5")).0, NEXTSSL_ERR_PARAM_RANGE);
    assert_eq!(tag(Some("bogus=1")).0, NEXTSSL_ERR_PARAM_UNKNOWN);
    assert_eq!(tag(Some("hash")).0, NEXTSSL_ERR_INVALID_INPUT);
    assert_eq!(
        tag(Some("hash=sha256;hash=sha256")).0,
        NEXTSSL_ERR_INVALID_INPUT
    );
}

#[test]
fn mac_verify_and_key_lengths() {
    let a = cs("hmac");
    let key = [7u8; 32];
    let (k, d) = (inp(&key), inp(b"message"));
    let (rc, tag) = grow(|o| {
        // SAFETY: all pointers refer to live locals.
        unsafe { nextssl_mac(a.as_ptr(), null(), &k, &d, 0, o) }
    });
    assert_eq!(rc, NEXTSSL_OK);
    let t = inp(&tag);
    // SAFETY: as above.
    let ok = unsafe { nextssl_mac_verify(a.as_ptr(), null(), &k, &d, &t) };
    assert_eq!(ok, NEXTSSL_OK);
    let mut bad = tag.clone();
    bad[0] ^= 1;
    let bt = inp(&bad);
    // SAFETY: as above.
    let rc = unsafe { nextssl_mac_verify(a.as_ptr(), null(), &k, &d, &bt) };
    assert_eq!(rc, NEXTSSL_ERR_AUTHENTICATION_FAILED);
    // a tag length the MAC does not declare is an error, never a truncation
    let (rc, _) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_mac(a.as_ptr(), null(), &k, &d, 100, o) }
    });
    assert_ne!(rc, NEXTSSL_OK);
}

#[test]
fn aead_round_trip_and_tamper() {
    let a = cs("aes-256-gcm");
    let (key, nonce, aad, pt) = (
        [1u8; 32],
        [2u8; 12],
        b"aad".as_slice(),
        b"secret".as_slice(),
    );
    let (k, n, ad, p) = (inp(&key), inp(&nonce), inp(aad), inp(pt));
    let (rc, ct) = grow(|o| {
        // SAFETY: all pointers refer to live locals.
        unsafe { nextssl_aead_seal(a.as_ptr(), null(), &k, &n, &ad, &p, o) }
    });
    assert_eq!((rc, ct.len()), (NEXTSSL_OK, pt.len() + 16));
    let open = |ct: &[u8], key: &[u8]| {
        let (c, kk) = (inp(ct), inp(key));
        grow(|o| {
            // SAFETY: as above.
            unsafe { nextssl_aead_open(a.as_ptr(), null(), &kk, &n, &ad, &c, o) }
        })
    };
    assert_eq!(open(&ct, &key), (NEXTSSL_OK, pt.to_vec()));
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert_eq!(open(&bad, &key).0, NEXTSSL_ERR_AUTHENTICATION_FAILED);
    assert_ne!(
        open(&ct, &key[..16]).0,
        NEXTSSL_OK,
        "key length is never ignored"
    );
}

#[test]
fn multi_output_is_all_or_nothing() {
    if cfg!(miri) {
        return; // ml-kem is too slow under the interpreter
    }
    let a = cs("ml-kem-768");
    let mut pk = vec![0xAAu8; 1184];
    let mut sk = vec![0xAAu8; 10]; // too small on purpose
    let (mut po, mut so) = (outp(&mut pk), outp(&mut sk));
    // SAFETY: pointers refer to live locals.
    let rc = unsafe { nextssl_kem_keygen(a.as_ptr(), null(), &mut po, &mut so) };
    assert_eq!(rc, NEXTSSL_ERR_BAD_OUTPUT_LEN);
    assert_eq!((po.len, so.len), (1184, 2400));
    assert!(pk.iter().all(|&b| b == 0xAA), "no partial write");
    // a full round trip
    let mut pk = vec![0u8; 1184];
    let mut sk = vec![0u8; 2400];
    let (mut po, mut so) = (outp(&mut pk), outp(&mut sk));
    // SAFETY: as above.
    assert_eq!(
        unsafe { nextssl_kem_keygen(a.as_ptr(), null(), &mut po, &mut so) },
        NEXTSSL_OK
    );
    let (pki, ski) = (inp(&pk), inp(&sk));
    let (mut ct, mut ss1, mut ss2) = (vec![0u8; 1088], vec![0u8; 32], vec![0u8; 32]);
    let (mut co, mut s1o, mut s2o) = (outp(&mut ct), outp(&mut ss1), outp(&mut ss2));
    // SAFETY: as above.
    assert_eq!(
        unsafe { nextssl_kem_encaps(a.as_ptr(), null(), &pki, &mut co, &mut s1o) },
        NEXTSSL_OK
    );
    let cti = inp(&ct);
    // SAFETY: as above.
    assert_eq!(
        unsafe { nextssl_kem_decaps(a.as_ptr(), null(), &ski, &cti, &mut s2o) },
        NEXTSSL_OK
    );
    assert_eq!(ss1, ss2);
    assert_ne!(ss1, vec![0u8; 32]);
}

#[test]
fn sign_and_verify_detached() {
    if cfg!(miri) {
        return;
    }
    let a = cs("ed25519");
    let (mut pk, mut sk) = (vec![0u8; 32], vec![0u8; 32]);
    let (mut po, mut so) = (outp(&mut pk), outp(&mut sk));
    // SAFETY: pointers refer to live locals.
    assert_eq!(
        unsafe { nextssl_sign_keygen(a.as_ptr(), null(), &mut po, &mut so) },
        NEXTSSL_OK
    );
    let (msg, ctx, ski, pki) = (b"hello".as_slice(), b"".as_slice(), inp(&sk), inp(&pk));
    let (m, c) = (inp(msg), inp(ctx));
    let (rc, sig) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_sign_detached(a.as_ptr(), null(), &ski, &m, &c, o) }
    });
    assert_eq!((rc, sig.len()), (NEXTSSL_OK, 64));
    let sg = inp(&sig);
    // SAFETY: as above.
    assert_eq!(
        unsafe { nextssl_verify_detached(a.as_ptr(), null(), &pki, &m, &c, &sg) },
        NEXTSSL_OK
    );
    let other = inp(b"hellp");
    // SAFETY: as above.
    assert_eq!(
        unsafe { nextssl_verify_detached(a.as_ptr(), null(), &pki, &other, &c, &sg) },
        NEXTSSL_ERR_AUTHENTICATION_FAILED
    );
}

#[test]
fn encode_with_params_and_checksum() {
    let (a, d) = (cs("base64"), inp(b"f"));
    let (rc, e) = grow(|o| {
        // SAFETY: all pointers refer to live locals.
        unsafe { nextssl_encode_with(a.as_ptr(), null(), &d, o) }
    });
    assert_eq!((rc, e.as_slice()), (NEXTSSL_OK, b"Zg==".as_slice()));
    let ei = inp(&e);
    let (rc, back) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_decode_with(a.as_ptr(), null(), &ei, o) }
    });
    assert_eq!((rc, back.as_slice()), (NEXTSSL_OK, b"f".as_slice()));
    let bad = inp(b"Zg");
    let (rc, _) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_decode_with(a.as_ptr(), null(), &bad, o) }
    });
    assert_eq!(rc, NEXTSSL_ERR_INVALID_INPUT);
    let (c, data) = (cs("crc32"), inp(b"123456789"));
    let (rc, crc) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_checksum(c.as_ptr(), null(), &data, o) }
    });
    assert_eq!((rc, crc), (NEXTSSL_OK, vec![0xcb, 0xf4, 0x39, 0x26]));
}

#[test]
fn drbg_handles_are_validated() {
    if cfg!(miri) {
        return;
    }
    let a = cs("hmac-drbg-sha256");
    let (ent, non, pers) = ([5u8; 48], [6u8; 16], b"".as_slice());
    let (e, n, p) = (inp(&ent), inp(&non), inp(pers));
    let mut h = 0u64;
    // SAFETY: pointers refer to live locals.
    assert_eq!(
        unsafe { nextssl_drbg_new(a.as_ptr(), null(), &e, &n, &p, &mut h) },
        NEXTSSL_OK
    );
    assert_ne!(h, 0);
    let add = inp(b"");
    let gen = |h: u64, want: usize| {
        grow(|o| {
            // SAFETY: as above.
            unsafe { nextssl_drbg_generate(h, &add, want, o) }
        })
    };
    let (rc, one) = gen(h, 32);
    assert_eq!((rc, one.len()), (NEXTSSL_OK, 32));
    let (_, two) = gen(h, 32);
    assert_ne!(one, two);
    assert_eq!(gen(h, 0).0, NEXTSSL_ERR_INVALID_LENGTH);
    // SAFETY: handle calls take no pointers beyond the ones passed.
    unsafe {
        assert_eq!(nextssl_drbg_free(h), NEXTSSL_OK);
        assert_eq!(nextssl_drbg_free(h), NEXTSSL_ERR_BAD_HANDLE);
        assert_eq!(nextssl_drbg_free(0), NEXTSSL_ERR_BAD_HANDLE);
        assert_eq!(nextssl_drbg_free(u64::MAX), NEXTSSL_ERR_BAD_HANDLE);
    }
    assert_eq!(gen(h, 8).0, NEXTSSL_ERR_BAD_HANDLE);
    // a short entropy input is an error and creates no handle
    let short = inp(&ent[..8]);
    let mut h2 = 77u64;
    // SAFETY: as above.
    let rc = unsafe { nextssl_drbg_new(a.as_ptr(), null(), &short, &n, &p, &mut h2) };
    assert_ne!(rc, NEXTSSL_OK);
    assert_eq!(h2, 0);
}

#[test]
fn rng_and_pake_sessions() {
    if cfg!(miri) {
        return;
    }
    let (a, os) = (cs("os-entropy"), cs("os-entropy"));
    let (rc, r1) = grow(|o| {
        // SAFETY: pointers refer to live locals.
        unsafe { nextssl_rng_fill(a.as_ptr(), null(), 32, o) }
    });
    assert_eq!((rc, r1.len()), (NEXTSSL_OK, 32));
    let (_, r2) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_rng_fill(os.as_ptr(), null(), 32, o) }
    });
    assert_ne!(r1, r2);
    // PAKE exists only as nextssl_root_*; two parties agree.
    let alg = cs("spake2-ed25519");
    let (pw, ctx) = (inp(b"hunter2"), inp(b"nextssl-test"));
    let start = |role: u32| {
        let mut h = 0u64;
        let mut buf = vec![0u8; 4096];
        let mut o = outp(&mut buf);
        // SAFETY: as above.
        let rc = unsafe {
            nextssl_root_pake_start(alg.as_ptr(), null(), role, &pw, &ctx, &mut h, &mut o)
        };
        assert_eq!(rc, NEXTSSL_OK);
        buf.truncate(o.len);
        (h, buf)
    };
    let (ha, ma) = start(0);
    let (hb, mb) = start(1);
    let step = |h: u64, m: &[u8]| {
        let mi = inp(m);
        let (mut mo, mut ss) = (vec![0u8; 4096], vec![0u8; 4096]);
        let (mut moo, mut sso) = (outp(&mut mo), outp(&mut ss));
        let mut done = 9u32;
        // SAFETY: as above.
        let rc = unsafe { nextssl_root_pake_step(h, &mi, &mut moo, &mut sso, &mut done) };
        assert_eq!(rc, NEXTSSL_OK);
        mo.truncate(moo.len);
        ss.truncate(sso.len);
        (done, mo, ss)
    };
    let (da, _, ssa) = step(ha, &mb);
    let (db, _, ssb) = step(hb, &ma);
    assert_eq!((da, db), (1, 1));
    assert_eq!(ssa, ssb);
    assert_eq!(ssa.len(), 32);
    // the session closed itself; stepping again is a stale handle
    let mi = inp(b"");
    let (mut mo, mut ss) = (vec![0u8; 64], vec![0u8; 64]);
    let (mut moo, mut sso) = (outp(&mut mo), outp(&mut ss));
    let mut done = 0u32;
    // SAFETY: as above.
    let rc = unsafe { nextssl_root_pake_step(ha, &mi, &mut moo, &mut sso, &mut done) };
    assert_eq!(rc, NEXTSSL_ERR_BAD_HANDLE);
    // safe policy never reaches a root-only kind, whatever the entry
    let (mut pk, mut sk) = (vec![0u8; 8192], vec![0u8; 8192]);
    let (mut po, mut so) = (outp(&mut pk), outp(&mut sk));
    // SAFETY: as above.
    let rc = unsafe { nextssl_kem_keygen(alg.as_ptr(), null(), &mut po, &mut so) };
    assert_eq!(rc, NEXTSSL_ERR_WRONG_KIND);
}

#[test]
fn panics_do_not_cross_the_abi() {
    let mut buf = [0u8; 4];
    let mut o = outp(&mut buf);
    let outs = [&mut o as *mut NextsslOut];
    // SAFETY: `o` is a live NextsslOut over a live buffer.
    let rc = unsafe { crate::boundary::run(&outs, || panic!("boom")) };
    assert_eq!((rc, o.len), (NEXTSSL_ERR_PANIC, 0));
    let rc = crate::boundary::run_unit(|| panic!("boom"));
    assert_eq!(rc, NEXTSSL_ERR_PANIC);
}

#[test]
fn discovery_json_and_messages() {
    // The full 386-entry listing is far too slow for Miri; the kind-filtered listing below
    // exercises the same code and pointer handling.
    if !cfg!(miri) {
        let mut buf = vec![0u8; 1];
        let mut o = outp(&mut buf);
        // SAFETY: pointers refer to live locals; a null kind means all kinds.
        let rc = unsafe { nextssl_algorithms_json(null(), &mut o) };
        assert_eq!(rc, NEXTSSL_ERR_BAD_OUTPUT_LEN);
        let mut big = vec![0u8; o.len];
        let mut o2 = outp(&mut big);
        // SAFETY: as above.
        assert_eq!(
            unsafe { nextssl_algorithms_json(null(), &mut o2) },
            NEXTSSL_OK
        );
        let text = std::str::from_utf8(&big).unwrap();
        assert!(text.contains("\"id\":\"sha256\"") && text.contains("\"abi_version\":1"));
    }
    let k = cs("kem");
    let (rc, kems) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_algorithms_json(k.as_ptr(), o) }
    });
    assert_eq!(rc, NEXTSSL_OK);
    assert!(!String::from_utf8(kems).unwrap().contains("\"sha256\""));
    let bad = cs("nope");
    let (rc, _) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_algorithms_json(bad.as_ptr(), o) }
    });
    assert_eq!(rc, NEXTSSL_ERR_INVALID_INPUT);
    let sha = cs("sha256");
    let (rc, info) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_algorithm_info_json(sha.as_ptr(), o) }
    });
    assert_eq!(rc, NEXTSSL_OK);
    assert!(String::from_utf8(info)
        .unwrap()
        .contains("\"safe_api\":true"));
    for code in [0, 1, 3, 10, 14, 100, 101, 102, 9999] {
        let m = nextssl_error_message(code);
        assert!(!m.is_null());
        // SAFETY: the message table returns NUL-terminated static strings.
        let s = unsafe { CStr::from_ptr(m as *const c_char) }
            .to_str()
            .unwrap();
        assert!(!s.is_empty());
    }
    assert_eq!(nextssl_abi_version(), 1);
}

#[test]
fn buffers_alloc_and_free() {
    assert!(nextssl_buf_alloc(0).is_null());
    assert!(nextssl_buf_alloc(usize::MAX).is_null());
    let p = nextssl_buf_alloc(64);
    assert!(!p.is_null());
    // SAFETY: `p` is a live 64-byte zeroed allocation from nextssl_buf_alloc.
    unsafe {
        assert_eq!(*p.add(63), 0);
        *p.add(63) = 9;
        nextssl_buf_free(p, 64);
        nextssl_buf_free(null_mut(), 64);
    }
}

#[test]
fn packed_lists_are_strict() {
    let packed = ops::pack(&[b"ab", b"", b"cde"]).unwrap();
    assert_eq!(ops::unpack(&packed).unwrap(), vec![&b"ab"[..], b"", b"cde"]);
    assert!(ops::unpack(&packed[..packed.len() - 1]).is_err());
    assert!(ops::unpack(&[1, 0]).is_err());
    assert!(ops::unpack(&[9, 0, 0, 0, 1]).is_err());
    assert!(ops::unpack(&[]).unwrap().is_empty());
}

#[test]
fn every_registered_algorithm_has_info() {
    if cfg!(miri) {
        return; // 386 JSON renderings: too slow for the interpreter
    }
    // Discovery covers the whole registry; the operation sweep lives in abi_sweep.rs.
    for a in nextssl_registry::all() {
        let c = cs(a.id);
        let info = grow(|o| {
            // SAFETY: pointers refer to live locals.
            unsafe { nextssl_algorithm_info_json(c.as_ptr(), o) }
        });
        assert_eq!(info.0, NEXTSSL_OK, "{}", a.id);
    }
    assert!(handles::live() < handles::NEXTSSL_MAX_HANDLES);
}

#[test]
fn threshold_split_and_combine_through_packed_lists() {
    if cfg!(miri) {
        return;
    }
    let a = cs("shamir");
    let secret = inp(b"split me three ways");
    let (rc, packed) = grow(|o| {
        // SAFETY: pointers refer to live locals.
        unsafe { nextssl_root_threshold_split(a.as_ptr(), null(), &secret, 3, 5, o) }
    });
    assert_eq!(rc, NEXTSSL_OK);
    let shares = ops::unpack(&packed).unwrap();
    assert_eq!(shares.len(), 5);
    let three = ops::pack(&shares[1..4]).unwrap();
    let ti = inp(&three);
    let (rc, back) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_root_threshold_combine(a.as_ptr(), null(), &ti, o) }
    });
    assert_eq!(
        (rc, back.as_slice()),
        (NEXTSSL_OK, b"split me three ways".as_slice())
    );
    // t > n is an explicit error, and the safe policy has no entry for this kind at all
    let (rc, _) = grow(|o| {
        // SAFETY: as above.
        unsafe { nextssl_root_threshold_split(a.as_ptr(), null(), &secret, 6, 5, o) }
    });
    assert_ne!(rc, NEXTSSL_OK);
}
