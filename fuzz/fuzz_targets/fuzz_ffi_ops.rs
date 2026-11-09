#![no_main]
//! Fuzzes the generic C ABI (`nextssl_*`) through its exported functions: hostile algorithm names,
//! parameter strings, lengths, tiny output buffers and stale handles. The ABI must never panic
//! (a panic is a fuzzer crash, because `catch_unwind` would hide it from the caller but still
//! indicates a bug) and must never write past a buffer (ASan).
use libfuzzer_sys::fuzz_target;
use nextssl_ffi::*;
use std::ffi::CString;
use std::ptr::{null, null_mut};

/// Splits `data` into `n` parts using one length byte per part (the rest goes to the last part).
fn split<const N: usize>(mut data: &[u8]) -> [&[u8]; N] {
    let mut parts: [&[u8]; N] = [&[]; N];
    for p in parts.iter_mut().take(N.saturating_sub(1)) {
        let Some((&l, rest)) = data.split_first() else {
            return parts;
        };
        let l = usize::from(l).min(rest.len());
        *p = &rest[..l];
        data = &rest[l..];
    }
    if N > 0 {
        parts[N - 1] = data;
    }
    parts
}

fn inp(b: &[u8]) -> NextsslIn {
    NextsslIn {
        ptr: if b.is_empty() { null() } else { b.as_ptr() },
        len: b.len(),
    }
}

// Cheap pure-Rust algorithms only: the point is the ABI layer, not the primitives.
const HASHES: &[&str] = &["sha256", "sha3-256", "blake3", "crc32", "md5"];
const AEADS: &[&str] = &["aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305"];
const MACS: &[&str] = &["hmac", "poly1305", "blake3-mac"];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let cap = usize::from(sel >> 4) * 9; // 0..=135: exercises BAD_OUTPUT_LEN as well as success
    let mut buf = vec![0u8; cap];
    let mut buf2 = vec![0u8; cap];
    let mut out = NextsslOut {
        ptr: if cap == 0 {
            null_mut()
        } else {
            buf.as_mut_ptr()
        },
        cap,
        len: 7,
    };
    let mut out2 = NextsslOut {
        ptr: if cap == 0 {
            null_mut()
        } else {
            buf2.as_mut_ptr()
        },
        cap,
        len: 7,
    };
    let pick = |list: &[&'static str]| CString::new(list[usize::from(sel) % list.len()]).unwrap();
    // SAFETY (every call below): all pointers refer to live locals, strings are NUL-terminated,
    // and each in/out struct describes memory that stays valid for the call.
    unsafe {
        match sel & 0x0f {
            0 => {
                let [params, d] = split(rest);
                let p = CString::new(
                    params
                        .iter()
                        .copied()
                        .filter(|&b| b != 0)
                        .collect::<Vec<u8>>(),
                )
                .unwrap();
                let (a, i) = (pick(HASHES), inp(d));
                nextssl_hash_with(a.as_ptr(), p.as_ptr(), &i, &mut out);
                nextssl_root_hash_with(a.as_ptr(), p.as_ptr(), &i, &mut out);
            }
            1 => {
                // an arbitrary algorithm name and parameter text
                let [name, params, d] = split(rest);
                let n = CString::new(
                    name.iter()
                        .copied()
                        .filter(|&b| b != 0)
                        .collect::<Vec<u8>>(),
                )
                .unwrap();
                let p = CString::new(
                    params
                        .iter()
                        .copied()
                        .filter(|&b| b != 0)
                        .collect::<Vec<u8>>(),
                )
                .unwrap();
                let i = inp(d);
                nextssl_root_hash_with(n.as_ptr(), p.as_ptr(), &i, &mut out);
                nextssl_algorithm_info_json(n.as_ptr(), &mut out);
                nextssl_algorithms_json(n.as_ptr(), &mut out);
            }
            2 => {
                let [d] = split(rest);
                let (a, i) = (CString::new("base64").unwrap(), inp(d));
                nextssl_decode_with(a.as_ptr(), null(), &i, &mut out);
                nextssl_encode_with(a.as_ptr(), null(), &i, &mut out);
            }
            3 => {
                let [key, d, tag] = split(rest);
                let (a, k, i, t) = (pick(MACS), inp(key), inp(d), inp(tag));
                nextssl_mac(a.as_ptr(), null(), &k, &i, usize::from(sel), &mut out);
                nextssl_mac_verify(a.as_ptr(), null(), &k, &i, &t);
            }
            4 => {
                let [key, nonce, aad, ct] = split(rest);
                let (a, k, n, ad, c) = (pick(AEADS), inp(key), inp(nonce), inp(aad), inp(ct));
                nextssl_aead_open(a.as_ptr(), null(), &k, &n, &ad, &c, &mut out);
                nextssl_aead_seal(a.as_ptr(), null(), &k, &n, &ad, &c, &mut out);
            }
            5 => {
                let [pk, msg, sig] = split(rest);
                let (a, p, m, s, none) = (
                    CString::new("ed25519").unwrap(),
                    inp(pk),
                    inp(msg),
                    inp(sig),
                    inp(b""),
                );
                nextssl_verify_detached(a.as_ptr(), null(), &p, &m, &none, &s);
                nextssl_sign_detached(a.as_ptr(), null(), &p, &m, &s, &mut out);
            }
            6 => {
                let [sk, peer] = split(rest);
                let (a, s, p) = (CString::new("x25519").unwrap(), inp(sk), inp(peer));
                nextssl_kex_agree(a.as_ptr(), null(), &s, &p, &mut out);
                nextssl_kex_keygen(a.as_ptr(), null(), &mut out, &mut out2);
            }
            7 => {
                // stale and forged handles
                let mut h = [0u8; 8];
                for (d, s) in h.iter_mut().zip(rest) {
                    *d = *s;
                }
                let h = u64::from_le_bytes(h);
                let none = inp(b"");
                nextssl_drbg_generate(h, &none, usize::from(sel), &mut out);
                nextssl_drbg_reseed(h, &none, &none);
                nextssl_drbg_free(h);
                nextssl_root_pake_free(h);
                nextssl_root_threshold_free(h);
            }
            8 => {
                // lengths that disagree with the buffers
                let i = NextsslIn {
                    ptr: rest.as_ptr(),
                    len: rest.len(),
                };
                let a = CString::new("sha256").unwrap();
                nextssl_hash_with(a.as_ptr(), null(), &i, &mut out);
                let bad = NextsslIn {
                    ptr: null(),
                    len: usize::from(sel),
                };
                nextssl_hash_with(a.as_ptr(), null(), &bad, &mut out);
                let huge = NextsslIn {
                    ptr: rest.as_ptr(),
                    len: usize::MAX,
                };
                nextssl_hash_with(a.as_ptr(), null(), &huge, &mut out);
            }
            _ => {
                let [name, d] = split(rest);
                let n = CString::new(
                    name.iter()
                        .copied()
                        .filter(|&b| b != 0)
                        .collect::<Vec<u8>>(),
                )
                .unwrap();
                let i = inp(d);
                nextssl_xof(n.as_ptr(), null(), &i, usize::from(sel) * 3, &mut out);
                nextssl_checksum(n.as_ptr(), null(), &i, &mut out);
                nextssl_rng_fill(n.as_ptr(), null(), usize::from(sel), &mut out);
                nextssl_error_message(i32::from(sel) - 120);
            }
        }
    }
});
