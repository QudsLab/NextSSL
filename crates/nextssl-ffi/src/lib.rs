//! C ABI for NextSSL. Every export is prefixed `nextssl_`.
//!
//! Return value: `NEXTSSL_OK` (0) or a positive error code (see the `NEXTSSL_ERR_*` constants).
//! Output is never truncated: when `out_cap` is too small the call fails with
//! `NEXTSSL_ERR_BAD_OUTPUT_LEN`, and `*out_len` is set to the required size.
//! `nextssl_*` functions use the safe API (safe + standard tiers); `nextssl_root_*` use the
//! root API (any tier).

#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_char, CStr};
use nextssl_core::Error;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const NEXTSSL_OK: i32 = 0;
pub const NEXTSSL_ERR_UNKNOWN_ALGORITHM: i32 = 1;
pub const NEXTSSL_ERR_WRONG_KIND: i32 = 2;
pub const NEXTSSL_ERR_TIER_NOT_ALLOWED: i32 = 3;
pub const NEXTSSL_ERR_PARAM: i32 = 4;
pub const NEXTSSL_ERR_INVALID_LENGTH: i32 = 8;
pub const NEXTSSL_ERR_INVALID_INPUT: i32 = 9;
pub const NEXTSSL_ERR_BAD_OUTPUT_LEN: i32 = 10;
pub const NEXTSSL_ERR_BACKEND: i32 = 11;
pub const NEXTSSL_ERR_AUTHENTICATION_FAILED: i32 = 14;
pub const NEXTSSL_ERR_NULL_POINTER: i32 = 100;
pub const NEXTSSL_ERR_PANIC: i32 = 101;

type Op = fn(&str, &[u8]) -> nextssl_core::Result<Vec<u8>>;

#[allow(unsafe_code)]
mod abi {
    use super::*;

    /// # Safety
    /// Pointer contracts as documented on the exported functions.
    pub(super) unsafe fn run(
        alg: *const c_char,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
        op: Op,
    ) -> i32 {
        if alg.is_null()
            || out_len.is_null()
            || (data.is_null() && data_len != 0)
            || (out.is_null() && out_cap != 0)
        {
            return NEXTSSL_ERR_NULL_POINTER;
        }
        let r = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: `alg` is non-null and, per the documented contract, points to a
            // NUL-terminated string that stays valid for the duration of the call.
            let Ok(alg) = (unsafe { CStr::from_ptr(alg) }).to_str() else {
                return Err(Error::InvalidInput("algorithm name is not UTF-8"));
            };
            let input: &[u8] = if data_len == 0 {
                &[]
            } else {
                // SAFETY: `data` is non-null (checked) and the caller guarantees it points to
                // `data_len` readable bytes that are not mutated during the call.
                unsafe { core::slice::from_raw_parts(data, data_len) }
            };
            op(alg, input)
        }));
        let res = match r {
            Ok(v) => v,
            Err(_) => return NEXTSSL_ERR_PANIC,
        };
        match res {
            Ok(buf) => {
                // SAFETY: `out_len` is non-null (checked) and the caller guarantees it is
                // valid for a `usize` write.
                unsafe { *out_len = buf.len() };
                if buf.len() > out_cap {
                    return NEXTSSL_ERR_BAD_OUTPUT_LEN;
                }
                if !buf.is_empty() {
                    // SAFETY: `out` is non-null when `out_cap > 0` (checked), the caller
                    // guarantees `out_cap` writable bytes, `buf.len() <= out_cap`, and `buf`
                    // is a distinct Rust allocation so the regions cannot overlap.
                    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
                }
                NEXTSSL_OK
            }
            Err(e) => e.code(),
        }
    }
    /// # Safety
    /// `p` must be null (only with `len == 0`) or point to `len` readable bytes.
    pub(super) unsafe fn slice<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
        if len == 0 {
            Some(&[])
        } else if p.is_null() {
            None
        } else {
            // SAFETY: non-null and the caller guarantees `len` readable, unmutated bytes.
            Some(unsafe { core::slice::from_raw_parts(p, len) })
        }
    }

    /// # Safety
    /// `p` must be null or a valid NUL-terminated string.
    pub(super) unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a CStr> {
        if p.is_null() {
            None
        } else {
            // SAFETY: non-null, NUL-terminated per the caller's contract.
            Some(unsafe { CStr::from_ptr(p) })
        }
    }

    /// Runs `f` (panics become `NEXTSSL_ERR_PANIC`) and copies its result to `out`, wiping the
    /// Rust-side copy. Sets `*out_len` to the required size; too small a buffer is
    /// `NEXTSSL_ERR_BAD_OUTPUT_LEN` and nothing is written.
    ///
    /// # Safety
    /// `out`/`out_cap`/`out_len` follow the contract of the exported functions.
    pub(super) unsafe fn finish(
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
        f: impl FnOnce() -> nextssl_core::Result<nextssl_core::Zeroizing<Vec<u8>>>,
    ) -> i32 {
        if out_len.is_null() || (out.is_null() && out_cap != 0) {
            return NEXTSSL_ERR_NULL_POINTER;
        }
        let res = match catch_unwind(AssertUnwindSafe(f)) {
            Ok(v) => v,
            Err(_) => return NEXTSSL_ERR_PANIC,
        };
        match res {
            Ok(buf) => {
                // SAFETY: `out_len` is non-null (checked) and valid for a `usize` write.
                unsafe { *out_len = buf.len() };
                if buf.len() > out_cap {
                    return NEXTSSL_ERR_BAD_OUTPUT_LEN;
                }
                if !buf.is_empty() {
                    // SAFETY: `out` is non-null when `out_cap > 0`, has `out_cap >= buf.len()`
                    // writable bytes, and `buf` is a distinct Rust allocation.
                    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len()) };
                }
                NEXTSSL_OK
            }
            Err(e) => e.code(),
        }
    }
}

/// Hash `data` with a safe/standard tier algorithm.
///
/// # Safety
/// `alg` must be a valid NUL-terminated string. `data` must point to `data_len` readable
/// bytes (may be null only when `data_len` is 0). `out` must point to `out_cap` writable
/// bytes (may be null only when `out_cap` is 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_hash(
    alg: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: forwarded under the same contract documented above.
    unsafe { abi::run(alg, data, data_len, out, out_cap, out_len, nextssl::hash) }
}

/// Hash `data` with any-tier algorithm.
///
/// # Safety
/// `alg` must be a valid NUL-terminated string. `data` must point to `data_len` readable
/// bytes (may be null only when `data_len` is 0). `out` must point to `out_cap` writable
/// bytes (may be null only when `out_cap` is 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_root_hash(
    alg: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: forwarded under the same contract documented above.
    unsafe {
        abi::run(
            alg,
            data,
            data_len,
            out,
            out_cap,
            out_len,
            nextssl_root::hash,
        )
    }
}

/// Encode `data` (safe/standard tier).
///
/// # Safety
/// `alg` must be a valid NUL-terminated string. `data` must point to `data_len` readable
/// bytes (may be null only when `data_len` is 0). `out` must point to `out_cap` writable
/// bytes (may be null only when `out_cap` is 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_encode(
    alg: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: forwarded under the same contract documented above.
    unsafe { abi::run(alg, data, data_len, out, out_cap, out_len, nextssl::encode) }
}

/// Encode `data` (any tier).
///
/// # Safety
/// `alg` must be a valid NUL-terminated string. `data` must point to `data_len` readable
/// bytes (may be null only when `data_len` is 0). `out` must point to `out_cap` writable
/// bytes (may be null only when `out_cap` is 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_root_encode(
    alg: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: forwarded under the same contract documented above.
    unsafe {
        abi::run(
            alg,
            data,
            data_len,
            out,
            out_cap,
            out_len,
            nextssl_root::encode,
        )
    }
}

/// Strictly decode `data` (safe/standard tier).
///
/// # Safety
/// `alg` must be a valid NUL-terminated string. `data` must point to `data_len` readable
/// bytes (may be null only when `data_len` is 0). `out` must point to `out_cap` writable
/// bytes (may be null only when `out_cap` is 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_decode(
    alg: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: forwarded under the same contract documented above.
    unsafe { abi::run(alg, data, data_len, out, out_cap, out_len, nextssl::decode) }
}

/// Strictly decode `data` (any tier).
///
/// # Safety
/// `alg` must be a valid NUL-terminated string. `data` must point to `data_len` readable
/// bytes (may be null only when `data_len` is 0). `out` must point to `out_cap` writable
/// bytes (may be null only when `out_cap` is 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_root_decode(
    alg: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: forwarded under the same contract documented above.
    unsafe {
        abi::run(
            alg,
            data,
            data_len,
            out,
            out_cap,
            out_len,
            nextssl_root::decode,
        )
    }
}

fn alg_str(a: &CStr) -> nextssl_core::Result<&str> {
    a.to_str()
        .map_err(|_| Error::InvalidInput("algorithm name is not UTF-8"))
}

/// Reads the (alg, key, aad, data) inputs shared by the envelope functions.
macro_rules! envelope_inputs {
    ($alg:expr, $key:expr, $key_len:expr, $aad:expr, $aad_len:expr, $data:expr, $data_len:expr) => {{
        // SAFETY: forwarded under the contract documented on the exported functions.
        let parts = unsafe {
            (
                abi::cstr($alg),
                abi::slice($key, $key_len),
                abi::slice($aad, $aad_len),
                abi::slice($data, $data_len),
            )
        };
        match parts {
            (Some(a), Some(k), Some(x), Some(d)) => (a, k, x, d),
            _ => return NEXTSSL_ERR_NULL_POINTER,
        }
    }};
}

/// Encrypts `pt` into a COSE_Encrypt0 envelope (binary CBOR). `alg` is `"xchacha20-poly1305"`
/// or `"aes-256-gcm"`; `key` must be 32 bytes. `aad` is authenticated but not stored.
///
/// # Safety
/// `alg` must be a NUL-terminated string. Each pointer must reference its stated length of
/// readable bytes (null only when the length is 0). `out` must reference `out_cap` writable
/// bytes (null only when 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_encrypt_with_key(
    alg: *const c_char,
    key: *const u8,
    key_len: usize,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (alg, key, aad, pt) = envelope_inputs!(alg, key, key_len, aad, aad_len, pt, pt_len);
    // SAFETY: forwarded under the same contract documented above.
    unsafe {
        abi::finish(out, out_cap, out_len, || {
            let alg = nextssl::AeadAlg::from_id(alg_str(alg)?)?;
            let key = nextssl::SymmetricKey::from_bytes(key, nextssl_core::Len::range(0, 4096))?;
            nextssl::encrypt_with_key(&key, pt, aad, alg).map(nextssl_core::Zeroizing::new)
        })
    }
}

/// Decrypts a COSE_Encrypt0 envelope made by `nextssl_encrypt_with_key`. The algorithm is read
/// from the authenticated header. Failure releases no plaintext.
///
/// # Safety
/// Each pointer must reference its stated length of readable bytes (null only when the length
/// is 0). `out` must reference `out_cap` writable bytes (null only when 0). `out_len` must be
/// valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_decrypt(
    key: *const u8,
    key_len: usize,
    aad: *const u8,
    aad_len: usize,
    envelope: *const u8,
    envelope_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: forwarded under the contract documented above.
    let parts = unsafe {
        (
            abi::slice(key, key_len),
            abi::slice(aad, aad_len),
            abi::slice(envelope, envelope_len),
        )
    };
    let (Some(key), Some(aad), Some(env)) = parts else {
        return NEXTSSL_ERR_NULL_POINTER;
    };
    // SAFETY: forwarded under the same contract documented above.
    unsafe {
        abi::finish(out, out_cap, out_len, || {
            let key = nextssl::SymmetricKey::from_bytes(key, nextssl_core::Len::range(0, 4096))?;
            nextssl::decrypt(&key, env, aad)
        })
    }
}

/// Signs `msg` into a COSE_Sign1 envelope. `alg` is `"ml-dsa-65"` or `"ed25519"`; `sk` is the
/// algorithm's 32-byte private key.
///
/// # Safety
/// `alg` must be a NUL-terminated string. Each pointer must reference its stated length of
/// readable bytes (null only when the length is 0). `out` must reference `out_cap` writable
/// bytes (null only when 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_sign(
    alg: *const c_char,
    sk: *const u8,
    sk_len: usize,
    aad: *const u8,
    aad_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (alg, sk, aad, msg) = envelope_inputs!(alg, sk, sk_len, aad, aad_len, msg, msg_len);
    // SAFETY: forwarded under the same contract documented above.
    unsafe {
        abi::finish(out, out_cap, out_len, || {
            let alg = nextssl::SignAlg::from_id(alg_str(alg)?)?;
            let sk = nextssl::PrivateKey::from_bytes(sk, nextssl_core::Len::range(0, 1 << 16))?;
            nextssl::sign(alg, &sk, msg, aad).map(nextssl_core::Zeroizing::new)
        })
    }
}

/// Verifies a COSE_Sign1 envelope and writes its payload to `out`. The envelope must name
/// exactly `alg`. A bad signature is `NEXTSSL_ERR_AUTHENTICATION_FAILED`.
///
/// # Safety
/// `alg` must be a NUL-terminated string. Each pointer must reference its stated length of
/// readable bytes (null only when the length is 0). `out` must reference `out_cap` writable
/// bytes (null only when 0). `out_len` must be valid for one `size_t` write.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn nextssl_verify(
    alg: *const c_char,
    pk: *const u8,
    pk_len: usize,
    aad: *const u8,
    aad_len: usize,
    envelope: *const u8,
    envelope_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (alg, pk, aad, env) =
        envelope_inputs!(alg, pk, pk_len, aad, aad_len, envelope, envelope_len);
    // SAFETY: forwarded under the same contract documented above.
    unsafe {
        abi::finish(out, out_cap, out_len, || {
            let alg = nextssl::SignAlg::from_id(alg_str(alg)?)?;
            let pk = nextssl::PublicKey::from_bytes(pk, nextssl_core::Len::range(0, 1 << 20))?;
            nextssl::verify(alg, &pk, env, aad).map(nextssl_core::Zeroizing::new)
        })
    }
}

/// Library version as a static NUL-terminated string.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn nextssl_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::ffi::CString;

    type F =
        unsafe extern "C" fn(*const c_char, *const u8, usize, *mut u8, usize, *mut usize) -> i32;

    fn call(f: F, alg: &str, data: &[u8], cap: usize) -> (i32, Vec<u8>, usize) {
        let alg = CString::new(alg).unwrap();
        let mut out = vec![0u8; cap];
        let mut n = 0usize;
        // SAFETY: all pointers come from live Rust values with matching lengths.
        let rc = unsafe {
            f(
                alg.as_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        };
        (rc, out, n)
    }

    #[test]
    fn hash_and_buffer_rules() {
        let (rc, out, n) = call(nextssl_hash, "sha256", b"abc", 32);
        assert_eq!((rc, n), (NEXTSSL_OK, 32));
        assert_eq!(out[0], 0xba);
        let (rc, _, n) = call(nextssl_hash, "sha256", b"abc", 31);
        assert_eq!((rc, n), (NEXTSSL_ERR_BAD_OUTPUT_LEN, 32));
        let (rc, _, _) = call(nextssl_hash, "nope", b"", 64);
        assert_eq!(rc, NEXTSSL_ERR_UNKNOWN_ALGORITHM);
        let (rc, _, _) = call(nextssl_decode, "base64", b"Zg", 16);
        assert_eq!(rc, NEXTSSL_ERR_INVALID_INPUT);
        // blake2b-512 is C-backed; Miri cannot call foreign functions (covered natively + ASan).
        #[cfg(not(miri))]
        {
            let (rc, _, _) = call(nextssl_root_hash, "blake2b-512", b"", 64);
            assert_eq!(rc, NEXTSSL_OK);
        }
        let (rc, _, _) = call(nextssl_root_hash, "sha256", b"", 32);
        assert_eq!(rc, NEXTSSL_OK);
    }

    #[test]
    fn null_pointers_rejected() {
        let mut n = 0usize;
        // SAFETY: null `alg` is detected before any dereference.
        let rc = unsafe {
            nextssl_hash(
                core::ptr::null(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                0,
                &mut n,
            )
        };
        assert_eq!(rc, NEXTSSL_ERR_NULL_POINTER);
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod envelope_tests {
    use super::*;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn encrypt_decrypt_round_trip_buffer_rules_and_tamper() {
        let (alg, key, aad, pt) = (cs("xchacha20-poly1305"), [7u8; 32], b"aad", b"payload");
        let mut env = vec![0u8; 512];
        let mut n = 0usize;
        // SAFETY: pointers come from live Rust values with matching lengths.
        let rc = unsafe {
            nextssl_encrypt_with_key(
                alg.as_ptr(),
                key.as_ptr(),
                32,
                aad.as_ptr(),
                3,
                pt.as_ptr(),
                pt.len(),
                env.as_mut_ptr(),
                env.len(),
                &mut n,
            )
        };
        assert_eq!(rc, NEXTSSL_OK);
        env.truncate(n);
        // too-small output buffer reports the needed size and fails
        let mut small = [0u8; 4];
        let mut need = 0usize;
        // SAFETY: as above.
        let rc = unsafe {
            nextssl_encrypt_with_key(
                alg.as_ptr(),
                key.as_ptr(),
                32,
                aad.as_ptr(),
                3,
                pt.as_ptr(),
                pt.len(),
                small.as_mut_ptr(),
                small.len(),
                &mut need,
            )
        };
        assert_eq!(rc, NEXTSSL_ERR_BAD_OUTPUT_LEN);
        assert!(need > 4);

        let dec = |env: &[u8], key: &[u8]| {
            let mut out = vec![0u8; 64];
            let mut n = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                nextssl_decrypt(
                    key.as_ptr(),
                    key.len(),
                    aad.as_ptr(),
                    3,
                    env.as_ptr(),
                    env.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut n,
                )
            };
            out.truncate(n);
            (rc, out)
        };
        assert_eq!(dec(&env, &key), (NEXTSSL_OK, pt.to_vec()));
        assert_eq!(dec(&env, &[8u8; 32]).0, NEXTSSL_ERR_AUTHENTICATION_FAILED);
        assert_ne!(dec(&env, &[7u8; 16]).0, NEXTSSL_OK);
        let mut bad = env.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_ne!(dec(&bad, &key).0, NEXTSSL_OK);
        // unknown algorithm, null pointers
        let nope = cs("md5");
        let mut n2 = 0usize;
        // SAFETY: as above.
        let rc = unsafe {
            nextssl_encrypt_with_key(
                nope.as_ptr(),
                key.as_ptr(),
                32,
                aad.as_ptr(),
                3,
                pt.as_ptr(),
                pt.len(),
                env.as_mut_ptr(),
                env.len(),
                &mut n2,
            )
        };
        assert_eq!(rc, NEXTSSL_ERR_UNKNOWN_ALGORITHM);
        // SAFETY: null `alg` is detected before any dereference.
        let rc = unsafe {
            nextssl_encrypt_with_key(
                core::ptr::null(),
                key.as_ptr(),
                32,
                aad.as_ptr(),
                3,
                pt.as_ptr(),
                pt.len(),
                env.as_mut_ptr(),
                env.len(),
                &mut n2,
            )
        };
        assert_eq!(rc, NEXTSSL_ERR_NULL_POINTER);
    }

    #[test]
    fn sign_verify_round_trip() {
        let (alg, seed, aad, msg) = (cs("ed25519"), [9u8; 32], b"", b"message");
        let (pk, _) =
            nextssl::keypair_from_seed("ed25519", &seed, nextssl::SeedMode::Native).unwrap();
        let mut env = vec![0u8; 512];
        let mut n = 0usize;
        // SAFETY: pointers come from live Rust values with matching lengths.
        let rc = unsafe {
            nextssl_sign(
                alg.as_ptr(),
                seed.as_ptr(),
                32,
                aad.as_ptr(),
                0,
                msg.as_ptr(),
                msg.len(),
                env.as_mut_ptr(),
                env.len(),
                &mut n,
            )
        };
        assert_eq!(rc, NEXTSSL_OK);
        env.truncate(n);
        let verify = |env: &[u8], alg: &CString| {
            let mut out = vec![0u8; 64];
            let mut n = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                nextssl_verify(
                    alg.as_ptr(),
                    pk.as_bytes().as_ptr(),
                    32,
                    aad.as_ptr(),
                    0,
                    env.as_ptr(),
                    env.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut n,
                )
            };
            out.truncate(n);
            (rc, out)
        };
        assert_eq!(verify(&env, &alg), (NEXTSSL_OK, msg.to_vec()));
        assert_ne!(verify(&env, &cs("ml-dsa-65")).0, NEXTSSL_OK);
        let mut bad = env.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_ne!(verify(&bad, &alg).0, NEXTSSL_OK);
    }
}
