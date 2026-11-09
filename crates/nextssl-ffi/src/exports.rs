//! The generic C ABI: every registered algorithm, by name.
//!
//! Naming: `nextssl_<op>` reaches only `safe` and `standard` tiers (an explicit
//! `NEXTSSL_ERR_TIER_NOT_ALLOWED` otherwise); `nextssl_root_<op>` reaches every tier. Kinds that
//! are root-only by policy (pke, pake, stateful signatures, zk, threshold, he, vdf) exist only
//! as `nextssl_root_*`.
//!
//! Arguments: `alg` is an algorithm id or alias (NUL-terminated UTF-8). `params` is null or
//! `name=value;name=value` using the algorithm's declared parameters (`nextssl_algorithm_info_json`
//! lists them; `bytes` values are hex). Byte inputs are `nextssl_in*`, byte outputs are
//! `nextssl_out*`. The return value is `NEXTSSL_OK` or a `NEXTSSL_ERR_*` code; verification
//! functions return `NEXTSSL_ERR_AUTHENTICATION_FAILED` for "invalid".
//!
//! Pointer contract for every function here: pointers are null only where stated, `nextssl_in`
//! and `nextssl_out` structs are aligned and readable/writable, the memory they reference stays
//! valid for the call, and output buffers do not overlap each other or any input.

#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc, clippy::too_many_arguments)]

use crate::boundary::{
    buf_alloc, buf_free, input, name, opt_text, put, run, run_unit, tr, NextsslIn, NextsslOut,
};
use crate::{handles, json, ops, NEXTSSL_ERR_BAD_HANDLE, NEXTSSL_ERR_BAD_OUTPUT_LEN};
use crate::{NEXTSSL_ERR_NULL_POINTER, NEXTSSL_OK};
use core::ffi::c_char;
use nextssl_registry::Policy;

macro_rules! n {
    ($p:expr) => {
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        tr!(unsafe { name($p) })
    };
}
macro_rules! t {
    ($p:expr) => {
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        tr!(unsafe { opt_text($p) })
    };
}
macro_rules! i {
    ($p:expr) => {
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        tr!(unsafe { input($p) })
    };
}

// ---- implementations (policy-generic) ----------------------------------------------------------

mod imp {
    use super::*;

    pub unsafe fn hash(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        data: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, d) = (n!(alg), t!(params), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::hash(pol, a, p, d)) }
    }

    pub unsafe fn encode(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        data: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, d) = (n!(alg), t!(params), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::encode(pol, a, p, d)) }
    }

    pub unsafe fn decode(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        data: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, d) = (n!(alg), t!(params), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::decode(pol, a, p, d)) }
    }

    pub unsafe fn xof(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        data: *const NextsslIn,
        want: usize,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, d) = (n!(alg), t!(params), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::xof(pol, a, p, d, want)) }
    }

    pub unsafe fn checksum(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        data: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, d) = (n!(alg), t!(params), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::checksum(pol, a, p, d)) }
    }

    pub unsafe fn mac(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        key: *const NextsslIn,
        data: *const NextsslIn,
        tag_len: usize,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, k, d) = (n!(alg), t!(params), i!(key), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::mac(pol, a, p, k, d, tag_len)) }
    }

    pub unsafe fn mac_verify(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        key: *const NextsslIn,
        data: *const NextsslIn,
        tag: *const NextsslIn,
    ) -> i32 {
        let (a, p, k, d, g) = (n!(alg), t!(params), i!(key), i!(data), i!(tag));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[], || ops::mac_verify(pol, a, p, k, d, g)) }
    }

    pub unsafe fn kdf(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        ikm: *const NextsslIn,
        salt: *const NextsslIn,
        info: *const NextsslIn,
        want: usize,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, k, s, f) = (n!(alg), t!(params), i!(ikm), i!(salt), i!(info));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::kdf(pol, a, p, k, s, f, want)) }
    }

    pub unsafe fn pwhash(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        password: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, w) = (n!(alg), t!(params), i!(password));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::pwhash(pol, a, p, w)) }
    }

    pub unsafe fn pwhash_salted(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        password: *const NextsslIn,
        salt: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, w, s) = (n!(alg), t!(params), i!(password), i!(salt));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::pwhash_salted(pol, a, p, w, s)) }
    }

    pub unsafe fn pwhash_verify(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        password: *const NextsslIn,
        phc: *const NextsslIn,
    ) -> i32 {
        let (a, p, w, h) = (n!(alg), t!(params), i!(password), i!(phc));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[], || ops::pwhash_verify(pol, a, p, w, h)) }
    }

    pub unsafe fn pwhash_derive(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        password: *const NextsslIn,
        salt: *const NextsslIn,
        want: usize,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, w, s) = (n!(alg), t!(params), i!(password), i!(salt));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::pwhash_derive(pol, a, p, w, s, want)) }
    }

    pub unsafe fn aead_seal(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        key: *const NextsslIn,
        nonce: *const NextsslIn,
        aad: *const NextsslIn,
        pt: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, k, nc, ad, m) = (n!(alg), t!(params), i!(key), i!(nonce), i!(aad), i!(pt));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::aead_seal(pol, a, p, k, nc, ad, m)) }
    }

    pub unsafe fn aead_open(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        key: *const NextsslIn,
        nonce: *const NextsslIn,
        aad: *const NextsslIn,
        ct: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, k, nc, ad, c) = (n!(alg), t!(params), i!(key), i!(nonce), i!(aad), i!(ct));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::aead_open(pol, a, p, k, nc, ad, c)) }
    }

    pub unsafe fn blockcipher(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        key: *const NextsslIn,
        block: *const NextsslIn,
        out: *mut NextsslOut,
        decrypt: bool,
    ) -> i32 {
        let (a, p, k, b) = (n!(alg), t!(params), i!(key), i!(block));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::blockcipher(pol, a, p, k, b, decrypt)) }
    }

    pub unsafe fn stream_apply(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        key: *const NextsslIn,
        nonce: *const NextsslIn,
        data: *const NextsslIn,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, k, nc, d) = (n!(alg), t!(params), i!(key), i!(nonce), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::stream_apply(pol, a, p, k, nc, d)) }
    }

    pub unsafe fn blockmode(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        key: *const NextsslIn,
        nonce: *const NextsslIn,
        data: *const NextsslIn,
        out: *mut NextsslOut,
        decrypt: bool,
    ) -> i32 {
        let (a, p, k, nc, d) = (n!(alg), t!(params), i!(key), i!(nonce), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::blockmode(pol, a, p, k, nc, d, decrypt)) }
    }

    pub unsafe fn mode(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        cipher: *const c_char,
        cipher_params: *const c_char,
        key: *const NextsslIn,
        iv: *const NextsslIn,
        data: *const NextsslIn,
        out: *mut NextsslOut,
        decrypt: bool,
    ) -> i32 {
        let (a, p, c, cp) = (n!(alg), t!(params), n!(cipher), t!(cipher_params));
        let (k, v, d) = (i!(key), i!(iv), i!(data));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::mode(pol, a, p, c, cp, k, v, d, decrypt)) }
    }

    pub unsafe fn rng_fill(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        want: usize,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p) = (n!(alg), t!(params));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[out], || ops::rng_fill(pol, a, p, want)) }
    }

    pub unsafe fn drbg_new(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        entropy: *const NextsslIn,
        nonce: *const NextsslIn,
        pers: *const NextsslIn,
        handle: *mut u64,
    ) -> i32 {
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        if !unsafe { put(handle, 0) } {
            return NEXTSSL_ERR_NULL_POINTER;
        }
        let (a, p, e, nc, ps) = (n!(alg), t!(params), i!(entropy), i!(nonce), i!(pers));
        run_unit(|| {
            let h = ops::drbg_new(pol, a, p, e, nc, ps)?;
            // SAFETY: `handle` was checked non-null and written above under the caller's contract.
            unsafe { put(handle, h) };
            Ok(())
        })
    }

    pub unsafe fn keygen2(
        run_with: impl FnOnce() -> ops::R,
        pk: *mut NextsslOut,
        sk: *mut NextsslOut,
    ) -> i32 {
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[pk, sk], run_with) }
    }

    pub unsafe fn pow_solve(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        challenge: *const NextsslIn,
        difficulty: u32,
        max_work: u64,
        out: *mut NextsslOut,
    ) -> i32 {
        let (a, p, c) = (n!(alg), t!(params), i!(challenge));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe {
            run(&[out], || {
                ops::pow_solve(pol, a, p, c, difficulty, max_work)
            })
        }
    }

    pub unsafe fn pow_verify(
        pol: Policy,
        alg: *const c_char,
        params: *const c_char,
        challenge: *const NextsslIn,
        solution: *const NextsslIn,
        difficulty: u32,
    ) -> i32 {
        let (a, p, c, s) = (n!(alg), t!(params), i!(challenge), i!(solution));
        // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
        unsafe { run(&[], || ops::pow_verify(pol, a, p, c, s, difficulty)) }
    }
}

// ---- keyless -------------------------------------------------------------------------------------

/// Hash `data` with a safe/standard algorithm, with parameters. `out` receives the digest.
#[no_mangle]
pub unsafe extern "C" fn nextssl_hash_with(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::hash(Policy::Safe, alg, params, data, out) }
}

/// Hash `data` with an algorithm of any tier, with parameters.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_hash_with(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::hash(Policy::Any, alg, params, data, out) }
}

/// Encode `data` (safe/standard), with parameters (for example `hrp=bc` for bech32).
#[no_mangle]
pub unsafe extern "C" fn nextssl_encode_with(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::encode(Policy::Safe, alg, params, data, out) }
}

/// Encode `data` (any tier), with parameters.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_encode_with(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::encode(Policy::Any, alg, params, data, out) }
}

/// Strictly decode `data` (safe/standard), with parameters.
#[no_mangle]
pub unsafe extern "C" fn nextssl_decode_with(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::decode(Policy::Safe, alg, params, data, out) }
}

/// Strictly decode `data` (any tier), with parameters.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_decode_with(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::decode(Policy::Any, alg, params, data, out) }
}

/// Extendable-output function (safe/standard): exactly `want` bytes (1..=16 MiB) into `out`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_xof(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::xof(Policy::Safe, alg, params, data, want, out) }
}

/// Extendable-output function, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_xof(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::xof(Policy::Any, alg, params, data, want, out) }
}

/// Non-cryptographic checksum (CRC, Adler, ...), safe/standard tiers only.
#[no_mangle]
pub unsafe extern "C" fn nextssl_checksum(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::checksum(Policy::Safe, alg, params, data, out) }
}

/// Non-cryptographic checksum, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_checksum(
    alg: *const c_char,
    params: *const c_char,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::checksum(Policy::Any, alg, params, data, out) }
}

// ---- MAC, KDF, password hashing -------------------------------------------------------------------

/// MAC tag (safe/standard). `tag_len` 0 selects the longest tag the MAC declares; any other
/// value must be a declared tag length.
#[no_mangle]
pub unsafe extern "C" fn nextssl_mac(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    data: *const NextsslIn,
    tag_len: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::mac(Policy::Safe, alg, params, key, data, tag_len, out) }
}

/// MAC tag, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_mac(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    data: *const NextsslIn,
    tag_len: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::mac(Policy::Any, alg, params, key, data, tag_len, out) }
}

/// Constant-time MAC check (safe/standard). `NEXTSSL_OK` = valid, `AUTHENTICATION_FAILED` = wrong tag.
#[no_mangle]
pub unsafe extern "C" fn nextssl_mac_verify(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    data: *const NextsslIn,
    tag: *const NextsslIn,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::mac_verify(Policy::Safe, alg, params, key, data, tag) }
}

/// Constant-time MAC check, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_mac_verify(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    data: *const NextsslIn,
    tag: *const NextsslIn,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::mac_verify(Policy::Any, alg, params, key, data, tag) }
}

/// Key derivation (safe/standard): exactly `want` bytes (1..=16 MiB), or an error if the KDF
/// cannot produce that many.
#[no_mangle]
pub unsafe extern "C" fn nextssl_kdf(
    alg: *const c_char,
    params: *const c_char,
    ikm: *const NextsslIn,
    salt: *const NextsslIn,
    info: *const NextsslIn,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::kdf(Policy::Safe, alg, params, ikm, salt, info, want, out) }
}

/// Key derivation, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_kdf(
    alg: *const c_char,
    params: *const c_char,
    ikm: *const NextsslIn,
    salt: *const NextsslIn,
    info: *const NextsslIn,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::kdf(Policy::Any, alg, params, ikm, salt, info, want, out) }
}

/// Password hash as a PHC string with a fresh random salt (safe/standard).
#[no_mangle]
pub unsafe extern "C" fn nextssl_pwhash(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash(Policy::Safe, alg, params, password, out) }
}

/// Password hash as a PHC string with a fresh random salt, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pwhash(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash(Policy::Any, alg, params, password, out) }
}

/// Password hash as a PHC string with a caller-supplied salt (safe/standard).
#[no_mangle]
pub unsafe extern "C" fn nextssl_pwhash_salted(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    salt: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash_salted(Policy::Safe, alg, params, password, salt, out) }
}

/// Password hash as a PHC string with a caller-supplied salt, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pwhash_salted(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    salt: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash_salted(Policy::Any, alg, params, password, salt, out) }
}

/// Verify a password against a PHC string (safe/standard). `AUTHENTICATION_FAILED` = wrong password.
#[no_mangle]
pub unsafe extern "C" fn nextssl_pwhash_verify(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    phc: *const NextsslIn,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash_verify(Policy::Safe, alg, params, password, phc) }
}

/// Verify a password against a PHC string, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pwhash_verify(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    phc: *const NextsslIn,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash_verify(Policy::Any, alg, params, password, phc) }
}

/// Raw key derivation from a password (safe/standard): exactly `want` bytes.
#[no_mangle]
pub unsafe extern "C" fn nextssl_pwhash_derive(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    salt: *const NextsslIn,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash_derive(Policy::Safe, alg, params, password, salt, want, out) }
}

/// Raw key derivation from a password, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pwhash_derive(
    alg: *const c_char,
    params: *const c_char,
    password: *const NextsslIn,
    salt: *const NextsslIn,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pwhash_derive(Policy::Any, alg, params, password, salt, want, out) }
}

// ---- AEAD, ciphers, modes ----------------------------------------------------------------------------

/// AEAD seal (safe/standard): writes `ciphertext || tag`. The caller owns nonce uniqueness.
#[no_mangle]
pub unsafe extern "C" fn nextssl_aead_seal(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    aad: *const NextsslIn,
    pt: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::aead_seal(Policy::Safe, alg, params, key, nonce, aad, pt, out) }
}

/// AEAD seal, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_aead_seal(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    aad: *const NextsslIn,
    pt: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::aead_seal(Policy::Any, alg, params, key, nonce, aad, pt, out) }
}

/// AEAD open of `ciphertext || tag` (safe/standard). A failed tag is `AUTHENTICATION_FAILED`
/// and releases no plaintext.
#[no_mangle]
pub unsafe extern "C" fn nextssl_aead_open(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    aad: *const NextsslIn,
    ct: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::aead_open(Policy::Safe, alg, params, key, nonce, aad, ct, out) }
}

/// AEAD open, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_aead_open(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    aad: *const NextsslIn,
    ct: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::aead_open(Policy::Any, alg, params, key, nonce, aad, ct, out) }
}

/// Encrypt one block (safe/standard). `block` must be exactly the cipher's block size.
#[no_mangle]
pub unsafe extern "C" fn nextssl_blockcipher_encrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    block: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockcipher(Policy::Safe, alg, params, key, block, out, false) }
}

/// Encrypt one block, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_blockcipher_encrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    block: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockcipher(Policy::Any, alg, params, key, block, out, false) }
}

/// Decrypt one block (safe/standard).
#[no_mangle]
pub unsafe extern "C" fn nextssl_blockcipher_decrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    block: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockcipher(Policy::Safe, alg, params, key, block, out, true) }
}

/// Decrypt one block, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_blockcipher_decrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    block: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockcipher(Policy::Any, alg, params, key, block, out, true) }
}

/// XOR the keystream of a stream cipher into `data` (safe/standard). Encrypt and decrypt are the same call.
#[no_mangle]
pub unsafe extern "C" fn nextssl_stream_apply(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::stream_apply(Policy::Safe, alg, params, key, nonce, data, out) }
}

/// Stream cipher, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_stream_apply(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::stream_apply(Policy::Any, alg, params, key, nonce, data, out) }
}

/// Encrypt with a concrete block-cipher mode such as `aes-256-cbc` (safe/standard). `nonce` is
/// the IV or tweak, empty for modes that take none.
#[no_mangle]
pub unsafe extern "C" fn nextssl_blockmode_encrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockmode(Policy::Safe, alg, params, key, nonce, data, out, false) }
}

/// Block-cipher mode encrypt, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_blockmode_encrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockmode(Policy::Any, alg, params, key, nonce, data, out, false) }
}

/// Decrypt with a concrete block-cipher mode (safe/standard). Bad padding is an error; do not
/// expose that distinction on a network.
#[no_mangle]
pub unsafe extern "C" fn nextssl_blockmode_decrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockmode(Policy::Safe, alg, params, key, nonce, data, out, true) }
}

/// Block-cipher mode decrypt, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_blockmode_decrypt(
    alg: *const c_char,
    params: *const c_char,
    key: *const NextsslIn,
    nonce: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::blockmode(Policy::Any, alg, params, key, nonce, data, out, true) }
}

/// Encrypt with a generic mode (`alg`) over the block cipher `cipher` (both safe/standard).
#[no_mangle]
pub unsafe extern "C" fn nextssl_mode_encrypt(
    alg: *const c_char,
    params: *const c_char,
    cipher: *const c_char,
    cipher_params: *const c_char,
    key: *const NextsslIn,
    iv: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::mode(
            Policy::Safe,
            alg,
            params,
            cipher,
            cipher_params,
            key,
            iv,
            data,
            out,
            false,
        )
    }
}

/// Generic mode over a block cipher, encrypt, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_mode_encrypt(
    alg: *const c_char,
    params: *const c_char,
    cipher: *const c_char,
    cipher_params: *const c_char,
    key: *const NextsslIn,
    iv: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::mode(
            Policy::Any,
            alg,
            params,
            cipher,
            cipher_params,
            key,
            iv,
            data,
            out,
            false,
        )
    }
}

/// Decrypt with a generic mode over a block cipher (safe/standard).
#[no_mangle]
pub unsafe extern "C" fn nextssl_mode_decrypt(
    alg: *const c_char,
    params: *const c_char,
    cipher: *const c_char,
    cipher_params: *const c_char,
    key: *const NextsslIn,
    iv: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::mode(
            Policy::Safe,
            alg,
            params,
            cipher,
            cipher_params,
            key,
            iv,
            data,
            out,
            true,
        )
    }
}

/// Generic mode over a block cipher, decrypt, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_mode_decrypt(
    alg: *const c_char,
    params: *const c_char,
    cipher: *const c_char,
    cipher_params: *const c_char,
    key: *const NextsslIn,
    iv: *const NextsslIn,
    data: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::mode(
            Policy::Any,
            alg,
            params,
            cipher,
            cipher_params,
            key,
            iv,
            data,
            out,
            true,
        )
    }
}

// ---- randomness ------------------------------------------------------------------------------------------

/// Fill `out` with exactly `want` bytes (1..=16 MiB) from the entropy source `alg`
/// (for example `os-entropy`), safe/standard tiers.
#[no_mangle]
pub unsafe extern "C" fn nextssl_rng_fill(
    alg: *const c_char,
    params: *const c_char,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::rng_fill(Policy::Safe, alg, params, want, out) }
}

/// Entropy source, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_rng_fill(
    alg: *const c_char,
    params: *const c_char,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::rng_fill(Policy::Any, alg, params, want, out) }
}

/// Instantiate a DRBG (safe/standard). Entropy and nonce are caller-supplied (take them from
/// `nextssl_rng_fill`); `*handle` receives an opaque id (0 on error). Release it with `nextssl_drbg_free`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_drbg_new(
    alg: *const c_char,
    params: *const c_char,
    entropy: *const NextsslIn,
    nonce: *const NextsslIn,
    personalization: *const NextsslIn,
    handle: *mut u64,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::drbg_new(
            Policy::Safe,
            alg,
            params,
            entropy,
            nonce,
            personalization,
            handle,
        )
    }
}

/// Instantiate a DRBG of any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_drbg_new(
    alg: *const c_char,
    params: *const c_char,
    entropy: *const NextsslIn,
    nonce: *const NextsslIn,
    personalization: *const NextsslIn,
    handle: *mut u64,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::drbg_new(
            Policy::Any,
            alg,
            params,
            entropy,
            nonce,
            personalization,
            handle,
        )
    }
}

/// Generate exactly `want` bytes (1..=16 MiB, and within the DRBG's per-request limit) from a DRBG handle.
#[no_mangle]
pub unsafe extern "C" fn nextssl_drbg_generate(
    handle: u64,
    additional: *const NextsslIn,
    want: usize,
    out: *mut NextsslOut,
) -> i32 {
    let ad = i!(additional);
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::drbg_generate(handle, ad, want)) }
}

/// Reseed a DRBG handle.
#[no_mangle]
pub unsafe extern "C" fn nextssl_drbg_reseed(
    handle: u64,
    entropy: *const NextsslIn,
    additional: *const NextsslIn,
) -> i32 {
    let (e, ad) = (i!(entropy), i!(additional));
    run_unit(|| ops::drbg_reseed(handle, e, ad))
}

/// Zeroize and release a DRBG handle. A second free is `NEXTSSL_ERR_BAD_HANDLE`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_drbg_free(handle: u64) -> i32 {
    run_unit(|| ops::drbg_free(handle))
}

// ---- KEM, key exchange, signatures -------------------------------------------------------------------------

/// KEM key pair (safe/standard) from the OS entropy source: `pk` and `sk`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_kem_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    sk: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::kem_keygen(Policy::Safe, a, p), pk, sk) }
}

/// KEM key pair, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_kem_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    sk: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::kem_keygen(Policy::Any, a, p), pk, sk) }
}

/// KEM encapsulation (safe/standard): `ct` goes to the peer, `ss` is the shared secret.
#[no_mangle]
pub unsafe extern "C" fn nextssl_kem_encaps(
    alg: *const c_char,
    params: *const c_char,
    pk: *const NextsslIn,
    ct: *mut NextsslOut,
    ss: *mut NextsslOut,
) -> i32 {
    let (a, p, k) = (n!(alg), t!(params), i!(pk));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[ct, ss], || ops::kem_encaps(Policy::Safe, a, p, k)) }
}

/// KEM encapsulation, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_kem_encaps(
    alg: *const c_char,
    params: *const c_char,
    pk: *const NextsslIn,
    ct: *mut NextsslOut,
    ss: *mut NextsslOut,
) -> i32 {
    let (a, p, k) = (n!(alg), t!(params), i!(pk));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[ct, ss], || ops::kem_encaps(Policy::Any, a, p, k)) }
}

/// KEM decapsulation (safe/standard). Wrong lengths are errors; an invalid ciphertext follows
/// the scheme (ML-KEM returns a pseudorandom secret by implicit rejection).
#[no_mangle]
pub unsafe extern "C" fn nextssl_kem_decaps(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    ct: *const NextsslIn,
    ss: *mut NextsslOut,
) -> i32 {
    let (a, p, k, c) = (n!(alg), t!(params), i!(sk), i!(ct));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[ss], || ops::kem_decaps(Policy::Safe, a, p, k, c)) }
}

/// KEM decapsulation, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_kem_decaps(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    ct: *const NextsslIn,
    ss: *mut NextsslOut,
) -> i32 {
    let (a, p, k, c) = (n!(alg), t!(params), i!(sk), i!(ct));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[ss], || ops::kem_decaps(Policy::Any, a, p, k, c)) }
}

/// Key-exchange key pair (X25519, ECDH, ...), safe/standard.
#[no_mangle]
pub unsafe extern "C" fn nextssl_kex_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    sk: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::kex_keygen(Policy::Safe, a, p), pk, sk) }
}

/// Key-exchange key pair, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_kex_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    sk: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::kex_keygen(Policy::Any, a, p), pk, sk) }
}

/// Shared secret from our private key and the peer's public key (safe/standard). The raw
/// secret is not hashed; feed it to a KDF.
#[no_mangle]
pub unsafe extern "C" fn nextssl_kex_agree(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    peer_pk: *const NextsslIn,
    ss: *mut NextsslOut,
) -> i32 {
    let (a, p, k, c) = (n!(alg), t!(params), i!(sk), i!(peer_pk));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[ss], || ops::kex_agree(Policy::Safe, a, p, k, c)) }
}

/// Key agreement, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_kex_agree(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    peer_pk: *const NextsslIn,
    ss: *mut NextsslOut,
) -> i32 {
    let (a, p, k, c) = (n!(alg), t!(params), i!(sk), i!(peer_pk));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[ss], || ops::kex_agree(Policy::Any, a, p, k, c)) }
}

/// Signature key pair (safe/standard).
#[no_mangle]
pub unsafe extern "C" fn nextssl_sign_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    sk: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::sign_keygen(Policy::Safe, a, p), pk, sk) }
}

/// Signature key pair, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_sign_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    sk: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::sign_keygen(Policy::Any, a, p), pk, sk) }
}

/// Detached signature over `msg` (safe/standard). `ctx` is the domain-separation context; a
/// non-empty one on an algorithm without contexts is an error.
#[no_mangle]
pub unsafe extern "C" fn nextssl_sign_detached(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    msg: *const NextsslIn,
    ctx: *const NextsslIn,
    sig: *mut NextsslOut,
) -> i32 {
    let (a, p, k, m, c) = (n!(alg), t!(params), i!(sk), i!(msg), i!(ctx));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[sig], || ops::sign_detached(Policy::Safe, a, p, k, m, c)) }
}

/// Detached signature, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_sign_detached(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    msg: *const NextsslIn,
    ctx: *const NextsslIn,
    sig: *mut NextsslOut,
) -> i32 {
    let (a, p, k, m, c) = (n!(alg), t!(params), i!(sk), i!(msg), i!(ctx));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[sig], || ops::sign_detached(Policy::Any, a, p, k, m, c)) }
}

/// Verify a detached signature (safe/standard). `NEXTSSL_OK` = valid; `AUTHENTICATION_FAILED`
/// = does not verify; any other code = malformed input. Treat every non-zero code as rejection.
#[no_mangle]
pub unsafe extern "C" fn nextssl_verify_detached(
    alg: *const c_char,
    params: *const c_char,
    pk: *const NextsslIn,
    msg: *const NextsslIn,
    ctx: *const NextsslIn,
    sig: *const NextsslIn,
) -> i32 {
    let (a, p, k, m, c, s) = (n!(alg), t!(params), i!(pk), i!(msg), i!(ctx), i!(sig));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[], || ops::verify_detached(Policy::Safe, a, p, k, m, c, s)) }
}

/// Verify a detached signature, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_verify_detached(
    alg: *const c_char,
    params: *const c_char,
    pk: *const NextsslIn,
    msg: *const NextsslIn,
    ctx: *const NextsslIn,
    sig: *const NextsslIn,
) -> i32 {
    let (a, p, k, m, c, s) = (n!(alg), t!(params), i!(pk), i!(msg), i!(ctx), i!(sig));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[], || ops::verify_detached(Policy::Any, a, p, k, m, c, s)) }
}

/// Proof of work solver (safe/standard): at most `max_work` attempts, then `WORK_LIMIT`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_pow_solve(
    alg: *const c_char,
    params: *const c_char,
    challenge: *const NextsslIn,
    difficulty: u32,
    max_work: u64,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::pow_solve(
            Policy::Safe,
            alg,
            params,
            challenge,
            difficulty,
            max_work,
            out,
        )
    }
}

/// Proof of work solver, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pow_solve(
    alg: *const c_char,
    params: *const c_char,
    challenge: *const NextsslIn,
    difficulty: u32,
    max_work: u64,
    out: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe {
        imp::pow_solve(
            Policy::Any,
            alg,
            params,
            challenge,
            difficulty,
            max_work,
            out,
        )
    }
}

/// Verify a proof of work (safe/standard). `AUTHENTICATION_FAILED` = solution does not meet the difficulty.
#[no_mangle]
pub unsafe extern "C" fn nextssl_pow_verify(
    alg: *const c_char,
    params: *const c_char,
    challenge: *const NextsslIn,
    solution: *const NextsslIn,
    difficulty: u32,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pow_verify(Policy::Safe, alg, params, challenge, solution, difficulty) }
}

/// Verify a proof of work, any tier.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pow_verify(
    alg: *const c_char,
    params: *const c_char,
    challenge: *const NextsslIn,
    solution: *const NextsslIn,
    difficulty: u32,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::pow_verify(Policy::Any, alg, params, challenge, solution, difficulty) }
}

// ---- root-only kinds ---------------------------------------------------------------------------------------------

/// Public-key encryption key pair (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pke_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    sk: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::pke_keygen(a, p), pk, sk) }
}

/// Public-key encryption of `pt` to `pk`, bound to `label` (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pke_encrypt(
    alg: *const c_char,
    params: *const c_char,
    pk: *const NextsslIn,
    pt: *const NextsslIn,
    label: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, k, m, l) = (n!(alg), t!(params), i!(pk), i!(pt), i!(label));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::pke_encrypt(a, p, k, m, l)) }
}

/// Public-key decryption (root only). Every failure is the same `AUTHENTICATION_FAILED`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pke_decrypt(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    ct: *const NextsslIn,
    label: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, k, c, l) = (n!(alg), t!(params), i!(sk), i!(ct), i!(label));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::pke_decrypt(a, p, k, c, l)) }
}

/// Stateful hash-based signature key pair (root only): `pk` and the serialized secret `state`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_stateful_keygen(
    alg: *const c_char,
    params: *const c_char,
    pk: *mut NextsslOut,
    state: *mut NextsslOut,
) -> i32 {
    let (a, p) = (n!(alg), t!(params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { imp::keygen2(|| ops::stateful_keygen(a, p), pk, state) }
}

/// Stateful signature (root only). Writes the signature and the advanced `new_state`. The
/// caller MUST persist `new_state` and discard the old state before releasing the signature;
/// signing again from an old state reuses a one-time key and breaks the scheme.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_stateful_sign(
    alg: *const c_char,
    params: *const c_char,
    state: *const NextsslIn,
    msg: *const NextsslIn,
    sig: *mut NextsslOut,
    new_state: *mut NextsslOut,
) -> i32 {
    let (a, p, s, m) = (n!(alg), t!(params), i!(state), i!(msg));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[sig, new_state], || ops::stateful_sign(a, p, s, m)) }
}

/// Verify a stateful signature (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_stateful_verify(
    alg: *const c_char,
    params: *const c_char,
    pk: *const NextsslIn,
    msg: *const NextsslIn,
    sig: *const NextsslIn,
) -> i32 {
    let (a, p, k, m, s) = (n!(alg), t!(params), i!(pk), i!(msg), i!(sig));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[], || ops::stateful_verify(a, p, k, m, s)) }
}

/// Signatures left in a serialized key state, and the key's lifetime total (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_stateful_remaining(
    alg: *const c_char,
    params: *const c_char,
    state: *const NextsslIn,
    remaining: *mut u64,
    max_signatures: *mut u64,
) -> i32 {
    if remaining.is_null() || max_signatures.is_null() {
        return NEXTSSL_ERR_NULL_POINTER;
    }
    let (a, p, s) = (n!(alg), t!(params), i!(state));
    run_unit(|| {
        let (r, m) = ops::stateful_remaining(a, p, s)?;
        // SAFETY: both pointers were checked non-null and are writable per the contract.
        unsafe {
            put(remaining, r);
            put(max_signatures, m);
        }
        Ok(())
    })
}

/// Zero-knowledge setup (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_zk_setup(
    alg: *const c_char,
    params: *const c_char,
    setup_params: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, s) = (n!(alg), t!(params), i!(setup_params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::zk_setup(a, p, s)) }
}

/// Zero-knowledge proof (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_zk_prove(
    alg: *const c_char,
    params: *const c_char,
    setup: *const NextsslIn,
    statement: *const NextsslIn,
    witness: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, s, st, w) = (n!(alg), t!(params), i!(setup), i!(statement), i!(witness));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::zk_prove(a, p, s, st, w)) }
}

/// Zero-knowledge verification (root only). `AUTHENTICATION_FAILED` = proof does not verify.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_zk_verify(
    alg: *const c_char,
    params: *const c_char,
    setup: *const NextsslIn,
    statement: *const NextsslIn,
    proof: *const NextsslIn,
) -> i32 {
    let (a, p, s, st, pr) = (n!(alg), t!(params), i!(setup), i!(statement), i!(proof));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[], || ops::zk_verify(a, p, s, st, pr)) }
}

/// Verifiable delay function evaluation (root only): `output` and `proof`.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_vdf_eval(
    alg: *const c_char,
    params: *const c_char,
    challenge: *const NextsslIn,
    t: u64,
    output: *mut NextsslOut,
    proof: *mut NextsslOut,
) -> i32 {
    let (a, p, c) = (n!(alg), t!(params), i!(challenge));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[output, proof], || ops::vdf_eval(a, p, c, t)) }
}

/// Verifiable delay function verification (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_vdf_verify(
    alg: *const c_char,
    params: *const c_char,
    challenge: *const NextsslIn,
    t: u64,
    output: *const NextsslIn,
    proof: *const NextsslIn,
) -> i32 {
    let (a, p, c, o, pr) = (n!(alg), t!(params), i!(challenge), i!(output), i!(proof));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[], || ops::vdf_verify(a, p, c, t, o, pr)) }
}

/// Homomorphic encryption key set (root only): secret, public and evaluation keys.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_he_keygen(
    alg: *const c_char,
    params: *const c_char,
    he_params: *const NextsslIn,
    sk: *mut NextsslOut,
    pk: *mut NextsslOut,
    evk: *mut NextsslOut,
) -> i32 {
    let (a, p, h) = (n!(alg), t!(params), i!(he_params));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[sk, pk, evk], || ops::he_keygen(a, p, h)) }
}

/// Homomorphic encryption (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_he_encrypt(
    alg: *const c_char,
    params: *const c_char,
    pk: *const NextsslIn,
    pt: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, k, m) = (n!(alg), t!(params), i!(pk), i!(pt));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::he_encrypt(a, p, k, m)) }
}

/// Homomorphic decryption (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_he_decrypt(
    alg: *const c_char,
    params: *const c_char,
    sk: *const NextsslIn,
    ct: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, k, c) = (n!(alg), t!(params), i!(sk), i!(ct));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::he_decrypt(a, p, k, c)) }
}

/// Homomorphic evaluation (root only). `op` is `add`, `sub`, `mul`, `neg`, `and`, `or`, `xor`
/// or `not`; `cts` is a packed list (`u32` little-endian length, then bytes, repeated).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_he_eval(
    alg: *const c_char,
    params: *const c_char,
    op: *const c_char,
    cts: *const NextsslIn,
    evk: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, o, c, k) = (n!(alg), t!(params), n!(op), i!(cts), i!(evk));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::he_eval(a, p, o, c, k)) }
}

/// Split a secret into `n` shares, any `t` of which reconstruct it (root only). `out` receives
/// the shares as a packed list (`u32` little-endian length, then bytes, repeated).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_threshold_split(
    alg: *const c_char,
    params: *const c_char,
    secret: *const NextsslIn,
    t: usize,
    n: usize,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, s) = (n!(alg), t!(params), i!(secret));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::threshold_split(a, p, s, t, n)) }
}

/// Reconstruct a secret from a packed list of shares (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_threshold_combine(
    alg: *const c_char,
    params: *const c_char,
    shares: *const NextsslIn,
    out: *mut NextsslOut,
) -> i32 {
    let (a, p, s) = (n!(alg), t!(params), i!(shares));
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || ops::threshold_combine(a, p, s)) }
}

/// Start a PAKE (root only). `role` 0 = initiator, 1 = responder. `*handle` receives the session
/// (0 on error); `msg` receives the first message (empty when this role waits for the peer).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pake_start(
    alg: *const c_char,
    params: *const c_char,
    role: u32,
    password: *const NextsslIn,
    context: *const NextsslIn,
    handle: *mut u64,
    msg: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    if !unsafe { put(handle, 0) } {
        return NEXTSSL_ERR_NULL_POINTER;
    }
    let (a, p, w, c) = (n!(alg), t!(params), i!(password), i!(context));
    let mut h = 0u64;
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    let rc = unsafe {
        run(&[msg], || {
            let (id, m) = ops::pake_start(a, p, role, w, c)?;
            h = id;
            Ok(vec![m])
        })
    };
    if rc != NEXTSSL_OK {
        if h != 0 {
            let _ = handles::remove(h);
        }
        return rc;
    }
    // SAFETY: `handle` was checked non-null above.
    unsafe { put(handle, h) };
    rc
}

/// One PAKE step (root only). `msg_out` is the message for the peer; `ss` is empty until
/// `*done` is 1, when it holds the shared secret and the session is closed. A step consumes the
/// session: after any error, including `BAD_OUTPUT_LEN`, the handle is invalid. Use buffers of
/// at least 64 KiB, or retry from `nextssl_root_pake_start` with the size the error reports.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pake_step(
    handle: u64,
    msg_in: *const NextsslIn,
    msg_out: *mut NextsslOut,
    ss: *mut NextsslOut,
    done: *mut u32,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    if !unsafe { put(done, 0) } {
        return NEXTSSL_ERR_NULL_POINTER;
    }
    let m = i!(msg_in);
    let mut fin = false;
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    let rc = unsafe {
        run(&[msg_out, ss], || {
            let (d, outs) = ops::pake_step(handle, m)?;
            fin = d;
            Ok(outs)
        })
    };
    if rc == NEXTSSL_ERR_BAD_OUTPUT_LEN {
        // The step already ran; its result was not delivered, so the session cannot continue.
        let _ = handles::remove(handle);
    }
    if rc == NEXTSSL_OK {
        // SAFETY: `done` was checked non-null above.
        unsafe { put(done, u32::from(fin)) };
    }
    rc
}

/// Release a PAKE or threshold session (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_pake_free(handle: u64) -> i32 {
    run_unit(|| ops::session_free(handle))
}

/// Start a threshold session for one party (root only): `op` 0 = distributed key generation,
/// 1 = signing (`input` is then the message or the party's key share, per the scheme).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_threshold_start(
    alg: *const c_char,
    params: *const c_char,
    op: u32,
    party: u16,
    t: u16,
    n: u16,
    input: *const NextsslIn,
    handle: *mut u64,
    msg: *mut NextsslOut,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    if !unsafe { put(handle, 0) } {
        return NEXTSSL_ERR_NULL_POINTER;
    }
    let (a, p, inp) = (n!(alg), t!(params), i!(input));
    let mut h = 0u64;
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    let rc = unsafe {
        run(&[msg], || {
            let (id, m) = ops::threshold_start(a, p, op, party, t, n, inp)?;
            h = id;
            Ok(vec![m])
        })
    };
    if rc != NEXTSSL_OK {
        if h != 0 {
            let _ = handles::remove(h);
        }
        return rc;
    }
    // SAFETY: `handle` was checked non-null above.
    unsafe { put(handle, h) };
    rc
}

/// One threshold step (root only); same rules as `nextssl_root_pake_step`. `output` (key share
/// or signature) is empty until `*done` is 1.
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_threshold_step(
    handle: u64,
    msg_in: *const NextsslIn,
    msg_out: *mut NextsslOut,
    output: *mut NextsslOut,
    done: *mut u32,
) -> i32 {
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    if !unsafe { put(done, 0) } {
        return NEXTSSL_ERR_NULL_POINTER;
    }
    let m = i!(msg_in);
    let mut fin = false;
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    let rc = unsafe {
        run(&[msg_out, output], || {
            let (d, outs) = ops::threshold_step(handle, m)?;
            fin = d;
            Ok(outs)
        })
    };
    if rc == NEXTSSL_ERR_BAD_OUTPUT_LEN {
        let _ = handles::remove(handle);
    }
    if rc == NEXTSSL_OK {
        // SAFETY: `done` was checked non-null above.
        unsafe { put(done, u32::from(fin)) };
    }
    rc
}

/// Release a threshold session (root only).
#[no_mangle]
pub unsafe extern "C" fn nextssl_root_threshold_free(handle: u64) -> i32 {
    run_unit(|| ops::session_free(handle))
}

// ---- discovery and helpers -----------------------------------------------------------------------------------------

/// All algorithms as JSON: `{"abi_version":N,"algorithms":[{...}]}`. Each entry has `id`, `kind`,
/// `category`, `family`, `aliases`, `tier`, `status`, `standards`, `license`, `copyleft`,
/// `c_backed`, `safe_api`, `root_only_kind`, `cose_alg`, `oid`, `sizes`, `params` and `ops`.
/// `kind` is null or empty for all kinds, or one kind name (`hash`, `aead`, `kem`, ...).
#[no_mangle]
pub unsafe extern "C" fn nextssl_algorithms_json(kind: *const c_char, out: *mut NextsslOut) -> i32 {
    let k = t!(kind);
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || Ok(vec![json::list(k)?.into_bytes().into()])) }
}

/// One algorithm (by id or alias) as a JSON object (same fields as `nextssl_algorithms_json`).
#[no_mangle]
pub unsafe extern "C" fn nextssl_algorithm_info_json(
    alg: *const c_char,
    out: *mut NextsslOut,
) -> i32 {
    let a = n!(alg);
    // SAFETY: forwarded under the pointer contract documented on this function and in the file header.
    unsafe { run(&[out], || Ok(vec![json::info(a)?.into_bytes().into()])) }
}

/// Static, NUL-terminated English message for an error code (never null).
#[no_mangle]
pub extern "C" fn nextssl_error_message(code: i32) -> *const c_char {
    crate::error_message(code).as_ptr().cast()
}

/// Version of this C ABI (bumped on any incompatible change).
#[no_mangle]
pub extern "C" fn nextssl_abi_version() -> u32 {
    crate::NEXTSSL_ABI_VERSION
}

/// Allocate `size` zeroed bytes in the library's memory (for WebAssembly hosts). Returns null
/// for 0, for more than 256 MiB, or on failure. Release with `nextssl_buf_free` and the same size.
#[no_mangle]
pub extern "C" fn nextssl_buf_alloc(size: usize) -> *mut u8 {
    buf_alloc(size)
}

/// Wipe and release a buffer from `nextssl_buf_alloc`. `ptr` may be null.
#[no_mangle]
pub unsafe extern "C" fn nextssl_buf_free(ptr: *mut u8, size: usize) {
    // SAFETY: forwarded under the contract of this function.
    unsafe { buf_free(ptr, size) }
}

// Handle-range errors share the constant so a binding can tell a stale handle from bad input.
const _: () = assert!(NEXTSSL_ERR_BAD_HANDLE == 102);
