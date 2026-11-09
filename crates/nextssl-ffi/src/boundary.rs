//! The pointer boundary of the generic ABI. Every `unsafe` block that decodes caller memory for
//! the new functions is in this file, each with a `// SAFETY:` note. The exported functions in
//! `exports.rs` call these helpers and then run safe code from `ops.rs`.
//!
//! Conventions:
//! - Inputs are `nextssl_in { ptr, len }` passed by pointer. `len == 0` accepts a null `ptr`.
//! - Outputs are `nextssl_out { ptr, cap, len }` passed by pointer. On return `len` is the number
//!   of bytes written, or the required size when the result is `NEXTSSL_ERR_BAD_OUTPUT_LEN`
//!   (nothing is written then), or 0 for any other error.
//! - A call with several outputs is all or nothing: if any buffer is too small, none is written
//!   and every `len` reports its required size.

#![allow(unsafe_code)]

use crate::ops::{Fail, Outs};
use crate::{
    NEXTSSL_ERR_BACKEND, NEXTSSL_ERR_BAD_OUTPUT_LEN, NEXTSSL_ERR_INVALID_INPUT,
    NEXTSSL_ERR_INVALID_LENGTH, NEXTSSL_ERR_NULL_POINTER, NEXTSSL_ERR_PANIC, NEXTSSL_OK,
};
use core::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Read-only byte input.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NextsslIn {
    pub ptr: *const u8,
    pub len: usize,
}

/// Writable byte output with in/out length.
#[repr(C)]
pub struct NextsslOut {
    pub ptr: *mut u8,
    pub cap: usize,
    pub len: usize,
}

/// Unwraps `Ok` or returns the error code from the enclosing function.
macro_rules! tr {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(c) => return c,
        }
    };
}
pub(crate) use tr;

/// # Safety
/// `p` must be null or point to a readable, aligned `NextsslIn` whose `ptr` (when `len > 0`)
/// references `len` readable bytes that are not mutated during the call.
pub unsafe fn input<'a>(p: *const NextsslIn) -> Result<&'a [u8], i32> {
    if p.is_null() {
        return Err(NEXTSSL_ERR_NULL_POINTER);
    }
    // SAFETY: `p` is non-null and, per the contract, points to a readable aligned struct.
    let s = unsafe { *p };
    if s.len == 0 {
        return Ok(&[]);
    }
    if s.ptr.is_null() {
        return Err(NEXTSSL_ERR_NULL_POINTER);
    }
    if s.len > isize::MAX as usize {
        return Err(NEXTSSL_ERR_INVALID_LENGTH);
    }
    // SAFETY: `s.ptr` is non-null, `s.len <= isize::MAX`, and the caller guarantees `s.len`
    // readable bytes that stay unmodified for the call.
    Ok(unsafe { core::slice::from_raw_parts(s.ptr, s.len) })
}

/// # Safety
/// `p` must be null or a valid NUL-terminated string that outlives the call.
pub unsafe fn name<'a>(p: *const c_char) -> Result<&'a str, i32> {
    if p.is_null() {
        return Err(NEXTSSL_ERR_NULL_POINTER);
    }
    // SAFETY: non-null and NUL-terminated per the contract.
    let c = unsafe { CStr::from_ptr(p) };
    c.to_str().map_err(|_| NEXTSSL_ERR_INVALID_INPUT)
}

/// Like [`name`] but a null pointer means "none".
///
/// # Safety
/// Same as [`name`].
pub unsafe fn opt_text<'a>(p: *const c_char) -> Result<Option<&'a str>, i32> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: forwarded under the same contract.
    unsafe { name(p) }.map(Some)
}

/// Writes a scalar through an out pointer. Returns false when `p` is null.
///
/// # Safety
/// `p` must be null or valid and aligned for one write of `T`.
pub unsafe fn put<T>(p: *mut T, v: T) -> bool {
    if p.is_null() {
        return false;
    }
    // SAFETY: non-null, and valid and aligned per the contract.
    unsafe { p.write(v) };
    true
}

/// Checks that an out pointer is usable and returns it.
///
/// # Safety
/// `o` must be null or point to a readable `NextsslOut`.
unsafe fn check_out(o: *mut NextsslOut) -> Result<(), i32> {
    if o.is_null() {
        return Err(NEXTSSL_ERR_NULL_POINTER);
    }
    // SAFETY: non-null, readable per the contract.
    let (ptr, cap) = unsafe { ((*o).ptr, (*o).cap) };
    if ptr.is_null() && cap != 0 {
        return Err(NEXTSSL_ERR_NULL_POINTER);
    }
    if cap > isize::MAX as usize {
        return Err(NEXTSSL_ERR_INVALID_LENGTH);
    }
    Ok(())
}

/// # Safety
/// Every pointer in `outs` was accepted by [`check_out`].
unsafe fn set_lens(outs: &[*mut NextsslOut], lens: impl Fn(usize) -> usize) {
    for (i, &o) in outs.iter().enumerate() {
        // SAFETY: validated non-null and writable by `check_out`.
        unsafe { (*o).len = lens(i) };
    }
}

/// Runs `f` (a panic becomes `NEXTSSL_ERR_PANIC`), then copies its buffers into `outs`.
/// Secret buffers are wiped when `f`'s result drops, on success, error and panic alike.
///
/// # Safety
/// Each `outs[i]` must be null or point to a `NextsslOut` whose `ptr` references `cap` writable
/// bytes, not overlapping each other or any input.
pub unsafe fn run(outs: &[*mut NextsslOut], f: impl FnOnce() -> Result<Outs, Fail>) -> i32 {
    for &o in outs {
        // SAFETY: forwarded under the contract above.
        tr!(unsafe { check_out(o) });
    }
    let res = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => {
            // SAFETY: every out was validated above.
            unsafe { set_lens(outs, |_| 0) };
            return NEXTSSL_ERR_PANIC;
        }
    };
    let bufs = match res {
        Ok(b) if b.len() == outs.len() => b,
        Ok(_) => {
            // SAFETY: every out was validated above.
            unsafe { set_lens(outs, |_| 0) };
            return NEXTSSL_ERR_BACKEND;
        }
        Err(e) => {
            // SAFETY: every out was validated above.
            unsafe { set_lens(outs, |_| 0) };
            return e.code();
        }
    };
    // SAFETY: every out was validated above.
    unsafe { set_lens(outs, |i| bufs[i].len()) };
    let fits = outs.iter().zip(&bufs).all(|(&o, b)| {
        // SAFETY: validated and readable.
        b.len() <= unsafe { (*o).cap }
    });
    if !fits {
        return NEXTSSL_ERR_BAD_OUTPUT_LEN;
    }
    for (&o, b) in outs.iter().zip(&bufs) {
        if !b.is_empty() {
            // SAFETY: `ptr` is non-null here (cap >= b.len() > 0 and check_out rejected null with
            // cap != 0), has `cap >= b.len()` writable bytes, and `b` is a distinct Rust
            // allocation, so the regions cannot overlap.
            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), (*o).ptr, b.len()) };
        }
    }
    NEXTSSL_OK
}

/// Runs `f` for calls whose result is a status only (no buffers).
pub fn run_unit(f: impl FnOnce() -> Result<(), Fail>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => NEXTSSL_OK,
        Ok(Err(e)) => e.code(),
        Err(_) => NEXTSSL_ERR_PANIC,
    }
}

/// Allocates `size` zeroed bytes for the caller (used by WebAssembly hosts, which have no other
/// way to put bytes in linear memory). Returns null for size 0, for sizes above 256 MiB and when
/// allocation fails. Free with [`buf_free`] using the same size.
pub fn buf_alloc(size: usize) -> *mut u8 {
    if size == 0 || size > nextssl_core::MAX_INPUT_LEN {
        return core::ptr::null_mut();
    }
    let mut v: Vec<u8> = Vec::new();
    if v.try_reserve_exact(size).is_err() {
        return core::ptr::null_mut();
    }
    v.resize(size, 0);
    Box::into_raw(v.into_boxed_slice()).cast::<u8>()
}

/// # Safety
/// `ptr` must be null or come from [`buf_alloc`] called with exactly `size`, and not be freed
/// twice. The bytes are wiped before release.
pub unsafe fn buf_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    // SAFETY: per the contract `ptr`/`size` describe a live `Box<[u8]>` made by `buf_alloc`.
    let mut b = unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, size)) };
    nextssl_core::Zeroize::zeroize(&mut *b);
}
