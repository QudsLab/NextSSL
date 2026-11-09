//! Adapter: SHA-0 (withdrawn FIPS 180, 1993), sphlib implementation (C, verbatim) -> nextssl `Hash` (20-byte output, no parameters).
//! All lengths are checked here before the C call; the C side is a one-shot digest (shim.c).

use core::ffi::{c_int, c_void};
use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 20;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__sha0__digest"]
        fn digest(data: *const c_void, len: usize, out: *mut c_void) -> c_int;
    }

    /// Precondition (checked by callers in this crate): `out.len() == OUT_LEN`.
    #[allow(unsafe_code)]
    pub(super) fn digest_oneshot(out: &mut [u8], data: &[u8]) -> bool {
        // SAFETY: `data` and `out` are valid slices for the lengths passed; the callee reads
        // exactly `data.len()` bytes and writes exactly OUT_LEN (= out.len()) bytes. Zero-length
        // slices give non-null aligned pointers, which the callee accepts when the length is 0.
        let rc = unsafe { digest(data.as_ptr().cast(), data.len(), out.as_mut_ptr().cast()) };
        rc == 0
    }
}

struct Impl;

impl Hash for Impl {
    fn output_len(&self) -> usize {
        OUT_LEN
    }

    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != OUT_LEN {
            return Err(Error::BadOutputLen {
                expected: OUT_LEN,
                got: out.len(),
            });
        }
        if ffi::digest_oneshot(out, data) {
            Ok(())
        } else {
            Err(Error::Backend("sha0 failed"))
        }
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_output_length_is_refused() {
        let h = new(&Params::new()).unwrap();
        for bad in [0usize, OUT_LEN - 1, OUT_LEN + 1] {
            let mut out = vec![0u8; bad];
            assert!(matches!(
                h.digest(b"abc", &mut out),
                Err(Error::BadOutputLen { .. })
            ));
        }
    }
}
