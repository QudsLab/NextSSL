//! Adapter: sphlib LUFFA (C, verbatim) -> nextssl `Hash`. Parameter `out_len` selects the
//! variant (allowed: 28 | 32 | 48 | 64 bytes, default 32); any other value is `ParamOutOfRange`.
//! All lengths are checked here before the C call; the C side is a one-shot digest (shim.c).

use core::ffi::{c_int, c_void};
use nextssl_core::{Error, Hash, Params, Result};

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__luffa__digest"]
        fn digest(out_len: u32, data: *const c_void, len: usize, out: *mut c_void) -> c_int;
    }

    /// Precondition (checked by callers in this crate): `out.len()` is one of the supported lengths.
    #[allow(unsafe_code)]
    pub(super) fn digest_oneshot(out: &mut [u8], data: &[u8]) -> bool {
        // SAFETY: `data` and `out` are valid slices for the lengths passed; the callee reads
        // exactly `data.len()` bytes and writes exactly `out.len()` bytes (the digest size it
        // selects from `out_len`, which the caller guarantees equals `out.len()`). Zero-length
        // slices give non-null aligned pointers, which the callee accepts when the length is 0.
        let rc = unsafe {
            digest(
                out.len() as u32,
                data.as_ptr().cast(),
                data.len(),
                out.as_mut_ptr().cast(),
            )
        };
        rc == 0
    }
}

const ALLOWED: [u64; 4] = [28, 32, 48, 64];

struct Impl {
    out_len: usize,
}

impl Hash for Impl {
    fn output_len(&self) -> usize {
        self.out_len
    }

    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != self.out_len {
            return Err(Error::BadOutputLen {
                expected: self.out_len,
                got: out.len(),
            });
        }
        if ffi::digest_oneshot(out, data) {
            Ok(())
        } else {
            Err(Error::Backend("luffa failed"))
        }
    }
}

/// Registry constructor. Optional parameter `out_len` (default 32).
pub fn new(params: &Params) -> Result<Box<dyn Hash>> {
    let n = params.get_u64("out_len").unwrap_or(32);
    if !ALLOWED.contains(&n) {
        return Err(Error::ParamOutOfRange("out_len"));
    }
    Ok(Box::new(Impl {
        out_len: n as usize,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;

    #[test]
    fn unsupported_out_len_is_refused() {
        for bad in [0u64, 1, 19, 27, 29, 33, 63, 65, 1000] {
            if ALLOWED.contains(&bad) {
                continue;
            }
            let p = Params::new().with("out_len", Value::U64(bad));
            assert!(matches!(new(&p), Err(Error::ParamOutOfRange(_))), "{bad}");
        }
    }

    #[test]
    fn wrong_output_length_is_refused() {
        let h = new(&Params::new()).unwrap();
        let mut short = vec![0u8; h.output_len() - 1];
        assert!(matches!(
            h.digest(b"abc", &mut short),
            Err(Error::BadOutputLen { .. })
        ));
        let mut long = vec![0u8; h.output_len() + 1];
        assert!(matches!(
            h.digest(b"abc", &mut long),
            Err(Error::BadOutputLen { .. })
        ));
    }
}
