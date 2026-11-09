//! Adapter: BLAKE2b reference C implementation -> nextssl `Hash` (64-byte output,
//! optional 0..=64 byte key). All lengths are checked here before the C call.

use core::ffi::{c_int, c_void};
use nextssl_core::{Error, Hash, Params, Result, Zeroizing};

const OUT_LEN: usize = 64;
const KEY_MAX: usize = 64;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__blake2b_512__blake2b"]
        fn blake2b(
            out: *mut c_void,
            outlen: usize,
            input: *const c_void,
            inlen: usize,
            key: *const c_void,
            keylen: usize,
        ) -> c_int;
    }

    /// Precondition (checked by callers in this crate): `out.len() == 64`, `key.len() <= 64`.
    #[allow(unsafe_code)]
    pub(super) fn blake2b_oneshot(out: &mut [u8], data: &[u8], key: &[u8]) -> bool {
        // SAFETY: `out`, `data` and `key` are valid slices for the lengths passed (Rust slices
        // are never dangling-with-nonzero-length); the callee only writes `outlen` (= out.len(),
        // 64) bytes to `out` and reads `inlen`/`keylen` bytes from the others. Zero-length
        // slices yield non-null aligned pointers, which upstream accepts when length is 0.
        let rc = unsafe {
            blake2b(
                out.as_mut_ptr().cast(),
                out.len(),
                data.as_ptr().cast(),
                data.len(),
                key.as_ptr().cast(),
                key.len(),
            )
        };
        rc == 0
    }
}

struct Blake2b512 {
    key: Zeroizing<Vec<u8>>,
}

impl Hash for Blake2b512 {
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
        nextssl_core::check_len("key", self.key.len(), 0, KEY_MAX)?;
        if ffi::blake2b_oneshot(out, data, &self.key) {
            Ok(())
        } else {
            Err(Error::Backend("blake2b failed"))
        }
    }
}

/// Registry constructor. Optional parameter `key` (0..=64 bytes) selects keyed mode.
pub fn new(params: &Params) -> Result<Box<dyn Hash>> {
    let key = params.get_bytes("key").unwrap_or(&[]);
    nextssl_core::check_len("key", key.len(), 0, KEY_MAX)?;
    Ok(Box::new(Blake2b512 {
        key: Zeroizing::new(key.to_vec()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;

    #[test]
    fn rejects_bad_lengths() {
        let h = new(&Params::new()).unwrap();
        let mut short = [0u8; 63];
        assert!(matches!(
            h.digest(b"", &mut short),
            Err(Error::BadOutputLen { .. })
        ));
        let p = Params::new().with("key", Value::Bytes(vec![0; 65]));
        assert!(matches!(new(&p), Err(Error::InvalidLength { .. })));
    }
}
