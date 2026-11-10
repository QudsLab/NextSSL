//! Adapter: bash384 (SUPERCOP crypto_hash) (ref) (verbatim C, symbols renamed `nextssl__bash384__*`) -> nextssl `Hash`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled).

use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 48;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulonglong};
    extern "C" {
        #[link_name = "nextssl__bash384__crypto_hash"]
        pub fn hash(out: *mut u8, input: *const u8, len: c_ulonglong) -> c_int;
    }
}

struct H;

impl Hash for H {
    fn output_len(&self) -> usize {
        OUT_LEN
    }

    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != OUT_LEN {
            return Err(Error::InvalidLength {
                what: "out",
                got: out.len(),
                min: OUT_LEN,
                max: OUT_LEN,
            });
        }
        // SAFETY: out is valid for OUT_LEN bytes (checked above); data for data.len() bytes.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::hash(
                out.as_mut_ptr(),
                data.as_ptr(),
                data.len() as core::ffi::c_ulonglong,
            )
        };
        if rc != 0 {
            return Err(Error::Backend("hash failed"));
        }
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Hash>> {
    Ok(Box::new(H))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_length_checked() {
        let h = new(&Params::new()).unwrap();
        let mut a = vec![0u8; OUT_LEN];
        let mut b = vec![0u8; OUT_LEN];
        h.digest(b"abc", &mut a).unwrap();
        h.digest(b"abc", &mut b).unwrap();
        assert_eq!(a, b);
        let mut c = vec![0u8; OUT_LEN];
        h.digest(b"abd", &mut c).unwrap();
        assert_ne!(a, c);
        assert!(h.digest(b"abc", &mut [0u8; OUT_LEN + 1]).is_err());
    }
}
