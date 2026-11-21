//! Adapter: BASH-224 (STB 34.101.77, libecc hash/bash224.c, verbatim C, symbols renamed `nextssl__bash224__*`) -> nextssl `Hash`.
//! Glue only, no crypto logic. Output 28 bytes; input longer than 2^32-1 bytes is an error (upstream length is u32).

use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 28;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::c_int;
    extern "C" {
        #[link_name = "nextssl__bash224__shim_hash"]
        pub fn hash(out: *mut u8, input: *const u8, len: core::ffi::c_ulong) -> c_int;
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
        if data.len() as u64 > u32::MAX as u64 {
            return Err(Error::InvalidInput("input longer than 2^32-1 bytes"));
        }
        // SAFETY: out is valid for OUT_LEN bytes (checked above); data for data.len() bytes.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::hash(
                out.as_mut_ptr(),
                data.as_ptr(),
                data.len() as core::ffi::c_ulong,
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
