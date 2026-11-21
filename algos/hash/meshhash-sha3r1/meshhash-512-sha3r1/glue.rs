//! Adapter: meshhash 512 (NIST SHA-3 round 1) (NIST SHA-3 round-1 submission, verbatim C, symbols renamed `nextssl__meshhash_512_sha3r1__*`) -> nextssl `Hash`.
//! Generated wiring, no crypto logic. Calls the upstream one-shot `Hash(hashbitlen, data, databitlen, hashval)` through shim.c.

use nextssl_core::{Error, Hash, Params, Result};

const OUT_LEN: usize = 64;
const HASH_BITS: core::ffi::c_int = 512;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulonglong};
    extern "C" {
        #[link_name = "nextssl__meshhash_512_sha3r1__ns_hash"]
        pub fn hash(bits: c_int, input: *const u8, len_bits: c_ulonglong, out: *mut u8) -> c_int;
        #[link_name = "nextssl__meshhash_512_sha3r1__ns_max_bits"]
        pub fn max_bits() -> c_ulonglong;
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
        // The NIST API takes the length in bits; refuse inputs whose bit length overflows u64 or the upstream DataLength.
        // SAFETY: max_bits() takes no arguments and only reads a constant.
        #[allow(unsafe_code)]
        let max_bits = unsafe { ffi::max_bits() };
        let len_bits = (data.len() as u64)
            .checked_mul(8)
            .filter(|b| *b <= max_bits)
            .ok_or(Error::InvalidInput(
                "message too long: bit length does not fit the upstream DataLength type",
            ))?;
        // SAFETY: out is valid for OUT_LEN bytes, the digest size selected by HASH_BITS (checked above); data is valid
        // for data.len() bytes and the bit length passed is exactly 8 * data.len().
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::hash(HASH_BITS, data.as_ptr(), len_bits, out.as_mut_ptr()) };
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
        assert!(h.digest(b"abc", &mut [0u8; OUT_LEN - 1]).is_err());
    }
}
