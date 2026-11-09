//! Adapter: SpookyHash V2 128-bit (jibsen/spooky C conversion of Bob Jenkins' SpookyHash) (verbatim C, symbols renamed `nextssl__spookyhash__*`) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC; reachable through the root API only. Seeds fixed to 0. Output: 16 bytes, h1 then h2, each big-endian.
//! Generated wiring, no crypto logic.

use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const OUT: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use super::OUT;
    extern "C" {
        #[link_name = "nextssl__spookyhash__shim_hash"]
        fn hash(data: *const u8, len: usize, out: *mut u8);
    }

    pub(super) fn run(data: &[u8]) -> [u8; OUT] {
        let mut o = [0u8; OUT];
        // SAFETY: `data` is a valid slice of `len` bytes (read only); `o` is a writable buffer of exactly OUT
        // bytes, which is all the shim writes; no pointer is kept.
        unsafe { hash(data.as_ptr(), data.len(), o.as_mut_ptr()) };
        o
    }
}

struct Impl;

impl Checksum for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: Some(Len::fixed(OUT)),
            ..Sizes::NONE
        }
    }

    fn checksum(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::fixed(OUT).check("out", out.len())?;
        out.copy_from_slice(&ffi::run(data));
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Checksum>> {
    Ok(Box::new(Impl))
}
