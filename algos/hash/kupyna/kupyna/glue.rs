//! Adapter: RustCrypto `kupyna` (DSTU 7564:2014) -> nextssl `Hash`. Parameter `out_len` selects the variant
//! (allowed: 28 | 32 | 48 | 64 bytes, default 32); any other value is `ParamOutOfRange`.

use kupyna::{Digest, Kupyna224, Kupyna256, Kupyna384, Kupyna512};
use nextssl_core::{Error, Hash, Params, Result};

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
        match self.out_len {
            28 => out.copy_from_slice(Kupyna224::digest(data).as_slice()),
            32 => out.copy_from_slice(Kupyna256::digest(data).as_slice()),
            48 => out.copy_from_slice(Kupyna384::digest(data).as_slice()),
            64 => out.copy_from_slice(Kupyna512::digest(data).as_slice()),
            _ => return Err(Error::Backend("unreachable out_len")),
        }
        Ok(())
    }
}

/// Registry constructor. Optional parameter `out_len` (default 32).
pub fn new(params: &Params) -> Result<Box<dyn Hash>> {
    let n = params.get_u64("out_len").unwrap_or(32);
    let out_len = match n {
        28 | 32 | 48 | 64 => n as usize,
        _ => return Err(Error::ParamOutOfRange("out_len")),
    };
    Ok(Box::new(Impl { out_len }))
}
