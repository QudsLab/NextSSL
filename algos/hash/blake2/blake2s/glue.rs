//! Adapter: RustCrypto `blake2` BLAKE2s (RFC 7693), unkeyed. Parameter `out_len` is one of
//! 16, 24, 28, 32 bytes (default 32); other values are `ParamOutOfRange`. Keyed mode is not
//! exposed here (it belongs to a MAC id).

use blake2::digest::consts::{U16, U24, U28, U32};
use blake2::{Blake2s, Digest};
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
            16 => out.copy_from_slice(Blake2s::<U16>::digest(data).as_slice()),
            24 => out.copy_from_slice(Blake2s::<U24>::digest(data).as_slice()),
            28 => out.copy_from_slice(Blake2s::<U28>::digest(data).as_slice()),
            32 => out.copy_from_slice(Blake2s::<U32>::digest(data).as_slice()),
            _ => return Err(Error::Backend("unreachable out_len")),
        }
        Ok(())
    }
}

/// Registry constructor. Optional parameter `out_len` (default 32).
pub fn new(params: &Params) -> Result<Box<dyn Hash>> {
    let n = params.get_u64("out_len").unwrap_or(32);
    let out_len = match n {
        16 | 24 | 28 | 32 => n as usize,
        _ => return Err(Error::ParamOutOfRange("out_len")),
    };
    Ok(Box::new(Impl { out_len }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;

    #[test]
    fn unsupported_out_len_is_refused() {
        for bad in [0u64, 1, 15, 17, 31, 33, 64] {
            let p = Params::new().with("out_len", Value::U64(bad));
            assert!(matches!(new(&p), Err(Error::ParamOutOfRange(_))), "{bad}");
        }
    }

    #[test]
    fn wrong_output_length_is_refused() {
        let h = new(&Params::new()).unwrap();
        let mut short = vec![0u8; 31];
        assert!(matches!(
            h.digest(b"abc", &mut short),
            Err(Error::BadOutputLen { .. })
        ));
    }
}
