//! Adapter: jh JH -> nextssl `Hash`. Parameter `out_len` selects the variant
//! (allowed: 28 | 32 | 48 | 64 bytes, default 32); any other value is `ParamOutOfRange`.

use jh::{Digest, Jh224, Jh256, Jh384, Jh512};
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
            28 => out.copy_from_slice(Jh224::digest(data).as_slice()),
            32 => out.copy_from_slice(Jh256::digest(data).as_slice()),
            48 => out.copy_from_slice(Jh384::digest(data).as_slice()),
            64 => out.copy_from_slice(Jh512::digest(data).as_slice()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;

    #[test]
    fn unsupported_out_len_is_refused() {
        for bad in [0u64, 1, 27, 29, 33, 63, 65, 1000] {
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
    }
}
