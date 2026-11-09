//! Adapter: tiny-keccak `ParallelHash::v128` (NIST SP 800-185). Parameters: `block_size` B in
//! bytes (default 8192; SP 800-185 fixes no default, 0 is refused), `out_len` L in bytes
//! (default 32; the digest must be requested with exactly this length because L is
//! encoded into the hash), `custom` customization string S (default empty).

use nextssl_core::{Error, Hash, Params, Result};
use tiny_keccak::{Hasher, ParallelHash};

const MAX_OUT: usize = 1024;
const MAX_CUSTOM: usize = 65536;
const MAX_BLOCK: u64 = u32::MAX as u64;

struct Impl {
    block_size: usize,
    out_len: usize,
    custom: Vec<u8>,
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
        let mut h = ParallelHash::v128(&self.custom, self.block_size);
        h.update(data);
        h.finalize(out);
        Ok(())
    }
}

/// Registry constructor; validates every parameter.
pub fn new(params: &Params) -> Result<Box<dyn Hash>> {
    let block_size = params.get_u64("block_size").unwrap_or(8192);
    if block_size == 0 || block_size > MAX_BLOCK {
        return Err(Error::ParamOutOfRange("block_size"));
    }
    let out_len = params.get_u64("out_len").unwrap_or(32);
    if out_len == 0 || out_len > MAX_OUT as u64 {
        return Err(Error::ParamOutOfRange("out_len"));
    }
    let custom = params.get_bytes("custom").unwrap_or(&[]);
    nextssl_core::check_len("custom", custom.len(), 0, MAX_CUSTOM)?;
    Ok(Box::new(Impl {
        block_size: block_size as usize,
        out_len: out_len as usize,
        custom: custom.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;

    #[test]
    fn bad_params_are_refused() {
        for (k, v) in [
            ("block_size", 0u64),
            ("block_size", 1 << 33),
            ("out_len", 0),
            ("out_len", 1025),
        ] {
            let p = Params::new().with(k, Value::U64(v));
            assert!(matches!(new(&p), Err(Error::ParamOutOfRange(_))), "{k}={v}");
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
