//! Adapter: RustCrypto `cshake` (cSHAKE128, NIST SP 800-185) -> nextssl `Xof`.
//! Parameter `custom` is the customization string S (default empty). The function-name string N is
//! always empty here (N is reserved for NIST-defined derived functions). With empty N and S,
//! cSHAKE is SHAKE by definition; use the shake128 id for that.

use cshake::digest::{ExtendableOutput, Update, XofReader};
use cshake::CShake128;
use nextssl_core::{Len, Params, Result, Xof};

const MAX_CUSTOM: usize = 65536;

struct Impl {
    custom: Vec<u8>,
}

impl Xof for Impl {
    fn squeeze(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, usize::MAX).check("out", out.len())?;
        let mut hasher = CShake128::new_with_function_name(b"", &self.custom);
        hasher.update(data);
        hasher.finalize_xof().read(out);
        Ok(())
    }
}

/// Registry constructor. Optional parameter `custom` (0..=65536 bytes).
pub fn new(params: &Params) -> Result<Box<dyn Xof>> {
    let custom = params.get_bytes("custom").unwrap_or(&[]);
    nextssl_core::check_len("custom", custom.len(), 0, MAX_CUSTOM)?;
    Ok(Box::new(Impl {
        custom: custom.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Error;
    use serde_json::Value as J;
    use std::path::PathBuf;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn load(name: &str) -> J {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("kat")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    #[test]
    fn kats() {
        let doc = load("cshake128.json");
        assert_eq!(doc["algorithm"], "cshake128");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let msg = unhex(v["msg_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let custom = unhex(v["custom_hex"].as_str().unwrap());
            let x = new(&Params::new().with("custom", nextssl_core::Value::Bytes(custom))).unwrap();
            let mut got = vec![0u8; want.len()];
            x.squeeze(&msg, &mut got).unwrap();
            assert_eq!(got, want, "{id}");
            // Prefix property: a shorter request is a prefix of a longer one.
            if want.len() > 1 {
                let mut shorter = vec![0u8; want.len() - 1];
                x.squeeze(&msg, &mut shorter).unwrap();
                assert_eq!(shorter, want[..want.len() - 1], "{id} prefix");
            }
            n += 1;
        }
        assert!(n >= 18);
    }

    #[test]
    fn empty_output_is_refused() {
        let x = new(&Params::new()).unwrap();
        assert!(matches!(
            x.squeeze(b"abc", &mut []),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn oversized_custom_is_refused() {
        let p = Params::new().with("custom", nextssl_core::Value::Bytes(vec![0u8; 65537]));
        assert!(matches!(new(&p), Err(Error::InvalidLength { .. })));
    }
}
