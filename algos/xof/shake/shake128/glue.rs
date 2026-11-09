//! Adapter: RustCrypto `sha3` (SHAKE128, FIPS 202) -> nextssl `Xof`.
//! Fills the whole of `out` (non-empty). No parameters, no customization string (that is cSHAKE).

use nextssl_core::{Len, Params, Result, Xof};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

struct Shake128Xof;

impl Xof for Shake128Xof {
    fn squeeze(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, usize::MAX).check("out", out.len())?;
        let mut hasher = Shake128::default();
        hasher.update(data);
        hasher.finalize_xof().read(out);
        Ok(())
    }
}

/// Registry constructor. SHAKE128 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Xof>> {
    Ok(Box::new(Shake128Xof))
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
        let doc = load("shake128.json");
        assert_eq!(doc["algorithm"], "shake128");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let msg = unhex(v["msg_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let x = new(&Params::new()).unwrap();
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
        assert!(n >= 20);
    }

    #[test]
    fn empty_output_is_refused() {
        let x = new(&Params::new()).unwrap();
        assert!(matches!(
            x.squeeze(b"abc", &mut []),
            Err(Error::InvalidLength { .. })
        ));
    }
}
