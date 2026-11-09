//! Adapter: `fletcher` crate (Fletcher-16, modulus 255) -> nextssl `Checksum`.
//!
//! NON-CRYPTOGRAPHIC integrity check; reachable through the root API only. Output: 2 bytes,
//! big-endian (`sum2 << 8 | sum1`). Note that Fletcher-16 cannot tell 0x00 from 0xFF.

use nextssl_core::{Checksum, Len, Params, Result, Sizes};

const OUT: usize = 2;

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
        out.copy_from_slice(&fletcher::calc_fletcher16(data).to_be_bytes());
        Ok(())
    }
}

/// Registry constructor. Fletcher-16 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Checksum>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
#[allow(clippy::single_element_loop)]
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
    fn sizes_match_metadata() {
        assert_eq!(
            new(&Params::new()).unwrap().sizes().out,
            Some(Len::fixed(2))
        );
    }

    #[test]
    fn known_answers() {
        let c = new(&Params::new()).unwrap();
        let doc = load("vectors.json");
        assert_eq!(doc["algorithm"], "fletcher16");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let mut got = vec![0u8; want.len()];
            c.checksum(&data, &mut got).unwrap();
            assert_eq!(got, want, "{}", v["id"]);
            n += 1;
        }
        assert!(n >= 4);
    }

    #[test]
    fn rejects_bad_output_length() {
        let c = new(&Params::new()).unwrap();
        for bad in [0usize, 1, 3, 64] {
            let mut out = vec![0xAAu8; bad];
            assert!(matches!(
                c.checksum(b"x", &mut out),
                Err(Error::InvalidLength { .. })
            ));
            assert!(out.iter().all(|&b| b == 0xAA));
        }
    }
}
