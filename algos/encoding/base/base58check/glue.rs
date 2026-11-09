//! Adapter: `bs58` with the `check` feature (Base58Check: payload || first 4 bytes of
//! SHA-256(SHA-256(payload)), Bitcoin alphabet) -> nextssl `Encoding`.
//!
//! `data` is the full payload INCLUDING any version byte (nothing is added or stripped).
//! Decode verifies the 4-byte checksum and returns the payload. Limits as for base58.
//! The checksum hash comes from the `sha2` 0.10 copy pulled in by `bs58`'s `check` feature.

use nextssl_core::{Encoding, Error, Params, Result};

const MAX_DATA: usize = 4096;
const MAX_TEXT: usize = 8192;

struct Impl;

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, MAX_DATA)?;
        Ok(bs58::encode(data).with_check().into_string().into_bytes())
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, MAX_TEXT)?;
        bs58::decode(text)
            .with_check(None)
            .into_vec()
            .map_err(|_| Error::InvalidInput("invalid base58check"))
    }
}

/// Registry constructor. Base58Check takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Encoding>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
#[allow(clippy::single_element_loop)]
mod tests {
    use super::*;
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
    fn known_answers() {
        let e = new(&Params::new()).unwrap();
        let doc = load("vectors.json");
        assert_eq!(doc["algorithm"], "base58check");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let data = unhex(v["data_hex"].as_str().unwrap());
            let text = v["text"].as_str().unwrap().as_bytes();
            assert_eq!(e.encode(&data).unwrap(), text, "{}", v["id"]);
            assert_eq!(e.decode(text).unwrap(), data, "{}", v["id"]);
            n += 1;
        }
        assert!(n >= 38);
    }

    #[test]
    fn rejects_invalid_text() {
        let e = new(&Params::new()).unwrap();
        let doc = load("vectors.json");
        for bad in doc["invalid"].as_array().unwrap() {
            let text = bad["text"].as_str().unwrap().as_bytes();
            assert!(e.decode(text).is_err(), "accepted {:?}", bad["text"]);
        }
    }

    #[test]
    fn length_limits() {
        let e = new(&Params::new()).unwrap();
        assert!(e.encode(&vec![1u8; 4097]).is_err());
        assert!(e.decode(&vec![b'2'; 8193]).is_err());
        assert!(e.encode(&vec![1u8; 4096]).is_ok());
    }
}
