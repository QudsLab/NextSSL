//! Adapter: `base91` crate (basE91 by Joachim Henke, alphabet A-Za-z0-9 and !#$%&()*+,./:;<=>?@[]^_`{|}~") -> nextssl `Encoding`.
//!
//! UNVERIFIED tier: the crate's decoder is lenient (it silently skips characters outside the
//! alphabet and accepts non-canonical text). This adapter makes decode strict in Rust: every
//! character must be in the alphabet, and the decoded bytes must re-encode to exactly the input
//! text. Input limited to 1 MiB.

use nextssl_core::{Encoding, Error, Params, Result};

const MAX_DATA: usize = 1 << 20;
const MAX_TEXT: usize = 2 * MAX_DATA;
const ALPHABET: &[u8; 91] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

struct Impl;

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, MAX_DATA)?;
        Ok(base91::slice_encode(data))
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, MAX_TEXT)?;
        if !text.iter().all(|c| ALPHABET.contains(c)) {
            return Err(Error::InvalidInput("invalid base91 character"));
        }
        let data = base91::slice_decode(text);
        if base91::slice_encode(&data) != text {
            return Err(Error::InvalidInput("non-canonical base91"));
        }
        Ok(data)
    }
}

/// Registry constructor. Base91 takes no parameters.
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
        assert_eq!(doc["algorithm"], "base91");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let data = unhex(v["data_hex"].as_str().unwrap());
            let text = v["text"].as_str().unwrap().as_bytes();
            assert_eq!(e.encode(&data).unwrap(), text, "{}", v["id"]);
            assert_eq!(e.decode(text).unwrap(), data, "{}", v["id"]);
            n += 1;
        }
        assert!(n >= 10);
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
}
