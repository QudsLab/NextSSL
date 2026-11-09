//! Adapter: `data-encoding` (base32hex, RFC 4648 section 7) -> nextssl `Encoding`.
//!
//! Strict on decode: canonical alphabet only (no lowercase unless the alphabet has it, no
//! whitespace), required padding, no non-zero trailing bits. Anything else is an error.
//! Input is limited to nextssl_core::MAX_INPUT_LEN bytes.

use data_encoding::BASE32HEX;
use nextssl_core::{Encoding, Error, Params, Result};

struct Impl;

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        Ok(BASE32HEX.encode(data).into_bytes())
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, nextssl_core::MAX_INPUT_LEN)?;
        let data = BASE32HEX
            .decode(text)
            .map_err(|_| Error::InvalidInput("invalid base32hex"))?;
        // Canonical form only: re-encoding must reproduce the input exactly (rejects padded
        // blocks concatenated together and any other accepted-but-non-canonical text).
        if BASE32HEX.encode(&data).as_bytes() != text {
            return Err(Error::InvalidInput("non-canonical base32hex"));
        }
        Ok(data)
    }
}

/// Registry constructor. base32hex takes no parameters.
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
        assert_eq!(doc["algorithm"], "base32hex");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let data = unhex(v["data_hex"].as_str().unwrap());
            let text = v["text"].as_str().unwrap().as_bytes();
            assert_eq!(e.encode(&data).unwrap(), text, "{}", v["id"]);
            assert_eq!(e.decode(text).unwrap(), data, "{}", v["id"]);
            n += 1;
        }
        assert!(n >= 7);
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
