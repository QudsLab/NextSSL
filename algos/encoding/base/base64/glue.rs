//! Adapter: `base64` crate (RFC 4648 standard alphabet, padded, canonical) -> nextssl `Encoding`.

use base64::{engine::general_purpose::STANDARD, Engine};
use nextssl_core::{Encoding, Error, Params, Result};

struct Base64;

impl Encoding for Base64 {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(STANDARD.encode(data).into_bytes())
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        STANDARD
            .decode(text)
            .map_err(|_| Error::InvalidInput("invalid base64"))
    }
}

/// Registry constructor. Base64 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Encoding>> {
    Ok(Box::new(Base64))
}
