//! Adapter: `bs58` FLICKR alphabet (Flickr Base58 short URLs) -> nextssl `Encoding`.
//!
//! Strict on decode: the text must decode and must re-encode to exactly the input (rejects non-canonical forms).
//! Input is limited to 4096 bytes (encode) / 8192 characters (decode): the conversion is quadratic.


use nextssl_core::{Encoding, Error, Params, Result};

struct Impl;

fn enc(data: &[u8]) -> Vec<u8> {
    bs58::encode(data).with_alphabet(bs58::Alphabet::FLICKR).into_string().into_bytes()
}

fn dec(text: &[u8]) -> core::result::Result<Vec<u8>, ()> {
    bs58::decode(text).with_alphabet(bs58::Alphabet::FLICKR).into_vec().map_err(|_| ())
}

impl Encoding for Impl {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("data", data.len(), 0, 4096)?;
        Ok(enc(data))
    }

    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        nextssl_core::check_len("text", text.len(), 0, 8192)?;
        let data = dec(text).map_err(|()| Error::InvalidInput("invalid base58-flickr"))?;
        if enc(&data) != text {
            return Err(Error::InvalidInput("non-canonical base58-flickr"));
        }
        Ok(data)
    }
}

/// Registry constructor. base58-flickr takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Encoding>> {
    Ok(Box::new(Impl))
}
