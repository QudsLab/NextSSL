//! Adapter: RustCrypto `chacha20` (IETF ChaCha20, RFC 8439) -> nextssl `StreamCipher`.
//!
//! Key 32 bytes, nonce 12 bytes, 32-bit block counter starting at the `initial_counter` param
//! (default 0). Unauthenticated: pair with a MAC or use an AEAD. Inputs that would run the
//! 32-bit block counter to its last value (the upstream crate never uses block 2^32 - 1) are
//! refused before any byte is touched.

use chacha20::cipher::{KeyIvInit, StreamCipher as _, StreamCipherSeek as _};
use chacha20::ChaCha20;
use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const BLOCK_LEN: u64 = 64;
/// Block counter values the upstream crate can use: 0..=2^32-2 (it rejects the final block).
const COUNTER_SPACE: u64 = (1 << 32) - 1;

struct ChaCha20Cipher {
    initial_counter: u32,
}

impl StreamCipher for ChaCha20Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::fixed(KEY_LEN)),
            nonce: Some(Len::fixed(NONCE_LEN)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        Len::fixed(KEY_LEN).check("key", key.len())?;
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
        // Keystream limit: blocks_needed must fit in the counter values left after the start.
        let blocks_needed = u64::try_from(data.len())
            .map_err(|_| Error::InvalidInput("chacha20: input too long"))?
            .div_ceil(BLOCK_LEN);
        let blocks_left = COUNTER_SPACE - u64::from(self.initial_counter);
        if blocks_needed > blocks_left {
            return Err(Error::InvalidInput("chacha20: keystream limit exceeded"));
        }
        let mut cipher = ChaCha20::new_from_slices(key.as_bytes(), nonce)
            .map_err(|_| Error::Backend("chacha20 key/nonce setup"))?;
        cipher
            .try_seek(u64::from(self.initial_counter) * BLOCK_LEN)
            .map_err(|_| Error::Backend("chacha20 counter seek"))?;
        cipher
            .try_apply_keystream(data)
            .map_err(|_| Error::InvalidInput("chacha20: keystream limit exceeded"))
    }
}

/// Registry constructor. Optional param `initial_counter` (u32, default 0).
pub fn new(params: &Params) -> Result<Box<dyn StreamCipher>> {
    let initial_counter = params.get_u32("initial_counter").unwrap_or(0);
    Ok(Box::new(ChaCha20Cipher { initial_counter }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::Value;
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

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    fn with_counter(c: u32) -> Box<dyn StreamCipher> {
        new(&Params::new().with("initial_counter", Value::U32(c))).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.key, Some(Len::fixed(KEY_LEN)));
        assert_eq!(s.nonce, Some(Len::fixed(NONCE_LEN)));
    }

    #[test]
    fn rfc8439_kats() {
        let doc = load("rfc8439.json");
        assert_eq!(doc["algorithm"], "chacha20");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let ctr = u32::try_from(v["params"]["initial_counter"].as_u64().unwrap()).unwrap();
            let c = with_counter(ctr);
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let nonce = unhex(v["nonce_hex"].as_str().unwrap());
            let pt = unhex(v["data_hex"].as_str().unwrap());
            let ct = unhex(v["out_hex"].as_str().unwrap());
            let mut buf = pt.clone();
            c.apply_keystream(&k, &nonce, &mut buf).unwrap();
            assert_eq!(buf, ct, "encrypt {id}");
            c.apply_keystream(&k, &nonce, &mut buf).unwrap();
            assert_eq!(buf, pt, "decrypt {id}");
            n += 1;
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn counter_limit_is_enforced_before_touching_data() {
        let k = key(&[9u8; KEY_LEN]);
        let nonce = [3u8; NONCE_LEN];
        // Last usable block counter: exactly one block (<= 64 bytes) is allowed.
        let c = with_counter(u32::MAX - 1);
        let mut one = [0x55u8; 64];
        c.apply_keystream(&k, &nonce, &mut one).unwrap();
        assert_ne!(one, [0x55u8; 64]);
        let mut two = [0x55u8; 65];
        assert!(matches!(
            c.apply_keystream(&k, &nonce, &mut two),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(two, [0x55u8; 65], "data modified despite error");
        // Counter u32::MAX has no usable block at all; empty input is still fine.
        let c = with_counter(u32::MAX);
        let mut one = [0x55u8; 1];
        assert!(matches!(
            c.apply_keystream(&k, &nonce, &mut one),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(one, [0x55u8; 1]);
        c.apply_keystream(&k, &nonce, &mut []).unwrap();
        // Counter 0 allows the whole counter space; small inputs always fine.
        with_counter(0)
            .apply_keystream(&k, &nonce, &mut [0u8; 200])
            .unwrap();
    }

    #[test]
    fn counter_param_selects_the_block() {
        // Keystream at counter N+1 equals the second block of the keystream at counter N.
        let k = key(&[1u8; KEY_LEN]);
        let nonce = [2u8; NONCE_LEN];
        let mut a = [0u8; 128];
        with_counter(5).apply_keystream(&k, &nonce, &mut a).unwrap();
        let mut b = [0u8; 64];
        with_counter(6).apply_keystream(&k, &nonce, &mut b).unwrap();
        assert_eq!(a[64..], b);
    }

    #[test]
    fn rejects_bad_lengths_without_touching_data() {
        let c = new(&Params::new()).unwrap();
        for bad in [0usize, 16, 31, 33, 64] {
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&key(&vec![1u8; bad]), &[0u8; NONCE_LEN], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
        let k = key(&[1u8; KEY_LEN]);
        for bad in [0usize, 8, 11, 13, 16, 24] {
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&k, &vec![0u8; bad], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "nonce {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
    }
}
