//! Adapter: HITAG2 (C port of hitag.py, symbols renamed `nextssl__hitag2__*`) -> nextssl `StreamCipher`.
//! Key exactly 6 bytes (48-bit key, big-endian). The 8-byte nonce is the uid (4 bytes) followed by the 32-bit
//! nonce, both big-endian. Unauthenticated; keystream is bounded by the 2^48 - 1 bit LFSR period. Generated
//! wiring, no crypto logic. UNTESTED (not yet compiled). The C side (shim.c) maps bytes to the integers the
//! port takes and XORs the keystream in place.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const KEY_LEN: usize = 6;
const NONCE_LEN: usize = 8;
/// Keystream bytes before the 48-bit LFSR would repeat: (2^48 - 1) / 8 rounded down.
const MAX_BYTES: u64 = ((1u64 << 48) - 1) / 8;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_uchar};
    extern "C" {
        #[link_name = "nextssl__hitag2__shim_apply"]
        pub fn apply(key: *const c_uchar, nonce: *const c_uchar, data: *mut c_uchar, len: usize) -> c_int;
    }
}

struct Cipher;

impl StreamCipher for Cipher {
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
        if data.len() as u64 > MAX_BYTES {
            return Err(Error::InvalidInput("hitag2: keystream limit exceeded"));
        }
        // SAFETY: key has exactly KEY_LEN and nonce exactly NONCE_LEN readable bytes (checked above); data is a
        // valid slice written for data.len() bytes; the callee keeps no pointer and wipes its state.
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::apply(key.as_bytes().as_ptr(), nonce.as_ptr(), data.as_mut_ptr(), data.len()) };
        if rc != 0 {
            return Err(Error::Backend("hitag2 failed"));
        }
        Ok(())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StreamCipher>> {
    Ok(Box::new(Cipher))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
    }

    fn key(bytes: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(bytes, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn kat_files() {
        let c = new(&Params::new()).unwrap();
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kat").join("kat.json");
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let nonce = unhex(v["nonce_hex"].as_str().unwrap());
            let pt = unhex(v["data_hex"].as_str().unwrap());
            let ct = unhex(v["out_hex"].as_str().unwrap());
            let mut b = pt.clone();
            c.apply_keystream(&k, &nonce, &mut b).unwrap();
            assert_eq!(b, ct, "{} encrypt", v["id"]);
            c.apply_keystream(&k, &nonce, &mut b).unwrap();
            assert_eq!(b, pt, "{} decrypt", v["id"]);
            n += 1;
        }
        assert!(n >= 10, "too few KATs ran: {n}");
    }

    #[test]
    fn rejects_bad_lengths_without_touching_data() {
        let c = new(&Params::new()).unwrap();
        for bad in [0usize, 5, 7, 16] {
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&key(&vec![1u8; bad]), &[0u8; NONCE_LEN], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "key {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
        let k = key(&[1u8; KEY_LEN]);
        for bad in [0usize, 7, 9] {
            let mut d = [0xAAu8; 20];
            let r = c.apply_keystream(&k, &vec![0u8; bad], &mut d);
            assert!(matches!(r, Err(Error::InvalidLength { .. })), "nonce {bad}");
            assert_eq!(d, [0xAAu8; 20]);
        }
        c.apply_keystream(&k, &[0u8; NONCE_LEN], &mut []).unwrap();
    }
}
