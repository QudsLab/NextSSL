//! Adapter: simeck-64 (Crypto++ simeck.cpp, verbatim C++17; namespace renamed `nextssl_simeck_64_CryptoPP`) -> nextssl `BlockCipher`.
//! Generated wiring, no crypto logic. Block 8 bytes, key length one of 16 bytes (checked here, wrong
//! lengths are `InvalidLength`). Byte order is whatever Crypto++ defines; the glue only moves bytes. The C++ side
//! (shim.cpp) owns one key schedule per keyed cipher and Crypto++ wipes it on destruction.

use core::ffi::c_void;
use nextssl_core::{
    BlockCipher, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey, Zeroizing,
};

const BLOCK_LEN: usize = 8;
const KEY_MIN: usize = 16;
const KEY_MAX: usize = 16;
#[allow(dead_code)]
const KEY_LENS: &[usize] = &[16];

fn key_len() -> Len {
    Len::fixed(16)
}

fn key_ok(len: usize) -> bool {
    (KEY_MIN..=KEY_MAX).contains(&len)
}

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_void};
    extern "C" {
        #[link_name = "nextssl__simeck_64__shim_new"]
        pub fn ctx_new(key: *const u8, keylen: c_int) -> *mut c_void;
        #[link_name = "nextssl__simeck_64__shim_enc"]
        pub fn ctx_enc(ctx: *const c_void, input: *const u8, output: *mut u8) -> c_int;
        #[link_name = "nextssl__simeck_64__shim_dec"]
        pub fn ctx_dec(ctx: *const c_void, input: *const u8, output: *mut u8) -> c_int;
        #[link_name = "nextssl__simeck_64__shim_free"]
        pub fn ctx_free(ctx: *mut c_void);
    }
}

/// Owner of one C++ key schedule. Read-only after construction.
struct Ctx(*mut c_void);

// SAFETY: the pointer is a unique heap allocation owned by this value; after construction the C++ side only
// reads it (ProcessBlock is a const method), so shared access is data-race free.
#[allow(unsafe_code)]
unsafe impl Send for Ctx {}
#[allow(unsafe_code)]
unsafe impl Sync for Ctx {}

impl Drop for Ctx {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: created by ctx_new, freed exactly once here (the destructor wipes the schedule).
        unsafe { ffi::ctx_free(self.0) }
    }
}

struct Keyed(Ctx);

impl Keyed {
    fn apply(&self, enc: bool, block: &mut [u8]) -> Result<()> {
        Len::fixed(BLOCK_LEN).check("block", block.len())?;
        let mut out = Zeroizing::new(vec![0u8; BLOCK_LEN]);
        // SAFETY: the context is live (owned by self); input and output are distinct slices of exactly
        // one block, which is all the callee reads and writes.
        #[allow(unsafe_code)]
        let rc = unsafe {
            if enc {
                ffi::ctx_enc(self.0 .0, block.as_ptr(), out.as_mut_ptr())
            } else {
                ffi::ctx_dec(self.0 .0, block.as_ptr(), out.as_mut_ptr())
            }
        };
        if rc != 0 {
            return Err(Error::Backend("block operation failed"));
        }
        block.copy_from_slice(&out);
        Ok(())
    }
}

impl KeyedBlockCipher for Keyed {
    fn block_len(&self) -> usize {
        BLOCK_LEN
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        self.apply(true, block)
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        self.apply(false, block)
    }
}

struct Cipher;

impl BlockCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(key_len()),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        if !key_ok(key.len()) {
            return Err(Error::InvalidLength {
                what: "key",
                got: key.len(),
                min: KEY_MIN,
                max: KEY_MAX,
            });
        }
        // SAFETY: key is valid for key.len() bytes, checked against the accepted lengths above; the
        // callee copies what it needs and keeps no pointer to it.
        #[allow(unsafe_code)]
        let p = unsafe { ffi::ctx_new(key.as_bytes().as_ptr(), key.len() as core::ffi::c_int) };
        if p.is_null() {
            return Err(Error::Backend("key setup failed"));
        }
        Ok(Box::new(Keyed(Ctx(p))))
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn BlockCipher>> {
    Ok(Box::new(Cipher))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn key(n: usize) -> SymmetricKey {
        SymmetricKey::from_bytes(&vec![7u8; n], Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn roundtrip_and_lengths() {
        let c = new(&Params::new()).unwrap();
        for &n in KEY_LENS {
            let k = c.keyed(&key(n)).unwrap();
            let orig: Vec<u8> = (0..BLOCK_LEN as u8).collect();
            let mut b = orig.clone();
            k.encrypt_block(&mut b).unwrap();
            assert_ne!(b, orig);
            k.decrypt_block(&mut b).unwrap();
            assert_eq!(b, orig);
            assert!(k.encrypt_block(&mut [0u8; BLOCK_LEN + 1]).is_err());
            assert!(k.decrypt_block(&mut [0u8; BLOCK_LEN - 1]).is_err());
        }
        for bad in 0..=KEY_MAX + 3 {
            if key_ok(bad) {
                continue;
            }
            assert!(
                matches!(c.keyed(&key(bad)), Err(Error::InvalidLength { .. })),
                "key {bad}"
            );
        }
    }

    #[test]
    fn kat_file() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kat/kat.json");
        let doc: J = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(doc["algorithm"], "simeck-64");
        let c = new(&Params::new()).unwrap();
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let k = c.keyed(&key_of(&unhex(v["key_hex"].as_str().unwrap()))).unwrap();
            let pt = unhex(v["pt_hex"].as_str().unwrap());
            let ct = unhex(v["ct_hex"].as_str().unwrap());
            let mut b = pt.clone();
            k.encrypt_block(&mut b).unwrap();
            assert_eq!(b, ct, "encrypt {}", v["id"]);
            k.decrypt_block(&mut b).unwrap();
            assert_eq!(b, pt, "decrypt {}", v["id"]);
            n += 1;
        }
        assert!(n >= 3, "too few KATs ran: {n}");
    }

    fn key_of(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }
}
