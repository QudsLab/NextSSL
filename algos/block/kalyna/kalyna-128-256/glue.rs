//! Adapter: Kalyna (DSTU 7624:2014) reference C (C, verbatim) -> nextssl `BlockCipher`.
//! Raw single-block permutation only (no mode, no padding). The C side is a thin context wrapper (shim.c).

use core::ffi::{c_int, c_void};
use nextssl_core::{
    BlockCipher, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey,
};
use std::sync::Mutex;

struct Variant {
    #[allow(dead_code)]
    name: &'static str,
    key: usize,
    block: usize,
    /// Index of the instance in the C shim table.
    ci: usize,
}

const VARIANTS: &[Variant] = &[Variant {
    name: "128-256",
    key: 32,
    block: 16,
    ci: 1,
}];

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__kalyna_128_256__new"]
        fn ctx_new(v: c_int, key: *const u8) -> *mut c_void;
        #[link_name = "nextssl__kalyna_128_256__enc"]
        fn ctx_enc(ctx: *mut c_void, input: *const u8, output: *mut u8) -> c_int;
        #[link_name = "nextssl__kalyna_128_256__dec"]
        fn ctx_dec(ctx: *mut c_void, input: *const u8, output: *mut u8) -> c_int;
        #[link_name = "nextssl__kalyna_128_256__free"]
        fn ctx_free(ctx: *mut c_void);
    }

    /// Owner of one C key-schedule context. All access goes through the `Mutex` in `Keyed`.
    pub(super) struct Ctx(*mut c_void);

    // SAFETY: the pointer is a unique heap allocation owned by this value and only dereferenced
    // by the C functions below while the surrounding `Mutex` is held.
    #[allow(unsafe_code)]
    unsafe impl Send for Ctx {}

    impl Ctx {
        /// Precondition: `key.len()` equals the variant's key size.
        #[allow(unsafe_code)]
        pub(super) fn new(v: usize, key: &[u8]) -> Option<Ctx> {
            // SAFETY: `key` is valid for `key.len()` bytes, which equals the variant key size the
            // callee reads; the callee copies it and keeps no pointer to it.
            let p = unsafe { ctx_new(v as c_int, key.as_ptr()) };
            if p.is_null() {
                None
            } else {
                Some(Ctx(p))
            }
        }

        /// Precondition: `input` and `output` both hold exactly one block.
        #[allow(unsafe_code)]
        pub(super) fn run(&mut self, enc: bool, input: &[u8], output: &mut [u8]) -> bool {
            // SAFETY: `self.0` is a live context (freed only in Drop); `input`/`output` are distinct
            // slices of exactly one block, which is all the callee reads and writes.
            unsafe {
                if enc {
                    ctx_enc(self.0, input.as_ptr(), output.as_mut_ptr()) == 0
                } else {
                    ctx_dec(self.0, input.as_ptr(), output.as_mut_ptr()) == 0
                }
            }
        }
    }

    impl Drop for Ctx {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: the context was created by `ctx_new` and is freed exactly once here.
            unsafe { ctx_free(self.0) }
        }
    }
}

struct Keyed {
    block: usize,
    ctx: Mutex<ffi::Ctx>,
}

impl KeyedBlockCipher for Keyed {
    fn block_len(&self) -> usize {
        self.block
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        self.apply(true, block)
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        self.apply(false, block)
    }
}

impl Keyed {
    fn apply(&self, enc: bool, block: &mut [u8]) -> Result<()> {
        Len::fixed(self.block).check("block", block.len())?;
        let mut out = vec![0u8; self.block];
        let ok = self
            .ctx
            .lock()
            .map_err(|_| Error::Backend("kalyna-128-256: poisoned"))?
            .run(enc, block, &mut out);
        if !ok {
            return Err(Error::Backend("kalyna-128-256: block operation failed"));
        }
        block.copy_from_slice(&out);
        Ok(())
    }
}

struct Cipher {
    idx: usize,
}

impl BlockCipher for Cipher {
    fn sizes(&self) -> Sizes {
        let v = &VARIANTS[self.idx];
        Sizes {
            key: Some(Len::fixed(v.key)),
            block: Some(Len::fixed(v.block)),
            ..Sizes::NONE
        }
    }

    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        let v = &VARIANTS[self.idx];
        Len::fixed(v.key).check("key", key.len())?;
        let ctx = ffi::Ctx::new(v.ci, key.as_bytes())
            .ok_or(Error::Backend("kalyna-128-256: key setup failed"))?;
        Ok(Box::new(Keyed {
            block: v.block,
            ctx: Mutex::new(ctx),
        }))
    }
}

/// Registry constructor. Optional enum parameter `variant`.
pub fn new(params: &Params) -> Result<Box<dyn BlockCipher>> {
    let _ = params;
    let idx = 0;
    Ok(Box::new(Cipher { idx }))
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

    #[test]
    fn known_answers() {
        let mut total = 0;
        for file in ["kalyna-128-256.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "kalyna-128-256");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let name = v["params"]["variant"].as_str().unwrap();
                let c = new(&Params::new().with("variant", Value::Str(name.to_string()))).unwrap();
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let pt = unhex(v["pt_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                let mut b = pt.clone();
                c.encrypt_block(&k, &mut b).unwrap();
                assert_eq!(b, ct, "encrypt {id}");
                c.decrypt_block(&k, &mut b).unwrap();
                assert_eq!(b, pt, "decrypt {id}");
                total += 1;
            }
        }
        assert!(total >= 1, "too few vectors ran: {total}");
    }

    #[test]
    fn rejects_bad_lengths() {
        for var in VARIANTS {
            let c = new(&Params::new().with("variant", Value::Str(var.name.to_string()))).unwrap();
            let k = key(&vec![3u8; var.key]);
            for bad in [0, var.block - 1, var.block + 1, 65] {
                let mut b = vec![0u8; bad];
                assert!(
                    matches!(
                        c.encrypt_block(&k, &mut b),
                        Err(Error::InvalidLength { .. })
                    ),
                    "block {bad}"
                );
            }
            for bad in [0, var.key - 1, var.key + 1] {
                let mut b = vec![0u8; var.block];
                assert!(
                    matches!(
                        c.encrypt_block(&key(&vec![3u8; bad]), &mut b),
                        Err(Error::InvalidLength { .. })
                    ),
                    "key {bad}"
                );
            }
        }
    }
}
