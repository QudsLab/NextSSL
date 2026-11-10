//! Adapter: Mercy-6 (Paul Crowley, 4096-bit block cipher for disk blocks; verbatim C `fast-mercy.c`, symbols renamed
//! `nextssl__mercy_6__*`) -> nextssl `BlockMode`. Generated wiring, no crypto logic. UNTESTED.
//!
//! Shape: key 1..=256 bytes (any length is accepted by the upstream key schedule), nonce = the 96-byte "spice"
//! (6 rounds x 4 words, the per-block tweak of the design), data = exactly one 512-byte block. Words are read and
//! written little-endian by the shim, independent of the host. Not authenticated.
//!
//! Upstream keeps the key schedule in file-level static state (`schedule_key` fills global tables). Every call
//! therefore takes one process-wide mutex, schedules the key and runs the block under it: calls are serialised, and
//! two instances with different keys cannot interfere. The tables stay in memory after a call (upstream statics, not
//! reachable for wiping: recorded in docs/UPSTREAM_ISSUES.md).

use nextssl_core::{BlockMode, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};
use std::sync::Mutex;

const BLOCK: usize = 512;
const SPICE: usize = 96;
const KEY_MIN: usize = 1;
const KEY_MAX: usize = 256;

static GLOBAL_KEY_STATE: Mutex<()> = Mutex::new(());

mod ffi {
    #![allow(unsafe_code)]
    extern "C" {
        #[link_name = "nextssl__mercy_6__shim_crypt"]
        fn crypt(
            direction: i32,
            key: *const u8,
            keylen: i32,
            spice: *const u8,
            block: *mut u8,
        ) -> i32;
    }

    /// `direction`: 1 encrypt, 0 decrypt. Caller holds the global lock.
    pub(super) fn run(direction: i32, key: &[u8], spice: &[u8], block: &mut [u8]) -> i32 {
        debug_assert!(
            !key.is_empty() && key.len() <= 256 && spice.len() == 96 && block.len() == 512
        );
        // SAFETY: key is `key.len()` readable bytes (1..=256, checked by the caller), spice is 96 readable bytes and
        // block 512 writable bytes (both checked by the caller); the shim keeps no pointer after returning.
        unsafe {
            crypt(
                direction,
                key.as_ptr(),
                key.len() as i32,
                spice.as_ptr(),
                block.as_mut_ptr(),
            )
        }
    }
}

struct Mode;

impl Mode {
    fn check(&self, key: &SymmetricKey, nonce: &[u8], data: &[u8]) -> Result<()> {
        Len::range(KEY_MIN, KEY_MAX).check("key", key.len())?;
        Len::fixed(SPICE).check("nonce", nonce.len())?;
        Len::fixed(BLOCK).check("data", data.len())
    }

    fn run(&self, dir: i32, key: &SymmetricKey, nonce: &[u8], block: &mut [u8]) -> Result<()> {
        let _g = GLOBAL_KEY_STATE
            .lock()
            .map_err(|_| Error::Backend("mercy key-state lock poisoned"))?;
        if ffi::run(dir, key.as_bytes(), nonce, block) != 0 {
            return Err(Error::Backend("mercy failed"));
        }
        Ok(())
    }
}

impl BlockMode for Mode {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(KEY_MIN, KEY_MAX)),
            nonce: Some(Len::fixed(SPICE)),
            block: Some(Len::fixed(BLOCK)),
            ..Sizes::NONE
        }
    }

    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce, pt)?;
        let mut buf = pt.to_vec();
        self.run(1, key, nonce, &mut buf)?;
        Ok(buf)
    }

    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce, ct)?;
        let mut buf = Zeroizing::new(ct.to_vec());
        self.run(0, key, nonce, &mut buf)?;
        Ok(buf)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn BlockMode>> {
    Ok(Box::new(Mode))
}
