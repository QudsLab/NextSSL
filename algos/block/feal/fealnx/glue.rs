//! Adapter: FEAL-NX (N rounds, 128-bit key; fealnx.c by Peter Pearson from the funet archive, verbatim old C, symbols renamed `nextssl__fealnx__*`) -> nextssl `BlockCipher`.
//! Glue only, no crypto logic. Block 8 bytes, key exactly 16 bytes, param `rounds` (even, 4..=64, default 32). Static buffers upstream: one process-wide lock.

use nextssl_core::{
    BlockCipher, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey, Zeroizing,
};
use std::sync::Mutex;

const BLOCK_LEN: usize = 8;

/// The upstream keeps its key schedule in file-level statics, so every call (key schedule + one block) runs under this lock.
static LOCK: Mutex<()> = Mutex::new(());

fn key_len() -> Len {
    Len::range(16, 16)
}

fn key_ok(n: usize) -> Result<()> {
    if n == 16 {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what: "key",
            got: n,
            min: 16,
            max: 16,
        })
    }
}

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulong};
    extern "C" {
        #[link_name = "nextssl__fealnx__shim_crypt"]
        pub fn crypt(enc: c_int, rounds: c_int, key: *const u8, keylen: c_ulong, input: *const u8, output: *mut u8) -> c_int;
    }
}

/// A keyed cipher: holds the key (zeroized on drop); the C side re-derives the schedule per block under `LOCK`.
struct Keyed {
    key: Zeroizing<Vec<u8>>,
    rounds: u32,
}

impl Keyed {
    fn apply(&self, enc: bool, block: &mut [u8]) -> Result<()> {
        Len::fixed(BLOCK_LEN).check("block", block.len())?;
        let mut out = Zeroizing::new(vec![0u8; BLOCK_LEN]);
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: key is valid for its (checked) length and read only; input and output are distinct buffers of exactly one
        // block; the process-wide lock serialises use of the upstream's static state; the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::crypt(
                i32::from(enc),
                self.rounds as i32,
                self.key.as_ptr(),
                self.key.len() as core::ffi::c_ulong,
                block.as_ptr(),
                out.as_mut_ptr(),
            )
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

struct Cipher {
    rounds: u32,
}

impl BlockCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(key_len()),
            block: Some(Len::fixed(BLOCK_LEN)),
            ..Sizes::NONE
        }
    }

    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        key_ok(key.len())?;
        Ok(Box::new(Keyed {
            key: Zeroizing::new(key.as_bytes().to_vec()),
            rounds: self.rounds,
        }))
    }
}

/// Registry constructor. Param `rounds` (even, 4..=64, default 32).
pub fn new(params: &Params) -> Result<Box<dyn BlockCipher>> {
    let rounds = params.get_u32("rounds").unwrap_or(32);
    if !(4..=64).contains(&rounds) || rounds % 2 != 0 {
        return Err(Error::ParamOutOfRange("rounds"));
    }
    Ok(Box::new(Cipher { rounds }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn roundtrip_and_lengths() {
        let c = new(&Params::new()).unwrap();
        assert!(new(&Params::new().with("rounds", nextssl_core::Value::U32(7))).is_err());
        for kl in [16] {
            let kb: Vec<u8> = (0..kl as u8).map(|i| i.wrapping_mul(13).wrapping_add(1)).collect();
            let k = c.keyed(&key(&kb)).unwrap();
            let orig: Vec<u8> = (0..BLOCK_LEN as u8).collect();
            let mut b = orig.clone();
            k.encrypt_block(&mut b).unwrap();
            assert_ne!(b, orig);
            k.decrypt_block(&mut b).unwrap();
            assert_eq!(b, orig);
            assert!(k.encrypt_block(&mut [0u8; BLOCK_LEN + 1]).is_err());
        }
        assert!(c.keyed(&key(&[1u8; 15])).is_err());
        assert!(c.keyed(&key(&[1u8; 17])).is_err());
    }

    #[test]
    fn parallel_use_is_serialised() {
        let c = std::sync::Arc::new(new(&Params::new()).unwrap());
        let handles: Vec<_> = (0..4u8)
            .map(|t| {
                let c = c.clone();
                std::thread::spawn(move || {
                    let k = c.keyed(&key(&[t + 1; 16])).unwrap();
                    for _ in 0..50 {
                        let mut b = [t; BLOCK_LEN];
                        k.encrypt_block(&mut b).unwrap();
                        k.decrypt_block(&mut b).unwrap();
                        assert_eq!(b, [t; BLOCK_LEN]);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
