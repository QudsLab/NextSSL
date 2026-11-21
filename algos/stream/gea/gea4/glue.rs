//! Adapter: libosmocore GEA4 (GPRS keystream generator, GPL-2.0-or-later, verbatim C, symbols renamed `nextssl__gea4__*`) -> nextssl `StreamCipher`.
//! Glue only, no crypto logic. Key exactly 16 bytes. Nonce = 5 bytes: 32-bit INPUT (big endian) then the direction byte (0 or 1).
//! At most 1523 bytes of data per call. Unauthenticated; the nonce encoding is also stated in algo.toml.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const NONCE_LEN: usize = 5;
const MAX_LEN: usize = 1523;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulong};
    extern "C" {
        #[link_name = "nextssl__gea4__shim_apply"]
        pub fn apply(
            key: *const u8,
            keylen: c_ulong,
            nonce: *const u8,
            noncelen: c_ulong,
            data: *mut u8,
            len: c_ulong,
        ) -> c_int;
    }
}

struct Cipher;

fn key_len() -> Len {
    Len::fixed(16)
}

impl StreamCipher for Cipher {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(key_len()),
            nonce: Some(Len::fixed(NONCE_LEN)),
            ..Sizes::NONE
        }
    }

    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        key_len().check("key", key.len())?;
        Len::fixed(NONCE_LEN).check("nonce", nonce.len())?;
        if data.len() > MAX_LEN {
            // The keystream is finite: refuse before touching `data` (no truncation, no wrap-around).
            return Err(Error::InvalidLength {
                what: "data",
                got: data.len(),
                min: 0,
                max: MAX_LEN,
            });
        }
        if nonce[4] > 1 {
            return Err(Error::ParamOutOfRange("direction"));
        }
        // SAFETY: key and nonce are valid for their (checked) lengths and only read; `data` is a valid mutable
        // slice processed in place; the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::apply(
                key.as_bytes().as_ptr(),
                key.len() as core::ffi::c_ulong,
                nonce.as_ptr(),
                nonce.len() as core::ffi::c_ulong,
                data.as_mut_ptr(),
                data.len() as core::ffi::c_ulong,
            )
        };
        if rc != 0 {
            return Err(Error::Backend("stream setup failed"));
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
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn key(b: &[u8]) -> SymmetricKey {
        SymmetricKey::from_bytes(b, Len::range(0, usize::MAX)).unwrap()
    }

    #[test]
    fn known_answers() {
        let c = new(&Params::new()).unwrap();
        for (k, n, d, o) in [("d3c5d592327fb11c4035c6680af8c6d1", "0a3a59b400", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "6e217ce41ebefb5ec8094c15974290065e42babc9ae35654a53085ce68dfa4426a2ff0ad4af3341006a3f84b7613acb4fbdc34"), ("3d43c388c9581e337ff1f97eb5c1f85e", "48571ab900", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "fc7314ef00a63ed0116f236c5d25c54eec56a5b71f9f18b4d7941f84e422acbde5eea9a204679002d14f312f3dee2a1ac917c3fbdc3696143c0f5d"), ("a4496a64df4f399f3b4506814a3e07a1", "eb04ade201", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "2aeb5970fb06b718027d048488aaf24fb3b74ea4a6b1242ff85b108ff816a303c72757d9aad862b835d1d287dbc141d0a28d79d87bb137cd1198cd")] {
            let mut buf = unhex(d);
            c.apply_keystream(&key(&unhex(k)), &unhex(n), &mut buf).unwrap();
            assert_eq!(buf, unhex(o));
        }
    }

    #[test]
    fn roundtrip_and_lengths() {
        let c = new(&Params::new()).unwrap();
        let kl = key_len().min();
        let k = key(&vec![9u8; kl]);
        let mut n = [0u8; NONCE_LEN];
        n[2] = 5;
        let mut d = *b"hello stream cipher";
        c.apply_keystream(&k, &n, &mut d).unwrap();
        assert_ne!(&d, b"hello stream cipher");
        c.apply_keystream(&k, &n, &mut d).unwrap();
        assert_eq!(&d, b"hello stream cipher");
        assert!(matches!(
            c.apply_keystream(&key(&vec![1u8; kl - 1]), &n, &mut d),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            c.apply_keystream(&k, &n[..NONCE_LEN - 1], &mut d),
            Err(Error::InvalidLength { .. })
        ));
        let mut big = vec![0u8; MAX_LEN + 1];
        assert!(matches!(
            c.apply_keystream(&k, &n, &mut big),
            Err(Error::InvalidLength { .. })
        ));
        assert!(big.iter().all(|b| *b == 0), "data untouched on error");
    }
}
