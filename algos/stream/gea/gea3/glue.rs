//! Adapter: libosmocore GEA3 (GPRS keystream generator, GPL-2.0-or-later, verbatim C, symbols renamed `nextssl__gea3__*`) -> nextssl `StreamCipher`.
//! Glue only, no crypto logic. Key exactly 8 bytes. Nonce = 5 bytes: 32-bit INPUT (big endian) then the direction byte (0 or 1).
//! At most 1523 bytes of data per call. Unauthenticated; the nonce encoding is also stated in algo.toml.

use nextssl_core::{Error, Len, Params, Result, Sizes, StreamCipher, SymmetricKey};

const NONCE_LEN: usize = 5;
const MAX_LEN: usize = 1523;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_ulong};
    extern "C" {
        #[link_name = "nextssl__gea3__shim_apply"]
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
    Len::fixed(8)
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
        for (k, n, d, o) in [("2bd6459f82c5bc00", "8e9421a300", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "5f359709de950d0105b17b6c90194280f880b48dccdc2afeed415dbef4354eebb21d073ccbbfb2d706bd7affd371fc96e3970d143dcb2624054826"), ("952c49104881ff48", "5064db7100", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "fdc03d738c8e14ff0320e59aaf75760799e9da78dd8f888471c4aeaac1849633a26cd84f459d265b83d7d9b9a0b1e54f4d75e331640df19e0db0e0"), ("efa8b2229e720c2a", "4bdbd5e501", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "4718a2adfc90590949ddadab406ec3b925f1af1214673909daab96bb4c18b1374bb1e99445a81cc856e47c6e49e9dbb9873d0831b2175ca1e109ba"), ("3451f23a43bd2c87", "893fe14f00", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "b46b1e284e3f8b63b86d9df0915cfceddf2f061895bf9f82bf2593ae4847e94a4626c393cf8941ce15ea7812690d8415b88c5730fe1f5d410e16a2")] {
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
