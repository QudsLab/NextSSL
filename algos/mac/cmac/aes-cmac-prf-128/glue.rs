//! Adapter: RustCrypto `cmac` + `aes` -> AES-CMAC-PRF-128 (RFC 4615) as a nextssl `Mac`.
//!
//! RFC 4615 section 3.1: a 16-byte key is used directly; any other key length VK first becomes
//! K = AES-CMAC(0^128, VK). The only code that is ours is that one call (a composition of the
//! upstream primitive exactly as the RFC states it). Key 1..=2^28 bytes, tag exactly 16 bytes.

use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac as _};
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey, Zeroize};

const KEY_MAX: usize = 1 << 28;
const TAG_LEN: usize = 16;

struct Impl;

type C = Cmac<Aes128>;

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(1, KEY_MAX)),
            tag: Some(Len::fixed(TAG_LEN)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, KEY_MAX).check("key", key.len())?;
        Len::fixed(TAG_LEN).check("tag", out.len())?;
        let mut k = [0u8; 16];
        if key.len() == 16 {
            k.copy_from_slice(key.as_bytes());
        } else {
            let mut z = <C as KeyInit>::new_from_slice(&[0u8; 16])
                .map_err(|_| Error::Backend("aes-cmac-prf zero key"))?;
            z.update(key.as_bytes());
            let mut derived = z.finalize().into_bytes();
            k.copy_from_slice(derived.as_slice());
            derived.as_mut_slice().zeroize();
        }
        let r = <C as KeyInit>::new_from_slice(&k)
            .map_err(|_| Error::Backend("aes-cmac-prf key setup"));
        k.zeroize();
        let mut mac = r?;
        mac.update(data);
        let mut full = mac.finalize().into_bytes();
        out.copy_from_slice(full.as_slice());
        full.as_mut_slice().zeroize();
        Ok(())
    }
}

/// Registry constructor. AES-CMAC-PRF-128 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
    Ok(Box::new(Impl))
}

#[cfg(test)]
#[allow(clippy::single_element_loop)]
mod tests {
    use super::*;
    use nextssl_core::Error;
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

    #[allow(unused_variables)]
    fn make(v: &J) -> Box<dyn Mac> {
        new(&Params::new()).unwrap()
    }

    fn mac() -> Box<dyn Mac> {
        make(&J::Null)
    }

    #[test]
    fn sizes_match_metadata() {
        let s = mac().sizes();
        assert_eq!(s.key, Some(Len::range(1, 268435456)));
        assert_eq!(s.tag, Some(Len::fixed(16)));
    }

    #[test]
    fn known_answers() {
        let mut total = 0;
        for file in ["rfc4615.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "aes-cmac-prf-128");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let m = make(v);
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let data = unhex(v["data_hex"].as_str().unwrap());
                let want = unhex(v["tag_hex"].as_str().unwrap());
                let mut got = vec![0u8; want.len()];
                m.tag(&k, &data, &mut got).unwrap();
                assert_eq!(got, want, "{id}");
                assert!(m.verify(&k, &data, &want).unwrap(), "{id}");
                for pos in 0..want.len() {
                    let mut bad = want.clone();
                    bad[pos] ^= 0x80;
                    assert!(!m.verify(&k, &data, &bad).unwrap(), "{id} bitflip {pos}");
                }
                // Different data is rejected (unless the key is degenerate and the tag is data-independent).
                let mut other = data.clone();
                other.push(0);
                let mut alt = vec![0u8; want.len()];
                m.tag(&k, &other, &mut alt).unwrap();
                if alt != want {
                    assert!(!m.verify(&k, &other, &want).unwrap(), "{id}");
                }
                total += 1;
            }
        }
        assert!(total >= 3, "too few vectors ran: {total}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = mac();
        let k = key(&[1u8; 32]);
        for bad in [0, 15, 17] {
            let mut out = vec![0xAAu8; bad];
            assert!(
                matches!(m.tag(&k, b"x", &mut out), Err(Error::InvalidLength { .. })),
                "tag {bad}"
            );
            assert!(out.iter().all(|&b| b == 0xAA), "output written on error");
            assert!(
                matches!(
                    m.verify(&k, b"x", &vec![0u8; bad]),
                    Err(Error::InvalidLength { .. })
                ),
                "verify tag {bad}"
            );
        }
        for bad in [0] {
            assert!(
                matches!(
                    m.tag(&key(&vec![1u8; bad]), b"x", &mut [0u8; 16]),
                    Err(Error::InvalidLength { .. })
                ),
                "key {bad}"
            );
        }
    }
}
