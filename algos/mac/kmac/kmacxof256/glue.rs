//! Adapter: `tiny-keccak` (NIST SP 800-185 KMAC256XOF) -> nextssl `Mac`.
//!
//! Param `custom` is the customisation string S (0..=65536 bytes, default empty). KMACXOF: the requested output length is NOT encoded into the customisation (L = 0), so shorter
//! tags are prefixes of longer ones.
//! Key 1..=268435456 bytes (empty key refused), tag 16..=1024 bytes.
//! Upstream keeps its sponge state in a plain array and does not zeroize it on drop; this is a
//! known limitation of the pinned crate (rule 9 gap, recorded for the owner).

use nextssl_core::{Len, Mac, Params, Result, Sizes, SymmetricKey};
use tiny_keccak::{Hasher, IntoXof, Kmac, Xof};

const KEY_MIN: usize = 1;
const KEY_MAX: usize = 268435456;
const TAG_MIN: usize = 16;
const TAG_MAX: usize = 1024;
const MAX_CUSTOM: usize = 65536;

struct Impl {
    custom: Vec<u8>,
}

impl Mac for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(KEY_MIN, KEY_MAX)),
            tag: Some(Len::range(TAG_MIN, TAG_MAX)),
            ..Sizes::NONE
        }
    }

    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(KEY_MIN, KEY_MAX).check("key", key.len())?;
        Len::range(TAG_MIN, TAG_MAX).check("tag", out.len())?;
        let mut k = Kmac::v256(key.as_bytes(), &self.custom);
        k.update(data);
        let mut x = k.into_xof();
        x.squeeze(out);
        Ok(())
    }
}

/// Registry constructor. Optional parameter `custom` (0..=65536 bytes).
pub fn new(params: &Params) -> Result<Box<dyn Mac>> {
    let custom = params.get_bytes("custom").unwrap_or(&[]);
    nextssl_core::check_len("custom", custom.len(), 0, MAX_CUSTOM)?;
    Ok(Box::new(Impl {
        custom: custom.to_vec(),
    }))
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
        let custom = v["custom_hex"].as_str().map(unhex).unwrap_or_default();
        let mut p = Params::new();
        if !custom.is_empty() {
            p.set("custom", nextssl_core::Value::Bytes(custom));
        }
        new(&p).unwrap()
    }

    fn mac() -> Box<dyn Mac> {
        make(&J::Null)
    }

    #[test]
    fn sizes_match_metadata() {
        let s = mac().sizes();
        assert_eq!(s.key, Some(Len::range(1, 268435456)));
        assert_eq!(s.tag, Some(Len::range(16, 1024)));
    }

    #[test]
    fn known_answers() {
        let mut total = 0;
        for file in ["nist-sp800-185-samples.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "kmacxof256");
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
        for bad in [0, 15, 1025] {
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
