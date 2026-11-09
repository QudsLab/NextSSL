//! Adapter: RustCrypto `hmac` + `sha2` (HMAC-SHA-256, RFC 2104 / FIPS 198-1) -> nextssl `Mac`.
//!
//! Key: 1..=2^28 bytes (empty key refused). Tag: 16..=32 bytes; the tag is the leftmost
//! `out.len()` bytes of the full 32-byte HMAC, so truncation happens only when the caller asks
//! for a declared shorter length. Verification is constant time (trait default over `ct_eq`).

use hmac::{Hmac, KeyInit, Mac as _};
use nextssl_core::{Error, Len, Mac, Params, Result, Sizes, SymmetricKey, Zeroize};
use sha2::Sha256;

const KEY_MIN: usize = 1;
const KEY_MAX: usize = 1 << 28;
const TAG_MIN: usize = 16;
const TAG_MAX: usize = 32;

struct HmacSha256;

impl Mac for HmacSha256 {
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
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes())
            .map_err(|_| Error::Backend("hmac-sha256 key setup"))?;
        mac.update(data);
        let mut full = mac.finalize().into_bytes();
        out.copy_from_slice(&full.as_slice()[..out.len()]);
        full.as_mut_slice().zeroize();
        Ok(())
    }
}

/// Registry constructor. HMAC-SHA-256 takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Mac>> {
    Ok(Box::new(HmacSha256))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn mac() -> Box<dyn Mac> {
        new(&Params::new()).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = mac().sizes();
        assert_eq!(s.key, Some(Len::range(1, 268_435_456)));
        assert_eq!(s.tag, Some(Len::range(16, 32)));
    }

    #[test]
    fn rfc4231_kats() {
        let m = mac();
        let doc = load("rfc4231.json");
        assert_eq!(doc["algorithm"], "hmac-sha256");
        let mut n = 0;
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let k = key(&unhex(v["key_hex"].as_str().unwrap()));
            let data = unhex(v["data_hex"].as_str().unwrap());
            let want = unhex(v["tag_hex"].as_str().unwrap());
            let mut got = vec![0u8; want.len()];
            m.tag(&k, &data, &mut got).unwrap();
            assert_eq!(got, want, "{id}");
            assert!(m.verify(&k, &data, &want).unwrap(), "{id}");
            // Any single flipped bit in the tag is rejected.
            for pos in 0..want.len() {
                let mut bad = want.clone();
                bad[pos] ^= 0x80;
                assert!(!m.verify(&k, &data, &bad).unwrap(), "{id} bitflip {pos}");
            }
            // Different data is rejected.
            let mut other = data.clone();
            other.push(0);
            assert!(!m.verify(&k, &other, &want).unwrap(), "{id}");
            n += 1;
        }
        assert_eq!(n, 7);
    }

    #[test]
    fn wycheproof() {
        let m = mac();
        let doc = load("wycheproof_hmac_sha256_test.json");
        let (mut valid, mut invalid) = (0usize, 0usize);
        for g in doc["testGroups"].as_array().unwrap() {
            let tag_bytes = usize::try_from(g["tagSize"].as_u64().unwrap()).unwrap() / 8;
            for t in g["tests"].as_array().unwrap() {
                let tc = t["tcId"].as_u64().unwrap();
                let k = key(&unhex(t["key"].as_str().unwrap()));
                let msg = unhex(t["msg"].as_str().unwrap());
                let tag = unhex(t["tag"].as_str().unwrap());
                assert_eq!(tag.len(), tag_bytes, "tcId {tc}");
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        let mut got = vec![0u8; tag.len()];
                        m.tag(&k, &msg, &mut got).unwrap();
                        assert_eq!(got, tag, "tcId {tc}");
                        assert!(m.verify(&k, &msg, &tag).unwrap(), "tcId {tc}");
                        valid += 1;
                    }
                    "invalid" => {
                        assert!(
                            !m.verify(&k, &msg, &tag).unwrap(),
                            "invalid tag accepted, tcId {tc}"
                        );
                        invalid += 1;
                    }
                    other => panic!("tcId {tc}: unexpected result {other:?}"),
                }
            }
        }
        let total = usize::try_from(doc["numberOfTests"].as_u64().unwrap()).unwrap();
        assert_eq!(valid + invalid, total, "not every Wycheproof case ran");
        assert!(valid > 0 && invalid > 0);
        eprintln!("wycheproof: total {total}, valid {valid}, invalid rejected {invalid}");
    }

    #[test]
    fn rejects_bad_lengths() {
        let m = mac();
        let k = key(&[1u8; 32]);
        for bad in [0usize, 1, 15, 33, 64] {
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
        let empty = key(&[]);
        assert!(matches!(
            m.tag(&empty, b"x", &mut [0u8; 32]),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn truncated_tag_is_a_prefix_of_the_full_tag() {
        let m = mac();
        let k = key(b"truncation key");
        let mut full = [0u8; 32];
        m.tag(&k, b"data", &mut full).unwrap();
        for len in 16..=32 {
            let mut t = vec![0u8; len];
            m.tag(&k, b"data", &mut t).unwrap();
            assert_eq!(t, full[..len]);
        }
    }
}
