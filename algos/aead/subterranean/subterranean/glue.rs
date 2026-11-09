//! Adapter: Subterranean 2.0 AEAD (rweather/lightweight-crypto) (C, verbatim) -> nextssl `Aead`.
//! Output of `seal` is `ciphertext || tag`. All lengths are checked here before the C call;
//! the C side is a thin dispatcher (shim.c).

use core::ffi::{c_int, c_ulonglong};
use nextssl_core::{Aead, Error, Len, Params, Result, Sizes, SymmetricKey, Zeroizing};

struct Variant {
    #[allow(dead_code)]
    name: &'static str,
    key: usize,
    nonce: usize,
    tag: usize,
}

const VARIANTS: &[Variant] = &[Variant {
    name: "subterranean",
    key: 16,
    nonce: 16,
    tag: 16,
}];

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__subterranean__seal"]
        fn seal(
            v: c_int,
            c: *mut u8,
            clen: *mut c_ulonglong,
            m: *const u8,
            mlen: c_ulonglong,
            ad: *const u8,
            adlen: c_ulonglong,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__subterranean__open"]
        fn open(
            v: c_int,
            m: *mut u8,
            mlen: *mut c_ulonglong,
            c: *const u8,
            clen: c_ulonglong,
            ad: *const u8,
            adlen: c_ulonglong,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;
    }

    /// Precondition (checked by callers): `key` and `nonce` have the variant's exact lengths and
    /// `out.len() == pt.len() + tag`.
    #[allow(unsafe_code)]
    pub(super) fn seal_raw(
        v: usize,
        out: &mut [u8],
        pt: &[u8],
        ad: &[u8],
        nonce: &[u8],
        key: &[u8],
    ) -> Option<usize> {
        let mut clen: c_ulonglong = 0;
        // SAFETY: every pointer comes from a live slice whose length was validated against the
        // variant sizes; `out` has room for plaintext + tag, which is all the callee writes; the
        // callee keeps no pointer. Zero-length slices yield non-null aligned pointers.
        let rc = unsafe {
            seal(
                v as c_int,
                out.as_mut_ptr(),
                &mut clen,
                pt.as_ptr(),
                pt.len() as c_ulonglong,
                ad.as_ptr(),
                ad.len() as c_ulonglong,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };
        if rc == 0 {
            Some(clen as usize)
        } else {
            None
        }
    }

    /// Precondition: as above, `ct.len() >= tag`, `out.len() == ct.len()`. Returns (rc, mlen).
    #[allow(unsafe_code)]
    pub(super) fn open_raw(
        v: usize,
        out: &mut [u8],
        ct: &[u8],
        ad: &[u8],
        nonce: &[u8],
        key: &[u8],
    ) -> (i32, usize) {
        let mut mlen: c_ulonglong = 0;
        // SAFETY: as in `seal_raw`; the callee writes at most `ct.len() - tag` plaintext bytes to
        // `out`, which holds `ct.len()` bytes.
        let rc = unsafe {
            open(
                v as c_int,
                out.as_mut_ptr(),
                &mut mlen,
                ct.as_ptr(),
                ct.len() as c_ulonglong,
                ad.as_ptr(),
                ad.len() as c_ulonglong,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };
        (rc, mlen as usize)
    }
}

struct Impl {
    idx: usize,
}

impl Impl {
    fn v(&self) -> &'static Variant {
        &VARIANTS[self.idx]
    }

    fn check(&self, key: &SymmetricKey, nonce: &[u8]) -> Result<()> {
        Len::fixed(self.v().key).check("key", key.len())?;
        Len::fixed(self.v().nonce).check("nonce", nonce.len())
    }
}

impl Aead for Impl {
    fn sizes(&self) -> Sizes {
        let v = self.v();
        Sizes {
            key: Some(Len::fixed(v.key)),
            nonce: Some(Len::fixed(v.nonce)),
            tag: Some(Len::fixed(v.tag)),
            ..Sizes::NONE
        }
    }

    fn seal(&self, key: &SymmetricKey, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce)?;
        let mut out = vec![0u8; pt.len() + self.v().tag];
        match ffi::seal_raw(self.idx, &mut out, pt, aad, nonce, key.as_bytes()) {
            Some(n) if n == out.len() => Ok(out),
            Some(_) => Err(Error::Backend("subterranean: unexpected output length")),
            None => Err(Error::Backend("subterranean: seal failed")),
        }
    }

    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce)?;
        let tag = self.v().tag;
        Len::range(tag, usize::MAX).check("ciphertext", ct.len())?;
        let mut out = Zeroizing::new(vec![0u8; ct.len()]);
        let (rc, n) = ffi::open_raw(self.idx, &mut out, ct, aad, nonce, key.as_bytes());
        if rc == -1 {
            return Err(Error::AuthenticationFailed);
        }
        if rc != 0 || n != ct.len() - tag {
            return Err(Error::Backend("subterranean: open failed"));
        }
        out.truncate(n);
        Ok(out)
    }
}

/// Registry constructor.
pub fn new(params: &Params) -> Result<Box<dyn Aead>> {
    let _ = params;
    let idx = 0;
    Ok(Box::new(Impl { idx }))
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

    fn make(v: &J) -> Box<dyn Aead> {
        let mut p = Params::new();
        if let Some(n) = v
            .get("params")
            .and_then(|x| x.get("variant"))
            .and_then(J::as_str)
        {
            p.set("variant", Value::Str(n.to_string()));
        }
        new(&p).unwrap()
    }

    #[test]
    fn known_answers() {
        let mut total = 0;
        for file in ["subterranean.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "subterranean");
            for v in doc["vectors"].as_array().unwrap() {
                let id = v["id"].as_str().unwrap();
                let a = make(v);
                let k = key(&unhex(v["key_hex"].as_str().unwrap()));
                let nonce = unhex(v["nonce_hex"].as_str().unwrap());
                let aad = unhex(v["aad_hex"].as_str().unwrap());
                let pt = unhex(v["pt_hex"].as_str().unwrap());
                let ct = unhex(v["ct_hex"].as_str().unwrap());
                assert_eq!(a.seal(&k, &nonce, &aad, &pt).unwrap(), ct, "seal {id}");
                assert_eq!(
                    &a.open(&k, &nonce, &aad, &ct).unwrap()[..],
                    &pt[..],
                    "open {id}"
                );
                if total % 7 == 0 {
                    for pos in [0, ct.len() / 2, ct.len() - 1] {
                        let mut t = ct.clone();
                        t[pos] ^= 1;
                        assert_eq!(
                            a.open(&k, &nonce, &aad, &t).unwrap_err(),
                            Error::AuthenticationFailed,
                            "bitflip {pos} {id}"
                        );
                    }
                    let mut bad_aad = aad.clone();
                    bad_aad.push(0);
                    assert_eq!(
                        a.open(&k, &nonce, &bad_aad, &ct).unwrap_err(),
                        Error::AuthenticationFailed,
                        "aad {id}"
                    );
                }
                total += 1;
            }
        }
        assert!(total >= 30, "too few vectors ran: {total}");
    }

    #[test]
    fn rejects_bad_lengths() {
        for var in VARIANTS {
            let a = new(&Params::new().with("variant", Value::Str(var.name.to_string())))
                .or_else(|_| new(&Params::new()))
                .unwrap();
            let s = a.sizes();
            let (kl, nl, tl) = (
                s.key.unwrap().max(),
                s.nonce.unwrap().max(),
                s.tag.unwrap().max(),
            );
            let k = key(&vec![1u8; kl]);
            let n = vec![2u8; nl];
            for bad in [0, kl.wrapping_sub(1), kl + 1] {
                if bad == kl {
                    continue;
                }
                assert!(
                    matches!(
                        a.seal(&key(&vec![1u8; bad]), &n, b"", b"x"),
                        Err(Error::InvalidLength { .. })
                    ),
                    "key {bad}"
                );
            }
            for bad in [nl + 1, nl + 12] {
                assert!(
                    matches!(
                        a.seal(&k, &vec![2u8; bad], b"", b"x"),
                        Err(Error::InvalidLength { .. })
                    ),
                    "nonce {bad}"
                );
            }
            if nl > 0 {
                assert!(matches!(
                    a.seal(&k, &n[..nl - 1], b"", b"x"),
                    Err(Error::InvalidLength { .. })
                ));
            }
            for bad in 0..tl {
                assert!(
                    matches!(
                        a.open(&k, &n, b"", &vec![0u8; bad]),
                        Err(Error::InvalidLength { .. })
                    ),
                    "ct {bad}"
                );
            }
        }
    }
}
