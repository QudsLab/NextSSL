//! Adapter: Ascon-CXOF128 (ascon-c reference C) (C, verbatim) -> nextssl `Xof`.
//! Parameter `custom` is the customization string Z (0..=256 bytes, i.e. 2048 bits, default empty).

use core::ffi::{c_int, c_ulonglong};
use nextssl_core::{Error, Len, Params, Result, Xof};

const MAX_CUSTOM: usize = 256;

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__ascon_cxof128__xof"]
        fn xof(
            out: *mut u8,
            outlen: c_ulonglong,
            input: *const u8,
            inlen: c_ulonglong,
            cs: *const u8,
            cslen: c_ulonglong,
        ) -> c_int;
    }

    /// Precondition (checked by the caller): `out` is non-empty, `cs.len() <= MAX_CUSTOM`.
    #[allow(unsafe_code)]
    pub(super) fn run(out: &mut [u8], data: &[u8], cs: &[u8]) -> bool {
        // SAFETY: all three pointers come from live slices whose lengths are passed alongside; the
        // callee writes exactly `out.len()` bytes to `out` and keeps no pointer.
        unsafe {
            xof(
                out.as_mut_ptr(),
                out.len() as c_ulonglong,
                data.as_ptr(),
                data.len() as c_ulonglong,
                cs.as_ptr(),
                cs.len() as c_ulonglong,
            ) == 0
        }
    }
}

struct Impl {
    custom: Vec<u8>,
}

impl Xof for Impl {
    fn squeeze(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, usize::MAX).check("out", out.len())?;
        if ffi::run(out, data, &self.custom) {
            Ok(())
        } else {
            Err(Error::Backend("ascon-cxof128: xof failed"))
        }
    }
}

/// Registry constructor. Optional parameter `custom` (0..=256 bytes).
pub fn new(params: &Params) -> Result<Box<dyn Xof>> {
    let custom = params.get_bytes("custom").unwrap_or(&[]);
    nextssl_core::check_len("custom", custom.len(), 0, MAX_CUSTOM)?;
    Ok(Box::new(Impl {
        custom: custom.to_vec(),
    }))
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

    #[test]
    fn known_answers() {
        let mut total = 0;
        for file in ["ascon-cxof128.json"] {
            let doc = load(file);
            assert_eq!(doc["algorithm"], "ascon-cxof128");
            for v in doc["vectors"].as_array().unwrap() {
                let msg = unhex(v["msg_hex"].as_str().unwrap());
                let want = unhex(v["out_hex"].as_str().unwrap());
                let custom = unhex(v["custom_hex"].as_str().unwrap());
                let x = new(&Params::new().with("custom", Value::Bytes(custom))).unwrap();
                let mut got = vec![0u8; want.len()];
                x.squeeze(&msg, &mut got).unwrap();
                assert_eq!(got, want, "{}", v["id"]);
                // Prefix property of an XOF.
                let mut shorter = vec![0u8; 17];
                x.squeeze(&msg, &mut shorter).unwrap();
                assert_eq!(&shorter[..], &want[..17], "prefix {}", v["id"]);
                total += 1;
            }
        }
        assert!(total >= 30, "too few vectors ran: {total}");
    }

    #[test]
    fn rejects_bad_input() {
        let x = new(&Params::new()).unwrap();
        assert!(x.squeeze(b"x", &mut []).is_err());
        let p = Params::new().with("custom", Value::Bytes(vec![0; MAX_CUSTOM + 1]));
        assert!(new(&p).is_err());
    }
}
