//! Adapter: libosmocore TUAK f2/f3/f4/f5 (3GPP TS 35.231, Keccak-based, GPL-2.0-or-later, verbatim C, symbols renamed `nextssl__tuak__*`) -> nextssl `Kdf`.
//! Glue only, no crypto logic. Shape: ikm = K (16 or 32), salt = RAND (16), info = TOPc (32), output = RES || CK || IK || AK(6);
//! res_len / ck_len / ik_len / keccak_iterations are params and out.len() must match them exactly.

use nextssl_core::{Error, Kdf, Len, Params, Result, Sizes, SymmetricKey};

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::c_int;
    extern "C" {
        #[link_name = "nextssl__tuak__shim_derive"]
        pub fn derive(topc: *const u8, k: *const u8, klen: core::ffi::c_ulong, rnd: *const u8, res_len: core::ffi::c_ulong, ck_len: core::ffi::c_ulong, ik_len: core::ffi::c_ulong, iters: core::ffi::c_ulong, out: *mut u8) -> c_int;
    }
}

const MIN_OUT: usize = 4 + 16 + 16 + 6;
const MAX_OUT: usize = 32 + 32 + 32 + 6;

struct Impl {
    res_len: usize,
    ck_len: usize,
    ik_len: usize,
    iters: u32,
}

impl Kdf for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(16, 32)),
            salt: Some(Len::fixed(16)),
            info: Some(Len::fixed(32)),
            out: Some(Len::range(MIN_OUT, MAX_OUT)),
            ..Sizes::NONE
        }
    }

    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        let kl = ikm.len();
        if kl != 16 && kl != 32 {
            return Err(Error::InvalidLength { what: "ikm", got: kl, min: 16, max: 32 });
        }
        Len::fixed(16).check("salt", salt.len())?;
        Len::fixed(32).check("info", info.len())?;
        let want = self.res_len + self.ck_len + self.ik_len + 6;
        if out.len() != want {
            return Err(Error::BadOutputLen { expected: want, got: out.len() });
        }
        // SAFETY: info is valid for 32 bytes, ikm for kl (16 or 32), salt for 16 (all checked), out for exactly
        // res_len + ck_len + ik_len + 6 bytes (checked, and each length is one of the validated set); the callee keeps no pointer.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::derive(
                info.as_ptr(),
                ikm.as_bytes().as_ptr(),
                kl as core::ffi::c_ulong,
                salt.as_ptr(),
                self.res_len as core::ffi::c_ulong,
                self.ck_len as core::ffi::c_ulong,
                self.ik_len as core::ffi::c_ulong,
                self.iters as core::ffi::c_ulong,
                out.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Backend("tuak failed"));
        }
        Ok(())
    }
}

/// Registry constructor.
pub fn new(params: &Params) -> Result<Box<dyn Kdf>> {
    let res_len = params.get_u32("res_len").unwrap_or(4) as usize;
    let ck_len = params.get_u32("ck_len").unwrap_or(16) as usize;
    let ik_len = params.get_u32("ik_len").unwrap_or(16) as usize;
    let iters = params.get_u32("keccak_iterations").unwrap_or(1);
    if !matches!(res_len, 4 | 8 | 16 | 32) {
        return Err(Error::ParamOutOfRange("res_len"));
    }
    if !matches!(ck_len, 16 | 32) {
        return Err(Error::ParamOutOfRange("ck_len"));
    }
    if !matches!(ik_len, 16 | 32) {
        return Err(Error::ParamOutOfRange("ik_len"));
    }
    if !(1..=1024).contains(&iters) {
        return Err(Error::ParamOutOfRange("keccak_iterations"));
    }
    Ok(Box::new(Impl { res_len, ck_len, ik_len, iters }))
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

    fn inst(res: u32, ck: u32, ik: u32, it: u32) -> Box<dyn Kdf> {
        new(&Params::new()
            .with("res_len", nextssl_core::Value::U32(res))
            .with("ck_len", nextssl_core::Value::U32(ck))
            .with("ik_len", nextssl_core::Value::U32(ik))
            .with("keccak_iterations", nextssl_core::Value::U32(it)))
        .unwrap()
    }

    #[test]
    fn known_answers() {
        for (k, rnd, topc, it, rl, cl, il, o) in [
            ("abababababababababababababababab", "42424242424242424242424242424242", "bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff", 1, 4, 16, 16, "657acd64d71a1e5c6caffe986a26f783e5c78be1be849fa2564f869aecee6f62d4337e72719f1e9b9054"),
            ("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", "0123456789abcdef0123456789abcdef", "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524", 1, 8, 16, 16, "e9d749dc4eea0035a4cb6f6529ab17f8337f27baa8234d472274155ccf4199d5e2abcbf621907f90480a9345cc1e"),
            ("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", "0123456789abcdef0123456789abcdef", "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524", 1, 8, 16, 32, "07021c73e7635c7d4d59ac796834eb85d11fa148a5058c3c126d47500136fdc5ddfd14f19ebf16749ce4b6435323fbb5715a3a796a6082bd1d6622c4e59a"),
            ("b8da837a50652d6ac7c97da14f6acc61", "6887e55425a966bd86c9661a5fa72be8", "2bc16eb657a68e1f446f08f57c0efb1d493527a2e652ce281eb6ca0e4487760a", 1, 16, 16, 16, "4041ce438e3e38e8aa96562eed83ac433e3bc01bea0cd914c4c2c83ce2d92757666a8e6f577b1aa77b7fd53cebb8a3d61f880d005119"),
            ("1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5", "c570aac68cde651fb1e3088322498bef", "3c6052e41532a28a47aa3cbb89f223e8f3aaa976aecd48bc3e7d6165a55eff62", 1, 32, 32, 16, "84d89b41db1867ffd4c7ba1d82163f4d526a20fbae5418fbb526940b1eeb905cd419676afe5ab58c1d8bee0d43523a4d2f52ef0b31a4676a0c334427a988fe65205533e505661b61d05cc0eac87818f4d7b3d2d4980a"),
            ("1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5", "c570aac68cde651fb1e3088322498bef", "b04a66f26c62fcd6c82de22a179ab65506ecf47f56245cd149966cfa9cec7a51", 2, 32, 32, 32, "d67e6e64590d22eecba7324afa4af4460c93f01b24506d6e12047d789a94c867ede57edfc57cdffe1aae75066a1b7479bbc3837438e88d37a801cccc9f972b8948ed9299126e5057402fe01f9201cf25249f9c5c0ed2afcf084755daff1d39996aae8d18c448")
        ] {
            let kdf = inst(rl, cl, il, it);
            let mut out = vec![0u8; (rl + cl + il) as usize + 6];
            kdf.derive(&key(&unhex(k)), &unhex(rnd), &unhex(topc), &mut out).unwrap();
            assert_eq!(out, unhex(o));
        }
    }

    #[test]
    fn deterministic_and_lengths() {
        let k = new(&Params::new()).unwrap();
        let kk = key(&[0x11u8; 16]);
        let (mut a, mut b) = ([0u8; MIN_OUT], [0u8; MIN_OUT]);
        k.derive(&kk, &[0x22u8; 16], &[0x33u8; 32], &mut a).unwrap();
        k.derive(&kk, &[0x22u8; 16], &[0x33u8; 32], &mut b).unwrap();
        assert_eq!(a, b);
        k.derive(&kk, &[0x22u8; 16], &[0x34u8; 32], &mut b).unwrap();
        assert_ne!(a, b);
        assert!(k.derive(&key(&[0u8; 24]), &[0u8; 16], &[0u8; 32], &mut a).is_err());
        assert!(k.derive(&kk, &[0u8; 15], &[0u8; 32], &mut a).is_err());
        assert!(k.derive(&kk, &[0u8; 16], &[0u8; 31], &mut a).is_err());
        assert!(k.derive(&kk, &[0u8; 16], &[0u8; 32], &mut [0u8; MIN_OUT + 1]).is_err());
        assert!(new(&Params::new().with("res_len", nextssl_core::Value::U32(5))).is_err());
    }
}
