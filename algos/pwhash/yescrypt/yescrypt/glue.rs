//! Adapter: yescrypt reference C (Peslyak, verbatim) -> nextssl `PwHash`, YESCRYPT_DEFAULTS flavour.
//!
//! Policy (the DoS guard): `ln` (log2 N) 2..=20, `r` 1..=32, `p` 1..=16, `t` 0..=255, and the
//! working memory 128 * r * 2^ln must not exceed 2^30 bytes (1 GiB); salt 0..=64 bytes, output
//! 16..=1024 bytes. The same ranges apply to a PHC string read by `verify`, before any memory is
//! allocated. PHC form: `$yescrypt$ln=<n>,r=<n>,p=<n>,t=<n>$<salt>$<hash>` (NextSSL framing; the
//! native `$y$` crypt format is not used).

use core::ffi::{c_int, c_void};
use nextssl_core::phc::{self, PhcParam, PhcSpec};
use nextssl_core::{
    ct_eq, Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
    MAX_INPUT_LEN,
};

const LN_MIN: u32 = 2;
const LN_MAX: u32 = 20;
const R_MIN: u32 = 1;
const R_MAX: u32 = 32;
const P_MIN: u32 = 1;
const P_MAX: u32 = 16;
const T_MIN: u32 = 0;
const T_MAX: u32 = 255;
const MEM_MAX: u64 = 1 << 30;
const SALT_MIN: usize = 0;
const SALT_MAX: usize = 64;
const OUT_MIN: usize = 16;
const OUT_MAX: usize = 1024;

const PHC: PhcSpec = PhcSpec {
    id: "yescrypt",
    version: None,
    params: &[
        PhcParam {
            name: "ln",
            min: LN_MIN,
            max: LN_MAX,
        },
        PhcParam {
            name: "r",
            min: R_MIN,
            max: R_MAX,
        },
        PhcParam {
            name: "p",
            min: P_MIN,
            max: P_MAX,
        },
        PhcParam {
            name: "t",
            min: T_MIN,
            max: T_MAX,
        },
    ],
    salt: Len::range(SALT_MIN, SALT_MAX),
    hash: Len::range(OUT_MIN, OUT_MAX),
};

const SPECS: [ParamSpec; 5] = [
    spec("ln", LN_MIN, LN_MAX, 14),
    spec("r", R_MIN, R_MAX, 8),
    spec("p", P_MIN, P_MAX, 1),
    spec("t", T_MIN, T_MAX, 0),
    spec("out_len", OUT_MIN as u32, OUT_MAX as u32, 32),
];

const fn spec(name: &'static str, min: u32, max: u32, default: u32) -> ParamSpec {
    ParamSpec {
        name,
        ty: ParamType::U32,
        min: min as u64,
        max: max as u64,
        required: false,
        default: Some(default as u64),
    }
}

mod ffi {
    use super::*;

    extern "C" {
        #[link_name = "nextssl__yescrypt__kdf"]
        #[allow(clippy::too_many_arguments)]
        fn kdf(
            pw: *const c_void,
            pwlen: usize,
            salt: *const c_void,
            saltlen: usize,
            ln: u32,
            r: u32,
            p: u32,
            t: u32,
            out: *mut c_void,
            outlen: usize,
        ) -> c_int;
    }

    /// Precondition (checked by callers in this crate): cost within policy, salt and output
    /// lengths within range.
    #[allow(unsafe_code)]
    pub(super) fn run(cost: super::Cost, pw: &[u8], salt: &[u8], out: &mut [u8]) -> bool {
        // SAFETY: all pointers come from valid slices and are read/written only for the lengths
        // passed alongside them; the callee keeps no pointer after returning. Zero-length slices
        // give non-null aligned pointers, which the callee accepts for length 0. Its allocation
        // (128 * r * 2^ln bytes) is bounded by the policy checked in `Cost::check`.
        let rc = unsafe {
            kdf(
                pw.as_ptr().cast(),
                pw.len(),
                salt.as_ptr().cast(),
                salt.len(),
                cost.ln,
                cost.r,
                cost.p,
                cost.t,
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        rc == 0
    }
}

#[derive(Clone, Copy)]
struct Cost {
    ln: u32,
    r: u32,
    p: u32,
    t: u32,
}

impl Cost {
    fn check(self) -> Result<()> {
        in_range("ln", self.ln, LN_MIN, LN_MAX)?;
        in_range("r", self.r, R_MIN, R_MAX)?;
        in_range("p", self.p, P_MIN, P_MAX)?;
        in_range("t", self.t, T_MIN, T_MAX)?;
        if 128u64 * u64::from(self.r) * (1u64 << self.ln) > MEM_MAX {
            return Err(Error::ParamOutOfRange("ln"));
        }
        Ok(())
    }
}

fn in_range(name: &'static str, v: u32, min: u32, max: u32) -> Result<()> {
    if (min..=max).contains(&v) {
        Ok(())
    } else {
        Err(Error::ParamOutOfRange(name))
    }
}

fn check_salt(salt: &[u8]) -> Result<()> {
    Len::range(SALT_MIN, SALT_MAX).check("salt", salt.len())
}

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, MAX_INPUT_LEN).check("password", password.len())
}

/// Raw yescrypt. Callers have already validated `cost`, `salt` and `out.len()`.
fn run(cost: Cost, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
    if ffi::run(cost, password, salt, out) {
        Ok(())
    } else {
        Err(Error::Backend("yescrypt failed"))
    }
}

struct Impl {
    cost: Cost,
    out_len: usize,
}

impl PwHash for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            salt: Some(Len::range(SALT_MIN, SALT_MAX)),
            out: Some(Len::range(OUT_MIN, OUT_MAX)),
            ..Sizes::NONE
        }
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String> {
        let mut out = Zeroizing::new(vec![0u8; self.out_len]);
        self.derive(password, salt, &mut out)?;
        phc::write(
            &PHC,
            &[self.cost.ln, self.cost.r, self.cost.p, self.cost.t],
            salt,
            &out,
        )
    }

    fn verify(&self, password: &[u8], phc_str: &str) -> Result<bool> {
        check_password(password)?;
        let p = phc::parse(phc_str, &PHC)?;
        let cost = Cost {
            ln: p.params[0],
            r: p.params[1],
            p: p.params[2],
            t: p.params[3],
        };
        // Cross-parameter memory bound, before any allocation.
        cost.check()?;
        let mut mine = Zeroizing::new(vec![0u8; p.hash.len()]);
        run(cost, password, &p.salt, &mut mine)?;
        Ok(ct_eq(&mine, &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        check_salt(salt)?;
        Len::range(OUT_MIN, OUT_MAX).check("out", out.len())?;
        run(self.cost, password, salt, out)
    }
}

fn get(params: &Params, name: &'static str) -> Result<u32> {
    match params.get(name) {
        Some(Value::U32(v)) => Ok(*v),
        _ => Err(Error::ParamType(name)),
    }
}

/// Registry constructor. Parameters: `ln`, `r`, `p`, `t`, `out_len` (all `u32`; defaults and
/// ranges in `algo.toml`). Unknown names and out-of-range values are errors.
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    let cost = Cost {
        ln: get(&v, "ln")?,
        r: get(&v, "r")?,
        p: get(&v, "p")?,
        t: get(&v, "t")?,
    };
    cost.check()?;
    Ok(Box::new(Impl {
        cost,
        out_len: get(&v, "out_len")? as usize,
    }))
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

    fn u32_of(v: &J, k: &str) -> u32 {
        u32::try_from(v[k].as_u64().unwrap()).unwrap()
    }

    fn inst(v: &J) -> Box<dyn PwHash> {
        let p = Params::new()
            .with("ln", Value::U32(u32_of(v, "ln")))
            .with("r", Value::U32(u32_of(v, "r")))
            .with("p", Value::U32(u32_of(v, "p")))
            .with("t", Value::U32(u32_of(v, "t")))
            .with("out_len", Value::U32(u32_of(v, "out_len")));
        new(&p).unwrap()
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.salt, Some(Len::range(0, 64)));
        assert_eq!(s.out, Some(Len::range(16, 1024)));
    }

    #[test]
    fn known_answers() {
        let mut ran = 0usize;
        let doc = load("yescrypt.json");
        assert_eq!(doc["algorithm"], "yescrypt");
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let pw = unhex(v["password_hex"].as_str().unwrap());
            let salt = unhex(v["salt_hex"].as_str().unwrap());
            let want = unhex(v["out_hex"].as_str().unwrap());
            let h = inst(v);
            let mut got = vec![0u8; want.len()];
            h.derive(&pw, &salt, &mut got).unwrap();
            assert_eq!(got, want, "{id}");
            let phc = h.hash(&pw, &salt).unwrap();
            assert!(h.verify(&pw, &phc).unwrap(), "{id} verify");
            let mut wrong = pw.clone();
            wrong.push(b'x');
            assert!(!h.verify(&wrong, &phc).unwrap(), "{id} wrong password");
            ran += 1;
        }
        assert!(ran >= 8, "too few vectors ran: {ran}");
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let mut out = [0u8; 16];
        assert!(matches!(
            h.derive(b"pw", &[0u8; 65], &mut out),
            Err(Error::InvalidLength { what: "salt", .. })
        ));
        for n in [0, 15, 1025] {
            assert!(matches!(
                h.derive(b"pw", &[0u8; 16], &mut vec![0u8; n]),
                Err(Error::InvalidLength { what: "out", .. })
            ));
        }
        let bad = |name: &str, v: u32| new(&Params::new().with(name, Value::U32(v))).err().unwrap();
        assert!(matches!(bad("ln", 1), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("ln", 21), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("r", 0), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("r", 33), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("p", 0), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("p", 17), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("t", 256), Error::ParamOutOfRange(_)));
        assert!(matches!(bad("out_len", 15), Error::ParamOutOfRange(_)));
        let unknown = Params::new().with("salt", Value::Bytes(vec![0; 16]));
        assert!(matches!(new(&unknown), Err(Error::ParamUnknown)));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let h = new(&Params::new()).unwrap();
        let s = "c29tZXNhbHRzb21lc2FsdA"; // 16 bytes
        let hs = "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"; // 32 bytes
        let ok = format!("$yescrypt$ln=4,r=1,p=1,t=0${s}${hs}");
        assert!(!h.verify(b"pw", &ok).unwrap());
        let cases = [
            format!("$yescrypt$ln=4,r=1,p=1,t=0${s}${hs}$"),
            format!("$yescrypt$ln=4,r=1,p=1,t=0${s}"),
            format!("$other$ln=4,r=1,p=1,t=0${s}${hs}"),
            format!("$yescrypt$ln=1,r=1,p=1,t=0${s}${hs}"),
            format!("$yescrypt$ln=21,r=1,p=1,t=0${s}${hs}"),
            format!("$yescrypt$ln=4294967295,r=1,p=1,t=0${s}${hs}"),
            format!("$yescrypt$ln=4,r=33,p=1,t=0${s}${hs}"),
            format!("$yescrypt$ln=4,r=1,p=1,t=256${s}${hs}"),
            format!("$yescrypt$ln=20,r=32,p=1,t=0${s}${hs}"),
            format!("$yescrypt$ln=4,r=1,p=1${s}${hs}"),
            String::new(),
            "$".repeat(5000),
        ];
        for c in &cases {
            assert!(h.verify(b"pw", c).is_err(), "must reject: {c:.80}");
        }
    }
}
