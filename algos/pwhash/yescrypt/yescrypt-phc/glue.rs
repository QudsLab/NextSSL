//! Adapter: yescrypt v2 / 0.8.1 (PHC finalist, reference core, PHC entry point) (verbatim upstream, PHC competition `PHS` entry point) -> nextssl `PwHash`.
//! Generated wiring, no crypto logic. Tier `unverified`: root API only.
//!
//! Policy (the DoS guard, applied to `new`, `derive` and to a PHC string read by `verify`, before
//! any work or allocation): `t_cost` 0..=4, `m_cost` 0..=12, salt 0..=64 bytes,
//! password 0..=MAX_INPUT_LEN bytes, output 16..=1024 bytes.
//! PHC form: `$yescrypt-phc$t=<n>,m=<n>$<salt>$<hash>` (NextSSL framing, strict parser in `nextssl_core::phc`).
//! PHC submission version 0.8.1 (distinct from the 1.x 'yescrypt'): phc.c PHS = yescrypt_kdf with YESCRYPT_RW, N = 8 << m_cost, r = 8, p = 1, t = t_cost. Portable yescrypt-ref.c core (no OpenMP, no SIMD). Sources carry a short 'redistribution and use ... are permitted' notice (no SPDX id, no license file).
// TARGET GATE (cargo xtask gen, from algo.toml exclude_targets)
#![cfg(not(target_env = "msvc"))]

use core::ffi::{c_int, c_void};
use nextssl_core::phc::{self, PhcParam, PhcSpec};
use nextssl_core::{
    ct_eq, Error, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, Value, Zeroizing,
    MAX_INPUT_LEN,
};

const T_MIN: u32 = 0;
const T_MAX: u32 = 4;
const T_DEF: u32 = 0;
const M_MIN: u32 = 0;
const M_MAX: u32 = 12;
const M_DEF: u32 = 4;
const SALT_MIN: usize = 0;
const SALT_MAX: usize = 64;
const PW_MIN: usize = 0;
const PW_MAX: usize = MAX_INPUT_LEN;
const OUT_MIN: usize = 16;
const OUT_MAX: usize = 1024;
const OUT_DEF: u32 = 32;

const PHC: PhcSpec = PhcSpec {
    id: "yescrypt-phc",
    version: None,
    params: &[
        PhcParam {
            name: "t",
            min: T_MIN,
            max: T_MAX,
        },
        PhcParam {
            name: "m",
            min: M_MIN,
            max: M_MAX,
        },
    ],
    salt: Len::range(SALT_MIN, SALT_MAX),
    hash: Len::range(OUT_MIN, OUT_MAX),
};

const SPECS: [ParamSpec; 3] = [
    spec("t_cost", T_MIN, T_MAX, T_DEF),
    spec("m_cost", M_MIN, M_MAX, M_DEF),
    spec("out_len", OUT_MIN as u32, OUT_MAX as u32, OUT_DEF),
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
        #[link_name = "nextssl__yescrypt_phc__derive"]
        #[allow(clippy::too_many_arguments)]
        fn derive(
            pw: *const c_void,
            pwlen: usize,
            salt: *const c_void,
            saltlen: usize,
            t_cost: u32,
            m_cost: u32,
            out: *mut c_void,
            outlen: usize,
        ) -> c_int;
    }

    /// Precondition (checked by callers in this crate): cost, password, salt and output lengths
    /// are within policy.
    #[allow(unsafe_code)]
    pub(super) fn run(cost: super::Cost, pw: &[u8], salt: &[u8], out: &mut [u8]) -> bool {
        // SAFETY: all pointers come from valid slices and are read/written only for the lengths
        // passed alongside them; the callee keeps no pointer after returning. Zero-length slices
        // give non-null aligned pointers, which the callee accepts for length 0. Its allocation is
        // bounded by the policy (`t_cost`, `m_cost`) checked in `Cost::check`.
        let rc = unsafe {
            derive(
                pw.as_ptr().cast(),
                pw.len(),
                salt.as_ptr().cast(),
                salt.len(),
                cost.t,
                cost.m,
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        rc == 0
    }
}

#[derive(Clone, Copy)]
struct Cost {
    t: u32,
    m: u32,
}

impl Cost {
    fn check(self) -> Result<()> {
        in_range("t_cost", self.t, T_MIN, T_MAX)?;
        in_range("m_cost", self.m, M_MIN, M_MAX)?;
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
    Len::range(PW_MIN, PW_MAX).check("password", password.len())
}

fn check_out(len: usize) -> Result<()> {
    Len::range(OUT_MIN, OUT_MAX).check("out", len)?;
    Ok(())
}

/// Raw call. Callers have already validated `cost`, password, `salt` and `out.len()`.
fn run(cost: Cost, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
    if ffi::run(cost, password, salt, out) {
        Ok(())
    } else {
        Err(Error::Backend("yescrypt-phc failed"))
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
        check_out(self.out_len)?;
        let mut out = Zeroizing::new(vec![0u8; self.out_len]);
        self.derive(password, salt, &mut out)?;
        phc::write(&PHC, &[self.cost.t, self.cost.m], salt, &out)
    }

    fn verify(&self, password: &[u8], phc_str: &str) -> Result<bool> {
        check_password(password)?;
        let p = phc::parse(phc_str, &PHC)?;
        let cost = Cost {
            t: p.params[0],
            m: p.params[1],
        };
        // Cross-parameter rules, before any allocation.
        cost.check()?;
        check_salt(&p.salt)?;
        check_out(p.hash.len())?;
        let mut mine = Zeroizing::new(vec![0u8; p.hash.len()]);
        run(cost, password, &p.salt, &mut mine)?;
        Ok(ct_eq(&mine, &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        check_salt(salt)?;
        check_out(out.len())?;
        run(self.cost, password, salt, out)
    }
}

fn get(params: &Params, name: &'static str) -> Result<u32> {
    match params.get(name) {
        Some(Value::U32(v)) => Ok(*v),
        _ => Err(Error::ParamType(name)),
    }
}

/// Registry constructor. Parameters: `t_cost`, `m_cost`, `out_len` (all `u32`; defaults and
/// ranges in `algo.toml`). Unknown names and out-of-range values are errors.
pub fn new(params: &Params) -> Result<Box<dyn PwHash>> {
    let v = params.validate(&SPECS)?;
    let cost = Cost {
        t: get(&v, "t_cost")?,
        m: get(&v, "m_cost")?,
    };
    cost.check()?;
    let out_len = get(&v, "out_len")? as usize;
    check_out(out_len)?;
    Ok(Box::new(Impl { cost, out_len }))
}

#[cfg(test)]
#[allow(clippy::single_element_loop)]
mod tests {
    use super::*;

    fn good_cost() -> Params {
        Params::new()
            .with("t_cost", Value::U32(T_DEF))
            .with("m_cost", Value::U32(M_DEF))
    }

    #[test]
    fn sizes_match_metadata() {
        let s = new(&Params::new()).unwrap().sizes();
        assert_eq!(s.salt, Some(Len::range(SALT_MIN, SALT_MAX)));
        assert_eq!(s.out, Some(Len::range(OUT_MIN, OUT_MAX)));
    }

    #[test]
    fn default_round_trip() {
        let h = new(&Params::new()).unwrap();
        let salt = [7u8; 16];
        let pw = [b'p'; 8];
        let phc = h.hash(&pw, &salt).unwrap();
        assert!(phc.starts_with("$yescrypt-phc$t="));
        assert!(h.verify(&pw, &phc).unwrap());
        let mut wrong = pw.to_vec();
        wrong[0] ^= 1;
        assert!(!h.verify(&wrong, &phc).unwrap());
        let mut a = vec![0u8; OUT_DEF as usize];
        let mut b = vec![0u8; OUT_DEF as usize];
        h.derive(&pw, &salt, &mut a).unwrap();
        h.derive(&pw, &salt, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn input_and_param_limits() {
        let h = new(&Params::new()).unwrap();
        let ok_salt = vec![0u8; 16];
        let mut out = vec![0u8; OUT_DEF as usize];
        assert!(matches!(
            h.derive(b"pw", &vec![0u8; SALT_MAX + 1], &mut out),
            Err(Error::InvalidLength { what: "salt", .. })
        ));
        if SALT_MIN > 0 {
            assert!(matches!(
                h.derive(b"pw", &vec![0u8; SALT_MIN.saturating_sub(1)], &mut out),
                Err(Error::InvalidLength { what: "salt", .. })
            ));
        }
        if PW_MIN > 0 {
            assert!(matches!(
                h.derive(&[], &ok_salt, &mut out),
                Err(Error::InvalidLength {
                    what: "password",
                    ..
                })
            ));
        }
        if PW_MAX < 1 << 20 {
            assert!(matches!(
                h.derive(&vec![b'p'; PW_MAX + 1], &ok_salt, &mut out),
                Err(Error::InvalidLength {
                    what: "password",
                    ..
                })
            ));
        }
        for n in [OUT_MIN.saturating_sub(1), OUT_MAX + 1] {
            assert!(matches!(
                h.derive(b"pw", &ok_salt, &mut vec![0u8; n]),
                Err(Error::InvalidLength { what: "out", .. })
            ));
        }
        let bad = |name: &str, v: u32| new(&good_cost().with(name, Value::U32(v))).err().unwrap();
        if T_MIN > 0 {
            assert!(matches!(
                bad("t_cost", T_MIN.saturating_sub(1)),
                Error::ParamOutOfRange(_)
            ));
        }
        assert!(matches!(
            bad("t_cost", T_MAX + 1),
            Error::ParamOutOfRange(_)
        ));
        if M_MIN > 0 {
            assert!(matches!(
                bad("m_cost", M_MIN.saturating_sub(1)),
                Error::ParamOutOfRange(_)
            ));
        }
        assert!(matches!(
            bad("m_cost", M_MAX + 1),
            Error::ParamOutOfRange(_)
        ));
        assert!(matches!(
            bad("out_len", OUT_MIN as u32 - 1),
            Error::ParamOutOfRange(_)
        ));
        assert!(matches!(
            bad("out_len", OUT_MAX as u32 + 1),
            Error::ParamOutOfRange(_)
        ));
        let unknown = Params::new().with("salt", Value::Bytes(vec![0; 16]));
        assert!(matches!(new(&unknown), Err(Error::ParamUnknown)));
        let wrong_ty = Params::new().with("out_len", Value::U64(32));
        assert!(matches!(new(&wrong_ty), Err(Error::ParamType(_))));
    }

    #[test]
    fn hostile_phc_strings_are_rejected_before_any_work() {
        let h = new(&Params::new()).unwrap();
        let s = "c29tZXNhbHRzb21lc2FsdA"; // 16 bytes
        let hs = "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"; // 32 bytes
        let (t, m) = (T_DEF, M_DEF);
        let ok = format!("$yescrypt-phc$t={t},m={m}${s}${hs}");
        // Well-formed: parses, wrong password, so Ok(false).
        assert!(!h.verify(b"pw", &ok).unwrap());
        let mut cases = vec![
            format!("$yescrypt-phc$t={t},m={m}${s}${hs}$"),
            format!("yescrypt-phc$t={t},m={m}${s}${hs}"),
            format!("$yescrypt-phc$t={t},m={m}${s}"),
            format!("$other$t={t},m={m}${s}${hs}"),
            format!("$yescrypt-phc$v=19$t={t},m={m}${s}${hs}"),
            format!("$yescrypt-phc$t={t}${s}${hs}"),
            format!("$yescrypt-phc$m={m},t={t}${s}${hs}"),
            format!("$yescrypt-phc$t={t},m={m},x=1${s}${hs}"),
            format!("$yescrypt-phc$t={t},m={m} ${s}${hs}"),
            format!("$yescrypt-phc$t={},m={m}${s}${hs}", T_MAX + 1),
            format!("$yescrypt-phc$t={t},m={}${s}${hs}", M_MAX + 1),
            format!("$yescrypt-phc$t=4294967295,m={m}${s}${hs}"),
            format!("$yescrypt-phc$t={t},m=4294967295${s}${hs}"),
            format!("$yescrypt-phc$t=0{t},m={m}${s}${hs}"),
            String::new(),
            "$".repeat(5000),
        ];
        if T_MIN > 0 {
            cases.push(format!(
                "$yescrypt-phc$t={},m={m}${s}${hs}",
                T_MIN.saturating_sub(1)
            ));
        }
        if M_MIN > 0 {
            cases.push(format!(
                "$yescrypt-phc$t={t},m={}${s}${hs}",
                M_MIN.saturating_sub(1)
            ));
        }
        for c in &cases {
            assert!(h.verify(b"pw", c).is_err(), "must reject: {c:.80}");
        }
        assert!(h.verify(b"pw", "$yescrypt-phc$é$é$é").is_err());
    }
}
