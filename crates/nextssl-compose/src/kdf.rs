//! `hkdf(<digest>)` (RFC 5869) and `pbkdf2(hmac(<digest>))` (RFC 8018): upstream `hkdf` and
//! `pbkdf2` crates over the digest chosen by name. Limits match the concrete `hkdf` and
//! `pbkdf2` ids, so `hkdf(sha256)` and `hkdf` with `hash=sha256` give identical output.

use crate::mac::digest_len;
use hkdf::Hkdf;
use nextssl_core::phc::{self, PhcParam, PhcSpec};
use nextssl_core::{
    ct_eq, Error, Kdf, Len, ParamSpec, ParamType, Params, PwHash, Result, Sizes, SymmetricKey,
    Zeroize, Zeroizing, MAX_INPUT_LEN,
};
use pbkdf2::pbkdf2_hmac;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const IKM_MAX: usize = 1 << 28;

// ---- HKDF -----------------------------------------------------------------------------

pub struct HkdfKdf {
    digest: &'static str,
    len: usize,
}

impl HkdfKdf {
    pub fn new(digest: &'static str) -> Result<Self> {
        Ok(Self {
            digest,
            len: digest_len(digest)?,
        })
    }

    fn max_out(&self) -> usize {
        255 * self.len
    }

    fn extract_prk(&self, ikm: &SymmetricKey, salt: &[u8]) -> Result<SymmetricKey> {
        Len::range(1, IKM_MAX).check("ikm", ikm.len())?;
        with_digest!(self.digest, D => {
            let (mut prk, _hk) = Hkdf::<D>::extract(Some(salt), ikm.as_bytes());
            let key = SymmetricKey::from_bytes(prk.as_slice(), Len::fixed(self.len));
            prk.as_mut_slice().zeroize();
            key
        })
    }

    fn expand_okm(&self, prk: &SymmetricKey, info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(self.len, IKM_MAX).check("prk", prk.len())?;
        Len::range(1, self.max_out()).check("out", out.len())?;
        let max = self.max_out();
        with_digest!(self.digest, D => {
            let hk = Hkdf::<D>::from_prk(prk.as_bytes())
                .map_err(|_| Error::Backend("hkdf prk setup"))?;
            hk.expand(info, out).map_err(|_| Error::InvalidLength {
                what: "out",
                got: out.len(),
                min: 1,
                max,
            })
        })
    }
}

impl Kdf for HkdfKdf {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(1, IKM_MAX)),
            out: Some(Len::range(1, self.max_out())),
            ..Sizes::NONE
        }
    }

    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, self.max_out()).check("out", out.len())?;
        let prk = self.extract_prk(ikm, salt)?;
        self.expand_okm(&prk, info, out)
    }

    fn extract(&self, ikm: &SymmetricKey, salt: &[u8]) -> Result<SymmetricKey> {
        self.extract_prk(ikm, salt)
    }

    fn expand(&self, prk: &SymmetricKey, info: &[u8], out: &mut [u8]) -> Result<()> {
        self.expand_okm(prk, info, out)
    }
}

// ---- PBKDF2 ---------------------------------------------------------------------------

const I_MIN: u32 = 1;
const I_MAX: u32 = 16_777_216;
const I_DEFAULT: u32 = 600_000;
const SALT_MIN: usize = 4;
const SALT_MAX: usize = 64;
const OUT_MIN: usize = 16;
const OUT_MAX: usize = 1024;
const OUT_DEFAULT: u32 = 32;

pub const PBKDF2_PARAMS: [ParamSpec; 2] = [
    spec("iterations", I_MIN, I_MAX, I_DEFAULT),
    spec("out_len", OUT_MIN as u32, OUT_MAX as u32, OUT_DEFAULT),
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

/// One `PhcSpec` per digest, built once. The set is bounded by the generated digest table.
fn phc_spec(digest: &str) -> &'static PhcSpec {
    static CACHE: OnceLock<Mutex<HashMap<String, &'static PhcSpec>>> = OnceLock::new();
    let mut map = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(s) = map.get(digest) {
        return s;
    }
    let id: &'static str = Box::leak(format!("pbkdf2-{digest}").into_boxed_str());
    let params: &'static [PhcParam] = Box::leak(Box::new([PhcParam {
        name: "i",
        min: I_MIN,
        max: I_MAX,
    }]));
    let s: &'static PhcSpec = Box::leak(Box::new(PhcSpec {
        id,
        version: None,
        params,
        salt: Len::range(SALT_MIN, SALT_MAX),
        hash: Len::range(OUT_MIN, OUT_MAX),
    }));
    map.insert(digest.to_string(), s);
    s
}

pub struct Pbkdf2 {
    digest: &'static str,
    iterations: u32,
    out_len: usize,
}

impl Pbkdf2 {
    pub fn new(digest: &'static str, params: &Params) -> Result<Self> {
        let p = params.validate(&PBKDF2_PARAMS)?;
        digest_len(digest)?;
        Ok(Self {
            digest,
            iterations: p
                .get_u32("iterations")
                .ok_or(Error::ParamMissing("iterations"))?,
            out_len: p.get_u32("out_len").ok_or(Error::ParamMissing("out_len"))? as usize,
        })
    }

    /// Raw PBKDF2-HMAC. Callers have validated `iterations`, `salt` and `out.len()`.
    fn run(&self, iterations: u32, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        with_digest!(self.digest, D => {
            pbkdf2_hmac::<D>(password, salt, iterations, out);
            Ok(())
        })
    }
}

fn check_password(password: &[u8]) -> Result<()> {
    Len::range(0, MAX_INPUT_LEN).check("password", password.len())
}

impl PwHash for Pbkdf2 {
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
        phc::write(phc_spec(self.digest), &[self.iterations], salt, &out)
    }

    fn verify(&self, password: &[u8], phc_str: &str) -> Result<bool> {
        check_password(password)?;
        let p = phc::parse(phc_str, phc_spec(self.digest))?;
        let mut mine = Zeroizing::new(vec![0u8; p.hash.len()]);
        self.run(p.params[0], password, &p.salt, &mut mine)?;
        Ok(ct_eq(&mine, &p.hash))
    }

    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        check_password(password)?;
        Len::range(SALT_MIN, SALT_MAX).check("salt", salt.len())?;
        Len::range(OUT_MIN, OUT_MAX).check("out", out.len())?;
        self.run(self.iterations, password, salt, out)
    }
}
