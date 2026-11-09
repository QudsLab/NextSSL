//! NextSSL composition engine.
//!
//! One engine builds composite algorithms from a constructor plus slots, instead of importing
//! each combination: `hmac(sha3-256)`, `pbkdf2(hmac(sm3))`, `hkdf(whirlpool)`,
//! `hmac-drbg(sha512)`, `hash-drbg(sha256)`, `ctr-drbg(aes-256)`, `cmac(aria-256)`,
//! `cbc(camellia-128)`, `hashcash(sha256)`.
//!
//! - **Grammar:** strict (see [`grammar`]). Names must be canonical or a registered alias; every
//!   id must resolve; a name in the wrong slot kind is an explicit error. No fallback.
//! - **Slots:** `digest` / `cipher` are type-level (generated from the `digest`, `digests` and
//!   `cipher` fields of `algo.toml`); the crypto stays in the upstream generic crates.
//!   `oneshot` is dynamic through the registry (hashcash).
//! - **Tier:** the worst part wins (`safe > standard > legacy > research > unverified >
//!   broken`). The safe API refuses anything below `standard` with `TierNotAllowed`.
//! - **Size:** SHA-2, SHA-3 and AES are always compiled in; everything else needs the cargo
//!   feature `compose-all`, otherwise selecting it is `Error::Unsupported`.
//! - **Scope:** MAC, KDF, password hash, block mode, DRBG and PoW only. Compositions have no
//!   COSE id, so there is no composed AEAD in the envelope.

#[macro_use]
mod generated;
mod drbg;
pub mod grammar;
mod kdf;
pub mod keygen;
mod mac;
mod modes;
mod parts;
mod pow;
pub mod rng;

pub use generated::{Part, CIPHERS, DIGESTS};
pub use grammar::{parse, Node, MAX_DEPTH, MAX_LEN};
pub use nextssl_registry::Policy;
pub use parts::{rank, worst};

use nextssl_core::{
    BlockMode, Drbg, Error, Kdf, Kind, Mac, ParamSpec, ParamType, Params, Pow, PwHash, Result, Tier,
};
use nextssl_registry::allowed;
use parts::OneShot;

/// The constructed algorithm, one variant per supported kind.
pub enum Built {
    Mac(Box<dyn Mac>),
    Kdf(Box<dyn Kdf>),
    PwHash(Box<dyn PwHash>),
    BlockMode(Box<dyn BlockMode>),
    Drbg(Box<dyn Drbg>),
    Pow(Box<dyn Pow>),
}

impl Built {
    pub fn kind(&self) -> Kind {
        match self {
            Built::Mac(_) => Kind::Mac,
            Built::Kdf(_) => Kind::Kdf,
            Built::PwHash(_) => Kind::PwHash,
            Built::BlockMode(_) => Kind::BlockMode,
            Built::Drbg(_) => Kind::Drbg,
            Built::Pow(_) => Kind::Pow,
        }
    }
}

/// Instance handle returned by [`compose`]: the algorithm plus its canonical name and
/// effective tier.
pub struct Composed {
    canonical: String,
    tier: Tier,
    built: Built,
}

impl Composed {
    /// Canonical text form (aliases resolved), e.g. `pbkdf2(hmac(sha3-256))`.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Worst tier of the constructor and its parts.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn kind(&self) -> Kind {
        self.built.kind()
    }

    pub fn built(&self) -> &Built {
        &self.built
    }

    pub fn into_built(self) -> Built {
        self.built
    }

    pub fn mac(&self) -> Result<&dyn Mac> {
        match &self.built {
            Built::Mac(m) => Ok(m.as_ref()),
            _ => Err(Error::WrongKind),
        }
    }

    pub fn kdf(&self) -> Result<&dyn Kdf> {
        match &self.built {
            Built::Kdf(k) => Ok(k.as_ref()),
            _ => Err(Error::WrongKind),
        }
    }

    pub fn pwhash(&self) -> Result<&dyn PwHash> {
        match &self.built {
            Built::PwHash(p) => Ok(p.as_ref()),
            _ => Err(Error::WrongKind),
        }
    }

    pub fn blockmode(&self) -> Result<&dyn BlockMode> {
        match &self.built {
            Built::BlockMode(b) => Ok(b.as_ref()),
            _ => Err(Error::WrongKind),
        }
    }

    pub fn pow(&self) -> Result<&dyn Pow> {
        match &self.built {
            Built::Pow(p) => Ok(p.as_ref()),
            _ => Err(Error::WrongKind),
        }
    }

    /// DRBGs have state, so this needs `&mut self`.
    pub fn drbg(&mut self) -> Result<&mut dyn Drbg> {
        match &mut self.built {
            Built::Drbg(d) => Ok(d.as_mut()),
            _ => Err(Error::WrongKind),
        }
    }
}

// ---- planning -------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Plan {
    Hmac(&'static Part),
    Cmac(&'static Part),
    Hkdf(&'static Part),
    Pbkdf2(&'static Part),
    Cbc(&'static Part),
    Ecb(&'static Part),
    Cfb(&'static Part),
    HmacDrbg(&'static Part),
    HashDrbg(&'static Part),
    CtrDrbg(&'static Part),
    Hashcash(OneShot),
}

const DF_VALUES: &[&str] = &["yes", "no"];
const DF_PARAM: [ParamSpec; 1] = [ParamSpec {
    name: "df",
    ty: ParamType::Enum(DF_VALUES),
    min: 0,
    max: 0,
    required: false,
    default: Some(0),
}];

fn leaf_arg(args: &[Node]) -> Result<&str> {
    match args {
        [Node::Leaf(n)] => Ok(n),
        [Node::Call { .. }] => Err(Error::InvalidInput(
            "composition: this slot takes a name, not a nested call",
        )),
        _ => Err(Error::InvalidInput(
            "composition: exactly one argument expected",
        )),
    }
}

fn plan(node: &Node) -> Result<Plan> {
    let Node::Call { name, args } = node else {
        return Err(Error::InvalidInput(
            "composition: expected ctor(...), found a bare name",
        ));
    };
    Ok(match name.as_str() {
        "hmac" => Plan::Hmac(parts::digest(leaf_arg(args)?)?),
        "hkdf" => Plan::Hkdf(parts::digest(leaf_arg(args)?)?),
        "hmac-drbg" => Plan::HmacDrbg(parts::digest(leaf_arg(args)?)?),
        "hash-drbg" => Plan::HashDrbg(parts::digest(leaf_arg(args)?)?),
        "cmac" => Plan::Cmac(parts::cipher(leaf_arg(args)?)?),
        "cbc" => Plan::Cbc(parts::cipher(leaf_arg(args)?)?),
        "ecb" => Plan::Ecb(parts::cipher(leaf_arg(args)?)?),
        "cfb" => Plan::Cfb(parts::cipher(leaf_arg(args)?)?),
        "ctr-drbg" => Plan::CtrDrbg(parts::cipher(leaf_arg(args)?)?),
        "hashcash" => Plan::Hashcash(parts::oneshot(leaf_arg(args)?)?),
        "pbkdf2" => match args.as_slice() {
            [Node::Call { name, args }] if name == "hmac" => {
                Plan::Pbkdf2(parts::digest(leaf_arg(args)?)?)
            }
            [Node::Call { .. }] => return Err(Error::Unsupported),
            _ => {
                return Err(Error::InvalidInput(
                    "composition: pbkdf2 takes hmac(<digest>)",
                ))
            }
        },
        _ => return Err(Error::UnknownAlgorithm),
    })
}

impl Plan {
    fn render(&self) -> String {
        match self {
            Plan::Hmac(p) => format!("hmac({})", p.name),
            Plan::Cmac(p) => format!("cmac({})", p.name),
            Plan::Hkdf(p) => format!("hkdf({})", p.name),
            Plan::Pbkdf2(p) => format!("pbkdf2(hmac({}))", p.name),
            Plan::Cbc(p) => format!("cbc({})", p.name),
            Plan::Ecb(p) => format!("ecb({})", p.name),
            Plan::Cfb(p) => format!("cfb({})", p.name),
            Plan::HmacDrbg(p) => format!("hmac-drbg({})", p.name),
            Plan::HashDrbg(p) => format!("hash-drbg({})", p.name),
            Plan::CtrDrbg(p) => format!("ctr-drbg({})", p.name),
            Plan::Hashcash(o) => format!("hashcash({})", o.info.id),
        }
    }

    /// Worst tier of the constructor and its parts. Constructors that have an upstream generic
    /// crate (`hmac`, `hkdf`, `pbkdf2`, `cmac`, `cbc`, `cfb`) are `standard`; ECB is `legacy`;
    /// the DRBGs and hashcash are our own state machines (port exception) and `unverified`.
    fn tier(&self) -> Tier {
        let (own, part) = match self {
            Plan::Hmac(p)
            | Plan::Cmac(p)
            | Plan::Hkdf(p)
            | Plan::Pbkdf2(p)
            | Plan::Cbc(p)
            | Plan::Cfb(p) => (Tier::Standard, p.tier),
            Plan::Ecb(p) => (Tier::Legacy, p.tier),
            Plan::HmacDrbg(p) | Plan::HashDrbg(p) | Plan::CtrDrbg(p) => (Tier::Unverified, p.tier),
            Plan::Hashcash(o) => (Tier::Unverified, o.tier),
        };
        worst(&[own, part])
    }

    fn build(&self, params: &Params) -> Result<Built> {
        let none = |params: &Params| params.validate(&[]).map(|_| ());
        Ok(match self {
            Plan::Hmac(p) => {
                none(params)?;
                Built::Mac(Box::new(mac::HmacMac::new(p.name)?))
            }
            Plan::Cmac(p) => {
                none(params)?;
                Built::Mac(Box::new(mac::CmacMac::new(p.name)?))
            }
            Plan::Hkdf(p) => {
                none(params)?;
                Built::Kdf(Box::new(kdf::HkdfKdf::new(p.name)?))
            }
            Plan::Pbkdf2(p) => Built::PwHash(Box::new(kdf::Pbkdf2::new(p.name, params)?)),
            Plan::Cbc(p) => Built::BlockMode(Box::new(modes::CipherMode::new(
                modes::Which::Cbc,
                p.name,
                params,
            )?)),
            Plan::Ecb(p) => Built::BlockMode(Box::new(modes::CipherMode::new(
                modes::Which::Ecb,
                p.name,
                params,
            )?)),
            Plan::Cfb(p) => Built::BlockMode(Box::new(modes::CipherMode::new(
                modes::Which::Cfb,
                p.name,
                params,
            )?)),
            Plan::HmacDrbg(p) => {
                none(params)?;
                Built::Drbg(Box::new(drbg::HmacDrbg::new(p.name)?))
            }
            Plan::HashDrbg(p) => {
                none(params)?;
                Built::Drbg(Box::new(drbg::HashDrbg::new(p.name)?))
            }
            Plan::CtrDrbg(p) => {
                let v = params.validate(&DF_PARAM)?;
                let df = v.get_str("df") != Some("no");
                Built::Drbg(Box::new(drbg::CtrDrbg::new(p.name, df)?))
            }
            Plan::Hashcash(o) => {
                none(params)?;
                Built::Pow(Box::new(pow::Hashcash::new(*o)?))
            }
        })
    }
}

// ---- public entry points ----------------------------------------------------------------

/// Canonical form of a composition string (aliases resolved) without building it.
pub fn canonical(spec: &str) -> Result<String> {
    Ok(plan(&parse(spec)?)?.render())
}

/// Effective tier of a composition string without building it.
pub fn effective_tier(spec: &str) -> Result<Tier> {
    Ok(plan(&parse(spec)?)?.tier())
}

/// Builds a composition with default parameters under `policy`.
pub fn compose(spec: &str, policy: Policy) -> Result<Composed> {
    compose_with(spec, &Params::new(), policy)
}

/// Builds a composition. `params` are validated against the constructor's schema
/// (`pbkdf2`: `iterations`, `out_len`; `cbc`/`ecb`: `padding`; `ctr-drbg`: `df`).
/// `Policy::Safe` refuses an effective tier below `standard` with `TierNotAllowed`.
pub fn compose_with(spec: &str, params: &Params, policy: Policy) -> Result<Composed> {
    let plan = plan(&parse(spec)?)?;
    let tier = plan.tier();
    if !allowed(tier, policy) {
        return Err(Error::TierNotAllowed(tier));
    }
    Ok(Composed {
        canonical: plan.render(),
        tier,
        built: plan.build(params)?,
    })
}
