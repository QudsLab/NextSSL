//! Algorithm registry. The table in `generated.rs` is produced by `cargo xtask gen` from
//! `algos/**/algo.toml`; never edit it by hand.
//!
//! Every [`Kind`] can be registered: [`Ctor`] has one variant per kind and [`Instance`] holds
//! the constructed trait object. Algorithms flagged `copyleft` in `algo.toml` exist in the
//! table only when the `copyleft` cargo feature is on.

use nextssl_core::{
    Aead, BlockCipher, BlockMode, Checksum, Drbg, Encoding, EntropySource, Error, Hash, He, Kdf,
    Kem, Kex, Kind, Len, Mac, Mode, Pake, ParamSpec, Params, Pke, Pow, PwHash, Result, Sign,
    Sizes, StatefulSign, Status, StreamCipher, Threshold, Tier, Vdf, Xof, Zk, MAX_INPUT_LEN,
};

mod generated;

#[cfg(test)]
mod fakes;

/// Which tiers a caller may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Safe API: `safe` + `standard` only.
    Safe,
    /// Root API: every tier.
    Any,
}

/// Tier policy check.
pub const fn allowed(tier: Tier, policy: Policy) -> bool {
    match policy {
        Policy::Any => true,
        Policy::Safe => matches!(tier, Tier::Safe | Tier::Standard),
    }
}

/// Defines `Ctor`, `Instance` and one typed `new_<kind>_in` lookup per kind from one list, so
/// a kind cannot be added to one and forgotten in another.
macro_rules! kinds {
    ($($var:ident => $tr:ident, $new_fn:ident;)*) => {
        /// Constructor for an algorithm instance; the variant must match [`AlgoInfo::kind`].
        /// The `Params` passed in have already been validated against the algorithm's schema.
        #[derive(Clone, Copy)]
        pub enum Ctor {
            $($var(fn(&Params) -> Result<Box<dyn $tr>>),)*
        }

        impl Ctor {
            pub fn kind(&self) -> Kind {
                match self {
                    $(Ctor::$var(_) => Kind::$var,)*
                }
            }
        }

        /// A constructed algorithm, one variant per kind.
        pub enum Instance {
            $($var(Box<dyn $tr>),)*
        }

        impl Instance {
            pub fn kind(&self) -> Kind {
                match self {
                    $(Instance::$var(_) => Kind::$var,)*
                }
            }
        }

        $(
            /// Constructs algorithm `name` of this kind under `policy` with validated `params`.
            pub fn $new_fn(
                table: &[AlgoInfo],
                policy: Policy,
                name: &str,
                params: &Params,
            ) -> Result<Box<dyn $tr>> {
                let info = resolve(table, policy, name, Kind::$var)?;
                let params = params.validate(info.params)?;
                let Ctor::$var(new) = info.ctor else {
                    return Err(Error::WrongKind);
                };
                new(&params)
            }
        )*
    };
}

kinds! {
    Hash => Hash, new_hash_in;
    Xof => Xof, new_xof_in;
    Mac => Mac, new_mac_in;
    Kdf => Kdf, new_kdf_in;
    PwHash => PwHash, new_pwhash_in;
    Aead => Aead, new_aead_in;
    BlockCipher => BlockCipher, new_blockcipher_in;
    StreamCipher => StreamCipher, new_streamcipher_in;
    Mode => Mode, new_mode_in;
    BlockMode => BlockMode, new_blockmode_in;
    Kem => Kem, new_kem_in;
    Kex => Kex, new_kex_in;
    Sign => Sign, new_sign_in;
    Rng => EntropySource, new_rng_in;
    Drbg => Drbg, new_drbg_in;
    Encoding => Encoding, new_encoding_in;
    Checksum => Checksum, new_checksum_in;
    Pow => Pow, new_pow_in;
    Zk => Zk, new_zk_in;
    Threshold => Threshold, new_threshold_in;
    Vdf => Vdf, new_vdf_in;
    Pke => Pke, new_pke_in;
    Pake => Pake, new_pake_in;
    StatefulSign => StatefulSign, new_statefulsign_in;
    He => He, new_he_in;
}

impl Instance {
    /// The sizes this object actually enforces. `Hash` reports `out`; `Mode` needs a cipher
    /// to know its sizes, and keyless/reserved kinds have none, so those report nothing.
    pub fn sizes(&self) -> Sizes {
        match self {
            Instance::Hash(h) => Sizes {
                out: Some(Len::fixed(h.output_len())),
                ..Sizes::NONE
            },
            Instance::Checksum(x) => x.sizes(),
            Instance::Mac(x) => x.sizes(),
            Instance::Kdf(x) => x.sizes(),
            Instance::PwHash(x) => x.sizes(),
            Instance::Aead(x) => x.sizes(),
            Instance::BlockCipher(x) => x.sizes(),
            Instance::StreamCipher(x) => x.sizes(),
            Instance::BlockMode(x) => x.sizes(),
            Instance::Kem(x) => x.sizes(),
            Instance::Kex(x) => x.sizes(),
            Instance::Sign(x) => x.sizes(),
            Instance::Drbg(x) => x.sizes(),
            Instance::Pow(x) => x.sizes(),
            Instance::Pke(x) => x.sizes(),
            Instance::Pake(x) => x.sizes(),
            Instance::StatefulSign(x) => x.sizes(),
            Instance::Threshold(x) => x.sizes(),
            Instance::Xof(_)
            | Instance::Mode(_)
            | Instance::Rng(_)
            | Instance::Encoding(_)
            | Instance::Zk(_)
            | Instance::He(_)
            | Instance::Vdf(_) => Sizes::NONE,
        }
    }
}

/// Static metadata plus constructor for one algorithm.
pub struct AlgoInfo {
    pub id: &'static str,
    pub kind: Kind,
    pub category: &'static str,
    pub family: &'static str,
    pub aliases: &'static [&'static str],
    pub tier: Tier,
    pub status: Status,
    pub standards: &'static [&'static str],
    pub license: &'static str,
    /// Upstream is GPL/LGPL/AGPL: present only with the `copyleft` cargo feature.
    pub copyleft: bool,
    /// Core is C/C++ behind FFI (algo.toml `[upstream]` is a repo or url pin, not a crate).
    /// Miri cannot run foreign code, so tests skip these under `cfg(miri)`.
    pub c_backed: bool,
    pub fips: bool,
    /// IANA COSE algorithm id, or a private-use id (REBUILD_PLAN.md section 5).
    pub cose_alg: Option<i64>,
    /// Dotted OID, or empty.
    pub oid: &'static str,
    /// Declared byte sizes (`algo.toml [sizes]`).
    pub sizes: Sizes,
    pub params: &'static [ParamSpec],
    /// `(name, value)` string values (`algo.toml` `test_value`) for `str` parameters that are
    /// `required`, so generic tests can instantiate the algorithm. Empty for most algorithms.
    pub test_params: &'static [(&'static str, &'static str)],
    /// Directory under `algos/`, e.g. `hash/sha2/sha256`.
    pub dir: &'static str,
    /// KAT files relative to `dir`.
    pub kat: &'static [&'static str],
    /// `Some(reason)` when `algo.toml` declares `smoke = "skip"` (only `zk`, `he` and
    /// `threshold`, where setup is too heavy for the generic round trip).
    pub smoke_skip: Option<&'static str>,
    pub ctor: Ctor,
}

impl AlgoInfo {
    /// Params that make the algorithm instantiable in generic tests: every `required` string
    /// parameter set to its declared `test_value`; everything else left to its default.
    pub fn smoke_params(&self) -> Params {
        let mut p = Params::new();
        for (name, value) in self.test_params {
            p.set(name, nextssl_core::Value::Str((*value).to_string()));
        }
        p
    }
}

/// Every algorithm compiled into this build, sorted by id.
pub fn all() -> &'static [AlgoInfo] {
    generated::ALGORITHMS
}

/// Finds an algorithm by id or alias in `table`.
pub fn lookup_in<'a>(table: &'a [AlgoInfo], name: &str) -> Option<&'a AlgoInfo> {
    table
        .iter()
        .find(|a| a.id == name || a.aliases.contains(&name))
}

/// Finds an algorithm by id or alias in the generated table.
pub fn lookup(name: &str) -> Option<&'static AlgoInfo> {
    lookup_in(all(), name)
}

/// Finds an algorithm by COSE algorithm id.
pub fn lookup_cose_in(table: &[AlgoInfo], id: i64) -> Option<&AlgoInfo> {
    table.iter().find(|a| a.cose_alg == Some(id))
}

fn resolve<'a>(
    table: &'a [AlgoInfo],
    policy: Policy,
    name: &str,
    kind: Kind,
) -> Result<&'a AlgoInfo> {
    let info = lookup_in(table, name).ok_or(Error::UnknownAlgorithm)?;
    if info.kind != kind {
        return Err(Error::WrongKind);
    }
    if !allowed(info.tier, policy) || (kind.root_only() && policy == Policy::Safe) {
        // Root-only kinds (pke, pake, statefulsign, zk, threshold, he, vdf) are never reachable
        // from the safe API, whatever tier they declare.
        return Err(Error::TierNotAllowed(info.tier));
    }
    Ok(info)
}

/// Constructs algorithm `name` of any kind under `policy`. Params are validated first.
pub fn instantiate_in(
    table: &[AlgoInfo],
    policy: Policy,
    name: &str,
    params: &Params,
) -> Result<Instance> {
    let info = lookup_in(table, name).ok_or(Error::UnknownAlgorithm)?;
    let kind = info.kind;
    resolve(table, policy, name, kind)?;
    let params = params.validate(info.params)?;
    macro_rules! build {
        ($($var:ident),*) => {
            match info.ctor {
                $(Ctor::$var(new) => Instance::$var(new(&params)?),)*
            }
        };
    }
    Ok(build!(
        Hash,
        Xof,
        Mac,
        Kdf,
        PwHash,
        Aead,
        BlockCipher,
        StreamCipher,
        Mode,
        BlockMode,
        Kem,
        Kex,
        Sign,
        Rng,
        Drbg,
        Encoding,
        Checksum,
        Pow,
        Zk,
        Threshold,
        Vdf,
        Pke,
        Pake,
        StatefulSign,
        He
    ))
}

/// Conformance check used by tests and the conformance tool: the instance must declare every
/// size its kind requires, and must not accept anything the `algo.toml` metadata does not.
pub fn check_sizes(info: &AlgoInfo, inst: &Instance) -> std::result::Result<(), String> {
    if inst.kind() != info.kind {
        return Err(format!("{}: instance kind differs from metadata", info.id));
    }
    if let Some(f) = info.sizes.missing_for(info.kind) {
        return Err(format!("{}: algo.toml [sizes] lacks `{f}`", info.id));
    }
    if info.kind == Kind::Mode {
        return Ok(()); // sizes depend on the cipher
    }
    let s = inst.sizes();
    if let Some(f) = s.missing_for(info.kind) {
        return Err(format!("{}: instance sizes() lacks `{f}`", info.id));
    }
    s.check_within(&info.sizes).map_err(|f| {
        format!(
            "{}: instance `{f}` is not within algo.toml [sizes]",
            info.id
        )
    })
}

fn check_input(data: &[u8]) -> Result<()> {
    nextssl_core::check_len("input", data.len(), 0, MAX_INPUT_LEN)
}

/// Hashes `data` with algorithm `name` under `policy`.
pub fn hash_in(
    table: &[AlgoInfo],
    policy: Policy,
    name: &str,
    params: &Params,
    data: &[u8],
) -> Result<Vec<u8>> {
    check_input(data)?;
    let h = new_hash_in(table, policy, name, params)?;
    let mut out = vec![0u8; h.output_len()];
    h.digest(data, &mut out)?;
    Ok(out)
}

/// Encodes `data` with encoding `name` under `policy`.
pub fn encode_in(
    table: &[AlgoInfo],
    policy: Policy,
    name: &str,
    params: &Params,
    data: &[u8],
) -> Result<Vec<u8>> {
    check_input(data)?;
    new_encoding_in(table, policy, name, params)?.encode(data)
}

/// Decodes `text` with encoding `name` under `policy`.
pub fn decode_in(
    table: &[AlgoInfo],
    policy: Policy,
    name: &str,
    params: &Params,
    text: &[u8],
) -> Result<Vec<u8>> {
    check_input(text)?;
    new_encoding_in(table, policy, name, params)?.decode(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_policy() {
        for t in [Tier::Safe, Tier::Standard] {
            assert!(allowed(t, Policy::Safe));
        }
        for t in [Tier::Legacy, Tier::Broken, Tier::Research, Tier::Unverified] {
            assert!(!allowed(t, Policy::Safe));
            assert!(allowed(t, Policy::Any));
        }
    }

    #[test]
    fn table_sorted_unique() {
        let ids: Vec<_> = all().iter().map(|a| a.id).collect();
        let mut s = ids.clone();
        s.sort();
        s.dedup();
        assert_eq!(ids, s);
    }

    #[test]
    fn generated_table_is_consistent_with_instances() {
        for a in all() {
            assert_eq!(a.ctor.kind(), a.kind, "{}: ctor/kind mismatch", a.id);
            assert_eq!(
                a.sizes.missing_for(a.kind),
                None,
                "{}: [sizes] incomplete",
                a.id
            );
            let inst = instantiate_in(all(), Policy::Any, a.id, &a.smoke_params())
                .unwrap_or_else(|e| panic!("{}: {e}", a.id));
            check_sizes(a, &inst).unwrap_or_else(|e| panic!("{e}"));
        }
    }
}
