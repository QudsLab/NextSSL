//! Password engine: a symmetric key from a password with a registered memory-hard `pwhash`.
//!
//! Parameters are a typed key/value map validated against the algorithm's `algo.toml`
//! `[params]` schema. The result carries a [`KdfRecord`] (algorithm id, salt, every parameter
//! after defaults) that the envelope stores, so the key can always be re-derived.
//!
//! Decoding a record from an envelope is attacker-controlled input. On top of the schema, the
//! caller's [`KdfCaps`] bound memory and time (the schema maximum is 4 GiB, far above what a
//! decoder should spend on an unauthenticated header). Only algorithms whose parameters are all
//! known to the caps (`m_kib`, `t`, `p`, `out_len`) are accepted, so no cost parameter can
//! escape the check.

use nextssl_core::Kind;
use nextssl_core::{
    EntropySource, Error, Len, ParamType, Params, Result, SymmetricKey, Value, Zeroizing,
    MAX_INPUT_LEN,
};
use nextssl_registry::{allowed, lookup_in, new_pwhash_in, AlgoInfo, Policy};

/// Parameter names the caps know how to bound.
const KNOWN: [&str; 4] = ["m_kib", "t", "p", "out_len"];

/// Upper bounds applied to KDF parameters (on top of the algorithm schema).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCaps {
    /// Maximum memory in KiB (default 1 GiB).
    pub max_m_kib: u32,
    /// Maximum passes (default 64).
    pub max_t: u32,
}

impl Default for KdfCaps {
    fn default() -> Self {
        KdfCaps {
            max_m_kib: 1 << 20,
            max_t: 64,
        }
    }
}

/// What an envelope stores to re-derive a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfRecord {
    /// Registry id of the password hash (`argon2id`).
    pub alg: String,
    pub salt: Vec<u8>,
    /// Every parameter, defaults included, as `(name, value)` in schema order.
    pub params: Vec<(String, u32)>,
}

fn info_for<'a>(table: &'a [AlgoInfo], policy: Policy, id: &str) -> Result<&'a AlgoInfo> {
    let info = lookup_in(table, id).ok_or(Error::UnknownAlgorithm)?;
    if info.kind != Kind::PwHash {
        return Err(Error::WrongKind);
    }
    if !allowed(info.tier, policy) {
        return Err(Error::TierNotAllowed(info.tier));
    }
    if info
        .params
        .iter()
        .any(|p| p.ty != ParamType::U32 || !KNOWN.contains(&p.name))
    {
        return Err(Error::Unsupported);
    }
    Ok(info)
}

fn check_caps(p: &Params, caps: &KdfCaps) -> Result<()> {
    if p.get_u32("m_kib").is_some_and(|m| m > caps.max_m_kib) {
        return Err(Error::ParamOutOfRange("m_kib"));
    }
    if p.get_u32("t").is_some_and(|t| t > caps.max_t) {
        return Err(Error::ParamOutOfRange("t"));
    }
    Ok(())
}

fn run(
    table: &[AlgoInfo],
    policy: Policy,
    info: &AlgoInfo,
    params: &Params,
    password: &[u8],
    salt: &[u8],
    key_len: usize,
) -> Result<SymmetricKey> {
    Len::range(0, MAX_INPUT_LEN).check("password", password.len())?;
    let h = new_pwhash_in(table, policy, info.id, params)?;
    Len::range(1, 1024).check("key", key_len)?;
    let mut out = Zeroizing::new(vec![0u8; key_len]);
    h.derive(password, salt, &mut out)?;
    SymmetricKey::from_bytes(&out, Len::fixed(key_len))
}

/// Derives a `key_len`-byte key. `params` are the caller's choices (anything unset takes the
/// schema default); `salt` is random (minimum schema length) when `None`.
#[allow(clippy::too_many_arguments)]
pub fn derive_key_in(
    table: &[AlgoInfo],
    policy: Policy,
    caps: &KdfCaps,
    kdf_id: &str,
    password: &[u8],
    params: &Params,
    salt: Option<&[u8]>,
    rng: &mut dyn EntropySource,
    key_len: usize,
) -> Result<(SymmetricKey, KdfRecord)> {
    let info = info_for(table, policy, kdf_id)?;
    let mut p = params.clone();
    if info.params.iter().any(|s| s.name == "out_len") {
        match p.get("out_len") {
            None => {}
            Some(Value::U32(v)) if *v as usize == key_len => {}
            Some(_) => return Err(Error::ParamOutOfRange("out_len")),
        }
        p.set(
            "out_len",
            Value::U32(u32::try_from(key_len).map_err(|_| Error::InvalidInput("key length"))?),
        );
    }
    let p = p.validate(info.params)?;
    check_caps(&p, caps)?;
    let salt_len = new_pwhash_in(table, policy, info.id, &p)?
        .sizes()
        .salt
        .ok_or(Error::Unsupported)?
        .min();
    let salt = match salt {
        Some(s) => s.to_vec(),
        None => {
            let mut s = vec![0u8; salt_len];
            rng.fill(&mut s)?;
            s
        }
    };
    let key = run(table, policy, info, &p, password, &salt, key_len)?;
    let params = info
        .params
        .iter()
        .map(|s| {
            p.get_u32(s.name)
                .map(|v| (s.name.to_string(), v))
                .ok_or(Error::ParamMissing(s.name))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        key,
        KdfRecord {
            alg: info.id.to_string(),
            salt,
            params,
        },
    ))
}

/// Re-derives the key described by `record` (decoded from an envelope). The record is
/// validated against the schema and `caps` before any memory is allocated.
pub fn rederive_in(
    table: &[AlgoInfo],
    policy: Policy,
    caps: &KdfCaps,
    record: &KdfRecord,
    password: &[u8],
    key_len: usize,
) -> Result<SymmetricKey> {
    let info = info_for(table, policy, &record.alg)?;
    let mut p = Params::new();
    for (name, v) in &record.params {
        let spec = info
            .params
            .iter()
            .find(|s| s.name == name.as_str())
            .ok_or(Error::ParamUnknown)?;
        if p.get(spec.name).is_some() {
            return Err(Error::InvalidInput("duplicate KDF parameter"));
        }
        p.set(spec.name, Value::U32(*v));
    }
    // Every parameter must be present: a record is a complete description, never "plus defaults".
    for s in info.params {
        if p.get(s.name).is_none() {
            return Err(Error::ParamMissing(s.name));
        }
    }
    let p = p.validate(info.params)?;
    check_caps(&p, caps)?;
    if p.get_u32("out_len").is_some_and(|v| v as usize != key_len) {
        return Err(Error::ParamOutOfRange("out_len"));
    }
    run(table, policy, info, &p, password, &record.salt, key_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;
    use nextssl_registry::all;

    fn small() -> Params {
        Params::new()
            .with("m_kib", Value::U32(8))
            .with("t", Value::U32(1))
    }

    #[test]
    fn derive_then_rederive_round_trips_and_records_all_params() {
        let mut rng = FixedEntropy::new(&[9u8; 64]);
        let caps = KdfCaps::default();
        let (k, rec) = derive_key_in(
            all(),
            Policy::Safe,
            &caps,
            "argon2id",
            b"pw",
            &small(),
            None,
            &mut rng,
            32,
        )
        .unwrap();
        assert_eq!(rec.alg, "argon2id");
        assert_eq!(rec.salt, vec![9u8; 16]);
        let names: Vec<_> = rec.params.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["m_kib", "out_len", "p", "t"]); // schema (algo.toml) order
        let k2 = rederive_in(all(), Policy::Safe, &caps, &rec, b"pw", 32).unwrap();
        assert_eq!(k, k2);
        let k3 = rederive_in(all(), Policy::Safe, &caps, &rec, b"other", 32).unwrap();
        assert_ne!(k, k3);
    }

    #[test]
    fn schema_caps_and_record_validation() {
        let mut rng = FixedEntropy::new(&[1u8; 64]);
        let caps = KdfCaps {
            max_m_kib: 64,
            max_t: 2,
        };
        let go = |p: &Params, rng: &mut FixedEntropy, caps: &KdfCaps| {
            derive_key_in(
                all(),
                Policy::Safe,
                caps,
                "argon2id",
                b"pw",
                p,
                None,
                rng,
                32,
            )
        };
        // schema violations
        assert!(go(&Params::new().with("m_kib", Value::U32(7)), &mut rng, &caps).is_err());
        assert!(go(&Params::new().with("bogus", Value::U32(7)), &mut rng, &caps).is_err());
        assert!(go(&Params::new().with("t", Value::U64(1)), &mut rng, &caps).is_err());
        assert!(go(
            &Params::new().with("out_len", Value::U32(48)),
            &mut rng,
            &caps
        )
        .is_err());
        // caps (default m_kib is 65536 > 64)
        assert_eq!(
            go(&Params::new(), &mut rng, &caps).err(),
            Some(Error::ParamOutOfRange("m_kib"))
        );
        let (_, rec) = go(&small(), &mut rng, &caps).unwrap();
        // record tampering: cost above caps / schema, unknown, duplicate, missing, bad algorithm
        let with = |f: &dyn Fn(&mut KdfRecord)| {
            let mut r = rec.clone();
            f(&mut r);
            rederive_in(all(), Policy::Safe, &caps, &r, b"pw", 32).err()
        };
        assert!(with(&|r| r.params[0].1 = 4_194_304).is_some());
        assert!(with(&|r| r.params[0].1 = 128).is_some(), "above cap");
        assert!(with(&|r| r.params[1].1 = 3).is_some(), "t above cap");
        assert!(with(&|r| r.params.push(("zzz".into(), 1))).is_some());
        assert!(with(&|r| r.params.push(("t".into(), 1))).is_some());
        assert!(with(&|r| {
            r.params.pop();
        })
        .is_some());
        assert!(with(&|r| r.salt.truncate(8)).is_some());
        assert!(with(&|r| r.alg = "sha256".into()).is_some());
        assert!(with(&|r| r.alg = "nope".into()).is_some());
        assert!(with(&|_| {}).is_none());
        assert!(
            rederive_in(all(), Policy::Safe, &caps, &rec, b"pw", 16).is_err(),
            "key_len bound"
        );
    }
}
