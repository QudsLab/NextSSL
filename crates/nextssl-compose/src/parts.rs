//! Slot resolution: names in a composition -> generated digest/cipher entries, or registered
//! algorithms for the dynamic `oneshot` slot.

use crate::generated::{Part, CIPHERS, DIGESTS};
use nextssl_core::{Error, Kind, Result, Tier};
use nextssl_registry::{all, lookup_in, AlgoInfo};

fn find(list: &'static [Part], name: &str) -> Option<&'static Part> {
    list.iter()
        .find(|p| p.name == name || p.aliases.contains(&name))
}

/// Error for a name that is not in the slot table: wrong slot kind, known but not selectable
/// at type level, or unknown.
fn miss(name: &str, other: &'static [Part]) -> Error {
    if find(other, name).is_some() {
        return Error::WrongKind;
    }
    match lookup_in(all(), name) {
        // Registered, but with no type-level digest/cipher (C-backed, lazy-buffer hashes,
        // variable-key ciphers, other kinds). Never substituted by another algorithm.
        Some(_) => Error::Unsupported,
        None => Error::UnknownAlgorithm,
    }
}

fn checked(p: &'static Part) -> Result<&'static Part> {
    if p.compiled {
        Ok(p)
    } else {
        Err(Error::Unsupported)
    }
}

/// A type-level digest slot (`digest = ".."` in algo.toml).
pub fn digest(name: &str) -> Result<&'static Part> {
    find(DIGESTS, name).map_or_else(|| Err(miss(name, CIPHERS)), checked)
}

/// A type-level block-cipher slot (`cipher = ".."` in algo.toml).
pub fn cipher(name: &str) -> Result<&'static Part> {
    find(CIPHERS, name).map_or_else(|| Err(miss(name, DIGESTS)), checked)
}

/// A dynamic slot: any registered hash, XOF or checksum. Checksums are not cryptographic, so
/// they count as tier `broken`; the safe API therefore never reaches them.
#[derive(Clone, Copy)]
pub struct OneShot {
    pub info: &'static AlgoInfo,
    pub tier: Tier,
}

pub fn oneshot(name: &str) -> Result<OneShot> {
    let info = lookup_in(all(), name).ok_or(Error::UnknownAlgorithm)?;
    let tier = match info.kind {
        Kind::Hash | Kind::Xof => info.tier,
        Kind::Checksum => Tier::Broken,
        _ => return Err(Error::WrongKind),
    };
    Ok(OneShot { info, tier })
}

/// Tier order for composites: the worst part wins. `safe > standard > legacy > research >
/// unverified > broken`. The derived `Ord` of `Tier` is not this order.
pub fn rank(t: Tier) -> u8 {
    match t {
        Tier::Safe => 0,
        Tier::Standard => 1,
        Tier::Legacy => 2,
        Tier::Research => 3,
        Tier::Unverified => 4,
        Tier::Broken => 5,
    }
}

/// Effective tier of a composition: the worst of its parts.
pub fn worst(tiers: &[Tier]) -> Tier {
    tiers
        .iter()
        .copied()
        .max_by_key(|t| rank(*t))
        .unwrap_or(Tier::Broken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_tier_order() {
        assert_eq!(worst(&[Tier::Safe, Tier::Standard]), Tier::Standard);
        assert_eq!(worst(&[Tier::Legacy, Tier::Unverified]), Tier::Unverified);
        assert_eq!(worst(&[Tier::Unverified, Tier::Broken]), Tier::Broken);
        assert_eq!(worst(&[Tier::Research, Tier::Legacy]), Tier::Research);
        assert_eq!(worst(&[Tier::Safe]), Tier::Safe);
    }

    #[test]
    fn slot_errors_are_explicit() {
        assert_eq!(digest("sha256").unwrap().name, "sha256");
        assert_eq!(digest("aes-128").err(), Some(Error::WrongKind));
        assert_eq!(cipher("sha256").err(), Some(Error::WrongKind));
        assert_eq!(digest("nope").err(), Some(Error::UnknownAlgorithm));
        // Registered hash without a type-level digest.
        assert_eq!(digest("blake3").err(), Some(Error::Unsupported));
        assert_eq!(oneshot("aes-128").err(), Some(Error::WrongKind));
        assert_eq!(oneshot("crc32").unwrap().tier, Tier::Broken);
    }
}
