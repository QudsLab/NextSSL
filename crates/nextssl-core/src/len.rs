use crate::{Error, Kind, Result};

/// An inclusive length range in bytes. A fixed size is a range with `min == max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Len {
    min: usize,
    max: usize,
}

impl Len {
    /// Exactly `n` bytes.
    pub const fn fixed(n: usize) -> Len {
        Len { min: n, max: n }
    }

    /// `min..=max` bytes. Panics (at compile time in statics) if `min > max`.
    pub const fn range(min: usize, max: usize) -> Len {
        assert!(min <= max, "Len::range: min > max");
        Len { min, max }
    }

    pub const fn min(&self) -> usize {
        self.min
    }

    pub const fn max(&self) -> usize {
        self.max
    }

    /// `Some(n)` when this is a single fixed size.
    pub const fn as_fixed(&self) -> Option<usize> {
        if self.min == self.max {
            Some(self.min)
        } else {
            None
        }
    }

    pub const fn contains(&self, n: usize) -> bool {
        n >= self.min && n <= self.max
    }

    /// True when every length of `self` is also allowed by `outer`.
    pub const fn is_within(&self, outer: &Len) -> bool {
        self.min >= outer.min && self.max <= outer.max
    }

    /// Returns `Error::InvalidLength` unless `got` is in range.
    pub fn check(&self, what: &'static str, got: usize) -> Result<()> {
        crate::check_len(what, got, self.min, self.max)
    }
}

/// Per-kind byte sizes. Declared in `algo.toml` `[sizes]` (static metadata) and returned by
/// each instance's `sizes()` (what the object really enforces); the registry tests check the
/// instance never accepts more than the metadata declares.
///
/// Field meaning by kind (the required set is `Kind::required_sizes`):
/// - `key`: symmetric key, MAC key, KDF input keying material
/// - `nonce`: AEAD nonce, stream-cipher nonce, mode IV or tweak
/// - `tag`: AEAD tag, MAC tag
/// - `block`: block-cipher block size
/// - `out`: digest, XOF/KDF output, password-hash output, checksum
/// - `salt`: password-hash salt
/// - `pk`, `sk`, `ct`, `ss`, `sig`: public key, secret key, ciphertext, shared secret, signature
/// - `seed`: deterministic keygen seed (KEM/KEX/Sign) or DRBG entropy input; `0` means none
/// - `coins`: KEM encapsulation randomness; `0` means none
/// - `ctx`: signature context string, `0..=n`; `0` means contexts are unsupported
/// - `info`: KDF `info` input; absent = any length, `0` = the KDF takes no `info` (a non-empty
///   one is an error). The KDF `salt` input uses `salt`: absent = any length, `0` = no salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sizes {
    pub key: Option<Len>,
    pub nonce: Option<Len>,
    pub tag: Option<Len>,
    pub block: Option<Len>,
    pub out: Option<Len>,
    pub salt: Option<Len>,
    pub pk: Option<Len>,
    pub sk: Option<Len>,
    pub ct: Option<Len>,
    pub ss: Option<Len>,
    pub sig: Option<Len>,
    pub seed: Option<Len>,
    pub coins: Option<Len>,
    pub ctx: Option<Len>,
    pub info: Option<Len>,
}

impl Sizes {
    /// Nothing declared.
    pub const NONE: Sizes = Sizes {
        key: None,
        nonce: None,
        tag: None,
        block: None,
        out: None,
        salt: None,
        pk: None,
        sk: None,
        ct: None,
        ss: None,
        sig: None,
        seed: None,
        coins: None,
        ctx: None,
        info: None,
    };

    /// All fields with their names, in declaration order.
    pub fn fields(&self) -> [(&'static str, Option<Len>); 15] {
        [
            ("key", self.key),
            ("nonce", self.nonce),
            ("tag", self.tag),
            ("block", self.block),
            ("out", self.out),
            ("salt", self.salt),
            ("pk", self.pk),
            ("sk", self.sk),
            ("ct", self.ct),
            ("ss", self.ss),
            ("sig", self.sig),
            ("seed", self.seed),
            ("coins", self.coins),
            ("ctx", self.ctx),
            ("info", self.info),
        ]
    }

    /// Field by name (`"key"`, `"pk"`, ...).
    pub fn get(&self, name: &str) -> Option<Len> {
        self.fields()
            .into_iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, l)| l)
    }

    /// Name of the first size that `kind` requires but this does not declare.
    pub fn missing_for(&self, kind: Kind) -> Option<&'static str> {
        kind.required_sizes()
            .iter()
            .copied()
            .find(|n| self.get(n).is_none())
    }

    /// Checks that every size declared here is also declared by `meta` and allowed by it.
    /// Returns the name of the first offending field.
    pub fn check_within(&self, meta: &Sizes) -> core::result::Result<(), &'static str> {
        for (name, mine) in self.fields() {
            if let Some(m) = mine {
                match meta.get(name) {
                    Some(outer) if m.is_within(&outer) => {}
                    _ => return Err(name),
                }
            }
        }
        Ok(())
    }
}

/// Reads a fixed non-zero seed/coins length; absent or `0` means unsupported.
pub(crate) fn fixed_nonzero(l: Option<Len>) -> Result<usize> {
    match l.and_then(|l| l.as_fixed()) {
        Some(n) if n > 0 => Ok(n),
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_semantics() {
        let l = Len::range(2, 5);
        assert!(l.contains(2) && l.contains(5) && !l.contains(6) && !l.contains(1));
        assert_eq!(Len::fixed(3).as_fixed(), Some(3));
        assert_eq!(l.as_fixed(), None);
        assert!(Len::fixed(3).is_within(&l) && !Len::range(1, 5).is_within(&l));
        assert!(matches!(
            l.check("x", 9),
            Err(Error::InvalidLength {
                got: 9,
                min: 2,
                max: 5,
                ..
            })
        ));
    }

    #[test]
    fn sizes_required_and_within() {
        let s = Sizes {
            key: Some(Len::fixed(32)),
            ..Sizes::NONE
        };
        assert_eq!(s.missing_for(Kind::Aead), Some("nonce"));
        assert_eq!(s.missing_for(Kind::Hash), Some("out"));
        assert_eq!(s.missing_for(Kind::Pow), None);
        let meta = Sizes {
            key: Some(Len::range(16, 32)),
            ..Sizes::NONE
        };
        assert_eq!(s.check_within(&meta), Ok(()));
        let wider = Sizes {
            key: Some(Len::range(1, 64)),
            ..Sizes::NONE
        };
        assert_eq!(wider.check_within(&meta), Err("key"));
        let undeclared = Sizes {
            tag: Some(Len::fixed(16)),
            ..Sizes::NONE
        };
        assert_eq!(undeclared.check_within(&meta), Err("tag"));
    }
}
