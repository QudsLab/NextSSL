/// Safety tier of an algorithm (REBUILD_PLAN.md section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Safe,
    Standard,
    Legacy,
    Broken,
    Research,
    /// Source found but not fully proven (no independent KAT or unclear provenance). Root only.
    Unverified,
}

impl Tier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::Safe => "safe",
            Tier::Standard => "standard",
            Tier::Legacy => "legacy",
            Tier::Broken => "broken",
            Tier::Research => "research",
            Tier::Unverified => "unverified",
        }
    }

    pub fn parse(s: &str) -> Option<Tier> {
        Some(match s {
            "safe" => Tier::Safe,
            "standard" => Tier::Standard,
            "legacy" => Tier::Legacy,
            "broken" => Tier::Broken,
            "research" => Tier::Research,
            "unverified" => Tier::Unverified,
            _ => return None,
        })
    }
}

/// Algorithm lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Importing,
    Active,
    Deprecated,
    Revoked,
}

impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Importing => "importing",
            Status::Active => "active",
            Status::Deprecated => "deprecated",
            Status::Revoked => "revoked",
        }
    }
}

/// Algorithm kind; selects which trait the algorithm implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
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
}

impl Kind {
    /// Every kind, in a stable order.
    pub const ALL: [Kind; 21] = [
        Kind::Hash,
        Kind::Xof,
        Kind::Mac,
        Kind::Kdf,
        Kind::PwHash,
        Kind::Aead,
        Kind::BlockCipher,
        Kind::StreamCipher,
        Kind::Mode,
        Kind::BlockMode,
        Kind::Kem,
        Kind::Kex,
        Kind::Sign,
        Kind::Rng,
        Kind::Drbg,
        Kind::Encoding,
        Kind::Checksum,
        Kind::Pow,
        Kind::Zk,
        Kind::Threshold,
        Kind::Vdf,
    ];

    /// The string used in `algo.toml` `kind = "..."`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Hash => "hash",
            Kind::Xof => "xof",
            Kind::Mac => "mac",
            Kind::Kdf => "kdf",
            Kind::PwHash => "pwhash",
            Kind::Aead => "aead",
            Kind::BlockCipher => "blockcipher",
            Kind::StreamCipher => "streamcipher",
            Kind::Mode => "mode",
            Kind::BlockMode => "blockmode",
            Kind::Kem => "kem",
            Kind::Kex => "kex",
            Kind::Sign => "sign",
            Kind::Rng => "rng",
            Kind::Drbg => "drbg",
            Kind::Encoding => "encoding",
            Kind::Checksum => "checksum",
            Kind::Pow => "pow",
            Kind::Zk => "zk",
            Kind::Threshold => "threshold",
            Kind::Vdf => "vdf",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// `Sizes` fields that `algo.toml [sizes]` and the instance's `sizes()` must declare.
    pub const fn required_sizes(self) -> &'static [&'static str] {
        match self {
            Kind::Hash | Kind::Kdf | Kind::Checksum => &["out"],
            Kind::Mac => &["key", "tag"],
            Kind::PwHash => &["salt", "out"],
            Kind::Aead => &["key", "nonce", "tag"],
            Kind::BlockCipher => &["key", "block"],
            Kind::StreamCipher | Kind::BlockMode => &["key", "nonce"],
            Kind::Kem => &["pk", "sk", "ct", "ss", "seed", "coins"],
            Kind::Kex => &["pk", "sk", "ss", "seed"],
            Kind::Sign => &["pk", "sk", "sig", "seed", "ctx"],
            Kind::Drbg => &["seed"],
            Kind::Xof
            | Kind::Mode
            | Kind::Rng
            | Kind::Encoding
            | Kind::Pow
            | Kind::Zk
            | Kind::Threshold
            | Kind::Vdf => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_strings_roundtrip_and_are_unique() {
        for k in Kind::ALL {
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Kind::parse("nope"), None);
        let mut names: alloc::vec::Vec<_> = Kind::ALL.iter().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Kind::ALL.len());
    }
}
