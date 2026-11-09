use crate::Tier;
use core::fmt;

/// Result alias used across NextSSL.
pub type Result<T> = core::result::Result<T, Error>;

/// All failures are explicit; there are no silent fallbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No algorithm with that id or alias.
    UnknownAlgorithm,
    /// Algorithm exists but is a different kind (e.g. hash vs encoding).
    WrongKind,
    /// Algorithm tier is not allowed by the active policy.
    TierNotAllowed(Tier),
    /// Required parameter missing.
    ParamMissing(&'static str),
    /// Parameter not declared by the algorithm.
    ParamUnknown,
    /// Parameter has the wrong type.
    ParamType(&'static str),
    /// Parameter value outside its declared range.
    ParamOutOfRange(&'static str),
    /// A length is outside the permitted range.
    InvalidLength {
        what: &'static str,
        got: usize,
        min: usize,
        max: usize,
    },
    /// Malformed or non-canonical input.
    InvalidInput(&'static str),
    /// Output buffer has the wrong size.
    BadOutputLen { expected: usize, got: usize },
    /// The algorithm backend failed.
    Backend(&'static str),
    /// Operation not provided by this algorithm.
    Unsupported,
    /// Algorithm is scaffolded but its upstream has not been imported yet.
    Unimplemented,
    /// AEAD tag or other authentication check failed; no plaintext is released.
    AuthenticationFailed,
    /// DRBG used before `instantiate` (or after `uninstantiate`).
    NotInstantiated,
    /// DRBG reseed interval reached; call `reseed` first.
    ReseedRequired,
    /// Entropy source failed or failed a health test.
    EntropyFailure(&'static str),
    /// A proof-of-work solver reached its work cap without finding a solution.
    WorkLimitExceeded,
    /// A stateful signature key has no one-time keys left. No signature is produced.
    KeyExhausted,
    /// The caller's `persist` callback failed, so the advanced key state was not stored and no
    /// signature is released.
    PersistFailed,
    /// An interactive protocol (PAKE, threshold round) rejected a message or a party id. The
    /// protocol state is destroyed and cannot be reused.
    ProtocolAborted(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownAlgorithm => f.write_str("unknown algorithm"),
            Error::WrongKind => f.write_str("algorithm is of a different kind"),
            Error::TierNotAllowed(t) => write!(f, "tier {} not allowed by policy", t.as_str()),
            Error::ParamMissing(n) => write!(f, "missing required parameter {n}"),
            Error::ParamUnknown => f.write_str("unknown parameter"),
            Error::ParamType(n) => write!(f, "parameter {n} has wrong type"),
            Error::ParamOutOfRange(n) => write!(f, "parameter {n} out of range"),
            Error::InvalidLength {
                what,
                got,
                min,
                max,
            } => {
                write!(f, "{what} length {got} not in {min}..={max}")
            }
            Error::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Error::BadOutputLen { expected, got } => {
                write!(f, "output buffer is {got} bytes, expected {expected}")
            }
            Error::Backend(m) => write!(f, "backend error: {m}"),
            Error::Unsupported => f.write_str("operation not supported"),
            Error::Unimplemented => f.write_str("algorithm not implemented yet"),
            Error::AuthenticationFailed => f.write_str("authentication failed"),
            Error::NotInstantiated => f.write_str("DRBG is not instantiated"),
            Error::ReseedRequired => f.write_str("DRBG reseed required"),
            Error::EntropyFailure(m) => write!(f, "entropy source failure: {m}"),
            Error::WorkLimitExceeded => f.write_str("proof-of-work work limit reached"),
            Error::KeyExhausted => f.write_str("stateful signature key is exhausted"),
            Error::PersistFailed => f.write_str("key state could not be persisted"),
            Error::ProtocolAborted(m) => write!(f, "protocol aborted: {m}"),
        }
    }
}

impl core::error::Error for Error {}

impl Error {
    /// Stable numeric code for the C ABI (0 is success and never returned here).
    pub fn code(&self) -> i32 {
        match self {
            Error::UnknownAlgorithm => 1,
            Error::WrongKind => 2,
            Error::TierNotAllowed(_) => 3,
            Error::ParamMissing(_) => 4,
            Error::ParamUnknown => 5,
            Error::ParamType(_) => 6,
            Error::ParamOutOfRange(_) => 7,
            Error::InvalidLength { .. } => 8,
            Error::InvalidInput(_) => 9,
            Error::BadOutputLen { .. } => 10,
            Error::Backend(_) => 11,
            Error::Unsupported => 12,
            Error::Unimplemented => 13,
            Error::AuthenticationFailed => 14,
            Error::NotInstantiated => 15,
            Error::ReseedRequired => 16,
            Error::EntropyFailure(_) => 17,
            Error::WorkLimitExceeded => 18,
            Error::KeyExhausted => 19,
            Error::PersistFailed => 20,
            Error::ProtocolAborted(_) => 21,
        }
    }
}
