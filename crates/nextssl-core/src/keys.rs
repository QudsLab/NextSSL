//! Typed byte containers for keys and key-like values.
//!
//! Secret types zeroize on drop, compare in constant time, have no `Clone` and never print
//! their contents. Public types are plain. Constructors take the declared [`Len`] and fail
//! with `Error::InvalidLength`, so a value of these types has had its length checked once;
//! algorithms still re-check against their own `sizes()` and never trust the caller.

use crate::{Len, Result};
use alloc::vec::Vec;
use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constant-time equality for byte strings. Different lengths compare unequal (lengths are
/// public).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

macro_rules! secret_bytes {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        pub struct $name(Vec<u8>);

        impl $name {
            /// Copies `bytes` after checking `len`. The caller's copy is not wiped.
            pub fn from_bytes(bytes: &[u8], len: Len) -> Result<Self> {
                len.check(stringify!($name), bytes.len())?;
                Ok(Self(bytes.to_vec()))
            }

            /// Takes ownership of `bytes` after checking `len`; wipes them on error.
            pub fn from_vec(mut bytes: Vec<u8>, len: Len) -> Result<Self> {
                if let Err(e) = len.check(stringify!($name), bytes.len()) {
                    bytes.zeroize();
                    return Err(e);
                }
                Ok(Self(bytes))
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            pub fn len(&self) -> usize {
                self.0.len()
            }

            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl ZeroizeOnDrop for $name {}

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                ct_eq(&self.0, &other.0)
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(<{} bytes redacted>)", stringify!($name), self.0.len())
            }
        }
    };
}

macro_rules! public_bytes {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Copies `bytes` after checking `len`.
            pub fn from_bytes(bytes: &[u8], len: Len) -> Result<Self> {
                len.check(stringify!($name), bytes.len())?;
                Ok(Self(bytes.to_vec()))
            }

            /// Takes ownership of `bytes` after checking `len`.
            pub fn from_vec(bytes: Vec<u8>, len: Len) -> Result<Self> {
                len.check(stringify!($name), bytes.len())?;
                Ok(Self(bytes))
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            pub fn len(&self) -> usize {
                self.0.len()
            }

            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }

            pub fn into_vec(self) -> Vec<u8> {
                self.0
            }
        }
    };
}

secret_bytes!(
    /// Symmetric key or input keying material (AEAD, MAC, KDF, ciphers, modes).
    SymmetricKey
);
secret_bytes!(
    /// Asymmetric private key in the algorithm's native encoding (KEM, KEX, signature).
    PrivateKey
);
secret_bytes!(
    /// Output of KEM decapsulation or key agreement.
    SharedSecret
);
secret_bytes!(
    /// Deterministic key-generation seed, KEM coins, or DRBG entropy input.
    Seed
);
secret_bytes!(
    /// Serialized state of a stateful hash-based signature key (XMSS, LMS/HSS). It has no `Clone`:
    /// copying a one-time-key state is exactly the bug stateful signatures must prevent.
    StatefulKey
);
secret_bytes!(
    /// One share of a split secret (index and value, in the scheme's own encoding).
    Share
);
public_bytes!(
    /// Asymmetric public key in the algorithm's native encoding.
    PublicKey
);
public_bytes!(
    /// KEM ciphertext.
    Ciphertext
);
public_bytes!(
    /// Signature in the algorithm's native encoding.
    Signature
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use alloc::format;
    use alloc::vec;

    #[test]
    fn length_checked_on_construction() {
        let l = Len::fixed(4);
        assert!(SymmetricKey::from_bytes(&[1; 4], l).is_ok());
        assert!(matches!(
            SymmetricKey::from_bytes(&[1; 5], l),
            Err(Error::InvalidLength { got: 5, .. })
        ));
        assert!(PublicKey::from_vec(vec![0; 3], l).is_err());
    }

    #[test]
    fn debug_never_prints_contents() {
        let k = PrivateKey::from_bytes(&[0xAB; 8], Len::fixed(8)).unwrap();
        let s = format!("{k:?}");
        assert!(
            s.contains("redacted") && !s.to_lowercase().contains("ab"),
            "{s}"
        );
    }

    #[test]
    fn constant_time_eq_semantics() {
        let a = Seed::from_bytes(&[1, 2], Len::fixed(2)).unwrap();
        let b = Seed::from_bytes(&[1, 2], Len::fixed(2)).unwrap();
        let c = Seed::from_bytes(&[1, 3], Len::fixed(2)).unwrap();
        assert!(a == b && a != c);
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn zeroize_clears() {
        let mut k = SharedSecret::from_bytes(&[7; 4], Len::fixed(4)).unwrap();
        k.zeroize();
        assert!(k.is_empty(), "Vec::zeroize wipes the buffer and clears it");
    }
}
