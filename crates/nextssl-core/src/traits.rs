//! One trait per [`Kind`](crate::Kind). Frozen by P1a: algorithm imports implement these and
//! nothing else, so new methods may only be added with a default body.
//!
//! Conventions that every implementation must follow:
//! - Every length is validated against the algorithm's own `sizes()` before use. A wrong
//!   length is `Error::InvalidLength` / `Error::BadOutputLen`, never a truncation or padding.
//! - Output buffers are exact: `out.len()` must be allowed by the matching size, otherwise the
//!   call fails. Nothing is written on error where the algorithm can avoid it.
//! - Inputs larger than [`MAX_INPUT_LEN`] are rejected by the shell; glue still checks limits
//!   the algorithm itself has (counter overflow, maximum message, maximum output).
//! - A feature the algorithm lacks returns `Error::Unsupported`; it is never emulated with a
//!   different algorithm.
//! - Anything secret is held in the zeroizing types from [`crate::keys`] or `Zeroizing<_>`.
//! - Instances are immutable `Send + Sync` objects unless the trait holds state
//!   (`EntropySource`, `Drbg`: `Send` only, `&mut self`).

use crate::keys::{Ciphertext, PrivateKey, PublicKey, Seed, SharedSecret, Signature, SymmetricKey};
use crate::len::fixed_nonzero;
use crate::{Error, Result, Sizes};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Upper bound on any single input accepted by the shell (256 MiB).
pub const MAX_INPUT_LEN: usize = 1 << 28;

/// Fills a fresh [`Seed`] of the fixed length declared by `len` from `rng`.
/// `Error::Unsupported` when the algorithm declares no seed (`0` or absent).
fn draw_seed(rng: &mut dyn EntropySource, len: Option<crate::Len>) -> Result<Seed> {
    let n = fixed_nonzero(len)?;
    let mut buf = Zeroizing::new(vec![0u8; n]);
    rng.fill(&mut buf)?;
    Seed::from_bytes(&buf, crate::Len::fixed(n))
}

// ---------------------------------------------------------------------------------------
// Keyless primitives
// ---------------------------------------------------------------------------------------

/// Cryptographic hash, one-shot. (Incremental hashing may be added later as a defaulted
/// method.) Optional keyed modes (BLAKE2/3 `key`) are params, not a separate kind.
pub trait Hash: Send + Sync {
    fn output_len(&self) -> usize;
    /// `out.len()` must equal `output_len()`.
    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()>;
}

/// Extendable-output function (SHAKE, BLAKE3 XOF, KangarooTwelve, ...).
/// Customization strings (cSHAKE) and similar are params.
pub trait Xof: Send + Sync {
    /// Fills all of `out`. `out` must be non-empty.
    fn squeeze(&self, data: &[u8], out: &mut [u8]) -> Result<()>;
}

/// Non-cryptographic checksum (CRC, Adler, xxHash, ...). A separate kind from [`Hash`] so no
/// hash/KDF/PoW selector can pick one by accident; reachable through `root` only.
pub trait Checksum: Send + Sync {
    /// Sizes: `out`.
    fn sizes(&self) -> Sizes;
    /// `out.len()` must be allowed by `sizes().out`. Big-endian unless the standard says otherwise.
    fn checksum(&self, data: &[u8], out: &mut [u8]) -> Result<()>;
}

/// Keyless, reversible, strict text encoding (base64, hex, bech32, ...).
pub trait Encoding: Send + Sync {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>>;
    /// Strict: non-canonical or malformed input is an error.
    fn decode(&self, text: &[u8]) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------------------
// Symmetric
// ---------------------------------------------------------------------------------------

/// Message authentication code.
pub trait Mac: Send + Sync {
    /// Sizes: `key` (range), `tag` (range; shorter tags are allowed only if declared).
    fn sizes(&self) -> Sizes;

    /// Writes a tag of exactly `out.len()` bytes. `out.len()` must be inside `sizes().tag`;
    /// truncation only happens because the caller asked for a declared shorter length.
    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()>;

    /// Constant-time verification. A tag of an undeclared length is `Err`, a wrong tag is
    /// `Ok(false)`. Implementations that override this must stay constant time.
    fn verify(&self, key: &SymmetricKey, data: &[u8], tag: &[u8]) -> Result<bool> {
        let allowed = self.sizes().tag.ok_or(Error::Unsupported)?;
        allowed.check("tag", tag.len())?;
        let mut mine = Zeroizing::new(vec![0u8; tag.len()]);
        self.tag(key, data, &mut mine)?;
        Ok(crate::ct_eq(&mine, tag))
    }
}

/// Key derivation from existing key material (HKDF, KBKDF, X9.63, ...). Password hashing is
/// [`PwHash`].
pub trait Kdf: Send + Sync {
    /// Sizes: `out` (`min..=max` derivable bytes), optionally `key` (input keying material).
    fn sizes(&self) -> Sizes;

    /// One-shot derive. `out.len()` must be non-empty and inside `sizes().out`; asking for
    /// more than the KDF can produce is an error, not a short output.
    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()>;

    /// Extract step for extract-then-expand KDFs (HKDF). Returns the pseudorandom key.
    fn extract(&self, _ikm: &SymmetricKey, _salt: &[u8]) -> Result<SymmetricKey> {
        Err(Error::Unsupported)
    }

    /// Expand step; `prk` comes from [`Kdf::extract`] (or is already uniformly random).
    fn expand(&self, _prk: &SymmetricKey, _info: &[u8], _out: &mut [u8]) -> Result<()> {
        Err(Error::Unsupported)
    }
}

/// Password hashing / password-based KDF (Argon2, scrypt, bcrypt, PBKDF2, ...). Cost
/// parameters are instance params, validated against the `algo.toml` schema.
pub trait PwHash: Send + Sync {
    /// Sizes: `salt` (range), `out` (hash length for the configured params).
    fn sizes(&self) -> Sizes;

    /// Hashes `password` with the caller-supplied `salt` and returns a PHC string
    /// (`$id$v=..$params$salt$hash`) that records the algorithm id and all cost parameters.
    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String>;

    /// Verifies against a PHC string. The string is parsed strictly; its algorithm id must be
    /// this algorithm; its cost parameters must lie inside the schema ranges (so a hostile
    /// string cannot demand unbounded memory or time); the comparison is constant time.
    /// `Ok(false)` = wrong password, `Err` = malformed or out-of-policy string.
    fn verify(&self, password: &[u8], phc: &str) -> Result<bool>;

    /// Raw derivation (key-from-password engine): `out.len()` must be inside `sizes().out`.
    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()>;
}

/// Authenticated encryption with associated data.
pub trait Aead: Send + Sync {
    /// Sizes: `key`, `nonce` (range for variable-IV AEADs; `0` for nonce-less ones such as
    /// key wrap), `tag`.
    fn sizes(&self) -> Sizes;

    /// Returns `ciphertext || tag`. The nonce is chosen by the caller; the safe layer
    /// generates it and never reuses one under a key.
    fn seal(&self, key: &SymmetricKey, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>>;

    /// Takes `ciphertext || tag`. Failure is `Error::AuthenticationFailed` and releases no
    /// plaintext.
    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Raw block permutation, one block at a time (AES, Camellia, ARIA, ...). Tweakable or
/// wide-block variants take their extra input as params.
pub trait BlockCipher: Send + Sync {
    /// Sizes: `key` (range), `block`.
    fn sizes(&self) -> Sizes;

    /// Expands `key` once; use the result for many blocks (what [`Mode`] does). The returned
    /// object holds round keys and must zeroize them on drop.
    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>>;

    /// One-off encryption of one block in place. `block.len()` must equal `sizes().block`.
    fn encrypt_block(&self, key: &SymmetricKey, block: &mut [u8]) -> Result<()> {
        self.keyed(key)?.encrypt_block(block)
    }

    /// One-off decryption of one block in place.
    fn decrypt_block(&self, key: &SymmetricKey, block: &mut [u8]) -> Result<()> {
        self.keyed(key)?.decrypt_block(block)
    }
}

/// A [`BlockCipher`] with its key schedule already computed.
pub trait KeyedBlockCipher: Send + Sync {
    fn block_len(&self) -> usize;
    /// `block.len()` must equal `block_len()`.
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()>;
    fn decrypt_block(&self, block: &mut [u8]) -> Result<()>;
}

/// Native stream cipher (ChaCha, Salsa, RC4, ...). Keystream XOR is its own inverse.
pub trait StreamCipher: Send + Sync {
    /// Sizes: `key`, `nonce` (`0` for ciphers without one, e.g. RC4).
    fn sizes(&self) -> Sizes;

    /// XORs the keystream into `data` in place, starting at the beginning of the keystream
    /// (or at the `initial_counter` param if the cipher declares one). Fails, without
    /// processing, if `data` would exceed the cipher's keystream limit.
    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()>;
}

/// Unauthenticated mode of operation over any registered [`BlockCipher`] (ECB, CBC, CBC-CS1/2/3,
/// CFB, OFB, CTR, XTS). A mode is generic over the cipher, so each is imported once and
/// composes with every block cipher at run time. Authenticated compositions (GCM, CCM, OCB,
/// EAX, SIV) are concrete [`Aead`]s because their glue is cipher-specific. Padding is a mode
/// param; decryption reports bad padding as `Error::InvalidInput` and callers must not expose
/// that distinction on a network (padding oracles): prefer an AEAD.
pub trait Mode: Send + Sync {
    /// Sizes for this mode on `cipher`: `key` (XTS: twice the cipher key), `nonce` (IV or
    /// tweak), `block`. `Err` if the cipher is unsuitable (e.g. XTS needs a 128-bit block).
    fn sizes(&self, cipher: &dyn BlockCipher) -> Result<Sizes>;

    fn encrypt(
        &self,
        cipher: &dyn BlockCipher,
        key: &SymmetricKey,
        iv: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>>;

    fn decrypt(
        &self,
        cipher: &dyn BlockCipher,
        key: &SymmetricKey,
        iv: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Concrete block-cipher mode with the cipher fixed by the algorithm: `aes-256-cbc`,
/// `aes-128-xts`, `aes-kw`, `aes-fpe-ff1`, ... Unlike [`Mode`] it has no `cipher` argument, so it
/// can wrap an upstream mode crate directly without hand-written mode logic.
///
/// Sizes: `key`, `nonce` (the IV, XTS tweak or FPE tweak; `0` = the mode takes none, a non-empty
/// value is then an error) and `block` (the cipher block size in bytes). `encrypt`/`decrypt` map
/// the whole input in one call; lengths a mode cannot handle (not a block multiple without
/// padding, key wrap < 16 bytes, ...) are `Error::InvalidLength`/`InvalidInput`, never padded or
/// truncated silently. Padding is a `[params]` enum. Decryption reports bad padding or a failed
/// key-wrap integrity check as an error; do not expose that distinction on a network (padding
/// oracles): prefer an AEAD.
pub trait BlockMode: Send + Sync {
    fn sizes(&self) -> Sizes;

    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>>;

    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

// ---------------------------------------------------------------------------------------
// Asymmetric
// ---------------------------------------------------------------------------------------

/// Key encapsulation mechanism.
///
/// `keygen`/`encaps` have default bodies that draw the declared `seed`/`coins` from the RNG
/// and call the deterministic functions, which is correct whenever the standard defines
/// keygen/encaps as a function of such randomness (ML-KEM, X-Wing, ...). Algorithms without
/// that structure override `keygen`/`encaps` and return `Unsupported` from the `_from_*` ones.
pub trait Kem: Send + Sync {
    /// Sizes: `pk`, `sk`, `ct`, `ss`, `seed` (`0` = none), `coins` (`0` = none).
    fn sizes(&self) -> Sizes;

    /// Deterministic keygen; `seed.len()` must equal `sizes().seed`.
    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)>;

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let seed = draw_seed(rng, self.sizes().seed)?;
        self.keygen_from_seed(&seed)
    }

    /// Deterministic encapsulation; `coins.len()` must equal `sizes().coins`.
    fn encaps_from_coins(&self, pk: &PublicKey, coins: &Seed)
        -> Result<(Ciphertext, SharedSecret)>;

    fn encaps(
        &self,
        pk: &PublicKey,
        rng: &mut dyn EntropySource,
    ) -> Result<(Ciphertext, SharedSecret)> {
        let coins = draw_seed(rng, self.sizes().coins)?;
        self.encaps_from_coins(pk, &coins)
    }

    /// Wrong-length inputs are `Err`. A well-formed but invalid ciphertext follows the
    /// scheme (ML-KEM: implicit rejection returns a pseudorandom secret, never an error).
    fn decaps(&self, sk: &PrivateKey, ct: &Ciphertext) -> Result<SharedSecret>;
}

/// Diffie-Hellman style key agreement (X25519, X448, ECDH, FFDH, CSIDH, ...).
pub trait Kex: Send + Sync {
    /// Sizes: `pk`, `sk`, `ss`, `seed` (`0` = none).
    fn sizes(&self) -> Sizes;

    fn keypair_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)>;

    fn keypair(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let seed = draw_seed(rng, self.sizes().seed)?;
        self.keypair_from_seed(&seed)
    }

    /// Computes the shared secret. Invalid or low-order peer keys and all-zero results are
    /// `Err(InvalidInput)`, never a zero secret. The raw secret is not hashed; the safe layer
    /// feeds it to a KDF.
    fn agree(&self, sk: &PrivateKey, peer_pk: &PublicKey) -> Result<SharedSecret>;
}

/// Digital signature (ML-DSA, SLH-DSA, Ed25519, ECDSA, RSA-PSS, ...).
pub trait Sign: Send + Sync {
    /// Sizes: `pk`, `sk`, `sig` (range for DER ECDSA), `seed` (`0` = none), `ctx`
    /// (`0..=n` context-string length; `0` means contexts are unsupported).
    fn sizes(&self) -> Sizes;

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)>;

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let seed = draw_seed(rng, self.sizes().seed)?;
        self.keygen_from_seed(&seed)
    }

    /// Signs `msg` with a domain-separation context (FIPS 204 `ctx`, Ed25519ctx/ph). A
    /// non-empty `ctx` on an algorithm with `ctx == 0`, or one longer than `sizes().ctx`, is
    /// an error (never ignored). `rng` supplies signing randomness (hedged ML-DSA, ECDSA k);
    /// deterministic algorithms do not read it. Pre-hash variants are separate algorithm ids.
    fn sign(
        &self,
        sk: &PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Signature>;

    /// `Ok(false)`: well-formed signature that does not verify. `Err`: wrong lengths,
    /// malformed key/signature encoding, or bad `ctx`. Callers treat both as rejection.
    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &Signature) -> Result<bool>;
}

// ---------------------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------------------

/// Source of random bytes: OS RNG, CPU RNG, jitter entropy, hardware TRNG. Health-test
/// failures are `Error::EntropyFailure`; implementations never return partial or zero fills
/// silently. `Send` but not `Sync`: it has mutable state.
pub trait EntropySource: Send {
    /// Fills all of `out`.
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}

/// Deterministic random bit generator (SP 800-90A: CTR_DRBG, HMAC_DRBG, Hash_DRBG, ...).
/// Entropy is always passed in by the caller (the shell reads an [`EntropySource`]), so KAT
/// vectors replay exactly. Implementations zeroize their state on drop and in
/// [`Drbg::uninstantiate`]. `Send` but not `Sync`.
pub trait Drbg: Send {
    /// Sizes: `seed` = required entropy-input length (range), for `instantiate` and `reseed`.
    fn sizes(&self) -> Sizes;

    /// Security strength in bits.
    fn security_strength(&self) -> usize;

    /// Maximum bytes per `generate` call.
    fn max_request_len(&self) -> usize;

    /// Initializes the state (SP 800-90A `Instantiate`: entropy_input, nonce,
    /// personalization_string). `entropy.len()` must be inside `sizes().seed`. The nonce is
    /// passed separately so KAT vectors replay exactly; DRBGs that do not take one (or take it
    /// as part of the entropy) document how they treat it.
    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<()>;

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()>;

    /// Fills all of `out` (non-empty, at most `max_request_len()`). `NotInstantiated` before
    /// `instantiate`; `ReseedRequired` once the reseed interval is exhausted.
    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()>;

    /// Zeroizes the state; afterwards `generate` returns `NotInstantiated`.
    fn uninstantiate(&mut self);
}

// ---------------------------------------------------------------------------------------
// Reserved kinds (P3). Intentionally empty: methods are added when the first algorithm of the
// family is imported. Nothing implements them yet, so adding required methods then is not a
// breaking change for existing glue.
// ---------------------------------------------------------------------------------------

/// Proof of work (hashcash, Argon2-based, Equihash, ...). Challenges will carry the full
/// algorithm id and parameters (REBUILD_PLAN.md section 6).
///
/// Difficulty is explicit and bounded by [`Pow::difficulty`]; a value outside it is an error,
/// never clamped. `solve` takes a work cap so a hostile difficulty cannot hang the caller:
/// when the cap is reached without a solution it returns `Error::WorkLimitExceeded`.
pub trait Pow: Send + Sync {
    /// Sizes: `out` = solution length range (bytes).
    fn sizes(&self) -> Sizes;

    /// Inclusive `(min, max)` difficulty this algorithm accepts.
    fn difficulty(&self) -> (u32, u32);

    /// Finds a solution for `challenge` at `difficulty` using at most `max_work` attempts.
    fn solve(&self, challenge: &[u8], difficulty: u32, max_work: u64) -> Result<Vec<u8>>;

    /// `Ok(false)`: well-formed solution that does not meet `difficulty`. `Err`: wrong
    /// difficulty or malformed solution or challenge.
    fn verify(&self, challenge: &[u8], solution: &[u8], difficulty: u32) -> Result<bool>;
}

/// Zero-knowledge proof systems (Schnorr proofs, Bulletproofs, SNARKs, STARKs).
pub trait Zk: Send + Sync {}

/// Threshold schemes (Shamir, FROST, threshold ECDSA, DKG).
pub trait Threshold: Send + Sync {}

/// Verifiable delay functions (Wesolowski, Pietrzak).
pub trait Vdf: Send + Sync {}
