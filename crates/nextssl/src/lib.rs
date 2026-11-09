//! Safe API. Only `safe` and `standard` tier algorithms are reachable; anything else returns
//! `Error::TierNotAllowed`. Use `nextssl-root` for the other tiers.

use nextssl_core::{EntropySource, Len, Params, Zeroizing};
use nextssl_registry::{
    all, decode_in, encode_in, hash_in, new_kdf_in, new_kem_in, new_mac_in, new_pwhash_in,
    new_rng_in, AlgoInfo, Policy,
};

pub mod envelope;
pub mod keygen;

pub use envelope::{from_text, to_text, Limits};
pub use keygen::password::{KdfCaps, KdfRecord};
pub use keygen::seed::{Expander, SeedMode};
pub use nextssl_core::{
    Ciphertext, Error, PrivateKey, PublicKey, Result, Seed, SharedSecret, Signature, SymmetricKey,
    Tier, Value,
};
pub use nextssl_registry::all as algorithms;

/// Hash `data` with the named algorithm and default parameters.
pub fn hash(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    hash_with(alg, &Params::new(), data)
}

/// Hash with explicit parameters (validated against the algorithm schema).
pub fn hash_with(alg: &str, params: &Params, data: &[u8]) -> Result<Vec<u8>> {
    hash_in(nextssl_registry::all(), Policy::Safe, alg, params, data)
}

/// Encode `data` (e.g. base64).
pub fn encode(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    encode_in(
        nextssl_registry::all(),
        Policy::Safe,
        alg,
        &Params::new(),
        data,
    )
}

/// Strictly decode `text`; malformed or non-canonical input is an error.
pub fn decode(alg: &str, text: &[u8]) -> Result<Vec<u8>> {
    decode_in(
        nextssl_registry::all(),
        Policy::Safe,
        alg,
        &Params::new(),
        text,
    )
}

// ---------------------------------------------------------------------------------------
// Typed choices. The default is the first variant; the chosen algorithm is recorded in the
// output (COSE `alg`), so decoding never guesses.
// ---------------------------------------------------------------------------------------

/// AEAD for envelopes. Default: XChaCha20-Poly1305 (192-bit random nonce).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AeadAlg {
    #[default]
    XChaCha20Poly1305,
    /// AES-256-GCM: random 96-bit nonces limit one key to about 2^32 messages.
    Aes256Gcm,
}

impl AeadAlg {
    /// Parses a registry id; anything other than the two safe-API AEADs is `UnknownAlgorithm`.
    pub fn from_id(id: &str) -> Result<Self> {
        match id {
            "xchacha20-poly1305" => Ok(AeadAlg::XChaCha20Poly1305),
            "aes-256-gcm" => Ok(AeadAlg::Aes256Gcm),
            _ => Err(Error::UnknownAlgorithm),
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            AeadAlg::XChaCha20Poly1305 => "xchacha20-poly1305",
            AeadAlg::Aes256Gcm => "aes-256-gcm",
        }
    }
}

/// Signature algorithm. Default: ML-DSA-65 (post-quantum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignAlg {
    #[default]
    MlDsa65,
    Ed25519,
}

impl SignAlg {
    /// Parses a registry id; anything other than the two safe-API signatures is `UnknownAlgorithm`.
    pub fn from_id(id: &str) -> Result<Self> {
        match id {
            "ml-dsa-65" => Ok(SignAlg::MlDsa65),
            "ed25519" => Ok(SignAlg::Ed25519),
            _ => Err(Error::UnknownAlgorithm),
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            SignAlg::MlDsa65 => "ml-dsa-65",
            SignAlg::Ed25519 => "ed25519",
        }
    }
}

const KEM: &str = "ml-kem-768";
const PWHASH: &str = "argon2id";

/// OS entropy through the registry.
fn os_rng() -> Result<Box<dyn EntropySource>> {
    new_rng_in(all(), Policy::Safe, "os-entropy", &Params::new())
}

/// A fresh random 32-byte key for [`encrypt_with_key`].
pub fn generate_key() -> Result<SymmetricKey> {
    let mut b = Zeroizing::new(vec![0u8; 32]);
    os_rng()?.fill(&mut b)?;
    SymmetricKey::from_bytes(&b, Len::fixed(32))
}

// ---------------------------------------------------------------------------------------
// Encryption (COSE_Encrypt0)
// ---------------------------------------------------------------------------------------

/// COSE_Encrypt0 under `key` (32 bytes). `aad` is authenticated but not stored.
pub fn encrypt_with_key(
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &[u8],
    alg: AeadAlg,
) -> Result<Vec<u8>> {
    envelope::encrypt_in(
        all(),
        Policy::Safe,
        alg.id(),
        key,
        aad,
        plaintext,
        &mut *os_rng()?,
    )
}

/// Decrypts a key-based envelope; the algorithm comes from its (authenticated) header.
pub fn decrypt(key: &SymmetricKey, envelope: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_with_limits(key, envelope, aad, &Limits::default())
}

pub fn decrypt_with_limits(
    key: &SymmetricKey,
    envelope: &[u8],
    aad: &[u8],
    limits: &Limits,
) -> Result<Zeroizing<Vec<u8>>> {
    envelope::decrypt_in(all(), Policy::Safe, limits, key, envelope, aad)
}

/// Password-based COSE_Encrypt0: Argon2id derives the key; its parameters and salt travel in
/// the protected header. `kdf_params` are checked against the `argon2id` schema (`m_kib`, `t`,
/// `p`; unset values take the schema defaults); pass `Params::new()` for the defaults.
pub fn encrypt_with_password(
    password: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    alg: AeadAlg,
    kdf_params: &Params,
) -> Result<Vec<u8>> {
    envelope::encrypt_with_password_in(
        all(),
        Policy::Safe,
        &Limits::default(),
        alg.id(),
        PWHASH,
        kdf_params,
        password,
        aad,
        plaintext,
        &mut *os_rng()?,
    )
}

pub fn decrypt_with_password(
    password: &[u8],
    envelope: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_with_password_with_limits(password, envelope, aad, &Limits::default())
}

pub fn decrypt_with_password_with_limits(
    password: &[u8],
    envelope: &[u8],
    aad: &[u8],
    limits: &Limits,
) -> Result<Zeroizing<Vec<u8>>> {
    envelope::decrypt_with_password_in(all(), Policy::Safe, limits, password, envelope, aad)
}

// ---------------------------------------------------------------------------------------
// Signatures (COSE_Sign1)
// ---------------------------------------------------------------------------------------

/// Random signing key pair.
pub fn sign_keygen(alg: SignAlg) -> Result<(PublicKey, PrivateKey)> {
    nextssl_registry::new_sign_in(all(), Policy::Safe, alg.id(), &Params::new())?
        .keygen(&mut *os_rng()?)
}

/// COSE_Sign1 with the payload attached.
pub fn sign(alg: SignAlg, sk: &PrivateKey, message: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    envelope::sign_in(
        all(),
        Policy::Safe,
        alg.id(),
        sk,
        message,
        aad,
        &mut *os_rng()?,
    )
}

/// Verifies a COSE_Sign1 and returns the payload. The envelope must name exactly `alg`.
pub fn verify(alg: SignAlg, pk: &PublicKey, envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    verify_with_limits(alg, pk, envelope, aad, &Limits::default())
}

pub fn verify_with_limits(
    alg: SignAlg,
    pk: &PublicKey,
    envelope: &[u8],
    aad: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>> {
    envelope::verify_in(all(), Policy::Safe, limits, alg.id(), pk, envelope, aad)
}

// ---------------------------------------------------------------------------------------
// KEM (ML-KEM-768)
// ---------------------------------------------------------------------------------------

pub fn kem_keygen() -> Result<(PublicKey, PrivateKey)> {
    new_kem_in(all(), Policy::Safe, KEM, &Params::new())?.keygen(&mut *os_rng()?)
}

/// Returns the ciphertext to send and the shared secret to keep.
pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    new_kem_in(all(), Policy::Safe, KEM, &Params::new())?.encaps(pk, &mut *os_rng()?)
}

pub fn decapsulate(sk: &PrivateKey, ct: &Ciphertext) -> Result<SharedSecret> {
    new_kem_in(all(), Policy::Safe, KEM, &Params::new())?.decaps(sk, ct)
}

// ---------------------------------------------------------------------------------------
// MAC, KDF, password hashing
// ---------------------------------------------------------------------------------------

/// Full-length MAC tag (`hmac-sha256` is the registered MAC).
pub fn mac(alg: &str, key: &SymmetricKey, data: &[u8]) -> Result<Vec<u8>> {
    let m = new_mac_in(all(), Policy::Safe, alg, &Params::new())?;
    let n = m.sizes().tag.ok_or(Error::Unsupported)?.max();
    let mut tag = vec![0u8; n];
    m.tag(key, data, &mut tag)?;
    Ok(tag)
}

/// Constant-time MAC check. `Ok(false)` = wrong tag.
pub fn mac_verify(alg: &str, key: &SymmetricKey, data: &[u8], tag: &[u8]) -> Result<bool> {
    new_mac_in(all(), Policy::Safe, alg, &Params::new())?.verify(key, data, tag)
}

/// Derives exactly `out_len` bytes (an error if the KDF cannot produce that many).
pub fn kdf(
    alg: &str,
    ikm: &SymmetricKey,
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let k = new_kdf_in(all(), Policy::Safe, alg, &Params::new())?;
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    k.derive(ikm, salt, info, &mut out)?;
    Ok(out)
}

/// Argon2id PHC string with a random salt and the schema default cost.
pub fn password_hash(password: &[u8]) -> Result<String> {
    let h = new_pwhash_in(all(), Policy::Safe, PWHASH, &Params::new())?;
    let n = h.sizes().salt.ok_or(Error::Unsupported)?.min();
    let mut salt = vec![0u8; n];
    os_rng()?.fill(&mut salt)?;
    h.hash(password, &salt)
}

/// Verifies against a PHC string (strict parse, cost capped by the schema). `Ok(false)` =
/// wrong password; `Err` = malformed or out-of-policy string.
pub fn password_verify(password: &[u8], phc: &str) -> Result<bool> {
    new_pwhash_in(all(), Policy::Safe, PWHASH, &Params::new())?.verify(password, phc)
}

// ---------------------------------------------------------------------------------------
// Key generation shortcuts
// ---------------------------------------------------------------------------------------

/// Deterministic key pair for `ml-kem-768`, `ml-dsa-65`, `ed25519` or `x25519`.
pub fn keypair_from_seed(
    alg: &str,
    seed: &[u8],
    mode: SeedMode,
) -> Result<(PublicKey, PrivateKey)> {
    keygen::seed::keypair_from_seed_in(all(), Policy::Safe, alg, seed, mode)
}

/// Key from a password plus the record to store so it can be re-derived.
pub fn key_from_password(
    password: &[u8],
    params: &Params,
    key_len: usize,
) -> Result<(SymmetricKey, KdfRecord)> {
    keygen::password::derive_key_in(
        all(),
        Policy::Safe,
        &KdfCaps::default(),
        PWHASH,
        password,
        params,
        None,
        &mut *os_rng()?,
        key_len,
    )
}

// ---------------------------------------------------------------------------------------
// Composition engine and random keygen (nextssl-compose)
// ---------------------------------------------------------------------------------------

pub use nextssl_compose::{Built, Composed};

/// Builds a composition such as `hmac(sha3-256)`, `hkdf(sm3)` or `pbkdf2(hmac(sha256))`.
/// The effective tier is the worst of the parts; anything below `standard` (a `broken` hash in
/// an HMAC, every DRBG and PoW composition today) is `Error::TierNotAllowed`.
pub fn compose(spec: &str) -> Result<Composed> {
    nextssl_compose::compose(spec, Policy::Safe)
}

/// Like [`compose`] with explicit parameters (`pbkdf2`: `iterations`, `out_len`; `cbc`/`ecb`:
/// `padding`).
pub fn compose_with(spec: &str, params: &Params) -> Result<Composed> {
    nextssl_compose::compose_with(spec, params, Policy::Safe)
}

/// `n` random bytes (1..=16 MiB) from `rng`: `"os-entropy"` or a safe/standard DRBG id
/// (`"hmac-drbg-sha256"`). The DRBG is seeded from OS entropy; see `nextssl_compose::rng`.
pub fn random_bytes(n: usize, rng: &str) -> Result<Zeroizing<Vec<u8>>> {
    nextssl_compose::keygen::random_bytes(n, rng, Policy::Safe)
}

/// A key of the right length for the AEAD, MAC or cipher `alg`, drawn from `rng`.
pub fn random_key(alg: &str, rng: &str) -> Result<SymmetricKey> {
    nextssl_compose::keygen::random_key(alg, rng, Policy::Safe)
}

/// Key pair for a signature, KEM or key-exchange algorithm, with the randomness source chosen
/// by the caller. [`sign_keygen`], [`kem_keygen`] draw from the OS directly.
pub fn keygen_with_rng(alg: &str, rng: &str) -> Result<(PublicKey, PrivateKey)> {
    nextssl_compose::keygen::keygen_with_rng(alg, rng, Policy::Safe)
}

#[doc(hidden)]
pub fn hash_in_table(table: &[AlgoInfo], alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    hash_in(table, Policy::Safe, alg, &Params::new(), data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::{Hash, Kind, Sizes, Status};
    use nextssl_registry::Ctor;

    #[test]
    fn compose_and_random_keygen_obey_the_safe_policy() {
        let c = compose("hkdf(sha256)").unwrap();
        assert_eq!(c.tier(), Tier::Standard);
        assert_eq!(
            compose("hmac-drbg(sha256)").err(),
            Some(Error::TierNotAllowed(Tier::Unverified))
        );
        assert_eq!(
            compose("hashcash(sha256)").err(),
            Some(Error::TierNotAllowed(Tier::Unverified))
        );
        assert_eq!(random_bytes(16, "os-entropy").unwrap().len(), 16);
        assert_eq!(random_bytes(16, "hmac-drbg-sha256").unwrap().len(), 16);
        assert!(random_bytes(16, "hash-drbg(sha256)").is_err());
        assert_eq!(random_key("aes-128-gcm", "os-entropy").unwrap().len(), 16);
        assert!(keygen_with_rng("ml-kem-768", "hmac-drbg-sha256").is_ok());
    }

    struct Fake;
    impl Hash for Fake {
        fn output_len(&self) -> usize {
            1
        }
        fn digest(&self, _d: &[u8], out: &mut [u8]) -> Result<()> {
            out[0] = 0;
            Ok(())
        }
    }
    fn new_fake(_: &Params) -> Result<Box<dyn Hash>> {
        Ok(Box::new(Fake))
    }
    fn fake(id: &'static str, tier: Tier) -> AlgoInfo {
        AlgoInfo {
            id,
            kind: Kind::Hash,
            category: "test",
            family: "test",
            aliases: &[],
            tier,
            status: Status::Active,
            standards: &[],
            license: "CC0-1.0",
            copyleft: false,
            c_backed: false,
            fips: false,
            cose_alg: None,
            oid: "",
            sizes: Sizes::NONE,
            params: &[],
            test_params: &[],
            dir: "",
            kat: &[],
            smoke_skip: None,
            ctor: Ctor::Hash(new_fake),
        }
    }

    #[test]
    fn safe_api_rejects_non_safe_tiers() {
        let table = [
            fake("fake-broken", Tier::Broken),
            fake("fake-legacy", Tier::Legacy),
            fake("fake-research", Tier::Research),
            fake("fake-safe", Tier::Safe),
            fake("fake-standard", Tier::Standard),
        ];
        assert_eq!(
            hash_in_table(&table, "fake-broken", b""),
            Err(Error::TierNotAllowed(Tier::Broken))
        );
        assert_eq!(
            hash_in_table(&table, "fake-legacy", b""),
            Err(Error::TierNotAllowed(Tier::Legacy))
        );
        assert_eq!(
            hash_in_table(&table, "fake-research", b""),
            Err(Error::TierNotAllowed(Tier::Research))
        );
        assert!(hash_in_table(&table, "fake-safe", b"").is_ok());
        assert!(hash_in_table(&table, "fake-standard", b"").is_ok());
    }

    #[test]
    fn real_registry_is_reachable_and_wrong_kind_rejected() {
        assert_eq!(hash("sha256", b"abc").unwrap().len(), 32);
        assert_eq!(hash("nope", b""), Err(Error::UnknownAlgorithm));
        assert_eq!(hash("base64", b""), Err(Error::WrongKind));
        assert_eq!(encode("base64", b"foo").unwrap(), b"Zm9v");
        assert_eq!(decode("base64", b"Zm9v").unwrap(), b"foo");
    }
}
