//! Root API. Same calls as `nextssl` but every tier is reachable, including `legacy`,
//! `broken` and `research` algorithms. The caller accepts the risk by choosing this crate.

use nextssl_core::Params;
use nextssl_registry::{decode_in, encode_in, hash_in, AlgoInfo, Policy};

pub use nextssl_core::{Error, Result, Tier, Value};
pub use nextssl_registry::all as algorithms;

pub fn hash(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    hash_with(alg, &Params::new(), data)
}

pub fn hash_with(alg: &str, params: &Params, data: &[u8]) -> Result<Vec<u8>> {
    hash_in(nextssl_registry::all(), Policy::Any, alg, params, data)
}

pub fn encode(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    encode_in(
        nextssl_registry::all(),
        Policy::Any,
        alg,
        &Params::new(),
        data,
    )
}

pub fn decode(alg: &str, text: &[u8]) -> Result<Vec<u8>> {
    decode_in(
        nextssl_registry::all(),
        Policy::Any,
        alg,
        &Params::new(),
        text,
    )
}

// ---- envelopes, any tier --------------------------------------------------------------
// Same COSE formats as the safe API, but the algorithm is any registered id and every tier
// (legacy, broken, research) may be created and decoded. The caller accepts the risk.

use nextssl::envelope::{self, Limits};
use nextssl_core::{EntropySource, PrivateKey, PublicKey, SymmetricKey, Zeroizing};

fn os_rng() -> Result<Box<dyn EntropySource>> {
    nextssl_registry::new_rng_in(
        nextssl_registry::all(),
        Policy::Any,
        "os-entropy",
        &Params::new(),
    )
}

/// COSE_Encrypt0 with any registered AEAD (by id).
pub fn encrypt_with_key(
    alg: &str,
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    envelope::encrypt_in(
        nextssl_registry::all(),
        Policy::Any,
        alg,
        key,
        aad,
        plaintext,
        &mut *os_rng()?,
    )
}

/// Decrypts a key-based envelope of any tier.
pub fn decrypt(key: &SymmetricKey, envelope: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    envelope::decrypt_in(
        nextssl_registry::all(),
        Policy::Any,
        &Limits::default(),
        key,
        envelope,
        aad,
    )
}

/// Decrypts a key-based envelope of any tier, requiring that it names exactly `alg`.
pub fn decrypt_as(
    alg: &str,
    key: &SymmetricKey,
    envelope: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    envelope::decrypt_expect_in(
        nextssl_registry::all(),
        Policy::Any,
        &Limits::default(),
        alg,
        key,
        envelope,
        aad,
    )
}

/// COSE_Sign1 with any registered signature algorithm (by id).
pub fn sign(alg: &str, sk: &PrivateKey, message: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    envelope::sign_in(
        nextssl_registry::all(),
        Policy::Any,
        alg,
        sk,
        message,
        aad,
        &mut *os_rng()?,
    )
}

/// Verifies a COSE_Sign1 of any tier; the envelope must name exactly `alg`.
pub fn verify(alg: &str, pk: &PublicKey, envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    envelope::verify_in(
        nextssl_registry::all(),
        Policy::Any,
        &Limits::default(),
        alg,
        pk,
        envelope,
        aad,
    )
}

// ---- keyless and symmetric primitives, any tier -----------------------------------------
// Thin string-based entry points. The flat accessors in `generated.rs` (for example
// `nextssl_root::hmac::tag`) call these with a fixed algorithm id. Every `*_with` takes
// explicit parameters; the plain form uses the schema defaults.

use nextssl_core::{Ciphertext, SharedSecret, MAX_INPUT_LEN};
use nextssl_registry::{
    new_aead_in, new_blockcipher_in, new_blockmode_in, new_checksum_in, new_kdf_in, new_kem_in,
    new_kex_in, new_mac_in, new_pke_in, new_pwhash_in, new_sign_in, new_streamcipher_in,
    new_threshold_in, new_vdf_in, new_xof_in, new_zk_in,
};

fn check_input(data: &[u8]) -> Result<()> {
    nextssl_core::check_len("input", data.len(), 0, MAX_INPUT_LEN)
}

fn reg() -> &'static [AlgoInfo] {
    nextssl_registry::all()
}

pub fn encode_with(alg: &str, params: &Params, data: &[u8]) -> Result<Vec<u8>> {
    encode_in(reg(), Policy::Any, alg, params, data)
}

pub fn decode_with(alg: &str, params: &Params, text: &[u8]) -> Result<Vec<u8>> {
    decode_in(reg(), Policy::Any, alg, params, text)
}

/// Upper bound on one XOF call made through the root API (16 MiB).
const MAX_XOF_OUT: usize = 1 << 24;

/// Extendable-output function: exactly `out_len` bytes (1..=16 MiB).
pub fn xof_with(alg: &str, params: &Params, data: &[u8], out_len: usize) -> Result<Vec<u8>> {
    check_input(data)?;
    let x = new_xof_in(reg(), Policy::Any, alg, params)?;
    nextssl_core::check_len("out", out_len, 1, MAX_XOF_OUT)?;
    let mut out = vec![0u8; out_len];
    x.squeeze(data, &mut out)?;
    Ok(out)
}

pub fn xof(alg: &str, data: &[u8], out_len: usize) -> Result<Vec<u8>> {
    xof_with(alg, &Params::new(), data, out_len)
}

/// Non-cryptographic checksum (CRC, Adler, ...), full-length output.
pub fn checksum_with(alg: &str, params: &Params, data: &[u8]) -> Result<Vec<u8>> {
    check_input(data)?;
    let c = new_checksum_in(reg(), Policy::Any, alg, params)?;
    let n = c.sizes().out.ok_or(Error::Unsupported)?.max();
    let mut out = vec![0u8; n];
    c.checksum(data, &mut out)?;
    Ok(out)
}

pub fn checksum(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    checksum_with(alg, &Params::new(), data)
}

/// Full-length MAC tag.
pub fn mac_with(alg: &str, params: &Params, key: &SymmetricKey, data: &[u8]) -> Result<Vec<u8>> {
    check_input(data)?;
    let m = new_mac_in(reg(), Policy::Any, alg, params)?;
    let n = m.sizes().tag.ok_or(Error::Unsupported)?.max();
    let mut tag = vec![0u8; n];
    m.tag(key, data, &mut tag)?;
    Ok(tag)
}

pub fn mac(alg: &str, key: &SymmetricKey, data: &[u8]) -> Result<Vec<u8>> {
    mac_with(alg, &Params::new(), key, data)
}

/// Constant-time MAC check. `Ok(false)` = wrong tag, `Err` = undeclared tag length.
pub fn mac_verify_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    data: &[u8],
    tag: &[u8],
) -> Result<bool> {
    check_input(data)?;
    new_mac_in(reg(), Policy::Any, alg, params)?.verify(key, data, tag)
}

pub fn mac_verify(alg: &str, key: &SymmetricKey, data: &[u8], tag: &[u8]) -> Result<bool> {
    mac_verify_with(alg, &Params::new(), key, data, tag)
}

/// Derives exactly `out_len` bytes (an error if the KDF cannot produce that many).
pub fn kdf_with(
    alg: &str,
    params: &Params,
    ikm: &SymmetricKey,
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    check_input(salt)?;
    check_input(info)?;
    let k = new_kdf_in(reg(), Policy::Any, alg, params)?;
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    k.derive(ikm, salt, info, &mut out)?;
    Ok(out)
}

pub fn kdf(
    alg: &str,
    ikm: &SymmetricKey,
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    kdf_with(alg, &Params::new(), ikm, salt, info, out_len)
}

/// Password hash as a PHC string with a caller-supplied salt.
pub fn password_hash_salted_with(
    alg: &str,
    params: &Params,
    password: &[u8],
    salt: &[u8],
) -> Result<String> {
    check_input(password)?;
    new_pwhash_in(reg(), Policy::Any, alg, params)?.hash(password, salt)
}

pub fn password_hash_salted(alg: &str, password: &[u8], salt: &[u8]) -> Result<String> {
    password_hash_salted_with(alg, &Params::new(), password, salt)
}

/// Password hash as a PHC string with a fresh random salt (16 bytes, clamped to the
/// algorithm's declared salt range).
pub fn password_hash_with(alg: &str, params: &Params, password: &[u8]) -> Result<String> {
    check_input(password)?;
    let h = new_pwhash_in(reg(), Policy::Any, alg, params)?;
    let s = h.sizes().salt.ok_or(Error::Unsupported)?;
    let mut salt = vec![0u8; 16usize.clamp(s.min(), s.max())];
    os_rng()?.fill(&mut salt)?;
    h.hash(password, &salt)
}

pub fn password_hash(alg: &str, password: &[u8]) -> Result<String> {
    password_hash_with(alg, &Params::new(), password)
}

/// Verifies against a PHC string. `Ok(false)` = wrong password; `Err` = malformed string.
pub fn password_verify_with(
    alg: &str,
    params: &Params,
    password: &[u8],
    phc: &str,
) -> Result<bool> {
    check_input(password)?;
    new_pwhash_in(reg(), Policy::Any, alg, params)?.verify(password, phc)
}

pub fn password_verify(alg: &str, password: &[u8], phc: &str) -> Result<bool> {
    password_verify_with(alg, &Params::new(), password, phc)
}

/// Raw key derivation from a password: exactly `out_len` bytes.
pub fn password_derive_with(
    alg: &str,
    params: &Params,
    password: &[u8],
    salt: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    check_input(password)?;
    let h = new_pwhash_in(reg(), Policy::Any, alg, params)?;
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    h.derive(password, salt, &mut out)?;
    Ok(out)
}

pub fn password_derive(
    alg: &str,
    password: &[u8],
    salt: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    password_derive_with(alg, &Params::new(), password, salt, out_len)
}

/// Raw AEAD seal: returns `ciphertext || tag`. The caller owns nonce uniqueness; prefer
/// [`encrypt_with_key`], which draws a fresh nonce.
pub fn aead_seal_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    check_input(pt)?;
    check_input(aad)?;
    new_aead_in(reg(), Policy::Any, alg, params)?.seal(key, nonce, aad, pt)
}

pub fn aead_seal(
    alg: &str,
    key: &SymmetricKey,
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    aead_seal_with(alg, &Params::new(), key, nonce, aad, pt)
}

/// Raw AEAD open of `ciphertext || tag`. Failure is `Error::AuthenticationFailed`.
pub fn aead_open_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    check_input(ct)?;
    check_input(aad)?;
    new_aead_in(reg(), Policy::Any, alg, params)?.open(key, nonce, aad, ct)
}

pub fn aead_open(
    alg: &str,
    key: &SymmetricKey,
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    aead_open_with(alg, &Params::new(), key, nonce, aad, ct)
}

/// One block, encrypted in place. `block.len()` must equal the cipher block size.
pub fn block_encrypt_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    block: &mut [u8],
) -> Result<()> {
    new_blockcipher_in(reg(), Policy::Any, alg, params)?.encrypt_block(key, block)
}

pub fn block_encrypt(alg: &str, key: &SymmetricKey, block: &mut [u8]) -> Result<()> {
    block_encrypt_with(alg, &Params::new(), key, block)
}

pub fn block_decrypt_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    block: &mut [u8],
) -> Result<()> {
    new_blockcipher_in(reg(), Policy::Any, alg, params)?.decrypt_block(key, block)
}

pub fn block_decrypt(alg: &str, key: &SymmetricKey, block: &mut [u8]) -> Result<()> {
    block_decrypt_with(alg, &Params::new(), key, block)
}

/// XORs the keystream into `data` in place (encrypt and decrypt are the same call).
pub fn stream_apply_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    nonce: &[u8],
    data: &mut [u8],
) -> Result<()> {
    check_input(data)?;
    new_streamcipher_in(reg(), Policy::Any, alg, params)?.apply_keystream(key, nonce, data)
}

pub fn stream_apply(alg: &str, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
    stream_apply_with(alg, &Params::new(), key, nonce, data)
}

/// Encrypts `data` with the concrete block-cipher mode `alg` (`aes-256-cbc`, `aes-128-xts`,
/// `aes-kw`, ...). `nonce` is the IV / tweak, empty for modes that take none.
pub fn blockmode_encrypt_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    nonce: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    check_input(data)?;
    new_blockmode_in(reg(), Policy::Any, alg, params)?.encrypt(key, nonce, data)
}

pub fn blockmode_encrypt(
    alg: &str,
    key: &SymmetricKey,
    nonce: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    blockmode_encrypt_with(alg, &Params::new(), key, nonce, data)
}

pub fn blockmode_decrypt_with(
    alg: &str,
    params: &Params,
    key: &SymmetricKey,
    nonce: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    check_input(data)?;
    new_blockmode_in(reg(), Policy::Any, alg, params)?.decrypt(key, nonce, data)
}

pub fn blockmode_decrypt(
    alg: &str,
    key: &SymmetricKey,
    nonce: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    blockmode_decrypt_with(alg, &Params::new(), key, nonce, data)
}

// ---- asymmetric, any tier ---------------------------------------------------------------

/// Signature key pair from the OS RNG.
pub fn sign_keygen_with(alg: &str, params: &Params) -> Result<(PublicKey, PrivateKey)> {
    new_sign_in(reg(), Policy::Any, alg, params)?.keygen(&mut *os_rng()?)
}

pub fn sign_keygen(alg: &str) -> Result<(PublicKey, PrivateKey)> {
    sign_keygen_with(alg, &Params::new())
}

pub fn kem_keygen_with(alg: &str, params: &Params) -> Result<(PublicKey, PrivateKey)> {
    new_kem_in(reg(), Policy::Any, alg, params)?.keygen(&mut *os_rng()?)
}

pub fn kem_keygen(alg: &str) -> Result<(PublicKey, PrivateKey)> {
    kem_keygen_with(alg, &Params::new())
}

pub fn kem_encapsulate_with(
    alg: &str,
    params: &Params,
    pk: &PublicKey,
) -> Result<(Ciphertext, SharedSecret)> {
    new_kem_in(reg(), Policy::Any, alg, params)?.encaps(pk, &mut *os_rng()?)
}

pub fn kem_encapsulate(alg: &str, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    kem_encapsulate_with(alg, &Params::new(), pk)
}

pub fn kem_decapsulate_with(
    alg: &str,
    params: &Params,
    sk: &PrivateKey,
    ct: &Ciphertext,
) -> Result<SharedSecret> {
    new_kem_in(reg(), Policy::Any, alg, params)?.decaps(sk, ct)
}

pub fn kem_decapsulate(alg: &str, sk: &PrivateKey, ct: &Ciphertext) -> Result<SharedSecret> {
    kem_decapsulate_with(alg, &Params::new(), sk, ct)
}

pub fn kex_keygen_with(alg: &str, params: &Params) -> Result<(PublicKey, PrivateKey)> {
    new_kex_in(reg(), Policy::Any, alg, params)?.keypair(&mut *os_rng()?)
}

pub fn kex_keygen(alg: &str) -> Result<(PublicKey, PrivateKey)> {
    kex_keygen_with(alg, &Params::new())
}

/// Shared secret from our private key and the peer's public key. The raw secret is not
/// hashed; feed it to a KDF.
pub fn kex_agree_with(
    alg: &str,
    params: &Params,
    sk: &PrivateKey,
    peer_pk: &PublicKey,
) -> Result<SharedSecret> {
    new_kex_in(reg(), Policy::Any, alg, params)?.agree(sk, peer_pk)
}

pub fn kex_agree(alg: &str, sk: &PrivateKey, peer_pk: &PublicKey) -> Result<SharedSecret> {
    kex_agree_with(alg, &Params::new(), sk, peer_pk)
}

// ---- root-only kinds: pke, zk, vdf, threshold ---------------------------------------------
// Not reachable from the safe API. Pake, stateful signatures and homomorphic encryption are
// stateful or multi-object: build them with `nextssl_registry::new_<kind>_in(.., Policy::Any, ..)`.

pub use nextssl_registry::{new_he_in, new_pake_in, new_statefulsign_in};

pub fn pke_keygen_with(alg: &str, params: &Params) -> Result<(PublicKey, PrivateKey)> {
    new_pke_in(reg(), Policy::Any, alg, params)?.keygen(&mut *os_rng()?)
}

pub fn pke_keygen(alg: &str) -> Result<(PublicKey, PrivateKey)> {
    pke_keygen_with(alg, &Params::new())
}

pub fn pke_encrypt_with(
    alg: &str,
    params: &Params,
    pk: &PublicKey,
    pt: &[u8],
    label: &[u8],
) -> Result<Vec<u8>> {
    check_input(pt)?;
    new_pke_in(reg(), Policy::Any, alg, params)?.encrypt(pk, pt, label, &mut *os_rng()?)
}

pub fn pke_encrypt(alg: &str, pk: &PublicKey, pt: &[u8], label: &[u8]) -> Result<Vec<u8>> {
    pke_encrypt_with(alg, &Params::new(), pk, pt, label)
}

/// Every decryption failure is the same `Error::AuthenticationFailed`.
pub fn pke_decrypt_with(
    alg: &str,
    params: &Params,
    sk: &PrivateKey,
    ct: &[u8],
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    check_input(ct)?;
    new_pke_in(reg(), Policy::Any, alg, params)?.decrypt(sk, ct, label)
}

pub fn pke_decrypt(
    alg: &str,
    sk: &PrivateKey,
    ct: &[u8],
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    pke_decrypt_with(alg, &Params::new(), sk, ct, label)
}

pub fn zk_setup_with(alg: &str, params: &Params, setup_params: &[u8]) -> Result<Vec<u8>> {
    check_input(setup_params)?;
    new_zk_in(reg(), Policy::Any, alg, params)?.setup(setup_params, &mut *os_rng()?)
}

pub fn zk_setup(alg: &str, setup_params: &[u8]) -> Result<Vec<u8>> {
    zk_setup_with(alg, &Params::new(), setup_params)
}

pub fn zk_prove_with(
    alg: &str,
    params: &Params,
    setup: &[u8],
    statement: &[u8],
    witness: &[u8],
) -> Result<Vec<u8>> {
    check_input(setup)?;
    check_input(statement)?;
    check_input(witness)?;
    new_zk_in(reg(), Policy::Any, alg, params)?.prove(setup, statement, witness, &mut *os_rng()?)
}

pub fn zk_prove(alg: &str, setup: &[u8], statement: &[u8], witness: &[u8]) -> Result<Vec<u8>> {
    zk_prove_with(alg, &Params::new(), setup, statement, witness)
}

pub fn zk_verify_with(
    alg: &str,
    params: &Params,
    setup: &[u8],
    statement: &[u8],
    proof: &[u8],
) -> Result<bool> {
    check_input(setup)?;
    check_input(statement)?;
    check_input(proof)?;
    new_zk_in(reg(), Policy::Any, alg, params)?.verify(setup, statement, proof)
}

pub fn zk_verify(alg: &str, setup: &[u8], statement: &[u8], proof: &[u8]) -> Result<bool> {
    zk_verify_with(alg, &Params::new(), setup, statement, proof)
}

pub fn vdf_eval_with(
    alg: &str,
    params: &Params,
    challenge: &[u8],
    t: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    check_input(challenge)?;
    new_vdf_in(reg(), Policy::Any, alg, params)?.eval(challenge, t)
}

pub fn vdf_eval(alg: &str, challenge: &[u8], t: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    vdf_eval_with(alg, &Params::new(), challenge, t)
}

pub fn vdf_verify_with(
    alg: &str,
    params: &Params,
    challenge: &[u8],
    t: u64,
    output: &[u8],
    proof: &[u8],
) -> Result<bool> {
    check_input(challenge)?;
    check_input(output)?;
    check_input(proof)?;
    new_vdf_in(reg(), Policy::Any, alg, params)?.verify(challenge, t, output, proof)
}

pub fn vdf_verify(
    alg: &str,
    challenge: &[u8],
    t: u64,
    output: &[u8],
    proof: &[u8],
) -> Result<bool> {
    vdf_verify_with(alg, &Params::new(), challenge, t, output, proof)
}

/// `t` of `n` secret sharing; `1 <= t <= n <= max_parties` is enforced by the algorithm.
pub fn threshold_split_with(
    alg: &str,
    params: &Params,
    secret: &[u8],
    t: usize,
    n: usize,
) -> Result<Vec<nextssl_core::Share>> {
    check_input(secret)?;
    new_threshold_in(reg(), Policy::Any, alg, params)?.split(secret, t, n, &mut *os_rng()?)
}

pub fn threshold_split(
    alg: &str,
    secret: &[u8],
    t: usize,
    n: usize,
) -> Result<Vec<nextssl_core::Share>> {
    threshold_split_with(alg, &Params::new(), secret, t, n)
}

pub fn threshold_combine_with(
    alg: &str,
    params: &Params,
    shares: &[nextssl_core::Share],
) -> Result<Zeroizing<Vec<u8>>> {
    new_threshold_in(reg(), Policy::Any, alg, params)?.combine(shares)
}

pub fn threshold_combine(alg: &str, shares: &[nextssl_core::Share]) -> Result<Zeroizing<Vec<u8>>> {
    threshold_combine_with(alg, &Params::new(), shares)
}

// ---- composition engine and random keygen, any tier -----------------------------------------

pub use nextssl_compose::{Built, Composed};

/// Builds a composition such as `hmac(sm3)`, `pbkdf2(hmac(blake3))`, `hmac-drbg(sha512)`,
/// `ctr-drbg(aes-256)` or `hashcash(sha256)`. Every tier is reachable; the returned handle
/// reports the effective tier (the worst part). A part that is not compiled in (see the cargo
/// feature `compose-all`) is `Error::Unsupported`.
pub fn compose(spec: &str) -> Result<Composed> {
    nextssl_compose::compose(spec, Policy::Any)
}

/// Like [`compose`] with explicit parameters.
pub fn compose_with(spec: &str, params: &Params) -> Result<Composed> {
    nextssl_compose::compose_with(spec, params, Policy::Any)
}

/// `n` random bytes (1..=16 MiB) from `rng`: `"os-entropy"`, a registered DRBG id or a composed
/// DRBG such as `"hash-drbg(sha256)"`.
pub fn random_bytes(n: usize, rng: &str) -> Result<nextssl_core::Zeroizing<Vec<u8>>> {
    nextssl_compose::keygen::random_bytes(n, rng, Policy::Any)
}

/// A key of the right length for the AEAD, MAC or cipher `alg`, drawn from `rng`.
pub fn random_key(alg: &str, rng: &str) -> Result<SymmetricKey> {
    nextssl_compose::keygen::random_key(alg, rng, Policy::Any)
}

/// Key pair for a signature, KEM or key-exchange algorithm with a caller-chosen randomness source.
pub fn keygen_with_rng(alg: &str, rng: &str) -> Result<(PublicKey, PrivateKey)> {
    nextssl_compose::keygen::keygen_with_rng(alg, rng, Policy::Any)
}

/// A verified FF70 frame: `header`, `exclude`, `meta` and the decoded `payload`.
pub use nextssl_algo_ff70::Frame as Ff70Frame;

/// Parses and verifies any FF70 frame (`[Header](Config){Data|Sum}[Meta]`) and returns all its
/// fields. The 4-byte BLAKE3 sum is an error check only, not an authenticator.
pub fn ff70_parse(text: &[u8]) -> Result<Ff70Frame> {
    nextssl_algo_ff70::parse(text)
}

// ---- flat per-algorithm accessors ---------------------------------------------------------
// One module per registered algorithm id (`sha3-256` -> `sha3_256`), generated by
// `cargo xtask gen` from the registry. `include!` makes a name clash with an item above a
// compile error as well as a generator error.
include!("generated.rs");

#[doc(hidden)]
pub fn hash_in_table(table: &[AlgoInfo], alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    hash_in(table, Policy::Any, alg, &Params::new(), data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_reaches_all_registered_algorithms() {
        assert_eq!(hash("blake2b-512", b"").unwrap().len(), 64);
        assert_eq!(encode("base64", b"f").unwrap(), b"Zg==");
        assert_eq!(decode("base64", b"Zg==").unwrap(), b"f");
    }

    #[test]
    fn flat_accessors_work_for_each_kind() {
        use nextssl_core::Len;
        // hash, encoding
        assert_eq!(md5::hash(b"").unwrap().len(), 16);
        assert_eq!(base64::encode(b"f").unwrap(), b"Zg==");
        assert_eq!(&md5::INFO.id, &"md5");
        // enum parameter: default sha256, explicit sha512, unknown value is an error
        let key = SymmetricKey::from_bytes(&[7; 32], Len::fixed(32)).unwrap();
        assert_eq!(hmac::tag(&key, b"m").unwrap().len(), 32);
        let p512 = Params::new().with("hash", Value::Str("sha512".into()));
        let t = hmac::tag_with(&p512, &key, b"m").unwrap();
        assert_eq!(t.len(), 64);
        assert!(hmac::verify_with(&p512, &key, b"m", &t).unwrap());
        let bad = Params::new().with("hash", Value::Str("md5".into()));
        assert!(hmac::tag_with(&bad, &key, b"m").is_err());
        // required string parameter: only the `_with` form exists
        let bc = Params::new().with("hrp", Value::Str("bc".into()));
        let s = bech32::encode_with(&bc, b"abc").unwrap();
        assert_eq!(bech32::decode_with(&bc, &s).unwrap(), b"abc");
        // AEAD envelope and raw
        let env = aes_256_gcm::encrypt(&key, b"hello", b"aad").unwrap();
        assert_eq!(
            &aes_256_gcm::decrypt(&key, &env, b"aad").unwrap()[..],
            b"hello"
        );
        assert!(xchacha20_poly1305::decrypt(&key, &env, b"aad").is_err());
        // KEM and signature
        let (pk, sk) = ml_kem_768::keygen().unwrap();
        let (ct, ss) = ml_kem_768::encapsulate(&pk).unwrap();
        assert_eq!(ml_kem_768::decapsulate(&sk, &ct).unwrap(), ss);
        let (pk, sk) = ed25519::keygen().unwrap();
        let sig = ed25519::sign(&sk, b"msg", b"").unwrap();
        assert_eq!(ed25519::verify(&pk, &sig, b"").unwrap(), b"msg");
        // KDF
        let okm = hkdf::derive(&key, b"salt", b"info", 42).unwrap();
        assert_eq!(okm.len(), 42);
    }

    #[test]
    fn compose_random_keygen_and_ff70_frame() {
        use nextssl_core::Len;
        let key = SymmetricKey::from_bytes(&[7; 32], Len::fixed(32)).unwrap();
        let c = compose("hmac(sha3-256)").unwrap();
        assert_eq!(c.canonical(), "hmac(sha3-256)");
        let mut tag = [0u8; 32];
        c.mac().unwrap().tag(&key, b"m", &mut tag).unwrap();
        let reg = hmac::tag_with(
            &Params::new().with("hash", Value::Str("sha3-256".into())),
            &key,
            b"m",
        )
        .unwrap();
        assert_eq!(&tag[..], &reg[..]);
        assert_eq!(random_bytes(10, "hash-drbg(sha256)").unwrap().len(), 10);
        assert_eq!(
            random_key("aes-256-gcm", "ctr-drbg(aes-128)")
                .unwrap()
                .len(),
            32
        );
        assert!(keygen_with_rng("ed25519", "hmac-drbg(sha512)").is_ok());
        let e = ff70::encode_with(
            &Params::new()
                .with("header", Value::Str("Key".into()))
                .with("meta", Value::Str("t:1".into())),
            b"abc",
        )
        .unwrap();
        let f = ff70_parse(&e).unwrap();
        assert_eq!(
            (f.header.as_str(), f.meta.as_str(), &f.payload[..]),
            ("Key", "t:1", &b"abc"[..])
        );
        assert!(ff70_parse(b"[](){|}[]").is_err());
    }

    #[test]
    fn root_envelopes_round_trip_any_registered_id() {
        use nextssl_core::Len;
        let key = SymmetricKey::from_bytes(&[5; 32], Len::fixed(32)).unwrap();
        let env = encrypt_with_key("aes-256-gcm", &key, b"root", b"").unwrap();
        assert_eq!(&decrypt(&key, &env, b"").unwrap()[..], b"root");
        assert_eq!(
            encrypt_with_key("sha256", &key, b"x", b"").err(),
            Some(Error::WrongKind)
        );
    }
}
