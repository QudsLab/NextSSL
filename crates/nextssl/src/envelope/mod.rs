//! Self-describing output (REBUILD_PLAN.md section 5): COSE_Encrypt0 and COSE_Sign1 (RFC 9052)
//! built with the `coset` crate, plus the `nxs1.` + base64url text form.
//!
//! # Algorithm ids
//! The algorithm is named in the protected header by its COSE id, taken from `algo.toml`
//! `cose_alg` (IANA where one exists: A256GCM = 3, Ed25519 = -19, ML-DSA-65 = -49; private use
//! below -65536 otherwise: XChaCha20-Poly1305 = -65800, Argon2id = -65601).
//!
//! # Password envelopes
//! The protected header also carries the private-use header parameter [`KDF_LABEL`] (listed in
//! `crit`, so a foreign decoder that does not know it must refuse): `[kdf_cose_alg, salt,
//! {param: uint, ...}]`. It holds every KDF parameter, so the key can be re-derived.
//!
//! # Decoding rules (all enforced before any key material is touched)
//! 1. input size <= [`Limits::max_input`]; CBOR nesting <= `max_depth`, items <= `max_items`,
//!    definite lengths only (the protected header bytes are checked too), exactly one item;
//! 2. the CBOR tag must be the expected one (16 Encrypt0 / 18 Sign1): no guessing;
//! 3. `alg` must be in the protected header, resolve in the registry to the expected kind, and
//!    the tier must be allowed by the policy (safe API: safe + standard) and the algorithm
//!    must be `active` or `deprecated`;
//! 4. `crit` must be protected, and every critical label must be understood here;
//! 5. KDF parameters are schema-validated and capped (see `keygen::password`).

mod guard;

use crate::keygen::password::{self, KdfCaps, KdfRecord};
use base64ct::{Base64UrlUnpadded, Encoding};
use coset::cbor::value::Value;
use coset::iana::EnumI64;
use coset::{
    enc_structure_data, sig_structure_data, Algorithm, AsCborValue, CoseEncrypt0,
    CoseEncrypt0Builder, CoseSign1, CoseSign1Builder, EncryptionContext, Header, HeaderBuilder,
    Label, RegisteredLabelWithPrivate, SignatureContext, TaggedCborSerializable,
};
use nextssl_core::Status;
use nextssl_core::{
    EntropySource, Error, Kind, Len, Params, PrivateKey, PublicKey, Result, Signature,
    SymmetricKey, Zeroizing,
};
use nextssl_registry::{
    allowed, lookup_cose_in, lookup_in, new_aead_in, new_sign_in, AlgoInfo, Policy,
};

/// Text form prefix.
pub const TEXT_PREFIX: &str = "nxs1.";
/// Private-use COSE header parameter holding the KDF record of a password envelope.
pub const KDF_LABEL: i64 = -66000;

const TAG_ENCRYPT0: u8 = 0xd0; // tag 16
const TAG_SIGN1: u8 = 0xd2; // tag 18

/// Decoder limits. The defaults are safe for untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum envelope size in bytes (default 64 MiB).
    pub max_input: usize,
    /// Maximum CBOR nesting depth (default 8).
    pub max_depth: usize,
    /// Maximum number of CBOR data items, string contents excluded (default 256).
    pub max_items: usize,
    /// Bounds on KDF cost parameters of password envelopes.
    pub kdf: KdfCaps,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_input: 64 << 20,
            max_depth: 8,
            max_items: 256,
            kdf: KdfCaps::default(),
        }
    }
}

fn malformed(what: &'static str) -> Error {
    Error::InvalidInput(what)
}

// ---------------------------------------------------------------------------------------
// Text form
// ---------------------------------------------------------------------------------------

/// `nxs1.` + base64url (no padding) of the envelope bytes.
pub fn to_text(envelope: &[u8]) -> String {
    format!(
        "{TEXT_PREFIX}{}",
        Base64UrlUnpadded::encode_string(envelope)
    )
}

/// Strict inverse of [`to_text`]: exact prefix, canonical unpadded base64url, size limit
/// applied to the text before anything is decoded.
pub fn from_text(text: &str, limits: &Limits) -> Result<Vec<u8>> {
    let body = text
        .strip_prefix(TEXT_PREFIX)
        .ok_or_else(|| malformed("missing nxs1. prefix"))?;
    let max_text = limits.max_input / 3 * 4 + 4;
    if body.len() > max_text {
        return Err(Error::InvalidLength {
            what: "envelope text",
            got: body.len(),
            min: 0,
            max: max_text,
        });
    }
    let bytes = Base64UrlUnpadded::decode_vec(body).map_err(|_| malformed("bad base64url"))?;
    Len::range(0, limits.max_input).check("envelope", bytes.len())?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------

fn resolve(info: Option<&AlgoInfo>, policy: Policy, kind: Kind) -> Result<&AlgoInfo> {
    let info = info.ok_or(Error::UnknownAlgorithm)?;
    if info.kind != kind {
        return Err(Error::WrongKind);
    }
    if !allowed(info.tier, policy) {
        return Err(Error::TierNotAllowed(info.tier));
    }
    if !matches!(info.status, Status::Active | Status::Deprecated) {
        return Err(malformed("algorithm is not active"));
    }
    Ok(info)
}

fn alg_label(id: i64) -> Result<Algorithm> {
    Algorithm::from_cbor_value(Value::from(id)).map_err(|_| malformed("bad COSE algorithm id"))
}

fn header_alg(h: &Header) -> Result<i64> {
    match h
        .alg
        .as_ref()
        .ok_or_else(|| malformed("alg missing from protected header"))?
    {
        RegisteredLabelWithPrivate::Assigned(a) => Ok(a.to_i64()),
        RegisteredLabelWithPrivate::PrivateUse(n) => Ok(*n),
        RegisteredLabelWithPrivate::Text(_) => Err(malformed("text algorithm names are refused")),
    }
}

/// Structural guard on the raw bytes: outer item and the protected header bstr inside it.
fn guard_cose(data: &[u8], tag: u8, array_len: u8, limits: &Limits) -> Result<()> {
    Len::range(1, limits.max_input).check("envelope", data.len())?;
    guard::check(data, limits.max_depth, limits.max_items)?;
    if data.len() < 3 || data[0] != tag || data[1] != 0x80 | array_len {
        return Err(malformed("not the expected COSE structure"));
    }
    // data[2] is the head of the protected-header bstr (definite length, checked above).
    let b = data[2];
    if b >> 5 != 2 {
        return Err(malformed("protected header must be a bstr"));
    }
    let (len, start): (usize, usize) = match b & 31 {
        n @ 0..=23 => (usize::from(n), 3),
        24 => (
            usize::from(*data.get(3).ok_or_else(|| malformed("truncated"))?),
            4,
        ),
        25 => {
            let h = data.get(3..5).ok_or_else(|| malformed("truncated"))?;
            (usize::from(u16::from_be_bytes([h[0], h[1]])), 5)
        }
        _ => return Err(malformed("protected header too large")),
    };
    let inner = data
        .get(start..start.checked_add(len).ok_or_else(|| malformed("length"))?)
        .ok_or_else(|| malformed("truncated"))?;
    if !inner.is_empty() {
        guard::check(inner, limits.max_depth, limits.max_items)?;
    }
    Ok(())
}

/// Header rules shared by Encrypt0 and Sign1 (module docs, rules 3-4).
fn check_headers(protected: &Header, unprotected: &Header, understood: &[i64]) -> Result<()> {
    if unprotected.alg.is_some() {
        return Err(malformed("alg must be protected"));
    }
    if !unprotected.crit.is_empty() {
        return Err(malformed("crit must be protected"));
    }
    if unprotected
        .rest
        .iter()
        .any(|(l, _)| *l == Label::Int(KDF_LABEL))
    {
        return Err(malformed("KDF record must be protected"));
    }
    if !protected.iv.is_empty() || !protected.partial_iv.is_empty() {
        return Err(malformed("IV must be unprotected"));
    }
    for c in &protected.crit {
        match c {
            RegisteredLabelWithPrivate::PrivateUse(n)
                if understood.contains(n)
                    && protected.rest.iter().any(|(l, _)| *l == Label::Int(*n)) => {}
            _ => return Err(malformed("unknown critical header")),
        }
    }
    let kdf_present = protected
        .rest
        .iter()
        .any(|(l, _)| *l == Label::Int(KDF_LABEL));
    let kdf_critical = protected
        .crit
        .contains(&RegisteredLabelWithPrivate::PrivateUse(KDF_LABEL));
    if kdf_present != kdf_critical {
        return Err(malformed("KDF record must be critical"));
    }
    Ok(())
}

fn kdf_to_value(info: &AlgoInfo, rec: &KdfRecord) -> Result<Value> {
    let id = info.cose_alg.ok_or(Error::Unsupported)?;
    let params = rec
        .params
        .iter()
        .map(|(n, v)| (Value::Text(n.clone()), Value::from(*v)))
        .collect();
    Ok(Value::Array(vec![
        Value::from(id),
        Value::Bytes(rec.salt.clone()),
        Value::Map(params),
    ]))
}

fn kdf_from_value(table: &[AlgoInfo], policy: Policy, v: &Value) -> Result<KdfRecord> {
    let bad = || malformed("malformed KDF record");
    let Value::Array(a) = v else {
        return Err(bad());
    };
    let [Value::Integer(id), Value::Bytes(salt), Value::Map(m)] = a.as_slice() else {
        return Err(bad());
    };
    let id = i64::try_from(i128::from(*id)).map_err(|_| bad())?;
    let info = resolve(lookup_cose_in(table, id), policy, Kind::PwHash)?;
    if m.len() > 16 {
        return Err(bad());
    }
    let mut params = Vec::with_capacity(m.len());
    for (k, val) in m {
        let (Value::Text(name), Value::Integer(n)) = (k, val) else {
            return Err(bad());
        };
        if name.len() > 32 {
            return Err(bad());
        }
        let n = u32::try_from(i128::from(*n)).map_err(|_| bad())?;
        params.push((name.clone(), n));
    }
    Ok(KdfRecord {
        alg: info.id.to_string(),
        salt: salt.clone(),
        params,
    })
}

// ---------------------------------------------------------------------------------------
// COSE_Encrypt0
// ---------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn seal_in(
    table: &[AlgoInfo],
    policy: Policy,
    alg: &str,
    key: &SymmetricKey,
    kdf: Option<&KdfRecord>,
    aad: &[u8],
    pt: &[u8],
    rng: &mut dyn EntropySource,
) -> Result<Vec<u8>> {
    let info = resolve(lookup_in(table, alg), policy, Kind::Aead)?;
    let cose = info.cose_alg.ok_or(Error::Unsupported)?;
    let aead = new_aead_in(table, policy, info.id, &Params::new())?;
    let nonce_len = aead
        .sizes()
        .nonce
        .and_then(|l| l.as_fixed())
        .filter(|n| *n > 0)
        .ok_or(Error::Unsupported)?;
    let mut nonce = vec![0u8; nonce_len];
    rng.fill(&mut nonce)?;

    let mut prot = HeaderBuilder::new().algorithm_label(alg_label(cose)?);
    if let Some(rec) = kdf {
        let kinfo = resolve(lookup_in(table, &rec.alg), policy, Kind::PwHash)?;
        prot = prot
            .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(KDF_LABEL))
            .value(KDF_LABEL, kdf_to_value(kinfo, rec)?);
    }
    let unprot = HeaderBuilder::new().iv(nonce.clone()).build();
    let enc = CoseEncrypt0Builder::new()
        .protected(prot.build())
        .unprotected(unprot)
        .try_create_ciphertext(pt, aad, |pt, enc_aad| aead.seal(key, &nonce, enc_aad, pt))?
        .build();
    let out = enc
        .to_tagged_vec()
        .map_err(|_| malformed("COSE encoding failed"))?;
    Len::range(0, Limits::default().max_input).check("envelope", out.len())?;
    Ok(out)
}

/// COSE_Encrypt0 with a caller-supplied key. A fresh random nonce is drawn per call.
pub fn encrypt_in(
    table: &[AlgoInfo],
    policy: Policy,
    alg: &str,
    key: &SymmetricKey,
    aad: &[u8],
    pt: &[u8],
    rng: &mut dyn EntropySource,
) -> Result<Vec<u8>> {
    seal_in(table, policy, alg, key, None, aad, pt, rng)
}

struct ParsedEnc<'a> {
    enc: CoseEncrypt0,
    info: &'a AlgoInfo,
    kdf: Option<KdfRecord>,
}

fn parse_encrypt0<'a>(
    table: &'a [AlgoInfo],
    policy: Policy,
    limits: &Limits,
    env: &[u8],
) -> Result<ParsedEnc<'a>> {
    guard_cose(env, TAG_ENCRYPT0, 3, limits)?;
    let enc =
        CoseEncrypt0::from_tagged_slice(env).map_err(|_| malformed("malformed COSE_Encrypt0"))?;
    check_headers(&enc.protected.header, &enc.unprotected, &[KDF_LABEL])?;
    let id = header_alg(&enc.protected.header)?;
    let info = resolve(lookup_cose_in(table, id), policy, Kind::Aead)?;
    let kdf = enc
        .protected
        .header
        .rest
        .iter()
        .find(|(l, _)| *l == Label::Int(KDF_LABEL))
        .map(|(_, v)| kdf_from_value(table, policy, v))
        .transpose()?;
    Ok(ParsedEnc { enc, info, kdf })
}

fn open_parsed(
    table: &[AlgoInfo],
    policy: Policy,
    p: &ParsedEnc<'_>,
    key: &SymmetricKey,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let aead = new_aead_in(table, policy, p.info.id, &Params::new())?;
    let ct = p
        .enc
        .ciphertext
        .as_ref()
        .ok_or_else(|| malformed("ciphertext missing"))?;
    let nonce_len = aead
        .sizes()
        .nonce
        .and_then(|l| l.as_fixed())
        .ok_or(Error::Unsupported)?;
    Len::fixed(nonce_len).check("nonce", p.enc.unprotected.iv.len())?;
    let enc_aad = enc_structure_data(
        EncryptionContext::CoseEncrypt0,
        p.enc.protected.clone(),
        aad,
    );
    aead.open(key, &p.enc.unprotected.iv, &enc_aad, ct)
}

/// Decrypts a key-based COSE_Encrypt0. An envelope that carries a KDF record is refused (it
/// needs [`decrypt_with_password_in`]).
pub fn decrypt_in(
    table: &[AlgoInfo],
    policy: Policy,
    limits: &Limits,
    key: &SymmetricKey,
    env: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let p = parse_encrypt0(table, policy, limits, env)?;
    if p.kdf.is_some() {
        return Err(malformed("envelope is password-based"));
    }
    open_parsed(table, policy, &p, key, aad)
}

/// Like [`decrypt_in`], but the protected header must name exactly `alg` (the sender cannot
/// pick a different algorithm than the caller expects, as with [`verify_in`]).
pub fn decrypt_expect_in(
    table: &[AlgoInfo],
    policy: Policy,
    limits: &Limits,
    alg: &str,
    key: &SymmetricKey,
    env: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let p = parse_encrypt0(table, policy, limits, env)?;
    if p.kdf.is_some() {
        return Err(malformed("envelope is password-based"));
    }
    let want = resolve(lookup_in(table, alg), policy, Kind::Aead)?;
    if p.info.id != want.id {
        return Err(malformed(
            "envelope algorithm differs from the expected one",
        ));
    }
    open_parsed(table, policy, &p, key, aad)
}

/// Password-based COSE_Encrypt0: the key comes from the password engine; the KDF record is
/// stored in the protected header.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_with_password_in(
    table: &[AlgoInfo],
    policy: Policy,
    limits: &Limits,
    aead_alg: &str,
    kdf_alg: &str,
    kdf_params: &Params,
    password: &[u8],
    aad: &[u8],
    pt: &[u8],
    rng: &mut dyn EntropySource,
) -> Result<Vec<u8>> {
    let info = resolve(lookup_in(table, aead_alg), policy, Kind::Aead)?;
    let key_len = new_aead_in(table, policy, info.id, &Params::new())?
        .sizes()
        .key
        .and_then(|l| l.as_fixed())
        .ok_or(Error::Unsupported)?;
    let (key, rec) = password::derive_key_in(
        table,
        policy,
        &limits.kdf,
        kdf_alg,
        password,
        kdf_params,
        None,
        rng,
        key_len,
    )?;
    seal_in(table, policy, info.id, &key, Some(&rec), aad, pt, rng)
}

/// Decrypts a password-based envelope. KDF cost is schema-validated and capped by
/// `limits.kdf` before the password hash runs.
pub fn decrypt_with_password_in(
    table: &[AlgoInfo],
    policy: Policy,
    limits: &Limits,
    password: &[u8],
    env: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let p = parse_encrypt0(table, policy, limits, env)?;
    let rec = p
        .kdf
        .as_ref()
        .ok_or_else(|| malformed("envelope is not password-based"))?;
    let key_len = new_aead_in(table, policy, p.info.id, &Params::new())?
        .sizes()
        .key
        .and_then(|l| l.as_fixed())
        .ok_or(Error::Unsupported)?;
    let key = password::rederive_in(table, policy, &limits.kdf, rec, password, key_len)?;
    open_parsed(table, policy, &p, &key, aad)
}

// ---------------------------------------------------------------------------------------
// COSE_Sign1
// ---------------------------------------------------------------------------------------

/// COSE_Sign1 with the payload attached. Signatures use an empty context string.
pub fn sign_in(
    table: &[AlgoInfo],
    policy: Policy,
    alg: &str,
    sk: &PrivateKey,
    payload: &[u8],
    aad: &[u8],
    rng: &mut dyn EntropySource,
) -> Result<Vec<u8>> {
    let info = resolve(lookup_in(table, alg), policy, Kind::Sign)?;
    let cose = info.cose_alg.ok_or(Error::Unsupported)?;
    let signer = new_sign_in(table, policy, info.id, &Params::new())?;
    let prot = HeaderBuilder::new()
        .algorithm_label(alg_label(cose)?)
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(prot)
        .payload(payload.to_vec())
        .try_create_signature(aad, |tbs| {
            signer
                .sign(sk, tbs, &[], rng)
                .map(|s| s.as_bytes().to_vec())
        })?
        .build();
    let out = sign1
        .to_tagged_vec()
        .map_err(|_| malformed("COSE encoding failed"))?;
    Len::range(0, Limits::default().max_input).check("envelope", out.len())?;
    Ok(out)
}

/// Verifies a COSE_Sign1 against `pk` and returns the payload. The header algorithm must be
/// exactly `alg`: the signer cannot choose a different (weaker) algorithm.
pub fn verify_in(
    table: &[AlgoInfo],
    policy: Policy,
    limits: &Limits,
    alg: &str,
    pk: &PublicKey,
    env: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    guard_cose(env, TAG_SIGN1, 4, limits)?;
    let sign1 = CoseSign1::from_tagged_slice(env).map_err(|_| malformed("malformed COSE_Sign1"))?;
    check_headers(&sign1.protected.header, &sign1.unprotected, &[])?;
    let id = header_alg(&sign1.protected.header)?;
    let info = resolve(lookup_cose_in(table, id), policy, Kind::Sign)?;
    let want = resolve(lookup_in(table, alg), policy, Kind::Sign)?;
    if info.id != want.id {
        return Err(malformed(
            "envelope algorithm differs from the expected one",
        ));
    }
    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| malformed("detached payload not supported"))?;
    let verifier = new_sign_in(table, policy, info.id, &Params::new())?;
    let sig_len = verifier.sizes().sig.ok_or(Error::Unsupported)?;
    let sig = Signature::from_bytes(&sign1.signature, sig_len)?;
    let tbs = sig_structure_data(
        SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        aad,
        payload,
    );
    if verifier.verify(pk, &tbs, &[], &sig)? {
        Ok(payload.clone())
    } else {
        Err(Error::AuthenticationFailed)
    }
}
