//! Safe Rust side of the generic C ABI. Nothing in this file is `unsafe`: every function takes
//! plain slices and strings, validates them, calls the registry and returns owned, zeroizing
//! buffers. The exported `extern "C"` functions only decode pointers and forward here.
//!
//! The ABI is driven by the registry at run time (`nextssl_registry::all()`), so adding an
//! algorithm to `algo.toml` makes it reachable by name without any change in this crate.

use crate::handles::{self, Obj};
use nextssl_core::{
    check_len, Ciphertext, Error, Kind, Len, Params, PrivateKey, PublicKey, Share, Signature,
    StatefulKey, SymmetricKey, Value, Zeroizing, MAX_INPUT_LEN,
};
use nextssl_core::{HeOp, PakeRole, ParamType, ThresholdOp, ThresholdSession};
use nextssl_registry as reg;
use reg::{AlgoInfo, Policy};

/// One output buffer. Every output is treated as potentially secret and wiped on drop.
pub type Out = Zeroizing<Vec<u8>>;
pub type Outs = Vec<Out>;
pub type R = Result<Outs, Fail>;

/// Upper bound for caller-chosen output lengths (XOF, KDF, RNG, DRBG): 16 MiB.
pub const NEXTSSL_MAX_OUT: usize = 1 << 24;
/// Most items accepted in one packed list (shares, ciphertext operands).
const MAX_ITEMS: usize = 1 << 16;

/// Failure of an ABI call: a library error or a stale handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    Core(Error),
    BadHandle,
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Fail::Core(e)
    }
}

impl Fail {
    pub fn code(&self) -> i32 {
        match self {
            Fail::Core(e) => e.code(),
            Fail::BadHandle => crate::NEXTSSL_ERR_BAD_HANDLE,
        }
    }
}

type E<T> = Result<T, Error>;

fn z(v: Vec<u8>) -> Out {
    Zeroizing::new(v)
}

fn one(v: Vec<u8>) -> R {
    Ok(vec![z(v)])
}

/// A verification result: valid is an empty success, invalid is `AuthenticationFailed`.
fn flag(valid: bool) -> R {
    if valid {
        Ok(Vec::new())
    } else {
        Err(Error::AuthenticationFailed.into())
    }
}

fn chk(data: &[u8]) -> E<()> {
    check_len("input", data.len(), 0, MAX_INPUT_LEN)
}

fn want_len(what: &'static str, n: usize) -> E<usize> {
    check_len(what, n, 1, NEXTSSL_MAX_OUT)?;
    Ok(n)
}

fn skey(b: &[u8]) -> E<SymmetricKey> {
    SymmetricKey::from_bytes(b, Len::range(0, MAX_INPUT_LEN))
}
fn privkey(b: &[u8]) -> E<PrivateKey> {
    PrivateKey::from_bytes(b, Len::range(0, MAX_INPUT_LEN))
}
fn pubkey(b: &[u8]) -> E<PublicKey> {
    PublicKey::from_bytes(b, Len::range(0, MAX_INPUT_LEN))
}
fn cipherbytes(b: &[u8]) -> E<Ciphertext> {
    Ciphertext::from_bytes(b, Len::range(0, MAX_INPUT_LEN))
}
fn sigbytes(b: &[u8]) -> E<Signature> {
    Signature::from_bytes(b, Len::range(0, MAX_INPUT_LEN))
}

// ---- hex and packed lists ---------------------------------------------------------------

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    // The value may be a key: a partial result is wiped if decoding stops half way.
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    for p in s.as_bytes().chunks(2) {
        out.push(nib(p[0])? << 4 | nib(p[1])?);
    }
    Some(core::mem::take(&mut *out))
}

/// Packs items as `u32 little-endian length || bytes`, repeated. Used for share lists and
/// ciphertext operand lists.
pub fn pack(items: &[&[u8]]) -> E<Vec<u8>> {
    let mut out = Vec::new();
    for it in items {
        let n = u32::try_from(it.len()).map_err(|_| Error::InvalidInput("packed item too long"))?;
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(it);
    }
    Ok(out)
}

/// Strict inverse of [`pack`]: a truncated or oversized record is an error.
pub fn unpack(mut buf: &[u8]) -> E<Vec<&[u8]>> {
    let mut items = Vec::new();
    while !buf.is_empty() {
        if items.len() >= MAX_ITEMS {
            return Err(Error::InvalidInput("too many packed items"));
        }
        let (head, rest) = buf
            .split_at_checked(4)
            .ok_or(Error::InvalidInput("truncated packed list"))?;
        let n = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let (item, rest) = rest
            .split_at_checked(n)
            .ok_or(Error::InvalidInput("truncated packed list"))?;
        items.push(item);
        buf = rest;
    }
    Ok(items)
}

// ---- name, tier and parameter handling ----------------------------------------------------

/// Parses `name=value;name=value` against the algorithm's declared parameters. `u32`/`u64` are
/// decimal, `str` and `enum` are text, `bytes` are hex. Unknown names, duplicates, empty items
/// and unparsable values are errors.
pub fn parse_params(info: &AlgoInfo, text: Option<&str>) -> E<Params> {
    let mut p = Params::new();
    let Some(text) = text.filter(|t| !t.is_empty()) else {
        return Ok(p);
    };
    for item in text.split(';') {
        let (k, v) = item
            .split_once('=')
            .ok_or(Error::InvalidInput("parameter must be name=value"))?;
        let spec = info
            .params
            .iter()
            .find(|s| s.name == k)
            .ok_or(Error::ParamUnknown)?;
        if p.get(spec.name).is_some() {
            return Err(Error::InvalidInput("duplicate parameter"));
        }
        let val = match spec.ty {
            ParamType::U32 => Value::U32(v.parse().map_err(|_| Error::ParamType(spec.name))?),
            ParamType::U64 => Value::U64(v.parse().map_err(|_| Error::ParamType(spec.name))?),
            ParamType::Str | ParamType::Enum(_) => Value::Str(v.to_string()),
            ParamType::Bytes => Value::Bytes(hex_decode(v).ok_or(Error::ParamType(spec.name))?),
        };
        p.set(spec.name, val);
    }
    Ok(p)
}

/// Looks `alg` up, checks kind and tier for `policy`, then parses the parameters.
fn prep(policy: Policy, alg: &str, kind: Kind, params: Option<&str>) -> E<Params> {
    let info = reg::lookup(alg).ok_or(Error::UnknownAlgorithm)?;
    if info.kind != kind {
        return Err(Error::WrongKind);
    }
    if !reg::allowed(info.tier, policy) || (kind.root_only() && policy == Policy::Safe) {
        return Err(Error::TierNotAllowed(info.tier));
    }
    parse_params(info, params)
}

fn rng(policy: Policy) -> E<Box<dyn nextssl_core::EntropySource>> {
    reg::new_rng_in(reg::all(), policy, "os-entropy", &Params::new())
}

macro_rules! make {
    ($new:ident, $kind:expr, $policy:expr, $alg:expr, $params:expr) => {{
        let p = prep($policy, $alg, $kind, $params)?;
        reg::$new(reg::all(), $policy, $alg, &p)?
    }};
}

// ---- keyless -------------------------------------------------------------------------------

pub fn hash(policy: Policy, alg: &str, params: Option<&str>, data: &[u8]) -> R {
    chk(data)?;
    let p = prep(policy, alg, Kind::Hash, params)?;
    one(reg::hash_in(reg::all(), policy, alg, &p, data)?)
}

pub fn xof(policy: Policy, alg: &str, params: Option<&str>, data: &[u8], want: usize) -> R {
    chk(data)?;
    let x = make!(new_xof_in, Kind::Xof, policy, alg, params);
    let mut out = vec![0u8; want_len("out", want)?];
    x.squeeze(data, &mut out)?;
    one(out)
}

pub fn checksum(policy: Policy, alg: &str, params: Option<&str>, data: &[u8]) -> R {
    chk(data)?;
    let c = make!(new_checksum_in, Kind::Checksum, policy, alg, params);
    let n = c.sizes().out.ok_or(Error::Unsupported)?.max();
    let mut out = vec![0u8; n];
    c.checksum(data, &mut out)?;
    one(out)
}

pub fn encode(policy: Policy, alg: &str, params: Option<&str>, data: &[u8]) -> R {
    chk(data)?;
    let p = prep(policy, alg, Kind::Encoding, params)?;
    one(reg::encode_in(reg::all(), policy, alg, &p, data)?)
}

pub fn decode(policy: Policy, alg: &str, params: Option<&str>, text: &[u8]) -> R {
    chk(text)?;
    let p = prep(policy, alg, Kind::Encoding, params)?;
    one(reg::decode_in(reg::all(), policy, alg, &p, text)?)
}

// ---- symmetric -----------------------------------------------------------------------------

/// `tag_len == 0` selects the longest tag the MAC declares; any other value must be declared.
pub fn mac(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    key: &[u8],
    data: &[u8],
    tag_len: usize,
) -> R {
    chk(data)?;
    let m = make!(new_mac_in, Kind::Mac, policy, alg, params);
    let n = if tag_len == 0 {
        m.sizes().tag.ok_or(Error::Unsupported)?.max()
    } else {
        tag_len
    };
    let mut tag = vec![0u8; want_len("tag", n)?];
    m.tag(&skey(key)?, data, &mut tag)?;
    one(tag)
}

pub fn mac_verify(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    key: &[u8],
    data: &[u8],
    tag: &[u8],
) -> R {
    chk(data)?;
    let m = make!(new_mac_in, Kind::Mac, policy, alg, params);
    flag(m.verify(&skey(key)?, data, tag)?)
}

pub fn kdf(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    want: usize,
) -> R {
    chk(salt)?;
    chk(info)?;
    let k = make!(new_kdf_in, Kind::Kdf, policy, alg, params);
    let mut out = z(vec![0u8; want_len("out", want)?]);
    k.derive(&skey(ikm)?, salt, info, &mut out)?;
    Ok(vec![out])
}

/// Password hash as a PHC string with a fresh 16-byte salt from the OS entropy source, clamped
/// to the algorithm's declared salt range.
pub fn pwhash(policy: Policy, alg: &str, params: Option<&str>, password: &[u8]) -> R {
    chk(password)?;
    let h = make!(new_pwhash_in, Kind::PwHash, policy, alg, params);
    let s = h.sizes().salt.ok_or(Error::Unsupported)?;
    let mut salt = vec![0u8; 16usize.clamp(s.min(), s.max())];
    rng(policy)?.fill(&mut salt)?;
    one(h.hash(password, &salt)?.into_bytes())
}

pub fn pwhash_salted(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    password: &[u8],
    salt: &[u8],
) -> R {
    chk(password)?;
    let h = make!(new_pwhash_in, Kind::PwHash, policy, alg, params);
    one(h.hash(password, salt)?.into_bytes())
}

pub fn pwhash_verify(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    password: &[u8],
    phc: &[u8],
) -> R {
    chk(password)?;
    let phc =
        core::str::from_utf8(phc).map_err(|_| Error::InvalidInput("PHC string is not UTF-8"))?;
    let h = make!(new_pwhash_in, Kind::PwHash, policy, alg, params);
    flag(h.verify(password, phc)?)
}

pub fn pwhash_derive(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    password: &[u8],
    salt: &[u8],
    want: usize,
) -> R {
    chk(password)?;
    let h = make!(new_pwhash_in, Kind::PwHash, policy, alg, params);
    let mut out = z(vec![0u8; want_len("out", want)?]);
    h.derive(password, salt, &mut out)?;
    Ok(vec![out])
}

pub fn aead_seal(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> R {
    chk(pt)?;
    chk(aad)?;
    let a = make!(new_aead_in, Kind::Aead, policy, alg, params);
    one(a.seal(&skey(key)?, nonce, aad, pt)?)
}

pub fn aead_open(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> R {
    chk(ct)?;
    chk(aad)?;
    let a = make!(new_aead_in, Kind::Aead, policy, alg, params);
    Ok(vec![a.open(&skey(key)?, nonce, aad, ct)?])
}

pub fn blockcipher(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    key: &[u8],
    block: &[u8],
    decrypt: bool,
) -> R {
    let c = make!(new_blockcipher_in, Kind::BlockCipher, policy, alg, params);
    let mut b = z(block.to_vec());
    let k = skey(key)?;
    if decrypt {
        c.decrypt_block(&k, &mut b)?;
    } else {
        c.encrypt_block(&k, &mut b)?;
    }
    Ok(vec![b])
}

pub fn stream_apply(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> R {
    chk(data)?;
    let c = make!(new_streamcipher_in, Kind::StreamCipher, policy, alg, params);
    let mut buf = z(data.to_vec());
    c.apply_keystream(&skey(key)?, nonce, &mut buf)?;
    Ok(vec![buf])
}

pub fn blockmode(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    decrypt: bool,
) -> R {
    chk(data)?;
    let m = make!(new_blockmode_in, Kind::BlockMode, policy, alg, params);
    let k = skey(key)?;
    if decrypt {
        Ok(vec![m.decrypt(&k, nonce, data)?])
    } else {
        one(m.encrypt(&k, nonce, data)?)
    }
}

/// Unauthenticated mode `alg` (ECB, CBC, CTR, ...) over the block cipher `cipher`.
#[allow(clippy::too_many_arguments)]
pub fn mode(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    cipher: &str,
    cipher_params: Option<&str>,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    decrypt: bool,
) -> R {
    chk(data)?;
    let m = make!(new_mode_in, Kind::Mode, policy, alg, params);
    let c = make!(
        new_blockcipher_in,
        Kind::BlockCipher,
        policy,
        cipher,
        cipher_params
    );
    let k = skey(key)?;
    if decrypt {
        Ok(vec![m.decrypt(&*c, &k, iv, data)?])
    } else {
        one(m.encrypt(&*c, &k, iv, data)?)
    }
}

// ---- randomness ----------------------------------------------------------------------------

pub fn rng_fill(policy: Policy, alg: &str, params: Option<&str>, want: usize) -> R {
    let mut r = make!(new_rng_in, Kind::Rng, policy, alg, params);
    let mut out = z(vec![0u8; want_len("out", want)?]);
    r.fill(&mut out)?;
    Ok(vec![out])
}

pub fn drbg_new(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    entropy: &[u8],
    nonce: &[u8],
    personalization: &[u8],
) -> Result<u64, Fail> {
    let mut d = make!(new_drbg_in, Kind::Drbg, policy, alg, params);
    d.instantiate(entropy, nonce, personalization)?;
    handles::insert(Obj::Drbg(d))
}

pub fn drbg_generate(handle: u64, additional: &[u8], want: usize) -> R {
    let mut out = z(vec![0u8; want_len("out", want)?]);
    handles::with_drbg(handle, |d| d.generate(additional, &mut out))?;
    Ok(vec![out])
}

pub fn drbg_reseed(handle: u64, entropy: &[u8], additional: &[u8]) -> Result<(), Fail> {
    handles::with_drbg(handle, |d| d.reseed(entropy, additional))
}

pub fn drbg_free(handle: u64) -> Result<(), Fail> {
    let Obj::Drbg(mut d) = handles::remove_drbg(handle)? else {
        return Err(Fail::BadHandle);
    };
    d.uninstantiate();
    Ok(())
}

// ---- asymmetric ----------------------------------------------------------------------------

fn keypair(pk: PublicKey, sk: PrivateKey) -> R {
    Ok(vec![z(pk.into_vec()), z(sk.as_bytes().to_vec())])
}

pub fn kem_keygen(policy: Policy, alg: &str, params: Option<&str>) -> R {
    let k = make!(new_kem_in, Kind::Kem, policy, alg, params);
    let (pk, sk) = k.keygen(&mut *rng(policy)?)?;
    keypair(pk, sk)
}

pub fn kem_encaps(policy: Policy, alg: &str, params: Option<&str>, pk: &[u8]) -> R {
    let k = make!(new_kem_in, Kind::Kem, policy, alg, params);
    let (ct, ss) = k.encaps(&pubkey(pk)?, &mut *rng(policy)?)?;
    Ok(vec![z(ct.into_vec()), z(ss.as_bytes().to_vec())])
}

pub fn kem_decaps(policy: Policy, alg: &str, params: Option<&str>, sk: &[u8], ct: &[u8]) -> R {
    let k = make!(new_kem_in, Kind::Kem, policy, alg, params);
    let ss = k.decaps(&privkey(sk)?, &cipherbytes(ct)?)?;
    one(ss.as_bytes().to_vec())
}

pub fn kex_keygen(policy: Policy, alg: &str, params: Option<&str>) -> R {
    let k = make!(new_kex_in, Kind::Kex, policy, alg, params);
    let (pk, sk) = k.keypair(&mut *rng(policy)?)?;
    keypair(pk, sk)
}

pub fn kex_agree(policy: Policy, alg: &str, params: Option<&str>, sk: &[u8], peer: &[u8]) -> R {
    let k = make!(new_kex_in, Kind::Kex, policy, alg, params);
    let ss = k.agree(&privkey(sk)?, &pubkey(peer)?)?;
    one(ss.as_bytes().to_vec())
}

pub fn sign_keygen(policy: Policy, alg: &str, params: Option<&str>) -> R {
    let s = make!(new_sign_in, Kind::Sign, policy, alg, params);
    let (pk, sk) = s.keygen(&mut *rng(policy)?)?;
    keypair(pk, sk)
}

pub fn sign_detached(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
) -> R {
    chk(msg)?;
    let s = make!(new_sign_in, Kind::Sign, policy, alg, params);
    let sig = s.sign(&privkey(sk)?, msg, ctx, &mut *rng(policy)?)?;
    one(sig.into_vec())
}

pub fn verify_detached(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    pk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> R {
    chk(msg)?;
    let s = make!(new_sign_in, Kind::Sign, policy, alg, params);
    flag(s.verify(&pubkey(pk)?, msg, ctx, &sigbytes(sig)?)?)
}

pub fn pow_solve(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    challenge: &[u8],
    difficulty: u32,
    max_work: u64,
) -> R {
    chk(challenge)?;
    let p = make!(new_pow_in, Kind::Pow, policy, alg, params);
    one(p.solve(challenge, difficulty, max_work)?)
}

pub fn pow_verify(
    policy: Policy,
    alg: &str,
    params: Option<&str>,
    challenge: &[u8],
    solution: &[u8],
    difficulty: u32,
) -> R {
    chk(challenge)?;
    chk(solution)?;
    let p = make!(new_pow_in, Kind::Pow, policy, alg, params);
    flag(p.verify(challenge, solution, difficulty)?)
}

// ---- root-only kinds -----------------------------------------------------------------------

pub fn pke_keygen(alg: &str, params: Option<&str>) -> R {
    let k = make!(new_pke_in, Kind::Pke, Policy::Any, alg, params);
    let (pk, sk) = k.keygen(&mut *rng(Policy::Any)?)?;
    keypair(pk, sk)
}

pub fn pke_encrypt(alg: &str, params: Option<&str>, pk: &[u8], pt: &[u8], label: &[u8]) -> R {
    chk(pt)?;
    let k = make!(new_pke_in, Kind::Pke, Policy::Any, alg, params);
    one(k.encrypt(&pubkey(pk)?, pt, label, &mut *rng(Policy::Any)?)?)
}

pub fn pke_decrypt(alg: &str, params: Option<&str>, sk: &[u8], ct: &[u8], label: &[u8]) -> R {
    chk(ct)?;
    let k = make!(new_pke_in, Kind::Pke, Policy::Any, alg, params);
    Ok(vec![k.decrypt(&privkey(sk)?, ct, label)?])
}

pub fn stateful_keygen(alg: &str, params: Option<&str>) -> R {
    let s = make!(
        new_statefulsign_in,
        Kind::StatefulSign,
        Policy::Any,
        alg,
        params
    );
    let (pk, state) = s.keygen(&mut *rng(Policy::Any)?)?;
    Ok(vec![z(pk.into_vec()), z(state.as_bytes().to_vec())])
}

fn state_key(b: &[u8]) -> E<StatefulKey> {
    StatefulKey::from_bytes(b, Len::range(0, MAX_INPUT_LEN))
}

/// Returns `[signature, new_state]`. The caller MUST durably store `new_state` and discard the
/// old state before releasing the signature: reusing an old state reuses a one-time key.
pub fn stateful_sign(alg: &str, params: Option<&str>, state: &[u8], msg: &[u8]) -> R {
    chk(msg)?;
    let s = make!(
        new_statefulsign_in,
        Kind::StatefulSign,
        Policy::Any,
        alg,
        params
    );
    let mut key = state_key(state)?;
    let sig = s.sign(&mut key, msg, &mut |_new_state| Ok(()))?;
    Ok(vec![z(sig.into_vec()), z(key.as_bytes().to_vec())])
}

pub fn stateful_verify(alg: &str, params: Option<&str>, pk: &[u8], msg: &[u8], sig: &[u8]) -> R {
    chk(msg)?;
    let s = make!(
        new_statefulsign_in,
        Kind::StatefulSign,
        Policy::Any,
        alg,
        params
    );
    flag(s.verify(&pubkey(pk)?, msg, &sigbytes(sig)?)?)
}

/// `(remaining, max_signatures)` for a serialized key state.
pub fn stateful_remaining(alg: &str, params: Option<&str>, state: &[u8]) -> E<(u64, u64)> {
    let s = make!(
        new_statefulsign_in,
        Kind::StatefulSign,
        Policy::Any,
        alg,
        params
    );
    Ok((s.remaining(&state_key(state)?)?, s.max_signatures()))
}

pub fn zk_setup(alg: &str, params: Option<&str>, setup_params: &[u8]) -> R {
    chk(setup_params)?;
    let z_ = make!(new_zk_in, Kind::Zk, Policy::Any, alg, params);
    one(z_.setup(setup_params, &mut *rng(Policy::Any)?)?)
}

pub fn zk_prove(
    alg: &str,
    params: Option<&str>,
    setup: &[u8],
    statement: &[u8],
    witness: &[u8],
) -> R {
    chk(setup)?;
    chk(statement)?;
    chk(witness)?;
    let z_ = make!(new_zk_in, Kind::Zk, Policy::Any, alg, params);
    one(z_.prove(setup, statement, witness, &mut *rng(Policy::Any)?)?)
}

pub fn zk_verify(
    alg: &str,
    params: Option<&str>,
    setup: &[u8],
    statement: &[u8],
    proof: &[u8],
) -> R {
    chk(setup)?;
    chk(statement)?;
    chk(proof)?;
    let z_ = make!(new_zk_in, Kind::Zk, Policy::Any, alg, params);
    flag(z_.verify(setup, statement, proof)?)
}

/// Non-cryptographic seeded generator (root only): `want` bytes from `seed`.
pub fn prng(alg: &str, params: Option<&str>, seed: &[u8], want: usize) -> R {
    chk(seed)?;
    let g = make!(new_prng_in, Kind::Prng, Policy::Any, alg, params);
    let mut out = vec![0u8; want_len("out", want)?];
    g.generate(seed, &mut out)?;
    one(out)
}

pub fn h2c_hash(alg: &str, params: Option<&str>, msg: &[u8], dst: &[u8]) -> R {
    chk(msg)?;
    let h = make!(new_hashtocurve_in, Kind::HashToCurve, Policy::Any, alg, params);
    one(h.hash(msg, dst)?)
}

pub fn h2c_encode(alg: &str, params: Option<&str>, msg: &[u8], dst: &[u8]) -> R {
    chk(msg)?;
    let h = make!(new_hashtocurve_in, Kind::HashToCurve, Policy::Any, alg, params);
    one(h.encode(msg, dst)?)
}

pub fn oprf_keygen(alg: &str, params: Option<&str>) -> R {
    let o = make!(new_oprf_in, Kind::Oprf, Policy::Any, alg, params);
    let (pk, sk) = o.keygen(&mut *rng(Policy::Any)?)?;
    keypair(pk, sk)
}

pub fn oprf_blind(alg: &str, params: Option<&str>, input: &[u8]) -> R {
    chk(input)?;
    let o = make!(new_oprf_in, Kind::Oprf, Policy::Any, alg, params);
    let (state, blinded) = o.blind(input, &mut *rng(Policy::Any)?)?;
    Ok(vec![state, z(blinded)])
}

pub fn oprf_evaluate(alg: &str, params: Option<&str>, sk: &[u8], blinded: &[u8], info: &[u8]) -> R {
    chk(blinded)?;
    chk(info)?;
    let o = make!(new_oprf_in, Kind::Oprf, Policy::Any, alg, params);
    let (ev, proof) = o.evaluate(&privkey(sk)?, blinded, info, &mut *rng(Policy::Any)?)?;
    Ok(vec![z(ev), z(proof)])
}

#[allow(clippy::too_many_arguments)]
pub fn oprf_finalize(
    alg: &str,
    params: Option<&str>,
    state: &[u8],
    input: &[u8],
    evaluated: &[u8],
    proof: &[u8],
    pk: &[u8],
    info: &[u8],
) -> R {
    chk(state)?;
    chk(input)?;
    chk(evaluated)?;
    chk(proof)?;
    chk(info)?;
    let o = make!(new_oprf_in, Kind::Oprf, Policy::Any, alg, params);
    Ok(vec![o.finalize(state, input, evaluated, proof, &pubkey(pk)?, info)?])
}

pub fn vdf_eval(alg: &str, params: Option<&str>, challenge: &[u8], t: u64) -> R {
    chk(challenge)?;
    let v = make!(new_vdf_in, Kind::Vdf, Policy::Any, alg, params);
    let (output, proof) = v.eval(challenge, t)?;
    Ok(vec![z(output), z(proof)])
}

pub fn vdf_verify(
    alg: &str,
    params: Option<&str>,
    challenge: &[u8],
    t: u64,
    output: &[u8],
    proof: &[u8],
) -> R {
    chk(challenge)?;
    chk(output)?;
    chk(proof)?;
    let v = make!(new_vdf_in, Kind::Vdf, Policy::Any, alg, params);
    flag(v.verify(challenge, t, output, proof)?)
}

fn he_op(name: &str) -> E<HeOp> {
    Ok(match name {
        "add" => HeOp::Add,
        "sub" => HeOp::Sub,
        "mul" => HeOp::Mul,
        "neg" => HeOp::Neg,
        "and" => HeOp::And,
        "or" => HeOp::Or,
        "xor" => HeOp::Xor,
        "not" => HeOp::Not,
        _ => return Err(Error::InvalidInput("unknown homomorphic operation")),
    })
}

/// Returns `[secret_key, public_key, evaluation_key]`.
pub fn he_keygen(alg: &str, params: Option<&str>, he_params: &[u8]) -> R {
    chk(he_params)?;
    let h = make!(new_he_in, Kind::He, Policy::Any, alg, params);
    let k = h.keygen(he_params, &mut *rng(Policy::Any)?)?;
    Ok(vec![
        z(k.secret.as_bytes().to_vec()),
        z(k.public.into_vec()),
        z(k.eval.into_vec()),
    ])
}

pub fn he_encrypt(alg: &str, params: Option<&str>, pk: &[u8], pt: &[u8]) -> R {
    chk(pt)?;
    let h = make!(new_he_in, Kind::He, Policy::Any, alg, params);
    one(h.encrypt(&pubkey(pk)?, pt, &mut *rng(Policy::Any)?)?)
}

pub fn he_decrypt(alg: &str, params: Option<&str>, sk: &[u8], ct: &[u8]) -> R {
    chk(ct)?;
    let h = make!(new_he_in, Kind::He, Policy::Any, alg, params);
    Ok(vec![h.decrypt(&privkey(sk)?, ct)?])
}

/// `cts` is a packed list of operands (see [`pack`]); `op` is `add`, `sub`, `mul`, `neg`, `and`,
/// `or`, `xor` or `not`.
pub fn he_eval(alg: &str, params: Option<&str>, op: &str, cts: &[u8], evk: &[u8]) -> R {
    chk(cts)?;
    let h = make!(new_he_in, Kind::He, Policy::Any, alg, params);
    let items = unpack(cts)?;
    one(h.eval(he_op(op)?, &items, &pubkey(evk)?)?)
}

/// Packed list of shares.
pub fn threshold_split(alg: &str, params: Option<&str>, secret: &[u8], t: usize, n: usize) -> R {
    chk(secret)?;
    let th = make!(new_threshold_in, Kind::Threshold, Policy::Any, alg, params);
    let shares = th.split(secret, t, n, &mut *rng(Policy::Any)?)?;
    let items: Vec<&[u8]> = shares.iter().map(Share::as_bytes).collect();
    Ok(vec![z(pack(&items)?)])
}

pub fn threshold_combine(alg: &str, params: Option<&str>, shares: &[u8]) -> R {
    chk(shares)?;
    let th = make!(new_threshold_in, Kind::Threshold, Policy::Any, alg, params);
    let list = unpack(shares)?
        .into_iter()
        .map(|b| Share::from_bytes(b, Len::range(0, MAX_INPUT_LEN)))
        .collect::<E<Vec<_>>>()?;
    Ok(vec![th.combine(&list)?])
}

// ---- interactive state machines (handles) ----------------------------------------------------

/// Starts a PAKE. `role` 0 = initiator, 1 = responder. Returns the handle and the first
/// message (empty when this role waits for the peer).
pub fn pake_start(
    alg: &str,
    params: Option<&str>,
    role: u32,
    password: &[u8],
    context: &[u8],
) -> Result<(u64, Out), Fail> {
    chk(password)?;
    chk(context)?;
    let role = match role {
        0 => PakeRole::Initiator,
        1 => PakeRole::Responder,
        _ => return Err(Error::InvalidInput("role must be 0 (initiator) or 1 (responder)").into()),
    };
    let p = make!(new_pake_in, Kind::Pake, Policy::Any, alg, params);
    let (state, msg) = p.start(role, password, context, &mut *rng(Policy::Any)?)?;
    Ok((handles::insert(Obj::Pake(state))?, z(msg)))
}

/// One step. Returns `(done, [message, shared_secret])`; `shared_secret` is empty until done.
/// The step consumes the state: after any error the handle is gone.
pub fn pake_step(handle: u64, msg: &[u8]) -> Result<(bool, Outs), Fail> {
    chk(msg)?;
    let Obj::Pake(state) = handles::remove_pake(handle)? else {
        return Err(Fail::BadHandle);
    };
    match state.step(msg)? {
        nextssl_core::PakeStep::Send(next, out) => {
            handles::restore(handle, Obj::Pake(next))?;
            Ok((false, vec![z(out), z(Vec::new())]))
        }
        nextssl_core::PakeStep::Done(ss, last) => Ok((
            true,
            vec![z(last.unwrap_or_default()), z(ss.as_bytes().to_vec())],
        )),
    }
}

/// Starts a threshold DKG (`op` 0) or signing (`op` 1) session for one party.
pub fn threshold_start(
    alg: &str,
    params: Option<&str>,
    op: u32,
    party: u16,
    t: u16,
    n: u16,
    input: &[u8],
) -> Result<(u64, Out), Fail> {
    chk(input)?;
    let op = match op {
        0 => ThresholdOp::Dkg,
        1 => ThresholdOp::Sign,
        _ => return Err(Error::InvalidInput("op must be 0 (dkg) or 1 (sign)").into()),
    };
    let th = make!(new_threshold_in, Kind::Threshold, Policy::Any, alg, params);
    let session = ThresholdSession {
        op,
        party,
        t,
        n,
        input: input.to_vec(),
    };
    let r = th.start(&session, &mut *rng(Policy::Any)?);
    let _wipe = Zeroizing::new(session.input);
    let (state, msg) = r?;
    Ok((handles::insert(Obj::Threshold(state))?, z(msg)))
}

/// Returns `(done, [message, output])`; `output` (key share or signature) is empty until done.
pub fn threshold_step(handle: u64, msg: &[u8]) -> Result<(bool, Outs), Fail> {
    chk(msg)?;
    let Obj::Threshold(state) = handles::remove_threshold(handle)? else {
        return Err(Fail::BadHandle);
    };
    match state.step(msg)? {
        nextssl_core::ThresholdStep::Send(next, out) => {
            handles::restore(handle, Obj::Threshold(next))?;
            Ok((false, vec![z(out), z(Vec::new())]))
        }
        nextssl_core::ThresholdStep::Done(output, last) => {
            Ok((true, vec![z(last.unwrap_or_default()), output]))
        }
    }
}

/// Releases a PAKE or threshold handle without finishing it.
pub fn session_free(handle: u64) -> Result<(), Fail> {
    handles::remove(handle).map(drop)
}
