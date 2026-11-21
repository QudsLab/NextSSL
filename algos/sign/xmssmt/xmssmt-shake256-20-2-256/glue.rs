//! Adapter: XMSS reference implementation (xmss-reference, RFC 8391 / NIST SP 800-208) `XMSSMT-SHAKE256_20/2_256` (verbatim C, symbols renamed
//! `nextssl__xmssmt_shake256_20_2_256__*`) -> nextssl `StatefulSign`.
//! Generated wiring, no crypto logic. pk = [OID || root || PUB_SEED], sk = the reference's serialized state
//! [OID || index || SK_SEED || SK_PRF || root || PUB_SEED] (the whole secret key including the index, fixed length), sig = the
//! RFC 8391 signature (the reference's `sm` without the appended message).
//! Persist-before-release: the C code advances a private copy of the state, `persist` receives that copy, and only after `Ok` is the
//! key replaced and the signature returned. The reference never signs with the last leaf (it wipes the key in memory and
//! signs with a zero seed), so the usable number of signatures is 2^h - 1 and the key counts as exhausted at index 2^h - 1.
//! Keygen from `rng` draws 3 * n bytes; `keygen_from_seed` takes SK_SEED || SK_PRF || PUB_SEED (3 * n bytes).
// TARGET GATE (cargo xtask gen, from algo.toml exclude_targets)
#![cfg(not(target_env = "msvc"))]

use nextssl_core::{
    EntropySource, Error, Len, Params, PublicKey, Result, Seed, Signature, Sizes, StatefulKey,
    StatefulSign, Zeroizing,
};

const OID: u32 = 0x00000029;
const MT: core::ffi::c_int = 1;
const PK: usize = 68;
const SK: usize = 135;
const SIG: usize = 4963;
const SEED: usize = 96;
/// Index field: offset (after the 4-byte OID) and length in bytes, big endian.
const IDX_OFF: usize = 4;
const IDX_BYTES: usize = 3;
/// Signatures the reference can produce: 2^h - 1.
const MAX: u64 = (1u64 << 20) - 1;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_void};

    pub type FillFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;

    extern "C" {
        #[link_name = "nextssl__xmssmt_shake256_20_2_256__nsw_keypair"]
        pub fn keypair(pk: *mut u8, sk: *mut u8, oid: u32, mt: c_int) -> c_int;
        #[link_name = "nextssl__xmssmt_shake256_20_2_256__nsw_keypair_seed"]
        pub fn keypair_seed(pk: *mut u8, sk: *mut u8, oid: u32, mt: c_int, seed: *mut u8) -> c_int;
        #[link_name = "nextssl__xmssmt_shake256_20_2_256__nsw_sign"]
        pub fn sign(
            sk: *mut u8,
            sm: *mut u8,
            smlen: *mut u64,
            m: *const u8,
            mlen: u64,
            mt: c_int,
        ) -> c_int;
        #[link_name = "nextssl__xmssmt_shake256_20_2_256__nsw_open"]
        pub fn open(
            m: *mut u8,
            mlen: *mut u64,
            sm: *const u8,
            smlen: u64,
            pk: *const u8,
            mt: c_int,
        ) -> c_int;
        #[link_name = "nextssl__xmssmt_shake256_20_2_256__rng_set"]
        pub fn rng_set(f: Option<FillFn>, ctx: *mut c_void);
        #[link_name = "nextssl__xmssmt_shake256_20_2_256__rng_failed"]
        pub fn rng_failed() -> c_int;
    }

    /// Trampoline called by the C `randombytes`; fills `out[..n]` from the active EntropySource.
    ///
    /// # Safety
    /// `ctx` must be the `*mut &mut dyn EntropySource` installed by `with_rng` and `out` must be
    /// valid for `n` writable bytes.
    pub unsafe extern "C" fn fill_cb(ctx: *mut c_void, out: *mut u8, n: usize) -> c_int {
        // SAFETY: ctx is the live `&mut &mut dyn EntropySource` set by `with_rng` on this thread
        // for the duration of the C call; `out` is valid for `n` bytes per the shim's contract.
        let rng = unsafe { &mut *(ctx as *mut &mut dyn nextssl_core::EntropySource) };
        let buf = unsafe { core::slice::from_raw_parts_mut(out, n) };
        match rng.fill(buf) {
            Ok(()) => 0,
            Err(_) => 1,
        }
    }
}

/// Runs `f` (a C call) with `rng` installed as the source of the upstream's `randombytes`.
/// A failed or exhausted entropy source is an error, never a zero fill.
#[allow(unsafe_code)]
fn with_rng<T>(rng: &mut dyn EntropySource, f: impl FnOnce() -> T) -> Result<T> {
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            // SAFETY: clears the thread-local callback installed below.
            unsafe { ffi::rng_set(None, core::ptr::null_mut()) }
        }
    }
    let mut r: &mut dyn EntropySource = rng;
    let ctx = (&mut r as *mut &mut dyn EntropySource).cast::<core::ffi::c_void>();
    // SAFETY: `ctx` outlives the scope; the callback matches FillFn.
    unsafe { ffi::rng_set(Some(ffi::fill_cb), ctx) };
    let _scope = Scope;
    let v = f();
    // SAFETY: reads the thread-local failure flag set by the shim.
    if unsafe { ffi::rng_failed() } != 0 {
        return Err(Error::EntropyFailure("entropy source failed during C call"));
    }
    Ok(v)
}

fn len_err(what: &'static str, got: usize, min: usize, max: usize) -> Error {
    Error::InvalidLength {
        what,
        got,
        min,
        max,
    }
}

fn oid_prefix() -> [u8; 4] {
    OID.to_be_bytes()
}

/// Checks length and OID prefix of a serialized key state and returns its index.
fn index_of(sk: &[u8]) -> Result<u64> {
    if sk.len() != SK {
        return Err(len_err("sk", sk.len(), SK, SK));
    }
    if sk[..4] != oid_prefix() {
        return Err(Error::InvalidInput(
            "key state belongs to another parameter set",
        ));
    }
    let mut idx = 0u64;
    for b in &sk[IDX_OFF..IDX_OFF + IDX_BYTES] {
        idx = (idx << 8) | u64::from(*b);
    }
    Ok(idx)
}

struct Alg;

impl StatefulSign for Alg {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            sig: Some(Len::fixed(SIG)),
            seed: Some(Len::fixed(SEED)),
            ..Sizes::NONE
        }
    }

    fn max_signatures(&self) -> u64 {
        MAX
    }

    fn remaining(&self, key: &StatefulKey) -> Result<u64> {
        let idx = index_of(key.as_bytes())?;
        Ok(MAX.saturating_sub(idx))
    }

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, StatefulKey)> {
        Len::fixed(SEED).check("seed", seed.len())?;
        let mut s = Zeroizing::new(seed.as_bytes().to_vec());
        let mut pk = vec![0u8; PK];
        let mut sk = Zeroizing::new(vec![0u8; SK]);
        // SAFETY: pk/sk are valid for PK/SK bytes (OID + core sizes of this parameter set), seed for SEED = 3 * n bytes.
        #[allow(unsafe_code)]
        let rc =
            unsafe { ffi::keypair_seed(pk.as_mut_ptr(), sk.as_mut_ptr(), OID, MT, s.as_mut_ptr()) };
        if rc != 0 {
            return Err(Error::Backend("keygen failed"));
        }
        Ok((
            PublicKey::from_vec(pk, Len::fixed(PK))?,
            StatefulKey::from_bytes(&sk, Len::fixed(SK))?,
        ))
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, StatefulKey)> {
        let mut pk = vec![0u8; PK];
        let mut sk = Zeroizing::new(vec![0u8; SK]);
        // SAFETY: pk/sk are valid for PK/SK bytes, the exact sizes of the upstream API for this OID.
        #[allow(unsafe_code)]
        let rc = with_rng(rng, || unsafe {
            ffi::keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), OID, MT)
        })?;
        if rc != 0 {
            return Err(Error::Backend("keygen failed"));
        }
        Ok((
            PublicKey::from_vec(pk, Len::fixed(PK))?,
            StatefulKey::from_bytes(&sk, Len::fixed(SK))?,
        ))
    }

    fn sign(
        &self,
        key: &mut StatefulKey,
        msg: &[u8],
        persist: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Signature> {
        let idx = index_of(key.as_bytes())?;
        if idx >= MAX {
            return Err(Error::KeyExhausted);
        }
        let mut work = Zeroizing::new(key.as_bytes().to_vec());
        let mut sm = vec![0u8; SIG + msg.len()];
        let mut smlen: u64 = 0;
        // SAFETY: work holds the full SK-byte state; sm is valid for SIG + msg.len() bytes, the upstream's output size.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::sign(
                work.as_mut_ptr(),
                sm.as_mut_ptr(),
                &mut smlen,
                msg.as_ptr(),
                msg.len() as u64,
                MT,
            )
        };
        if rc != 0 || smlen != (SIG + msg.len()) as u64 {
            return Err(Error::Backend("signing failed"));
        }
        // Persist the advanced state before the signature leaves this function.
        persist(&work)?;
        *key = StatefulKey::from_bytes(&work, Len::fixed(SK))?;
        sm.truncate(SIG);
        Signature::from_vec(sm, Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<bool> {
        if pk.len() != PK {
            return Err(len_err("pk", pk.len(), PK, PK));
        }
        if pk.as_bytes()[..4] != oid_prefix() {
            return Err(Error::InvalidInput(
                "public key belongs to another parameter set",
            ));
        }
        if sig.len() != SIG {
            return Err(len_err("sig", sig.len(), SIG, SIG));
        }
        let mut sm = Vec::with_capacity(SIG + msg.len());
        sm.extend_from_slice(sig.as_bytes());
        sm.extend_from_slice(msg);
        let mut out = vec![0u8; sm.len()];
        let mut outlen: u64 = 0;
        // SAFETY: sm is valid for SIG + msg.len() bytes, out for the same size, pk for PK bytes (length and OID checked above).
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::open(
                out.as_mut_ptr(),
                &mut outlen,
                sm.as_ptr(),
                sm.len() as u64,
                pk.as_bytes().as_ptr(),
                MT,
            )
        };
        Ok(rc == 0)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StatefulSign>> {
    Ok(Box::new(Alg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;

    fn rng() -> FixedEntropy {
        FixedEntropy::new(
            &(0..4096u64)
                .map(|i| {
                    let x = (i + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    let x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    (x ^ (x >> 31)) as u8
                })
                .collect::<Vec<u8>>(),
        )
    }

    #[test]
    fn roundtrip_state_and_rejects() {
        let a = new(&Params::new()).unwrap();
        let (pk, mut sk) = a.keygen(&mut rng()).unwrap();
        assert_eq!(a.remaining(&sk).unwrap(), a.max_signatures());
        let mut persisted: Vec<Vec<u8>> = Vec::new();
        let mut keep = |s: &[u8]| -> Result<()> {
            persisted.push(s.to_vec());
            Ok(())
        };
        let s1 = a.sign(&mut sk, b"message one", &mut keep).unwrap();
        let s2 = a.sign(&mut sk, b"message two", &mut keep).unwrap();
        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[1], sk.as_bytes());
        assert_eq!(a.remaining(&sk).unwrap(), a.max_signatures() - 2);
        assert!(a.verify(&pk, b"message one", &s1).unwrap());
        assert!(a.verify(&pk, b"message two", &s2).unwrap());
        assert!(!a.verify(&pk, b"message two", &s1).unwrap());
        assert!(!a.verify(&pk, b"message onE", &s1).unwrap());
        assert_ne!(s1.as_bytes(), s2.as_bytes());
        // A failed persist returns no signature and keeps the old state.
        let before = sk.as_bytes().to_vec();
        let mut fail = |_: &[u8]| -> Result<()> { Err(Error::PersistFailed) };
        assert!(matches!(
            a.sign(&mut sk, b"x", &mut fail),
            Err(Error::PersistFailed)
        ));
        assert_eq!(sk.as_bytes(), &before[..]);
        // Wrong lengths are errors, not silent truncation.
        let short = Signature::from_vec(vec![0; SIG - 1], Len::fixed(SIG - 1)).unwrap();
        assert!(matches!(
            a.verify(&pk, b"m", &short),
            Err(Error::InvalidLength { .. })
        ));
        let mut dry = FixedEntropy::new(&[0u8; 1]);
        assert!(a.keygen(&mut dry).is_err());
    }

    #[test]
    fn exhausted_key_and_seed_keygen() {
        let a = new(&Params::new()).unwrap();
        let seed = Seed::from_bytes(&vec![7u8; SEED], Len::fixed(SEED)).unwrap();
        let (pk1, sk1) = a.keygen_from_seed(&seed).unwrap();
        let (pk2, _) = a.keygen_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        // Craft a key state whose index is the last unusable value: exhausted before persist is called.
        let mut raw = sk1.as_bytes().to_vec();
        for (i, b) in MAX.to_be_bytes()[8 - IDX_BYTES.min(8)..].iter().enumerate() {
            raw[IDX_OFF + i] = *b;
        }
        let mut dead = StatefulKey::from_bytes(&raw, Len::fixed(SK)).unwrap();
        assert_eq!(a.remaining(&dead).unwrap(), 0);
        let mut called = false;
        let mut p = |_: &[u8]| -> Result<()> {
            called = true;
            Ok(())
        };
        assert!(matches!(
            a.sign(&mut dead, b"m", &mut p),
            Err(Error::KeyExhausted)
        ));
        assert!(!called);
        let bad_seed = Seed::from_bytes(&vec![7u8; SEED - 1], Len::fixed(SEED - 1)).unwrap();
        assert!(a.keygen_from_seed(&bad_seed).is_err());
    }
}
