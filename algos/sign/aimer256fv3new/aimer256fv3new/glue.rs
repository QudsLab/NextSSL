//! Adapter: PQClean `aimer256fv3new (SUPERCOP crypto_sign) (ref)` (verbatim C, symbols renamed `nextssl__aimer256fv3new__*`) -> nextssl `Sign`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled). Randomness comes only from the
//! caller's EntropySource; there is no deterministic seed (`seed = 0`) and no context string
//! (`ctx = 0`: a non-empty ctx is an error, never ignored).

use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign, Signature, Sizes,
    Zeroizing,
};

const PK: usize = 64;
const SK: usize = 96;
const SIG_MAX: usize = 31360;
const SIG_MIN: usize = 1;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_void};

    pub type FillFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;

    extern "C" {
        #[link_name = "nextssl__aimer256fv3new__crypto_sign_keypair"]
        pub fn keypair(pk: *mut u8, sk: *mut u8) -> c_int;
        #[link_name = "nextssl__aimer256fv3new__crypto_sign"]
        pub fn sign(
            sm: *mut u8,
            smlen: *mut core::ffi::c_ulonglong,
            m: *const u8,
            mlen: core::ffi::c_ulonglong,
            sk: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__aimer256fv3new__crypto_sign_open"]
        pub fn open(
            m: *mut u8,
            mlen: *mut core::ffi::c_ulonglong,
            sm: *const u8,
            smlen: core::ffi::c_ulonglong,
            pk: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__aimer256fv3new__rng_set"]
        pub fn rng_set(f: Option<FillFn>, ctx: *mut c_void);
        #[link_name = "nextssl__aimer256fv3new__rng_failed"]
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

struct S;

impl Sign for S {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            sig: Some(Len::range(SIG_MIN, SIG_MAX)),
            seed: Some(Len::fixed(0)),
            ctx: Some(Len::fixed(0)),
            ..Sizes::NONE
        }
    }

    fn keygen_from_seed(&self, _seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        Err(Error::Unsupported)
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let mut pk = vec![0u8; PK];
        let mut sk = Zeroizing::new(vec![0u8; SK]);
        // SAFETY: pk/sk are valid for PK/SK bytes, the exact sizes of the upstream API.
        #[allow(unsafe_code)]
        let rc = with_rng(rng, || unsafe {
            ffi::keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        })?;
        if rc != 0 {
            return Err(Error::Backend("keypair failed"));
        }
        Ok((
            PublicKey::from_vec(pk, Len::fixed(PK))?,
            PrivateKey::from_bytes(&sk, Len::fixed(SK))?,
        ))
    }

    fn sign(
        &self,
        sk: &PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Signature> {
        if !ctx.is_empty() {
            return Err(Error::InvalidInput("this algorithm has no context string"));
        }
        if sk.len() != SK {
            return Err(len_err("sk", sk.len(), SK, SK));
        }
        let mut sm = vec![0u8; msg.len() + SIG_MAX];
        let mut smlen: core::ffi::c_ulonglong = 0;
        // SAFETY: sm has room for msg + SIG_MAX bytes (the NIST bound); msg/sk valid for their lengths.
        #[allow(unsafe_code)]
        let rc = with_rng(rng, || unsafe {
            ffi::sign(
                sm.as_mut_ptr(),
                &mut smlen,
                msg.as_ptr(),
                msg.len() as core::ffi::c_ulonglong,
                sk.as_bytes().as_ptr(),
            )
        })?;
        let smlen = smlen as usize;
        if rc != 0 || smlen < msg.len() || smlen > sm.len() {
            return Err(Error::Backend("signing failed"));
        }
        let siglen = smlen - msg.len();
        if !(SIG_MIN..=SIG_MAX).contains(&siglen) {
            return Err(Error::Backend(
                "signing failed: unexpected signature length",
            ));
        }
        // NIST layout: signed message = signature || message. Anything else is an error, never guessed.
        if sm[siglen..smlen] != *msg {
            return Err(Error::Backend("signed message is not signature||message"));
        }
        sm.truncate(siglen);
        Signature::from_vec(sm, Len::range(SIG_MIN, SIG_MAX))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &Signature) -> Result<bool> {
        if !ctx.is_empty() {
            return Err(Error::InvalidInput("this algorithm has no context string"));
        }
        if pk.len() != PK {
            return Err(len_err("pk", pk.len(), PK, PK));
        }
        if sig.len() < SIG_MIN || sig.len() > SIG_MAX {
            return Err(len_err("sig", sig.len(), SIG_MIN, SIG_MAX));
        }
        let mut sm = Vec::with_capacity(sig.len() + msg.len());
        sm.extend_from_slice(sig.as_bytes());
        sm.extend_from_slice(msg);
        let mut m = vec![0u8; sm.len()];
        let mut mlen: core::ffi::c_ulonglong = 0;
        // SAFETY: m and sm are valid for sm.len() bytes; pk length checked above.
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::open(
                m.as_mut_ptr(),
                &mut mlen,
                sm.as_ptr(),
                sm.len() as core::ffi::c_ulonglong,
                pk.as_bytes().as_ptr(),
            )
        };
        Ok(rc == 0 && mlen as usize == msg.len() && m[..msg.len()] == *msg)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(S))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;

    #[test]
    fn roundtrip_and_rejects() {
        let g = new(&Params::new()).unwrap();
        let mut rng = FixedEntropy::new(
            &(0..8192u64)
                .map(|i| {
                    let x = (i + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    let x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    let x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                    (x ^ (x >> 31)) as u8
                })
                .collect::<Vec<u8>>(),
        );
        let (pk, sk) = g.keygen(&mut rng).unwrap();
        let sig = g.sign(&sk, b"message", b"", &mut rng).unwrap();
        assert!(g.verify(&pk, b"message", b"", &sig).unwrap());
        assert!(!g.verify(&pk, b"messagE", b"", &sig).unwrap());
        assert!(g.sign(&sk, b"m", b"ctx", &mut rng).is_err());
        let too_long = Signature::from_vec(vec![0; SIG_MAX + 1], Len::fixed(SIG_MAX + 1)).unwrap();
        assert!(matches!(
            g.verify(&pk, b"m", b"", &too_long),
            Err(Error::InvalidLength { .. })
        ));
    }
}
