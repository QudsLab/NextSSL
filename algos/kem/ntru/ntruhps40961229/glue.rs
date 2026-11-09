//! Adapter: PQClean `PQCLEAN_NTRUHPS40961229_CLEAN` (verbatim C, symbols renamed `nextssl__ntruhps40961229__*`) -> nextssl `Kem`.
//! Generated wiring, no crypto logic. UNTESTED (not yet compiled). Randomness comes only from the
//! caller's EntropySource; there is no deterministic seed (`seed = 0`, `coins = 0`).
//! Decapsulation: the scheme uses implicit rejection, so a nonzero C return code still carries the
//! pseudorandom rejection secret and is not an error (see upstream kem.c).

use nextssl_core::{
    Ciphertext, EntropySource, Error, Kem, Len, Params, PrivateKey, PublicKey, Result, Seed,
    SharedSecret, Sizes, Zeroizing,
};

const PK: usize = 1842;
const SK: usize = 2366;
const CT: usize = 1842;
const SS: usize = 32;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_void};

    pub type FillFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;

    extern "C" {
        #[link_name = "nextssl__ntruhps40961229__PQCLEAN_NTRUHPS40961229_CLEAN_crypto_kem_keypair"]
        pub fn keypair(pk: *mut u8, sk: *mut u8) -> c_int;
        #[link_name = "nextssl__ntruhps40961229__PQCLEAN_NTRUHPS40961229_CLEAN_crypto_kem_enc"]
        pub fn enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
        #[link_name = "nextssl__ntruhps40961229__PQCLEAN_NTRUHPS40961229_CLEAN_crypto_kem_dec"]
        pub fn dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
        #[link_name = "nextssl__ntruhps40961229__rng_set"]
        pub fn rng_set(f: Option<FillFn>, ctx: *mut c_void);
        #[link_name = "nextssl__ntruhps40961229__rng_failed"]
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
    Error::InvalidLength { what, got, min, max }
}

struct K;

impl Kem for K {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            ct: Some(Len::fixed(CT)),
            ss: Some(Len::fixed(SS)),
            seed: Some(Len::fixed(0)),
            coins: Some(Len::fixed(0)),
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
        let rc = with_rng(rng, || unsafe { ffi::keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) })?;
        if rc != 0 {
            return Err(Error::Backend("keypair failed"));
        }
        Ok((
            PublicKey::from_vec(pk, Len::fixed(PK))?,
            PrivateKey::from_bytes(&sk, Len::fixed(SK))?,
        ))
    }

    fn encaps_from_coins(&self, _pk: &PublicKey, _coins: &Seed) -> Result<(Ciphertext, SharedSecret)> {
        Err(Error::Unsupported)
    }

    fn encaps(
        &self,
        pk: &PublicKey,
        rng: &mut dyn EntropySource,
    ) -> Result<(Ciphertext, SharedSecret)> {
        if pk.len() != PK {
            return Err(len_err("pk", pk.len(), PK, PK));
        }
        let mut ct = vec![0u8; CT];
        let mut ss = Zeroizing::new(vec![0u8; SS]);
        // SAFETY: ct/ss/pk are valid for CT/SS/PK bytes (pk length checked above).
        #[allow(unsafe_code)]
        let rc = with_rng(rng, || unsafe {
            ffi::enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_bytes().as_ptr())
        })?;
        if rc != 0 {
            return Err(Error::Backend("encapsulation failed"));
        }
        Ok((
            Ciphertext::from_vec(ct, Len::fixed(CT))?,
            SharedSecret::from_bytes(&ss, Len::fixed(SS))?,
        ))
    }

    fn decaps(&self, sk: &PrivateKey, ct: &Ciphertext) -> Result<SharedSecret> {
        if sk.len() != SK {
            return Err(len_err("sk", sk.len(), SK, SK));
        }
        if ct.len() != CT {
            return Err(len_err("ct", ct.len(), CT, CT));
        }
        let mut ss = Zeroizing::new(vec![0u8; SS]);
        // SAFETY: ss/ct/sk are valid for SS/CT/SK bytes (lengths checked above).
        #[allow(unsafe_code)]
        let _rc = unsafe { ffi::dec(ss.as_mut_ptr(), ct.as_bytes().as_ptr(), sk.as_bytes().as_ptr()) };
        SharedSecret::from_bytes(&ss, Len::fixed(SS))
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Kem>> {
    Ok(Box::new(K))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;

    #[test]
    fn roundtrip_and_lengths() {
        let k = new(&Params::new()).unwrap();
        let mut rng = FixedEntropy::new(&[0x5Au8; 8192]);
        let (pk, sk) = k.keygen(&mut rng).unwrap();
        let (ct, ss) = k.encaps(&pk, &mut rng).unwrap();
        assert_eq!(k.decaps(&sk, &ct).unwrap(), ss);
        let short = Ciphertext::from_vec(vec![0; CT - 1], Len::fixed(CT - 1)).unwrap();
        assert!(matches!(k.decaps(&sk, &short), Err(Error::InvalidLength { .. })));
        let mut dry = FixedEntropy::new(&[0u8; 1]);
        assert!(k.keygen(&mut dry).is_err());
    }
}
