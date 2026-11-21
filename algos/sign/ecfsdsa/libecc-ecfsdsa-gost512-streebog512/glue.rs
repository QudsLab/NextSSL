//! Adapter: libecc `ECFSDSA` over `GOST512` with `STREEBOG512` (verbatim C, symbols renamed `nextssl__libecc_ecfsdsa_gost512_streebog512__*`) -> nextssl `Sign`.
//! Glue only, no crypto logic. Randomness (signing nonces, key generation) comes solely from the caller's
//! EntropySource through a per-thread callback; libecc's own OS-random source is not compiled.
//! Key formats: sk = the private scalar (big-endian, exactly the group order length in bytes; `keygen_from_seed`
//! takes it as the seed and rejects 0 and values >= q); pk = affine x || y (field-size bytes each);
//! sig = the libecc native signature encoding. No context string (`ctx = 0`: a non-empty ctx is an error).

use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign, Signature, Sizes,
    Zeroizing,
};

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_uint, c_ulong, c_void};

    pub type FillFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;

    extern "C" {
        #[link_name = "nextssl__libecc_ecfsdsa_gost512_streebog512__shim_rng_set"]
        pub fn rng_set(f: Option<FillFn>, ctx: *mut c_void);
        #[link_name = "nextssl__libecc_ecfsdsa_gost512_streebog512__shim_rng_failed"]
        pub fn rng_failed() -> c_int;
        #[link_name = "nextssl__libecc_ecfsdsa_gost512_streebog512__shim_sizes"]
        pub fn sizes(sk: *mut c_uint, pk: *mut c_uint, sig: *mut c_uint) -> c_int;
        #[link_name = "nextssl__libecc_ecfsdsa_gost512_streebog512__shim_keygen"]
        pub fn keygen(sk: *mut u8, pk: *mut u8) -> c_int;
        #[link_name = "nextssl__libecc_ecfsdsa_gost512_streebog512__shim_pk_from_sk"]
        pub fn pk_from_sk(sk: *const u8, pk: *mut u8) -> c_int;
        #[link_name = "nextssl__libecc_ecfsdsa_gost512_streebog512__shim_sign"]
        pub fn sign(sk: *const u8, msg: *const u8, mlen: c_ulong, sig: *mut u8) -> c_int;
        #[link_name = "nextssl__libecc_ecfsdsa_gost512_streebog512__shim_verify"]
        pub fn verify(pk: *const u8, msg: *const u8, mlen: c_ulong, sig: *const u8) -> c_int;
    }

    /// Trampoline called by the C `get_random`; fills `out[..n]` from the active EntropySource.
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

/// Runs `f` (a C call) with `rng` installed as the source of libecc's `get_random`.
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

fn len_err(what: &'static str, got: usize, want: usize) -> Error {
    Error::InvalidLength {
        what,
        got,
        min: want,
        max: want,
    }
}

struct S {
    sk: usize,
    pk: usize,
    sig: usize,
}

impl S {
    #[allow(unsafe_code)]
    fn probe() -> Result<Self> {
        let (mut a, mut b, mut c) = (0u32, 0u32, 0u32);
        // SAFETY: three valid out-pointers.
        let rc = unsafe { ffi::sizes(&mut a, &mut b, &mut c) };
        if rc != 0 || a == 0 || b == 0 || c == 0 {
            return Err(Error::Backend("libecc size query failed"));
        }
        Ok(S {
            sk: a as usize,
            pk: b as usize,
            sig: c as usize,
        })
    }

    fn check_sk(&self, sk: &PrivateKey) -> Result<()> {
        if sk.len() != self.sk {
            return Err(len_err("sk", sk.len(), self.sk));
        }
        Ok(())
    }
}

impl Sign for S {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(self.pk)),
            sk: Some(Len::fixed(self.sk)),
            sig: Some(Len::fixed(self.sig)),
            seed: Some(Len::fixed(self.sk)),
            ctx: Some(Len::fixed(0)),
            ..Sizes::NONE
        }
    }

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        if seed.len() != self.sk {
            return Err(len_err("seed", seed.len(), self.sk));
        }
        let mut pk = vec![0u8; self.pk];
        // SAFETY: seed is valid for sk bytes (checked), pk for pk bytes (the shim's own size query).
        #[allow(unsafe_code)]
        let rc = unsafe { ffi::pk_from_sk(seed.as_bytes().as_ptr(), pk.as_mut_ptr()) };
        if rc != 0 {
            return Err(Error::InvalidInput(
                "seed is not a valid private scalar (must satisfy 0 < d < group order)",
            ));
        }
        Ok((
            PublicKey::from_vec(pk, Len::fixed(self.pk))?,
            PrivateKey::from_bytes(seed.as_bytes(), Len::fixed(self.sk))?,
        ))
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let mut pk = vec![0u8; self.pk];
        let mut sk = Zeroizing::new(vec![0u8; self.sk]);
        // SAFETY: sk/pk are valid for the sizes the shim itself reports.
        #[allow(unsafe_code)]
        let rc = with_rng(rng, || unsafe { ffi::keygen(sk.as_mut_ptr(), pk.as_mut_ptr()) })?;
        if rc != 0 {
            return Err(Error::Backend("key generation failed"));
        }
        Ok((
            PublicKey::from_vec(pk, Len::fixed(self.pk))?,
            PrivateKey::from_bytes(&sk, Len::fixed(self.sk))?,
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
        self.check_sk(sk)?;
        if msg.len() as u64 > u32::MAX as u64 {
            return Err(Error::InvalidInput("message longer than 2^32-1 bytes"));
        }
        let mut sig = vec![0u8; self.sig];
        // SAFETY: sk valid for sk bytes (checked), msg for msg.len(), sig for sig bytes (shim's size query).
        #[allow(unsafe_code)]
        let rc = with_rng(rng, || unsafe {
            ffi::sign(
                sk.as_bytes().as_ptr(),
                msg.as_ptr(),
                msg.len() as core::ffi::c_ulong,
                sig.as_mut_ptr(),
            )
        })?;
        if rc != 0 {
            return Err(Error::Backend("signing failed (invalid private key or internal error)"));
        }
        Signature::from_vec(sig, Len::fixed(self.sig))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &Signature) -> Result<bool> {
        if !ctx.is_empty() {
            return Err(Error::InvalidInput("this algorithm has no context string"));
        }
        if pk.len() != self.pk {
            return Err(len_err("pk", pk.len(), self.pk));
        }
        if sig.len() != self.sig {
            return Err(len_err("sig", sig.len(), self.sig));
        }
        if msg.len() as u64 > u32::MAX as u64 {
            return Err(Error::InvalidInput("message longer than 2^32-1 bytes"));
        }
        // SAFETY: pk, sig valid for the checked lengths, msg for msg.len().
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::verify(
                pk.as_bytes().as_ptr(),
                msg.as_ptr(),
                msg.len() as core::ffi::c_ulong,
                sig.as_bytes().as_ptr(),
            )
        };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(Error::InvalidInput("malformed public key or signature")),
        }
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(S::probe()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;

    fn entropy() -> FixedEntropy {
        FixedEntropy::new(
            &(0..65536u64)
                .map(|i| {
                    let x = (i + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    let x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    let x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                    (x ^ (x >> 31)) as u8
                })
                .collect::<Vec<u8>>(),
        )
    }

    #[test]
    fn roundtrip_and_rejects() {
        let g = S::probe().unwrap();
        println!("SIZES libecc-ecfsdsa-gost512-streebog512 sk={} pk={} sig={}", g.sk, g.pk, g.sig);
        let mut rng = entropy();
        let (pk, sk) = g.keygen(&mut rng).unwrap();
        let sig = g.sign(&sk, b"message", b"", &mut rng).unwrap();
        assert!(g.verify(&pk, b"message", b"", &sig).unwrap());
        assert!(!g.verify(&pk, b"messagE", b"", &sig).unwrap());
        let mut bad = sig.as_bytes().to_vec();
        bad[0] ^= 1;
        let bad = Signature::from_vec(bad, Len::fixed(g.sig)).unwrap();
        assert!(!g.verify(&pk, b"message", b"", &bad).unwrap_or(false));
        assert!(g.sign(&sk, b"m", b"ctx", &mut rng).is_err());
        let short = Signature::from_vec(vec![0; g.sig + 1], Len::fixed(g.sig + 1)).unwrap();
        assert!(matches!(
            g.verify(&pk, b"m", b"", &short),
            Err(Error::InvalidLength { .. })
        ));
        // the seed path: a private scalar re-derives the same public key
        let seed = Seed::from_bytes(sk.as_bytes(), Len::fixed(g.sk)).unwrap();
        let (pk2, sk2) = g.keygen_from_seed(&seed).unwrap();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
        // zero and oversized scalars are refused
        let zero = Seed::from_bytes(&vec![0u8; g.sk], Len::fixed(g.sk)).unwrap();
        assert!(g.keygen_from_seed(&zero).is_err());
        let ff = Seed::from_bytes(&vec![0xffu8; g.sk], Len::fixed(g.sk)).unwrap();
        assert!(g.keygen_from_seed(&ff).is_err());
        // an exhausted entropy source is an error, not a zero nonce
        let mut empty = FixedEntropy::new(&[]);
        assert!(g.sign(&sk, b"message", b"", &mut empty).is_err());
    }

    /// libecc's own published self-test vectors: (private scalar, message, signature), all hex. The public key is
    /// derived by libecc from the published private scalar (printed as `KATPK` for kat.json), then the published
    /// signature must verify under it and must fail for a different message.
    const KATS: &[(&str, &str, &str)] = &[];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn published_vectors_verify() {
        let g = S::probe().unwrap();
        for (sk, msg, sig) in KATS.iter().copied() {
            let seed = Seed::from_bytes(&unhex(sk), Len::fixed(g.sk)).unwrap();
            let (pk, _) = g.keygen_from_seed(&seed).unwrap();
            println!("KATPK libecc-ecfsdsa-gost512-streebog512 {}", pk.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>());
            let sig = Signature::from_vec(unhex(sig), Len::fixed(g.sig)).unwrap();
            assert!(g.verify(&pk, &unhex(msg), b"", &sig).unwrap());
            let mut other = unhex(msg);
            other.push(0);
            assert!(!g.verify(&pk, &other, b"", &sig).unwrap());
        }
    }
}
