//! Adapter: NIST `giophantus IEC602 round 1 (encrypt/IEC602)` (verbatim C, symbols renamed `nextssl__giophantus_iec602_pke_r1__*`) -> nextssl `Pke`.
//! Generated wiring, no crypto logic. UNTESTED (not yet run). Randomness comes only from the caller's
//! EntropySource. IEC602 encrypts a fixed MLEN = 16-byte message into a fixed C_SIZE = 28824-byte
//! ciphertext: crypto_encrypt copies exactly 16 bytes whatever msglen says and crypto_encrypt_open reads
//! exactly C_SIZE bytes whatever ciplen says, so both lengths are checked here and any other length is an
//! error (the authors' KATs use these sizes). The label must be empty (the scheme has no label input), a
//! non-empty label is an error, never ignored.
//! Every decryption failure is the one `AuthenticationFailed`.

use nextssl_core::{
    EntropySource, Error, Len, Params, Pke, PrivateKey, PublicKey, Result, Sizes, Zeroizing,
};

const PK: usize = 14412;
const SK: usize = 15014;
const CT: usize = 28824;
const PT: usize = 16;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_void};

    pub type FillFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;

    extern "C" {
        #[link_name = "nextssl__giophantus_iec602_pke_r1__crypto_encrypt_keypair"]
        pub fn keypair(pk: *mut u8, sk: *mut u8) -> c_int;
        #[link_name = "nextssl__giophantus_iec602_pke_r1__crypto_encrypt"]
        pub fn encrypt(
            c: *mut u8,
            clen: *mut core::ffi::c_ulonglong,
            m: *const u8,
            mlen: core::ffi::c_ulonglong,
            pk: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__giophantus_iec602_pke_r1__crypto_encrypt_open"]
        pub fn decrypt(
            m: *mut u8,
            mlen: *mut core::ffi::c_ulonglong,
            c: *const u8,
            clen: core::ffi::c_ulonglong,
            sk: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__giophantus_iec602_pke_r1__rng_set"]
        pub fn rng_set(f: Option<FillFn>, ctx: *mut c_void);
        #[link_name = "nextssl__giophantus_iec602_pke_r1__rng_failed"]
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

struct P;

impl Pke for P {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            ct: Some(Len::fixed(CT)),
            out: Some(Len::fixed(PT)),
            ctx: Some(Len::fixed(0)),
            ..Sizes::NONE
        }
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

    fn encrypt(
        &self,
        pk: &PublicKey,
        pt: &[u8],
        label: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        if !label.is_empty() {
            return Err(Error::InvalidInput("this algorithm has no label input"));
        }
        if pk.len() != PK {
            return Err(len_err("pk", pk.len(), PK, PK));
        }
        if pt.len() != PT {
            return Err(len_err("plaintext", pt.len(), PT, PT));
        }
        let mut ct = vec![0u8; CT];
        let mut clen: core::ffi::c_ulonglong = 0;
        // SAFETY: ct is valid for CT = C_SIZE bytes, exactly what the callee writes; pt is valid for the
        // MLEN = PT bytes the callee reads and pk for PK bytes (both lengths checked above).
        #[allow(unsafe_code)]
        let rc = with_rng(rng, || unsafe {
            ffi::encrypt(
                ct.as_mut_ptr(),
                &mut clen,
                pt.as_ptr(),
                pt.len() as core::ffi::c_ulonglong,
                pk.as_bytes().as_ptr(),
            )
        })?;
        let clen = clen as usize;
        if rc != 0 || clen != CT {
            return Err(Error::Backend("encryption failed"));
        }
        ct.truncate(clen);
        Ok(ct)
    }

    fn decrypt(&self, sk: &PrivateKey, ct: &[u8], label: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if !label.is_empty() {
            return Err(Error::InvalidInput("this algorithm has no label input"));
        }
        if sk.len() != SK {
            return Err(len_err("sk", sk.len(), SK, SK));
        }
        if ct.len() != CT {
            return Err(len_err("ciphertext", ct.len(), CT, CT));
        }
        let mut m = Zeroizing::new(vec![0u8; PT]);
        let mut mlen: core::ffi::c_ulonglong = 0;
        // SAFETY: m is valid for the MLEN = PT bytes the callee writes; ct is valid for the CT = C_SIZE bytes
        // it reads and sk for SK bytes (both lengths checked above).
        #[allow(unsafe_code)]
        let rc = unsafe {
            ffi::decrypt(
                m.as_mut_ptr(),
                &mut mlen,
                ct.as_ptr(),
                ct.len() as core::ffi::c_ulonglong,
                sk.as_bytes().as_ptr(),
            )
        };
        let mlen = mlen as usize;
        if rc != 0 || mlen != PT {
            return Err(Error::AuthenticationFailed);
        }
        m.truncate(mlen);
        Ok(m)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Pke>> {
    Ok(Box::new(P))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextssl_core::testing::FixedEntropy;

    #[test]
    fn roundtrip_and_lengths() {
        let p = new(&Params::new()).unwrap();
        let mut rng = FixedEntropy::new(
            &(0..(1u64 << 20))
                .map(|i| {
                    let x = (i + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    let x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    let x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                    (x ^ (x >> 31)) as u8
                })
                .collect::<Vec<u8>>(),
        );
        let (pk, sk) = p.keygen(&mut rng).unwrap();
        let ct = p.encrypt(&pk, &[0x42u8; 16], b"", &mut rng).unwrap();
        assert_eq!(&p.decrypt(&sk, &ct, b"").unwrap()[..], &[0x42u8; 16][..]);
        assert!(p.encrypt(&pk, &[1u8; 16], b"label", &mut rng).is_err());
        // Upstream copies exactly 16 message bytes and reads exactly C_SIZE ciphertext bytes, so any other
        // length must be refused before the C code runs (a short buffer would be over-read).
        assert!(p.encrypt(&pk, &[1u8; PT - 1], b"", &mut rng).is_err());
        assert!(p.encrypt(&pk, &[1u8; PT + 1], b"", &mut rng).is_err());
        assert!(p.decrypt(&sk, &[0u8; 3], b"").is_err());
        assert!(p.decrypt(&sk, &ct[..CT - 1], b"").is_err());
        let mut long = ct.clone();
        long.push(0);
        assert!(p.decrypt(&sk, &long, b"").is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(p.decrypt(&sk, &bad, b"").is_err());
    }
}
