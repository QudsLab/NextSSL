//! Adapter: NIST `compactlwe Compact-LWE-Public-Key-Enc round 1 (.)` (verbatim C, symbols renamed `nextssl__compact_lwe_public_key_enc_r1__*`) -> nextssl `Pke`.
//! Generated wiring, no crypto logic. UNTESTED (not yet run). Randomness comes only from the caller's
//! EntropySource. NIST crypto_encrypt contract: clen <= mlen + CRYPTO_BYTES (the NIST KAT generator sizes
//! its buffer that way); plaintexts are capped at PT_MAX (the generator's maximum message length) and the
//! label must be empty (the scheme has no label input), a non-empty label is an error, never ignored.
//! Every decryption failure is the one `AuthenticationFailed`.

use nextssl_core::{
    EntropySource, Error, Len, Params, Pke, PrivateKey, PublicKey, Result, Sizes, Zeroizing,
};

const PK: usize = 2064;
const SK: usize = 232;
const OVER: usize = 720;
const PT_MAX: usize = 3300;

mod ffi {
    #![allow(unsafe_code)]
    use core::ffi::{c_int, c_void};

    pub type FillFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;

    extern "C" {
        #[link_name = "nextssl__compact_lwe_public_key_enc_r1__crypto_encrypt_keypair"]
        pub fn keypair(pk: *mut u8, sk: *mut u8) -> c_int;
        #[link_name = "nextssl__compact_lwe_public_key_enc_r1__crypto_encrypt"]
        pub fn encrypt(
            c: *mut u8,
            clen: *mut core::ffi::c_ulonglong,
            m: *const u8,
            mlen: core::ffi::c_ulonglong,
            pk: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__compact_lwe_public_key_enc_r1__crypto_encrypt_open"]
        pub fn decrypt(
            m: *mut u8,
            mlen: *mut core::ffi::c_ulonglong,
            c: *const u8,
            clen: core::ffi::c_ulonglong,
            sk: *const u8,
        ) -> c_int;
        #[link_name = "nextssl__compact_lwe_public_key_enc_r1__rng_set"]
        pub fn rng_set(f: Option<FillFn>, ctx: *mut c_void);
        #[link_name = "nextssl__compact_lwe_public_key_enc_r1__rng_failed"]
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

/// First four bytes of every serialized key: m, n, t_bytes, q_bytes (sk_out_str / pk_out_str). The C
/// parsers sk_in_str / pk_in_str take them from the buffer and use n and m as loop bounds over fixed
/// arrays (s[F][N], element[F][M]) before any check, so a crafted key would overflow those arrays. Only the
/// parameter set this crate is built for (M = 128, N = 9, T_BYTES = 4, Q_BYTES = 8) is accepted.
const KEY_HEADER: [u8; 4] = [128, 9, 4, 8];

fn check_header(what: &'static str, key: &[u8]) -> Result<()> {
    if key.get(..4) != Some(&KEY_HEADER[..]) {
        return Err(Error::InvalidInput(what));
    }
    Ok(())
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
            ct: Some(Len::range(1, PT_MAX + OVER)),
            out: Some(Len::range(0, PT_MAX)),
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
        check_header("pk header is not (m=128, n=9, t=4, q=8)", pk.as_bytes())?;
        if pt.len() > PT_MAX {
            return Err(len_err("plaintext", pt.len(), 0, PT_MAX));
        }
        let mut ct = vec![0u8; pt.len() + OVER];
        let mut clen: core::ffi::c_ulonglong = 0;
        // SAFETY: ct has room for plaintext + CRYPTO_BYTES (the NIST bound on what the callee writes);
        // pt/pk are valid for their lengths (pk length checked above).
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
        if rc != 0 || clen == 0 || clen > ct.len() {
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
        check_header("sk header is not (m=128, n=9, t=4, q=8)", sk.as_bytes())?;
        if ct.is_empty() || ct.len() > PT_MAX + OVER {
            return Err(len_err("ciphertext", ct.len(), 1, PT_MAX + OVER));
        }
        // The plaintext is never longer than the ciphertext in the NIST layout.
        let mut m = Zeroizing::new(vec![0u8; ct.len()]);
        let mut mlen: core::ffi::c_ulonglong = 0;
        // SAFETY: m is valid for ct.len() bytes (the plaintext cannot exceed the ciphertext); ct/sk are valid
        // for their lengths (sk length checked above).
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
        if rc != 0 || mlen > m.len() {
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
            &(0..8192u64)
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
        assert!(p
            .encrypt(&pk, &vec![1u8; PT_MAX + 1], b"", &mut rng)
            .is_err());
        assert!(p.decrypt(&sk, &[0u8; 3], b"").is_err());
        // Keys whose header names another parameter set never reach the C parsers.
        assert_eq!(&pk.as_bytes()[..4], &KEY_HEADER[..]);
        assert_eq!(&sk.as_bytes()[..4], &KEY_HEADER[..]);
        let mut bad_sk = sk.as_bytes().to_vec();
        bad_sk[1] = 200;
        assert!(p
            .decrypt(
                &PrivateKey::from_bytes(&bad_sk, Len::fixed(SK)).unwrap(),
                &ct,
                b""
            )
            .is_err());
        let mut bad_pk = pk.as_bytes().to_vec();
        bad_pk[0] = 255;
        assert!(p
            .encrypt(
                &PublicKey::from_bytes(&bad_pk, Len::fixed(PK)).unwrap(),
                &[1u8; 16],
                b"",
                &mut rng,
            )
            .is_err());
    }

    /// LP64 check: Windows compiles an LLP64-fixed copy of compact-lwe.c (build.rs). Fixed entropy must
    /// give the same keys and ciphertext on every target; the expected value was produced on Linux x86-64.
    #[test]
    fn same_output_on_every_target() {
        let p = new(&Params::new()).unwrap();
        let seed: Vec<u8> = (0..(1u64 << 16))
            .map(|i| (i.wrapping_mul(0x9E37_79B9) >> 7) as u8)
            .collect();
        let mut rng = FixedEntropy::new(&seed);
        let (pk, sk) = p.keygen(&mut rng).unwrap();
        let ct = p.encrypt(&pk, &[0x5Au8; 16], b"", &mut rng).unwrap();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in pk
            .as_bytes()
            .iter()
            .chain(sk.as_bytes().iter())
            .chain(ct.iter())
        {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        eprintln!(
            "FINGERPRINT {h:016x} {} {} {}",
            pk.as_bytes().len(),
            sk.as_bytes().len(),
            ct.len()
        );
        assert_eq!(h, EXPECTED);
    }
    const EXPECTED: u64 = 0x6806_bfc7_ed74_3fc3;
}
