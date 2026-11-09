//! Adapter: RustCrypto `rsa` 0.10.0 -> nextssl `Pke`, RSAES-OAEP with SHA-256 and MGF1-SHA-256 (RFC 8017), 3072-bit modulus, e = 65537.
//! pk = PKCS#1 DER RSAPublicKey, sk = PKCS#1 DER RSAPrivateKey, ct = modulus-length bytes.
//! Label: the OAEP label (raw bytes), at most 64 bytes; anything longer is an error.
//! Bad padding, a wrong label and a wrong key are all the one `Error::AuthenticationFailed`.
//! The crate is built without `getrandom`, so `decrypt` does no blinding with hidden OS entropy; the modular exponentiation is the
//! crate's constant-time crypto-bigint one (RUSTSEC-2023-0071 hardening, still tracked upstream as work in progress).

use nextssl_core::{
    EntropySource, Error, Len, Params, Pke, PrivateKey, PublicKey, Result, Sizes, Zeroizing,
};
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, PrivateKey as RsaPrivateKey, PublicKey as RsaPublicKey};
use sha2::Sha256;

/// Bridges nextssl's `EntropySource` to rand_core 0.10's fallible traits: a failing source surfaces as an error
/// (never as zeros), and `with_rng` reports it as `Error::EntropyFailure`.
#[derive(Debug)]
struct EntropyErr;
impl core::fmt::Display for EntropyErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("entropy source failed")
    }
}
impl core::error::Error for EntropyErr {}

struct Rng<'a> {
    src: &'a mut dyn EntropySource,
    failed: bool,
}
impl Rng<'_> {
    fn fill(&mut self, dst: &mut [u8]) -> core::result::Result<(), EntropyErr> {
        self.src.fill(dst).map_err(|_| {
            self.failed = true;
            EntropyErr
        })
    }
}
impl rand_core::TryRng for Rng<'_> {
    type Error = EntropyErr;
    fn try_next_u32(&mut self) -> core::result::Result<u32, EntropyErr> {
        let mut b = [0u8; 4];
        self.fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, EntropyErr> {
        let mut b = [0u8; 8];
        self.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), EntropyErr> {
        self.fill(dst)
    }
}
impl rand_core::TryCryptoRng for Rng<'_> {}

/// Runs `f` with an upstream-compatible RNG drawing from `src`; a source failure wins over whatever `f` returned.
fn with_rng<T>(src: &mut dyn EntropySource, f: impl FnOnce(&mut Rng<'_>) -> T) -> Result<T> {
    let mut r = Rng { src, failed: false };
    let v = f(&mut r);
    if r.failed {
        Err(Error::EntropyFailure("entropy source failed"))
    } else {
        Ok(v)
    }
}

const BITS: usize = 3072;
const N: usize = BITS / 8;
const PK_MIN: usize = N + 8;
const PK_MAX: usize = N + 32;
const SK_MIN: usize = 3 * N;
const SK_MAX: usize = 5 * N + 64;
const MAX_PT: usize = 318;
const MAX_LABEL: usize = 64;

fn check_key(key: &impl PublicKeyParts) -> Result<()> {
    if key.n().bit_width() as usize != BITS {
        return Err(Error::InvalidInput("RSA modulus is not 3072 bits"));
    }
    if key.e_bytes().as_ref() != [0x01u8, 0x00, 0x01] {
        return Err(Error::InvalidInput("RSA public exponent must be 65537"));
    }
    Ok(())
}

fn pub_key(bytes: &[u8]) -> Result<RsaPublicKey> {
    Len::range(PK_MIN, PK_MAX).check("pk", bytes.len())?;
    let k = RsaPublicKey::from_pkcs1_der(bytes)
        .map_err(|_| Error::InvalidInput("malformed RSA public key"))?;
    check_key(&k)?;
    Ok(k)
}

fn priv_key(bytes: &[u8]) -> Result<RsaPrivateKey> {
    Len::range(SK_MIN, SK_MAX).check("sk", bytes.len())?;
    let k = RsaPrivateKey::from_pkcs1_der(bytes)
        .map_err(|_| Error::InvalidInput("malformed RSA private key"))?;
    check_key(&k)?;
    k.validate()
        .map_err(|_| Error::InvalidInput("inconsistent RSA private key"))?;
    Ok(k)
}

struct Alg;

impl Pke for Alg {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::range(PK_MIN, PK_MAX)),
            sk: Some(Len::range(SK_MIN, SK_MAX)),
            ct: Some(Len::fixed(N)),
            out: Some(Len::range(0, MAX_PT)),
            ctx: Some(Len::range(0, MAX_LABEL)),
            ..Sizes::NONE
        }
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let k = with_rng(rng, |r| RsaPrivateKey::new(r, BITS))?
            .map_err(|_| Error::Backend("RSA key generation failed"))?;
        let sk_der = k
            .to_pkcs1_der()
            .map_err(|_| Error::Backend("RSA private key encoding"))?;
        let pk_der = k
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|_| Error::Backend("RSA public key encoding"))?;
        Ok((
            PublicKey::from_bytes(pk_der.as_bytes(), Len::range(PK_MIN, PK_MAX))?,
            PrivateKey::from_bytes(sk_der.as_bytes(), Len::range(SK_MIN, SK_MAX))?,
        ))
    }

    fn encrypt(
        &self,
        pk: &PublicKey,
        pt: &[u8],
        label: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        nextssl_core::check_len("plaintext", pt.len(), 0, MAX_PT)?;
        nextssl_core::check_len("label", label.len(), 0, MAX_LABEL)?;
        let key = pub_key(pk.as_bytes())?;
        let pad = if label.is_empty() {
            Oaep::<Sha256>::new()
        } else {
            Oaep::<Sha256>::new_with_label(label.to_vec())
        };
        with_rng(rng, |r| key.encrypt(r, pad, pt))?
            .map_err(|_| Error::Backend("RSA encrypt failed"))
    }

    fn decrypt(&self, sk: &PrivateKey, ct: &[u8], label: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        nextssl_core::check_len("ciphertext", ct.len(), N, N)?;
        nextssl_core::check_len("label", label.len(), 0, MAX_LABEL)?;
        let key = priv_key(sk.as_bytes())?;
        let pad = if label.is_empty() {
            Oaep::<Sha256>::new()
        } else {
            Oaep::<Sha256>::new_with_label(label.to_vec())
        };
        key.decrypt(pad, ct)
            .map(Zeroizing::new)
            .map_err(|_| Error::AuthenticationFailed)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Pke>> {
    Ok(Box::new(Alg))
}
