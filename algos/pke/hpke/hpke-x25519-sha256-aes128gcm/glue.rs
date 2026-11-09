//! Adapter: `hpke` 0.15.1 -> nextssl `Pke`, RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (suite 0x0020/0x0001/0x0001).
//! pk and sk are the KEM's serialized public and private keys; ct = encapsulated key || AEAD ciphertext+tag.
//! The label is the HPKE `info` string (at most 1024 bytes); the AAD is empty. Every decryption failure is the one
//! `Error::AuthenticationFailed`.

use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use nextssl_core::{EntropySource, Error, Len, Params, Pke, PrivateKey, PublicKey, Result, Sizes, Zeroizing};

type A = hpke::aead::AesGcm128;
type K = hpke::kdf::HkdfSha256;
type M = hpke::kem::X25519HkdfSha256;

/// Bridges nextssl's `EntropySource` to rand_core 0.10. The upstream traits are infallible, so a failing
/// source aborts the operation with a panic that `with_rng` turns into `Error::EntropyFailure`; zeros are never used.
struct Rng<'a> {
    src: &'a mut dyn EntropySource,
    failed: bool,
}
impl Rng<'_> {
    fn fill(&mut self, dst: &mut [u8]) {
        if self.src.fill(dst).is_err() {
            self.failed = true;
            panic!("entropy source failed");
        }
    }
}
impl rand_core::TryRng for Rng<'_> {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.fill(dst);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for Rng<'_> {}

/// Runs `f` with an upstream-compatible RNG drawing from `src`.
fn with_rng<T>(src: &mut dyn EntropySource, f: impl FnOnce(&mut Rng<'_>) -> T) -> Result<T> {
    let mut r = Rng { src, failed: false };
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut r)));
    match out {
        Ok(v) if !r.failed => Ok(v),
        _ if r.failed => Err(Error::EntropyFailure("entropy source failed")),
        _ => Err(Error::Backend("panic inside the upstream crate")),
    }
}

const PK: usize = 32;
const SK: usize = 32;
const ENC: usize = 32;
const TAG: usize = 16;
const MAX_PT: usize = 65536;
const MAX_INFO: usize = 1024;

struct Alg;

impl Pke for Alg {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            ct: Some(Len::range(ENC + TAG, ENC + TAG + MAX_PT)),
            out: Some(Len::range(0, MAX_PT)),
            ctx: Some(Len::range(0, MAX_INFO)),
            ..Sizes::NONE
        }
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let (sk, pk) = with_rng(rng, |r| M::gen_keypair_with_rng(r))?;
        let sk_b = Zeroizing::new(sk.to_bytes());
        Ok((
            PublicKey::from_bytes(&pk.to_bytes()[..], Len::fixed(PK))?,
            PrivateKey::from_bytes(&sk_b[..], Len::fixed(SK))?,
        ))
    }

    fn encrypt(&self, pk: &PublicKey, pt: &[u8], label: &[u8], rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        Len::fixed(PK).check("pk", pk.len())?;
        nextssl_core::check_len("plaintext", pt.len(), 0, MAX_PT)?;
        nextssl_core::check_len("label", label.len(), 0, MAX_INFO)?;
        let pk = <M as hpke::Kem>::PublicKey::from_bytes(pk.as_bytes()).map_err(|_| Error::InvalidInput("malformed HPKE public key"))?;
        let (enc, body) = with_rng(rng, |r| {
            hpke::single_shot_seal_with_rng::<A, K, M>(&OpModeS::Base, &pk, label, pt, &[], r)
        })?
        .map_err(|_| Error::Backend("HPKE seal failed"))?;
        let mut out = enc.to_bytes()[..].to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn decrypt(&self, sk: &PrivateKey, ct: &[u8], label: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Len::fixed(SK).check("sk", sk.len())?;
        nextssl_core::check_len("ciphertext", ct.len(), ENC + TAG, ENC + TAG + MAX_PT)?;
        nextssl_core::check_len("label", label.len(), 0, MAX_INFO)?;
        let sk = <M as hpke::Kem>::PrivateKey::from_bytes(sk.as_bytes()).map_err(|_| Error::InvalidInput("malformed HPKE private key"))?;
        let (enc_b, body) = ct.split_at(ENC);
        let enc = <M as hpke::Kem>::EncappedKey::from_bytes(enc_b).map_err(|_| Error::AuthenticationFailed)?;
        hpke::single_shot_open::<A, K, M>(&OpModeR::Base, &sk, &enc, label, body, &[])
            .map(Zeroizing::new)
            .map_err(|_| Error::AuthenticationFailed)
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Pke>> {
    Ok(Box::new(Alg))
}
