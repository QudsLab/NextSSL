//! Adapter: RustCrypto `sm2` 0.14.0 (GB/T 32918.2, SM2 digital signature, SM3 hash) -> nextssl `Sign`.
//! sk = 32-byte big-endian scalar, pk = SEC1 uncompressed point (65 bytes), sig = fixed-width r || s (64 bytes). The distinguishing id is
//! the standard default "1234567812345678"; ctx must be empty. seed = the scalar bytes (same as sk).
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign,
    Signature as NxSignature, Sizes,
};
use sm2::dsa::{
    signature::{
        rand_core::{TryCryptoRng, TryRng},
        RandomizedSigner, Verifier,
    },
    Signature as UpSig, SigningKey, VerifyingKey,
};

const PK: usize = 65;
const SK: usize = 32;
const SIG: usize = 64;
const DISTID: &str = "1234567812345678";
const KEYGEN_TRIES: usize = 64;

struct Rng<'a> {
    src: &'a mut dyn EntropySource,
    err: Option<Error>,
}
#[derive(Debug)]
struct RngFailed;
impl core::fmt::Display for RngFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("entropy source failed")
    }
}
impl core::error::Error for RngFailed {}
impl TryRng for Rng<'_> {
    type Error = RngFailed;
    fn try_next_u32(&mut self) -> core::result::Result<u32, RngFailed> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, RngFailed> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), RngFailed> {
        self.src.fill(dst).map_err(|e| {
            self.err = Some(e);
            RngFailed
        })
    }
}
impl TryCryptoRng for Rng<'_> {}

struct Alg;

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn signing_key(bytes: &[u8], what: &'static str) -> Result<SigningKey> {
    check(what, bytes.len(), SK)?;
    SigningKey::from_slice(DISTID, bytes)
        .map_err(|_| Error::InvalidInput("SM2 scalar out of range"))
}

fn pack(key: &SigningKey) -> Result<(PublicKey, PrivateKey)> {
    let point = key.verifying_key().to_sec1_bytes();
    let sk = key.to_bytes();
    Ok((
        PublicKey::from_bytes(&point, Len::fixed(PK))?,
        PrivateKey::from_bytes(sk.as_slice(), Len::fixed(SK))?,
    ))
}

impl Sign for Alg {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            sig: Some(Len::fixed(SIG)),
            seed: Some(Len::fixed(SK)),
            ctx: Some(Len::fixed(0)),
            ..Sizes::NONE
        }
    }

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        pack(&signing_key(seed.as_bytes(), "seed")?)
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let mut buf = nextssl_core::Zeroizing::new([0u8; SK]);
        for _ in 0..KEYGEN_TRIES {
            rng.fill(&mut buf[..])?;
            if let Ok(key) = SigningKey::from_slice(DISTID, &buf[..]) {
                return pack(&key);
            }
        }
        Err(Error::Backend("sm2 keygen: no valid scalar after 64 draws"))
    }

    fn sign(
        &self,
        sk: &PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<NxSignature> {
        check("ctx", ctx.len(), 0)?;
        let key = signing_key(sk.as_bytes(), "sk")?;
        let mut r = Rng {
            src: rng,
            err: None,
        };
        let sig: UpSig = match key.try_sign_with_rng(&mut r, msg) {
            Ok(s) => s,
            Err(_) => return Err(r.err.take().unwrap_or(Error::Backend("sm2 sign failed"))),
        };
        NxSignature::from_bytes(sig.to_bytes().as_slice(), Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        check("ctx", ctx.len(), 0)?;
        check("pk", pk.len(), PK)?;
        check("sig", sig.len(), SIG)?;
        if pk.as_bytes()[0] != 0x04 {
            return Err(Error::InvalidInput(
                "SM2 public key must be an uncompressed point",
            ));
        }
        let vk = VerifyingKey::from_sec1_bytes(DISTID, pk.as_bytes())
            .map_err(|_| Error::InvalidInput("SM2 public key is not a valid point"))?;
        let s = UpSig::from_slice(sig.as_bytes())
            .map_err(|_| Error::InvalidInput("SM2 signature r or s out of range"))?;
        Ok(vk.verify(msg, &s).is_ok())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(Alg))
}
