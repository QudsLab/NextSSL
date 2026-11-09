//! Adapter: lattice-safe `falcon-rs` (FN-DSA-1024, draft FIPS 206, vendored) -> nextssl `Sign`.
//!
//! Key pair from a 48-byte seed (`generate_deterministic`). sk = upstream private key (2305 bytes), pk = 1793 bytes,
//! sig = constant-time format (1577 bytes, header 0x50|logn). `ctx` is the FIPS 206 context string (0..=255 bytes).
//! Signing draws its 48-byte randomness from the caller's `EntropySource` and uses `sign_deterministic`, so no hidden
//! OS entropy is read. The pre-hash (HashFN-DSA) mode is not offered. Other signature encodings are refused.

use falcon::safe_api::{DomainSeparation, FalconError, FnDsaKeyPair, FnDsaSignature};
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey, PublicKey, Result, Seed, Sign, Signature as NxSignature, Sizes,
    Zeroizing,
};

const LOGN: u32 = 10;
const PK: usize = 1793;
const SK: usize = 2305;
const SIG: usize = 1577;
const SEED: usize = 48;
const CTX_MAX: usize = 255;

struct FnDsa;

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn check_ctx(ctx: &[u8]) -> Result<()> {
    nextssl_core::check_len("ctx", ctx.len(), 0, CTX_MAX)
}

fn domain(ctx: &[u8]) -> DomainSeparation<'_> {
    if ctx.is_empty() {
        DomainSeparation::None
    } else {
        DomainSeparation::Context(ctx)
    }
}

impl Sign for FnDsa {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(Len::fixed(SK)),
            sig: Some(Len::fixed(SIG)),
            seed: Some(Len::fixed(SEED)),
            ctx: Some(Len::range(0, CTX_MAX)),
            ..Sizes::NONE
        }
    }

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        check("seed", seed.as_bytes().len(), SEED)?;
        let kp = FnDsaKeyPair::generate_deterministic(seed.as_bytes(), LOGN)
            .map_err(|_| Error::Backend("fn-dsa key generation failed"))?;
        check("generated pk", kp.public_key().len(), PK)?;
        check("generated sk", kp.private_key().len(), SK)?;
        Ok((
            PublicKey::from_bytes(kp.public_key(), Len::fixed(PK))?,
            PrivateKey::from_bytes(kp.private_key(), Len::fixed(SK))?,
        ))
    }

    fn sign(&self, sk: &PrivateKey, msg: &[u8], ctx: &[u8], rng: &mut dyn EntropySource) -> Result<NxSignature> {
        check_ctx(ctx)?;
        check("sk", sk.as_bytes().len(), SK)?;
        if sk.as_bytes()[0] != (0x50 | LOGN as u8) {
            return Err(Error::InvalidInput("fn-dsa secret key header does not match this parameter set"));
        }
        let kp = FnDsaKeyPair::from_private_key(sk.as_bytes()).map_err(|_| Error::InvalidInput("fn-dsa secret key"))?;
        if kp.logn() != LOGN {
            return Err(Error::InvalidInput("fn-dsa secret key is for another parameter set"));
        }
        let mut seed = Zeroizing::new([0u8; SEED]);
        rng.fill(&mut seed[..]).map_err(|_| Error::EntropyFailure("entropy source failed"))?;
        let sig = kp
            .sign_deterministic(msg, &seed[..], &domain(ctx))
            .map_err(|e| match e {
                FalconError::FaultDetected => Error::Backend("fn-dsa: self-check of the signature failed"),
                _ => Error::Backend("fn-dsa signing failed"),
            })?;
        NxSignature::from_bytes(sig.to_bytes(), Len::fixed(SIG))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        check_ctx(ctx)?;
        check("pk", pk.as_bytes().len(), PK)?;
        check("sig", sig.as_bytes().len(), SIG)?;
        if pk.as_bytes()[0] != LOGN as u8 {
            return Err(Error::InvalidInput("fn-dsa public key header does not match this parameter set"));
        }
        if sig.as_bytes()[0] != (0x50 | LOGN as u8) {
            return Err(Error::InvalidInput("fn-dsa signature is not the constant-time encoding of this parameter set"));
        }
        FnDsaSignature::from_bytes(sig.as_bytes().to_vec()).map_err(|_| Error::InvalidInput("fn-dsa signature encoding"))?;
        match FnDsaSignature::verify(sig.as_bytes(), pk.as_bytes(), msg, &domain(ctx)) {
            Ok(()) => Ok(true),
            Err(FalconError::BadSignature) => Ok(false),
            Err(_) => Err(Error::InvalidInput("fn-dsa verify input")),
        }
    }
}

/// Registry constructor. FN-DSA takes no parameters here.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(FnDsa))
}
