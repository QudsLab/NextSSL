//! Adapter: Thomas Pornin `crrl` (Ed448 module, RFC 8032 Ed448ph, vendored) -> nextssl `Sign`.
//!
//! sk = the 57-byte RFC 8032 secret seed, pk = 57 bytes, sig = R || S (114 bytes). `ctx` is the RFC 8032 context
//! string (0..=255 bytes; longer is an error). The message is pre-hashed with SHAKE256 (64-byte output) as RFC 8032
//! 5.2 requires; the upstream asks the caller for that step and its own SHAKE256 is used. Signing is deterministic
//! and does not read `rng`. Note: the upstream `PrivateKey` is `Copy` and does not zeroize itself on drop.

use crrl::ed448::{PrivateKey, PublicKey};
use crrl::sha3::SHAKE256;
use nextssl_core::{
    EntropySource, Error, Len, Params, PrivateKey as NxPrivateKey, PublicKey as NxPublicKey,
    Result, Seed, Sign, Signature as NxSignature, Sizes,
};

const PK: usize = 57;
const SK: usize = 57;
const SIG: usize = 114;
const SEED: usize = 57;
const CTX_MAX: usize = 255;

struct Ed448Ph;

fn check(what: &'static str, got: usize, want: usize) -> Result<()> {
    nextssl_core::check_len(what, got, want, want)
}

fn check_ctx(ctx: &[u8]) -> Result<()> {
    nextssl_core::check_len("ctx", ctx.len(), 0, CTX_MAX)
}

/// PH(M) = SHAKE256(M, 64) per RFC 8032 section 5.2.
fn prehash(msg: &[u8]) -> [u8; 64] {
    let mut sh = SHAKE256::new();
    sh.inject(msg);
    let mut out = [0u8; 64];
    sh.flip_extract_reset(&mut out);
    out
}

impl Sign for Ed448Ph {
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

    fn keygen_from_seed(&self, seed: &Seed) -> Result<(NxPublicKey, NxPrivateKey)> {
        check("seed", seed.as_bytes().len(), SEED)?;
        let key = PrivateKey::from_seed(seed.as_bytes());
        Ok((
            NxPublicKey::from_bytes(&key.public_key.encode(), Len::fixed(PK))?,
            NxPrivateKey::from_bytes(seed.as_bytes(), Len::fixed(SK))?,
        ))
    }

    fn sign(
        &self,
        sk: &NxPrivateKey,
        msg: &[u8],
        ctx: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<NxSignature> {
        check_ctx(ctx)?;
        check("sk", sk.as_bytes().len(), SK)?;
        let key =
            PrivateKey::decode(sk.as_bytes()).ok_or(Error::InvalidInput("ed448ph secret key"))?;
        let sig = key.sign_ph(ctx, &prehash(msg));
        NxSignature::from_bytes(&sig, Len::fixed(SIG))
    }

    fn verify(&self, pk: &NxPublicKey, msg: &[u8], ctx: &[u8], sig: &NxSignature) -> Result<bool> {
        check_ctx(ctx)?;
        check("pk", pk.as_bytes().len(), PK)?;
        check("sig", sig.as_bytes().len(), SIG)?;
        let key = PublicKey::decode(pk.as_bytes()).ok_or(Error::InvalidInput(
            "ed448ph public key is not a valid point",
        ))?;
        Ok(key.verify_ph(sig.as_bytes(), ctx, &prehash(msg)))
    }
}

/// Registry constructor. Ed448ph takes no parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Sign>> {
    Ok(Box::new(Ed448Ph))
}
