//! Adapter: `hbs-lms` 0.2.0-alpha.1 (Fraunhofer AISEC, RFC 8554 LMS/HSS, SHA-256/M32) -> nextssl `StatefulSign`, LMS_SHA256_M32_H10 with LMOTS_SHA256_N32_W4, single level, 1024 signatures.
//! pk = HSS public key, sk = the crate's serialized private key (a used-signatures counter, the parameter set and the 32-byte
//! seed), sig = HSS signature. `sign` hands the advanced key to `persist` before any signature leaves this function; the crate
//! calls the update function first and only then returns the signature, and a persist error here discards the signature.
//! Keygen is deterministic from a 32-byte seed. An exhausted key is `Error::KeyExhausted` and `persist` is not called. The crate marks
//! a used-up key by overwriting its parameter bytes (its counter wraps to zero), so `remaining` reads the crate's lifetime, not the counter.

use hbs_lms::{
    keygen, sign, verify, HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256, SigningKey,
    VerifyingKey,
};
use nextssl_core::{
    Error, Len, Params, PublicKey, Result, Seed as NSeed, Signature, Sizes, StatefulKey,
    StatefulSign, Zeroizing,
};

type H = Sha256_256;

const SEED: usize = 32;
const PK: usize = 60;
const SK: Len = Len::range(32, 512);
const SIG: Len = Len::range(256, 65536);
/// Total one-time keys: the product of the tree sizes of all levels.
const MAX: u64 = 1024;
/// Offset and length of the parameter-set bytes in the serialized key (after the 8-byte used-keys counter). The crate marks a
/// fully used key by overwriting them with 0xFF and then `get_lifetime` is an error.
const PARAMS_OFF: usize = 8;
const PARAMS_LEN: usize = 8;

fn parameters() -> Vec<HssParameter<H>> {
    vec![HssParameter::new(
        LmotsAlgorithm::LmotsW4,
        LmsAlgorithm::LmsH10,
    )]
}

/// One-time keys still available: the crate's own lifetime, 0 for a key it has marked exhausted.
fn left(key: &StatefulKey) -> Result<u64> {
    SK.check("sk", key.len())?;
    let sk = SigningKey::<H>::from_bytes(key.as_bytes())
        .map_err(|_| Error::InvalidInput("malformed LMS key state"))?;
    match sk.get_lifetime() {
        Ok(n) => Ok(n),
        Err(_)
            if key.as_bytes()[PARAMS_OFF..PARAMS_OFF + PARAMS_LEN]
                .iter()
                .all(|b| *b == 0xFF) =>
        {
            Ok(0)
        }
        Err(_) => Err(Error::InvalidInput("malformed LMS key state")),
    }
}

struct Alg;

impl StatefulSign for Alg {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(PK)),
            sk: Some(SK),
            sig: Some(SIG),
            seed: Some(Len::fixed(SEED)),
            ..Sizes::NONE
        }
    }

    fn max_signatures(&self) -> u64 {
        MAX
    }

    fn remaining(&self, key: &StatefulKey) -> Result<u64> {
        left(key)
    }

    fn keygen_from_seed(&self, seed: &NSeed) -> Result<(PublicKey, StatefulKey)> {
        Len::fixed(SEED).check("seed", seed.len())?;
        let mut s = Seed::<H>::default();
        s.as_mut_slice().copy_from_slice(seed.as_bytes());
        let (sk, vk) = keygen::<H>(&parameters(), &s, None)
            .map_err(|_| Error::Backend("LMS keygen failed"))?;
        Ok((
            PublicKey::from_bytes(vk.as_slice(), Len::fixed(PK))?,
            StatefulKey::from_bytes(sk.as_slice(), SK)?,
        ))
    }

    fn sign(
        &self,
        key: &mut StatefulKey,
        msg: &[u8],
        persist: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Signature> {
        if self.remaining(key)? == 0 {
            return Err(Error::KeyExhausted);
        }
        let mut new_state: Option<Zeroizing<Vec<u8>>> = None;
        let mut persist_err: Option<Error> = None;
        let sig = {
            let mut update = |nk: &[u8]| -> core::result::Result<(), ()> {
                match persist(nk) {
                    Ok(()) => {
                        new_state = Some(Zeroizing::new(nk.to_vec()));
                        Ok(())
                    }
                    Err(e) => {
                        persist_err = Some(e);
                        Err(())
                    }
                }
            };
            sign::<H>(msg, key.as_bytes(), &mut update, None)
        };
        if let Some(e) = persist_err {
            return Err(e);
        }
        let sig = sig.map_err(|_| Error::Backend("LMS sign failed"))?;
        let ns = new_state.ok_or(Error::PersistFailed)?;
        *key = StatefulKey::from_bytes(&ns, SK)?;
        Signature::from_bytes(sig.as_ref(), SIG)
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<bool> {
        Len::fixed(PK).check("pk", pk.len())?;
        SIG.check("sig", sig.len())?;
        VerifyingKey::<H>::from_bytes(pk.as_bytes())
            .map_err(|_| Error::InvalidInput("malformed LMS public key"))?;
        Ok(verify::<H>(msg, sig.as_bytes(), pk.as_bytes()).is_ok())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn StatefulSign>> {
    Ok(Box::new(Alg))
}
