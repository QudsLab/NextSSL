//! Adapter: `spake2` 0.4.0 (Ed25519 group, the python-spake2 compatible variant, not RFC 9382) -> nextssl `Pake`.
//! Initiator = side A, responder = side B. Both sides send their 33-byte message from `start` (the first message is never
//! empty) and finish after one `step`. The identities are `A:` + context and `B:` + context. The 32-byte key is not
//! key-confirmed: a wrong password gives different keys, not an error. SPAKE2 has no confirmation step in this crate.

use nextssl_core::{EntropySource, Error, Len, Pake, PakeRole, PakeState, PakeStep, Params, Result, SharedSecret, Sizes, Zeroizing};
use rand_core::{CryptoRng, RngCore};
use spake2::{Ed25519Group, Identity, Password, Spake2};

/// Bridges nextssl's `EntropySource` to rand_core 0.6. The upstream traits are infallible, so a failing
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
impl RngCore for Rng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.fill(dst);
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill(dst);
        Ok(())
    }
}
impl CryptoRng for Rng<'_> {}

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

const MSG: usize = 33;
const SS: usize = 32;
const PW_MAX: usize = 256;
const CTX_MAX: usize = 128;

struct St(Spake2<Ed25519Group>);

impl PakeState for St {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        Len::fixed(MSG).check("message", msg.len())?;
        let key = Zeroizing::new(self.0.finish(msg).map_err(|_| Error::ProtocolAborted("spake2 message rejected"))?);
        Ok(PakeStep::Done(SharedSecret::from_bytes(&key, Len::fixed(SS))?, None))
    }
}

struct Alg;

impl Pake for Alg {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(1, PW_MAX)),
            ss: Some(Len::fixed(SS)),
            ..Sizes::NONE
        }
    }

    fn start(&self, role: PakeRole, password: &[u8], context: &[u8], rng: &mut dyn EntropySource) -> Result<(Box<dyn PakeState>, Vec<u8>)> {
        nextssl_core::check_len("password", password.len(), 1, PW_MAX)?;
        nextssl_core::check_len("context", context.len(), 0, CTX_MAX)?;
        let pw = Password::new(password);
        let id_a = Identity::new(&[b"A:", context].concat());
        let id_b = Identity::new(&[b"B:", context].concat());
        let (state, msg) = with_rng(rng, |r| match role {
            PakeRole::Initiator => Spake2::<Ed25519Group>::start_a_with_rng(&pw, &id_a, &id_b, r),
            PakeRole::Responder => Spake2::<Ed25519Group>::start_b_with_rng(&pw, &id_a, &id_b, r),
        })?;
        Ok((Box::new(St(state)), msg))
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Pake>> {
    Ok(Box::new(Alg))
}
