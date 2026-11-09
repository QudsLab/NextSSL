//! Adapter: `opaque-ke` 4.0.1 (RFC 9807 OPAQUE-3DH, ristretto255 + SHA-512, Argon2 default parameters) -> nextssl `Pake`.
//! Initiator = client, responder = server; `context` is the user name. Both roles are given the password: the responder
//! registers it locally at `start` (a stored password record, as a real server would hold), then the exchange is the login flow:
//! 1 client KE1; 2 server KE2; 3 client KE3. Both sides end with the 64-byte session key; a wrong client password makes the
//! client's `step` fail (envelope recovery) and the exchange ends. The responder creates a fresh server setup in `start`.
//! Later steps need randomness but `step` has no rng, so `start` draws a 32-byte seed from the caller's entropy source and each
//! state owns a ChaCha20 stream seeded with it (rand_chacha, not our code).

use nextssl_core::{EntropySource, Error, Len, Pake, PakeRole, PakeState, PakeStep, Params, Result, SharedSecret, Sizes, Zeroizing};
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization,
    CredentialRequest, CredentialResponse, Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    TripleDh,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

struct Cs;
impl CipherSuite for Cs {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

const PW_MAX: usize = 256;
const CTX_MAX: usize = 128;
const SS: usize = 64;
const MSG_MAX: usize = 4096;

fn rej<E>(m: &'static str) -> impl FnOnce(E) -> Error {
    move |_| Error::ProtocolAborted(m)
}

struct CLogin {
    rng: ChaCha20Rng,
    pw: Zeroizing<Vec<u8>>,
    st: ClientLogin<Cs>,
}
struct SLogin {
    rng: ChaCha20Rng,
    setup: ServerSetup<Cs>,
    user: Vec<u8>,
    file: ServerRegistration<Cs>,
}
struct SFinish {
    st: ServerLogin<Cs>,
}

impl PakeState for CLogin {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        nextssl_core::check_len("message", msg.len(), 1, MSG_MAX)?;
        let CLogin { mut rng, pw, st } = *self;
        let resp = CredentialResponse::<Cs>::deserialize(msg).map_err(rej("opaque: bad credential response"))?;
        let fin = st
            .finish(&mut rng, &pw, resp, ClientLoginFinishParameters::default())
            .map_err(rej("opaque: login failed (wrong password or server)"))?;
        let ke3 = fin.message.serialize().to_vec();
        let ss = SharedSecret::from_bytes(&fin.session_key, Len::fixed(SS))?;
        Ok(PakeStep::Done(ss, Some(ke3)))
    }
}

impl PakeState for SLogin {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        nextssl_core::check_len("message", msg.len(), 1, MSG_MAX)?;
        let SLogin { mut rng, setup, user, file } = *self;
        let req = CredentialRequest::<Cs>::deserialize(msg).map_err(rej("opaque: bad KE1"))?;
        let login = ServerLogin::start(&mut rng, &setup, Some(file), req, &user, ServerLoginParameters::default())
            .map_err(rej("opaque: server login start failed"))?;
        let out = login.message.serialize().to_vec();
        Ok(PakeStep::Send(Box::new(SFinish { st: login.state }), out))
    }
}

impl PakeState for SFinish {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        nextssl_core::check_len("message", msg.len(), 1, MSG_MAX)?;
        let ke3 = CredentialFinalization::<Cs>::deserialize(msg).map_err(rej("opaque: bad KE3"))?;
        let fin = self.st.finish(ke3, ServerLoginParameters::default()).map_err(rej("opaque: client proof rejected"))?;
        Ok(PakeStep::Done(SharedSecret::from_bytes(&fin.session_key, Len::fixed(SS))?, None))
    }
}

/// Registers `pw` for `user` against `setup` and returns the stored record (client and server halves both run here).
fn register(rng: &mut ChaCha20Rng, setup: &ServerSetup<Cs>, user: &[u8], pw: &[u8]) -> Result<ServerRegistration<Cs>> {
    let c = ClientRegistration::<Cs>::start(rng, pw).map_err(rej("opaque: registration start failed"))?;
    let s = ServerRegistration::<Cs>::start(setup, c.message, user).map_err(rej("opaque: registration response failed"))?;
    let f = c
        .state
        .finish(rng, pw, s.message, ClientRegistrationFinishParameters::default())
        .map_err(rej("opaque: registration finish failed"))?;
    Ok(ServerRegistration::<Cs>::finish(f.message))
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
        nextssl_core::check_len("context", context.len(), 1, CTX_MAX)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(&mut seed[..])?;
        let mut stream = ChaCha20Rng::from_seed(*seed);
        match role {
            PakeRole::Initiator => {
                let pw = Zeroizing::new(password.to_vec());
                let start = ClientLogin::<Cs>::start(&mut stream, &pw).map_err(rej("opaque: login start failed"))?;
                let msg = start.message.serialize().to_vec();
                Ok((Box::new(CLogin { rng: stream, pw, st: start.state }), msg))
            }
            PakeRole::Responder => {
                let setup = ServerSetup::<Cs>::new(&mut stream);
                let file = register(&mut stream, &setup, context, password)?;
                Ok((Box::new(SLogin { rng: stream, setup, user: context.to_vec(), file }), Vec::new()))
            }
        }
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Pake>> {
    Ok(Box::new(Alg))
}
