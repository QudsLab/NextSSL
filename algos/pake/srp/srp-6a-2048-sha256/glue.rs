//! Adapter: `srp` 0.6.0 (SRP-6a, RFC 5054 2048-bit group, SHA-256) -> nextssl `Pake`.
//! Initiator = client, responder = server; `context` is the user name. The responder derives its salt and verifier from the
//! password at `start` (a real server would store them; the trait has no registration step). Messages:
//! 1 client A; 2 server `salt_len(1) || salt || B`; 3 client M1; 4 server M2. Both sides get the crate's premaster-derived key
//! (variable length, at most 256 bytes). Proofs are checked in constant time by the crate; a failure ends the exchange.

use nextssl_core::{
    EntropySource, Error, Len, Pake, PakeRole, PakeState, PakeStep, Params, Result, SharedSecret,
    Sizes, Zeroizing,
};
use sha2::Sha256;
use srp::client::{SrpClient, SrpClientVerifier};
use srp::groups::G_2048;
use srp::server::{SrpServer, SrpServerVerifier};

const PW_MAX: usize = 256;
const CTX_MAX: usize = 128;
const SALT: usize = 16;
const KEY_MAX: usize = 256;
const PUB_MAX: usize = 256;

fn draw(rng: &mut dyn EntropySource, n: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut v = Zeroizing::new(vec![0u8; n]);
    rng.fill(&mut v)?;
    Ok(v)
}

fn abort<T, E>(m: &'static str) -> impl FnOnce(E) -> Result<T> {
    move |_| Err(Error::ProtocolAborted(m))
}

struct ClientWaitB {
    a: Zeroizing<Vec<u8>>,
    user: Vec<u8>,
    pw: Zeroizing<Vec<u8>>,
}
struct ClientWaitM2 {
    ver: SrpClientVerifier<Sha256>,
}
struct ServerWaitA {
    b: Zeroizing<Vec<u8>>,
    v: Zeroizing<Vec<u8>>,
    salt: Vec<u8>,
}
struct ServerWaitM1 {
    ver: SrpServerVerifier<Sha256>,
}

impl PakeState for ClientWaitB {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        nextssl_core::check_len("message", msg.len(), 1 + SALT + 1, 1 + SALT + PUB_MAX)?;
        let salt_len = msg[0] as usize;
        if salt_len != SALT || msg.len() < 1 + salt_len + 1 {
            return Err(Error::ProtocolAborted("srp: bad salt length"));
        }
        let (salt, b_pub) = msg[1..].split_at(salt_len);
        let client = SrpClient::<Sha256>::new(&G_2048);
        let ver = client
            .process_reply(&self.a, &self.user, &self.pw, salt, b_pub)
            .or_else(abort("srp: server value rejected"))?;
        let m1 = ver.proof().to_vec();
        Ok(PakeStep::Send(Box::new(ClientWaitM2 { ver }), m1))
    }
}

impl PakeState for ClientWaitM2 {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        self.ver
            .verify_server(msg)
            .or_else(abort("srp: server proof rejected"))?;
        let ss = SharedSecret::from_bytes(self.ver.key(), Len::range(1, KEY_MAX))?;
        Ok(PakeStep::Done(ss, None))
    }
}

impl PakeState for ServerWaitA {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        nextssl_core::check_len("message", msg.len(), 1, PUB_MAX)?;
        let server = SrpServer::<Sha256>::new(&G_2048);
        let ver = server
            .process_reply(&self.b, &self.v, msg)
            .or_else(abort("srp: client value rejected"))?;
        let b_pub = server.compute_public_ephemeral(&self.b, &self.v);
        let mut reply = vec![self.salt.len() as u8];
        reply.extend_from_slice(&self.salt);
        reply.extend_from_slice(&b_pub);
        Ok(PakeStep::Send(Box::new(ServerWaitM1 { ver }), reply))
    }
}

impl PakeState for ServerWaitM1 {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        self.ver
            .verify_client(msg)
            .or_else(abort("srp: client proof rejected"))?;
        let ss = SharedSecret::from_bytes(self.ver.key(), Len::range(1, KEY_MAX))?;
        Ok(PakeStep::Done(ss, Some(self.ver.proof().to_vec())))
    }
}

struct Alg;

impl Pake for Alg {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: Some(Len::range(1, PW_MAX)),
            ss: Some(Len::range(1, KEY_MAX)),
            ..Sizes::NONE
        }
    }

    fn start(
        &self,
        role: PakeRole,
        password: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Box<dyn PakeState>, Vec<u8>)> {
        nextssl_core::check_len("password", password.len(), 1, PW_MAX)?;
        nextssl_core::check_len("context", context.len(), 1, CTX_MAX)?;
        let a_or_b = draw(rng, 32)?;
        match role {
            PakeRole::Initiator => {
                let a_pub = SrpClient::<Sha256>::new(&G_2048).compute_public_ephemeral(&a_or_b);
                let st = ClientWaitB {
                    a: a_or_b,
                    user: context.to_vec(),
                    pw: Zeroizing::new(password.to_vec()),
                };
                Ok((Box::new(st), a_pub))
            }
            PakeRole::Responder => {
                let salt = draw(rng, SALT)?;
                let v = Zeroizing::new(
                    SrpClient::<Sha256>::new(&G_2048).compute_verifier(context, password, &salt),
                );
                let st = ServerWaitA {
                    b: a_or_b,
                    v,
                    salt: salt.to_vec(),
                };
                Ok((Box::new(st), Vec::new()))
            }
        }
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Pake>> {
    Ok(Box::new(Alg))
}
