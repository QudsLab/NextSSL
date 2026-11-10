//! Adapter: RFC 9497 OPRF (base mode), ciphersuite ristretto255-SHA512 (`voprf` 0.5.0, Meta, `danger` feature
//! only for the byte accessors of the blinded and evaluated elements) -> nextssl `Oprf`.
//!
//! Elements and the private key use the RFC 9497 encodings (32 bytes). The client state is the 32-byte blinding
//! scalar (secret, zeroized). The VOPRF and POPRF modes are NOT wired: the crate exposes no byte encoding of
//! its `Proof` without serde, see docs/UPSTREAM_ISSUES.md. `info` must be empty here; `proof` is empty.

use nextssl_core::{
    EntropySource, Error, Len, Oprf, Params, PrivateKey, PublicKey, Result, Sizes, Zeroize, Zeroizing,
};
use rand_core::{CryptoRng, RngCore};
use voprf::{BlindedElement, EvaluationElement, Group, OprfClient, OprfServer, Ristretto255};

const ELEM: usize = 32;
const SCALAR: usize = 32;
const OUT: usize = 64;

/// Adapter from the entropy source to the `rand_core` 0.6 traits. A failing source zero-fills and sets
/// `failed`; the caller checks the flag and discards the result.
struct Rng<'a> {
    src: &'a mut dyn EntropySource,
    failed: bool,
}

impl RngCore for Rng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.src.fill(dest).is_err() {
            self.failed = true;
            dest.fill(0);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for Rng<'_> {}

fn bad(_: voprf::Error) -> Error {
    Error::InvalidInput("oprf: malformed element, key or input")
}

fn input_ok(input: &[u8]) -> Result<()> {
    Len::range(1, 65535).check("input", input.len())
}

fn scalar_bytes(s: <Ristretto255 as Group>::Scalar) -> Zeroizing<Vec<u8>> {
    let mut a = Ristretto255::serialize_scalar(s);
    let v = Zeroizing::new(a.to_vec());
    a.as_mut_slice().zeroize();
    v
}

struct Impl;

impl Oprf for Impl {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: Some(Len::fixed(ELEM)),
            sk: Some(Len::fixed(SCALAR)),
            ..Sizes::NONE
        }
    }

    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let mut r = Rng { src: rng, failed: false };
        let sk = Ristretto255::random_scalar(&mut r);
        if r.failed {
            return Err(Error::EntropyFailure("oprf keygen"));
        }
        let pk = Ristretto255::base_elem() * &sk;
        let skb = scalar_bytes(sk);
        let pkb = Ristretto255::serialize_elem(pk);
        Ok((
            PublicKey::from_bytes(pkb.as_slice(), Len::fixed(ELEM))?,
            PrivateKey::from_bytes(&skb, Len::fixed(SCALAR))?,
        ))
    }

    fn blind(&self, input: &[u8], rng: &mut dyn EntropySource) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        input_ok(input)?;
        let mut r = Rng { src: rng, failed: false };
        let blind = Ristretto255::random_scalar(&mut r);
        if r.failed {
            return Err(Error::EntropyFailure("oprf blind"));
        }
        let res = OprfClient::<Ristretto255>::deterministic_blind_unchecked(input, blind).map_err(bad)?;
        let blinded = Ristretto255::serialize_elem(res.message.value()).to_vec();
        Ok((scalar_bytes(blind), blinded))
    }

    fn evaluate(
        &self,
        sk: &PrivateKey,
        blinded: &[u8],
        info: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if !info.is_empty() {
            return Err(Error::InvalidInput("info is not used by the base OPRF mode"));
        }
        Len::fixed(SCALAR).check("sk", sk.as_bytes().len())?;
        Len::fixed(ELEM).check("blinded", blinded.len())?;
        let server = OprfServer::<Ristretto255>::new_with_key(sk.as_bytes()).map_err(bad)?;
        let el = Ristretto255::deserialize_elem(blinded).map_err(bad)?;
        let out = server.blind_evaluate(&BlindedElement::from_value_unchecked(el));
        Ok((Ristretto255::serialize_elem(out.value()).to_vec(), Vec::new()))
    }

    fn finalize(
        &self,
        state: &[u8],
        input: &[u8],
        evaluated: &[u8],
        proof: &[u8],
        _pk: &PublicKey,
        info: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        input_ok(input)?;
        if !info.is_empty() {
            return Err(Error::InvalidInput("info is not used by the base OPRF mode"));
        }
        if !proof.is_empty() {
            return Err(Error::InvalidInput("the base OPRF mode has no proof"));
        }
        Len::fixed(SCALAR).check("state", state.len())?;
        Len::fixed(ELEM).check("evaluated", evaluated.len())?;
        let blind = Ristretto255::deserialize_scalar(state).map_err(bad)?;
        let client = OprfClient::<Ristretto255>::deterministic_blind_unchecked(input, blind)
            .map_err(bad)?
            .state;
        let el = Ristretto255::deserialize_elem(evaluated).map_err(bad)?;
        let out = client
            .finalize(input, &EvaluationElement::from_value_unchecked(el))
            .map_err(bad)?;
        debug_assert_eq!(out.len(), OUT);
        Ok(Zeroizing::new(out.to_vec()))
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Oprf>> {
    Ok(Box::new(Impl))
}
