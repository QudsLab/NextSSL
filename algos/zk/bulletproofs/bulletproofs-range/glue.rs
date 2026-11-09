//! Adapter: `bulletproofs` 5.0.0 (dalek, Ristretto255) -> nextssl `Zk`, single 64/32/16/8-bit range proof.
//! params for `setup` = empty (64 bits) or one byte in {8, 16, 32, 64}; the setup blob is that one byte (the generators are
//! derived, there is no trusted setup). statement = 32-byte compressed Pedersen commitment V = v*B + r*B_blinding.
//! witness = value (u64 little endian, must be below 2^bits) || blinding (32-byte canonical scalar). The proof is only made
//! when V matches the witness. `verify` draws its batching randomness from the crate's own thread RNG (soundness only, the
//! result is deterministic); the caller's entropy source is used for proving.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use nextssl_core::{EntropySource, Error, Params, Result, Zeroizing, Zk};
use rand_core::{CryptoRng, RngCore};

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

const LABEL: &[u8] = b"nextssl-bulletproofs-range-v1";
const MAX_PROOF: usize = 4096;

fn bits_of(setup: &[u8]) -> Result<usize> {
    match setup {
        [n] if matches!(*n, 8 | 16 | 32 | 64) => Ok(*n as usize),
        _ => Err(Error::InvalidInput("bulletproofs setup must be one byte in {8, 16, 32, 64}")),
    }
}

struct Alg;

impl Zk for Alg {
    fn setup(&self, params: &[u8], _rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        match params {
            [] => Ok(vec![64]),
            p => bits_of(p).map(|n| vec![n as u8]),
        }
    }

    fn prove(&self, setup: &[u8], statement: &[u8], witness: &[u8], rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        let n = bits_of(setup)?;
        nextssl_core::check_len("statement", statement.len(), 32, 32)?;
        nextssl_core::check_len("witness", witness.len(), 40, 40)?;
        let w = Zeroizing::new(witness.to_vec());
        let mut vb = [0u8; 8];
        vb.copy_from_slice(&w[..8]);
        let v = u64::from_le_bytes(vb);
        if n < 64 && v >> n != 0 {
            return Err(Error::InvalidInput("value does not fit the range"));
        }
        let mut sb = Zeroizing::new([0u8; 32]);
        sb.copy_from_slice(&w[8..]);
        let blinding = Option::<Scalar>::from(Scalar::from_canonical_bytes(*sb)).ok_or(Error::InvalidInput("blinding is not a canonical scalar"))?;
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(n, 1);
        let mut t = Transcript::new(LABEL);
        let (proof, commit) = with_rng(rng, |r| RangeProof::prove_single_with_rng(&bp, &pc, &mut t, v, &blinding, n, r))?
            .map_err(|_| Error::Backend("bulletproofs prove failed"))?;
        if commit.as_bytes() != statement {
            return Err(Error::InvalidInput("statement is not the commitment of the witness"));
        }
        Ok(proof.to_bytes())
    }

    fn verify(&self, setup: &[u8], statement: &[u8], proof: &[u8]) -> Result<bool> {
        let n = bits_of(setup)?;
        nextssl_core::check_len("statement", statement.len(), 32, 32)?;
        nextssl_core::check_len("proof", proof.len(), 7 * 32, MAX_PROOF)?;
        let mut v = [0u8; 32];
        v.copy_from_slice(statement);
        let proof = RangeProof::from_bytes(proof).map_err(|_| Error::InvalidInput("malformed range proof"))?;
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(n, 1);
        let mut t = Transcript::new(LABEL);
        Ok(proof.verify_single(&bp, &pc, &mut t, &CompressedRistretto(v), n).is_ok())
    }
}

/// Registry constructor. No parameters.
pub fn new(_params: &Params) -> Result<Box<dyn Zk>> {
    Ok(Box::new(Alg))
}
