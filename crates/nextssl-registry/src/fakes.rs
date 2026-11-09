//! Test doubles for every kind. NOT CRYPTO: these are trivially breakable toys that exist only
//! to prove that registration, tier policy, lookup, size metadata and the trait contracts work
//! for every kind before any real algorithm is imported. They are `cfg(test)` and never ship.

use super::*;
use nextssl_core::keys::{Ciphertext, PrivateKey, PublicKey, Seed, SharedSecret, Signature};
use nextssl_core::testing::FixedEntropy;
use nextssl_core::{
    ct_eq, HeKeys, HeOp, KeyedBlockCipher, PakeRole, PakeState, PakeStep, ParamType, Share,
    StatefulKey, SymmetricKey, ThresholdSession, ThresholdState, Value, Zeroizing,
};

fn l(n: usize) -> Option<Len> {
    Some(Len::fixed(n))
}
fn r(a: usize, b: usize) -> Option<Len> {
    Some(Len::range(a, b))
}
fn fold(data: &[u8]) -> u8 {
    data.iter()
        .fold(0u8, |a, b| a.wrapping_mul(31).wrapping_add(*b))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::InvalidInput("odd hex"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| Error::InvalidInput("hex"))
        })
        .collect()
}

// ---- keyless -------------------------------------------------------------------------

struct FHash;
impl Hash for FHash {
    fn output_len(&self) -> usize {
        4
    }
    fn digest(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != 4 {
            return Err(Error::BadOutputLen {
                expected: 4,
                got: out.len(),
            });
        }
        out.fill(fold(data));
        Ok(())
    }
}

struct FXof;
impl Xof for FXof {
    fn squeeze(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.is_empty() {
            return Err(Error::InvalidLength {
                what: "out",
                got: 0,
                min: 1,
                max: usize::MAX,
            });
        }
        for (i, o) in out.iter_mut().enumerate() {
            *o = fold(data).wrapping_add(i as u8);
        }
        Ok(())
    }
}

struct FChecksum;
impl Checksum for FChecksum {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: l(1),
            ..Sizes::NONE
        }
    }
    fn checksum(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        self.sizes().out.unwrap().check("out", out.len())?;
        out[0] = data.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        Ok(())
    }
}

struct FEncoding;
impl Encoding for FEncoding {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(hex(data).into_bytes())
    }
    fn decode(&self, text: &[u8]) -> Result<Vec<u8>> {
        let s = core::str::from_utf8(text).map_err(|_| Error::InvalidInput("utf8"))?;
        if s.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(Error::InvalidInput("non-canonical"));
        }
        unhex(s)
    }
}

// ---- symmetric -----------------------------------------------------------------------

struct FMac;
impl Mac for FMac {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: r(1, 16),
            tag: r(4, 8),
            ..Sizes::NONE
        }
    }
    fn tag(&self, key: &SymmetricKey, data: &[u8], out: &mut [u8]) -> Result<()> {
        let s = self.sizes();
        s.key.unwrap().check("key", key.len())?;
        s.tag.unwrap().check("tag", out.len())?;
        out.fill(fold(data) ^ fold(key.as_bytes()));
        Ok(())
    }
}

struct FKdf;
impl Kdf for FKdf {
    fn sizes(&self) -> Sizes {
        Sizes {
            out: r(1, 64),
            ..Sizes::NONE
        }
    }
    fn derive(&self, ikm: &SymmetricKey, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        self.sizes().out.unwrap().check("out", out.len())?;
        for (i, o) in out.iter_mut().enumerate() {
            *o = fold(ikm.as_bytes()) ^ fold(salt) ^ fold(info) ^ i as u8;
        }
        Ok(())
    }
}

struct FPwHash;
impl PwHash for FPwHash {
    fn sizes(&self) -> Sizes {
        Sizes {
            salt: r(8, 16),
            out: l(4),
            ..Sizes::NONE
        }
    }
    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<String> {
        let mut h = [0u8; 4];
        self.derive(password, salt, &mut h)?;
        Ok(format!("$fake-pw$v=1$m=8${}${}", hex(salt), hex(&h)))
    }
    fn verify(&self, password: &[u8], phc: &str) -> Result<bool> {
        let parts: Vec<&str> = phc.split('$').collect();
        let ["", "fake-pw", "v=1", "m=8", salt, hash] = parts.as_slice() else {
            return Err(Error::InvalidInput("not a fake-pw PHC string"));
        };
        let (salt, hash) = (unhex(salt)?, unhex(hash)?);
        let mut mine = [0u8; 4];
        self.derive(password, &salt, &mut mine)?;
        Ok(ct_eq(&mine, &hash))
    }
    fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        let s = self.sizes();
        s.salt.unwrap().check("salt", salt.len())?;
        s.out.unwrap().check("out", out.len())?;
        out.fill(fold(password) ^ fold(salt));
        Ok(())
    }
}

struct FAead;
impl FAead {
    fn tag(key: &SymmetricKey, nonce: &[u8], aad: &[u8], body: &[u8]) -> u8 {
        fold(key.as_bytes()) ^ fold(nonce) ^ fold(aad) ^ fold(body)
    }
    fn check(&self, key: &SymmetricKey, nonce: &[u8]) -> Result<()> {
        let s = self.sizes();
        s.key.unwrap().check("key", key.len())?;
        s.nonce.unwrap().check("nonce", nonce.len())
    }
}
impl Aead for FAead {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: l(4),
            nonce: l(3),
            tag: l(1),
            ..Sizes::NONE
        }
    }
    fn seal(&self, key: &SymmetricKey, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check(key, nonce)?;
        let mut ct: Vec<u8> = pt.iter().map(|b| b ^ key.as_bytes()[0]).collect();
        ct.push(Self::tag(key, nonce, aad, &ct));
        Ok(ct)
    }
    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check(key, nonce)?;
        let (body, tag) = ct.split_at(ct.len().checked_sub(1).ok_or(Error::InvalidLength {
            what: "ciphertext",
            got: 0,
            min: 1,
            max: usize::MAX,
        })?);
        if !ct_eq(&[Self::tag(key, nonce, aad, body)], tag) {
            return Err(Error::AuthenticationFailed);
        }
        Ok(Zeroizing::new(
            body.iter().map(|b| b ^ key.as_bytes()[0]).collect(),
        ))
    }
}

struct FBlock;
struct FKeyed(Zeroizing<Vec<u8>>);
impl KeyedBlockCipher for FKeyed {
    fn block_len(&self) -> usize {
        4
    }
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        Len::fixed(4).check("block", block.len())?;
        block
            .iter_mut()
            .zip(self.0.iter())
            .for_each(|(b, k)| *b ^= k);
        block.rotate_left(1);
        Ok(())
    }
    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        Len::fixed(4).check("block", block.len())?;
        block.rotate_right(1);
        block
            .iter_mut()
            .zip(self.0.iter())
            .for_each(|(b, k)| *b ^= k);
        Ok(())
    }
}
impl BlockCipher for FBlock {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: l(4),
            block: l(4),
            ..Sizes::NONE
        }
    }
    fn keyed(&self, key: &SymmetricKey) -> Result<Box<dyn KeyedBlockCipher>> {
        self.sizes().key.unwrap().check("key", key.len())?;
        Ok(Box::new(FKeyed(Zeroizing::new(key.as_bytes().to_vec()))))
    }
}

struct FStream;
impl StreamCipher for FStream {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: l(2),
            nonce: l(0),
            ..Sizes::NONE
        }
    }
    fn apply_keystream(&self, key: &SymmetricKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        let s = self.sizes();
        s.key.unwrap().check("key", key.len())?;
        s.nonce.unwrap().check("nonce", nonce.len())?;
        data.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b ^= key.as_bytes()[i % 2]);
        Ok(())
    }
}

/// Toy concrete block mode (XOR with the key, no nonce): proves the `BlockMode` kind registers.
struct FBlockMode;
impl BlockMode for FBlockMode {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: l(2),
            nonce: l(0),
            block: l(2),
            ..Sizes::NONE
        }
    }
    fn encrypt(&self, key: &SymmetricKey, nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        Len::fixed(2).check("key", key.len())?;
        Len::fixed(0).check("nonce", nonce.len())?;
        Ok(pt
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key.as_bytes()[i % 2])
            .collect())
    }
    fn decrypt(&self, key: &SymmetricKey, nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.encrypt(key, nonce, ct)?))
    }
}

/// ECB-shaped toy mode: proves a `Mode` composes with any registered `BlockCipher`.
struct FMode;
impl Mode for FMode {
    fn sizes(&self, cipher: &dyn BlockCipher) -> Result<Sizes> {
        let c = cipher.sizes();
        Ok(Sizes {
            key: c.key,
            nonce: l(0),
            block: c.block,
            ..Sizes::NONE
        })
    }
    fn encrypt(
        &self,
        cipher: &dyn BlockCipher,
        key: &SymmetricKey,
        iv: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>> {
        let bl = self
            .sizes(cipher)?
            .block
            .and_then(|b| b.as_fixed())
            .ok_or(Error::Unsupported)?;
        Len::fixed(0).check("iv", iv.len())?;
        if pt.len() % bl != 0 {
            return Err(Error::InvalidInput("not block aligned"));
        }
        let k = cipher.keyed(key)?;
        let mut out = pt.to_vec();
        out.chunks_mut(bl).try_for_each(|b| k.encrypt_block(b))?;
        Ok(out)
    }
    fn decrypt(
        &self,
        cipher: &dyn BlockCipher,
        key: &SymmetricKey,
        iv: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let bl = self
            .sizes(cipher)?
            .block
            .and_then(|b| b.as_fixed())
            .ok_or(Error::Unsupported)?;
        Len::fixed(0).check("iv", iv.len())?;
        if ct.len() % bl != 0 {
            return Err(Error::InvalidInput("not block aligned"));
        }
        let k = cipher.keyed(key)?;
        let mut out = Zeroizing::new(ct.to_vec());
        out.chunks_mut(bl).try_for_each(|b| k.decrypt_block(b))?;
        Ok(out)
    }
}

// ---- asymmetric ----------------------------------------------------------------------

struct FKem;
impl Kem for FKem {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: l(4),
            sk: l(4),
            ct: l(2),
            ss: l(2),
            seed: l(4),
            coins: l(2),
            ..Sizes::NONE
        }
    }
    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        Len::fixed(4).check("seed", seed.len())?;
        let pk: Vec<u8> = seed.as_bytes().iter().map(|b| !b).collect();
        Ok((
            PublicKey::from_vec(pk, Len::fixed(4))?,
            PrivateKey::from_bytes(seed.as_bytes(), Len::fixed(4))?,
        ))
    }
    fn encaps_from_coins(
        &self,
        pk: &PublicKey,
        coins: &Seed,
    ) -> Result<(Ciphertext, SharedSecret)> {
        Len::fixed(4).check("pk", pk.len())?;
        Len::fixed(2).check("coins", coins.len())?;
        let ss: Vec<u8> = coins
            .as_bytes()
            .iter()
            .zip(pk.as_bytes())
            .map(|(c, p)| c ^ p)
            .collect();
        Ok((
            Ciphertext::from_bytes(coins.as_bytes(), Len::fixed(2))?,
            SharedSecret::from_vec(ss, Len::fixed(2))?,
        ))
    }
    fn decaps(&self, sk: &PrivateKey, ct: &Ciphertext) -> Result<SharedSecret> {
        Len::fixed(4).check("sk", sk.len())?;
        Len::fixed(2).check("ct", ct.len())?;
        let ss: Vec<u8> = ct
            .as_bytes()
            .iter()
            .zip(sk.as_bytes())
            .map(|(c, s)| c ^ !s)
            .collect();
        SharedSecret::from_vec(ss, Len::fixed(2))
    }
}

struct FKex;
impl Kex for FKex {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: l(2),
            sk: l(2),
            ss: l(2),
            seed: l(2),
            ..Sizes::NONE
        }
    }
    fn keypair_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        Len::fixed(2).check("seed", seed.len())?;
        let pk: Vec<u8> = seed.as_bytes().iter().map(|b| b ^ 0x55).collect();
        Ok((
            PublicKey::from_vec(pk, Len::fixed(2))?,
            PrivateKey::from_bytes(seed.as_bytes(), Len::fixed(2))?,
        ))
    }
    fn agree(&self, sk: &PrivateKey, peer: &PublicKey) -> Result<SharedSecret> {
        Len::fixed(2).check("sk", sk.len())?;
        Len::fixed(2).check("peer pk", peer.len())?;
        let ss: Vec<u8> = sk
            .as_bytes()
            .iter()
            .zip(peer.as_bytes())
            .map(|(s, p)| (s ^ 0x55) ^ p)
            .collect();
        if ss.iter().all(|b| *b == 0) {
            return Err(Error::InvalidInput("all-zero shared secret"));
        }
        SharedSecret::from_vec(ss, Len::fixed(2))
    }
}

struct FSign;
impl FSign {
    fn tag(pk: &[u8], msg: &[u8], ctx: &[u8]) -> Vec<u8> {
        vec![fold(pk) ^ fold(msg), fold(ctx)]
    }
}
impl Sign for FSign {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: l(2),
            sk: l(2),
            sig: l(2),
            seed: l(2),
            ctx: r(0, 4),
            ..Sizes::NONE
        }
    }
    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, PrivateKey)> {
        Len::fixed(2).check("seed", seed.len())?;
        let pk: Vec<u8> = seed.as_bytes().iter().map(|b| b ^ 0xAA).collect();
        Ok((
            PublicKey::from_vec(pk, Len::fixed(2))?,
            PrivateKey::from_bytes(seed.as_bytes(), Len::fixed(2))?,
        ))
    }
    fn sign(
        &self,
        sk: &PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Signature> {
        let s = self.sizes();
        s.sk.unwrap().check("sk", sk.len())?;
        s.ctx.unwrap().check("ctx", ctx.len())?;
        let pk: Vec<u8> = sk.as_bytes().iter().map(|b| b ^ 0xAA).collect();
        Signature::from_vec(Self::tag(&pk, msg, ctx), Len::fixed(2))
    }
    fn verify(&self, pk: &PublicKey, msg: &[u8], ctx: &[u8], sig: &Signature) -> Result<bool> {
        let s = self.sizes();
        s.pk.unwrap().check("pk", pk.len())?;
        s.sig.unwrap().check("sig", sig.len())?;
        s.ctx.unwrap().check("ctx", ctx.len())?;
        Ok(ct_eq(&Self::tag(pk.as_bytes(), msg, ctx), sig.as_bytes()))
    }
}

// ---- randomness ----------------------------------------------------------------------

struct FRng(u8);
impl EntropySource for FRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        for o in out {
            self.0 = self.0.wrapping_add(1);
            *o = self.0;
        }
        Ok(())
    }
}

struct FDrbg(Option<u8>);
impl Drbg for FDrbg {
    fn sizes(&self) -> Sizes {
        Sizes {
            seed: r(16, 32),
            ..Sizes::NONE
        }
    }
    fn security_strength(&self) -> usize {
        128
    }
    fn max_request_len(&self) -> usize {
        64
    }
    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<()> {
        self.sizes().seed.unwrap().check("entropy", entropy.len())?;
        self.0 = Some(fold(entropy) ^ fold(nonce) ^ fold(personalization));
        Ok(())
    }
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()> {
        let st = self.0.ok_or(Error::NotInstantiated)?;
        self.sizes().seed.unwrap().check("entropy", entropy.len())?;
        self.0 = Some(st ^ fold(entropy) ^ fold(additional));
        Ok(())
    }
    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()> {
        let mut st = self.0.ok_or(Error::NotInstantiated)?;
        Len::range(1, self.max_request_len()).check("request", out.len())?;
        for o in out {
            st = st.wrapping_mul(5).wrapping_add(1) ^ fold(additional);
            *o = st;
        }
        self.0 = Some(st);
        Ok(())
    }
    fn uninstantiate(&mut self) {
        self.0 = None;
    }
}

// ---- reserved ------------------------------------------------------------------------

struct FPow;
impl Pow for FPow {
    fn sizes(&self) -> Sizes {
        Sizes::NONE
    }
    fn difficulty(&self) -> (u32, u32) {
        (0, 0)
    }
    fn solve(&self, _c: &[u8], _d: u32, _m: u64) -> Result<Vec<u8>> {
        Err(Error::Unsupported)
    }
    fn verify(&self, _c: &[u8], _s: &[u8], _d: u32) -> Result<bool> {
        Err(Error::Unsupported)
    }
}
struct FZk;
impl Zk for FZk {
    fn setup(&self, _params: &[u8], _rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        Ok(vec![1])
    }
    fn prove(
        &self,
        setup: &[u8],
        statement: &[u8],
        witness: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        if setup != [1] {
            return Err(Error::InvalidInput("setup"));
        }
        // toy relation: statement = fold(witness)
        if statement != [fold(witness)] {
            return Err(Error::InvalidInput("witness does not match statement"));
        }
        Ok(vec![fold(statement)])
    }
    fn verify(&self, setup: &[u8], statement: &[u8], proof: &[u8]) -> Result<bool> {
        if setup != [1] || statement.len() != 1 || proof.len() != 1 {
            return Err(Error::InvalidInput("lengths"));
        }
        Ok(proof[0] == fold(statement))
    }
}

struct FThreshold;
impl Threshold for FThreshold {
    fn max_parties(&self) -> usize {
        8
    }
    fn split(
        &self,
        secret: &[u8],
        t: usize,
        n: usize,
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<Share>> {
        nextssl_core::check_threshold(t, n, self.max_parties())?;
        if secret.is_empty() {
            return Err(Error::InvalidInput("empty secret"));
        }
        // toy, NOT sharing: every share carries t, its id and the secret
        (1..=n)
            .map(|i| {
                let mut v = vec![t as u8, i as u8];
                v.extend_from_slice(secret);
                Share::from_vec(v, Len::range(3, 4096))
            })
            .collect()
    }
    fn combine(&self, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
        let first = shares.first().ok_or(Error::InvalidInput("no shares"))?;
        let t = first.as_bytes()[0] as usize;
        if shares.len() < t {
            return Err(Error::InvalidInput("too few shares"));
        }
        let mut ids: Vec<u8> = shares.iter().map(|s| s.as_bytes()[1]).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != shares.len() {
            return Err(Error::InvalidInput("duplicate share id"));
        }
        Ok(Zeroizing::new(first.as_bytes()[2..].to_vec()))
    }
    fn start(
        &self,
        s: &ThresholdSession,
        _rng: &mut dyn EntropySource,
    ) -> Result<(Box<dyn ThresholdState>, Vec<u8>)> {
        nextssl_core::check_threshold(s.t as usize, s.n as usize, self.max_parties())?;
        nextssl_core::check_party(s.party as usize, s.n as usize)?;
        Err(Error::Unsupported)
    }
}

struct FVdf;
impl FVdf {
    fn run(challenge: &[u8], t: u64) -> u8 {
        (0..t).fold(fold(challenge), |a, _| a.wrapping_mul(3).wrapping_add(1))
    }
    fn check_t(&self, t: u64) -> Result<()> {
        if t == 0 || t > self.max_t() {
            return Err(Error::ParamOutOfRange("t"));
        }
        Ok(())
    }
}
impl Vdf for FVdf {
    fn max_t(&self) -> u64 {
        1000
    }
    fn eval(&self, challenge: &[u8], t: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        self.check_t(t)?;
        let o = Self::run(challenge, t);
        Ok((vec![o], vec![o ^ 0xFF]))
    }
    fn verify(&self, challenge: &[u8], t: u64, output: &[u8], proof: &[u8]) -> Result<bool> {
        self.check_t(t)?;
        if output.len() != 1 || proof.len() != 1 {
            return Err(Error::InvalidInput("lengths"));
        }
        Ok(output[0] == Self::run(challenge, t) && proof[0] == output[0] ^ 0xFF)
    }
}

struct FPke;
impl FPke {
    fn tag(k: u8, pt: &[u8], label: &[u8]) -> u8 {
        fold(pt) ^ fold(label) ^ k
    }
}
impl Pke for FPke {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: l(1),
            sk: l(1),
            ct: r(1, 33),
            out: r(0, 32),
            ctx: r(0, 8),
            ..Sizes::NONE
        }
    }
    fn keygen(&self, rng: &mut dyn EntropySource) -> Result<(PublicKey, PrivateKey)> {
        let mut k = [0u8; 1];
        rng.fill(&mut k)?;
        Ok((
            PublicKey::from_bytes(&k, Len::fixed(1))?,
            PrivateKey::from_bytes(&k, Len::fixed(1))?,
        ))
    }
    fn encrypt(
        &self,
        pk: &PublicKey,
        pt: &[u8],
        label: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        let s = self.sizes();
        s.pk.unwrap().check("pk", pk.len())?;
        s.out.unwrap().check("plaintext", pt.len())?;
        s.ctx.unwrap().check("label", label.len())?;
        let k = pk.as_bytes()[0];
        let mut ct: Vec<u8> = pt.iter().map(|b| b ^ k).collect();
        ct.push(Self::tag(k, pt, label));
        Ok(ct)
    }
    fn decrypt(&self, sk: &PrivateKey, ct: &[u8], label: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let s = self.sizes();
        s.sk.unwrap().check("sk", sk.len())?;
        s.ct.unwrap().check("ciphertext", ct.len())?;
        s.ctx.unwrap().check("label", label.len())?;
        let k = sk.as_bytes()[0];
        let (body, tag) = ct.split_at(ct.len() - 1);
        let pt: Zeroizing<Vec<u8>> = Zeroizing::new(body.iter().map(|b| b ^ k).collect());
        if tag[0] != Self::tag(k, &pt, label) {
            return Err(Error::AuthenticationFailed);
        }
        Ok(pt)
    }
}

struct FPake;
struct FPakeWait {
    expect: u8,
    ss: [u8; 4],
}
impl FPake {
    fn secret(pw: &[u8], ctx: &[u8]) -> [u8; 4] {
        [fold(pw), fold(ctx), 7, fold(pw) ^ fold(ctx)]
    }
}
impl PakeState for FPakeWait {
    fn step(self: Box<Self>, msg: &[u8]) -> Result<PakeStep> {
        if msg != [self.expect] {
            return Err(Error::ProtocolAborted("bad message"));
        }
        let ss = SharedSecret::from_bytes(&self.ss, Len::fixed(4))?;
        // the responder (odd `expect`) answers once; the initiator ends
        Ok(PakeStep::Done(
            ss,
            if self.expect & 1 == 1 {
                Some(vec![self.expect ^ 1])
            } else {
                None
            },
        ))
    }
}
impl Pake for FPake {
    fn sizes(&self) -> Sizes {
        Sizes {
            key: r(1, 32),
            ss: l(4),
            ..Sizes::NONE
        }
    }
    fn start(
        &self,
        role: PakeRole,
        password: &[u8],
        context: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<(Box<dyn PakeState>, Vec<u8>)> {
        self.sizes().key.unwrap().check("password", password.len())?;
        let ss = Self::secret(password, context);
        let h = fold(password) | 1; // odd: expected by the responder
        match role {
            PakeRole::Initiator => Ok((Box::new(FPakeWait { expect: h ^ 1, ss }), vec![h])),
            PakeRole::Responder => Ok((Box::new(FPakeWait { expect: h, ss }), vec![])),
        }
    }
}

struct FStateful;
const FS_MAX: u64 = 3;
impl FStateful {
    fn parse(key: &StatefulKey) -> Result<(u64, u8)> {
        Len::fixed(9).check("sk", key.len())?;
        let b = key.as_bytes();
        let mut n = [0u8; 8];
        n.copy_from_slice(&b[..8]);
        Ok((u64::from_be_bytes(n), b[8]))
    }
}
impl StatefulSign for FStateful {
    fn sizes(&self) -> Sizes {
        Sizes {
            pk: l(1),
            sk: l(9),
            sig: l(9),
            seed: l(1),
            ..Sizes::NONE
        }
    }
    fn max_signatures(&self) -> u64 {
        FS_MAX
    }
    fn remaining(&self, key: &StatefulKey) -> Result<u64> {
        Ok(FS_MAX.saturating_sub(Self::parse(key)?.0))
    }
    fn keygen_from_seed(&self, seed: &Seed) -> Result<(PublicKey, StatefulKey)> {
        Len::fixed(1).check("seed", seed.len())?;
        let s = seed.as_bytes()[0];
        let mut st = vec![0u8; 8];
        st.push(s);
        Ok((
            PublicKey::from_bytes(&[s ^ 0x5A], Len::fixed(1))?,
            StatefulKey::from_vec(st, Len::fixed(9))?,
        ))
    }
    fn sign(
        &self,
        key: &mut StatefulKey,
        msg: &[u8],
        persist: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Signature> {
        let (n, s) = Self::parse(key)?;
        if n >= FS_MAX {
            return Err(Error::KeyExhausted);
        }
        let mut next = Zeroizing::new((n + 1).to_be_bytes().to_vec());
        next.push(s);
        persist(&next)?;
        let mut sig = n.to_be_bytes().to_vec();
        sig.push(fold(msg) ^ s ^ n as u8);
        *key = StatefulKey::from_bytes(&next, Len::fixed(9))?;
        Signature::from_vec(sig, Len::fixed(9))
    }
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<bool> {
        Len::fixed(1).check("pk", pk.len())?;
        Len::fixed(9).check("sig", sig.len())?;
        let s = pk.as_bytes()[0] ^ 0x5A;
        let b = sig.as_bytes();
        Ok(b[8] == fold(msg) ^ s ^ b[7])
    }
}

struct FHe;
impl He for FHe {
    fn ops(&self) -> &'static [HeOp] {
        &[HeOp::Add]
    }
    fn keygen(&self, params: &[u8], rng: &mut dyn EntropySource) -> Result<HeKeys> {
        if !params.is_empty() {
            return Err(Error::InvalidInput("params"));
        }
        let mut k = [0u8; 1];
        rng.fill(&mut k)?;
        Ok(HeKeys {
            secret: PrivateKey::from_bytes(&k, Len::fixed(1))?,
            public: PublicKey::from_bytes(&k, Len::fixed(1))?,
            eval: PublicKey::from_bytes(&[0], Len::fixed(1))?,
        })
    }
    fn encrypt(
        &self,
        public: &PublicKey,
        pt: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        if pt.len() != 1 || public.len() != 1 {
            return Err(Error::InvalidInput("lengths"));
        }
        Ok(vec![pt[0].wrapping_add(public.as_bytes()[0])])
    }
    fn decrypt(&self, secret: &PrivateKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if ct.len() != 1 || secret.len() != 1 {
            return Err(Error::InvalidInput("lengths"));
        }
        Ok(Zeroizing::new(vec![
            ct[0].wrapping_sub(secret.as_bytes()[0]),
        ]))
    }
    fn eval(&self, op: HeOp, cts: &[&[u8]], _evk: &PublicKey) -> Result<Vec<u8>> {
        if !self.ops().contains(&op) {
            return Err(Error::Unsupported);
        }
        if cts.len() != op.arity() || cts.iter().any(|c| c.len() != 1) {
            return Err(Error::InvalidInput("operands"));
        }
        // toy: (a + k) + (b + k) is a + b + 2k; the test uses k = 0 keys only for this op
        Ok(vec![cts[0][0].wrapping_add(cts[1][0])])
    }
}

// ---- table ---------------------------------------------------------------------------

const PARAMS: &[ParamSpec] = &[ParamSpec {
    name: "rounds",
    ty: ParamType::U32,
    min: 1,
    max: 9,
    required: false,
    default: Some(1),
}];

fn ctor_for(kind: Kind) -> (Ctor, Sizes) {
    macro_rules! c {
        ($var:ident, $e:expr) => {
            Ctor::$var(|_| Ok(Box::new($e)))
        };
    }
    match kind {
        Kind::Hash => (
            c!(Hash, FHash),
            Sizes {
                out: l(4),
                ..Sizes::NONE
            },
        ),
        Kind::Xof => (c!(Xof, FXof), Sizes::NONE),
        Kind::Mac => (c!(Mac, FMac), FMac.sizes()),
        Kind::Kdf => (c!(Kdf, FKdf), FKdf.sizes()),
        Kind::PwHash => (c!(PwHash, FPwHash), FPwHash.sizes()),
        Kind::Aead => (c!(Aead, FAead), FAead.sizes()),
        Kind::BlockCipher => (c!(BlockCipher, FBlock), FBlock.sizes()),
        Kind::StreamCipher => (c!(StreamCipher, FStream), FStream.sizes()),
        Kind::Mode => (c!(Mode, FMode), Sizes::NONE),
        Kind::BlockMode => (c!(BlockMode, FBlockMode), FBlockMode.sizes()),
        Kind::Kem => (c!(Kem, FKem), FKem.sizes()),
        Kind::Kex => (c!(Kex, FKex), FKex.sizes()),
        Kind::Sign => (c!(Sign, FSign), FSign.sizes()),
        Kind::Rng => (c!(Rng, FRng(0)), Sizes::NONE),
        Kind::Drbg => (c!(Drbg, FDrbg(None)), FDrbg(None).sizes()),
        Kind::Encoding => (c!(Encoding, FEncoding), Sizes::NONE),
        Kind::Checksum => (c!(Checksum, FChecksum), FChecksum.sizes()),
        Kind::Pow => (c!(Pow, FPow), Sizes::NONE),
        Kind::Zk => (c!(Zk, FZk), Sizes::NONE),
        Kind::Threshold => (c!(Threshold, FThreshold), Sizes::NONE),
        Kind::Vdf => (c!(Vdf, FVdf), Sizes::NONE),
        Kind::Pke => (c!(Pke, FPke), FPke.sizes()),
        Kind::Pake => (c!(Pake, FPake), FPake.sizes()),
        Kind::StatefulSign => (c!(StatefulSign, FStateful), FStateful.sizes()),
        Kind::He => (c!(He, FHe), Sizes::NONE),
    }
}

// Indexed like `Kind::ALL`. Static (not leaked) so Miri reports no leaks.
const IDS: [&str; 25] = [
    "fake-hash",
    "fake-xof",
    "fake-mac",
    "fake-kdf",
    "fake-pwhash",
    "fake-aead",
    "fake-blockcipher",
    "fake-streamcipher",
    "fake-mode",
    "fake-blockmode",
    "fake-kem",
    "fake-kex",
    "fake-sign",
    "fake-rng",
    "fake-drbg",
    "fake-encoding",
    "fake-checksum",
    "fake-pow",
    "fake-zk",
    "fake-threshold",
    "fake-vdf",
    "fake-pke",
    "fake-pake",
    "fake-statefulsign",
    "fake-he",
];
const ALIASES: [[&str; 1]; 25] = [
    ["f-hash"],
    ["f-xof"],
    ["f-mac"],
    ["f-kdf"],
    ["f-pwhash"],
    ["f-aead"],
    ["f-blockcipher"],
    ["f-streamcipher"],
    ["f-mode"],
    ["f-blockmode"],
    ["f-kem"],
    ["f-kex"],
    ["f-sign"],
    ["f-rng"],
    ["f-drbg"],
    ["f-encoding"],
    ["f-checksum"],
    ["f-pow"],
    ["f-zk"],
    ["f-threshold"],
    ["f-vdf"],
    ["f-pke"],
    ["f-pake"],
    ["f-statefulsign"],
    ["f-he"],
];

/// One fake per kind, ids `fake-<kind>`, alias `f-<kind>`, all at `tier`.
fn table(tier: Tier) -> Vec<AlgoInfo> {
    Kind::ALL
        .into_iter()
        .enumerate()
        .map(|(i, kind)| {
            let (ctor, sizes) = ctor_for(kind);
            let id = IDS[i];
            let aliases: &'static [&'static str] = &ALIASES[i];
            AlgoInfo {
                id,
                kind,
                category: "test",
                family: "fake",
                aliases,
                tier,
                status: Status::Active,
                standards: &[],
                license: "CC0-1.0",
                copyleft: false,
                c_backed: false,
                fips: false,
                cose_alg: None,
                oid: "",
                sizes,
                params: PARAMS,
                test_params: &[],
                dir: "",
                kat: &[],
                smoke_skip: None,
                ctor,
            }
        })
        .collect()
}

fn key(n: usize, fill: u8) -> SymmetricKey {
    SymmetricKey::from_bytes(&vec![fill; n], Len::fixed(n)).unwrap()
}

#[test]
fn every_kind_registers_instantiates_and_matches_its_metadata() {
    let t = table(Tier::Safe);
    assert_eq!(t.len(), Kind::ALL.len());
    for info in &t {
        let inst = instantiate_in(&t, Policy::Any, info.id, &Params::new()).unwrap();
        assert_eq!(inst.kind(), info.kind, "{}", info.id);
        assert_eq!(info.ctor.kind(), info.kind);
        assert_eq!(info.id, format!("fake-{}", info.kind.as_str()), "IDS order");
        check_sizes(info, &inst).unwrap_or_else(|e| panic!("{e}"));
        // alias lookup resolves to the same entry
        let by_alias = lookup_in(&t, &format!("f-{}", info.kind.as_str())).unwrap();
        assert_eq!(by_alias.id, info.id);
    }
}

#[test]
fn tier_policy_applies_to_every_kind() {
    for tier in [Tier::Legacy, Tier::Broken, Tier::Research, Tier::Unverified] {
        let t = table(tier);
        for info in &t {
            assert!(
                matches!(
                    instantiate_in(&t, Policy::Safe, info.id, &Params::new()),
                    Err(Error::TierNotAllowed(x)) if x == tier
                ),
                "{} {tier:?}",
                info.id
            );
            assert!(instantiate_in(&t, Policy::Any, info.id, &Params::new()).is_ok());
        }
    }
    for tier in [Tier::Safe, Tier::Standard] {
        let t = table(tier);
        for info in &t {
            let r = instantiate_in(&t, Policy::Safe, info.id, &Params::new());
            if info.kind.root_only() {
                // never reachable from the safe API, even at tier safe
                assert!(
                    matches!(r, Err(Error::TierNotAllowed(x)) if x == tier),
                    "{}",
                    info.id
                );
            } else {
                assert!(r.is_ok(), "{}", info.id);
            }
        }
    }
}

#[test]
fn unknown_and_wrong_kind_and_params_are_explicit_errors() {
    let t = table(Tier::Safe);
    assert!(matches!(
        instantiate_in(&t, Policy::Any, "nope", &Params::new()),
        Err(Error::UnknownAlgorithm)
    ));
    assert!(matches!(
        new_aead_in(&t, Policy::Any, "fake-hash", &Params::new()),
        Err(Error::WrongKind)
    ));
    assert!(new_aead_in(&t, Policy::Any, "fake-aead", &Params::new()).is_ok());
    let bad = Params::new().with("rounds", Value::U32(10));
    assert!(matches!(
        instantiate_in(&t, Policy::Any, "fake-kem", &bad),
        Err(Error::ParamOutOfRange("rounds"))
    ));
    let unknown = Params::new().with("zz", Value::U32(1));
    assert!(matches!(
        instantiate_in(&t, Policy::Any, "fake-kem", &unknown),
        Err(Error::ParamUnknown)
    ));
}

#[test]
fn size_metadata_mismatch_is_detected() {
    let mut t = table(Tier::Safe);
    let i = t.iter().position(|a| a.kind == Kind::Aead).unwrap();
    t[i].sizes.tag = l(16); // instance says 1
    let inst = instantiate_in(&t, Policy::Any, "fake-aead", &Params::new()).unwrap();
    assert!(check_sizes(&t[i], &inst).unwrap_err().contains("tag"));
    t[i].sizes.nonce = None; // metadata incomplete
    assert!(check_sizes(&t[i], &inst).unwrap_err().contains("lacks"));
}

#[test]
fn mac_verify_is_checked_and_rejects_bad_lengths() {
    let t = table(Tier::Safe);
    let m = new_mac_in(&t, Policy::Any, "fake-mac", &Params::new()).unwrap();
    let k = key(8, 7);
    let mut tag = [0u8; 6];
    m.tag(&k, b"msg", &mut tag).unwrap();
    assert!(m.verify(&k, b"msg", &tag).unwrap());
    assert!(!m.verify(&k, b"msh", &tag).unwrap());
    assert!(
        m.verify(&k, b"msg", &tag[..3]).is_err(),
        "undeclared tag length is an error"
    );
    assert!(m.tag(&key(17, 1), b"", &mut tag).is_err());
    assert!(
        m.tag(&k, b"", &mut [0u8; 9]).is_err(),
        "no silent truncation or padding"
    );
}

#[test]
fn aead_rejects_tampering_and_bad_sizes() {
    let t = table(Tier::Safe);
    let a = new_aead_in(&t, Policy::Any, "fake-aead", &Params::new()).unwrap();
    let k = key(4, 3);
    let mut ct = a.seal(&k, &[1, 2, 3], b"aad", b"hello").unwrap();
    assert_eq!(&a.open(&k, &[1, 2, 3], b"aad", &ct).unwrap()[..], b"hello");
    assert!(matches!(
        a.open(&k, &[1, 2, 3], b"AAD", &ct),
        Err(Error::AuthenticationFailed)
    ));
    ct[0] ^= 1;
    assert!(matches!(
        a.open(&k, &[1, 2, 3], b"aad", &ct),
        Err(Error::AuthenticationFailed)
    ));
    assert!(a.seal(&k, &[1, 2], b"", b"").is_err());
    assert!(a.seal(&key(5, 3), &[1, 2, 3], b"", b"").is_err());
}

#[test]
fn kdf_pwhash_and_phc_policy() {
    let t = table(Tier::Safe);
    let kdf = new_kdf_in(&t, Policy::Any, "fake-kdf", &Params::new()).unwrap();
    let mut o = [0u8; 8];
    kdf.derive(&key(4, 1), b"s", b"i", &mut o).unwrap();
    assert!(kdf.derive(&key(4, 1), b"s", b"i", &mut []).is_err());
    assert!(kdf.derive(&key(4, 1), b"s", b"i", &mut [0u8; 65]).is_err());
    assert!(matches!(
        kdf.extract(&key(4, 1), b""),
        Err(Error::Unsupported)
    ));

    let pw = new_pwhash_in(&t, Policy::Any, "fake-pwhash", &Params::new()).unwrap();
    let phc = pw.hash(b"pw", b"saltsalt").unwrap();
    assert!(phc.starts_with("$fake-pw$"), "{phc}");
    assert!(pw.verify(b"pw", &phc).unwrap());
    assert!(!pw.verify(b"px", &phc).unwrap());
    assert!(pw.verify(b"pw", "$other$v=1$m=8$00$00").is_err());
    assert!(pw.hash(b"pw", b"short").is_err());
}

#[test]
fn block_cipher_and_generic_mode() {
    let t = table(Tier::Safe);
    let bc = new_blockcipher_in(&t, Policy::Any, "fake-blockcipher", &Params::new()).unwrap();
    let k = key(4, 9);
    let mut b = [1u8, 2, 3, 4];
    bc.encrypt_block(&k, &mut b).unwrap();
    assert_ne!(b, [1, 2, 3, 4]);
    bc.decrypt_block(&k, &mut b).unwrap();
    assert_eq!(b, [1, 2, 3, 4]);
    assert!(bc.encrypt_block(&k, &mut [0u8; 5]).is_err());

    let mode = new_mode_in(&t, Policy::Any, "fake-mode", &Params::new()).unwrap();
    let ct = mode
        .encrypt(bc.as_ref(), &k, &[], &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();
    let pt = mode.decrypt(bc.as_ref(), &k, &[], &ct).unwrap();
    assert_eq!(&pt[..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(mode.encrypt(bc.as_ref(), &k, &[], &[1, 2, 3]).is_err());
    assert!(
        mode.encrypt(bc.as_ref(), &k, &[0], &[0; 4]).is_err(),
        "unexpected IV is an error"
    );

    let sc = new_streamcipher_in(&t, Policy::Any, "fake-streamcipher", &Params::new()).unwrap();
    let mut d = *b"abcde";
    sc.apply_keystream(&key(2, 5), &[], &mut d).unwrap();
    sc.apply_keystream(&key(2, 5), &[], &mut d).unwrap();
    assert_eq!(&d, b"abcde");
    assert!(sc.apply_keystream(&key(3, 5), &[], &mut d).is_err());
}

#[test]
fn kem_kex_sign_roundtrips_with_seed_and_rng_paths() {
    let t = table(Tier::Safe);
    let kem = new_kem_in(&t, Policy::Any, "fake-kem", &Params::new()).unwrap();
    let mut rng = FixedEntropy::new(&[1, 2, 3, 4, 9, 9]); // seed(4) + coins(2)
    let (pk, sk) = kem.keygen(&mut rng).unwrap();
    let (ct, ss1) = kem.encaps(&pk, &mut rng).unwrap();
    assert_eq!(rng.remaining(), 0);
    assert_eq!(kem.decaps(&sk, &ct).unwrap(), ss1);
    assert!(
        kem.encaps(&pk, &mut rng).is_err(),
        "exhausted entropy is an error"
    );
    assert!(kem
        .decaps(
            &sk,
            &Ciphertext::from_bytes(&[0; 3], Len::fixed(3)).unwrap()
        )
        .is_err());
    let seed = Seed::from_bytes(&[1, 2, 3, 4], Len::fixed(4)).unwrap();
    assert_eq!(kem.keygen_from_seed(&seed).unwrap().0, pk);

    let kex = new_kex_in(&t, Policy::Any, "fake-kex", &Params::new()).unwrap();
    let (pa, sa) = kex.keypair(&mut FixedEntropy::new(&[1, 2])).unwrap();
    let (pb, sb) = kex.keypair(&mut FixedEntropy::new(&[7, 8])).unwrap();
    assert_eq!(kex.agree(&sa, &pb).unwrap(), kex.agree(&sb, &pa).unwrap());
    // peer key that cancels our public key gives an all-zero secret: refused
    let zero_peer = PublicKey::from_bytes(pa.as_bytes(), Len::fixed(2)).unwrap();
    assert!(kex.agree(&sa, &zero_peer).is_err());

    let sig = new_sign_in(&t, Policy::Any, "fake-sign", &Params::new()).unwrap();
    let mut none = FixedEntropy::new(&[]);
    let (pk, sk) = sig.keygen(&mut FixedEntropy::new(&[5, 6])).unwrap();
    let s = sig.sign(&sk, b"m", b"ctx", &mut none).unwrap();
    assert!(sig.verify(&pk, b"m", b"ctx", &s).unwrap());
    assert!(
        !sig.verify(&pk, b"m", b"oth", &s).unwrap(),
        "context is bound"
    );
    assert!(!sig.verify(&pk, b"n", b"ctx", &s).unwrap());
    assert!(
        sig.sign(&sk, b"m", &[0; 5], &mut none).is_err(),
        "over-long context is an error"
    );
    let short = Signature::from_bytes(&[0; 1], Len::fixed(1)).unwrap();
    assert!(sig.verify(&pk, b"m", b"", &short).is_err());
}

#[test]
fn rng_drbg_lifecycle() {
    let t = table(Tier::Safe);
    let mut rng = new_rng_in(&t, Policy::Any, "fake-rng", &Params::new()).unwrap();
    let mut a = [0u8; 4];
    rng.fill(&mut a).unwrap();
    assert_ne!(a, [0; 4]);

    let mut d = new_drbg_in(&t, Policy::Any, "fake-drbg", &Params::new()).unwrap();
    let mut out = [0u8; 8];
    assert!(matches!(
        d.generate(&[], &mut out),
        Err(Error::NotInstantiated)
    ));
    assert!(
        d.instantiate(&[1; 8], &[], &[]).is_err(),
        "entropy too short"
    );
    d.instantiate(&[1; 16], b"n", b"p").unwrap();
    d.generate(&[], &mut out).unwrap();
    assert!(d.generate(&[], &mut [0u8; 65]).is_err());
    d.reseed(&[2; 16], &[]).unwrap();
    d.uninstantiate();
    assert!(matches!(
        d.generate(&[], &mut out),
        Err(Error::NotInstantiated)
    ));
}

#[test]
fn keyless_kinds_and_reserved_stubs() {
    let t = table(Tier::Safe);
    assert_eq!(
        hash_in(&t, Policy::Any, "fake-hash", &Params::new(), b"abc")
            .unwrap()
            .len(),
        4
    );
    let x = new_xof_in(&t, Policy::Any, "fake-xof", &Params::new()).unwrap();
    assert!(x.squeeze(b"", &mut []).is_err());
    let c = new_checksum_in(&t, Policy::Any, "fake-checksum", &Params::new()).unwrap();
    let mut one = [0u8; 1];
    c.checksum(b"abc", &mut one).unwrap();
    assert!(c.checksum(b"abc", &mut [0u8; 2]).is_err());
    assert_eq!(
        encode_in(
            &t,
            Policy::Any,
            "fake-encoding",
            &Params::new(),
            b"\x01\xff"
        )
        .unwrap(),
        b"01ff"
    );
    assert!(decode_in(&t, Policy::Any, "fake-encoding", &Params::new(), b"01FF").is_err());
    assert!(decode_in(&t, Policy::Any, "fake-encoding", &Params::new(), b"0").is_err());
    for kind in [
        Kind::Pow,
        Kind::Zk,
        Kind::Threshold,
        Kind::Vdf,
        Kind::Pke,
        Kind::Pake,
        Kind::StatefulSign,
        Kind::He,
    ] {
        let id = format!("fake-{}", kind.as_str());
        assert_eq!(
            instantiate_in(&t, Policy::Any, &id, &Params::new())
                .unwrap()
                .kind(),
            kind
        );
    }
}

#[test]
fn stateful_sign_persists_before_release_and_never_reuses_a_state() {
    let t = table(Tier::Safe);
    let s = new_statefulsign_in(&t, Policy::Any, "fake-statefulsign", &Params::new()).unwrap();
    let (pk, mut key) = s.keygen(&mut FixedEntropy::new(&[9])).unwrap();
    assert_eq!(s.remaining(&key).unwrap(), 3);
    // persist failure: no signature, state unchanged
    let mut fail = |_: &[u8]| -> Result<()> { Err(Error::PersistFailed) };
    assert_eq!(s.sign(&mut key, b"m", &mut fail), Err(Error::PersistFailed));
    assert_eq!(s.remaining(&key).unwrap(), 3);
    // the state handed to persist is the advanced one, and each signature differs
    let mut stored: Vec<Vec<u8>> = Vec::new();
    let mut sigs = Vec::new();
    for _ in 0..3 {
        let mut keep = |b: &[u8]| -> Result<()> {
            stored.push(b.to_vec());
            Ok(())
        };
        let sig = s.sign(&mut key, b"m", &mut keep).unwrap();
        assert!(s.verify(&pk, b"m", &sig).unwrap());
        sigs.push(sig);
    }
    assert_eq!(stored.len(), 3);
    assert_ne!(sigs[0], sigs[1]);
    assert_eq!(s.remaining(&key).unwrap(), 0);
    let mut never = |_: &[u8]| -> Result<()> { panic!("persist called for an exhausted key") };
    assert_eq!(s.sign(&mut key, b"m", &mut never), Err(Error::KeyExhausted));
}

#[test]
fn pke_pake_threshold_vdf_he_contracts() {
    let t = table(Tier::Safe);
    let mut rng = FixedEntropy::new(&[7; 64]);
    // Pke: uniform decrypt failure, bounds enforced
    let p = new_pke_in(&t, Policy::Any, "fake-pke", &Params::new()).unwrap();
    let (pk, sk) = p.keygen(&mut rng).unwrap();
    let ct = p.encrypt(&pk, b"hello", b"lbl", &mut rng).unwrap();
    assert_eq!(&p.decrypt(&sk, &ct, b"lbl").unwrap()[..], b"hello");
    assert_eq!(p.decrypt(&sk, &ct, b"other"), Err(Error::AuthenticationFailed));
    assert!(p.encrypt(&pk, &[0; 33], b"", &mut rng).is_err());
    // Pake: both parties finish with the same secret; a wrong message ends the exchange
    let k = new_pake_in(&t, Policy::Any, "fake-pake", &Params::new()).unwrap();
    let (a, m1) = k.start(PakeRole::Initiator, b"pw", b"ctx", &mut rng).unwrap();
    let (b, m0) = k.start(PakeRole::Responder, b"pw", b"ctx", &mut rng).unwrap();
    assert!(m0.is_empty());
    let PakeStep::Done(sb, Some(m2)) = b.step(&m1).unwrap() else { panic!("responder") };
    let PakeStep::Done(sa, None) = a.step(&m2).unwrap() else { panic!("initiator") };
    assert_eq!(sa, sb);
    let (a2, _) = k.start(PakeRole::Initiator, b"pw", b"ctx", &mut rng).unwrap();
    assert!(matches!(a2.step(b"junk"), Err(Error::ProtocolAborted(_))));
    assert!(k.start(PakeRole::Initiator, b"", b"", &mut rng).is_err());
    // Threshold: 1 <= t <= n <= max enforced, party ids validated
    let th = new_threshold_in(&t, Policy::Any, "fake-threshold", &Params::new()).unwrap();
    for (tt, n) in [(0, 3), (4, 3), (1, 9)] {
        assert!(th.split(b"s", tt, n, &mut rng).is_err(), "{tt}/{n}");
    }
    let shares = th.split(b"secret", 2, 3, &mut rng).unwrap();
    assert_eq!(&th.combine(&shares[..2]).unwrap()[..], b"secret");
    assert!(th.combine(&shares[..1]).is_err());
    let sess = |party| ThresholdSession {
        op: nextssl_core::ThresholdOp::Dkg,
        party,
        t: 2,
        n: 3,
        input: vec![],
    };
    assert!(matches!(
        th.start(&sess(0), &mut rng),
        Err(Error::ProtocolAborted(_))
    ));
    assert!(matches!(
        th.start(&sess(4), &mut rng),
        Err(Error::ProtocolAborted(_))
    ));
    // Vdf: t cap
    let v = new_vdf_in(&t, Policy::Any, "fake-vdf", &Params::new()).unwrap();
    let (o, pr) = v.eval(b"c", 10).unwrap();
    assert!(v.verify(b"c", 10, &o, &pr).unwrap());
    assert!(!v.verify(b"c", 11, &o, &pr).unwrap());
    assert_eq!(v.eval(b"c", 0), Err(Error::ParamOutOfRange("t")));
    assert_eq!(v.eval(b"c", 1001), Err(Error::ParamOutOfRange("t")));
    // He: undeclared op is an error
    let h = new_he_in(&t, Policy::Any, "fake-he", &Params::new()).unwrap();
    let keys = h.keygen(&[], &mut FixedEntropy::new(&[0])).unwrap();
    let c1 = h.encrypt(&keys.public, &[3], &mut rng).unwrap();
    assert_eq!(
        h.eval(HeOp::Mul, &[&c1, &c1], &keys.eval),
        Err(Error::Unsupported)
    );
    assert!(h.eval(HeOp::Add, &[&c1], &keys.eval).is_err());
    let sum = h.eval(HeOp::Add, &[&c1, &c1], &keys.eval).unwrap();
    assert_eq!(&h.decrypt(&keys.secret, &sum).unwrap()[..], &[6]);
}
