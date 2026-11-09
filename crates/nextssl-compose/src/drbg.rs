//! `hmac-drbg(<digest>)`, `hash-drbg(<digest>)`, `ctr-drbg(aes-128|aes-192|aes-256)`:
//! NIST SP 800-90A Rev. 1 mechanisms over any selectable digest or AES.
//!
//! **Provenance (rule 1 port exception, deviation recorded in `upstream/ORIGIN.md`):** no
//! upstream crate offers these generic over RustCrypto digest 0.11 types (the `hmac-drbg` crate
//! needs digest 0.9; there is no Hash_DRBG crate; `libcrux-hmac-drbg` is SHA-256 only). The state
//! machines below follow SP 800-90A sections 10.1.2, 10.1.1 and 10.2 line by line; every hash,
//! HMAC and block-cipher call goes to the upstream generics or the registered AES. They are
//! therefore tier `unverified` (root API only) until an independent review. KATs: NIST CAVP
//! `drbgtestvectors` (no-reseed set).
//!
//! Limits (explicit errors, nothing truncated): entropy input `strength/8 ..= 1024` bytes,
//! nonce `strength/16 ..= 128` bytes, personalization and additional input `0 ..= 65536`,
//! request `1 ..= 65536` bytes (2^19 bits), reseed interval 2^48 generate calls.
//! Security strength is the largest of 256/192/128/112 bits not above the digest output size.

use hmac::digest::Digest;
use hmac::{Hmac, Mac};
use nextssl_core::{
    BlockCipher, Drbg, Error, KeyedBlockCipher, Len, Params, Result, Sizes, SymmetricKey, Zeroize,
    Zeroizing,
};
use nextssl_registry::{all, new_blockcipher_in, Policy};

use crate::mac::digest_len;

const ENTROPY_MAX: usize = 1024;
const NONCE_MAX: usize = 128;
const AUX_MAX: usize = 65_536;
const REQ_MAX: usize = 65_536;
const INTERVAL: u64 = 1 << 48;

fn strength_for(out_bits: usize) -> Result<usize> {
    [256, 192, 128, 112]
        .into_iter()
        .find(|s| out_bits >= *s)
        .ok_or(Error::Unsupported)
}

fn entropy_range(strength: usize) -> Len {
    Len::range(strength / 8, ENTROPY_MAX)
}

fn nonce_range(strength: usize) -> Len {
    Len::range(strength / 16, NONCE_MAX)
}

fn hmac_parts(digest: &str, key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>> {
    with_digest!(digest, D => {
        let mut mac = <Hmac<D> as hmac::KeyInit>::new_from_slice(key)
            .map_err(|_| Error::Backend("hmac key setup"))?;
        for p in parts {
            Mac::update(&mut mac, p);
        }
        let mut full = mac.finalize().into_bytes();
        let out = Zeroizing::new(full.as_slice().to_vec());
        full.as_mut_slice().zeroize();
        Ok(out)
    })
}

fn hash_parts(digest: &str, parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>> {
    with_digest!(digest, D => {
        let mut h = <D as Digest>::new();
        for p in parts {
            Digest::update(&mut h, p);
        }
        let mut full = Digest::finalize(h);
        let out = Zeroizing::new(full.as_slice().to_vec());
        full.as_mut_slice().zeroize();
        Ok(out)
    })
}

// ---- HMAC_DRBG (SP 800-90A section 10.1.2) ----------------------------------------------

struct HmacState {
    k: Zeroizing<Vec<u8>>,
    v: Zeroizing<Vec<u8>>,
    counter: u64,
}

pub struct HmacDrbg {
    digest: &'static str,
    outlen: usize,
    strength: usize,
    st: Option<HmacState>,
}

impl HmacDrbg {
    pub fn new(digest: &'static str) -> Result<Self> {
        let outlen = digest_len(digest)?;
        Ok(Self {
            digest,
            outlen,
            strength: strength_for(outlen * 8)?,
            st: None,
        })
    }

    /// HMAC_DRBG_Update.
    fn update(&self, st: &mut HmacState, data: &[&[u8]]) -> Result<()> {
        let rounds = if data.iter().any(|d| !d.is_empty()) {
            2
        } else {
            1
        };
        for round in 0..rounds {
            let tag = [round as u8];
            let mut parts: Vec<&[u8]> = vec![st.v.as_slice(), &tag];
            parts.extend_from_slice(data);
            let nk = hmac_parts(self.digest, st.k.as_slice(), &parts)?;
            st.k = nk;
            let nv = hmac_parts(self.digest, st.k.as_slice(), &[st.v.as_slice()])?;
            st.v = nv;
        }
        Ok(())
    }
}

impl Drbg for HmacDrbg {
    fn sizes(&self) -> Sizes {
        Sizes {
            seed: Some(entropy_range(self.strength)),
            ..Sizes::NONE
        }
    }

    fn security_strength(&self) -> usize {
        self.strength
    }

    fn max_request_len(&self) -> usize {
        REQ_MAX
    }

    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<()> {
        entropy_range(self.strength).check("entropy", entropy.len())?;
        nonce_range(self.strength).check("nonce", nonce.len())?;
        Len::range(0, AUX_MAX).check("personalization", personalization.len())?;
        let mut st = HmacState {
            k: Zeroizing::new(vec![0x00; self.outlen]),
            v: Zeroizing::new(vec![0x01; self.outlen]),
            counter: 1,
        };
        self.update(&mut st, &[entropy, nonce, personalization])?;
        self.st = Some(st);
        Ok(())
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()> {
        entropy_range(self.strength).check("entropy", entropy.len())?;
        Len::range(0, AUX_MAX).check("additional", additional.len())?;
        let mut st = self.st.take().ok_or(Error::NotInstantiated)?;
        let r = self.update(&mut st, &[entropy, additional]);
        if r.is_ok() {
            st.counter = 1;
        }
        self.st = Some(st);
        r
    }

    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()> {
        let mut st = self.st.take().ok_or(Error::NotInstantiated)?;
        let r = (|| {
            Len::range(1, REQ_MAX).check("request", out.len())?;
            Len::range(0, AUX_MAX).check("additional", additional.len())?;
            if st.counter > INTERVAL {
                return Err(Error::ReseedRequired);
            }
            if !additional.is_empty() {
                self.update(&mut st, &[additional])?;
            }
            for chunk in out.chunks_mut(self.outlen) {
                let nv = hmac_parts(self.digest, st.k.as_slice(), &[st.v.as_slice()])?;
                st.v = nv;
                chunk.copy_from_slice(&st.v[..chunk.len()]);
            }
            self.update(&mut st, &[additional])?;
            st.counter += 1;
            Ok(())
        })();
        self.st = Some(st);
        r
    }

    fn uninstantiate(&mut self) {
        self.st = None;
    }
}

// ---- Hash_DRBG (SP 800-90A section 10.1.1) ----------------------------------------------

/// Zeroizing byte string.
type Secret = Zeroizing<Vec<u8>>;

struct HashState {
    v: Zeroizing<Vec<u8>>,
    c: Zeroizing<Vec<u8>>,
    counter: u64,
}

pub struct HashDrbg {
    digest: &'static str,
    outlen: usize,
    seedlen: usize,
    strength: usize,
    st: Option<HashState>,
}

/// `v = (v + addend) mod 2^(8 * v.len())`, big endian; `addend` may be shorter than `v`.
fn add_be(v: &mut [u8], addend: &[u8]) {
    let mut carry = 0u16;
    let n = v.len();
    for i in 0..n {
        let a = if i < addend.len() {
            addend[addend.len() - 1 - i]
        } else {
            0
        };
        let idx = n - 1 - i;
        let s = u16::from(v[idx]) + u16::from(a) + carry;
        v[idx] = (s & 0xff) as u8;
        carry = s >> 8;
    }
}

impl HashDrbg {
    pub fn new(digest: &'static str) -> Result<Self> {
        let outlen = digest_len(digest)?;
        Ok(Self {
            digest,
            outlen,
            // Table 2 of SP 800-90A: 440 bits up to SHA-256, 888 bits above.
            seedlen: if outlen * 8 <= 256 { 55 } else { 111 },
            strength: strength_for(outlen * 8)?,
            st: None,
        })
    }

    /// Hash_df over the concatenation of `parts`, returning `n` bytes.
    fn hash_df(&self, parts: &[&[u8]], n: usize) -> Result<Zeroizing<Vec<u8>>> {
        let bits = ((n * 8) as u32).to_be_bytes();
        let mut out = Zeroizing::new(Vec::with_capacity(n + self.outlen));
        for counter in 1..=n.div_ceil(self.outlen) {
            let c = [counter as u8];
            let mut p: Vec<&[u8]> = vec![&c, &bits];
            p.extend_from_slice(parts);
            out.extend_from_slice(&hash_parts(self.digest, &p)?);
        }
        out.truncate(n);
        Ok(out)
    }

    fn seed(&self, parts: &[&[u8]]) -> Result<(Secret, Secret)> {
        let v = self.hash_df(parts, self.seedlen)?;
        let c = self.hash_df(&[&[0x00], v.as_slice()], self.seedlen)?;
        Ok((v, c))
    }
}

impl Drbg for HashDrbg {
    fn sizes(&self) -> Sizes {
        Sizes {
            seed: Some(entropy_range(self.strength)),
            ..Sizes::NONE
        }
    }

    fn security_strength(&self) -> usize {
        self.strength
    }

    fn max_request_len(&self) -> usize {
        REQ_MAX
    }

    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<()> {
        entropy_range(self.strength).check("entropy", entropy.len())?;
        nonce_range(self.strength).check("nonce", nonce.len())?;
        Len::range(0, AUX_MAX).check("personalization", personalization.len())?;
        let (v, c) = self.seed(&[entropy, nonce, personalization])?;
        self.st = Some(HashState { v, c, counter: 1 });
        Ok(())
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()> {
        entropy_range(self.strength).check("entropy", entropy.len())?;
        Len::range(0, AUX_MAX).check("additional", additional.len())?;
        let old = self.st.as_ref().ok_or(Error::NotInstantiated)?;
        let (v, c) = self.seed(&[&[0x01], old.v.as_slice(), entropy, additional])?;
        self.st = Some(HashState { v, c, counter: 1 });
        Ok(())
    }

    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()> {
        Len::range(1, REQ_MAX).check("request", out.len())?;
        Len::range(0, AUX_MAX).check("additional", additional.len())?;
        let mut st = self.st.take().ok_or(Error::NotInstantiated)?;
        let r = (|| {
            if st.counter > INTERVAL {
                return Err(Error::ReseedRequired);
            }
            if !additional.is_empty() {
                let w = hash_parts(self.digest, &[&[0x02], st.v.as_slice(), additional])?;
                add_be(&mut st.v, &w);
            }
            // Hashgen
            let mut data = st.v.clone();
            for chunk in out.chunks_mut(self.outlen) {
                let h = hash_parts(self.digest, &[data.as_slice()])?;
                chunk.copy_from_slice(&h[..chunk.len()]);
                add_be(&mut data, &[1]);
            }
            let h = hash_parts(self.digest, &[&[0x03], st.v.as_slice()])?;
            add_be(&mut st.v, &h);
            let c = st.c.clone();
            add_be(&mut st.v, &c);
            add_be(&mut st.v, &st.counter.to_be_bytes());
            st.counter += 1;
            Ok(())
        })();
        self.st = Some(st);
        r
    }

    fn uninstantiate(&mut self) {
        self.st = None;
    }
}

// ---- CTR_DRBG (SP 800-90A section 10.2) -------------------------------------------------

const BLK: usize = 16;

struct CtrState {
    key: Zeroizing<Vec<u8>>,
    v: Zeroizing<Vec<u8>>,
    counter: u64,
}

pub struct CtrDrbg {
    bc: Box<dyn BlockCipher>,
    keylen: usize,
    seedlen: usize,
    df: bool,
    st: Option<CtrState>,
}

fn inc_be(v: &mut [u8]) {
    for b in v.iter_mut().rev() {
        let (n, carry) = b.overflowing_add(1);
        *b = n;
        if !carry {
            break;
        }
    }
}

impl CtrDrbg {
    /// `aes_id` is `aes-128`, `aes-192` or `aes-256`; `df` selects the derivation function.
    pub fn new(aes_id: &'static str, df: bool) -> Result<Self> {
        let keylen = match aes_id {
            "aes-128" => 16,
            "aes-192" => 24,
            "aes-256" => 32,
            _ => return Err(Error::Unsupported),
        };
        let bc = new_blockcipher_in(all(), Policy::Any, aes_id, &Params::new())?;
        Ok(Self {
            bc,
            keylen,
            seedlen: keylen + BLK,
            df,
            st: None,
        })
    }

    fn keyed(&self, key: &[u8]) -> Result<Box<dyn KeyedBlockCipher>> {
        let k = SymmetricKey::from_bytes(key, Len::fixed(self.keylen))?;
        self.bc.keyed(&k)
    }

    fn strength(&self) -> usize {
        self.keylen * 8
    }

    /// BCC over `data` (a multiple of 16 bytes).
    fn bcc(kb: &dyn KeyedBlockCipher, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut chain = Zeroizing::new(vec![0u8; BLK]);
        for block in data.chunks(BLK) {
            for (c, d) in chain.iter_mut().zip(block) {
                *c ^= d;
            }
            kb.encrypt_block(&mut chain)?;
        }
        Ok(chain)
    }

    /// Block_Cipher_df over `input`, returning `n` bytes.
    fn block_df(&self, input: &[u8], n: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut s = Zeroizing::new(Vec::with_capacity(input.len() + 16 + BLK));
        s.extend_from_slice(&(input.len() as u32).to_be_bytes());
        s.extend_from_slice(&(n as u32).to_be_bytes());
        s.extend_from_slice(input);
        s.push(0x80);
        while s.len() % BLK != 0 {
            s.push(0);
        }
        let k0: Vec<u8> = (0..self.keylen as u8).collect();
        let kb0 = self.keyed(&k0)?;
        let mut temp = Zeroizing::new(Vec::with_capacity(self.seedlen + BLK));
        let mut i: u32 = 0;
        while temp.len() < self.seedlen {
            let mut chunk = Zeroizing::new(Vec::with_capacity(BLK + s.len()));
            chunk.extend_from_slice(&i.to_be_bytes());
            chunk.extend_from_slice(&[0u8; BLK - 4]);
            chunk.extend_from_slice(&s);
            temp.extend_from_slice(&Self::bcc(&*kb0, &chunk)?);
            i += 1;
        }
        let kb = self.keyed(&temp[..self.keylen])?;
        let mut x = Zeroizing::new(temp[self.keylen..self.seedlen].to_vec());
        let mut out = Zeroizing::new(Vec::with_capacity(n + BLK));
        while out.len() < n {
            kb.encrypt_block(&mut x)?;
            out.extend_from_slice(&x);
        }
        out.truncate(n);
        Ok(out)
    }

    /// CTR_DRBG_Update with `provided` of exactly `seedlen` bytes.
    fn update(&self, st: &mut CtrState, provided: &[u8]) -> Result<()> {
        let kb = self.keyed(&st.key)?;
        let mut temp = Zeroizing::new(Vec::with_capacity(self.seedlen + BLK));
        while temp.len() < self.seedlen {
            inc_be(&mut st.v);
            let mut blk = Zeroizing::new(st.v.to_vec());
            kb.encrypt_block(&mut blk)?;
            temp.extend_from_slice(&blk);
        }
        temp.truncate(self.seedlen);
        for (t, p) in temp.iter_mut().zip(provided) {
            *t ^= p;
        }
        st.key = Zeroizing::new(temp[..self.keylen].to_vec());
        st.v = Zeroizing::new(temp[self.keylen..].to_vec());
        Ok(())
    }

    /// `seedlen` bytes of seed material from entropy and the optional strings.
    fn material(&self, entropy: &[u8], nonce: &[u8], aux: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.df {
            let mut input =
                Zeroizing::new(Vec::with_capacity(entropy.len() + nonce.len() + aux.len()));
            input.extend_from_slice(entropy);
            input.extend_from_slice(nonce);
            input.extend_from_slice(aux);
            self.block_df(&input, self.seedlen)
        } else {
            Len::fixed(self.seedlen).check("entropy", entropy.len())?;
            Len::fixed(0).check("nonce", nonce.len())?;
            Len::range(0, self.seedlen).check("personalization", aux.len())?;
            let mut m = Zeroizing::new(entropy.to_vec());
            for (a, b) in m.iter_mut().zip(aux) {
                *a ^= b;
            }
            Ok(m)
        }
    }
}

impl Drbg for CtrDrbg {
    fn sizes(&self) -> Sizes {
        let seed = if self.df {
            Len::range(self.keylen, ENTROPY_MAX)
        } else {
            Len::fixed(self.seedlen)
        };
        Sizes {
            seed: Some(seed),
            ..Sizes::NONE
        }
    }

    fn security_strength(&self) -> usize {
        self.strength()
    }

    fn max_request_len(&self) -> usize {
        REQ_MAX
    }

    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<()> {
        if self.df {
            Len::range(self.keylen, ENTROPY_MAX).check("entropy", entropy.len())?;
            Len::range(self.keylen / 2, NONCE_MAX).check("nonce", nonce.len())?;
            Len::range(0, AUX_MAX).check("personalization", personalization.len())?;
        }
        let m = self.material(entropy, nonce, personalization)?;
        let mut st = CtrState {
            key: Zeroizing::new(vec![0u8; self.keylen]),
            v: Zeroizing::new(vec![0u8; BLK]),
            counter: 1,
        };
        self.update(&mut st, &m)?;
        self.st = Some(st);
        Ok(())
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()> {
        if self.df {
            Len::range(self.keylen, ENTROPY_MAX).check("entropy", entropy.len())?;
            Len::range(0, AUX_MAX).check("additional", additional.len())?;
        }
        let mut st = self.st.take().ok_or(Error::NotInstantiated)?;
        let r = self
            .material(entropy, &[], additional)
            .and_then(|m| self.update(&mut st, &m));
        if r.is_ok() {
            st.counter = 1;
        }
        self.st = Some(st);
        r
    }

    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()> {
        let mut st = self.st.take().ok_or(Error::NotInstantiated)?;
        let r = (|| {
            Len::range(1, REQ_MAX).check("request", out.len())?;
            if self.df {
                Len::range(0, AUX_MAX).check("additional", additional.len())?;
            } else {
                Len::range(0, self.seedlen).check("additional", additional.len())?;
            }
            if st.counter > INTERVAL {
                return Err(Error::ReseedRequired);
            }
            let mut add = Zeroizing::new(vec![0u8; self.seedlen]);
            if !additional.is_empty() {
                add = if self.df {
                    self.block_df(additional, self.seedlen)?
                } else {
                    let mut p = Zeroizing::new(vec![0u8; self.seedlen]);
                    p[..additional.len()].copy_from_slice(additional);
                    p
                };
                self.update(&mut st, &add)?;
            }
            let kb = self.keyed(&st.key)?;
            for chunk in out.chunks_mut(BLK) {
                inc_be(&mut st.v);
                let mut blk = Zeroizing::new(st.v.to_vec());
                kb.encrypt_block(&mut blk)?;
                chunk.copy_from_slice(&blk[..chunk.len()]);
            }
            self.update(&mut st, &add)?;
            st.counter += 1;
            Ok(())
        })();
        self.st = Some(st);
        r
    }

    fn uninstantiate(&mut self) {
        self.st = None;
    }
}
