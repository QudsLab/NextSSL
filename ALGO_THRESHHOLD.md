# Threshold Cryptography — Full Algorithm Reference
### NextSSL · All 36 Algorithms Explained for Crypto Learners

> **How to read this guide**
> Every entry follows the same pattern: what it is, the math that drives it, how it actually works step by step, and a full parameter table — including internal parameters that libraries usually hide from you. Nothing is skipped.

---

## Table of Contents

| # | Name | Category | What it does |
|---|------|----------|--------------|
| 1 | [frost](#1-frost) | Threshold Schnorr | Distributed Schnorr signature |
| 2 | [tbla](#2-tbla) | Threshold BLS | Distributed BLS signature |
| 3 | [gargos](#3-gargos) | Threshold Schnorr | Distributed Schnorr (alt protocol) |
| 4 | [tecla](#4-tecla) | Threshold ECDSA | 2-party ECDSA |
| 5 | [the-clash](#5-the-clash) | Threshold ECDSA | n-party ECDSA |
| 6 | [classic-schnorr](#6-classic-schnorr) | Threshold Schnorr | Classic threshold Schnorr |
| 7 | [bam](#7-bam) | 2-party ECDSA | Batched 2-party ECDSA |
| 8 | [ccgmp](#8-ccgmp) | n-party ECDSA | General n-party ECDSA |
| 9 | [haystack](#9-haystack) | Threshold HBS | Threshold hash-based signatures |
| 10 | [mithril](#10-mithril) | Threshold ML-DSA | Threshold Dilithium/CRYSTALS |
| 11 | [quorus](#11-quorus) | Threshold ML-DSA | Alt threshold Dilithium |
| 12 | [redeta](#12-redeta) | Threshold ECDLP | Threshold ECDLP signatures |
| 13 | [splitkey](#13-splitkey) | Server-assisted | Threshold sign + PKE |
| 14 | [minimpc](#14-minimpc) | MPC Symmetric | Threshold AES/SHA/MAC |
| 15 | [maestro](#15-maestro) | MPC Symmetric | T-AES / T-SHA / T-MAC |
| 16 | [amber](#16-amber) | Threshold KEM | Threshold lattice KEM |
| 17 | [hermine](#17-hermine) | Threshold Sign | Threshold lattice sign |
| 18 | [least](#18-least) | Threshold Sign | Code-based group actions |
| 19 | [tanuki](#19-tanuki) | Threshold Sign | Threshold lattice signature |
| 20 | [vinaigrette](#20-vinaigrette) | Threshold Sign | Threshold UOV + MAYO |
| 21 | [pantheria](#21-pantheria) | FHE | RLWE-FHE + Threshold FHE |
| 22 | [zama-tfhe](#22-zama-tfhe) | FHE | TFHE + Threshold FHE |
| 23 | [zama-zhenith](#23-zama-zhenith) | ZKP | Zero-Knowledge Proofs |
| 24 | [piver](#24-piver) | VSS | Verifiable Secret Sharing |
| 25 | [schmivitz](#25-schmivitz) | ZKPoK | VOLEith-based ZK proof of knowledge |
| 26 | [smallwood](#26-smallwood) | ZKPoK | Hash-based ZK proof of knowledge |
| 27 | [shamir](#27-shamir) | Secret Sharing | Shamir's Secret Sharing |
| 28 | [feldman-vss](#28-feldman-vss) | VSS | Feldman VSS |
| 29 | [pedersen-vss](#29-pedersen-vss) | VSS | Pedersen VSS |
| 30 | [dkg](#30-dkg) | DKG | Distributed Key Generation |
| 31 | [pvss](#31-pvss) | PVSS | Publicly Verifiable Secret Sharing |
| 32 | [ot](#32-ot) | MPC Primitive | Oblivious Transfer |
| 33 | [vole](#33-vole) | MPC Primitive | Vector Oblivious Linear Evaluation |
| 34 | [beaver](#34-beaver) | MPC Primitive | Beaver Triples |
| 35 | [mpc-ecdsa](#35-mpc-ecdsa) | Generic MPC | MPC ECDSA surface |
| 36 | [mpc-schnorr](#36-mpc-schnorr) | Generic MPC | MPC Schnorr surface |

---

## Quick Concept Primer

Before diving in, here are terms that appear everywhere:

**Threshold (t-of-n):** A secret is split among `n` parties. Any `t` of them together can reconstruct it or produce a signature. Fewer than `t` parties learn nothing useful.

**Shard / Share:** One piece of a split secret held by one party.

**Commitment:** A value you publish that locks you into a choice, without revealing what that choice is. Like a sealed envelope.

**Nonce:** A number used exactly once. Critical for signature security — reusing nonces leaks private keys.

**Group G, Generator G:** In elliptic curve math, `G` is a fixed starting point. Multiplying it by a number `x` gives a point `xG`. Going backwards — finding `x` from `xG` — is the hard problem (ECDLP).

---

## 1. `frost`

### Flexible Round-Optimized Schnorr Threshold Signatures

**What it solves:** You have `n` parties each holding a shard of a private key. You want any `t` of them to produce a valid Schnorr signature — without any one party ever holding the full private key and without a trusted dealer.

**Core equation:**

A Schnorr signature on message `m` is a pair `(R, s)` where:

```
R = k · G                          (commitment point, k = nonce)
e = H(R || pubkey || m)            (challenge hash)
s = k + e · x    (mod q)           (response, x = private key)
```

Verification: check that `s·G == R + e·pubkey`

In FROST, the private key `x` is split using Shamir's Secret Sharing (see entry 27). The nonce `k` is also split. Each party contributes a partial nonce and a partial response, and these are combined:

```
s = Σᵢ sᵢ  (mod q)
```

where each `sᵢ = kᵢ + e · λᵢ · xᵢ` and `λᵢ` is the Lagrange coefficient that weights each party's contribution correctly.

**How it works — step by step:**

1. **Setup:** Using DKG (entry 30), each of `n` parties gets a secret share `xᵢ` of the private key `x`. The group public key `X = x·G` is known to everyone.
2. **Preprocessing (Round 1):** Each participant generates two nonce pairs `(dᵢ, eᵢ)` and broadcasts commitments `(Dᵢ, Eᵢ) = (dᵢ·G, eᵢ·G)`. These can be stored and reused for many future signing sessions.
3. **Signing starts:** A coordinator picks `t` participants and broadcasts the message `m` and everyone's commitments `{Dᵢ, Eᵢ}`.
4. **Binding factor (Round 2):** Each participant computes a per-session binding factor `ρᵢ = H(i, m, {Dⱼ, Eⱼ})`. This prevents a particular attack called "Wagner's attack" where a malicious party could manipulate the combined nonce.
5. **Group nonce:** `R = Σᵢ (Dᵢ + ρᵢ · Eᵢ)` — a single combined point.
6. **Challenge:** `e = H(R || X || m)`
7. **Partial responses:** Each participant computes `sᵢ = dᵢ + (eᵢ · ρᵢ) + λᵢ · xᵢ · e`
8. **Aggregation:** Combine: `s = Σᵢ sᵢ`. Output signature `(R, s)`.
9. **Verify:** Standard Schnorr verification — `s·G == R + e·X`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n` | Setup | Total number of parties | Defines the group size |
| `t` | Setup | Threshold (minimum signers) | t-of-n policy |
| `q` | Protocol | Prime order of elliptic curve group | All math happens mod q |
| `G` | Protocol | Generator point on curve | The base point for EC math |
| `xᵢ` | Each party (private) | Secret key share | Never leaves the party |
| `X` | Public | Group public key = x·G | Used to verify signatures |
| `dᵢ, eᵢ` | Each party (internal) | Per-session nonce pair | Ephemeral randomness — must never repeat |
| `Dᵢ, Eᵢ` | Each party (public) | Nonce commitments | Shared before signing |
| `ρᵢ` | Computed | Binding factor | Ties nonces to this specific session to prevent Wagner attack |
| `λᵢ` | Computed | Lagrange interpolation coefficient | Weights each share so they combine to the real answer |
| `e` | Computed | Challenge hash | Binds signature to message, public key, and nonce |
| Hash `H` | Protocol | Cryptographic hash function (SHA-256 / SHA-3) | Must be collision-resistant |
| Curve | Protocol | e.g. secp256k1, Ed25519 | Defines G, q, and security level |

---

## 2. `tbla`

### Threshold BLS Signatures

**What it solves:** Same goal as FROST — `t`-of-`n` distributed signing — but using BLS (Boneh–Lynn–Shacham) signatures. BLS signatures have a superpower: they can be **aggregated**. Many signatures on the same message can be merged into one tiny combined signature that any verifier can check.

**Core equation:**

BLS relies on **pairing functions** — a special mathematical operation on points from two different elliptic curve groups:

```
e(P, Q) → target group element
```

A BLS signature is simply:
```
σ = x · H(m)     (private key x, hash-to-curve of message)
```

Verification uses a pairing:
```
e(σ, G) == e(H(m), X)
```
where `X = x·G` is the public key.

For threshold BLS:
```
σᵢ = xᵢ · H(m)    (each party's partial signature)
σ  = Σᵢ λᵢ · σᵢ   (combine using Lagrange, result is the full signature)
```

The beauty: each `σᵢ` is just a curve point. Aggregation is a single point addition.

**How it works — step by step:**

1. **Setup:** Private key `x` is split into `n` shares using Shamir (entry 27). Each party `i` holds `xᵢ`.
2. **Hash to curve:** Everyone computes `H(m)` — mapping the message to a point on a specific elliptic curve (BLS12-381 is common).
3. **Partial sign:** Each party computes `σᵢ = xᵢ · H(m)`.
4. **Partial verify (optional but good practice):** Verify `e(σᵢ, G) == e(H(m), Xᵢ)` using each party's individual public key `Xᵢ = xᵢ·G`.
5. **Aggregate:** The combiner picks `t` valid partial signatures and computes `σ = Σᵢ λᵢ · σᵢ`.
6. **Final verify:** `e(σ, G) == e(H(m), X)`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n` | Setup | Party count | Group size |
| `t` | Setup | Threshold | Min signers needed |
| `xᵢ` | Each party (private) | Key share | Never revealed |
| `X` | Public | Group public key | For final verification |
| `Xᵢ` | Public | Individual public key per party | For partial verification |
| `H(m)` | Computed | Hash-to-curve of message | Must map uniformly to curve points |
| `σᵢ` | Each party | Partial signature (a curve point) | Combined to form final sig |
| `λᵢ` | Computed | Lagrange coefficient | Weighted recombination |
| `G` | Protocol | Generator in G₁ (BLS12-381) | Base point for public keys |
| Pairing `e` | Protocol | Bilinear map G₁×G₂→Gₜ | The core cryptographic primitive |
| Curve | Protocol | BLS12-381 (usually) | Chosen for efficient pairings |
| Hash-to-field | Protocol | Cofactor-clearing hash (RFC 9380) | Safe deterministic point derivation |

---

## 3. `gargos`

### Alternative Threshold Schnorr Signature Protocol

**What it solves:** Same as FROST — threshold Schnorr signatures — but uses a different internal protocol structure. Where FROST focuses on minimal rounds and preprocessing, GARGOS may explore different trade-offs in communication cost, identifiable aborts (knowing which party misbehaved), or robustness under network failures.

**Core equation:**

Identical Schnorr base:
```
R = k·G,   e = H(R || X || m),   s = k + e·x  (mod q)
```

The difference lives in **how the distributed nonce `k` is computed and how the binding to the session is handled.** GARGOS-style protocols often use a different nonce derivation or a different commitment scheme to enforce honest behavior.

A common variant uses **verifiable nonces** with Feldman commitments (see entry 28):
```
kᵢ generated locally, Kᵢ = kᵢ·G published as commitment
K = Σᵢ Kᵢ  (group nonce point = R)
```

**How it works — step by step:**

1. **Key setup:** Each party holds share `xᵢ` from DKG.
2. **Nonce commitment round:** Each participant picks a random nonce `kᵢ`, publishes `Kᵢ = kᵢ·G`.
3. **Nonce aggregation:** `R = K = Σᵢ Kᵢ`.
4. **Challenge:** `e = H(R || X || m)`.
5. **Response:** Each party sends `sᵢ = kᵢ + e · λᵢ · xᵢ`.
6. **Combine:** `s = Σᵢ sᵢ`. Signature is `(R, s)`.

The key difference from FROST: GARGOS may add an additional round where parties prove their nonces are well-formed (using a ZKP), or uses a different binding mechanism.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n`, `t` | Setup | Group size, threshold | Same as FROST |
| `xᵢ` | Party private | Key share | Never exposed |
| `kᵢ` | Party internal | Ephemeral nonce | One-time use — reuse is catastrophic |
| `Kᵢ = kᵢ·G` | Party public | Nonce commitment | Proves commitment without revealing kᵢ |
| `R = ΣKᵢ` | Computed | Aggregated nonce point | Used in challenge |
| `e` | Computed | Challenge hash | Binds to session |
| `sᵢ` | Party output | Partial response | Combined to form final s |
| `λᵢ` | Computed | Lagrange weight | Correct recombination |
| ZKP (optional) | Internal | Proof that nonce is well-formed | Prevents rogue nonce attacks |

---

## 4. `tecla`

### 2-Party Threshold ECDSA

**What it solves:** ECDSA (used in Bitcoin, Ethereum, TLS) is notoriously hard to distribute because its signing equation involves a **modular inverse** that couples the nonce and private key in a non-linear way. TECLA solves this for exactly 2 parties: a user and a server must both cooperate to sign — neither can sign alone.

**Why ECDSA is harder than Schnorr:**

Schnorr: `s = k + e·x` — linear, easy to split.
ECDSA: `s = k⁻¹ · (H(m) + r·x)  (mod q)` — that `k⁻¹` (modular inverse of k) makes naive splitting impossible.

**Core trick — multiplicative-to-additive (MtA) conversion:**

To compute `k⁻¹ · x` without either party knowing `k` or `x` fully, the protocol uses **Paillier encryption** (a homomorphic encryption scheme):

```
Party 1 has k₁, x₁
Party 2 has k₂, x₂

k = k₁ · k₂  (mod q)   ← multiplicative sharing
x = x₁ + x₂  (mod q)   ← additive sharing
```

The homomorphic property lets party 2 compute on an encryption of `k₁` and `x₁` without decrypting them.

**How it works — step by step:**

1. **Key generation:** Party 1 samples `x₁`, Party 2 samples `x₂`. Public key `X = (x₁+x₂)·G`. Each party never knows the other's share.
2. **Nonce generation:** Party 1 picks `k₁`, Party 2 picks `k₂`. `R = k·G = k₁·k₂·G`. Compute `r = R.x mod q`.
3. **MtA phase:** Convert multiplicative sharing of `k` to additive sharing of `k⁻¹·x` using Paillier homomorphic encryption. This is the expensive communication round.
4. **Response:** Each party computes a partial `sᵢ`. Combined: `s = s₁ + s₂ (mod q)`.
5. **Output:** Signature `(r, s)`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `x₁, x₂` | Parties (private) | Additive key shares | Together form private key |
| `k₁, k₂` | Parties (internal ephemeral) | Multiplicative nonce shares | One-time — never reuse |
| `r` | Computed | x-coordinate of R mod q | First part of ECDSA signature |
| `s` | Computed | Signature response | Second part of ECDSA signature |
| Paillier key pair | Internal (per party) | Homomorphic encryption key | Enables MtA without revealing values |
| Paillier modulus `N` | Internal | Product of two large primes | Security parameter for Paillier |
| Range proofs | Internal ZKP | Proofs that values are in correct range | Prevents parties from cheating in MtA |
| Curve | Protocol | secp256k1 or similar | Defines q, G |
| `H` | Protocol | SHA-256 (double for Bitcoin) | Message hashing |
| `t = 2, n = 2` | Fixed | Hard-coded 2-party | This scheme is 2-of-2 only |

---

## 5. `the-clash`

### n-Party Threshold ECDSA

**What it solves:** Extends 2-party ECDSA (TECLA) to any `t`-of-`n` configuration. If TECLA is a handshake between two people, THE-CLASH is a group vote where any `t` out of `n` participants can sign.

**Core idea:**

The same ECDSA hardness (`k⁻¹` problem) exists. For n parties, the protocol:
- Uses Shamir sharing for the private key `x` in additive form.
- Uses a distributed nonce generation protocol (similar to DKG applied to the nonce).
- Uses **multiplicative-to-additive (MtA) conversion** between all pairs of signing participants (O(t²) pairwise MtA rounds).

Key equation stays the same:
```
s = k⁻¹ · (H(m) + r·x)  mod q
```

But now `k⁻¹` and `x` are both distributed across `t` parties.

**How it works — step by step:**

1. **DKG phase:** All `n` parties run DKG to generate shares `xᵢ` of the private key.
2. **Signing subset:** Any `t` parties agree to sign. Each gets their Lagrange weight `λᵢ`.
3. **Nonce generation:** Each party `i` generates `kᵢ`. The group nonce `R = (Πᵢ kᵢ)·G`.
4. **Pairwise MtA:** For every pair `(i,j)` in the signing group, run MtA to convert multiplicative sharing into additive sharing of `k⁻¹·x`.
5. **Partial signature:** Each party computes `sᵢ`. Combine `s = Σᵢ sᵢ mod q`.
6. **Broadcast + verify:** Parties broadcast partial results, coordinator checks and assembles.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n` | Setup | Total parties | Group size |
| `t` | Setup | Threshold | Minimum signers |
| `xᵢ` | Party (private) | Key share (Lagrange-adjusted) | Never exposed |
| `kᵢ` | Party (ephemeral internal) | Nonce share | One-time |
| Paillier key (per party) | Internal | Homomorphic enc. key | Used in pairwise MtA |
| MtA outputs `αᵢⱼ, βᵢⱼ` | Internal | Additive conversion results | Combine to give k⁻¹·x terms |
| `R, r` | Computed | Nonce point, its x-coord mod q | Signature component |
| `s` | Computed | Signature response | Signature component |
| Range proofs | Internal ZKP | Correctness proofs | Prevent cheating |
| Commitment scheme | Internal | Pedersen or hash commitments | Enforce honest nonce generation |
| `λᵢ` | Computed | Lagrange weights | Correctly recombine Shamir shares |

---

## 6. `classic-schnorr`

### Classic Threshold Schnorr

**What it solves:** This is the textbook version of threshold Schnorr — simpler than FROST, without the binding factor optimization. It serves as a baseline and is easier to reason about for learning purposes.

**Core equation:**

Same Schnorr:
```
R = Σᵢ kᵢ·G      (sum of individual nonce commitments)
e = H(R || X || m)
sᵢ = kᵢ + e · λᵢ · xᵢ
s = Σᵢ sᵢ
```

**What makes it "classic":** There is no binding factor `ρᵢ`. This makes it simpler but susceptible to Wagner's attack in certain multi-session settings (where an attacker interleaves multiple signing sessions to forge a signature). FROST was designed to fix this.

**How it works — step by step:**

1. **Keygen:** DKG gives each party `xᵢ`, public key `X = x·G`.
2. **Round 1 — Commitments:** Each party `i` picks nonce `kᵢ`, broadcasts `Rᵢ = kᵢ·G`.
3. **Aggregate:** `R = Σᵢ Rᵢ`.
4. **Challenge:** `e = H(R || X || m)`.
5. **Round 2 — Responses:** Each party sends `sᵢ = kᵢ + e · λᵢ · xᵢ`.
6. **Combine:** `s = Σᵢ sᵢ`. Signature: `(R, s)`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n`, `t` | Setup | Group size, threshold | |
| `xᵢ` | Party private | Key share | |
| `kᵢ` | Party internal | Ephemeral nonce | **Must be uniformly random, never reused** |
| `Rᵢ = kᵢ·G` | Party public | Nonce commitment | |
| `R = ΣRᵢ` | Computed | Aggregate nonce point | |
| `e` | Computed | Challenge | |
| `λᵢ` | Computed | Lagrange coefficient | |
| `sᵢ` | Party output | Partial response | |
| `s = Σsᵢ` | Final | Signature scalar | |
| Curve | Protocol | e.g. Ed25519, secp256k1 | |

---

## 7. `bam`

### 2-Party Batched ECDSA

**What it solves:** Same 2-party ECDSA as TECLA, but optimized for **batched signing** — signing many messages in one session. If you need to sign thousands of transactions, running the full MtA protocol for each one is expensive. BAM amortizes the heavy cryptography across a batch.

**Core technique — offline/online split:**

The expensive part of 2-party ECDSA (the MtA conversion, the range proofs) can be done **offline** before you know what message you'll sign. Then, when a message arrives, the **online** phase is very fast.

```
Offline: Precompute (r, k⁻¹·x) pairs as "signature tokens"
Online:  s = k⁻¹ · (H(m) + r·x)   using the precomputed token
```

A batch of `B` signatures requires:
- 1 heavy offline phase generating B tokens.
- B cheap online signing operations.

**How it works — step by step:**

1. **Key setup:** Same as TECLA — parties hold `x₁, x₂` with `X = (x₁+x₂)·G`.
2. **Batch offline phase:** Generate `B` nonce pairs `(k₁ᵦ, k₂ᵦ)`, compute `Rᵦ = k₁ᵦ·k₂ᵦ·G`, run MtA for each, store as tokens.
3. **Online signing (per message):** For message `m`, pick a precomputed token. Both parties contribute their share of `s` with one cheap multiplication each.
4. **Output:** `B` signatures `{(rᵦ, sᵦ)}`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `B` | Caller | Batch size | How many signatures per offline phase |
| `x₁, x₂` | Party private | Key shares | |
| `kᵢᵦ` | Party internal | Nonce share for batch index b | Never reuse across different b |
| `Rᵦ, rᵦ` | Computed | Per-batch nonce point | |
| Signature token | Internal | Precomputed `(rᵦ, k⁻¹·x terms)` | Offline work product |
| Paillier key | Internal | Homomorphic encryption key | For MtA in offline phase |
| Range proofs | Internal | ZKPs on token values | Integrity of offline phase |
| `H` | Protocol | Message hash function | |

---

## 8. `ccgmp`

### n-Party ECDSA (GG-style)

**What it solves:** General `t`-of-`n` ECDSA based on the Gennaro-Goldfeder-Lindell style protocols (GG18/GG20 are famous implementations). Suitable for arbitrary group sizes, used in production by many wallets and MPC systems.

**Core equation:** Same ECDSA:
```
s = k⁻¹ · (H(m) + r·x)  mod q
```

**What GG-style adds over basic n-party:** A careful key generation and signing protocol with:
- Feldman VSS for key shares.
- Paillier-based MtA for all pairwise conversions.
- Zero-knowledge proofs at each step to prevent malicious parties from learning extra information or biasing outputs.

**How it works — step by step:**

1. **Keygen (multi-round DKG):**
   - Each party `i` samples `uᵢ` locally.
   - Commits to `Uᵢ = uᵢ·G` and a Feldman VSS commitment to a polynomial.
   - Reveals and cross-verifies. Private key share: `xᵢ = Σⱼ fⱼ(i)` (sum of polynomials evaluated at index i).
   - Each party generates a Paillier key pair and proves it's correctly formed (using a ZKP).
2. **Signing subset selection:** Any `t` parties, compute Lagrange weights.
3. **Round 1:** Each party picks multiplicative nonce share `kᵢ`, commits to `Γᵢ = kᵢ·G`.
4. **Round 2:** Pairwise MtA between all pairs: convert multiplicative nonce to additive sharing. Also MtA for the `x` component.
5. **Round 3:** Each party computes `δᵢ = kᵢ·γᵢ + Σⱼ αᵢⱼ + βᵢⱼ`. Broadcast `δᵢ`.
6. **Round 4:** Reconstruct `k = (Σ δᵢ)⁻¹·R`, get `r`. Compute partial `sᵢ`. Sum to get `s`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n`, `t` | Setup | Group size, threshold | |
| `uᵢ` | Party internal | Secret key contribution | Each party contributes to shared key |
| `xᵢ` | Party private | Final key share | |
| `kᵢ, γᵢ` | Party ephemeral | Nonce shares | |
| Paillier `(pᵢ,qᵢ,Nᵢ)` | Party internal | Homomorphic enc. parameters | Must be safe primes |
| Feldman commitments | Internal | VSS verification points | Detect cheating parties |
| MtA outputs `αᵢⱼ,βᵢⱼ` | Internal | Additive conversion products | Build up k⁻¹x additively |
| ZKP parameters | Internal | Proofs of correct computation | Security proofs at each round |
| `δᵢ` | Internal | Nonce combination intermediate | Avoids direct k exposure |

---

## 9. `haystack`

### Threshold Hash-Based Signatures (HBS)

**What it solves:** Hash-based signatures (like XMSS, LMS, SPHINCS+) are quantum-resistant because their security relies only on the collision-resistance of hash functions — no elliptic curves, no lattices. HAYSTACK distributes hash-based signing across `t`-of-`n` parties.

**Core idea of HBS:**

Hash-based signatures are built from **One-Time Signatures (OTS)**. The most basic OTS is Lamport:

```
Private key: n pairs (a₀ᵢ, a₁ᵢ) of random values
Public key:  n pairs (H(a₀ᵢ), H(a₁ᵢ)) 
Sign bit bᵢ of message: reveal aᵦᵢ
Verify: check H(aᵦᵢ) against the public key
```

XMSS/LMS add a Merkle tree on top, letting you sign many messages with one key tree. SPHINCS+ avoids state entirely using a hypertree of few-time signature schemes (FORS).

**Threshold challenge:** OTS keys are used **once** — if two parties try to sign different things with the same leaf, catastrophic forgery is possible. The threshold protocol must ensure:
1. Every leaf is used at most once across all parties.
2. Key tree construction is distributed.

**How it works — step by step:**

1. **Distributed tree construction:** Each party generates its subtree or contributes to a shared Merkle tree using a protocol that computes `H(a || b)` across party-held values without revealing them directly.
2. **Leaf assignment:** A coordinator assigns specific OTS leaves to specific signing sessions — no leaf can be reused.
3. **Partial signing:** Each party computes their portion of the OTS signature (which values they reveal).
4. **Merge:** Combine partial signatures and the authentication path (Merkle proof) into the full signature.
5. **Verify:** Recompute hash path up to root, compare with known public root.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n`, `t` | Setup | Party count, threshold | |
| Tree height `h` | Protocol | Depth of Merkle tree | Determines max signatures (2^h) |
| OTS scheme | Protocol | Lamport / WOTS+ | Which one-time scheme is used |
| `w` (Winternitz param) | Protocol | Trade-off between signature size and computation | Higher w = smaller but slower |
| Hash function `H` | Protocol | SHA-256, SHA-3, SHAKE | Must be quantum-resistant (just needs collision-resistance) |
| Seed `SK_seed` | Party private | Root seed for tree generation | Deterministically generates all private values |
| `PK_seed` | Party public | Seed for generating public key elements | Used during verification |
| State / leaf index | Critical internal | Which leaf was last used | **Must be synchronized — never reuse** |
| Authentication path | Signature | Sibling hashes on path to root | Lets verifier climb the tree |
| `n` (security param) | Protocol | Hash output length in bytes | 16, 24, or 32 bytes depending on security level |

---

## 10. `mithril`

### Threshold ML-DSA (Dilithium)

**What it solves:** ML-DSA (Module Lattice Digital Signature Algorithm, also known as CRYSTALS-Dilithium) is NIST's post-quantum signature standard. MITHRIL makes it threshold — any `t` of `n` parties can sign using Dilithium, with no full private key ever assembled.

**Core idea of ML-DSA:**

ML-DSA is based on the **Module Learning With Errors (MLWE)** problem. The private key is a pair of short vectors `(s₁, s₂)`. The public key is a matrix-vector product:

```
A ← R_q^{k×l}    (public random matrix, k and l are module dimensions)
t = A·s₁ + s₂    (public key component)
```

Signing a message `m`:
1. Pick random short vector `y`.
2. `w = A·y`, compute `w₁` (high bits of w).
3. Challenge `c = H(μ || w₁)` (a sparse polynomial).
4. Response `z = y + c·s₁`. Check z is short enough (reject if not — this is "rejection sampling").
5. Signature: `(c, z, h)` where h is a hint for reconstruction.

**Threshold version:** Split `s₁` into shares across parties. Each party computes a partial `z` contribution. The challenge `c` is computed jointly from the message and a commitment.

**How it works — step by step:**

1. **Key splitting:** `s₁` is split into `n` additive shares `s₁⁽ⁱ⁾` with `Σᵢ s₁⁽ⁱ⁾ = s₁`. Similarly for `s₂`.
2. **Commitment round:** Each party picks short `yᵢ`, broadcasts commitment to `Aᵢ = A·yᵢ`.
3. **Aggregate:** `w = Σᵢ A·yᵢ = A·Σᵢ yᵢ`.
4. **Challenge:** `c = H(μ || w₁)` where `w₁` = high bits of `w`.
5. **Partial response:** Each party computes `zᵢ = yᵢ + c·s₁⁽ⁱ⁾` and checks it's short. Rejection sampling may require restarting.
6. **Combine:** `z = Σᵢ zᵢ`. Check final z is short enough.
7. **Hint:** Generate the hint vector `h` from combined data.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| Security level | Setup | 2, 3, or 5 (NIST levels) | Determines k, l, q, γ values |
| `q` | Protocol | Prime modulus (8380417) | All arithmetic mod q |
| `k, l` | Protocol | Module dimensions | k=4,l=4 at level 2; k=6,l=5 at level 3 |
| `A` | Public | Random matrix in R_q | Generated from public seed ρ |
| `ρ` | Public seed | Seed to expand A | Compressible representation of A |
| `s₁, s₂` | Private | Short secret vectors | Coefficients in [-η, η] |
| `s₁⁽ⁱ⁾` | Party private | Share of s₁ | |
| `η` | Protocol | Bound on secret coefficients | 2 or 4 depending on level |
| `γ₁, γ₂` | Protocol | Bounds for y and low-bits | Control rejection rate |
| `yᵢ` | Party internal | Ephemeral masking vector | Fresh each signing attempt |
| `c` | Computed | Sparse challenge polynomial | At most τ nonzero coefficients |
| `τ` | Protocol | Challenge weight | 39, 49, or 60 by level |
| `h` | Signature | Hint bits | Help verifier reconstruct high bits |
| Rejection sampler | Internal | Abort if z is too large | Prevents private key leakage through z |

---

## 11. `quorus`

### Alternative Threshold ML-DSA

**What it solves:** Another threshold variant of ML-DSA/Dilithium. Where MITHRIL may follow one specific threshold construction, QUORUS explores an alternative — possibly with different trade-offs in:
- Communication rounds.
- Robustness (can it recover if some parties drop out?).
- Identifiable abort (can you tell who misbehaved?).
- Efficiency under different parameter sets.

One key difference might be how rejection sampling is handled across parties — coordinating rejection is tricky because one party's "abort" causes the whole group to restart.

**Core difference idea:** QUORUS might use a **deterministic nonce derivation** (similar to RFC 6979 for ECDSA) applied in the lattice setting, making signing more reliable without repeated rounds of rejection.

**Parameters:** Similar to MITHRIL, with potential additions:

| Parameter | QUORUS specific | What it is | Why it matters |
|-----------|----------------|------------|----------------|
| All ML-DSA params | Same as MITHRIL | See above | |
| Abort policy | Protocol | What happens when z is too large | Could be: restart, blame, retry count |
| Max retries `T` | Protocol | Max rejection sampling restarts | Bounds protocol runtime |
| Deterministic mode | Optional | Whether y is pseudorandom | Eliminates randomness issues across parties |
| Coordinator role | Protocol | Which party aggregates | May be rotating or fixed |

---

## 12. `redeta`

### Threshold ECDLP-Based Signatures

**What it solves:** A family of threshold signatures built on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)** but using a different signature structure than standard Schnorr or ECDSA. This might include schemes like **Okamoto-Schnorr**, double-discrete-log proofs, or other ECDLP-based constructions.

**Core ECDLP hardness:**

Given `Y = x·G`, finding `x` is computationally infeasible for large groups. All ECDLP-based signatures rely on this. REDETA likely builds a threshold version of a less common but provably secure ECDLP signature.

**One likely structure — Okamoto signature:**

```
Public key: (Y₁ = x₁·G, Y₂ = x₂·H)   (two independent bases)
Sign: pick (r₁, r₂), R = r₁·G + r₂·H
      e = H(R || m)
      s₁ = r₁ + e·x₁,   s₂ = r₂ + e·x₂
Verify: s₁·G + s₂·H == R + e·(Y₁+Y₂)
```

In the threshold setting, each of `x₁, x₂` is distributed.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n`, `t` | Setup | Group size, threshold | |
| `G, H` | Protocol | Two independent generators | H must not be a known multiple of G |
| `x₁ᵢ, x₂ᵢ` | Party private | Shares of both secret keys | |
| `r₁ᵢ, r₂ᵢ` | Party internal | Ephemeral nonce shares | Two nonce components |
| `R` | Computed | Aggregate commitment point | |
| `e` | Computed | Challenge | |
| `s₁, s₂` | Computed | Response pair | |
| Curve | Protocol | e.g. Ed25519 | |
| Hash `H` | Protocol | Collision-resistant hash | |

---

## 13. `splitkey`

### Server-Assisted Threshold Signatures and PKE

**What it solves:** A practical 2-of-2 (or t-of-n) system where a **server** holds one key share and the **client** holds another. Neither can act alone. Commonly used for:
- Wallet key backup (server as guardian, user as owner).
- Policy enforcement (server checks rules before co-signing).
- Password-encrypted key recovery.

Also includes **Public Key Encryption (PKE)** — the split key can be used for decryption, not just signing. This is important for encrypted data recovery.

**Core idea:**

```
User key share:   x_u
Server key share: x_s
Full private key: x = x_u + x_s  (never assembled in one place)
```

For signing: user initiates, server checks policy (rate limits, IP, 2FA), both contribute.
For decryption: ciphertext was encrypted to `X = x·G`. Both parties contribute decryption shares:
```
D_u = x_u · C₂   (user's partial decryption of ElGamal ciphertext C₂)
D_s = x_s · C₂   (server's partial decryption)
m = C₁ - (D_u + D_s)
```

**How it works — step by step:**

1. **Registration:** User generates `x_u`, server generates `x_s`. Public key `X = (x_u + x_s)·G` registered.
2. **Authentication:** Before the server contributes its share, it validates identity (password, TOTP, hardware key, rate limit).
3. **Partial operation:** Both contribute their shares to the signing or decryption computation.
4. **Result:** Neither party ever sees the full private key.
5. **Recovery:** If user loses `x_u`, they can authenticate to server and recover (server-side escrow policies apply).

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `x_u` | User private | User's key share | Stored on user device |
| `x_s` | Server private | Server's key share | Stored on server |
| Policy rules | Server config | What must be true before server signs | The "trusted third party" logic |
| Auth factor | User input | Password / TOTP / biometric | Server authentication |
| `X = (x_u+x_s)·G` | Public | Combined public key | For verification / encryption |
| Session token | Internal | Ephemeral auth token | Binds server share release to authenticated session |
| PKE scheme | Protocol | ElGamal / ECIES / hybrid | For decryption use case |
| Encryption nonce | Internal | Random `r` in `C = (r·G, m + r·X)` | One-time encryption randomness |
| Recovery policy | Server config | When/how to release backup | Key recovery rules |

---

## 14. `minimpc`

### Threshold AES + SHA + MAC Gadgets (Minimal MPC)

**What it solves:** Sometimes you don't need to sign — you need to run **symmetric cryptography** (AES encryption, SHA hashing, HMAC authentication) where the key is distributed across multiple parties. No single party holds the AES key or HMAC key in full. This is useful for distributed HSMs, split-knowledge key stores, and privacy-preserving authentication.

**Core challenge:** AES is not designed for secret sharing — it uses AND gates (non-linear operations) which are expensive in MPC. The core technique uses **Beaver triples** (see entry 34) to evaluate AND gates without revealing inputs.

**MPC boolean circuit evaluation:**

```
Split secret a into: a = a₁ ⊕ a₂  (XOR secret sharing, one bit at a time)
XOR gate: a₁ ⊕ b₁  and  a₂ ⊕ b₂  (each party XORs their shares — free!)
AND gate: need Beaver triple (u, v, w) with u·v = w
          Then: a·b = (a ⊕ u)·(b ⊕ v) ⊕ (b⊕v)·u ⊕ (a⊕u)·v ⊕ w
          (each term is linear — computable from shares)
```

AES has 128 AND gates per block. SHA has ~22,000 AND gates for one block.

**How it works — step by step:**

1. **Precompute Beaver triples** (entry 34) for all AND gates needed.
2. **Input sharing:** Each party splits their portion of the key/input into XOR shares.
3. **Gate evaluation:** XOR gates: free (local computation). AND gates: use one Beaver triple each.
4. **Output reconstruction:** Parties exchange final output shares and XOR to get the result.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n`, `t` | Setup | Party count, threshold | |
| Key shares `kᵢ` | Party private | XOR shares of AES/HMAC key | `k = ⊕ᵢ kᵢ` |
| Message | Public or private | Data to encrypt/hash | Can itself be secret-shared |
| AND triple count | Computed | Based on circuit depth | AES-128: 6400 triples per block |
| Beaver triples | Internal precomputed | `(u,v,w)` with `u·v=w` in shares | Core MPC building block |
| Security parameter | Protocol | Statistical security `κ` | Usually 40–128 bits |
| OT extension | Internal | How triples are generated | IKNP or SilentOT based |
| Circuit representation | Internal | Netlist of AND/XOR gates | Bristol Fashion format common |
| Block size | Protocol | 128 bits for AES | Fixed |

---

## 15. `maestro`

### T-AES, T-SHA, T-MAC and Gadgets

**What it solves:** Similar to MINIMPC but potentially with a broader gadget library, more optimized circuit representations, or support for a wider range of symmetric operations. MAESTRO suggests a "conductor" approach — coordinating multiple sub-protocols (T-AES, T-SHA, T-MAC) under one framework.

**Core difference from MINIMPC:** Maestro likely uses more advanced MPC optimizations:
- **Half-gates technique:** Cuts AND gate cost roughly in half.
- **Free XOR:** Uses a global XOR offset `Δ` so XOR gates cost nothing.
- **Garbled circuits:** Instead of secret sharing, use Yao's garbled circuit approach for 2-party sub-protocols.

**Garbled circuit gadget:**

```
Garbler creates encrypted truth tables:
For each gate (a,b) → c:
  Enc_{k_a || k_b}(k_c)  for each input combination

Evaluator picks the right row using their input wire keys,
decrypts to get output wire key, never learning the underlying bit.
```

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| Protocol type | Caller | Garbled circuit vs GMW vs SPDZ | Determines communication model |
| `Δ` | Internal (garbler) | Global XOR offset | Free XOR optimization secret |
| Wire labels | Internal | 128-bit keys per wire per bit | Two per wire: for 0 and for 1 |
| PRG seed | Internal | Seed for label expansion | Compact key generation |
| T-AES variant | Config | Which AES-MPC protocol | Circuit-based or arithmetic |
| T-SHA variant | Config | SHA-256 or SHA-3 | Different circuit sizes |
| T-MAC flavor | Config | HMAC-SHA, GMAC, Poly1305 | Different algebraic structures |
| Gadget registry | Internal | Library of sub-circuits | Reusable building blocks |
| `n`, `t` | Setup | Party count, threshold | |

---

## 16. `amber`

### Threshold Lattice-Based KEM

**What it solves:** A Key Encapsulation Mechanism (KEM) allows one party to generate a shared secret and securely transmit it to another. In the threshold version, **decapsulation** requires cooperation from `t`-of-`n` parties. No single party can decrypt alone. Based on lattice problems (MLWE / RLWE) for post-quantum security.

**Core KEM idea (based on Kyber/ML-KEM):**

```
KeyGen: A ← R_q^{k×k},  s,e short vectors
        pk = (A, b = A·s + e),  sk = s

Encapsulate: pick small (r, e₁, e₂)
        u = Aᵀ·r + e₁
        v = bᵀ·r + e₂ + ⌊q/2⌋·m   (m = message/seed)
        ct = (u, v)

Decapsulate: m = v - sᵀ·u   (noise cancels, m recovered)
```

**Threshold decapsulation:**

Split `s` into `n` additive shares `sᵢ`. Each party computes their partial decapsulation:
```
mᵢ = v - sᵢᵀ·u    (partial result)
m = Σᵢ mᵢ          (combine — errors still cancel)
```

Because the structure is linear in `s`, additive secret sharing works cleanly.

**How it works — step by step:**

1. **Setup:** DKG-style protocol produces shares `sᵢ` of the private key `s`. Public key `pk = (A, b)`.
2. **Encapsulation:** Sender encapsulates normally — just needs the public key, doesn't know about threshold.
3. **Partial decapsulation:** Each of the `t` parties computes `mᵢ = v - sᵢᵀ·u`.
4. **Combine:** Coordinator sums: `m = Σᵢ mᵢ`. Decode to recover the original seed.
5. **Derive shared secret:** Run the seed through a KDF to get the final symmetric key.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| Security level | Setup | 1, 3, or 5 (NIST) | Kyber-512, 768, 1024 |
| `q` | Protocol | Modulus (3329 for Kyber) | All arithmetic mod q |
| `k` | Protocol | Module rank (2, 3, or 4) | Dimension of vectors |
| `A` | Public | Matrix (from public seed ρ) | Shared public random matrix |
| `s, e` | Private | Short secret and error | Basis of security |
| `sᵢ` | Party private | Share of s | Additive sharing |
| `η₁, η₂` | Protocol | Distribution bounds for errors | Controls noise magnitude |
| Ciphertext `(u, v)` | Sender | Encapsulated ciphertext | |
| `du, dv` | Protocol | Compression parameters | Ciphertext size reduction |
| KDF | Protocol | SHAKE-256 or similar | Key derivation from recovered seed |
| Rejection sampling | Internal | Hash check to catch decaps errors | Fujisaki-Okamoto transform |

---

## 17. `hermine`

### Threshold Lattice-Based Signing

**What it solves:** A threshold signature scheme built on lattice problems — specifically on **signature schemes like Falcon or Dilithium** — but using a construction different from MITHRIL/QUORUS. Hermine suggests a possibly Falcon-based construction (GPV/NTRU lattice framework).

**Falcon core idea:**

Falcon is based on NTRU lattices. The private key is a short basis for an NTRU lattice. Signing uses a **trapdoor sampler**:

```
Private: short polynomials (f, g, F, G) such that f·G - g·F = q
Public: h = g·f⁻¹ mod q

Sign: sample short (s₁, s₂) such that s₁ + s₂·h ≡ H(m) (mod q)
Verify: check s₁ + s₂·h ≡ H(m) (mod q) and ‖(s₁,s₂)‖ ≤ bound
```

**Threshold challenge with Falcon:** The trapdoor sampler is inherently sequential and hard to distribute. Threshold Falcon requires carefully partitioning the lattice sampling procedure.

**How it works — step by step:**

1. **Distributed key generation:** Generate shares of the Falcon private basis `(f, g, F, G)` across parties.
2. **Commitment:** Each party commits to a partial sample from their portion of the basis.
3. **Challenge:** Hash of message and commitment.
4. **Partial response:** Each party computes partial short vector contribution.
5. **Combine:** Aggregate partial vectors. Check combined vector is short enough.
6. **Rejection sampling:** If combined vector is too large, restart.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n` (NTRU degree) | Protocol | Polynomial degree (512 or 1024) | Security and signature size |
| `q` | Protocol | NTRU prime modulus (12289) | |
| `(f, g, F, G)` | Private | NTRU lattice basis | The trapdoor — never expose |
| `(fᵢ, gᵢ)` | Party private | Shares of secret basis | |
| `h = g·f⁻¹` | Public | Public key polynomial | |
| `σ` | Protocol | Gaussian standard deviation | Controls distribution of signatures |
| Gaussian sampler | Internal | Fast Fourier sampling (FFSAMPLING) | Basis for secure signature generation |
| `β²` | Protocol | Signature norm bound | Signature valid iff ‖(s₁,s₂)‖² ≤ β² |
| Party threshold `t, n` | Setup | t-of-n threshold params | |

---

## 18. `least`

### Threshold Signatures from Code-Based Group Actions

**What it solves:** Code-based cryptography relies on the hardness of decoding random linear codes (the **Syndrome Decoding Problem**). Group action-based signatures use algebraic group actions where inverting the action is hard. LEAST combines these into a threshold signature scheme — an exotic post-quantum alternative to lattice-based schemes.

**Core group action idea:**

A group `G` acts on a set `X`. Given `x ∈ X`, computing `g * x` is easy. Finding `g` from `x` and `g * x` is hard. This is the **Group Action Inverse Problem (GAIP)**.

```
Private key: g ∈ G (secret group element)
Public key:  y = g * x₀  (g acts on base element x₀)
Sign: pick random r ∈ G, compute R = r * x₀
      challenge e = H(R || m)
      response  s = r * gᵉ  (group operation)
Verify: check s * x₀ = R * yᵉ
```

In code-based settings, the group is related to equivalences of linear codes, making GAIP equivalent to code equivalence problems.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| Base element `x₀` | Protocol | Fixed code or matrix | Starting point for the group action |
| Group `G` | Protocol | e.g. permutation group, linear equivalences | Defines the action |
| Private key `g` | Party private | Secret group element | Core secret |
| `gᵢ` | Party private | Secret shares of g | |
| Nonce `r` | Party internal | Ephemeral group element | Per-signature randomness |
| `R = r * x₀` | Computed | Commitment | |
| `e` | Computed | Challenge | |
| `s` | Computed | Response group element | |
| Code parameters `[n,k,d]` | Protocol | Length, dimension, distance of code | Security level |
| Field `GF(q)` | Protocol | Finite field for code coefficients | Usually GF(2) or GF(2^m) |

---

## 19. `tanuki`

### Threshold Lattice-Based Signature (Different Construction)

**What it solves:** Yet another threshold lattice signature — TANUKI likely represents a specific academic construction that differs from MITHRIL (Dilithium-based) and HERMINE (Falcon-based). Possible basis: **HAETAE**, **Raccoon**, or a scheme from the **SIS (Short Integer Solution)** framework.

**Raccoon-style core idea (likely):**

Raccoon is a lattice signature built to be threshold-friendly from the ground up:

```
Public key: (A, t = A·s + e)
Sign: y ← D^l_σ  (Gaussian masking vector)
      w = A·y
      challenge c = H(m, w)
      z = y + c·s
      Check: ‖z‖ ≤ bound, abort and restart if not
      Add "flooding" noise to z for zero-knowledge: z' = z + noise
```

The flooding noise makes each party's response independently publishable without leaking their secret — critical for threshold settings where each party's `zᵢ` is broadcast before combining.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `q` | Protocol | Modulus | |
| `k, l` | Protocol | Module dimensions | |
| `σ` | Protocol | Masking Gaussian width | Controls rejection rate |
| `σ_flood` | Protocol | **Flooding noise width** | Makes partial responses zero-knowledge |
| `s` shares `sᵢ` | Party private | Secret key shares | |
| `yᵢ` | Party internal | Partial masking vector | Ephemeral |
| `c` | Computed | Challenge polynomial | |
| `zᵢ` | Party output | Partial response with flooding | Safe to broadcast |
| `z = Σzᵢ` | Combined | Full response | |
| Rejection bound `β` | Protocol | Maximum allowed z norm | Security parameter |

---

## 20. `vinaigrette`

### Threshold UOV + MAYO Signatures

**What it solves:** UOV (Unbalanced Oil and Vinegar) and MAYO are **multivariate** post-quantum signature schemes. Their security comes from the hardness of solving systems of multivariate polynomial equations over finite fields (MQ problem). VINAIGRETTE makes these schemes threshold-capable.

**UOV core idea:**

The private key is a linear map `T` that transforms "oil" variables into a form where a polynomial system is easy to solve. The public key is the composed, hard-looking system.

```
Variables: o "oil" variables + v "vinegar" variables  (o < v, unbalanced)
Signing: pick random vinegar, solve for oil using private T (linear system)
Verify: evaluate public multivariate system P(signature) == hash(m)
```

**MAYO improvement:** Uses a smaller oil space with "whipping" — a technique to reduce public key size dramatically.

**Threshold challenge:** The private map `T` must be shared. Computing the linear solve over shares is done using standard linear MPC techniques (no special lattice math needed — just arithmetic over GF(q)).

**How it works — step by step:**

1. **Split private map:** `T` is additively shared as `Tᵢ` among `n` parties.
2. **Vinegar selection:** Each party picks or the group agrees on vinegar values (these can be public or jointly sampled).
3. **Distributed linear solve:** Using MPC arithmetic (multiplication over GF(q) using Beaver triples), each party contributes to solving the oil system.
4. **Combine:** Oil values assembled from partial contributions.
5. **Output:** Signature is (oil, vinegar). Verify against public multivariate system.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `o` | Protocol | Number of oil variables | Security base |
| `v` | Protocol | Number of vinegar variables | Must be > o for UOV |
| Field `GF(q)` | Protocol | Usually GF(256) | Small field for efficiency |
| `m` | Protocol | Number of equations | Usually m = o |
| Public map `P` | Public | Multivariate system | The verification key |
| Private map `T` | Private | Oil-vinegar transformation | The trapdoor |
| `Tᵢ` | Party private | Share of T | |
| Vinegar values `v` | Per-signature | Random ephemeral values | Nonce equivalent |
| Beaver triples over GF(q) | Internal | For field multiplications in MPC | |
| MAYO whip parameter `k` | Protocol (MAYO only) | Number of UOV instances combined | Reduces public key size |

---

## 21. `pantheria`

### RLWE-Based FHE and Threshold FHE

**What it solves:** Fully Homomorphic Encryption (FHE) lets you compute **on encrypted data** — add and multiply ciphertexts — without decrypting. Pantheria uses Ring Learning With Errors (RLWE) as the basis. In the **threshold** variant, decryption requires cooperation from `t`-of-`n` parties, making it impossible for any single server to secretly read data.

**Core RLWE-FHE idea (BFV/BGV style):**

```
Ring: R_q = Z_q[x]/(xⁿ+1)   (polynomials mod xⁿ+1)

KeyGen:
  sk ← small polynomial s ∈ R
  a  ← R_q random
  e  ← small error polynomial
  pk = (b = -a·s + e, a)

Encrypt m ∈ R_t (message space mod t):
  ct = (c₀, c₁) = (b·u + e₁ + Δ·m, a·u + e₂)   where Δ = q/t

Decrypt:
  m = Round( (c₀ + c₁·s) · t/q )   (errors cancel, m recovered)

Homomorphic ops:
  ct_add = ct₁ + ct₂   (coefficient-wise)
  ct_mul = ct₁ ⊗ ct₂   (polynomial product, needs relinearization)
```

**Threshold decryption:** Share `s` across parties. Each party computes partial decryption `pᵢ = c₁·sᵢ + eᵢ'` (with fresh small noise `eᵢ'` added to hide their share). Combine: `Σᵢ pᵢ + c₀ ≈ m` after rounding.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n` (ring degree) | Protocol | Polynomial degree (1024–65536) | Security and capacity |
| `q` | Protocol | Ciphertext modulus (very large) | Computation depth supported |
| `t` | Protocol | Plaintext modulus | Message space size |
| `Δ = ⌊q/t⌋` | Computed | Scaling factor | Separates message from noise |
| Error distribution `χ` | Protocol | Gaussian or uniform small | Width determines security |
| `s` | Private | Secret key polynomial | Shared across parties |
| `sᵢ` | Party private | Secret key share | Never combine |
| Relinearization key `rlk` | Public | Enables multiplication | Computed from sk during setup |
| Galois keys | Public | Enable rotation/automorphism | SIMD-style batch operations |
| Noise budget | Internal | How many ops before noise overwhelms signal | Determines computation depth |
| Bootstrapping | Optional internal | Reset noise budget | Enables deep circuits |
| Smudging noise `eᵢ'` | Party internal | Extra noise added at decryption | Hides party's key share |
| `t, n` threshold | Setup | t-of-n decryption policy | |

---

## 22. `zama-tfhe`

### TFHE and Threshold FHE

**What it solves:** TFHE (Torus Fully Homomorphic Encryption) is a different FHE construction from BFV/BGV. Its specialty: **fast bootstrapping** (~10ms) that evaluates a full LUT (look-up table) on a single bit in one bootstrapping step. This makes TFHE extremely efficient for circuits over **binary inputs** — you can run any function of any depth without accumulating noise problems.

**Core TFHE idea:**

TFHE operates over the **Torus** `T = R/Z` (real numbers mod 1, like an angle).

```
LWE ciphertext:  ct = (a, b = a·s + e + μ)   (a random vector, μ = message encoding)
TLWE: ring version (polynomials instead of vectors)

Bootstrapping: evaluates a test polynomial while refreshing noise
               Boot(ct, testpoly) = TLWE ciphertext of testpoly evaluated at ct's message bit
```

The bootstrapping is the "programmable" part — the test polynomial `v` encodes any lookup table:
```
LUT gate: given ct encrypting a bit, bootstrap to evaluate f(bit)
          Result: fresh ciphertext encrypting f(bit)
```

**Threshold TFHE:** Distribute the bootstrapping key (which encodes `s`) across parties. Each party contributes a partial bootstrapping evaluation, which is combined.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| LWE dimension `n` | Protocol | Size of LWE secret key | Security level |
| GLWE dimension `k` | Protocol | Ring size in TLWE | |
| Polynomial degree `N` | Protocol | GLWE ring degree | |
| Modulus | Protocol | Usually 2³² or torus encoding | |
| σ_lwe | Protocol | LWE noise std dev | Security |
| σ_glwe | Protocol | GLWE noise std dev | Bootstrapping accuracy |
| BSK (bootstrapping key) | Public | Encryptions of sk bits under GLWE | Core of bootstrapping |
| KSK (keyswitch key) | Public | Converts TLWE key to LWE key | Key switching step |
| Test polynomial `v` | Per-gate | Encodes the desired LUT | |
| PBS (programmable bootstrap) | Operation | Main TFHE gate operation | |
| `t, n` threshold | Setup | Threshold decryption policy | |
| Partial BSK shares | Party private | Shares of bootstrapping key | |

---

## 23. `zama-zhenith`

### Zero-Knowledge Proofs (ZKP)

**What it solves:** A Zero-Knowledge Proof (ZKP) lets a prover convince a verifier of a statement's truth **without revealing why it's true** or any other information. "I know a password that opens this vault" without showing the password. ZAMA-ZHENITH likely provides ZKPs compatible with FHE computation — i.e., proving that an FHE computation was done correctly.

**Core Sigma protocol (simplest ZKP structure):**

For proving knowledge of `x` such that `X = x·G`:

```
Commit:  R = r·G  (prover sends R)
Challenge: e = H(R || X || context)  (verifier or Fiat-Shamir)
Response: s = r + e·x
Verify:  s·G == R + e·X
```

**Fiat-Shamir heuristic:** Makes it non-interactive — replace verifier's random challenge with a hash.

**ZK-SNARK / STARK structure** (for complex statements):

```
Computation → Arithmetic circuit → Constraint system (R1CS or AIR)
             → Polynomial commitment (KZG / FRI)
             → Proof of correct evaluation (PCP / IOP)
→ Short proof π, publicly verifiable
```

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| Statement | Prover | What is being proved | Must be expressible as circuit |
| Witness | Prover private | The secret that makes the statement true | Never revealed |
| Circuit | Protocol | Arithmetic circuit encoding the computation | Size determines proof cost |
| Commitment scheme | Protocol | KZG (pairing-based) or FRI (hash-based) | Determines trusted setup requirement |
| SRS (structured reference string) | Setup | Trusted setup output for KZG | KZG needs this; FRI does not |
| Security parameter `λ` | Protocol | Bit security level | |
| Hash function | Protocol | For Fiat-Shamir transform | Must be random oracle |
| Field `F_p` | Protocol | Prime field for constraints | |
| Prover time | Practical | O(N log N) for N constraint circuit | |
| Proof size | Practical | Constant (SNARKs) or polylog (STARKs) | |
| FHE compatibility | Protocol | Whether proofs work over torus/GLWE | Specific to ZAMA context |

---

## 24. `piver`

### Verifiable Secret Sharing

**What it solves:** In basic secret sharing (Shamir, entry 27), you hand out shares and trust that the dealer was honest. Verifiable Secret Sharing (VSS) adds cryptographic **commitments** that let each shareholder verify their share is consistent with everyone else's — without learning the secret. PIVER is a specific VSS construction.

**Core verification idea:**

If the dealer hides the secret in a polynomial `f(x) = s + a₁x + ... + aₜ₋₁xᵗ⁻¹`, they also publish commitments to each coefficient:

```
Cⱼ = aⱼ·G    (or Cⱼ = aⱼ·G + rⱼ·H for Pedersen-style)
```

Each party `i` can verify their share `sᵢ = f(i)`:
```
sᵢ·G == Σⱼ iʲ · Cⱼ
```
(The linear combination of published commitments should equal the commitment to the share.)

If this check fails, the shareholder knows the dealer cheated.

**How it works — step by step:**

1. **Dealer selects secret `s`**, constructs random polynomial `f(x)` of degree `t-1`.
2. **Dealer publishes** commitments `Cⱼ = aⱼ·G` for each coefficient `aⱼ`.
3. **Dealer distributes** share `sᵢ = f(i)` to party `i` over a private channel.
4. **Each party verifies** their share using the public commitments.
5. **Reconstruction:** Any `t` honest parties pool shares; Lagrange interpolation recovers `s`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n` | Setup | Number of parties | |
| `t` | Setup | Threshold | Min shares to reconstruct |
| `s` | Dealer private | The secret | |
| `f(x)` | Dealer internal | Degree `t-1` polynomial | Evaluates to shares |
| `a₁...aₜ₋₁` | Dealer internal | Random polynomial coefficients | Must be truly random |
| `Cⱼ = aⱼ·G` | Public | Feldman-style commitments | Verifiable without revealing secret |
| `G` | Protocol | Group generator | |
| `sᵢ = f(i)` | Party private | Share | |
| Reconstruction threshold `t` | Fixed | Min shares for recovery | |
| Channel security | Operational | How shares are transmitted | Must be private (TLS / encrypted) |

---

## 25. `schmivitz`

### VOLEith-Based Zero-Knowledge Proof of Knowledge

**What it solves:** A ZKPoK (Zero-Knowledge Proof of Knowledge) proves not just that a statement is true, but that the prover **knows** a specific witness. SCHMIVITZ is based on **VOLEith** — a highly efficient ZKP framework that uses Vector Oblivious Linear Evaluation (VOLE, entry 33) as its core building block. This makes it very fast for proving knowledge of large witnesses.

**VOLE-based ZKP core:**

Standard ZKP approaches (like Fiat-Shamir Sigma protocols) don't scale well for large witnesses. VOLEith (also called QuickSilver, or related to FAEST/VOLE-in-the-head):

```
Prover holds witness w (the secret)
VOLE gives: Δ (global key, verifier holds)
            Q = w·Δ + U  (prover holds U, verifier checks)

Proving a constraint like a·b = c over shares:
  Open masked versions, use VOLE correlation to verify
  No commitment-per-gate overhead needed
```

The VOLE correlation is like a shared secret between prover and verifier that the prover can use to authenticate their computation without revealing the witness.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `w` | Prover private | Witness (the secret being proved known) | |
| `Δ` | Verifier private | Global VOLE key | Binds all proofs together |
| `Q, U` | Shared VOLE output | Correlated randomness | Foundation of the protocol |
| Circuit | Protocol | What statement is proved | |
| Field `GF(2^k)` | Protocol | Arithmetic field | GF(2^128) common |
| OT extension | Internal | How VOLE is generated | SilentOT / IKNP |
| λ | Security param | Statistical security bits | |
| Proof size | Practical | O(|circuit|) in λ bits | Linear, very efficient |
| Prover time | Practical | O(|circuit|) sym ops | Very fast |

---

## 26. `smallwood`

### Hash-Based Zero-Knowledge Proof of Knowledge

**What it solves:** Same goal as SCHMIVITZ — prove knowledge of a witness — but using only **hash functions**. No VOLE, no elliptic curves. This makes it post-quantum secure (hash functions are quantum-resistant) and requires no trusted setup.

**MPC-in-the-head technique:**

The key idea: the prover **simulates an MPC protocol in their head** across `N` virtual parties. Then they commit to all parties' views, and the verifier challenges a random subset to open. If the prover cheats, they're caught with high probability.

```
1. Prover picks N virtual party inputs that are additive shares of witness w.
2. Runs MPC protocol computing f(w) internally.
3. Commits: sends hashes of each party's view.
4. Verifier challenges: "Open parties 3, 7, 12" (all but one).
5. Prover reveals those views. Verifier checks consistency.
6. The unopened party hides the witness.
```

Soundness: `1/N` per challenge → run multiple rounds or use many parties.

**FAEST and similar schemes** use this with FHE-like linear structure for efficiency.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `N` | Protocol | Number of virtual MPC parties | More = smaller proof, more computation |
| Rounds `τ` | Protocol | Number of repetitions | Soundness error: `(1/N)^τ` |
| Hash function `H` | Protocol | SHA-3 / SHAKE-256 | Must be collision-resistant |
| Commitment scheme | Internal | Hash-based (Merkle tree) | Compact opening proofs |
| Witness `w` | Prover private | Secret being proved | |
| Virtual shares | Prover internal | N additive shares of w | Simulated MPC inputs |
| MPC protocol | Internal | Which protocol is simulated | BGW / GMW style usually |
| Challenge indices | Verifier | Which parties to open | Random selection |
| Proof size | Practical | O(τ·N·|circuit|/N) = O(τ·|circuit|) | |
| Security level | Combined effect of τ and N | | Trade-off: more parties vs more rounds |

---

## 27. `shamir`

### Shamir's Secret Sharing

**What it solves:** The foundation of almost all threshold cryptography. A secret `s` is split into `n` shares such that any `t` shares can reconstruct `s`, but any `t-1` shares reveal nothing about `s`.

**Core math — polynomial interpolation:**

Pick a random polynomial of degree `t-1`:
```
f(x) = s + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹   (all mod prime p)
```

The secret is `f(0) = s`. Shares are:
```
sᵢ = f(i)   for i = 1, 2, ..., n
```

**Reconstruction (Lagrange interpolation):**

Given `t` shares `(i, sᵢ)`, reconstruct:
```
s = f(0) = Σᵢ sᵢ · λᵢ    where λᵢ = Π_{j≠i} (0-j)/(i-j)  mod p
```

**Why is t-1 shares nothing?** By the Schwartz-Zippel lemma, a random degree `t-1` polynomial has `t-1` free parameters — so `t-1` points fix `t-2` unknowns but leave the secret (`f(0)`) completely undetermined.

**How it works — step by step:**

1. **Setup:** Agree on prime `p > n` and threshold `t`.
2. **Dealer:** Pick random `a₁ ... aₜ₋₁` and secret `s`. Define `f(x)`.
3. **Distribute:** Send `(i, f(i))` to party `i` privately.
4. **Reconstruct:** Collect any `t` shares. Apply Lagrange formula. Get `s`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `p` | Protocol | Prime modulus | Must be `p > n` and large enough for security |
| `s ∈ GF(p)` | Dealer | The secret | Any field element |
| `t` | Setup | Threshold | Min shares to reconstruct |
| `n` | Setup | Total shares | Max parties |
| `a₁...aₜ₋₁` | Dealer internal | Random polynomial coefficients | **Must be uniformly random and secret** |
| `f(x)` | Dealer internal | The sharing polynomial | |
| `sᵢ = f(i)` | Per party | Individual share | |
| `λᵢ` | Computed at reconstruction | Lagrange weights | Depend on which t shares are used |
| Channel security | Operational | How shares are delivered | Must be private — if intercepted, share is exposed |
| Share index `i` | Public | Party identifier | Does not need to be secret |

---

## 28. `feldman-vss`

### Feldman Verifiable Secret Sharing

**What it solves:** Shamir's scheme trusts the dealer. Feldman adds **verifiability** — each shareholder can confirm their share is correct using publicly posted commitments. If the dealer gives a wrong share, the recipient can prove it.

**Core addition over Shamir:**

Using the same polynomial `f(x) = s + a₁x + ... + aₜ₋₁xᵗ⁻¹`:

**Dealer additionally publishes:**
```
C₀ = s·G,  C₁ = a₁·G,  ...,  Cₜ₋₁ = aₜ₋₁·G
```
(Commitments to each coefficient — Pedersen-style in the group G.)

**Party i verifies:**
```
sᵢ·G  ==  Σⱼ iʲ · Cⱼ   (i.e., f(i)·G == C₀ + i·C₁ + i²·C₂ + ...)
```

If the dealer gave the wrong `sᵢ`, this equation won't hold.

**Security caveat:** The commitment `C₀ = s·G` reveals the discrete log commitment of the secret. If the secret space is small, this leaks the secret. Pedersen VSS (entry 29) fixes this.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| All Shamir params | Same | See entry 27 | |
| `G` | Protocol | Group generator | |
| `Cⱼ = aⱼ·G` | Public | Coefficient commitments | Publicly verifiable |
| `C₀ = s·G` | Public | Commitment to secret | **Leaks s if s-space is small** |
| Group order `q` | Protocol | Must be large | Security |
| Verification equation | Per party | `sᵢ·G == Σ iʲCⱼ` | Run locally per party |

---

## 29. `pedersen-vss`

### Pedersen Verifiable Secret Sharing

**What it solves:** Same as Feldman VSS but **hides** the secret commitment — even from the public. Uses two independent generators `G` and `H` (called a Pedersen commitment) so that `C₀ = s·G + r·H` hides `s` perfectly (information-theoretically), because you can always find `r` to explain any `s`.

**Core Pedersen commitment:**

```
Commit(s, r) = s·G + r·H   (r is blinding randomness)
```

Properties:
- **Hiding:** Without knowing `r`, `C` reveals nothing about `s` (perfect hiding).
- **Binding:** Once committed, you can't change `s` without changing `r` (computationally binding — requires DLOG hardness).

**For VSS:**

Each coefficient `aⱼ` of the polynomial gets a blinded commitment:
```
Cⱼ = aⱼ·G + bⱼ·H   (bⱼ is a random blinding factor)
```

The dealer shares two values per party: `sᵢ = f(i)` and `tᵢ = g(i)` (two polynomials, one for blinding). Party verifies:
```
sᵢ·G + tᵢ·H == Σⱼ iʲ · Cⱼ
```

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| All Shamir params | Same | | |
| `G, H` | Protocol | Two independent generators | `H` must not be a known multiple of G |
| `bⱼ` | Dealer internal | Blinding coefficients for second polynomial | Must be random |
| `g(x)` | Dealer internal | Second polynomial (blinding) | `tᵢ = g(i)` are blinding shares |
| `Cⱼ = aⱼ·G + bⱼ·H` | Public | Blinded commitments | Hides secret information |
| `sᵢ, tᵢ` | Per party | Primary and blinding shares | Both needed to verify |

---

## 30. `dkg`

### Distributed Key Generation

**What it solves:** In all threshold schemes so far, a single **dealer** creates the secret and distributes shares. This is a trusted single point of failure — the dealer knows the full secret. DKG removes the dealer entirely: `n` parties jointly generate a shared secret key where **nobody ever knows the full key** — not even temporarily.

**Core approach — Pedersen DKG:**

Each party acts as their own mini-dealer:

```
Party i:
  - Pick random secret uᵢ
  - Run VSS to share uᵢ among all n parties
  - Broadcast commitments

All parties:
  - Cross-verify each other's VSS shares
  - Accuse parties whose shares don't verify (complaint round)
  - After disputes resolved:
    xᵢ = Σⱼ sⱼᵢ   (party i's final key share = sum of i-th shares from all j)
    X  = Σⱼ Uⱼ    (public key = sum of all parties' public contributions)
```

The combined private key is `x = Σⱼ uⱼ` — no single party ever computes this.

**How it works — step by step:**

1. **Commitment round:** Each party `j` commits to `Uⱼ = uⱼ·G` and a VSS polynomial.
2. **Share distribution:** Each party `j` sends `sⱼᵢ = fⱼ(i)` to party `i` privately.
3. **Verification:** Each party `i` verifies all received shares against published commitments.
4. **Complaint round:** If verification fails, `i` publicly broadcasts the bad share. All parties verify the complaint.
5. **Disqualification:** Parties that cheated are disqualified. Remaining parties are "qualified set."
6. **Key derivation:** `xᵢ = Σ_{j ∈ qualified} sⱼᵢ`. Public key `X = Σ_{j ∈ qualified} Uⱼ`.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `n` | Setup | Number of parties | |
| `t` | Setup | Threshold | |
| `uᵢ` | Party private | Each party's secret contribution | Never shared directly |
| VSS scheme | Protocol | Feldman or Pedersen | Which VSS is used |
| `Uⱼ = uⱼ·G` | Public | Each party's public key contribution | For final public key |
| `sⱼᵢ = fⱼ(i)` | Private channel | j-to-i share | Private between j and i |
| Qualified set `Q` | Protocol | Parties who passed verification | Only these contribute to key |
| Complaint threshold | Protocol | How many complaints before disqualify | Robustness parameter |
| `xᵢ = Σ sⱼᵢ` | Party private | Final key share | Never combined |
| `X = Σ Uⱼ` | Public | Group public key | Used for verification |

---

## 31. `pvss`

### Publicly Verifiable Secret Sharing

**What it solves:** Regular VSS lets share recipients verify their own share. PVSS goes further: **anyone** — even someone who holds no share — can verify that the sharing was done correctly. This is critical for public protocols like blockchain randomness beacons, e-voting, and leader election.

**Core idea (Stadler's PVSS):**

All shares are encrypted to each party's public key and published. A proof shows the encrypted shares come from a valid polynomial:

```
For each party i with public key Yᵢ = yᵢ·G:
  Encrypted share: Xᵢ = sᵢ·G  and  Yᵢ^{sᵢ} (DLEQ proof ties these together)
  
DLEQ (Discrete Log Equality) proof: proves that
  log_G(sᵢ·G) == log_{Yᵢ}(Yᵢ^{sᵢ})
  (same sᵢ used in both)
```

A NIZK (non-interactive ZK proof) published alongside each encrypted share lets anyone verify the share is correctly formed. Consistency across all shares (that they come from degree t-1 polynomial) is checked via the commitments.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `Yᵢ = yᵢ·G` | Party public key | Each party's encryption key | Shares encrypted under this |
| `yᵢ` | Party private | Private key for decrypting share | |
| Encrypted shares | Public | Published for all to see | Anyone can verify |
| DLEQ proof | Public | Proves share consistency | Core of public verifiability |
| Commitment polynomial | Public | VSS commitments | Verify polynomial structure |
| NIZK | Protocol | Non-interactive ZK for DLEQ | Fiat-Shamir based |
| All Shamir params | Same | See entry 27 | |

---

## 32. `ot`

### Oblivious Transfer

**What it solves:** A fundamental MPC primitive. In a 1-of-2 OT, a sender has two messages `(m₀, m₁)`. A receiver wants one of them — say `mᵦ` for choice bit `b`. After the protocol:
- Receiver gets `mᵦ` only.
- Sender doesn't know which one the receiver chose (b is hidden).
- Receiver learns nothing about the other message.

It's the atomic building block under almost all MPC protocols.

**Core construction (Naor-Pinkas, elliptic curve):**

```
Sender has (m₀, m₁)
Receiver has choice b ∈ {0,1}

1. Sender picks random c, sends C = c·G
2. Receiver picks random k, sends R = b·C + k·G
   (if b=0: R = k·G; if b=1: R = C + k·G)
3. Sender computes:
   kR₀ = c·R            → encrypt m₀ under k·(c·k·G)
   kR₁ = c·(R - C)      → encrypt m₁ under c·(R-C)·G
4. Receiver decrypts mᵦ using k:
   k·G·c from their side matches sender's kRᵦ
```

**OT Extension (IKNP):** Running OT 10,000 times from scratch is expensive. OT extension lets you run `k` "base OTs" and then produce millions of OTs cheaply using only symmetric crypto. This is how large MPC is practical.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `c` | Sender internal | Random scalar | Hidden ephemeral |
| `C = c·G` | Sender | First message to receiver | |
| `k` | Receiver internal | Random scalar | Hides choice bit |
| `b ∈ {0,1}` | Receiver private | Choice bit | Never revealed to sender |
| `R` | Receiver | Response encoding b | |
| `m₀, m₁` | Sender | The two messages | |
| Encryption `E` | Protocol | Symmetric enc. (AES) applied to point | |
| Base OT count `κ` | OT extension | Number of "setup" OTs | Usually 128 |
| Extended OT count `m` | Caller | How many OTs needed | Up to millions efficiently |
| PRG | OT extension | Pseudo-random generator | Expands base OT randomness |
| `G` | Protocol | Curve generator | |

---

## 33. `vole`

### Vector Oblivious Linear Evaluation

**What it solves:** A generalization of OT. In VOLE, a sender holds vectors `u` and `v`, a receiver holds `Δ` (a global "key"). The output satisfies:

```
w = u · Δ + v    (component-wise, over a field)
```

The receiver gets `w` and `Δ`. The sender gets `u` and `v`. Nobody learns the other's values. This correlation is the building block for VOLEith ZKPs (entry 25) and many SPDZ-style MPC protocols.

**Core construction (Silent VOLE):**

Silent VOLE generates millions of VOLE correlations from a short seed using **pseudorandom correlation generators (PCG)**:

```
Both parties expand a short seed using a PRG tree (based on LPN or Ring-LPN)
→ Output: (u, v, w, Δ) satisfying w = u·Δ + v without communication per correlation
```

LPN (Learning Parity with Noise) is the hard problem underlying this.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `Δ` | Receiver private | Global evaluation point | Fixed for a session |
| `u, v` | Sender private | VOLE input vectors | |
| `w = u·Δ + v` | Receiver | VOLE output | |
| Field | Protocol | GF(2^k) or GF(p) | Determines algebraic structure |
| Length `m` | Caller | Number of VOLE correlations | How many w=uΔ+v triples |
| LPN parameters | PCG | Hamming weight, code rate | Security of Silent VOLE |
| PRG seed | Internal | Short common randomness | Expands to full VOLE batch |
| Base OT count | Internal | Bootstrapping communication | Small, O(λ) OTs |
| Communication | Practical | O(λ) per batch (Silent VOLE) | Key efficiency advantage |

---

## 34. `beaver`

### Beaver Triples for MPC

**What it solves:** The fundamental trick for evaluating **multiplication** in secret-sharing-based MPC. Each party holds additive shares of values, and XOR/addition is free. But multiplication leaks information if done naively. Beaver triples pre-share the structure needed to do multiplication safely.

**Core idea:**

A Beaver triple is a correlated random tuple `(a, b, c)` such that `a · b = c`, split among parties:
```
Additive shares: [a] = (a₁, a₂, ..., aₙ), [b] = (b₁,...), [c] = (c₁,...)
                  a = Σaᵢ,  b = Σbᵢ,  c = Σcᵢ,  and  a·b = c
```

To multiply two secret-shared values `[x]` and `[y]`:
```
Mask:  ε = x - a  (revealed publicly: each party reveals (xᵢ - aᵢ), sum = ε)
        δ = y - b  (revealed publicly)
Compute: [x·y] = [c] + ε·[b] + δ·[a] + ε·δ
         (ε and δ are public; a,b,c shares are private)
```

Each party computes locally from their shares. Result is a valid secret-sharing of `x·y`.

**How triples are generated:**

- **Dealer model:** Trusted party pre-generates and distributes.
- **OT-based:** Use OT extension to generate triples without a dealer. Standard in practice.
- **VOLE-based:** Use VOLE correlations (entry 33) to batch-generate triples.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| `[a], [b], [c]` | Generated | Shares of a correlated triple | `a·b = c` must hold |
| Field | Protocol | GF(2) for boolean, GF(p) for arithmetic | Determines which operations |
| Triple count | Computed | One triple per multiplication gate | Must be precomputed |
| `ε = x - a` | Public (per mult) | Masked x value | Leaks nothing about x since a is random |
| `δ = y - b` | Public (per mult) | Masked y value | |
| Generation protocol | Internal | OT-based or VOLE-based | Communication cost driver |
| Authentication | Optional | MAC on each share | Detects malicious parties (SPDZ model) |
| MAC key `Δ` | Internal (SPDZ) | Global MAC key | Each share `[x]` has MAC `[Δ·x]` |

---

## 35. `mpc-ecdsa`

### Generic MPC ECDSA Signing Surface

**What it solves:** A unified interface layer over multiple ECDSA threshold protocols (TECLA, THE-CLASH, CCGMP, BAM). Rather than committing to one specific protocol, MPC-ECDSA exposes a standard API and lets the backend protocol be swapped. This is useful for libraries that want to support different ECDSA threshold schemes interchangeably.

**What it abstracts:**

```
interface MpcEcdsa {
  KeyGen(n, t) → (shares[n], pubkey)
  Sign(shares[t], message) → signature
  Verify(pubkey, message, signature) → bool
  Refresh(shares[n]) → new_shares[n]   // proactive key refresh
}
```

**Proactive secret sharing (key refresh):** After some time, old shares are "refreshed" — each party gets a new share of the same key, making old compromised shares useless. This is done by running a new round of secret sharing with zero as the secret, and adding it to existing shares.

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| Backend protocol | Config | TECLA / THE-CLASH / CCGMP / BAM | Actual cryptographic protocol |
| `n, t` | Setup | Group size, threshold | |
| Key shares | Party private | Shares in the chosen protocol's format | |
| Curve | Config | secp256k1, P-256, etc. | Must match intended use case |
| Refresh interval | Policy | How often to do proactive refresh | Limits exposure from old compromises |
| Identifiable abort | Config | Whether protocol can blame a cheater | Some protocols support, some don't |
| Presigning | Optional | Whether to precompute `(r, k⁻¹·x)` | Performance optimization |
| Serialization format | Config | How shares are encoded on disk/wire | |

---

## 36. `mpc-schnorr`

### Generic MPC Schnorr Signing Surface

**What it solves:** Same as MPC-ECDSA but for Schnorr-based protocols (FROST, GARGOS, CLASSIC-SCHNORR). A unified interface abstracting over the Schnorr threshold protocol family.

**Why Schnorr is easier to make threshold:**

Schnorr's response `s = k + e·x` is **linear** in both `k` (nonce) and `x` (private key). This means secret sharing both independently and adding partial responses works directly:
```
s = Σᵢ sᵢ   where  sᵢ = kᵢ + e · λᵢ · xᵢ
```
No MtA, no Paillier, no quadratic costs — just linear combination.

**Interface:**

```
interface MpcSchnorr {
  KeyGen(n, t, curve) → (shares[n], pubkey)
  Preprocess(party, count) → nonce_commitments   // FROST-style
  Sign(shares[t], nonce_material, message) → signature
  Verify(pubkey, message, signature) → bool
  Aggregate(partial_sigs[t]) → signature         // Coordinator role
}
```

**Parameters:**

| Parameter | Who sets it | What it is | Why it matters |
|-----------|-------------|------------|----------------|
| Backend protocol | Config | FROST / GARGOS / CLASSIC-SCHNORR | Determines security properties |
| `n, t` | Setup | Group size, threshold | |
| Curve | Config | Ed25519 / secp256k1 / Ristretto255 | Determines group and hash |
| Key shares `xᵢ` | Party private | Shamir shares of private key | |
| Nonce commitments | Preprocess | Batches of `(Dᵢ, Eᵢ)` | FROST preprocessing — stored |
| Binding factor | Internal | FROST-only — `ρᵢ = H(i, m, commitments)` | Prevents Wagner attack |
| Hash-to-scalar `H` | Protocol | How challenge `e` is computed | Domain separation important |
| Coordinator | Role | Who aggregates partial sigs | Can be any party or external |
| Identifiable abort | Config | Can bad party be identified? | Protocol-dependent |
| Aggregation key | Optional | BLS-style multi-key aggregation | If using non-interactive variant |

---

## Appendix A — Parameter Glossary

| Symbol | Name | Where it appears |
|--------|------|-----------------|
| `n` | Party count | All threshold schemes |
| `t` | Threshold | All threshold schemes |
| `q` | Group/field prime | EC schemes, lattice schemes |
| `G` | Generator point | All EC schemes |
| `λᵢ` | Lagrange coefficient | All Shamir-based schemes |
| `κ` | Security parameter | All schemes (usually 128 or 256 bits) |
| `σ` | Gaussian std dev | Lattice schemes |
| `η` | Secret coefficient bound | ML-DSA |
| `Δ` | Scaling factor (FHE) or MAC key (SPDZ) | FHE schemes, SPDZ |
| `ρᵢ` | Binding factor | FROST |
| `R` | Nonce commitment point | Schnorr, ECDSA |
| `e` | Challenge scalar | All signature schemes |
| `s` | Signature response | All signature schemes |

---

## Appendix B — Security Properties Quick Reference

| Property | Meaning | Which schemes care most |
|----------|---------|------------------------|
| **t-Privacy** | `t-1` colluding parties learn nothing | All threshold schemes |
| **Correctness** | Honest parties always succeed | All |
| **Unforgeability (EUF-CMA)** | Cannot forge sigs without threshold | All signing schemes |
| **Identifiable Abort** | Can tell who cheated | GG20-style, optional in others |
| **Proactive Security** | Old shares become useless after refresh | MPC-ECDSA, MPC-Schnorr refresh |
| **Post-Quantum Security** | Safe against quantum computers | Hash-based, lattice, code-based schemes |
| **Simulation-Based Security** | Protocol leaks only intended output | Formal model for all schemes |

---

*Guide covers NextSSL's full 36-algorithm threshold surface. All equations use standard cryptographic notation. All parameters include both caller-visible and internal/hidden parameters.*
