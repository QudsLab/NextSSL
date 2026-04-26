# Missing Cryptographic Domains

This file documents crypto domains NOT yet in ALGO.md, with proof they don't fundamentally collide with existing algorithms.

---

## 1. Zero-Knowledge Proofs (ZKP)

**What it is:** Proofs that verify a statement is true without revealing any information beyond validity.

**Math Example:**

```
Prover knows x such that Hash(x) = H (preimage resistance)
  Prover: x → [compute proof π] → Verifier
  Verifier: check Verify(H, π) = true/false

  Property: π reveals ZERO about x

Example: zkSNARK
  CRS: (G1, G2, [s·G1, s²·G1, ..., sⁿ·G1])
  Proof π = (π₁, π₂) where π₁ = [C + H(public)·s]·(1/(x+α))
  Verification: e(π₂, G₁) = e(C + public·α, π₁)  (pairing check)
```

```mermaid
flowchart LR
    subgraph ZKP["Zero-Knowledge Proof"]
        W["Witness x"] -->|compute| P["Prover C(x,w)"]
        S["Statement H"] -->|input| P
        P -->|output| Pi["Proof π"]
        Pi -->|verify| V["Verifier"]
        V -->|result| R["accept/reject"]
    end
    style ZKP fill:#e1f5fe
    style Pi fill:#fff3e0
    style R fill:#e8f5e9
```

**Non-collision proof:**

- Uses hash functions for Merkle trees/commitments, BUT adds new property: "proof of knowledge"
- NOT fundamental collision: Adds zero-knowledge property that hash/signature algos don't have

**OpenSSL:** Not supported (external libs: libsnark, zcash)

---

## 2. Functional Encryption (FE)

**What it is:** Encryption allowing fine-grained access control - decrypt different ciphertexts to different authorization levels.

**Math Example:**

```
Standard Encryption:
  CT = Enc(k, m) → Dec(k, CT) = m  (ALL or NOTHING)

Functional Encryption:
  CT = Enc(pk, m) with attributes a
  Dec(sk_attr, CT) = f(m) where f depends on attr match
```

```mermaid
flowchart TB
    Setup["Setup(1^λ)"] --> pkmsk["(pk, msk)"]
    pkmsk --> KeyGen["KeyGen(msk, policy)"]
    KeyGen --> sk["sk_policy"]
    pkmsk --> Encrypt["Encrypt(pk, m, attr)"]
    Encrypt --> CT["Ciphertext"]
    CT --> Decrypt["Decrypt(sk, CT)"]
    sk --> Decrypt
    Decrypt --> fx["f(m)"]
    
    subgraph FE["Functional Encryption - Different keys = Different outputs"]
        fx --> f1["f₁(m) = manager"]
        fx --> f2["f₂(m) = salary"]
        fx --> f3["f₃(m) = all"]
    end
    style FE fill:#e1f5fe
```

**OpenSSL:** Not supported

---

## 3. Private Set Intersection (PSI)

**What it is:** Protocol for two parties to find intersection of datasets without revealing each party's private data.

**Math Example:**

```
Party A: Set S = {a₁, a₂, ..., aₙ}
Party B: Set T = {b₁, b₂, ..., bₘ}

PSI Protocol (hash-based):
  1. A sends: Hash(aᵢ) for all aᵢ ∈ S
  2. B computes: Check if Hash(aᵢ) ∈ Hash(T)
  3. Output: |S ∩ T|
```

```mermaid
flowchart TB
    A["Party A: S = {1,3,5,7,9}"] --> HashA["Hash each element"]
    HashA --> BF["Bloom Filter"]
    B["Party B: T = {2,3,4,5,6}"] --> Test["Filter Test"]
    
    BF --> Test
    Test --> Out["Output: {3,5}"]
    
    style BF fill:#e8f5e9
    style Out fill:#fff3e0
```

**OpenSSL:** Not supported (external libs: PSI protocols)

---

## 4. Commitment Schemes

**What it is:** Cryptographic primitive allowing one to commit to a value while keeping it hidden, later revealing.

**Math Example:**

```
Pedersen Commitment:
  Commit: C = g^x · h^r  (choose random r)
  Open: reveal (x, r), verifier checks C = g^x·h^r

Property: Hiding (C reveals nothing) + Binding (cannot change x)
```

```mermaid
flowchart LR
    subgraph COMMIT["COMMIT PHASE"]
        x["x (secret)"] --> C1["Commit(x, r)"]
        r["randomness r"] --> C1
        C1 --> C["C = g^x · h^r"]
        C -->|"hidden"| Verifier1["Verifier"]
    end
    
    subgraph OPEN["OPEN PHASE"]
        reveal["reveal x, r"] --> V2["Verify"]
        C -.->|"same C"| V2
        V2 -->|"check"| Result["ACCEPT/REJECT"]
    end
    
    style COMMIT fill:#e1f5fe
    style OPEN fill:#fff3e0
```

**OpenSSL:** Limited (custom impl only)

---

## 5. Secure Multi-Party Computation (MPC)

**What it is:** Protocols enabling parties to jointly compute a function over their inputs while keeping inputs private.

**Math Example:**

```
Yao's Garbled Circuits:
  Party A: Garble circuit C for f(x,y)
  Party B: OT for input, evaluate
  
SPDZ Protocol:
  Secret share inputs → Compute on shares → Reconstruct
```

```mermaid
flowchart TB
    P1["Party P₁: x₁"] -->|secret share| S1["x₁ = s₁¹ + s₁²"]
    S1 --> MPC["Shared Computation"]
    
    P2["Party P₂: x₂"] -->|secret share| S2["x₂ = s₂¹ + s₂²"]
    S2 --> MPC
    
    Pn["Party Pₙ: xₙ"] -->|secret share| Sn["xₙ = sₙ¹ + sₙ²"]
    Sn --> MPC
    
    MPC --> Result["f(x₁,...,xₙ) shared output"]
    Result -->|each gets| RO["Result to all"]
    
    style MPC fill:#e1f5fe
    style Result fill:#fff3e0
```

**OpenSSL:** Not supported (external libs: MPySC, SCALE-Mamba)

---

## 6. Proxy Re-Encryption (PRE)

**What it is:** Encryption allowing a proxy to transform ciphertext from one key to another WITHOUT seeing plaintext.

**Math Example:**

```
PRE based on RSA:
  Encrypt: C = m^e mod n (for A)
  ReKey: rk = (d₁/d₂) mod λ
  Transform: C' = C^rk = m^(e·rk) = m^d₁ mod n
```

```mermaid
flowchart LR
    Sender["Sender"] -->|Encrypt m| CTA["CT₁ for A"]
    CTA -->|send| Proxy["Proxy / Re-Encryption Key"]
    Proxy -->|rk| Transform["Transform CT₁ → CT₂"]
    Transform -->|CT₂| B["Recipient B"]
    B -->|Decrypt| m["Original message m"]
    
    Proxy -.->|"never sees"| m
    
    style Proxy fill:#fff3e0
    style Transform fill:#e8f5e9
```

**OpenSSL:** Not supported (external libs: IBM PRE)

---

## 7. Verifiable Random Functions (VRF)

**What it is:** Function that produces random-looking output that's verifiable as authentic without revealing the seed.

**Math Example:**

```
EC-VRF:
  KeyGen: secret s, public Y = s·G
  Compute: H = s·P (appears random)
  Prove: π = [P, s·Hash(P)]
  Verify: e(π₁, G) = e(Hash(P), Y)
```

```mermaid
flowchart TB
    subgraph KEYGEN["Key Generation"]
        s["secret seed s"] --> Y["Y = s·G (public key)"]
    end
    
    subgraph COMPUTE["VRF Compute"]
        input["INPUT"] --> P["HashToCurve(P)"]
        s -->|"multiply"| H["H = s·P (random-looking)"]
        P -->|"hash"| Hp["Hash(P)"]
        s -->|"multiply"| Proof["π = s·Hash(P)"]
    end
    
    subgraph VERIFY["VRF Verify"]
        input2["INPUT"] --> V["VerifyVRF"]
        H --> V
        Proof --> V
        Y --> V
        V -->|check| result["valid/invalid"]
    end
    
    style H fill:#e8f5e9
    style result fill:#fff3e0
```

**OpenSSL:** Limited (custom impl)

---

## 8. Aggregate Signatures

**What it is:** Signatures that can be combined into a shorter single signature verifying multiple messages.

**Math Example:**

```
BLS Aggregation:
  Sign: σᵢ = sᵢ · H(mᵢ)
  Aggregate: σ = Σ σᵢ
  Verify: e(σ, G) = e(Σ pkᵢ, H(m))
```

```mermaid
flowchart TB
    P1["Party 1"] -->|Sign m₁| s1["σ₁ = s₁·H(m₁)"]
    P2["Party 2"] -->|Sign m₂| s2["σ₂ = s₂·H(m₂)"]
    Pn["Party n"] -->|Sign mₙ| sn["σₙ = sₙ·H(mₙ)"]
    
    s1 --> Aggregate["σ = σ₁ ⊕ σ₂ ⊕ ... ⊕ σₙ"]
    s2 --> Aggregate
    sn --> Aggregate
    
    Aggregate --> Verify["Single Verify"]
    Verify --> Result["valid - all n messages"]
    
    style Aggregate fill:#e8f5e9
    style Result fill:#fff3e0
```

**OpenSSL:** Not supported (BLS not in OpenSSL)

---

## 9. Password-Hardened Encryption (PHE)

**What it is:** Encryption where password contributes to key derivation, combining password with cryptographic key.

**Math Example:**

```
Two-Factor:
  K₁ = KeyGen() (random)
  K₂ = Argon2(password)
  K = K₁ ⊕ K₂
  CT = Enc(K, m) + Enc(K₁, K₂)
```

```mermaid
flowchart TB
    subgraph ENCRYPT["Encrypt"]
        KG["KeyGen()"] --> K1["K₁ (random key)"]
        Pwd["password"] --> Argon["Argon2id"]
        Argon --> K2["K₂ (from password)"]
        K1 --> XOR1["K = K₁ ⊕ K₂"]
        K2 --> XOR1
        XOR1 --> Enc["Enc_AES_GCM(K, m)"]
        Enc --> CT["Ciphertext"]
    end
    
    subgraph DECRYPT["Decrypt"]
        CT2["Ciphertext"] --> Dec["Decrypt"]
        Pwd2["password"] --> Argon2["Argon2id"]
        Argon2 --> K2d["K₂"]
        CT2 --> Extract["Extract K₁ from sealed"]
        Extract --> XOR2["K = K₁ ⊕ K₂"]
        K2d --> XOR2
        XOR2 --> Dec
        Dec --> m["message m"]
    end
    
    style XOR1 fill:#e8f5e9
    style XOR2 fill:#e8f5e9
```

**OpenSSL:** Not supported (custom protocol)

---

## 10. Proof of Reserve (PoR)

**What it is:** Cryptographic proof that a custodian holds backing assets (e.g., for stablecoins).

**Math Example:**

```
Merkle Sum Tree:
  Leaves: balance[i]
  Root: Σ balance[i] = Total reserves
  Proof: Merkle path → verify sum matches root
```

```mermaid
flowchart TB
    subgraph CUSTODIAN["Custodian"]
        Assets["Assets list"] --> Tree["Build Merkle Sum Tree"]
        Tree --> Root["Root hash = Σ balances"]
        Root --> Pub["Publish: Root + timestamp"]
    end
    
    Pub --> Query["User/Auditor Query"]
    Query --> Prove["Provide Merkle proof"]
    Prove --> Check["Verify path sums to root"]
    Check --> Result["assets ≥ liabilities / FAIL"]
    
    style Tree fill:#e1f5fe
    style Result fill:#fff3e0
```

**OpenSSL:** Not supported (external oracle integrations)

---

## Summary: Collision Analysis

| Domain | Base Algos Used | New Primitive? | Collision? |
|--------|---------------|----------------|-------------|
| ZKP | sha256, ed25519 | YES (proof) | NO |
| FE | aes, pairings | YES (partial decrypt) | NO |
| PSI | sha256, aes, ot | YES (protocol) | NO |
| Commitment | sha256, ec | YES (binding) | NO |
| MPC | aes, hash, ot | YES (model) | NO |
| PRE | rsa, ec | YES (transform) | NO |
| VRF | sha256, ecdsa | YES (verifiable randomness) | NO |
| Aggregate | blake2b (BLS) | PARTIAL | MINOR |
| PHE | argon2, aes | YES (protocol) | NO |
| PoR | sha256, ed25519 | YES (protocol) | NO |

---

## 11. Additional NIST-Approved Domains (from SP 800-140C / CAVP)

### 11.1 KDF Variants

| Algorithm | NIST Standard | OpenSSL | ALGO.md |
|-----------|-------------|--------|---------|
| `hkdf` | SP 800-56Cr2 | YES | YES |
| `tls-kdf` | SP 800-135 | YES | NO |
| `ssh-kdf` | RFC 4253 | YES | NO |
| `pbkdf2` | SP 800-132 | YES | YES |
| `scrypt` | - | YES | YES |
| `argon2id` | - | YES | YES |

### 11.2 Key Agreement / KAS

| Algorithm | NIST Standard | OpenSSL | ALGO.md |
|-----------|-------------|--------|---------|
| `x25519` | SP 800-56A | YES | YES |
| `x448` | SP 800-56A | YES | YES |
| `p-256`, `p-384`, `p-521` | SP 800-56A | YES | YES |
| `rsa` | SP 800-56B | YES | YES |

### 11.3 Digital Signatures

| Algorithm | FIPS Standard | OpenSSL | ALGO.md |
|-----------|-------------|--------|---------|
| `rsa` | FIPS 186-5 | YES | YES |
| `ecdsa` | FIPS 186-5 | YES | YES |
| `ed25519` | FIPS 186-5 | YES | YES |
| `ed448` | FIPS 186-5 | YES | Conditional |
| `ml-dsa-44/65/87` | FIPS 204 | YES | YES |
| `slh-dsa-*` | FIPS 205 | YES | YES |
| `lms` | SP 800-208 | YES | NO |

### 11.4 DRBG / RNG

| Algorithm | SP 800-90A | OpenSSL | ALGO.md |
|-----------|-----------|--------|---------|
| `hash-drbg` | YES | YES (default) | NO |
| `hmac-drbg` | YES | Internal | NO |
| `ctr-drbg` | YES | YES | NO |

### 11.5 Ascon (Lightweight)

| Algorithm | SP 800-232 | OpenSSL | ALGO.md |
|-----------|------------|--------|---------|
| `ascon-hash256` | New | YES (3.x) | NO |
| `ascon-xof128` | New | YES | NO |
| `ascon-aead128` | New | YES | NO |

---

## 12. ALGO.md vs OpenSSL Coverage

```mermaid
flowchart TB
    subgraph ALGO["ALGO.md Inventory"]
        Enc["Encoding (14)"] --> Hash["Hash/KDF (45)"]
        Hash --> Mod["Modern (32)"]
        Mod --> PQC["PQC (35)"]
        PQC --> Thresh["Threshold (26)"]
    end
    
    subgraph OPENSSL["OpenSSL 3.x"]
        Enc2["Encoding\n(limited)"] --> Hash2["Digests\n(20+)"]
        Hash2 --> Cipher["Symmetric\n(30+)"]
        Cipher --> Sig["Signatures\n(15+)"]
        Sig --> KDF2["KDF/KAS\n(10+)"]
    end
    
    subgraph MISSING["Gaps"]
        M1["ZKP, FE, PSI\nMPC, PRE, VRF"]
        M2["Ascon variants\n(~4)"]
        M3["KDF variants\n(~6)"]
        M4["BLS Aggregate\nLMS, HSS"]
    end
    
    ALGO -->|coverage| OPENSSL
    OPENSSL -->|missing| MISSING
    
    style MISSING fill:#ffcdd2
```

### Coverage Summary

| Category | ALGO.md | OpenSSL | Gap |
|----------|--------|--------|-----|
| Encoding | 14 | ~6 | ~8 |
| Hash/KDF | 45 | ~20 | ~15 |
| Modern | 32 | ~30 | ~2 |
| PQC | 35 | ~20 | ~15 |
| Threshold | 26 | ~3 | ~23 |
| NIST KDF | 10 | ~8 | ~2 |
| Total | 162+ | ~87 | ~65 |

### Conclusion

- Many domains (ZKP, MPC, PRE, VRF, Aggregate) NOT in OpenSSL - rely on external libs
- Ascon: Recently added (OpenSSL 3.x)
- Encoding: OpenSSL has minimal coverage (limited to base64)
- BLS Aggregate, LMS/HSS: Not in standard OpenSSL (only in external forks)
