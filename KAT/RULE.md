# KAT RULE

This document defines the canonical KAT data model for this workspace using dynamic
Python modules. All new KAT data belongs in `KAT/data/` and is stored as one module
per algorithm.

## Goals

- Store KAT datasets as Python modules for easy integration and programmatic use.
- Keep one file per algorithm and one category folder per KAT type.
- Reserve `KAT/repo/` for source/reference implementations and generation tooling only.
- Use the parser in `KAT/data/kat_base.py` to load and validate KAT modules.

## KAT layout

```tree``````````````````````````   
KAT/
  data/
    encoding/
      base16.py
      base32.py
      base58.py
      base64.py
      base64url.py
      base85.py
      bech32.py
      base58check.py
      base62.py
      crc32.py
      crc64.py
      ff70.py
      hex.py
      pem.py
    hash/
    modern/
    pqc/
  repo/
    encoding/
    hash/
    modern/
    pqc/
```

All new KAT data files live under `KAT/data/<category>/`.
Each algorithm gets exactly one module named `<normalized_algorithm>.py`.

Category folders:

- `encoding/`
- `hash/`
- `modern/`
- `pqc/`

`KAT/repo/` is for source material, reference implementations, and generation
scripts only.

## File naming and normalization

- Use underscore-separated filenames in Python modules.
- Replace hyphens and plus signs with underscores.
- Do not create per-algorithm subdirectories under `KAT/data/`.

Examples:

- `KAT/data/encoding/base64.py`
- `KAT/data/hash/sha256.py`
- `KAT/data/modern/aes_gcm.py`
- `KAT/data/pqc/falcon_512.py`

## Module structure

Every KAT module must export:

- `meta` — a dictionary with module metadata
- `cases` — a list of test case dictionaries

Required meta fields:

- `group` — one of `encoding`, `hash`, `modern`, `pqc`
- `algorithm` — canonical algorithm ID
- `source` — `nist`, `rfc`, `vendor`, `generated`, or `repo`
- `source_ref` — reference text, URL, or commit identifier
- `generated_by` — tool name/version or `None`
- `date` — ISO-formatted date string

Case structure:

- `id` — unique case identifier
- `input` — input fields for the algorithm
- `config` — algorithm parameters
- `output` — expected output fields
- optional `notes`
- optional `tags`

The parser can detect which optional keys are present and which are omitted.
Only include fields that are meaningful for the specific algorithm.

## Encoding modules

Encoding modules should expose only the fields needed for their cases.
A typical encoding KAT module looks like this:

```python
meta = {
    "group": "encoding",
    "algorithm": "base64",
    "source": "rfc",
    "source_ref": "RFC 4648",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    {
        "id": "base64-rfc4648-0001",
        "input_hex": "616263",
        "config": {
            "variant": "standard",
            "padding": True,
        },
        "output": "YWJj",
    }
]
```

For encoding data modules:

- `input_hex` is the canonical input field
- `output` is the encoded representation
- `config` contains algorithm-specific options

## Parser support

`KAT/data/kat_base.py` provides utilities to load and validate KAT modules:

- `load_kat_module(module_name)`
- `load_all_kats()`
- `validate_kat_module(module)`

The parser validates required metadata and ensures each case has the expected
base fields. Optional fields are detected dynamically, so modules only need to
declare the keys that apply.

## Rules summary

- Use Python modules only; do not store KAT data as JSON or text files.
- One algorithm = one file.
- One category folder = one algorithm group.
- `KAT/data/<category>/<normalized_algorithm>.py` is the canonical path.
- `KAT/repo/` is for refs and tooling, not the primary KAT dataset.

## Encoding algorithms to create now

The following encoding algorithms will be represented in `KAT/data/encoding/`:

- base16
- base32
- base58
- base64
- base64url
- hex
- ff70
- base58check
- base62
- base85
- bech32
- pem
- crc32
- crc64

---

## PQC KAT generation strategy

PQC algorithms (Group 4) require a special approach because their internal
operations are inherently randomised (key generation, encapsulation, signing).
Standard `rsp`-style KATs from the NIST PQC project feed a DRBG with a known
seed so every output is fully deterministic and reproducible.

### Toolchain — PQClean

Use **PQClean** (`https://github.com/PQClean/PQClean`) as the sole reference
implementation for all PQC KAT files. PQClean is the official, audited,
clean-room implementation suite accepted by NIST.

### Deterministic seed control

PQClean test harnesses use the `NIST DRBG` (AES-256 in CTR mode, as in
`test/common/randombytes.c`). To make the seed explicit and round-trippable:

1. **Patch `randombytes.c`** — expose the 48-byte entropy seed via a new
   `randombytes_seed_get(uint8_t out[48])` function and a
   `randombytes_seed_set(const uint8_t seed[48])` function. Store the seed in a
   file-scope variable so it can be read back after the DRBG is initialised.

2. **Wrap the test binary** — modify `test/test_kem.c` and `test/test_sign.c`
   so they:
   - Accept an optional seed hex string via `argv[1]` (default: all-zeros).
   - Print the seed at the top of output for reproducibility.
   - Emit `seed`, `pk`, `sk`, `ct`, `ss` (KEM) or `seed`, `pk`, `sk`, `msg`,
     `sig` (DSA/Falcon) in a simple `key=hex` format.

3. **Python extraction script** — `KAT/repo/pqc/gen_kat.py` parses the
   binary output and writes the canonical `.py` KAT module in `KAT/data/pqc/`.

### KAT case structure for PQC

KEM algorithms:

```python
{
    "id": 1,
    "seed_hex": "<48-byte DRBG seed>",          # controls key-gen and encap
    "pk_hex":   "<public key>",
    "sk_hex":   "<secret key>",
    "ct_hex":   "<ciphertext>",
    "ss_hex":   "<shared secret>",
}
```

Signature algorithms:

```python
{
    "id": 1,
    "seed_hex": "<48-byte DRBG seed>",          # controls key-gen and signing
    "pk_hex":   "<public key>",
    "sk_hex":   "<secret key>",
    "msg_hex":  "<message to sign>",
    "sig_hex":  "<signature>",
}
```

### Workflow summary

```
git clone https://github.com/PQClean/PQClean
cd PQClean
# apply seed-exposure patch (see KAT/repo/pqc/patches/)
make <scheme>
./test/test_kem_<scheme> <seed_hex>   # or test_sign_<scheme>
python KAT/repo/pqc/gen_kat.py <output> > KAT/data/pqc/<algo>.py
```

All PQC KAT files are generated this way. Raw `.req`/`.rsp` NIST KAT files
may be placed in `KAT/downloads/pqc/` for cross-reference but the `.py`
module is the canonical dataset.

### Deferred

All PQC KAT files (Group 4, entries 92–126) are **deferred** until the PQClean
patching workflow is in place. Mark all Group 4 entries `[~]` when work begins
and `[x]` only after at least 3 deterministic cases have been verified against
a second independent implementation.
