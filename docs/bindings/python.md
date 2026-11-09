# NextSSL from Python (ctypes)

Example: `examples/python/nextssl_demo.py` (one file, standard library only). It contains a small binding
(`NextSSL` class, about 150 lines) and a demo for **every** algorithm kind. Read [c-abi.md](c-abi.md) for the
function reference, error codes and buffer rules; this page shows how they look in Python.

## Build the library

```
cargo build -p nextssl-ffi --release                       # 367 algorithms
cargo build -p nextssl-ffi --release --features everything # all 386 (copyleft and heavy algorithms)
```

This produces `target/release/libnextssl_ffi.so` (Linux), `libnextssl_ffi.dylib` (macOS) or `nextssl_ffi.dll`
(Windows) next to a static library. The example looks there (`release`, then `debug`) or at the path in the
`NEXTSSL_LIB` environment variable. Build and run in Docker if you do not have a Rust toolchain:

```
docker run --rm -v "$PWD":/src -w /src nextssl-test cargo build -p nextssl-ffi --release --features everything
```

## Run the example

```
python examples/python/nextssl_demo.py                    # list every algorithm (id, kind, tier, safe/root)
python examples/python/nextssl_demo.py --list kem         # one kind
python examples/python/nextssl_demo.py sha256             # demo for one algorithm
python examples/python/nextssl_demo.py ml-kem-768
python examples/python/nextssl_demo.py --root md5         # legacy/broken/research/unverified need --root
python examples/python/nextssl_demo.py --params hash=sha512 hmac
python examples/python/nextssl_demo.py --info ml-dsa-65   # registry entry as JSON
python examples/python/nextssl_demo.py --all              # demo for every algorithm (root API), with a summary
```

Exit status is the NextSSL error code (0 on success). The demo per kind: hash digest of `abc` checked against a
known answer where the example knows one (`sha256`, `sha1`, `md5`); xof; checksum (`crc32` check value); encoding
round trip; MAC with verify and tampered verify; KDF; password hash and verify; AEAD round trip and tampered
rejection; block cipher, stream cipher and block mode round trips; KEM encaps/decaps; key exchange from both sides;
sign/verify and wrong-message rejection; RNG and DRBG; PKE round trip; stateful signatures (two signatures, the
state advancing); PAKE between two parties (multi-round loop); threshold split/combine. `zk` has no demo (its
statement is a scheme-specific commitment computed outside the library).

## Using the binding in your code

```python
from nextssl_demo import NextSSL, NextSSLError, U64     # copy the file or put it on sys.path

ns = NextSSL()                       # safe API: safe and standard tiers
root = NextSSL(root=True)            # nextssl_root_* entry points: every tier

digest = ns.call("hash_with", "sha256", None, b"abc")[0]                 # params=None
key = ns.random(32)                                                      # os-entropy
nonce = ns.random(12)
ct = ns.call("aead_seal", "aes-256-gcm", None, key, nonce, b"hdr", b"secret")[0]
pt = ns.call("aead_open", "aes-256-gcm", None, key, nonce, b"hdr", ct)[0]
pk, sk = ns.call("kem_keygen", "ml-kem-768", None, outs=2)
ct, ss = ns.call("kem_encaps", "ml-kem-768", None, pk, outs=2)
ok = ns.check("verify_detached", "ed25519", None, pk2, b"msg", b"", sig)  # True / False
```

`call(op, *args, outs=1)` maps Python values to the C types: `str` to `const char *`, `None` to NULL, `bytes` to a
`nextssl_in`, `int` to `size_t`, and `U32`/`U64`/`U16` wrappers to fixed-width integers (`difficulty`, handles,
party ids). It returns the output byte strings, growing the buffers automatically.

## API by kind

The Python names are the C names without the `nextssl_` / `nextssl_root_` prefix; the tier is chosen by
`NextSSL(root=...)`. Outputs are listed as returned.

| Kind | Call | Returns |
|---|---|---|
| hash | `call("hash_with", alg, p, data)` | `[digest]` |
| xof | `call("xof", alg, p, data, n)` | `[n bytes]` |
| checksum | `call("checksum", alg, p, data)` | `[value]` |
| encoding | `call("encode_with"/"decode_with", alg, p, data)` | `[text]` / `[bytes]` |
| mac | `call("mac", alg, p, key, data, 0)`; `check("mac_verify", alg, p, key, data, tag)` | `[tag]`; bool |
| kdf | `call("kdf", alg, p, ikm, salt, info, n)` | `[n bytes]` |
| pwhash | `call("pwhash", alg, p, password)`; `check("pwhash_verify", alg, p, password, phc)` | `[phc]`; bool |
| aead | `call("aead_seal"/"aead_open", alg, p, key, nonce, aad, data)` | `[ct||tag]` / `[plaintext]` |
| blockcipher | `call("blockcipher_encrypt"/"_decrypt", alg, p, key, block)` | `[block]` |
| streamcipher | `call("stream_apply", alg, p, key, nonce, data)` | `[data]` |
| blockmode | `call("blockmode_encrypt"/"_decrypt", alg, p, key, nonce, data)` | `[data]` |
| kem | `call("kem_keygen", alg, p, outs=2)`, `call("kem_encaps", alg, p, pk, outs=2)`, `call("kem_decaps", alg, p, sk, ct)` | `[pk, sk]`, `[ct, ss]`, `[ss]` |
| kex | `call("kex_keygen", ..., outs=2)`, `call("kex_agree", alg, p, sk, peer_pk)` | `[pk, sk]`, `[ss]` |
| sign | `call("sign_keygen", ..., outs=2)`, `call("sign_detached", alg, p, sk, msg, ctx)`, `check("verify_detached", alg, p, pk, msg, ctx, sig)` | `[pk, sk]`, `[sig]`, bool |
| rng | `call("rng_fill", alg, p, n)` | `[n bytes]` |
| drbg | `h = ns.new_handle("drbg_new", alg, p, entropy, nonce, pers)`; `call("drbg_generate", U64(h), b"", n)`; `call("drbg_free", U64(h), outs=0)` | handle; `[bytes]` |
| pke (root) | `call("pke_keygen", ..., outs=2)`, `pke_encrypt(alg, p, pk, pt, label)`, `pke_decrypt(alg, p, sk, ct, label)` | |
| statefulsign (root) | `stateful_keygen` (`[pk, state]`), `stateful_sign(alg, p, state, msg, outs=2)` (`[sig, new_state]`), `check("stateful_verify", ...)` | |
| pake (root) | see `_pake_start` / `_pake_step` in the example | |
| threshold (root) | `threshold_split(alg, p, secret, t, n)` / `threshold_combine(alg, p, packed)` | packed lists |

`p` is the parameter string or `None`.

## Tiers and root access

`NextSSL()` raises `NextSSLError` with `code == 3` for any algorithm outside `safe`/`standard`. Use `NextSSL(root=True)`
(`--root` in the example) to accept the risk of `legacy`, `broken`, `research` and `unverified` algorithms. Root-only
kinds (pke, pake, statefulsign, zk, threshold, he, vdf) are reachable only with `root=True`; with `root=False` the
binding reports that the operation exists only as `nextssl_root_*`. `info["safe_api"]` says which a given
algorithm needs.

## Error handling

Every non-zero status raises `NextSSLError(code, message, op)`; `str(e)` includes the library's message and
`e.code` is the number from [c-abi.md](c-abi.md). Verify-style calls go through `check()`, which turns
`AUTHENTICATION_FAILED` (14) into `False` and still raises for malformed input. Nothing falls back to another
algorithm: an unknown name is code 1, a wrong key length is code 8.

## Buffer sizes

The binding starts every output at 256 bytes and, on `BAD_OUTPUT_LEN` (10), retries with the exact size the library
reports; nothing is ever truncated. For secret-producing calls (key generation, encapsulation, signing) the
retry draws fresh randomness, so only the final result is used. To avoid the retry, size buffers from
`info["sizes"]` (for example `sizes["pk"]["max"]`). The Python `bytes` you receive and the key bytes you pass in
are ordinary Python objects and are **not** wiped by the library; keep secrets in `bytearray` and overwrite them when done if that
matters to you.

## Platform notes

* **Windows**: build with the MSVC toolchain (`x86_64-pc-windows-msvc`); load `nextssl_ffi.dll` with a 64-bit Python.
  Tested: Windows 11, Python 3.14.8, debug build of the DLL.
* **Linux**: `libnextssl_ffi.so` links against glibc. Tested in Docker: `python:3.12-slim` (Debian, glibc) with a
  release build from the `nextssl-test` image.
* **macOS**: `libnextssl_ffi.dylib`; use a Python of the same architecture (arm64 or x86_64) as the library. Not tested here.
* The example uses `ctypes.CDLL`; on Windows pass the full path (as `NEXTSSL_LIB` does).
