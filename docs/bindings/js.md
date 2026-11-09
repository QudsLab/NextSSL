# NextSSL from JavaScript (WebAssembly)

Example: `examples/js/nextssl_demo.mjs` (one ES-module file: a `NextSSL` class over the wasm exports, a small
WASI shim, and a demo for eleven kinds: hash, xof, checksum, encoding, mac, kdf, aead, kem, kex, sign, rng).
`examples/js/browser.html` is a short page that imports the same class in a browser. Function reference,
error codes and buffer rules: [c-abi.md](c-abi.md). The Python example covers every kind.

## What this is, and the wasi-libc question

The module is the **same C ABI library**, compiled for `wasm32-wasip1` (Rust plus the C upstreams built against
`wasi-libc`). Every `nextssl_*` function is a wasm export, plus `memory`. It imports exactly ten WASI preview-1
functions: `random_get`, `environ_get`, `environ_sizes_get`, `fd_close`, `fd_fdstat_get`, `fd_prestat_get`,
`fd_prestat_dir_name`, `fd_seek`, `fd_write` and `proc_exit`.

The existing `crates/nextssl-wasm` (wasm-bindgen, `wasm32-unknown-unknown`) is **not** used and was left as it was: it
links Debian's wasi-libc archive by hand and so also carries WASI imports, and it exposes only hash, encode and
decode. Rather than patch that, the example compiles the full ABI for `wasm32-wasip1`, where the libc is meant to be
there, and supplies the ten imports from a 40-line JavaScript shim (random from `crypto.getRandomValues`, stderr
through `console.error`, everything else an error return). So the wasi-libc "problem" is solved by shimming the
imports, not by removing the libc. The module has no JavaScript glue besides that shim.

## Build the module

In the `nextssl-test` Docker image (it has clang, wasi-libc and the wasm targets):

```
export CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar
export CFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi"
CARGO_TARGET_WASM32_WASIP1_RUSTFLAGS="-C link-arg=-zstack-size=8388608" \
  cargo build -p nextssl-ffi --target wasm32-wasip1 --release --features everything
# result: target/wasm32-wasip1/release/nextssl_ffi.wasm (about 11 MB with every algorithm, 9 MB without copyleft/heavy)
```

Copy it to `target/docker-out/wasm/nextssl_ffi.wasm` (the example's default) or set `NEXTSSL_WASM`. The 8 MiB
stack covers ML-KEM, ML-DSA and the common schemes; the code-based schemes (Classic McEliece, CROSS) need more
(the repository's wasm test run uses 64 MiB). Build time was a few minutes with the cargo and target volumes cached.

## Run the example (Node)

```
node examples/js/nextssl_demo.mjs                  # list all algorithms
node examples/js/nextssl_demo.mjs --list kem
node examples/js/nextssl_demo.mjs sha256           # demo (safe API)
node examples/js/nextssl_demo.mjs --root md5       # other tiers need --root
node examples/js/nextssl_demo.mjs --params hash=sha512 hmac
node examples/js/nextssl_demo.mjs --info ml-kem-768
```

Exit status is the NextSSL error code. Tested with Node 22.23.1 on Windows 11 (the wasm file built in Docker).

## Using the binding in your code

```js
import { NextSSL } from "./nextssl_demo.mjs";      // importing does not run the CLI
const ns = await NextSSL.load(wasmBytes);           // safe API; NextSSL.load(bytes, true) for nextssl_root_*
const digest = ns.call("hash_with", "ttb", ["sha256", null, new TextEncoder().encode("abc")])[0];
const [pk, sk] = ns.call("kem_keygen", "tt", ["ml-kem-768", null], 2);
const [ct, ss] = ns.call("kem_encaps", "ttb", ["ml-kem-768", null, pk], 2);
const ss2 = ns.call("kem_decaps", "ttbb", ["ml-kem-768", null, sk, ct])[0];
const valid = ns.check("verify_detached", "ttbbbb", ["ed25519", null, pk2, msg, new Uint8Array(0), sig]);
```

`call(op, sig, args, outs = 1)`: `sig` has one letter per argument before the outputs: `t` string (null allowed),
`b` `Uint8Array`, `z` size_t, `u` uint32, `q` uint64 (passed as `BigInt` internally). Returns the output
`Uint8Array`s. Memory for arguments is allocated in the module with `nextssl_buf_alloc` and wiped and freed with
`nextssl_buf_free` in a `finally` block, on success and on error.

## API by kind

Same function names as [c-abi.md](c-abi.md) without the prefix. The argument signatures for the eleven kinds in the
example are the same as in the PHP doc table (`hash_with ttb`, `xof ttbz`, `checksum ttb`, `encode_with`/`decode_with ttb`,
`mac ttbbz` / `mac_verify ttbbb`, `kdf ttbbbz`, `aead_seal`/`aead_open ttbbbb`, `kem_keygen tt` / `kem_encaps ttb` /
`kem_decaps ttbb`, `kex_keygen tt` / `kex_agree ttbb`, `sign_keygen tt` / `sign_detached ttbbb` / `verify_detached ttbbbb`,
`rng_fill ttz`). Any other function of the ABI is reachable the same way, since `call` builds the call from the
signature letters and looks the export up by name.

## Tiers and root access

`NextSSL.load(bytes)` uses `nextssl_*`: `safe` and `standard` tiers only; anything else throws `NextSSLError` with
`code === 3`. `NextSSL.load(bytes, true)` (`--root`) uses `nextssl_root_*`, which reaches every tier and the
root-only kinds.

## Error handling

Non-zero status throws `NextSSLError` (`.code`, message from `nextssl_error_message`). `check()` maps code 14
(`AUTHENTICATION_FAILED`) to `false`. A wasm trap (for example a stack overflow in a very large scheme) surfaces as a
`WebAssembly.RuntimeError`; the instance should be discarded afterwards. `proc_exit` from inside the module throws.

## Buffer sizes

Outputs start at 256 bytes and grow to the size the library reports on `BAD_OUTPUT_LEN`; nothing is truncated.
wasm32 has a 32-bit `size_t` and a 4 GiB memory limit; a single input is capped at 256 MiB and a caller-chosen output length at 16 MiB.
Linear memory only grows: after a large operation the module keeps the pages.

## Do browsers work?

Short answer: **yes in the one browser I ran, with caveats.** `browser.html` loaded the module with `fetch` and ran
`sha256("abc")` (correct digest) and an ML-KEM-768 keygen/encaps/decaps round trip with equal shared secrets, in the
Chromium-based browser pane of the Claude desktop app, served from `python -m http.server`, on the main thread.
Not run: Firefox, Safari, Web Workers, a bundler, a Content-Security-Policy that blocks `wasm-unsafe-eval`. Things to
know: `WebAssembly.compile` of an 11 MB module takes noticeable time (use `compileStreaming` and a worker for real
use); `crypto.getRandomValues` needs a secure context (https or localhost); the shim sends anything the module writes
to stderr to `console.error`.

## Platform notes

The wasm module is platform independent; Windows, Linux and macOS differ only in how you run Node. The build needs
the Docker image (or a Linux host with clang, `libclang-rt-dev-wasm32` and wasi-libc), because it compiles the C
upstreams for wasm; building on Windows or macOS directly was not tried.
