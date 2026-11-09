# NextSSL from Swift

Example: `examples/swift/main.swift` (one file, Foundation only). It loads the library with `dlopen`/`dlsym`, mirrors
the two C structs in Swift, and has a demo for eleven kinds: hash, xof, checksum, encoding, mac, kdf, aead, kem, kex,
sign and rng. No header, module map or Swift package is needed. Function reference, error codes and buffer rules:
[c-abi.md](c-abi.md). The Python example covers every kind.

## Build the library

```
cargo build -p nextssl-ffi --release                       # 367 algorithms
cargo build -p nextssl-ffi --release --features everything # all 386
```

The example looks for `target/release/libnextssl_ffi.so` (`libnextssl_ffi.dylib` on macOS), then `target/debug`,
relative to the current directory, or uses `NEXTSSL_LIB`.

## Build and run the example

```
cd examples/swift
swiftc -O -swift-version 5 main.swift -o nextssl_demo
./nextssl_demo                     # list all algorithms
./nextssl_demo --list kem
./nextssl_demo sha256              # demo (safe API)
./nextssl_demo --root md5          # other tiers need --root
./nextssl_demo --params hash=sha512 hmac
./nextssl_demo --info ml-kem-768
```

With Docker (this is how it was tested):

```
docker run --rm -v "$PWD":/src:ro -v "$PWD/target/docker-out/swift":/out -w /out swift:6.0 \
    swiftc -O -swift-version 5 /src/examples/swift/main.swift -o /out/nextssl_demo
docker run --rm -v "$PWD":/src:ro -v "$PWD/target/docker-out/swift":/out \
    -e NEXTSSL_LIB=/src/target/release/libnextssl_ffi.so swift:6.0 /out/nextssl_demo sha256
```

Exit status is the NextSSL error code. `-swift-version 5` avoids Swift 6 strict-concurrency errors for the file's
top-level code; the file does not use concurrency.

## Using the binding in your code

```swift
let ns = NextSSL(path: "libnextssl_ffi.dylib", root: false)      // true = nextssl_root_* (every tier)
let digest = try ns.data("hash_with", "sha256", nil, Array("abc".utf8))
let kp = try ns.keygen("kem_keygen", "ml-kem-768", nil)           // (pk, sk)
let enc = try ns.encaps("ml-kem-768", nil, kp.pk)                 // (ct, ss)
let ss2 = try ns.in2out("kem_decaps", "ml-kem-768", nil, kp.sk, enc.ct)
let ok = try ns.verify("ed25519", nil, pk, msg, sig)
```

Swift cannot call a `dlsym` pointer with a runtime-chosen signature, so the file defines one `@convention(c)` type per
call shape (`FData`, `FXof`, `FMac`, `FKdf`, `FAead`, `FKeygen`, `FEncaps`, `FIn2Out`, `FSign`, ...). Struct pointers are
declared `UnsafeRawPointer` there because `@convention(c)` cannot mention Swift structs; `NIn` and `NOut` have the same
layout as the C structs (a pointer and `Int`s). `NextSSL.run` allocates output buffers in a `Scratch` object, grows them on
`BAD_OUTPUT_LEN` and frees everything when the call finishes. To add a kind, define the shape's type and one helper.

## API by kind

| Kind | Helper | Returns |
|---|---|---|
| hash, checksum, encoding | `data("hash_with"/"checksum"/"encode_with"/"decode_with", alg, p, data)` | `[UInt8]` |
| xof | `xof(alg, p, data, n)` | `[UInt8]` |
| mac | `mac(alg, p, key, data)`, `macVerify(...)` | `[UInt8]`, `Bool` |
| kdf | `kdf(alg, p, ikm, salt, info, n)` | `[UInt8]` |
| aead | `aead("aead_seal"/"aead_open", alg, p, key, nonce, aad, data)` | `[UInt8]` |
| kem | `keygen("kem_keygen", ...)`, `encaps(...)`, `in2out("kem_decaps", ...)` | `(pk, sk)`, `(ct, ss)`, `[UInt8]` |
| kex | `keygen("kex_keygen", ...)`, `in2out("kex_agree", alg, p, sk, peer)` | `(pk, sk)`, `[UInt8]` |
| sign | `keygen("sign_keygen", ...)`, `sign(...)`, `verify(...)` | `(pk, sk)`, `[UInt8]`, `Bool` |
| rng | `rng(alg, p, n)`, `random(n)` | `[UInt8]` |

## Tiers and root access

`NextSSL(root: false)` calls `nextssl_*`: safe and standard tiers; anything else throws `NextSSLError` with `code == 3`.
`NextSSL(root: true)` (`--root`) calls `nextssl_root_*` and reaches every tier and the root-only kinds.

## Error handling

Non-zero status throws `NextSSLError(code:message:op:)`; the message comes from `nextssl_error_message`. The verify
helpers return `false` for `AUTHENTICATION_FAILED` (14) and throw for malformed input.

## Buffer sizes

Outputs start at 256 bytes and are retried at the exact size the library reports on `BAD_OUTPUT_LEN` (10); nothing is
truncated (key generation repeats with fresh randomness; only the last result is used). `[UInt8]` values holding secrets
are not wiped by the library; `Scratch` frees its C buffers but does not wipe them.

## Platform notes

* Tested: Swift 6.0.3 (`swift:6.0` image, Ubuntu, x86_64) against a release build with `--features everything`.
* **macOS**: `dlopen` of `libnextssl_ffi.dylib` works the same; the file uses only Foundation and `#if os(macOS)` for the
  library name. Match the architecture (arm64 or x86_64). Not tested here. An alternative on Apple platforms is a SwiftPM
  system-library target over `nextssl.h` with a module map; not tried.
* **Windows**: Swift on Windows has `LoadLibrary`, not `dlopen`; the file would need that substitution. Not tested here.
