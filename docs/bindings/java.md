# NextSSL from Java (Panama foreign function API)

Example: `examples/java/NextSSLDemo.java` (one file, JDK 22 or newer, no dependencies). It contains a small
`NextSSL` class over `java.lang.foreign`, a 70-line JSON reader (the JDK has none) and a demo for eleven kinds: hash, xof,
checksum, encoding, mac, kdf, aead, kem, kex, sign and rng. Other kinds are reachable with the same `call`.
Function reference, error codes and buffer rules: [c-abi.md](c-abi.md). The Python example covers every kind.

Panama is final in Java 22. On older JDKs use JNA or JNI instead; this binding does not support them.

## Build the library

```
cargo build -p nextssl-ffi --release                       # 367 algorithms
cargo build -p nextssl-ffi --release --features everything # all 386
```

The example looks for `target/release/libnextssl_ffi.so` (`.dylib` / `nextssl_ffi.dll`), then `target/debug`,
relative to the current directory (`examples/java`), or uses `NEXTSSL_LIB`.

## Run the example

Run it straight from source; `--enable-native-access=ALL-UNNAMED` silences the JDK's native-access warning:

```
cd examples/java
java --enable-native-access=ALL-UNNAMED NextSSLDemo.java                 # list all algorithms
java --enable-native-access=ALL-UNNAMED NextSSLDemo.java --list kem
java --enable-native-access=ALL-UNNAMED NextSSLDemo.java sha256          # demo (safe API)
java --enable-native-access=ALL-UNNAMED NextSSLDemo.java --root md5      # other tiers need --root
java --enable-native-access=ALL-UNNAMED NextSSLDemo.java --params hash=sha512 hmac
java --enable-native-access=ALL-UNNAMED NextSSLDemo.java --info ml-kem-768
```

With Docker (this is how it was tested):

```
docker run --rm -v "$PWD":/src:ro -w /src/examples/java -e NEXTSSL_LIB=/src/target/release/libnextssl_ffi.so \
    eclipse-temurin:25-jdk java --enable-native-access=ALL-UNNAMED NextSSLDemo.java sha256
```

Exit status is the NextSSL error code.

## Using the binding in your code

```java
NextSSL ns = new NextSSL(Path.of("libnextssl_ffi.so"), false);   // true = nextssl_root_* (every tier)
byte[] digest = ns.call("hash_with", "ttb", new Object[] {"sha256", null, "abc".getBytes()}, 1)[0];
byte[][] kp  = ns.call("kem_keygen", "tt", new Object[] {"ml-kem-768", null}, 2);          // {pk, sk}
byte[][] enc = ns.call("kem_encaps", "ttb", new Object[] {"ml-kem-768", null, kp[0]}, 2);  // {ct, ss}
byte[] ss2   = ns.call("kem_decaps", "ttbb", new Object[] {"ml-kem-768", null, kp[1], enc[0]}, 1)[0];
boolean ok   = ns.check("verify_detached", "ttbbbb", new Object[] {"ed25519", null, pk, msg, new byte[0], sig});
```

`call(op, sig, args, outs, okCodes...)`: one letter per argument before the outputs: `t` String (null allowed), `b`
`byte[]`, `z` size_t (as `long`; `size_t` is taken as 64-bit), `u` uint32, `q` uint64. It builds the `FunctionDescriptor`,
caches the `MethodHandle`, allocates a confined `Arena` per call and returns the output arrays. The `nextssl_in` and
`nextssl_out` structs are laid out by hand (16 and 24 bytes: a pointer, then `long`s).

## API by kind

Names are the C names without the prefix; argument letters are the same as in the [PHP](php.md) table
(`hash_with ttb`, `xof ttbz`, `checksum ttb`, `encode_with`/`decode_with ttb`, `mac ttbbz`, `mac_verify ttbbb`,
`kdf ttbbbz`, `aead_seal`/`aead_open ttbbbb`, `kem_keygen tt`, `kem_encaps ttb`, `kem_decaps ttbb`, `kex_keygen tt`,
`kex_agree ttbb`, `sign_keygen tt`, `sign_detached ttbbb`, `verify_detached ttbbbb`, `rng_fill ttz`). Handle-based kinds
(drbg, pake, threshold) take a `u64` handle (`q`) and need an output `long` for creation: add a small wrapper like
`json()` does for its out struct.

## Tiers and root access

`new NextSSL(lib, false)` calls `nextssl_*` (safe and standard tiers). Others throw `NextSSLError` with `code == 3`.
`new NextSSL(lib, true)` (`--root`) calls `nextssl_root_*` and reaches every tier and the root-only kinds. A missing
symbol (a root-only operation called without root) is reported as code 3 with an explanatory message.

## Error handling

`NextSSLError` (an unchecked exception) carries `code` and the library's message. `check()` returns `false` for
`AUTHENTICATION_FAILED` (14) and throws for malformed input. Other failures inside the Panama call are wrapped in
`RuntimeException`.

## Buffer sizes

Outputs start at 256 bytes and are retried with the exact size the library reports on `BAD_OUTPUT_LEN` (10). Nothing
is truncated; key generation retried this way draws fresh randomness and only the last result is returned. Java `byte[]`
holding keys are not wiped by the library; overwrite them (`Arrays.fill`) when you are done. Memory allocated in the
confined `Arena` is freed (not wiped) when the call returns.

## Platform notes

* Tested: Temurin OpenJDK 25.0.5 (`eclipse-temurin:25-jdk`) on Linux x86_64 in Docker against a release build with
  `--features everything`.
* **Windows**: pass the DLL path; the JVM must be 64-bit. Not tested here.
* **macOS**: `libnextssl_ffi.dylib`; match the architecture. Not tested here.
* `size_t` is mapped to `JAVA_LONG`, correct on 64-bit platforms only.
