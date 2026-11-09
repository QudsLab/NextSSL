# NextSSL from PHP (FFI extension)

Example: `examples/php/nextssl_demo.php` (one file). It contains a small `NextSSL` class over PHP's built-in FFI
extension and a demo for eleven kinds: hash, xof, checksum, encoding, mac, kdf, aead, kem, kex, sign and rng. The
other kinds work the same way; add their prototypes from `nextssl.h` to the `HEADER` constant (the example declares
only the functions it uses). The Python example covers every kind. Function reference, error codes and buffer rules:
[c-abi.md](c-abi.md).

## Build the library

```
cargo build -p nextssl-ffi --release                       # 367 algorithms
cargo build -p nextssl-ffi --release --features everything # all 386
```

The example looks for `target/release/libnextssl_ffi.so` (`.dylib` on macOS, `nextssl_ffi.dll` on Windows), then
`target/debug`, or uses `NEXTSSL_LIB`.

PHP needs the FFI extension (`extension=ffi`, plus `ffi.enable=1` or `-d ffi.enable=1`). The official
`php:8.3-cli` Docker image does not include it; this is the image used for the tests:

```
FROM php:8.3-cli
RUN apt-get update && apt-get install -y --no-install-recommends libffi-dev \
    && rm -rf /var/lib/apt/lists/* && docker-php-ext-install ffi
```

## Run the example

```
php -d ffi.enable=1 examples/php/nextssl_demo.php                 # list all algorithms
php -d ffi.enable=1 examples/php/nextssl_demo.php --list kem      # one kind
php -d ffi.enable=1 examples/php/nextssl_demo.php sha256          # demo (safe API)
php -d ffi.enable=1 examples/php/nextssl_demo.php --root md5      # other tiers need --root
php -d ffi.enable=1 examples/php/nextssl_demo.php --params hash=sha512 hmac
php -d ffi.enable=1 examples/php/nextssl_demo.php --info ml-kem-768
```

The exit status is the NextSSL error code (0 on success). Kinds without a demo in this file print their C function names.

## Using the binding in your code

```php
$ns = new NextSSL('/path/to/libnextssl_ffi.so');               // safe API
$root = new NextSSL('/path/to/libnextssl_ffi.so', root: true); // nextssl_root_* (every tier)

$digest = $ns->call('hash_with', 'ttb', ['sha256', null, 'abc'])[0];
$key = $ns->random(32);
$ct = $ns->call('aead_seal', 'ttbbbb', ['aes-256-gcm', null, $key, $nonce, 'hdr', 'secret'])[0];
[$pk, $sk] = $ns->call('kem_keygen', 'tt', ['ml-kem-768', null], 2);
$valid = $ns->check('verify_detached', 'ttbbbb', ['ed25519', null, $pk, 'msg', '', $sig]);
```

`call($op, $sig, $args, $outs = 1)` takes a signature string with one letter per argument before the outputs:
`t` = C string (null allowed), `b` = bytes (a PHP string, passed as a `nextssl_in`), `z` = `size_t`. It returns a list
of output strings, growing the buffers automatically.

## API by kind

| Kind | Call (`$sig`, args) | Returns |
|---|---|---|
| hash | `hash_with`, `ttb`, `[alg, p, data]` | `[digest]` |
| xof | `xof`, `ttbz`, `[alg, p, data, n]` | `[bytes]` |
| checksum | `checksum`, `ttb` | `[value]` |
| encoding | `encode_with` / `decode_with`, `ttb` | `[text]` / `[bytes]` |
| mac | `mac`, `ttbbz`, `[alg, p, key, data, 0]`; `check('mac_verify', 'ttbbb', ...)` | `[tag]`; bool |
| kdf | `kdf`, `ttbbbz`, `[alg, p, ikm, salt, info, n]` | `[bytes]` |
| aead | `aead_seal` / `aead_open`, `ttbbbb`, `[alg, p, key, nonce, aad, data]` | `[ct||tag]` / `[plaintext]` |
| kem | `kem_keygen` (`tt`, 2 outputs), `kem_encaps` (`ttb`, 2), `kem_decaps` (`ttbb`) | `[pk, sk]`, `[ct, ss]`, `[ss]` |
| kex | `kex_keygen` (2), `kex_agree` (`ttbb`: sk, peer pk) | `[pk, sk]`, `[ss]` |
| sign | `sign_keygen` (2), `sign_detached` (`ttbbb`: sk, msg, ctx), `check('verify_detached', 'ttbbbb', ...)` | `[pk, sk]`, `[sig]`, bool |
| rng | `rng_fill`, `ttz`, `[alg, p, n]` | `[bytes]` |

Other kinds: declare the prototype, then call it the same way. Handle-based kinds (drbg, pake, threshold) need a
`uint64_t` handle: use `$ffi->new('uint64_t')` and pass `FFI::addr($h)`.

## Tiers and root access

`new NextSSL($lib)` calls `nextssl_*`: only `safe` and `standard` algorithms. Anything else throws `NextSSLError`
with `codeNum === 3`. `new NextSSL($lib, root: true)` (`--root`) calls `nextssl_root_*` and reaches every tier. Root-only
kinds exist only with the root entry points.

## Error handling

Non-zero status throws `NextSSLError` (`codeNum` is the code from [c-abi.md](c-abi.md), the message comes from
`nextssl_error_message`). `check()` converts `AUTHENTICATION_FAILED` (14) to `false` and still throws on malformed input.
Nothing falls back to another algorithm.

## Buffer sizes

Outputs start at 256 bytes; on `BAD_OUTPUT_LEN` (10) the call is repeated with the exact size the library reports,
so nothing is truncated. For key generation and encapsulation the repeat draws new randomness; only the final result
is used. To avoid repeats, size buffers from `info['sizes']`. PHP strings holding keys are not wiped by the library;
PHP offers `sodium_memzero` for strings you control.

## Platform notes

* PHP's `FFI::new()` and `FFI::cast()` are instance methods since PHP 8.3 (the static calls are deprecated); the example uses the instance forms.
* A `const char *` return value (`nextssl_error_message`, `nextssl_version`) arrives as a PHP string.
* **Linux**: tested with PHP 8.3.36 (CLI, NTS) in Docker on x86_64 against a release build of the library.
* **Windows**: enable `extension=ffi` in `php.ini`; use a 64-bit PHP and `nextssl_ffi.dll`. Not tested here.
* **macOS**: `libnextssl_ffi.dylib`; PHP and the library must have the same architecture. Not tested here.
