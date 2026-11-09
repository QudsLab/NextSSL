#!/usr/bin/env bash
# NextSSL test runner (Docker image docker/Dockerfile.test, same image in CI).
#
# Always runs the base suite (gen --check, fmt, clippy, test) unless NEXTSSL_SKIP_BASE=1.
# Slow layers are opt-in through env flags:
#   NEXTSSL_SYMBOLS=1     cargo xtask check-symbols (nm over the ffi staticlib/cdylib + C archives)
#   NEXTSSL_MIRI=1        cargo +nightly miri test (core, registry, ffi; C-backed algos skipped)
#   NEXTSSL_FUZZ_SECS=N   run every fuzz target for N seconds (libFuzzer, ASan)
#   NEXTSSL_FUZZ_BUILD=1  only build the fuzz targets
#   NEXTSSL_ASAN=1        nightly -Zsanitizer=address + C compiled with ASan/UBSan, -Zbuild-std
#   NEXTSSL_WASM=1        wasm32-unknown-unknown build + wasm32-wasip1 tests under wasmtime
#   NEXTSSL_ALL=1         all of the above (fuzz seconds default 60)
set -euxo pipefail
cd "$(dirname "$0")/.."

if [ "${NEXTSSL_ALL:-0}" = "1" ]; then
  export NEXTSSL_SYMBOLS=1 NEXTSSL_MIRI=1 NEXTSSL_ASAN=1 NEXTSSL_WASM=1
  export NEXTSSL_FUZZ_SECS="${NEXTSSL_FUZZ_SECS:-60}"
fi

if [ "${NEXTSSL_SKIP_BASE:-0}" != "1" ]; then
  cargo xtask gen --check
  cargo fmt --all --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
fi

if [ "${NEXTSSL_SYMBOLS:-0}" = "1" ]; then
  cargo xtask check-symbols
fi

if [ "${NEXTSSL_MIRI:-0}" = "1" ]; then
  # KAT tests read algos/**/kat/*.json, so Miri needs host file access.
  # blake2b (C via FFI) is skipped under cfg(miri); the ffi crate is exercised with pure-Rust algos.
  MIRIFLAGS="-Zmiri-disable-isolation" CARGO_TARGET_DIR=/tmp/target-miri \
    cargo +nightly miri test -p nextssl-core -p nextssl-registry -p nextssl-ffi
fi

if [ "${NEXTSSL_ASAN:-0}" = "1" ]; then
  # Rust under AddressSanitizer; the C upstreams are built with ASan+UBSan by their build.rs.
  # rustc supplies the ASan runtime; UBSan in the C code is trap mode (no second runtime).
  NEXTSSL_C_SANITIZE=1 \
  CC=clang \
  RUSTFLAGS="-Zsanitizer=address" \
  ASAN_OPTIONS="detect_leaks=1:abort_on_error=0" \
\
  CARGO_TARGET_DIR=/tmp/target-asan \
    cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu --workspace
fi

FUZZ_TARGETS=$(cd fuzz/fuzz_targets && ls *.rs | sed 's/\.rs$//')
if [ "${NEXTSSL_FUZZ_BUILD:-0}" = "1" ] || [ -n "${NEXTSSL_FUZZ_SECS:-}" ]; then
  (cd fuzz && cargo +nightly fuzz build)
fi
if [ -n "${NEXTSSL_FUZZ_SECS:-}" ]; then
  mkdir -p /tmp/fuzzlogs
  for t in $FUZZ_TARGETS; do
    # A crash makes libFuzzer exit non-zero, which fails the script (pipefail).
    (cd fuzz && cargo +nightly fuzz run "$t" -- \
      -max_total_time="$NEXTSSL_FUZZ_SECS" -print_final_stats=1) 2>&1 | tee "/tmp/fuzzlogs/$t.log"
  done
  set +x
  for t in $FUZZ_TARGETS; do
    echo "FUZZ $t: $(grep -h 'stat::number_of_executed_units' "/tmp/fuzzlogs/$t.log" | tail -1)"
  done
  set -x
fi

if [ "${NEXTSSL_WASM:-0}" = "1" ]; then
  # The blake2b C core is compiled with clang for wasm. Only libc *headers* are needed
  # (Debian wasi-libc); memcpy/memset resolve at link time (compiler_builtins / Rust's wasi-libc).
  # The wasi headers refuse the bare unknown-unknown target, so the C objects are compiled with
  # --target=wasm32-wasip1; they call no WASI functions, so the module has no WASI imports.
  export CC_wasm32_unknown_unknown=clang AR_wasm32_unknown_unknown=llvm-ar
  export CFLAGS_wasm32_unknown_unknown="--target=wasm32-wasip1 -isystem /usr/include/wasm32-wasi"
  export CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar
  export CFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi"
  cargo build -p nextssl-wasm --target wasm32-unknown-unknown --release
  ls -l "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/nextssl_wasm.wasm"
  # KAT + unit tests inside wasmtime (/src preopened so the KAT json files are readable).
  CARGO_TARGET_WASM32_WASIP1_RUNNER="wasmtime run --dir=/src" \
    cargo test --target wasm32-wasip1 --workspace --exclude xtask --exclude nextssl-wasm
fi
