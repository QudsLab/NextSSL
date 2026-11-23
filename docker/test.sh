#!/usr/bin/env bash
# NextSSL test runner (Docker image docker/Dockerfile.test, same image in CI).
#
# Always runs the base suite (gen --check, fmt, clippy, test) unless NEXTSSL_SKIP_BASE=1.
# Slow layers are opt-in through env flags:
#   NEXTSSL_SYMBOLS=1     cargo xtask check-symbols (nm over the ffi staticlib/cdylib + C archives)
#   NEXTSSL_MIRI=1        cargo +nightly miri test (core, registry and ffi unit tests; see scope note below)
#   NEXTSSL_FUZZ_SECS=N   run every fuzz target for N seconds (libFuzzer, ASan)
#   NEXTSSL_FUZZ_BUILD=1  only build the fuzz targets
#   NEXTSSL_ASAN=1        nightly -Zsanitizer=address + C compiled with ASan/UBSan, -Zbuild-std
#   NEXTSSL_WASM=1        wasm32-unknown-unknown build + wasm32-wasip1 tests under wasmtime
#   NEXTSSL_WASM_BUILD=1  the same builds (incl. wasip1 test binaries), nothing run (CI build stage)
#   NEXTSSL_FFI_SWEEP=1   one round trip per registered algorithm through the C ABI (native, about 4 minutes)
#   NEXTSSL_ALL=1         all of the above (fuzz seconds default 60)
set -euxo pipefail
cd "$(dirname "$0")/.."
# Test reports (tools/testrun.py) go here; CI mounts a host directory and uploads it.
REPORT_DIR="${NEXTSSL_REPORT_DIR:-/tmp/test-report}"

if [ "${NEXTSSL_ALL:-0}" = "1" ]; then
  export NEXTSSL_SYMBOLS=1 NEXTSSL_MIRI=1 NEXTSSL_ASAN=1 NEXTSSL_WASM=1
  export NEXTSSL_FUZZ_SECS="${NEXTSSL_FUZZ_SECS:-60}"
fi

if [ "${NEXTSSL_SKIP_BASE:-0}" != "1" ]; then
  cargo xtask gen --check
  cargo fmt --all --check
  cargo clippy --workspace --all-targets -- -D warnings
  # Every test in its own process, in parallel, with a time limit; nothing stops the run (tools/testrun.py).
  python3 tools/testrun.py --out "$REPORT_DIR/base" -- --workspace
fi

if [ "${NEXTSSL_FFI_SWEEP:-0}" = "1" ]; then
  # Registry-driven: every algorithm through the generic nextssl_root_* functions (crates/nextssl-ffi/src/abi_sweep.rs).
  NEXTSSL_FFI_SWEEP=1 cargo test -p nextssl-ffi sweep -- --nocapture
fi

if [ "${NEXTSSL_SYMBOLS:-0}" = "1" ]; then
  cargo xtask check-symbols
fi

if [ "${NEXTSSL_MIRI:-0}" = "1" ]; then
  # KAT tests read algos/**/kat/*.json, so Miri needs host file access.
  # blake2b (C via FFI) is skipped under cfg(miri); the ffi crate is exercised with pure-Rust algos.
  MIRIFLAGS="-Zmiri-disable-isolation" CARGO_TARGET_DIR=/tmp/target-miri \
    cargo +nightly miri test -p nextssl-core -p nextssl-registry -p nextssl-ffi --lib
  # Scope: library unit tests only. Excluded: crates/nextssl-registry/tests/kat.rs, which runs every
  # algorithm of the catalog (388) and the published KATs; under the Miri interpreter that does not
  # finish in CI time (SLH-DSA, ML-DSA, scrypt, ...). The same file runs natively, under ASan/UBSan
  # and in wasmtime. Individual pure-Rust algorithm crates are not run under Miri.
fi

if [ "${NEXTSSL_ASAN:-0}" = "1" ]; then
  # Rust under AddressSanitizer; the C upstreams are built with ASan+UBSan by their build.rs.
  # rustc supplies the ASan runtime; UBSan in the C code is trap mode (no second runtime).
  # Each test runs in its own process (tools/testrun.py), so a sanitizer abort fails only that test.
  NEXTSSL_C_SANITIZE=1 \
  CC=clang \
  RUSTFLAGS="-Zsanitizer=address" \
  ASAN_OPTIONS="detect_leaks=1:abort_on_error=0" \
  CARGO_TARGET_DIR=/tmp/target-asan \
    python3 tools/testrun.py --out "$REPORT_DIR/asan" --cargo "cargo +nightly" --timeout 1200 \
    -- -Zbuild-std --target x86_64-unknown-linux-gnu --workspace
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

if [ "${NEXTSSL_WASM:-0}" = "1" ] || [ "${NEXTSSL_WASM_BUILD:-0}" = "1" ]; then
  # NEXTSSL_WASM_BUILD=1 (CI build stage): build everything for both wasm targets, run nothing.
  # NEXTSSL_WASM=1 (CI test stage): the same, then the tests in wasmtime.
  # The C upstreams are compiled with clang for wasm, against the Debian wasi-libc headers.
  # The wasi headers refuse the bare unknown-unknown target, so the C objects are compiled with
  # --target=wasm32-wasip1.
  export CC_wasm32_unknown_unknown=clang AR_wasm32_unknown_unknown=llvm-ar
  export CFLAGS_wasm32_unknown_unknown="--target=wasm32-wasip1 -isystem /usr/include/wasm32-wasi"
  export CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar
  export CFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi"
  # C++ upstreams (Crypto++, PHC entries) use the Debian wasi libc++ (libc++-dev-wasm32); the C++
  # headers must come before the C ones. Each C++ build.rs links static c++ and c++abi on wasm32.
  export CXX_wasm32_unknown_unknown=clang++ CXX_wasm32_wasip1=clang++
  export CXXFLAGS_wasm32_unknown_unknown="--target=wasm32-wasip1 -isystem /usr/include/wasm32-wasi/c++/v1 -isystem /usr/include/wasm32-wasi"
  export CXXFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi/c++/v1 -isystem /usr/include/wasm32-wasi"
  # Many C upstreams call malloc/calloc/free/assert/errno, and wasm32-unknown-unknown has no libc, so the
  # Debian wasi-libc archive is linked in. The module then carries WASI imports: this step is a link
  # check of the whole catalog, not a ready-to-ship browser module. getrandom 0.4 needs its wasm_js
  # backend cfg (see crates/nextssl-wasm/Cargo.toml); this env var replaces .cargo/config.toml rustflags.
  # Both wasm builds always run (--keep-going, failures collected) so one pass reports every crate.
  WASM_FAIL=0
  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C link-arg=-L/usr/lib/wasm32-wasi -C link-arg=-lc' \
    cargo build -p nextssl-wasm --target wasm32-unknown-unknown --release --keep-going || WASM_FAIL=1
  ls -l "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/nextssl_wasm.wasm" || WASM_FAIL=1
  # KAT + unit tests inside wasmtime (/src preopened so the KAT json files are readable).
  # The default 1 MiB wasm stack overflows in the larger code-based schemes (CROSS, McEliece).
  # NEXTSSL_WASM=1: every test in its own wasmtime process, in parallel, killed after
  # NEXTSSL_WASM_TEST_SECS (tools/testrun.py). NEXTSSL_WASM_BUILD=1: the same test binaries, not run.
  # No comment lines inside the continued commands below: a comment ends the command there (run 45182945205).
  export CARGO_TARGET_WASM32_WASIP1_RUSTFLAGS="-C link-arg=-zstack-size=67108864 -C link-arg=-L/usr/lib/wasm32-wasi"
  if [ "${NEXTSSL_WASM:-0}" = "1" ]; then
    python3 tools/testrun.py --out "$REPORT_DIR/wasm" --runner "wasmtime run --dir=/src" \
      --timeout "${NEXTSSL_WASM_TEST_SECS:-1200}" \
      -- --target wasm32-wasip1 --workspace --exclude xtask --exclude nextssl-wasm \
      || WASM_FAIL=1
  else
    cargo build --tests --target wasm32-wasip1 --workspace --exclude xtask --exclude nextssl-wasm --keep-going \
      || WASM_FAIL=1
  fi
  if [ "$WASM_FAIL" != "0" ]; then echo "wasm: FAILED"; exit 1; fi
fi
