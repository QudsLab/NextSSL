#!/usr/bin/env bash
# Package one platform's release build into dist/nextssl-<version>-<platform>.tar.gz (CI release jobs).
# Contents: the nextssl-ffi libraries (or nextssl_wasm.wasm), the C header, USAGE.md (the C ABI,
# docs/bindings/c-abi.md), BUILD_INFO.txt (version, commit, CI run), the NextSSL LICENSE, and licenses/
# (every algorithm's upstream license files, origin note and the SPDX table in README.md).
# Usage: bash tools/release_package.sh <platform>   (wasm: expects wasm-out/nextssl_wasm.wasm)
set -euo pipefail
cd "$(dirname "$0")/.."

platform="$1"
# Cargo.toml's version (tools/release_info.py; python3, or python on Windows runners; 3.11+ for tomllib).
py=python3
"$py" -c "import tomllib" 2> /dev/null || py=python
ver=$("$py" tools/release_info.py version)
name="nextssl-${ver}-${platform}"
stage="dist-stage/${name}"
rm -rf dist-stage dist
mkdir -p "${stage}/lib" "${stage}/include" "${stage}/licenses" dist

if [ "$platform" = wasm ]; then
  cp wasm-out/nextssl_wasm.wasm "${stage}/lib/"
else
  found=0
  for f in target/release/libnextssl_ffi.a target/release/libnextssl_ffi.so target/release/libnextssl_ffi.dylib \
           target/release/nextssl_ffi.lib target/release/nextssl_ffi.dll target/release/nextssl_ffi.dll.lib \
           target/release/nextssl_ffi.pdb; do
    if [ -f "$f" ]; then cp "$f" "${stage}/lib/"; found=1; fi
  done
  if [ "$found" != 1 ]; then echo "release_package: no nextssl_ffi library in target/release" >&2; exit 1; fi
  cp crates/nextssl-ffi/include/*.h "${stage}/include/"
fi

cp LICENSE "${stage}/LICENSE"
cp docs/bindings/c-abi.md "${stage}/USAGE.md"
# Every algorithm's upstream license files and origin note, and the table of SPDX ids: licenses/
# (tools/licenses_gen.py, checked by guard). One copy instead of a loop of ~10 processes per algorithm,
# which took 858 s on the windows-arm64 runner (run 45679985523).
cp -R licenses/. "${stage}/licenses/"

cat > "${stage}/BUILD_INFO.txt" <<EOF
NextSSL ${ver}
commit $(git rev-parse HEAD)
platform ${platform}
built by ${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}
EOF

tar -C dist-stage -czf "dist/${name}.tar.gz" "${name}"
ls -l dist
