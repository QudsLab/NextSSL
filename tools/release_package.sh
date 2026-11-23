#!/usr/bin/env bash
# Package one platform's release build into dist/nextssl-<version>+<commit>-<platform>.tar.gz (CI release
# jobs). Contents: the nextssl-ffi libraries (or nextssl_wasm.wasm), the C header, the NextSSL LICENSE,
# and for every algorithm its upstream LICENSE/ORIGIN.md plus a table of the SPDX ids from algo.toml.
# Usage: bash tools/release_package.sh <platform>   (wasm: expects wasm-out/nextssl_wasm.wasm)
set -euo pipefail
cd "$(dirname "$0")/.."

platform="$1"
ver=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
sha=$(git rev-parse --short=7 HEAD)
name="nextssl-${ver}+${sha}-${platform}"
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
# Every algorithm's upstream license text and origin note, and one table of the declared SPDX ids.
{
  printf 'algorithm\tlicense (algo.toml)\n'
  for t in algos/*/*/*/algo.toml; do
    d=$(dirname "$t")
    id=$(basename "$d")
    lic=$(grep -o 'license = "[^"]*"' "$t" | head -1 | sed 's/license = "\(.*\)"/\1/')
    printf '%s\t%s\n' "$id" "${lic:-UNKNOWN}"
    if [ -d "$d/upstream" ]; then
      mkdir -p "${stage}/licenses/${id}"
      for f in "$d"/upstream/LICENSE* "$d"/upstream/COPYING* "$d"/upstream/ORIGIN.md; do
        [ -f "$f" ] && cp "$f" "${stage}/licenses/${id}/"
      done
    fi
  done
} > "${stage}/licenses/ALGORITHM_LICENSES.tsv"

cat > "${stage}/BUILD_INFO.txt" <<EOF
NextSSL ${ver}
commit $(git rev-parse HEAD)
platform ${platform}
built by ${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}
EOF

tar -C dist-stage -czf "dist/${name}.tar.gz" "${name}"
ls -l dist
