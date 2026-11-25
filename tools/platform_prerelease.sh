#!/usr/bin/env bash
# Publish one platform's pre-release from dist/ (CI, after that platform's release build passed):
# tag v<version>-pre.<commit>.<platform>, marked pre-release. The final release v<version> is made by
# ci.yml only after every platform passed. Draft (owner decision 2026-11-25): only the owner sees it
# until the license policy for the NOASSERTION algorithms is decided (CLAUDE.md rule 3).
# Usage: GH_TOKEN=... bash tools/platform_prerelease.sh <platform>
set -euo pipefail
cd "$(dirname "$0")/.."

platform="$1"
ver=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$ver" ] || { echo "platform_prerelease: no version in Cargo.toml" >&2; exit 1; }
sha=$(git rev-parse HEAD)
tag="v${ver}-pre.${sha::7}.${platform}"
ls dist/*.tar.gz > /dev/null
(cd dist && sha256sum -- * > SHA256SUMS)
# A re-run of the same commit and platform replaces nothing: the existing draft is kept as it is.
if gh release list --limit 1000 --json tagName --jq '.[].tagName' | grep -qx "$tag"; then
  echo "$tag exists already; nothing to do."
  exit 0
fi
cat > dist-notes.md <<NOTES
Pre-release of NextSSL ${ver} for ${platform}, commit ${sha}.
Built and tested on ${platform} by CI run ${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}.
The archive holds the nextssl-ffi libraries (or the wasm module), the C header and the license of every
bundled upstream. Tested against published KAT vectors; not FIPS validated. Changes to upstream sources:
docs/UPSTREAM_CHANGES.md. The release v${ver} follows when every platform has passed.
NOTES
gh release create "$tag" dist/* --draft --prerelease --target "$sha" --title "NextSSL ${ver} pre-release (${platform}, ${sha::7})" --notes-file dist-notes.md
