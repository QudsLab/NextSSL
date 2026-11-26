#!/usr/bin/env bash
# GitHub releases of one CI run on main (owner decision 2026-11-26). Version (<base>.<run number>) and stage
# come from release.toml (tools/release_info.py); every tag carries the commit. Releases are public (no drafts).
#
#   bash tools/ci_release.sh platform <name>   a platform's pre-release job, after its tests and release
#                                              build passed: its own pre-release v<version>+<commit>-<name>
#                                              with this platform's dist/ files.
#   bash tools/ci_release.sh final             the release job, after every platform passed: the release
#                                              v<version>+<commit> with every platform's files (dist/);
#                                              marked pre-release unless release.toml says stage = "release".
# Needs GH_TOKEN (contents: write) and a checkout of the commit. A re-run never replaces an existing release.
set -euo pipefail
cd "$(dirname "$0")/.."

# python3, or python on Windows runners (where python3 may be the Store stub); 3.11+ for tomllib.
py=python3
"$py" -c "import tomllib" 2> /dev/null || py=python
sha=$(git rev-parse HEAD)
ver=$("$py" tools/release_info.py version)
stage=$("$py" tools/release_info.py stage)
note=$("$py" tools/release_info.py note)
base=$("$py" tools/release_info.py tag "$sha")
run_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"

exists() { gh release view "$1" --json tagName > /dev/null 2>&1; }

publish() { # <tag> <title> <prerelease: yes|no> <what>
  local tag="$1" title="$2" pre="$3" what="$4"
  if exists "$tag"; then
    echo "$tag exists already; nothing changed." | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
    return 0
  fi
  (cd dist && sha256sum -- * > SHA256SUMS)
  cat > release-notes.md <<NOTES
NextSSL ${ver}, commit ${sha}: ${what}. ${note}
Version stage (release.toml): ${stage}. CI run: ${run_url}
Each archive holds the nextssl-ffi libraries (or the wasm module), the C header and the license of every
bundled upstream. Tested against published KAT vectors; not FIPS validated. Changes to upstream sources:
docs/UPSTREAM_CHANGES.md.
NOTES
  local flags=(--target "$sha" --title "$title" --notes-file release-notes.md)
  [ "$pre" = yes ] && flags+=(--prerelease)
  gh release create "$tag" dist/* "${flags[@]}"
  echo "$tag published (pre-release: $pre)." | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

case "${1:-}" in
  platform)
    name="${2:?platform name}"
    ls dist/*.tar.gz > /dev/null
    publish "${base}-${name}" "NextSSL ${ver} pre-release ${name} (${sha::7})" yes "${name} build"
    ;;
  final)
    missing=0
    for p in linux-x64 linux-arm64 windows-x64 windows-arm64 macos-arm64 wasm; do
      set -- dist/nextssl-"${ver}"+"${sha::7}"-"${p}".tar.gz
      if [ "$#" != 1 ] || [ ! -s "$1" ]; then echo "missing: $p" >&2; missing=1; continue; fi
      # List once, then search the list: `tar | grep -q` fails under pipefail when grep exits at the
      # first match and tar gets a write error (run 45775068475: "no LICENSE" for all 6 archives).
      if ! list=$(tar -tzf "$1"); then echo "unreadable: $1" >&2; missing=1; continue; fi
      grep -q '/LICENSE$' <<< "$list" || { echo "no LICENSE in $1" >&2; missing=1; }
    done
    [ "$missing" = 0 ] || exit 1
    pre=yes
    [ "$stage" = release ] && pre=no
    publish "$base" "NextSSL ${ver} (${sha::7})" "$pre" "every platform"
    ;;
  *)
    echo "usage: ci_release.sh platform <name> | final" >&2
    exit 2
    ;;
esac
