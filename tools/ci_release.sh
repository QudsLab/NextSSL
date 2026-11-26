#!/usr/bin/env bash
# GitHub releases of one version (owner decision 2026-11-27; see release.toml). Runs only in a CI run
# on main whose guard found no release v<version> yet.
#
#   bash tools/ci_release.sh platform <name>   a platform's pre-release job, after its tests and release
#                                              build passed: pre-release v<version>-<name> with this
#                                              platform's dist/ files.
#   bash tools/ci_release.sh final             the release job, after every platform passed: the release
#                                              v<version> with every platform's files (dist/); marked
#                                              pre-release unless release.toml says stage = "release".
# Needs GH_TOKEN (contents: write) and a checkout of the commit. A published v<version> is never
# replaced. A platform pre-release of the same version from an earlier commit (a run whose other
# platforms failed) is replaced, so the platform pre-releases always match the release's commit.
set -euo pipefail
cd "$(dirname "$0")/.."

# python3, or python on Windows runners (where python3 may be the Store stub); 3.11+ for tomllib.
py=python3
"$py" -c "import tomllib" 2> /dev/null || py=python
sha=$(git rev-parse HEAD)
ver=$("$py" tools/release_info.py version)
tag=$("$py" tools/release_info.py tag)
stage=$("$py" tools/release_info.py stage)
label=$("$py" tools/release_info.py label)
note=$("$py" tools/release_info.py note)
run_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"
title="NextSSL ${ver}${label:+ ${label}}"

summary() { echo "$1" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"; }
exists() { gh release view "$1" --json tagName > /dev/null 2>&1; }

publish() { # <tag> <title> <prerelease: yes|no> <what>
  local t="$1" ttl="$2" pre="$3" what="$4"
  (cd dist && sha256sum -- * > SHA256SUMS)
  cat > release-notes.md <<NOTES
NextSSL ${ver}${label:+ (${label})}: ${what}. ${note}

Commit: ${sha}. CI run: ${run_url}
Release stage (release.toml): ${stage}.

Each archive holds the nextssl-ffi libraries (or the wasm module), the C header (include/nextssl.h),
USAGE.md (the C ABI), BUILD_INFO.txt and the license of every bundled upstream (licenses/). Check the
download against SHA256SUMS. Tested against published KAT vectors; not FIPS validated. Changes to
upstream sources: docs/UPSTREAM_CHANGES.md.
NOTES
  local flags=(--target "$sha" --title "$ttl" --notes-file release-notes.md)
  [ "$pre" = yes ] && flags+=(--prerelease)
  gh release create "$t" dist/* "${flags[@]}"
  summary "$t published (pre-release: $pre)."
}

if exists "$tag"; then
  summary "$tag is published already; nothing changed. Raise the version in Cargo.toml for a new release."
  exit 0
fi

case "${1:-}" in
  platform)
    name="${2:?platform name}"
    ls dist/*.tar.gz > /dev/null
    ptag="${tag}-${name}"
    if exists "$ptag"; then
      old=$(gh release view "$ptag" --json targetCommitish --jq .targetCommitish)
      if [ "$old" = "$sha" ]; then
        summary "$ptag exists for this commit; nothing changed."
        exit 0
      fi
      # Unpublished version: the pre-release of an earlier commit is replaced by this one.
      gh release delete "$ptag" --cleanup-tag --yes
      summary "$ptag of commit $old replaced."
    fi
    publish "$ptag" "${title} ${name} (pre-release)" yes "${name} build"
    ;;
  final)
    missing=0
    for p in linux-x64 linux-arm64 windows-x64 windows-arm64 macos-arm64 wasm; do
      f="dist/nextssl-${ver}-${p}.tar.gz"
      if [ ! -s "$f" ]; then echo "missing: $f" >&2; missing=1; continue; fi
      # List once, then search the list: `tar | grep -q` fails under pipefail when grep exits at the
      # first match and tar gets a write error (run 45775068475: "no LICENSE" for all 6 archives).
      if ! list=$(tar -tzf "$f"); then echo "unreadable: $f" >&2; missing=1; continue; fi
      for need in /LICENSE /USAGE.md /BUILD_INFO.txt; do
        grep -q "${need}\$" <<< "$list" || { echo "no ${need#/} in $f" >&2; missing=1; }
      done
    done
    [ "$missing" = 0 ] || exit 1
    pre=yes
    [ "$stage" = release ] && pre=no
    publish "$tag" "$title" "$pre" "every platform"
    ;;
  *)
    echo "usage: ci_release.sh platform <name> | final" >&2
    exit 2
    ;;
esac
