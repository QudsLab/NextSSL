#!/usr/bin/env python3
"""Mass smoke test runner — tests every variant at once.

For each variant in the selected set this runner:
  1. Locates the binary under  <lib-dir>/<variant-id>/  (or /<artifact-name>/)
  2. Checks the binary header (magic bytes: MZ / ELF / Mach-O / WASM)
  3. If natively executable on this host: runs a SHA-256 smoke KAT
     (one SHA-256 vector via ctypes — fast, < 1 ms per variant)
  4. Prints a single result line per variant
  5. Writes a markdown table to $GITHUB_STEP_SUMMARY when running in CI

Use  ``--full``  to escalate from smoke KAT to the full KAT engine
(delegates to  test/run_tests.py  for each variant).

Usage
-----
  # All 29 variants
  python test/mass/run_mass.py

  # Windows + Linux glibc (IDs 11-28)
  python test/mass/run_mass.py -R 11-28

  # Android only
  python test/mass/run_mass.py -R 61-64

  # Escalate to full KAT for iOS variants
  python test/mass/run_mass.py -R 71-73 --full

  # Single variant
  python test/mass/run_mass.py --id 21

  # Custom artifact root
  python test/mass/run_mass.py --lib-dir /path/to/extracted-artifacts

Artifact directory layout expected by --lib-dir
-------------------------------------------------
  <lib-dir>/
    11/   nextssl.dll                ← contents of nextssl__win__x86_64-msvc
    12/   nextssl.dll
    21/   libnextssl.so              ← contents of nextssl__linux-glibc__x86_64
    ...
    51/   nextssl.js  nextssl.wasm   ← Emscripten JS glue + .wasm
    52/   nextssl.wasm               ← WASI binary

  Alternatively the runner also checks <lib-dir>/<artifact-name>/ so you
  can drop CI artifacts without renaming.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Make the repo root importable regardless of cwd
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
sys.path.insert(0, str(_REPO))

from test.variants import ALL_IDS, VARIANTS, Variant, parse_range      # noqa: E402
from test.mass.header_check import check as header_check                # noqa: E402
from test.mass.header_check import HEADER_ONLY_MODES                   # noqa: E402
from test.mass.smoke_kat import run as smoke_kat                        # noqa: E402

_RUN_TESTS = _REPO / "test" / "run_tests.py"

# exec_modes that can run natively on the current host platform
_NATIVE_MODE = "native"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_binary(art_dir: Path, glob: str) -> "Path | None":
    matches = sorted(art_dir.glob(glob))
    return matches[0] if matches else None


def _art_dir(lib_dir: Path, v: Variant) -> "Path | None":
    """Return the artifact subdirectory for variant *v*, or None if missing."""
    by_id = lib_dir / str(v.vid)
    if by_id.is_dir():
        return by_id
    by_name = lib_dir / v.artifact
    if by_name.is_dir():
        return by_name
    return None


def _host_can_execute_native(v: Variant) -> bool:
    """True when *v* is native-mode AND its platform matches the current OS."""
    if v.exec_mode != _NATIVE_MODE:
        return False
    host = sys.platform
    if v.platform == "win" and host == "win32":
        return True
    if v.platform in ("linux-glibc", "linux-musl", "android") and host.startswith("linux"):
        return True
    if v.platform in ("macos", "ios") and host == "darwin":
        return True
    return False


def _run_full_kat(v: Variant, lib: Path, verbose: bool) -> str:
    """Delegate to run_tests.py for full KAT; returns status string."""
    cmd = [sys.executable, str(_RUN_TESTS)]
    if v.exec_mode == "node_wasm":
        cmd += ["--wasm", str(lib)]
    elif v.exec_mode == "wasi_wasm":
        cmd += ["--wasm-wasi", str(lib)]
    elif v.exec_mode in HEADER_ONLY_MODES:
        return "SKIP (header-only; full KAT not possible)"
    else:
        cmd += ["--lib", str(lib)]
    if verbose:
        cmd.append("--verbose")
    try:
        r = subprocess.run(cmd, capture_output=not verbose, text=True)
        return "PASS (full)" if r.returncode == 0 else f"FAIL (full exit={r.returncode})"
    except Exception as exc:
        return f"FAIL (full): {exc}"


def _test_one(v: Variant, lib_dir: Path, full: bool, verbose: bool) -> str:
    """Smoke-test a single variant; returns a status string."""
    adir = _art_dir(lib_dir, v)
    if adir is None:
        return "SKIP (artifact dir not found)"

    lib = _find_binary(adir, v.lib_glob)
    if lib is None:
        return f"SKIP (no {v.lib_glob} in {adir.name}/)"

    # 1 ── Header check
    ok, msg = header_check(lib, v.exec_mode, v.platform)
    if not ok:
        return f"FAIL header: {msg}"
    if verbose:
        print(f"      header : {msg}")

    # 2 ── Short-circuit: header-only modes
    if v.exec_mode in HEADER_ONLY_MODES:
        return f"HEADER-ONLY  ({v.note or 'cross-arch / no code-sign'})"

    # 3 ── Escalate to full KAT when requested
    if full:
        return _run_full_kat(v, lib, verbose)

    # 4 ── Smoke KAT (native host only)
    if _host_can_execute_native(v):
        ok2, msg2 = smoke_kat(lib, v.exec_mode)
        if verbose:
            print(f"      sha256 : {msg2}")
        return "PASS" if ok2 else f"FAIL KAT: {msg2}"

    # Cross-arch QEMU / WASM: header passed, execution needs special env
    return f"HEADER-OK  (exec needs {v.exec_mode}; run on CI or use --full)"


# ---------------------------------------------------------------------------
# Summary / reporting
# ---------------------------------------------------------------------------

def _marker(status: str) -> str:
    if status.startswith("PASS"):
        return "\u2713"   # ✓
    if status.startswith("FAIL"):
        return "\u2717"   # ✗
    return "~"


def _write_gha_summary(results: "list[tuple[int, Variant, str]]") -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write("## Mass smoke test — results\n\n")
        f.write("| ID | Platform | Arch | Toolchain | Result |\n")
        f.write("|----|----------|------|-----------|--------|\n")
        for vid, v, s in results:
            icon = "\u2705" if s.startswith("PASS") else ("\u26a0\ufe0f" if not s.startswith("FAIL") else "\u274c")
            f.write(f"| {vid} | {v.platform} | {v.arch} | {v.toolchain} | {icon} {s} |\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-R", "--range", metavar="SPEC",
        help="Variant ID range, e.g. '11-28', '61-64', '11,21,31'",
    )
    parser.add_argument(
        "--id", type=int, metavar="VID",
        help="Single variant ID (e.g. 21)",
    )
    parser.add_argument(
        "--lib-dir", default="artifacts", metavar="DIR",
        help="Root dir with per-variant subdirs (default: ./artifacts)",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Escalate each smoke test to a full KAT (delegates to run_tests.py)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
    )
    args = parser.parse_args()

    if args.id is not None:
        ids = [args.id]
    elif args.range:
        ids = parse_range(args.range)
        if not ids:
            print(f"ERROR: no variants match range {args.range!r}", file=sys.stderr)
            return 1
    else:
        ids = list(ALL_IDS)

    lib_dir = Path(args.lib_dir)
    if not lib_dir.is_absolute():
        lib_dir = Path.cwd() / lib_dir

    results: list[tuple[int, Variant, str]] = []
    for vid in ids:
        if vid not in VARIANTS:
            print(f"WARNING: variant {vid} not in registry, skipping", file=sys.stderr)
            continue
        v = VARIANTS[vid]
        if args.verbose:
            print(f"\n[{v.vid:02d}] {v.tag}")
        status = _test_one(v, lib_dir, args.full, args.verbose)
        results.append((vid, v, status))
        m = _marker(status)
        print(f"  {m}  {vid:02d}  {v.tag:<38}  {status}")

    n_pass   = sum(1 for _, _, s in results if s.startswith("PASS"))
    n_header = sum(1 for _, _, s in results if "HEADER" in s)
    n_skip   = sum(1 for _, _, s in results if s.startswith("SKIP"))
    n_fail   = sum(1 for _, _, s in results if s.startswith("FAIL"))
    n_total  = len(results)
    print(
        f"\n── {n_pass} PASS  {n_header} HEADER-ONLY  {n_skip} SKIP  "
        f"{n_fail} FAIL  / {n_total} variants ──"
    )

    _write_gha_summary(results)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
