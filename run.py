#!/usr/bin/env python3
"""run.py — NextSSL one-shot build + test runner.

Works on Windows, Linux, and macOS without any modification.

Usage
-----
    python run.py                  # auto-detect platform, build + test
    python run.py --skip-build     # run tests only (skip CMake)
    python run.py --skip-test      # build only (skip test.py)
    python run.py --clean          # wipe build dir before configuring
    python run.py --shared         # shared library (default)
    python run.py --static         # static library
    python run.py --debug          # Debug build (default: Release)
    python run.py --jobs 4         # parallel jobs (default: CPU count)
    python run.py --arch arm64     # override target architecture
    python run.py --platform linux # override target platform
    python run.py -v               # verbose cmake output

Cross-compilation note
----------------------
When --arch differs from the host architecture, the appropriate CMake
cross-compile flags are added automatically.  A matching cross-compiler
must be installed (e.g. aarch64-linux-gnu-gcc for Linux → arm64).
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ─── Project root (directory that contains this script) ───────────────────────
ROOT = Path(__file__).resolve().parent

# ─── Platform / arch detection ────────────────────────────────────────────────

def _detect_os() -> str:
    """Return one of: 'win', 'linux', 'macos'."""
    s = sys.platform
    if s.startswith("win"):
        return "win"
    if s == "darwin":
        return "macos"
    return "linux"


def _detect_arch() -> str:
    """Return one of: 'x86_64', 'arm64', 'x86', 'riscv64', ..."""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    if m in ("i686", "i386", "x86"):
        return "x86"
    return m  # pass through (riscv64, s390x, ppc64le, …)


def _find_cmake() -> str:
    cmake = shutil.which("cmake")
    if not cmake:
        print("ERROR: cmake not found on PATH.", file=sys.stderr)
        print("       Install CMake from https://cmake.org/download/", file=sys.stderr)
        sys.exit(1)
    return cmake


def _cpu_count() -> int:
    try:
        return os.cpu_count() or 4
    except Exception:
        return 4


# ─── Cross-compilation helpers ────────────────────────────────────────────────

# Map (host_os, target_arch) → extra CMake args
_CROSS_FLAGS: dict[tuple[str, str], list[str]] = {
    ("linux", "arm64"): [
        "-DCMAKE_SYSTEM_NAME=Linux",
        "-DCMAKE_SYSTEM_PROCESSOR=aarch64",
        "-DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc",
    ],
    ("linux", "armv7"): [
        "-DCMAKE_SYSTEM_NAME=Linux",
        "-DCMAKE_SYSTEM_PROCESSOR=armv7",
        "-DCMAKE_C_COMPILER=arm-linux-gnueabihf-gcc",
    ],
    ("linux", "riscv64"): [
        "-DCMAKE_SYSTEM_NAME=Linux",
        "-DCMAKE_SYSTEM_PROCESSOR=riscv64",
        "-DCMAKE_C_COMPILER=riscv64-linux-gnu-gcc",
    ],
    ("linux", "s390x"): [
        "-DCMAKE_SYSTEM_NAME=Linux",
        "-DCMAKE_SYSTEM_PROCESSOR=s390x",
        "-DCMAKE_C_COMPILER=s390x-linux-gnu-gcc",
    ],
    ("linux", "ppc64le"): [
        "-DCMAKE_SYSTEM_NAME=Linux",
        "-DCMAKE_SYSTEM_PROCESSOR=ppc64le",
        "-DCMAKE_C_COMPILER=powerpc64le-linux-gnu-gcc",
    ],
    ("linux", "x86"): [
        "-DCMAKE_SYSTEM_PROCESSOR=i686",
        "-DCMAKE_C_FLAGS=-m32",
    ],
}


def _cross_flags(host_os: str, host_arch: str, target_arch: str) -> list[str]:
    if host_arch == target_arch:
        return []
    return _CROSS_FLAGS.get((host_os, target_arch), [])


# ─── Generator selection ──────────────────────────────────────────────────────

def _generator_flags(os_name: str) -> list[str]:
    """Prefer Ninja everywhere; fall back to platform default."""
    if os_name == "win":
        # On Windows with MSVC we do NOT use -G so VS handles multi-arch via -A.
        # Ninja is still used for MinGW builds if cl.exe is absent.
        if shutil.which("cl"):
            return []  # let CMake pick Visual Studio generator
        if shutil.which("ninja"):
            return ["-G", "Ninja"]
        return []
    if shutil.which("ninja"):
        return ["-G", "Ninja"]
    return []


# ─── Build step ───────────────────────────────────────────────────────────────

def build(
    *,
    os_name: str,
    host_arch: str,
    target_arch: str,
    build_type: str,
    shared: bool,
    clean: bool,
    jobs: int,
    verbose: bool,
    extra_cmake_args: list[str],
) -> int:
    cmake = _find_cmake()
    build_dir = ROOT / f"_build_{os_name}_{target_arch}_{build_type.lower()}"

    if clean and build_dir.exists():
        print(f"[run.py] Cleaning {build_dir.name} ...")
        shutil.rmtree(build_dir)

    build_dir.mkdir(parents=True, exist_ok=True)

    # ── cmake configure ────────────────────────────────────────────────────────
    configure_cmd: list[str] = [cmake, str(ROOT)]
    configure_cmd += _generator_flags(os_name)
    configure_cmd += [f"-DCMAKE_BUILD_TYPE={build_type}"]
    configure_cmd += [f"-DNEXTSSL_SHARED={'ON' if shared else 'OFF'}"]

    # Windows MSVC: pass -A <arch> for multi-arch support
    if os_name == "win" and shutil.which("cl"):
        _msvc_arch = {
            "x86_64": "x64",
            "x86":    "Win32",
            "arm64":  "ARM64",
            "arm":    "ARM",
        }.get(target_arch, "x64")
        configure_cmd += ["-A", _msvc_arch]
    else:
        configure_cmd += _cross_flags(os_name, host_arch, target_arch)

    configure_cmd += extra_cmake_args

    print(f"[run.py] Configure: {' '.join(configure_cmd)}")
    rc = subprocess.run(configure_cmd, cwd=str(build_dir)).returncode
    if rc != 0:
        print(f"[run.py] CMake configure FAILED (exit {rc})", file=sys.stderr)
        return rc

    # ── cmake build ────────────────────────────────────────────────────────────
    build_cmd: list[str] = [cmake, "--build", ".", "--config", build_type,
                             "--parallel", str(jobs)]
    if verbose:
        build_cmd += ["--", "-v"] if shutil.which("ninja") else []

    print(f"[run.py] Build: {' '.join(build_cmd)}")
    rc = subprocess.run(build_cmd, cwd=str(build_dir)).returncode
    if rc != 0:
        print(f"[run.py] Build FAILED (exit {rc})", file=sys.stderr)
    return rc


# ─── Test step ────────────────────────────────────────────────────────────────

def run_tests() -> int:
    test_script = ROOT / "test.py"
    if not test_script.exists():
        print("[run.py] WARNING: test.py not found — skipping tests.", file=sys.stderr)
        return 0
    cmd = [sys.executable, str(test_script)]
    print(f"[run.py] Tests: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(ROOT)).returncode


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    host_os   = _detect_os()
    host_arch = _detect_arch()

    parser = argparse.ArgumentParser(
        description="NextSSL build + test runner (cross-platform)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--platform",
        default=host_os,
        choices=["win", "linux", "macos"],
        help=f"Target OS (default: {host_os})",
    )
    parser.add_argument(
        "--arch",
        default=host_arch,
        help=f"Target architecture (default: {host_arch})",
    )
    parser.add_argument(
        "--build-type",
        default="Release",
        choices=["Release", "Debug", "RelWithDebInfo", "MinSizeRel"],
        help="CMake build type (default: Release)",
    )
    _mode = parser.add_mutually_exclusive_group()
    _mode.add_argument("--shared", dest="shared", action="store_true",  default=True,
                       help="Build shared library — .dll/.so/.dylib (default)")
    _mode.add_argument("--static", dest="shared", action="store_false",
                       help="Build static library — .lib/.a")
    parser.add_argument("--debug", action="store_true",
                        help="Shorthand for --build-type Debug")
    parser.add_argument("--clean", action="store_true",
                        help="Remove build directory before configuring")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip CMake configure + build")
    parser.add_argument("--skip-test", action="store_true",
                        help="Skip test.py")
    parser.add_argument("--jobs", type=int, default=_cpu_count(),
                        help=f"Parallel jobs (default: {_cpu_count()})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Pass verbose flag to build tool")
    parser.add_argument(
        "cmake_args",
        nargs=argparse.REMAINDER,
        help="Extra arguments forwarded to cmake configure (after --)",
    )
    args = parser.parse_args()

    build_type = "Debug" if args.debug else args.build_type
    target_os   = args.platform
    target_arch = args.arch

    # Strip leading '--' separator if present
    extra = [a for a in args.cmake_args if a != "--"]

    print(f"[run.py] Platform : {target_os}")
    print(f"[run.py] Arch     : {target_arch}")
    print(f"[run.py] Type     : {build_type}")
    print(f"[run.py] Shared   : {args.shared}")
    print()

    # ── Build ──────────────────────────────────────────────────────────────────
    if not args.skip_build:
        rc = build(
            os_name=target_os,
            host_arch=host_arch,
            target_arch=target_arch,
            build_type=build_type,
            shared=args.shared,
            clean=args.clean,
            jobs=args.jobs,
            verbose=args.verbose,
            extra_cmake_args=extra,
        )
        if rc != 0:
            return rc
        print()

    # ── Tests ──────────────────────────────────────────────────────────────────
    if not args.skip_test:
        rc = run_tests()
        if rc != 0:
            print(f"\n[run.py] Tests FAILED (exit {rc})", file=sys.stderr)
            return rc
        print("\n[run.py] All tests passed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
