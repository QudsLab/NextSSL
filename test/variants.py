"""NextSSL variant registry.

Every built binary is assigned a two-digit integer ID:
  tens digit  = platform group (1–7)
  units digit = variant within that platform

  Platform 1 – Windows       11–16
  Platform 2 – Linux glibc   21–28
  Platform 3 – Linux musl    31–33
  Platform 4 – macOS         41–43
  Platform 5 – WASM          51–52
  Platform 6 – Android       61–64
  Platform 7 – iOS           71–73

Usage:
    from test.variants import VARIANTS, ALL_IDS, parse_range
    ids = parse_range("11-28")          # Windows + Linux glibc
    ids = parse_range("61-64")          # Android only
    ids = parse_range("11,21,31")       # pick three specific IDs
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Variant:
    vid: int
    """Two-digit variant ID (e.g. 21)."""

    platform: str
    """Platform group: win | linux-glibc | linux-musl | macos | wasm | android | ios"""

    arch: str
    """CPU architecture or WASM flavour (e.g. x86_64, arm64, armeabi-v7a, wasm32)."""

    toolchain: str
    """Compiler / toolchain: msvc | mingw | gcc | clang | ndk | emscripten | wasi"""

    artifact: str
    """GitHub Actions artifact name produced by the build workflow."""

    lib_glob: str
    """Glob used to locate the binary inside an extracted artifact directory."""

    exec_mode: str
    """How to execute the binary on a CI runner – see EXEC_MODES below."""

    runner: str
    """Preferred GitHub Actions runner."""

    note: str = field(default="")
    """Optional human note (e.g. 'cross-arch: header check only')."""

    @property
    def platform_id(self) -> int:
        """Tens digit of vid (1–7)."""
        return self.vid // 10

    @property
    def tag(self) -> str:
        """Short human label: platform/arch-toolchain."""
        return f"{self.platform}/{self.arch}-{self.toolchain}"


# ---------------------------------------------------------------------------
# Execution modes
# ---------------------------------------------------------------------------
# native           – run directly on the CI/host machine
# pe_check         – MZ header verification only (ARM PE cannot run on x86_64)
# macho_check      – Mach-O magic verification only (device/no-codesign)
# qemu_arm64       – execute via qemu-aarch64 user-mode
# qemu_arm         – execute via qemu-arm     user-mode (armv7 / armeabi)
# qemu_x86         – execute via qemu-i386    user-mode
# qemu_riscv64     – execute via qemu-riscv64 user-mode
# qemu_s390x       – execute via qemu-s390x   user-mode
# qemu_ppc64le     – execute via qemu-ppc64le user-mode
# qemu_loongarch64 – execute via qemu-loongarch64 user-mode
# node_wasm        – execute via Node.js + Emscripten JS glue
# wasi_wasm        – execute via wasmtime CLI (WASI .wasm)
EXEC_MODES: frozenset[str] = frozenset({
    "native", "pe_check", "macho_check",
    "qemu_arm64", "qemu_arm", "qemu_x86",
    "qemu_riscv64", "qemu_s390x", "qemu_ppc64le", "qemu_loongarch64",
    "node_wasm", "wasi_wasm",
})

# ---------------------------------------------------------------------------
# Complete variant table – 29 entries
# ---------------------------------------------------------------------------
_TABLE: list[Variant] = [
    # ── Platform 1: Windows (windows-2022) ─────────────────────────────
    Variant(11, "win", "x86_64",   "msvc",  "nextssl__win__x86_64-msvc",   "*.dll",   "native",    "windows-2022"),
    Variant(12, "win", "x86",      "msvc",  "nextssl__win__x86-msvc",      "*.dll",   "native",    "windows-2022"),
    Variant(13, "win", "arm64",    "msvc",  "nextssl__win__arm64-msvc",    "*.dll",   "pe_check",  "windows-2022", "cross-arch: PE header check only"),
    Variant(14, "win", "x86_64",   "mingw", "nextssl__win__x86_64-mingw",  "*.dll",   "native",    "windows-2022"),
    Variant(15, "win", "x86",      "mingw", "nextssl__win__x86-mingw",     "*.dll",   "native",    "windows-2022"),
    Variant(16, "win", "armv7",    "msvc",  "nextssl__win__armv7-msvc",    "*.dll",   "pe_check",  "windows-2022", "cross-arch: PE header check only"),

    # ── Platform 2: Linux glibc (ubuntu-24.04) ─────────────────────────
    Variant(21, "linux-glibc", "x86_64",      "gcc", "nextssl__linux-glibc__x86_64",      "*.so", "native",           "ubuntu-24.04"),
    Variant(22, "linux-glibc", "x86",          "gcc", "nextssl__linux-glibc__x86",          "*.so", "qemu_x86",         "ubuntu-24.04"),
    Variant(23, "linux-glibc", "arm64",        "gcc", "nextssl__linux-glibc__arm64",        "*.so", "qemu_arm64",       "ubuntu-24.04"),
    Variant(24, "linux-glibc", "armv7",        "gcc", "nextssl__linux-glibc__armv7",        "*.so", "qemu_arm",         "ubuntu-24.04"),
    Variant(25, "linux-glibc", "riscv64",      "gcc", "nextssl__linux-glibc__riscv64",      "*.so", "qemu_riscv64",     "ubuntu-24.04"),
    Variant(26, "linux-glibc", "s390x",        "gcc", "nextssl__linux-glibc__s390x",        "*.so", "qemu_s390x",       "ubuntu-24.04"),
    Variant(27, "linux-glibc", "ppc64le",      "gcc", "nextssl__linux-glibc__ppc64le",      "*.so", "qemu_ppc64le",     "ubuntu-24.04"),
    Variant(28, "linux-glibc", "loongarch64",  "gcc", "nextssl__linux-glibc__loongarch64",  "*.so", "qemu_loongarch64", "ubuntu-24.04"),

    # ── Platform 3: Linux musl (ubuntu-24.04) ──────────────────────────
    Variant(31, "linux-musl", "x86_64", "gcc", "nextssl__linux-musl__x86_64", "*.so", "native",    "ubuntu-24.04"),
    Variant(32, "linux-musl", "arm64",  "gcc", "nextssl__linux-musl__arm64",  "*.so", "qemu_arm64","ubuntu-24.04"),
    Variant(33, "linux-musl", "armv7",  "gcc", "nextssl__linux-musl__armv7",  "*.so", "qemu_arm",  "ubuntu-24.04"),

    # ── Platform 4: macOS (macos-14, Apple M1) ─────────────────────────
    Variant(41, "macos", "x86_64",    "clang", "nextssl__macos__x86_64",    "*.dylib", "native", "macos-14"),
    Variant(42, "macos", "arm64",     "clang", "nextssl__macos__arm64",     "*.dylib", "native", "macos-14"),
    Variant(43, "macos", "universal", "clang", "nextssl__macos__universal", "*.dylib", "native", "macos-14"),

    # ── Platform 5: WASM (ubuntu-24.04) ────────────────────────────────
    Variant(51, "wasm", "wasm32", "emscripten", "nextssl__wasm__emscripten-wasm32", "*.js",   "node_wasm", "ubuntu-24.04"),
    Variant(52, "wasm", "wasm32", "wasi",       "nextssl__wasm__wasi-wasm32",       "*.wasm", "wasi_wasm", "ubuntu-24.04"),

    # ── Platform 6: Android (ubuntu-24.04) ─────────────────────────────
    Variant(61, "android", "arm64-v8a",   "ndk", "nextssl__android__arm64-v8a",   "*.so", "qemu_arm64", "ubuntu-24.04"),
    Variant(62, "android", "armeabi-v7a", "ndk", "nextssl__android__armeabi-v7a", "*.so", "qemu_arm",   "ubuntu-24.04"),
    Variant(63, "android", "x86_64",      "ndk", "nextssl__android__x86_64",      "*.so", "native",     "ubuntu-24.04"),
    Variant(64, "android", "x86",         "ndk", "nextssl__android__x86",         "*.so", "qemu_x86",   "ubuntu-24.04"),

    # ── Platform 7: iOS (macos-14) ─────────────────────────────────────
    Variant(71, "ios", "device-arm64", "clang", "nextssl__ios__device-arm64", "*.dylib", "macho_check", "macos-14", "no code-sign in CI: Mach-O check only"),
    Variant(72, "ios", "sim-arm64",    "clang", "nextssl__ios__sim-arm64",    "*.dylib", "native",      "macos-14"),
    Variant(73, "ios", "sim-x86_64",   "clang", "nextssl__ios__sim-x86_64",  "*.dylib", "macho_check", "macos-14", "M1 runner cannot exec x86_64 slice"),
]

# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------
VARIANTS: dict[int, Variant] = {v.vid: v for v in _TABLE}
"""Dict keyed by variant ID for O(1) lookup."""

ALL_IDS: list[int] = sorted(VARIANTS)
"""Sorted list of all 29 variant IDs."""

PLATFORM_NAMES: dict[int, str] = {
    1: "Windows",
    2: "Linux glibc",
    3: "Linux musl",
    4: "macOS",
    5: "WASM",
    6: "Android",
    7: "iOS",
}


def parse_range(spec: str) -> list[int]:
    """Return variant IDs that fall within *spec*.

    Accepted formats
    ----------------
    ``"11-28"``   – all registered IDs whose numeric value is in [11, 28]
    ``"61-64"``   – Android only
    ``"11,21,31"``– specific IDs, comma-separated
    ``"21"``      – single ID

    Formats can be combined: ``"11-16,61-64"`` gives Windows + Android.
    Order-preserving, duplicates removed.
    """
    ids: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            ids.extend(v for v in ALL_IDS if lo <= v <= hi)
        else:
            vid = int(part)
            if vid in VARIANTS:
                ids.append(vid)

    seen: set[int] = set()
    result: list[int] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            result.append(i)
    return result


def ids_for_platform(platform_digit: int) -> list[int]:
    """Return all IDs whose platform equals *platform_digit* (1–7)."""
    return [v for v in ALL_IDS if v // 10 == platform_digit]
