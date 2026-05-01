# Test Proposal — Quick Overview

## What is being tested

29 pre-built shared-library binaries (`.dll` / `.so` / `.dylib` / `.wasm`)
covering 7 platform groups and every supported CPU architecture.

## Variant numbering

Each binary has a two-digit ID.
The **tens digit** is the platform group; the **units digit** is the variant
within that platform.

| ID range | Platform     | Count |
|----------|--------------|-------|
| 11–16    | Windows      | 6     |
| 21–28    | Linux glibc  | 8     |
| 31–33    | Linux musl   | 3     |
| 41–43    | macOS        | 3     |
| 51–52    | WASM         | 2     |
| 61–64    | Android      | 4     |
| 71–73    | iOS          | 3     |
| —        | **Total**    | **29**|

## Two test modes

| Mode      | Entry point              | What it does                                      | Speed     |
|-----------|--------------------------|---------------------------------------------------|-----------|
| **Mass**  | `test/mass/run_mass.py`  | Header magic check + 1 SHA-256 KAT per variant    | ~5 s      |
| **Full**  | `test/full/run_full.py`  | All algo groups, all KAT vectors, every variant   | ~5–20 min |

Add `--full` to the mass runner to escalate it to full KAT depth.

## Quick commands

```bash
# Mass test — all 29 variants
python test/mass/run_mass.py

# Mass test — Windows + Linux glibc only (IDs 11–28)
python test/mass/run_mass.py -R 11-28

# Mass test — Android, escalated to full KAT
python test/mass/run_mass.py -R 61-64 --full

# Full KAT — iOS simulator variants
python test/full/run_full.py -R 71-73

# Full KAT — single variant
python test/full/run_full.py --id 42
```

## Prerequisites

| Requirement          | When needed                       |
|----------------------|-----------------------------------|
| Python 3.11+         | always (no virtualenv required)   |
| `qemu-user-static`   | QEMU variants on Linux host       |
| Node.js 20           | variant 51 (Emscripten WASM)      |
| `wasmtime` CLI       | variant 52 (WASI WASM)            |
| Extracted artifacts  | `artifacts/<id>/` layout          |

## What to look for

- `PASS` — binary header correct AND KAT vectors all match.
- `HEADER-ONLY` — binary header verified; KAT skipped (cross-arch, no code-sign).
- `SKIP` — artifact directory not found locally.
- `FAIL` — header wrong **or** at least one KAT vector mismatched.

A run is considered successful when there are **zero FAIL results**.
