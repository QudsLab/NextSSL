# Test CI Flow

## Status

This file describes the workflow that is now implemented in `.github/workflows/test.yml` and `.github/workflows/test-variant.yml`.

The test CI has seven visible platform groups plus the final report job:

- `win`
- `linux-glibc`
- `linux-musl`
- `macos`
- `wasm`
- `android`
- `ios`
- `report`

Each variant is its own GitHub Actions job that calls `test-variant.yml` (reusable workflow), so the Actions UI shows per-variant progress directly.

## Current Behavior

- The workflow starts one queue per platform group in parallel.
- Inside a platform group, variants are chained one after another as visible jobs.
- The first failed variant closes that platform queue.
- Remaining jobs in that platform queue still run, but they record `status: skipped` logs instead of attempting a test.
- There is no flag gate. Every trigger (push, pull request, manual, or `workflow_run` after Build) runs all queues.
- When triggered via `workflow_run`, each job receives the exact `run_id` of the originating build run so the artifact download is pinned to that specific run.
- Each variant job downloads the binary artifact produced by `build.yml`, runs the appropriate test, and uploads `logs/test/<platform>/<variant>/` as its log artifact.
- Logs are uploaded with `if: always()` — a failed test or missing artifact never prevents log collection.
- Each variant job writes a `result.txt` in the same format as `ci_runner.py` so `ci_merge_logs.py` can produce per-platform `SUMMARY.txt` files.
- The `report` job always runs after all 29 variants and writes a Markdown summary table to `GITHUB_STEP_SUMMARY`.

## Platform Queues

- `win`: `x86_64-msvc -> x86-msvc -> arm64-msvc -> x86_64-mingw -> x86-mingw -> armv7-msvc`
- `linux-glibc`: `x86_64 -> x86 -> arm64 -> armv7 -> riscv64 -> s390x -> ppc64le -> loongarch64`
- `linux-musl`: `x86_64 -> arm64 -> armv7`
- `macos`: `x86_64 -> arm64 -> universal`
- `wasm`: `emscripten-wasm32 -> wasi-wasm32`
- `android`: `arm64-v8a -> armeabi-v7a -> x86_64 -> x86`
- `ios`: `device-arm64 -> sim-arm64 -> sim-x86_64`

## Platform Groups

- `win`: `x86_64-msvc (kat)` | `x86-msvc (kat)` | `arm64-msvc (pe-header)` | `x86_64-mingw (kat)` | `x86-mingw (kat)` | `armv7-msvc (pe-header)`
- `linux-glibc`: `x86_64 (native)` | `x86 (qemu-i386)` | `arm64 (qemu-aarch64)` | `armv7 (qemu-arm)` | `riscv64 (qemu-riscv64)` | `s390x (qemu-s390x)` | `ppc64le (qemu-ppc64le)` | `loongarch64 (qemu-loongarch64)`
- `linux-musl`: `x86_64 (native)` | `arm64 (qemu-aarch64)` | `armv7 (qemu-arm)`
- `macos`: `x86_64 (native)` | `arm64 (native)` | `universal (native)`
- `wasm`: `emscripten-wasm32 (node)` | `wasi-wasm32 (wasmtime)`
- `android`: `arm64-v8a (qemu-aarch64)` | `armeabi-v7a (qemu-arm)` | `x86_64 (native)` | `x86 (qemu-i386)`
- `ios`: `device-arm64 (macho-header)` | `sim-arm64 (native M1)` | `sim-x86_64 (macho-header)`

## Test Modes

- `kat` — run `test/run_tests.py --lib` (native or via `QEMU_LD_PREFIX` for cross-arch glibc)
- `wasm-node` — run `test/run_tests.py --wasm` via Node.js (emscripten)
- `wasm-wasi` — run `test/run_tests.py --wasm-wasi` via wasmtime
- `pe-header` — verify MZ magic bytes only; execution skipped (Windows ARM cross-arch)
- `macho-header` — verify Mach-O magic bytes only; execution skipped (iOS device / sim-x86_64)

## Layout Contract

- Test logs: `logs/test/<platform>/<variant>/`
- Build logs: `logs/build/<platform>/<variant>/`

Each variant log directory contains `kat.log` or `header.log` plus `result.txt`.

## Mermaid

```mermaid
flowchart TD
A[Trigger push PR or manual run\nor workflow_run after Build] --> W1
A --> LG1
A --> LM1
A --> M1
A --> WS1
A --> AD1
A --> I1

subgraph WIN[win]
W1[x86_64-msvc\nkat] --> W2[x86-msvc\nkat] --> W3[arm64-msvc\npe-header] --> W4[x86_64-mingw\nkat] --> W5[x86-mingw\nkat] --> W6[armv7-msvc\npe-header]
W1 -. failure closes queue .-> WX[record remaining win variants as skipped]
W2 -. failure closes queue .-> WX
W3 -. failure closes queue .-> WX
W4 -. failure closes queue .-> WX
W5 -. failure closes queue .-> WX
end

subgraph LINUX_GLIBC[linux-glibc]
LG1[x86_64\nnative] --> LG2[x86\nqemu-i386] --> LG3[arm64\nqemu-aarch64] --> LG4[armv7\nqemu-arm] --> LG5[riscv64\nqemu-riscv64] --> LG6[s390x\nqemu-s390x] --> LG7[ppc64le\nqemu-ppc64le] --> LG8[loongarch64\nqemu-loongarch64]
LG1 -. failure closes queue .-> LGX[record remaining linux-glibc variants as skipped]
LG2 -. failure closes queue .-> LGX
LG3 -. failure closes queue .-> LGX
LG4 -. failure closes queue .-> LGX
LG5 -. failure closes queue .-> LGX
LG6 -. failure closes queue .-> LGX
LG7 -. failure closes queue .-> LGX
end

subgraph LINUX_MUSL[linux-musl]
LM1[x86_64\nnative] --> LM2[arm64\nqemu-aarch64] --> LM3[armv7\nqemu-arm]
LM1 -. failure closes queue .-> LMX[record remaining linux-musl variants as skipped]
LM2 -. failure closes queue .-> LMX
end

subgraph MACOS[macos]
M1[x86_64\nnative] --> M2[arm64\nnative] --> M3[universal\nnative]
M1 -. failure closes queue .-> MX[record remaining macOS variants as skipped]
M2 -. failure closes queue .-> MX
end

subgraph WASM[wasm]
WS1[emscripten-wasm32\nNode.js] --> WS2[wasi-wasm32\nwasmtime]
WS1 -. failure closes queue .-> WSX[record remaining wasm variants as skipped]
end

subgraph ANDROID[android]
AD1[arm64-v8a\nqemu-aarch64] --> AD2[armeabi-v7a\nqemu-arm] --> AD3[x86_64\nnative] --> AD4[x86\nqemu-i386]
AD1 -. failure closes queue .-> ADX[record remaining android variants as skipped]
AD2 -. failure closes queue .-> ADX
AD3 -. failure closes queue .-> ADX
end

subgraph IOS[ios]
I1[device-arm64\nmacho-header] --> I2[sim-arm64\nnative M1] --> I3[sim-x86_64\nmacho-header]
I1 -. failure closes queue .-> IX[record remaining ios variants as skipped]
I2 -. failure closes queue .-> IX
end

W6 --> Z[report job\nwrite GITHUB_STEP_SUMMARY\ntable of all 29 variant_status outputs]
WX --> Z
LG8 --> Z
LGX --> Z
LM3 --> Z
LMX --> Z
M3 --> Z
MX --> Z
WS2 --> Z
WSX --> Z
AD4 --> Z
ADX --> Z
I3 --> Z
IX --> Z
```

## Notes

- The reusable workflow lives in `.github/workflows/test-variant.yml`.
- Queue stop behavior is enforced by workflow chaining: `should_test` is set false for a variant when the previous result was not `success` or `continue_queue` was not `true`.
- The `report` job reads `needs.<job>.outputs.variant_status` rather than the raw GitHub job result, so the summary shows `success / failed / skipped` based on the internal test outcome.
- `build/ci_merge_logs.py` handles both the legacy 3-part artifact name (`logs__<platform>__<variant>`) and the current 4-part name (`logs__<type>__<platform>__<variant>`).
- The `collect` job in `build.yml` downloads `logs__*` (covering both `logs__build__*` and `logs__test__*`) and merges everything into `<type>/<platform>/<variant>/` before publishing to the repo.

