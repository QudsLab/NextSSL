# CI Flow

## Status

This file describes the workflow that is now implemented in `.github/workflows/build.yml`.

The CI has seven visible platform groups plus the final log collector:

- `win`
- `linux-glibc`
- `linux-musl`
- `macos`
- `wasm`
- `android`
- `ios`
- `collect`

Each variant is now its own GitHub Actions job, so the Actions UI shows internal variant progress directly instead of hiding it inside one long per-platform step.

## Current Behavior

- The workflow starts one queue per platform group in parallel.
- Inside a platform group, variants are chained one after another as visible jobs.
- The first failed variant closes that platform queue.
- Remaining jobs in that platform queue still run, but they record `status: skipped` logs instead of attempting a build.
- Each visible variant uploads `bin/<platform>/<variant>/` as its binary artifact.
- Each visible variant uploads `logs/<platform>/<variant>/` as its log artifact.
- `collect` always runs, merges the per-variant log artifacts back into `logs/<platform>/<variant>/`, regenerates per-platform `SUMMARY.txt`, uploads `all-logs`, and publishes only `logs/` back to the repo when the run is on `main` or `master` and not a pull request.
- The job summary now tells the truth: it distinguishes between repo publication, no-op publication, artifact-only runs, and publish failures.

Binaries are uploaded as CI artifacts only. The repository publish step commits logs only.

## Platform Queues

- `win`: `x86_64-msvc -> x86-msvc -> arm64-msvc -> x86_64-mingw -> x86-mingw -> armv7-msvc`
- `linux-glibc`: `x86_64 -> x86 -> arm64 -> armv7 -> riscv64 -> s390x -> ppc64le -> loongarch64`
- `linux-musl`: `x86_64 -> arm64 -> armv7`
- `macos`: `x86_64 -> arm64 -> universal`
- `wasm`: `emscripten-wasm32 -> wasi-wasm32`
- `android`: `arm64-v8a -> armeabi-v7a -> x86_64 -> x86`
- `ios`: `device-arm64 -> sim-arm64 -> sim-x86_64`

## Layout Contract

- Logs: `logs/<platform>/<variant>/`
- Binaries: `bin/<platform>/<variant>/`

Each successful variant is expected to stage at least one matching artifact into its own variant bin directory.
If a build exits successfully but stages nothing into that directory, `build/ci_runner.py` records the variant as failed.

## Mermaid

```mermaid
flowchart TD
A[Trigger push PR or manual run] --> W1
A --> LG1
A --> LM1
A --> M1
A --> WS1
A --> AD1
A --> I1

subgraph WIN[win]
W1[x86_64-msvc] --> W2[x86-msvc] --> W3[arm64-msvc] --> W4[x86_64-mingw] --> W5[x86-mingw] --> W6[armv7-msvc]
W1 -. failure closes queue .-> WX[record remaining win variants as skipped]
W2 -. failure closes queue .-> WX
W3 -. failure closes queue .-> WX
W4 -. failure closes queue .-> WX
W5 -. failure closes queue .-> WX
end

subgraph LINUX_GLIBC[linux-glibc]
LG1[x86_64] --> LG2[x86] --> LG3[arm64] --> LG4[armv7] --> LG5[riscv64] --> LG6[s390x] --> LG7[ppc64le] --> LG8[loongarch64]
LG1 -. failure closes queue .-> LGX[record remaining linux-glibc variants as skipped]
LG2 -. failure closes queue .-> LGX
LG3 -. failure closes queue .-> LGX
LG4 -. failure closes queue .-> LGX
LG5 -. failure closes queue .-> LGX
LG6 -. failure closes queue .-> LGX
LG7 -. failure closes queue .-> LGX
end

subgraph LINUX_MUSL[linux-musl]
LM1[x86_64] --> LM2[arm64] --> LM3[armv7]
LM1 -. failure closes queue .-> LMX[record remaining linux-musl variants as skipped]
LM2 -. failure closes queue .-> LMX
end

subgraph MACOS[macos]
M1[x86_64] --> M2[arm64] --> M3[universal]
M1 -. failure closes queue .-> MX[record remaining macOS variants as skipped]
M2 -. failure closes queue .-> MX
end

subgraph WASM[wasm]
WS1[emscripten-wasm32] --> WS2[wasi-wasm32]
WS1 -. failure closes queue .-> WSX[record remaining wasm variants as skipped]
end

subgraph ANDROID[android]
AD1[arm64-v8a] --> AD2[armeabi-v7a] --> AD3[x86_64] --> AD4[x86]
AD1 -. failure closes queue .-> ADX[record remaining android variants as skipped]
AD2 -. failure closes queue .-> ADX
AD3 -. failure closes queue .-> ADX
end

subgraph IOS[ios]
I1[device-arm64] --> I2[sim-arm64] --> I3[sim-x86_64]
I1 -. failure closes queue .-> IX[record remaining ios variants as skipped]
I2 -. failure closes queue .-> IX
end

W6 --> Z[collect job\ndownload logs__* artifacts\nmerge logs/<platform>/<variant>/\nrebuild SUMMARY.txt\nupload all-logs\npublish logs when allowed]
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

- The reusable workflow lives in `.github/workflows/build-variant.yml`.
- Queue stop behavior is enforced by workflow chaining and by `build/ci_skip.py` for blocked variants.
- Log normalization in `collect` is handled by `build/ci_merge_logs.py`.
- Direct local `build.py` adapters are still narrower than the CI matrix; CI-only profiles are driven through `build/ci_runner.py` plus toolchain setup in the workflow.
