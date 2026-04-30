# CI Flow

## Status

This file now describes the workflow that is actually implemented in `.github/workflows/build.yml`.

The current CI only runs four platform jobs plus the final log collector:

- `win`
- `linux`
- `macos`
- `wasm`
- `collect`

The broader seven-platform matrix in `BINARY.md` is not fully implemented in code yet.

## Current Behavior

- The workflow starts the four implemented platform jobs in parallel.
- Each platform job initializes its own log directory and then calls `build/ci_runner.py`.
- Variants run one by one inside that platform job.
- The first failed variant stops the rest of that platform queue and later variants are recorded as skipped.
- Each platform uploads `bin/<platform>/` as a CI artifact and uploads `logs/<platform>/` as a log artifact.
- `collect` always runs, merges the downloaded log artifacts, uploads `all-logs`, and publishes only `logs/` back to `main`.

There is no standalone `main` prep job in the current workflow.
There are no current workflow jobs for `linux-musl`, `android`, or `ios`.
Binaries are uploaded as CI artifacts only; the repository publish step commits logs only.

## Implemented Variant Queues

- `win`: `x86_64 -> x86 -> arm64`
- `linux`: `x86_64 -> x86 -> arm64 -> armv7 -> riscv64`
- `macos`: `x86_64 -> arm64`
- `wasm`: `wasm32`

## Layout Contract

- Logs: `logs/<platform>/<variant>/`
- Binaries: `bin/<platform>/<variant>/`

Each successful native variant is now expected to leave an actual library file under its own variant bin directory.
If a build exits successfully but stages no artifact into that directory, `build/ci_runner.py` treats the variant as failed.

## Mermaid

```mermaid
flowchart TD
A[Trigger push PR or manual run] --> W0
A --> L0
A --> M0
A --> S0

subgraph WIN[win]
W0[x86_64] --> W0Q{success?}
W0Q -->|yes| W1[x86]
W0Q -->|no| WX[stop remaining win variants]
W1 --> W1Q{success?}
W1Q -->|yes| W2[arm64]
W1Q -->|no| WX
W2 --> W2Q{success?}
W2Q -->|yes| WD[win done]
W2Q -->|no| WX
end

subgraph LINUX[linux]
L0[x86_64] --> L0Q{success?}
L0Q -->|yes| L1[x86]
L0Q -->|no| LX[stop remaining linux variants]
L1 --> L1Q{success?}
L1Q -->|yes| L2[arm64]
L1Q -->|no| LX
L2 --> L2Q{success?}
L2Q -->|yes| L3[armv7]
L2Q -->|no| LX
L3 --> L3Q{success?}
L3Q -->|yes| L4[riscv64]
L3Q -->|no| LX
L4 --> L4Q{success?}
L4Q -->|yes| LD[linux done]
L4Q -->|no| LX
end

subgraph MACOS[macos]
M0[x86_64] --> M0Q{success?}
M0Q -->|yes| M1[arm64]
M0Q -->|no| MX[stop remaining macOS variants]
M1 --> M1Q{success?}
M1Q -->|yes| MD[macOS done]
M1Q -->|no| MX
end

subgraph WASM[wasm]
S0[wasm32] --> S0Q{success?}
S0Q -->|yes| SD[wasm done]
S0Q -->|no| SX[stop remaining wasm variants]
end

WD --> Z[collect job\ndownload log artifacts\nmerge logs\nupload all-logs\npublish logs to main]
WX --> Z
LD --> Z
LX --> Z
MD --> Z
MX --> Z
SD --> Z
SX --> Z
```

## Not Yet Implemented

These platform groups exist in `BINARY.md`, but they are not wired into the current workflow or the platform adapter code:

- `linux-musl`
- `android`
- `ios`

They are not impossible on GitHub-hosted runners, but each one still needs real build support in this repo before it should appear in the current flow chart:

- `linux-musl` needs musl toolchains and a dedicated runner branch.
- `android` needs NDK-based build adapters and artifact normalization.
- `ios` needs macOS-only SDK and simulator/device build adapters.

Until those adapters exist, they should stay out of the current CI flow description.
