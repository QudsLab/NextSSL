# CI Flow

## Status

This file is a review draft for the full CI topology.

It now covers all seven platform groups from `BINARY.md` and all twenty-nine listed variants.

It describes the target workflow behavior, not the current runner behavior.

Android and iOS are still marked optional in `BINARY.md`, but they are included here so the full branch shape and variant order are defined in one place.

## Goals

- Keep logs mandatory for every CI run.
- Clear stale logs at the beginning of the run.
- Keep log layout as `logs/<platform>/<variant>/`.
- Keep staged binary layout as `bin/<platform>/<variant>/`.
- Cover all 7 platform groups and all 29 variants from `BINARY.md`.
- Run only one active variant per platform at a time.
- Run all enabled platform groups in parallel after `main` finishes.
- Stop the remaining variants of a platform after the first failure in that platform.
- Always publish all collected logs at the end, even if one or more platforms fail early.

## Normalized Platform IDs

To keep CI layout consistent, the flow should use these platform IDs:

- `win`
- `linux-glibc`
- `linux-musl`
- `macos`
- `wasm`
- `android`
- `ios`

`BINARY.md` remains the source for the platform matrix and artifact details.
This flow file defines the normalized CI branch and variant IDs.

## Target Shape

The workflow should be split into these stages:

1. `main`
2. `win`
3. `linux-glibc`
4. `linux-musl`
5. `macos`
6. `wasm`
7. `android`
8. `ios`
9. `collect`

`main` runs first.

Its job is to:

- validate the run context
- clear old `logs/` content for a clean run
- recreate the base log folders
- write shared run metadata

After `main` succeeds, the seven platform branches can start in parallel:

- `win`
- `linux-glibc`
- `linux-musl`
- `macos`
- `wasm`
- `android`
- `ios`

Inside each platform job, variants run one by one.

When all seven platform groups are enabled, the maximum active build count should be seven:

- one Windows variant
- one Linux glibc variant
- one Linux musl variant
- one macOS variant
- one WASM variant
- one Android variant
- one iOS variant

If `main` fails, the platform branches should not start, but `collect` should still publish the `main` logs.

## Variant Queues

The queue order should favor the most representative supported build first, then continue to the other variants for that platform.

- `win`: `x86_64-msvc -> x86-msvc -> arm64-msvc -> x86_64-mingw -> x86-mingw -> armv7-msvc`
- `linux-glibc`: `x86_64 -> x86 -> arm64 -> armv7 -> riscv64 -> s390x -> ppc64le -> loongarch64`
- `linux-musl`: `x86_64 -> arm64 -> armv7`
- `macos`: `x86_64 -> arm64 -> universal`
- `wasm`: `emscripten-wasm32 -> wasi-wasm32`
- `android`: `arm64-v8a -> armeabi-v7a -> x86_64 -> x86`
- `ios`: `device-arm64 -> sim-arm64 -> sim-x86_64`

Notes:

- `macos/universal` should run only after both thin macOS builds succeed in sequence.
- `ios` variants produce static libraries, but they should still use the same log structure.
- `wasm` currently has a legacy `bin/web/` builder output in parts of the repo; CI staging should normalize that into `bin/wasm/<variant>/` before upload.

## Failure Rule

This is the rule to follow:

- start the first variant in each enabled platform branch
- if a variant succeeds, continue to the next variant in that same branch
- if a variant fails, stop the remaining variants in that same branch
- do not stop the other platform branches because of one platform failure
- always keep the logs already produced by the failed branch
- always run the final log collection and publish step

This changes the old behavior.

The old flow kept running later variants in the same platform after a failure.
The target flow must not do that.

## Log Contract

The workflow should still write logs in a durable way.

Required files:

- `logs/main/bootstrap.log`
- `logs/main/job_info.txt`
- `logs/<platform>/bootstrap.log`
- `logs/<platform>/job_info.txt`
- `logs/<platform>/<variant>/configure.log`
- `logs/<platform>/<variant>/build.log`
- `logs/<platform>/<variant>/env.txt`
- `logs/<platform>/<variant>/job_info.txt`
- `logs/<platform>/<variant>/result.txt`

If a platform stops early, the failed variant must still write its result file.

Skipped variants must not create fake success logs.
If explicit skip tracking is desired, a skipped variant directory should contain only a small `result.txt` with `status: skipped` and the skip reason.

## Publish Rule

The last stage is `collect`.

`collect` must run with `always()` semantics so logs are still published when:

- `main` fails
- one variant fails
- one platform stops early
- multiple platforms fail in the same run

The `collect` stage should:

- download all log artifacts created by the platform jobs
- merge them into the flat repository layout
- upload a combined log artifact
- publish the merged `logs/` tree back to `main`

## Mermaid Review Chart

```mermaid
flowchart TD
A[Trigger Push PR or Manual Run] --> B[main job\ncheck run context\nclear logs\nrecreate logs tree\nwrite shared metadata]
B --> W0
B --> LG0
B --> LM0
B --> MC0
B --> WS0
B --> AD0
B --> IO0

subgraph WIN[win branch]
W0[x86_64-msvc] --> W0Q{success?}
W0Q -->|yes| W1[x86-msvc]
W0Q -->|no| WX[stop remaining win variants]
W1 --> W1Q{success?}
W1Q -->|yes| W2[arm64-msvc]
W1Q -->|no| WX
W2 --> W2Q{success?}
W2Q -->|yes| W3[x86_64-mingw]
W2Q -->|no| WX
W3 --> W3Q{success?}
W3Q -->|yes| W4[x86-mingw]
W3Q -->|no| WX
W4 --> W4Q{success?}
W4Q -->|yes| W5[armv7-msvc]
W4Q -->|no| WX
W5 --> W5Q{success?}
W5Q -->|yes| WD[win done]
W5Q -->|no| WX
end

subgraph LINUX_GLIBC[linux-glibc branch]
LG0[x86_64] --> LG0Q{success?}
LG0Q -->|yes| LG1[x86]
LG0Q -->|no| LGX[stop remaining linux-glibc variants]
LG1 --> LG1Q{success?}
LG1Q -->|yes| LG2[arm64]
LG1Q -->|no| LGX
LG2 --> LG2Q{success?}
LG2Q -->|yes| LG3[armv7]
LG2Q -->|no| LGX
LG3 --> LG3Q{success?}
LG3Q -->|yes| LG4[riscv64]
LG3Q -->|no| LGX
LG4 --> LG4Q{success?}
LG4Q -->|yes| LG5[s390x]
LG4Q -->|no| LGX
LG5 --> LG5Q{success?}
LG5Q -->|yes| LG6[ppc64le]
LG5Q -->|no| LGX
LG6 --> LG6Q{success?}
LG6Q -->|yes| LG7[loongarch64]
LG6Q -->|no| LGX
LG7 --> LG7Q{success?}
LG7Q -->|yes| LGD[linux-glibc done]
LG7Q -->|no| LGX
end

subgraph LINUX_MUSL[linux-musl branch]
LM0[x86_64] --> LM0Q{success?}
LM0Q -->|yes| LM1[arm64]
LM0Q -->|no| LMX[stop remaining linux-musl variants]
LM1 --> LM1Q{success?}
LM1Q -->|yes| LM2[armv7]
LM1Q -->|no| LMX
LM2 --> LM2Q{success?}
LM2Q -->|yes| LMD[linux-musl done]
LM2Q -->|no| LMX
end

subgraph MACOS[macos branch]
MC0[x86_64] --> MC0Q{success?}
MC0Q -->|yes| MC1[arm64]
MC0Q -->|no| MCX[stop remaining macOS variants]
MC1 --> MC1Q{success?}
MC1Q -->|yes| MC2[universal]
MC1Q -->|no| MCX
MC2 --> MC2Q{success?}
MC2Q -->|yes| MCD[macOS done]
MC2Q -->|no| MCX
end

subgraph WASM[wasm branch]
WS0[emscripten-wasm32] --> WS0Q{success?}
WS0Q -->|yes| WS1[wasi-wasm32]
WS0Q -->|no| WSX[stop remaining wasm variants]
WS1 --> WS1Q{success?}
WS1Q -->|yes| WSD[wasm done]
WS1Q -->|no| WSX
end

subgraph ANDROID[android branch]
AD0[arm64-v8a] --> AD0Q{success?}
AD0Q -->|yes| AD1[armeabi-v7a]
AD0Q -->|no| ADX[stop remaining android variants]
AD1 --> AD1Q{success?}
AD1Q -->|yes| AD2[x86_64]
AD1Q -->|no| ADX
AD2 --> AD2Q{success?}
AD2Q -->|yes| AD3[x86]
AD2Q -->|no| ADX
AD3 --> AD3Q{success?}
AD3Q -->|yes| ADD[android done]
AD3Q -->|no| ADX
end

subgraph IOS[ios branch]
IO0[device-arm64] --> IO0Q{success?}
IO0Q -->|yes| IO1[sim-arm64]
IO0Q -->|no| IOX[stop remaining ios variants]
IO1 --> IO1Q{success?}
IO1Q -->|yes| IO2[sim-x86_64]
IO1Q -->|no| IOX
IO2 --> IO2Q{success?}
IO2Q -->|yes| IOD[ios done]
IO2Q -->|no| IOX
end

WD --> Z[collect job\ndownload platform logs\nmerge logs\nupload all-logs artifact\npublish logs to main]
WX --> Z
LGD --> Z
LGX --> Z
LMD --> Z
LMX --> Z
MCD --> Z
MCX --> Z
WSD --> Z
WSX --> Z
ADD --> Z
ADX --> Z
IOD --> Z
IOX --> Z
```

## Review Notes

This draft now matches the full matrix:

- 7 platform groups
- 29 total variants
- one active variant per platform branch
- stop-on-first-failure inside a branch
- final log publish still runs for partial and failed runs

## Local Validation Idea

When this flow is implemented, the runner should be tested with cases like:

- fail `win/x86_64-msvc` and confirm the rest of the Windows queue is skipped
- fail `linux-glibc/arm64` and confirm `armv7`, `riscv64`, `s390x`, `ppc64le`, and `loongarch64` are skipped
- fail `linux-musl/x86_64` and confirm the musl queue stops without affecting the glibc queue
- fail `macos/arm64` and confirm `universal` is skipped
- let `wasm/emscripten-wasm32` pass and `wasm/wasi-wasm32` fail, then confirm only the WASM queue stops
- let Android fail while iOS continues, then confirm `collect` still publishes logs from every branch
