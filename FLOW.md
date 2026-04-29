# CI Flow

## Goals

- Keep logs mandatory for every CI run.
- Store logs in `logs/<platform>/<variant>/`.
- Store binaries in `bin/<platform>/<variant>/`.
- Run each platform in parallel.
- Run variants sequentially inside each platform job.
- Keep building later variants even if one variant fails.

## Current Shape

The workflow in `.github/workflows/build.yml` is split into five jobs:

1. `win`
2. `linux`
3. `macos`
4. `wasm`
5. `collect`

The first four jobs run in parallel.

Each platform job calls `build/ci_runner.py`.
That runner executes the variants for one platform in a fixed order and always writes:

- `logs/<platform>/<variant>/configure.log`
- `logs/<platform>/<variant>/build.log`
- `logs/<platform>/<variant>/env.txt`
- `logs/<platform>/<variant>/job_info.txt`
- `logs/<platform>/<variant>/result.txt`

Each platform job also writes a bootstrap log at `logs/<platform>/bootstrap.log` and a platform-level `job_info.txt` so setup failures still leave pullable logs.

## Variant Order

Current configured order:

- Windows: `x86_64 -> x86 -> arm64`
- Linux: `x86_64 -> x86 -> arm64 -> armv7 -> riscv64`
- macOS: `x86_64 -> arm64`
- WASM: `wasm32`

## Failure Model

`build/ci_runner.py` keeps going inside a platform job.

If one variant fails:

- its logs are still written
- later variants for the same platform still run
- the platform job finishes non-zero after the sequence ends
- the `collect` job still runs because it uses `if: always()`

## Publishing

Each platform job uploads two artifacts:

- `nextssl-<platform>` from `bin/<platform>/`
- `logs-<platform>` from `logs/<platform>/`

The `collect` job downloads all `logs-*` artifacts, normalizes them into one merged tree, uploads the fallback `all-logs` artifact, then publishes the merged logs back to `main` under:

- `logs/win/...`
- `logs/linux/...`
- `logs/macos/...`
- `logs/wasm/...`

The workflow ignores `logs/**` on push and pull request triggers to avoid self-trigger loops from the log publish commit.

## Local Validation

The same runner can be used locally:

```powershell
c:/Users/Unkn0/Desktop/VScode/Python.py/Anon-leyline/.venv/bin/python.exe build/ci_runner.py --platform win --variants x86_64 x86 arm64 --jobs 2
```

This is the path used to reproduce CI logging and Windows failures locally.

Current local result on this machine:

- `win/x86_64`: passes
- `win/x86`: passes
- `win/arm64`: configure fails before compilation because the local Visual Studio Build Tools install does not expose the `ARM64` platform to MSBuild
