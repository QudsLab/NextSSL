# Testing

All tests are driven by `runner.py` at the repository root.

---

## Running Tests

```sh
# Build and test everything (default)
python runner.py

# Test only the hash module, all tiers
python runner.py --test hash

# Build only, skip tests
python runner.py --build hash:partial

# Target a specific platform
python runner.py --platform windows --test all

# Run with the lite variant only
python runner.py --variant lite --test all
```

---

## CLI Reference

| Flag | Values | Default | Description |
|---|---|---|---|
| `--build` | `all`, `<module>`, `<module>:<tier>` | (all when no flags given) | Build target |
| `--test` | `all`, `<module>`, `<module>:<tier>` | (all when no flags given) | Test target |
| `--platform` | `windows`, `linux`, `mac`, `web` | (host platform) | Output platform |
| `--variant` | `lite`, `full`, `both` | `both` | Build variant |
| `--load-mode` | `gen`, `genAll`, `genQuick` | `gen` | Test load map selection |
| `--action` | string | — | GitHub Actions mode; stores logs under `logs/action/<action>/` |
| `--action-log` | file path | — | Write runner log to the specified file |
| `--bin-root` | directory | `bin/` | Override binary output root |
| `--log-root` | directory | `logs/` | Override log output root |
| `--lib-ext` | `.dll`, `.so`, `.dylib`, `.wasm` | (inferred from platform) | Override output extension |
| `--no-color` | (flag) | off | Disable colored console output |

---

## Load Modes

The `--load-mode` flag selects which set of test targets is loaded.

| Mode | Map used | Description |
|---|---|---|
| `gen` | `LOAD_MAP` | Default set — balanced coverage |
| `genAll` | `LOAD_MAP_ALL` | Full set including slow/large tests |
| `genQuick` | `LOAD_MAP_QUICK` | Fast subset for local iteration |

---

## Test Output

Results are written to `logs/test/` by default.  Log file naming follows:

```
logs/test/<platform>/<tier>/<module>.log
```

---

## PoW Tests

> **Warning:** The PoW module (`src/PoW/`) is unstable and subject to
> structural change.  PoW tests may fail or behave inconsistently across
> builds.
>
> If you need reproducible PoW test results, pin to a specific commit hash
> before running:
>
> ```sh
> git checkout <commit-hash>
> python runner.py --test pow
> ```
>
> Do not rely on PoW test output for correctness assertions in CI pipelines
> targeting the `main` branch.

---

## Test Structure

```
script/test/
  base/       ← base-layer test scripts
  main/       ← main-layer test scripts
  partial/    ← partial-layer test scripts
  suites/     ← combined test suites

tests/
  test_all.py ← top-level pytest entry point
```
