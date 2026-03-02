# NextSSL Documentation

NextSSL is a next-generation C security library providing a unified
cryptographic API across two build variants (full and lite) with support for
classical, post-quantum, and legacy algorithms.

---

## API Reference

| File | Contents |
|---|---|
| [api/README.md](api/README.md) | Variant comparison, quick start, overview |
| [api/FUNCTIONS.md](api/FUNCTIONS.md) | Full function signatures for both variants |
| [api/ROOT.md](api/ROOT.md) | Explicit-algorithm bypass interface |
| [api/PROFILES.md](api/PROFILES.md) | Profiles, algorithm enums, config struct, error codes |
| [api/DHCM.md](api/DHCM.md) | DHCM subsystem API |
| [api/CHANGELOG.md](api/CHANGELOG.md) | API-level change history |

## Source Map

| File | Contents |
|---|---|
| [src/README.md](src/README.md) | Layer diagram and module summary |
| [src/LAYERS.md](src/LAYERS.md) | Layer rules and import direction |
| [src/MODULES.md](src/MODULES.md) | Per-module output paths and caveats |
| [src/PRIMITIVES.md](src/PRIMITIVES.md) | Full primitive table with key sizes and variant availability |

## Binary Distribution

| File | Contents |
|---|---|
| [bin/README.md](bin/README.md) | Layout, extension map, bins.json schema, checksums |

## Testing

| File | Contents |
|---|---|
| [test/README.md](test/README.md) | runner.py CLI reference, load modes, PoW warning |

## Developer Guide

| File | Contents |
|---|---|
| [dev/README.md](dev/README.md) | Prerequisites, getting started |
| [dev/BUILD.md](dev/BUILD.md) | Config fields, Builder behaviour, macro injection |
| [dev/ADDING_MODULE.md](dev/ADDING_MODULE.md) | Step-by-step guide for adding a new algorithm |
| [dev/PLATFORM.md](dev/PLATFORM.md) | Platform flags, reproducibility, DLL export guard |

## Rules of Consistency

| File | Contents |
|---|---|
| [rule/README.md](rule/README.md) | Naming conventions, layer import rule, macro definitions |