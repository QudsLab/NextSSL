#!/usr/bin/env python3
"""Skip a docker/test.sh layer whose inputs passed before, bit for bit (CI speed).

    python3 tools/layer_cache.py check  <layer> [extra...]   exit 0 when <layer> passed with these inputs
    python3 tools/layer_cache.py record <layer> [extra...]   record that <layer> passed with these inputs
    python3 tools/layer_cache.py key    <layer> [extra...]   print the key

Used for the layers tools/testrun.py does not cache per crate: symbols, miri, fuzz-smoke and the
browser module build. In run 45893927824, a commit that changed only .github/workflows/ci.yml, they
took 10, 14, 16 and 17 min while every test layer came from the result cache in 1-3 min.

The records live in $NEXTSSL_RESULT_CACHE/layers (the result cache CI keeps per job). Without that
variable `check` always fails and `record` does nothing, so a local run always runs every layer.

The key is a SHA-256 over
  * every file below the directories a build can read: algos/, algos_parked/, algos_untrusted/,
    crates/, xtask/, fuzz/ (not its corpus, artifacts or target), third_party/, tools/, docker/,
    .cargo/, and Cargo.toml, Cargo.lock, rust-toolchain.toml (path and content);
  * every environment variable tools/testrun.py keys on (CC*, CFLAGS*, CARGO_*, RUST*, NEXTSSL_*
    including NEXTSSL_IMAGE_ID, the toolchain image fingerprint, ...);
  * the layer name and the extra arguments (e.g. the fuzz seconds).
Docs, README files and .github/ are not inputs of a build or test and are left out; the CI settings
that reach the container do so as environment variables, which are keyed.
"""
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIRS = ['algos', 'algos_parked', 'algos_untrusted', 'crates', 'xtask', 'fuzz', 'third_party', 'tools',
        'docker', '.cargo']
FILES = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']
SKIP_DIRS = {os.path.join('fuzz', d) for d in ('corpus', 'artifacts', 'target')} | {'target', '.git'}
# Same selection as tools/testrun.py KEY_ENV / KEY_ENV_SKIP, minus the per-job paths and the shard.
KEY_ENV = re.compile(r'^(CC|CXX|AR|CFLAGS|CXXFLAGS|RUSTFLAGS|RUSTDOCFLAGS|CARGO_|RUST|NEXTSSL_|TARGET_|HOST_|'
                     r'SMOKE_|ASAN_|UBSAN_|LSAN_|MSAN_|MIRI|WASMTIME|ImageOS$|RUNNER_OS$|'
                     r'RUNNER_ARCH$|MACOSX_|SDKROOT$)')
KEY_ENV_SKIP = {'CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTUP_HOME', 'NEXTSSL_C_CACHE', 'NEXTSSL_REPORT_DIR',
                'NEXTSSL_RESULT_CACHE', 'NEXTSSL_RESULT_CACHE_WRITE_ONLY', 'NEXTSSL_SHARD', 'CARGO_TERM_COLOR',
                'NEXTSSL_WASM_OUT'}


def key(layer, extra):
    h = hashlib.sha256()
    h.update(f'layer={layer}\nextra={extra!r}\n'.encode())
    paths = []
    for d in DIRS:
        top = os.path.join(ROOT, d)
        for dirpath, dirnames, filenames in os.walk(top):
            rel = os.path.relpath(dirpath, ROOT)
            dirnames[:] = sorted(n for n in dirnames if os.path.join(rel, n) not in SKIP_DIRS
                                 and n not in ('__pycache__',))
            paths.extend(os.path.join(rel, f) for f in filenames if not f.endswith('.pyc'))
    paths.extend(f for f in FILES if os.path.isfile(os.path.join(ROOT, f)))
    for rel in sorted(p.replace(os.sep, '/') for p in paths):
        with open(os.path.join(ROOT, rel), 'rb') as f:
            data = f.read()
        h.update(f'{rel}\0{len(data)}\0'.encode())
        h.update(data)
    for k in sorted(os.environ):
        if KEY_ENV.match(k) and k not in KEY_ENV_SKIP:
            h.update(f'env {k}={os.environ[k]}\n'.encode())
    return h.hexdigest()


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ('check', 'record', 'key'):
        sys.exit(__doc__)
    action, layer, extra = sys.argv[1], sys.argv[2], sys.argv[3:]
    k = key(layer, extra)
    if action == 'key':
        print(k)
        return
    cache = os.environ.get('NEXTSSL_RESULT_CACHE')
    if not cache:
        sys.exit(1 if action == 'check' else 0)
    marker = os.path.join(cache, 'layers', f'{layer}-{k}')
    if action == 'check':
        if os.path.exists(marker):
            print(f'[layer-cache] {layer}: inputs unchanged since a passing run ({k[:12]}); not run again')
            return
        print(f'[layer-cache] {layer}: new inputs ({k[:12]}); running')
        sys.exit(1)
    # record: one marker per layer; older keys of the same layer are dropped.
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    for name in os.listdir(os.path.dirname(marker)):
        if name.startswith(f'{layer}-') and name != os.path.basename(marker):
            os.remove(os.path.join(os.path.dirname(marker), name))
    with open(marker, 'w', encoding='utf-8') as f:
        f.write(k + '\n')
    print(f'[layer-cache] {layer}: recorded ({k[:12]})')


if __name__ == '__main__':
    main()
