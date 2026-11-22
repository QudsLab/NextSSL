#!/usr/bin/env python3
"""Fast test: compile + clippy (no test runs) of the algorithms that changed, or of all of them, with
--keep-going, and a one-line-per-crate error summary. Run this first; run the full suite
(docker/test.sh) only when the fast test is clean.

  python tools/fasttest.py                    # changed algos (vs origin/main + working tree), linux (Docker)
  python tools/fasttest.py --target wasm      # same crates, wasm32-wasip1 build in Docker
  python tools/fasttest.py --target msvc      # same crates, clippy on this Windows host (MSVC)
  python tools/fasttest.py --all              # every crate (workspace), same summary
  python tools/fasttest.py -p ace -p mars     # explicit algorithm ids

Docker runs use the CI image (docker/Dockerfile.test built as nextssl-test:ci, see --build-image),
the registry cache volume nsl-cargo, and one target volume per target (nsl-target, nsl-wasm-target).
The summary is also written to target/fasttest-<target>.txt.
"""
import argparse, os, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = 'nextssl-test:ci'


def changed_algo_dirs():
    files = set()
    for args in (['git', 'diff', '--name-only', 'origin/main...HEAD'], ['git', 'status', '--porcelain']):
        out = subprocess.run(args, cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
        for l in out:
            p = l[3:].strip().strip('"') if args[1] == 'status' else l.strip()
            if ' -> ' in p:
                p = p.split(' -> ')[1]
            files.add(p)
    dirs = set()
    for f in files:
        parts = f.split('/')
        if len(parts) >= 4 and parts[0] == 'algos':
            dirs.add('/'.join(parts[:4]))
    return sorted(d for d in dirs if (ROOT / d / 'Cargo.toml').is_file())


def crate_of(d):
    return re.search(r'name = "([^"]+)"', (ROOT / d / 'Cargo.toml').read_text()).group(1)


def dir_of_id(i):
    hits = list(ROOT.glob(f'algos/*/*/{i}/Cargo.toml'))
    if len(hits) != 1:
        sys.exit(f'unknown algorithm id: {i}')
    return hits[0].parent.relative_to(ROOT).as_posix()


def summarize(log, target):
    lines = log.splitlines()
    first = {}
    for l in lines:
        m = re.match(r'(?:warning|error): (nextssl-algo-[a-z0-9-]+)@[^:]+: (.*)', l)
        if m and m.group(1) not in first and re.search(r'error[: ]|fatal error|undefined|panicked', m.group(2)):
            first[m.group(1)] = re.sub(r'^\S*?:\d+:\d+: ', '', m.group(2))[:160]
    # Rust-side errors: "error[...]: msg" followed by "--> path"
    cur = None
    for i, l in enumerate(lines):
        if re.match(r'^error(\[E\d+\])?: ', l) and not l.startswith('error: could not compile') \
                and not l.startswith('error: failed to run custom build'):
            cur = l
        m = re.match(r'^\s+--> (algos[/\\][^:]+)', l)
        if cur and m:
            d = '/'.join(m.group(1).replace('\\', '/').split('/')[:4])
            if (ROOT / d / 'Cargo.toml').is_file():
                first.setdefault(crate_of(d), cur[:160])
            cur = None
    # Build-script panics: the message is the line after "panicked at <path>".
    for i, l in enumerate(lines):
        m = re.search(r"panicked at (algos[/\\][^:]+)", l)
        if m and i + 1 < len(lines):
            d = '/'.join(m.group(1).replace('\\', '/').split('/')[:4])
            if (ROOT / d / 'Cargo.toml').is_file():
                first.setdefault(crate_of(d), 'build.rs panicked: ' + lines[i + 1].strip()[:140])
    failed = set(re.findall(r'failed to run custom build command for `([a-z0-9-]+)', log))
    failed |= set(re.findall(r"could not compile `([a-z0-9-]+)`", log))
    rows = [f'{c}: {first.get(c, "(see log)")}' for c in sorted(failed)]
    out = ROOT / 'target' / f'fasttest-{target}.txt'
    out.parent.mkdir(exist_ok=True)
    out.write_text('\n'.join(rows) + '\n')
    print(f'\n== fast test ({target}): {len(failed)} crate(s) failed; summary in {out}')
    for r in rows:
        print('  ' + r)
    return 1 if failed else 0


def docker(cmd, vol):
    src = str(ROOT)
    return ['docker', 'run', '--rm', '-v', f'{src}:/src', '-v', 'nsl-cargo:/usr/local/cargo/registry',
            '-v', f'{vol}:/tmp/target', '-e', 'CARGO_TARGET_DIR=/tmp/target', '-w', '/src', IMAGE, 'sh', '-c', cmd]


WASM_ENV = ('export CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar '
            'CFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi" CXX_wasm32_wasip1=clang++ '
            'CXXFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi/c++/v1 -isystem /usr/include/wasm32-wasi"; ')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--target', choices=['linux', 'wasm', 'msvc'], default='linux')
    ap.add_argument('--all', action='store_true', help='every crate in the workspace')
    ap.add_argument('-p', action='append', default=[], metavar='ID', help='algorithm id (repeatable)')
    ap.add_argument('--build-image', action='store_true', help=f'(re)build {IMAGE} from git HEAD first')
    a = ap.parse_args()

    if a.build_image:
        # Context = the committed tree (what CI checks out), never the working directory with target/.
        arch = subprocess.Popen(['git', 'archive', '--format=tar', 'HEAD'], cwd=ROOT, stdout=subprocess.PIPE)
        r = subprocess.run(['docker', 'build', '-f', 'docker/Dockerfile.test', '-t', IMAGE, '-'], stdin=arch.stdout)
        if r.returncode:
            sys.exit('image build failed')

    if a.all:
        sel = '--workspace'
        n = 'all'
    else:
        dirs = [dir_of_id(i) for i in a.p] if a.p else changed_algo_dirs()
        if not dirs:
            print('fast test: no changed algorithm folders (use --all or -p ID)')
            return 0
        sel = ' '.join('-p ' + crate_of(d) for d in dirs)
        n = str(len(dirs))
    print(f'fast test: {n} crate(s), target {a.target}')

    if a.target == 'linux':
        cmd = docker(f'cargo clippy --keep-going --all-targets {sel} -- -D warnings 2>&1', 'nsl-target')
    elif a.target == 'wasm':
        excl = ' --exclude xtask --exclude nextssl-wasm' if a.all else ''
        cmd = docker(WASM_ENV + f'cargo build --target wasm32-wasip1 --keep-going {sel}{excl} 2>&1', 'nsl-wasm-target')
    else:
        cmd = ['cargo', 'clippy', '--keep-going', '--all-targets'] + sel.split() + ['--', '-D', 'warnings']
    env = dict(os.environ, MSYS_NO_PATHCONV='1')
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, errors='replace', env=env)
    log = p.stdout + p.stderr
    (ROOT / 'target').mkdir(exist_ok=True)
    (ROOT / 'target' / f'fasttest-{a.target}.log').write_text(log, errors='replace')
    return summarize(log, a.target)


if __name__ == '__main__':
    sys.exit(main())
