#!/usr/bin/env python3
"""Fast test, two gated stages, ALL algorithms.

Stage 1 BUILD (every target, --keep-going so every error shows in one pass):
  linux  clippy -D warnings, whole workspace, all targets    (Docker, CI image nextssl-test:ci)
  wasm   cargo build --target wasm32-wasip1, whole workspace (Docker, CI image)
  msvc   clippy -D warnings, whole workspace                 (this Windows host)
  (macOS cannot run here; CI's macos job covers it.)
If ANY target has a failing crate, the run stops here: summary, exit 1, no tests.

Stage 2 TEST (only when stage 1 is clean on every target):
  smoke  one round trip per algorithm through the registry (linux), no published-KAT replay.
The full suite (docker/test.sh: all KATs, ASan, Miri, fuzz, wasm tests) comes after this.

  python tools/fasttest.py                    # stage 1 on all targets, then stage 2
  python tools/fasttest.py --targets linux    # stage 1 on a subset of targets (then stage 2 if clean)
  python tools/fasttest.py -p ace -p mars     # re-check a fix on explicit ids (not a replacement for the full pass)
  python tools/fasttest.py --build-image      # (re)build nextssl-test:ci from git HEAD first

Speed: the source tree is streamed into the container as a tar (no bind mount: reading thousands of small files
from the Windows drive was the bottleneck). Target caches: Docker volumes nsl-target / nsl-wasm-target.
Output: target/fasttest-summary.txt (one line per failure) and target/fasttest-<target>.log.
"""
import argparse, io, os, pathlib, re, subprocess, sys, tarfile, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = 'nextssl-test:ci'
SKIP = ('algos_untrusted/', 'algos_parked/', 'collection/', 'target/', 'docs/p2/')


def source_files():
    out = subprocess.run(['git', 'ls-files', '-c', '-o', '--exclude-standard', '-z'], cwd=ROOT,
                         capture_output=True).stdout.decode().split('\0')
    return [f for f in out if f and not f.startswith(SKIP) and (ROOT / f).is_file()]


def stream_tar(proc_stdin, files):
    with tarfile.open(fileobj=proc_stdin, mode='w|') as t:
        for f in files:
            t.add(str(ROOT / f), arcname=f, recursive=False)
    proc_stdin.close()


def crate_of(d):
    return re.search(r'name = "([^"]+)"', (ROOT / d / 'Cargo.toml').read_text()).group(1)


def id_of(d):
    return re.search(r'^id\s*=\s*"([^"]+)"', (ROOT / d / 'algo.toml').read_text(), re.M).group(1)


def dir_of_id(i):
    hits = list(ROOT.glob(f'algos/*/*/{i}/Cargo.toml'))
    if len(hits) != 1:
        sys.exit(f'unknown algorithm id: {i}')
    return hits[0].parent.relative_to(ROOT).as_posix()


def build_failures(log):
    lines = log.splitlines()
    first = {}
    for l in lines:
        m = re.match(r'(?:warning|error): (nextssl-algo-[a-z0-9-]+)@[^:]+: (.*)', l)
        if m and m.group(1) not in first and re.search(r'error[: ]|fatal error|undefined|panicked', m.group(2)):
            first[m.group(1)] = re.sub(r'^\S*?:\d+:\d+: ', '', m.group(2))[:160]
    cur = None
    for l in lines:
        if re.match(r'^error(\[E\d+\])?: ', l) and not l.startswith(('error: could not compile',
                                                                       'error: failed to run custom build')):
            cur = l
        m = re.match(r'^\s+--> (algos[/\\][^:]+)', l)
        if cur and m:
            d = '/'.join(m.group(1).replace('\\', '/').split('/')[:4])
            if (ROOT / d / 'Cargo.toml').is_file():
                first.setdefault(crate_of(d), cur[:160])
            cur = None
    for i, l in enumerate(lines):
        m = re.search(r"panicked at (algos[/\\][^:]+)", l)
        if m and i + 1 < len(lines):
            d = '/'.join(m.group(1).replace('\\', '/').split('/')[:4])
            if (ROOT / d / 'Cargo.toml').is_file():
                first.setdefault(crate_of(d), 'build.rs panicked: ' + lines[i + 1].strip()[:140])
    failed = set(re.findall(r'failed to run custom build command for `([a-z0-9-]+)', log))
    failed |= set(re.findall(r"could not compile `([a-z0-9-]+)`", log))
    rows = [f'{c}: {first.get(c, "(see log)")}' for c in sorted(failed)]
    bad_exit = [e for e in re.findall(r'^__EXIT__ (\d+)$', log, re.M) if e != '0']
    if bad_exit and not rows:
        errs = [l for l in lines if l.startswith('error')][:2]
        rows.append('command failed: ' + (' | '.join(errs)[:160] if errs else 'see log'))
    return rows


def smoke_failures(log):
    rows = [l.strip()[len('SMOKE FAIL '):][:180] for l in log.splitlines() if l.strip().startswith('SMOKE FAIL ')]
    if 'test result:' not in log:
        started = re.findall(r'^smoke (\S+)$', log, re.M)
        rows.append(f'{started[-1] if started else "?"}: process crashed (see log)')
    elif 'test result: FAILED' in log and not rows:
        rows.append('test failed (see log)')
    return rows


WASM_ENV = ('export CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar '
            'CFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi" CXX_wasm32_wasip1=clang++ '
            'CXXFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi/c++/v1 -isystem /usr/include/wasm32-wasi"; ')


def in_docker(cmd, vol, files):
    """Run `cmd` in /work inside the CI image, with the source tree streamed in as a tar."""
    full = f'mkdir -p /work && tar -xf - -C /work && cd /work && {cmd}'
    p = subprocess.Popen(['docker', 'run', '--rm', '-i', '-v', 'nsl-cargo:/usr/local/cargo/registry',
                          '-v', f'{vol}:/tmp/target', '-e', 'CARGO_TARGET_DIR=/tmp/target', IMAGE, 'sh', '-c', full],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stream_tar(p.stdin, files)
    out = p.stdout.read().decode(errors='replace')
    p.wait()
    return out


def on_host(args):
    p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, errors='replace')
    return p.stdout + p.stderr


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--targets', default='linux,wasm,msvc', help='comma list of linux,wasm,msvc')
    ap.add_argument('-p', action='append', default=[], metavar='ID', help='algorithm id (repeatable)')
    ap.add_argument('--build-image', action='store_true', help=f'(re)build {IMAGE} from git HEAD first')
    a = ap.parse_args()
    targets = [t for t in a.targets.split(',') if t]

    if a.build_image:
        arch = subprocess.Popen(['git', 'archive', '--format=tar', 'HEAD'], cwd=ROOT, stdout=subprocess.PIPE)
        if subprocess.run(['docker', 'build', '-f', 'docker/Dockerfile.test', '-t', IMAGE, '-'],
                          stdin=arch.stdout).returncode:
            sys.exit('image build failed')

    if a.p:
        dirs = [dir_of_id(i) for i in a.p]
        sel, ids = ' '.join('-p ' + crate_of(d) for d in dirs), ','.join(id_of(d) for d in dirs)
        what = f'{len(dirs)} selected algorithm(s)'
    else:
        sel, ids, what = '--workspace', '', 'ALL algorithms'
    files = source_files()
    out = ROOT / 'target'
    out.mkdir(exist_ok=True)
    summary = []

    print(f'STAGE 1 BUILD: {what}, targets {",".join(targets)} in parallel ({len(files)} source files)', flush=True)

    def build(t):
        t0 = time.time()
        # Every command's exit status is printed as `__EXIT__ <n>`; a non-zero status fails the target even
        # when no crate can be named (e.g. a bad cargo flag), so nothing hides behind an earlier "Finished".
        if t == 'linux':
            # the same commands as CI's build job: clippy, then the test binaries' codegen
            log = in_docker(f'cargo clippy --keep-going --all-targets {sel} -- -D warnings 2>&1; echo "__EXIT__ $?"; '
                            f'cargo test --no-run --no-fail-fast {sel} 2>&1; echo "__EXIT__ $?"', 'nsl-target', files)
        elif t == 'wasm':
            if sel == '--workspace':
                # exactly CI's build (wasm) job: both wasm targets via docker/test.sh
                log = in_docker('NEXTSSL_SKIP_BASE=1 NEXTSSL_WASM_BUILD=1 sh docker/test.sh 2>&1; echo "__EXIT__ $?"',
                                'nsl-wasm-target', files)
            else:
                log = in_docker(WASM_ENV + f'cargo build --target wasm32-wasip1 --keep-going {sel} 2>&1; echo "__EXIT__ $?"; '
                                'export CC_wasm32_unknown_unknown=clang AR_wasm32_unknown_unknown=llvm-ar '
                                'CFLAGS_wasm32_unknown_unknown="--target=wasm32-wasip1 -isystem /usr/include/wasm32-wasi" '
                                'CXX_wasm32_unknown_unknown=clang++ CXXFLAGS_wasm32_unknown_unknown="--target=wasm32-wasip1 '
                                '-isystem /usr/include/wasm32-wasi/c++/v1 -isystem /usr/include/wasm32-wasi"; '
                                f'cargo build --target wasm32-unknown-unknown --keep-going {sel} 2>&1; echo "__EXIT__ $?"',
                                'nsl-wasm-target', files)
        elif t == 'msvc':
            log = on_host(['cargo', 'clippy', '--keep-going', '--all-targets'] + sel.split() + ['--', '-D', 'warnings'])
            log += f'\n__EXIT__ {0 if "could not compile" not in log and "error:" not in log else 1}\n'
            # then the test binaries, as CI's build (windows) job does (links nextssl-ffi with every algorithm)
            tlog = on_host(['cargo', 'test', '--no-run', '--no-fail-fast'] + sel.split())
            log += tlog + f'\n__EXIT__ {0 if "could not compile" not in tlog and "error:" not in tlog else 1}\n'
        else:
            raise SystemExit(f'unknown target {t}')
        (out / f'fasttest-{t}.log').write_text(log, errors='replace')
        rows = build_failures(log)
        print(f'  build {t}: {len(rows)} failing crate(s) in {int(time.time() - t0)} s', flush=True)
        return [f'build {t} {r}' for r in rows]

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(len(targets)) as pool:
        for rows in pool.map(build, targets):
            summary += rows

    if summary:
        (out / 'fasttest-summary.txt').write_text('\n'.join(summary) + '\n')
        print(f'\nSTAGE 1 FAILED ({len(summary)} lines, target/fasttest-summary.txt). Stage 2 (tests) not run.')
        for r in summary:
            print('  ' + r)
        return 1

    print('STAGE 1 clean on every target. STAGE 2 TEST: smoke round trip per algorithm (linux)', flush=True)
    if ids:
        # Selected algorithms: their own crate tests (round trip, lengths, KATs in glue); the registry would
        # pull in every algorithm. A SMOKE FAIL-style line is synthesised per failing crate.
        slog = in_docker(f'cargo test --no-fail-fast {sel} 2>&1 | tee /tmp/t.log; '
                         r"grep -oE '^error: test failed, to rerun pass `-p [a-z0-9-]+' /tmp/t.log "
                         r"| sed -E 's/.*-p (.*)/SMOKE FAIL \1: crate tests failed/'", 'nsl-target', files)
        slog += '\ntest result: (per-crate run)\n'
    else:
        slog = in_docker(f'cargo test -p nextssl-registry --test kat --no-fail-fast '
                         f'every_algorithm_instantiates_with_metadata_sizes_and_behaves -- --nocapture 2>&1',
                         'nsl-target', files)
    (out / 'fasttest-smoke.log').write_text(slog, errors='replace')
    summary = [f'smoke {r}' for r in smoke_failures(slog)]
    (out / 'fasttest-summary.txt').write_text('\n'.join(summary) + '\n')
    print(f'STAGE 2: {len(summary)} failure(s)')
    for r in summary:
        print('  ' + r)
    return 1 if summary else 0


def cleanup():
    """Owner rule: after every run give memory and CPU back. Stops this tool's containers (if a run was
    interrupted) and drops the Docker VM's page cache, which otherwise keeps several GB of RAM in vmmem."""
    ids = subprocess.run(['docker', 'ps', '-q', '--filter', f'ancestor={IMAGE}'], capture_output=True,
                         text=True).stdout.split()
    if ids:
        subprocess.run(['docker', 'stop'] + ids, capture_output=True)
    subprocess.run(['docker', 'run', '--rm', '--privileged', '--pid=host', IMAGE, 'sh', '-c',
                    'sync; echo 3 > /proc/sys/vm/drop_caches'], capture_output=True)
    print('cleanup: containers stopped, Docker VM page cache dropped', flush=True)


if __name__ == '__main__':
    try:
        rc = main()
    finally:
        cleanup()
    sys.exit(rc)
