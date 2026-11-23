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
IMAGE_MAC = 'nextssl-test:macos'  # docker/Dockerfile.macos: IMAGE + Zig + cargo-zigbuild
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


# Owner rule: a run uses at most --mem-gb of RAM in total (default 10). Each target gets a share; a Docker
# target is hard-capped with --memory (no swap), and every target runs at most one cargo job per GB of its
# share, which bounds rustc/cc memory on the host (msvc) too.
BUDGET = {}
# Most jobs (a C file, a small glue crate) need a few hundred MB; only the workspace-wide links need GBs, and
# an OOM-killed link is retried with LOW_JOBS. So 2 jobs per GB keeps the CPU busy inside the same cap.
JOBS_PER_GB = 2


def share(t):
    return BUDGET.get(t, 3)


def jobs_of(t):
    return max(1, share(t) * JOBS_PER_GB)


OOM = 'signal: 9 (SIGKILL)'
LOW_JOBS = 2


EXTRA_ENV = {}  # extra -e VAR=value for every container (e.g. SMOKE_JOBS in local mode)
# Debug info is most of a debug target dir (1924 crates x 2 Docker targets reached 208 GB and filled D:).
# The gate compiles and links the same code without it; set for every container and the msvc host build.
NO_DEBUGINFO = {'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0'}
MIN_FREE_GB = 40  # refuse to start when D: (Docker disk and target/) has less free space than this


def check_disk():
    import shutil
    free = shutil.disk_usage(ROOT.anchor).free / 2**30
    if free < MIN_FREE_GB:
        sys.exit(f'only {free:.0f} GB free on {ROOT.anchor} (need {MIN_FREE_GB}); free space first, nothing started')
    print(f'disk: {free:.0f} GB free on {ROOT.anchor}', flush=True)


def in_docker(cmd, vol, files, t, jobs=None, image=IMAGE):
    """Run `cmd` in /work inside the CI image, with the source tree streamed in as a tar.

    Several workspace-wide links (nextssl-ffi, the api/kat tests: every algorithm in one binary) can run at
    once and together exceed the memory cap; the kernel then kills a linker (SIGKILL). The same command is
    then run once more with LOW_JOBS jobs: everything already built is cached, so only the remaining links
    run, and the second run's log replaces the first (a real error shows up again there)."""
    full = f'mkdir -p /work && tar -xf - -C /work && cd /work && {cmd}'
    gb = share(t)
    p = subprocess.Popen(['docker', 'run', '--rm', '-i', f'--memory={gb}g', f'--memory-swap={gb}g',
                          '-e', f'CARGO_BUILD_JOBS={jobs or jobs_of(t)}',
                          *[x for k, v in {**NO_DEBUGINFO, **EXTRA_ENV}.items() for x in ('-e', f'{k}={v}')],
                          '-v', 'nsl-cargo:/usr/local/cargo/registry',
                          '-v', f'{vol}:/tmp/target', '-e', 'CARGO_TARGET_DIR=/tmp/target', image, 'sh', '-c', full],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stream_tar(p.stdin, files)
    out = p.stdout.read().decode(errors='replace')
    p.wait()
    if jobs is None and OOM in out:
        print(f'  {t}: a linker hit the {gb} GB cap ({OOM}); re-running with {LOW_JOBS} jobs', flush=True)
        return (f'[fasttest] first run: a linker hit the {gb} GB memory cap; re-run with {LOW_JOBS} jobs\n'
                + in_docker(cmd, vol, files, t, LOW_JOBS, image))
    return out


def on_host(args):
    env = dict(os.environ, CARGO_BUILD_JOBS=str(jobs_of('msvc')), **NO_DEBUGINFO, **EXTRA_ENV)
    p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, errors='replace', env=env)
    return p.stdout + p.stderr


def main():
    global KEEP_DOCKER, JOBS_PER_GB
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--targets', default='linux,wasm,msvc', help='comma list of linux,wasm,msvc,macos (macos: build check via Zig, local only)')
    ap.add_argument('-p', action='append', default=[], metavar='ID', help='algorithm id (repeatable)')
    ap.add_argument('--build-image', action='store_true', help=f'(re)build {IMAGE} from git HEAD first')
    ap.add_argument('--mem-gb', type=int, default=10, help='RAM budget for the whole run in GB (default 10)')
    ap.add_argument('--mode', choices=('local', 'ci'), default='local',
                    help='local (default): fastest on this PC, smoke runs SMOKE_JOBS algorithms at once; '
                         'ci: everything exactly as GitHub CI runs it (smoke one algorithm at a time)')
    ap.add_argument('--keep-docker', action='store_true',
                    help='leave Docker Desktop running at the end (default: stop it, which frees its VM memory)')
    ap.add_argument('--jobs-per-gb', type=int, default=JOBS_PER_GB,
                    help=f'cargo jobs per GB of a target\'s RAM share (default {JOBS_PER_GB})')
    a = ap.parse_args()
    KEEP_DOCKER = a.keep_docker
    JOBS_PER_GB = max(1, a.jobs_per_gb)
    targets = [t for t in a.targets.split(',') if t]
    check_disk()
    ensure_docker()
    if a.mode == 'local':
        # same compile and test commands as CI; only the smoke loop runs several algorithms at once
        EXTRA_ENV['SMOKE_JOBS'] = str(min(os.cpu_count() or 4, 12))
    print(f'mode {a.mode}' + (f', SMOKE_JOBS={EXTRA_ENV["SMOKE_JOBS"]}' if EXTRA_ENV else ''), flush=True)
    # linux runs clippy + test builds of the biggest graph, so it gets the largest share
    weight = {'linux': 4, 'wasm': 3, 'msvc': 3, 'macos': 3}
    total = sum(weight.get(t, 3) for t in targets)
    for t in targets:
        BUDGET[t] = max(1, a.mem_gb * weight.get(t, 3) // total)
    # stage 2: the linux smoke container shares the budget with the Windows cargo test on the host
    BUDGET['smoke'] = max(1, a.mem_gb - BUDGET.get('msvc', 0))
    print('RAM budget: ' + ', '.join(f'{t} {BUDGET[t]} GB / {jobs_of(t)} jobs' for t in targets), flush=True)

    if a.build_image:
        arch = subprocess.Popen(['git', 'archive', '--format=tar', 'HEAD'], cwd=ROOT, stdout=subprocess.PIPE)
        if subprocess.run(['docker', 'build', '-f', 'docker/Dockerfile.test', '-t', IMAGE, '-'],
                          stdin=arch.stdout).returncode:
            sys.exit('image build failed')

    if 'macos' in targets and (a.build_image or subprocess.run(['docker', 'image', 'inspect', IMAGE_MAC],
                                                                capture_output=True).returncode):
        # no build context: the Dockerfile only adds Zig and cargo-zigbuild on top of IMAGE
        with open(ROOT / 'docker' / 'Dockerfile.macos', 'rb') as df:
            if subprocess.run(['docker', 'build', '-t', IMAGE_MAC, '-'], stdin=df).returncode:
                sys.exit('macos image build failed')

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
                            # link every test binary with --keep-going first: `cargo test --no-run` stops scheduling
                            # after the first failed crate, so it alone shows one link error per run
                            f'cargo build --tests --keep-going {sel} 2>&1; echo "__EXIT__ $?"; '
                            f'cargo test --no-run --no-fail-fast {sel} 2>&1; echo "__EXIT__ $?"', 'nsl-target', files, 'linux')
        elif t == 'wasm':
            if sel == '--workspace':
                # exactly CI's build (wasm) job: both wasm targets via docker/test.sh
                log = in_docker('NEXTSSL_SKIP_BASE=1 NEXTSSL_WASM_BUILD=1 sh docker/test.sh 2>&1; echo "__EXIT__ $?"',
                                'nsl-wasm-target', files, 'wasm')
            else:
                log = in_docker(WASM_ENV + f'cargo build --target wasm32-wasip1 --keep-going {sel} 2>&1; echo "__EXIT__ $?"; '
                                'export CC_wasm32_unknown_unknown=clang AR_wasm32_unknown_unknown=llvm-ar '
                                'CFLAGS_wasm32_unknown_unknown="--target=wasm32-wasip1 -isystem /usr/include/wasm32-wasi" '
                                'CXX_wasm32_unknown_unknown=clang++ CXXFLAGS_wasm32_unknown_unknown="--target=wasm32-wasip1 '
                                '-isystem /usr/include/wasm32-wasi/c++/v1 -isystem /usr/include/wasm32-wasi"; '
                                f'cargo build --target wasm32-unknown-unknown --keep-going {sel} 2>&1; echo "__EXIT__ $?"',
                                'nsl-wasm-target', files, 'wasm')
        elif t == 'macos':
            # Build check for Apple Silicon (CI's macos-latest is arm64): every crate and every test binary
            # compiled and linked by Zig; nothing runs. GitHub CI's macos job still runs the tests.
            log = in_docker('cargo-zigbuild build --target aarch64-apple-darwin --tests --keep-going '
                            f'{sel} 2>&1; echo "__EXIT__ $?"', 'nsl-macos-target', files, 'macos', image=IMAGE_MAC)
        elif t == 'msvc':
            log = on_host(['cargo', 'clippy', '--keep-going', '--all-targets'] + sel.split() + ['--', '-D', 'warnings'])
            log += f'\n__EXIT__ {0 if "could not compile" not in log and "error:" not in log else 1}\n'
            # then the test binaries, as CI's build (windows) job does (links nextssl-ffi with every algorithm)
            # every test binary linked with --keep-going first (`cargo test --no-run` stops after the first
            # failed crate, so alone it shows one link error per run), then CI's exact command
            tlog = on_host(['cargo', 'build', '--tests', '--keep-going'] + sel.split())
            tlog += f'\n__EXIT__ {0 if "could not compile" not in tlog and "error:" not in tlog else 1}\n'
            tlog += on_host(['cargo', 'test', '--no-run', '--no-fail-fast'] + sel.split())
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

    stage2 = [t for t in ('linux', 'msvc') if t in targets]
    if not stage2:
        print('STAGE 1 clean. STAGE 2 not run: neither linux nor msvc is among --targets.', flush=True)
        return 0
    # linux: the smoke round trip per algorithm. msvc: CI's `test (windows-latest)` job, every test of the
    # workspace run on this Windows host (CI runs `cargo test --workspace`; --no-fail-fast reports every
    # failing crate in one pass). Both at once: one runs in Docker, the other on the host.
    print('STAGE 1 clean on every target. STAGE 2 TEST: ' + ', '.join(
        {'linux': 'linux smoke round trip per algorithm', 'msvc': 'Windows cargo test --workspace'}[t]
        for t in stage2), flush=True)

    def linux_smoke():
        t0 = time.time()
        if ids:
            # Selected algorithms: their own crate tests (round trip, lengths, KATs in glue); the registry would
            # pull in every algorithm. A SMOKE FAIL-style line is synthesised per failing crate.
            slog = in_docker(f'cargo test --no-fail-fast {sel} 2>&1 | tee /tmp/t.log; '
                             r"grep -oE '^error: test failed, to rerun pass `-p [a-z0-9-]+' /tmp/t.log "
                             r"| sed -E 's/.*-p (.*)/SMOKE FAIL \1: crate tests failed/'", 'nsl-target', files,
                             'smoke')
            slog += '\ntest result: (per-crate run)\n'
        else:
            slog = in_docker(f'cargo test -p nextssl-registry --test kat --no-fail-fast '
                             f'every_algorithm_instantiates_with_metadata_sizes_and_behaves -- --nocapture 2>&1',
                             'nsl-target', files, 'smoke')
        (out / 'fasttest-smoke.log').write_text(slog, errors='replace')
        rows = [f'smoke {r}' for r in smoke_failures(slog)]
        print(f'  test linux smoke: {len(rows)} failure(s) in {int(time.time() - t0)} s', flush=True)
        return rows

    def msvc_test():
        t0 = time.time()
        tlog = on_host(['cargo', 'test', '--no-fail-fast'] + sel.split())
        (out / 'fasttest-msvc-test.log').write_text(tlog, errors='replace')
        rows = sorted(set(re.findall(r'error: test failed, to rerun pass `-p ([\w-]+)', tlog)))
        rows = [f'test msvc {c}: tests failed (target/fasttest-msvc-test.log)' for c in rows]
        if 'could not compile' in tlog:
            rows += [f'test msvc {c}: does not compile' for c in
                     sorted(set(re.findall(r'could not compile `([\w-]+)`', tlog)))]
        if not rows and not re.search(r'^test result: ok', tlog, re.M):
            rows = ['test msvc: no passing test result found (target/fasttest-msvc-test.log)']
        print(f'  test msvc (cargo test): {len(rows)} failure(s) in {int(time.time() - t0)} s', flush=True)
        return rows

    jobs = {'linux': linux_smoke, 'msvc': msvc_test}
    summary = []
    with ThreadPoolExecutor(len(stage2)) as pool:
        for rows in pool.map(lambda t: jobs[t](), stage2):
            summary += rows
    (out / 'fasttest-summary.txt').write_text('\n'.join(summary) + '\n')
    print(f'STAGE 2: {len(summary)} failure(s)')
    for r in summary:
        print('  ' + r)
    return 1 if summary else 0


KEEP_DOCKER = False
DOCKER_DESKTOP = pathlib.Path(r'C:\Program Files\Docker\Docker\Docker Desktop.exe')


def docker_up():
    return subprocess.run(['docker', 'info'], capture_output=True).returncode == 0


def ensure_docker():
    """Docker Desktop is not started at login (owner's choice, it holds ~10 GB of VM memory): start it here."""
    if docker_up():
        return
    print('starting Docker Desktop ...', flush=True)
    started = subprocess.run(['docker', 'desktop', 'start'], capture_output=True).returncode == 0
    if not started and DOCKER_DESKTOP.is_file():
        subprocess.Popen([str(DOCKER_DESKTOP)])
    for _ in range(90):
        if docker_up():
            print('Docker is up', flush=True)
            return
        time.sleep(2)
    sys.exit('Docker did not start within 3 minutes')


def cleanup():
    """Owner rule: after every run give memory and CPU back. Stops this tool's containers (if a run was
    interrupted), drops the Docker VM's page cache, then stops Docker Desktop (unless --keep-docker), which
    gives the VM's memory (up to the 10 GB .wslconfig cap) back to Windows."""
    if not docker_up():
        return
    ids = subprocess.run(['docker', 'ps', '-q', '--filter', f'ancestor={IMAGE}'], capture_output=True,
                         text=True).stdout.split()
    if ids:
        subprocess.run(['docker', 'stop'] + ids, capture_output=True)
    subprocess.run(['docker', 'run', '--rm', '--privileged', '--pid=host', IMAGE, 'sh', '-c',
                    'sync; echo 3 > /proc/sys/vm/drop_caches'], capture_output=True)
    msg = 'cleanup: containers stopped, Docker VM page cache dropped'
    if not KEEP_DOCKER:
        if subprocess.run(['docker', 'ps', '-q'], capture_output=True, text=True).stdout.strip():
            msg += '; Docker left running (other containers are running)'
        elif subprocess.run(['docker', 'desktop', 'stop'], capture_output=True).returncode == 0:
            msg += '; Docker Desktop stopped (VM memory returned)'
        else:
            msg += '; could not stop Docker Desktop (docker desktop stop failed)'
    print(msg, flush=True)


if __name__ == '__main__':
    try:
        rc = main()
    finally:
        cleanup()
    sys.exit(rc)
