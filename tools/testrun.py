#!/usr/bin/env python3
"""Build every test binary, then run every test in its own process, in parallel, with a time limit.

    python3 tools/testrun.py --out test-report [--jobs N] [--timeout S] [--runner CMD] [-- CARGO BUILD ARGS]

Steps
  1. build: `cargo build --tests --keep-going --message-format=json-render-diagnostics <args>`
     (default args: --workspace). A crate that does not compile is reported as a compile error;
     every other crate is still built and tested.
  2. list:  `<binary> --list --format terse` for every test binary.
  3. run:   `<binary> --exact <test> --test-threads 1 --nocapture`, one process per test, --jobs at a
     time, in the package directory (as cargo test does). A test that runs longer than --timeout is
     killed and reported as a hang; a crash (signal, access violation, abort, UB trap) fails only that
     test. Nothing stops the run.
  4. report (in --out):
       test-summary.md     totals, failures by kind, one section per failing crate, slowest tests
       test-failures.json  the same data for tools (--rerun-failed reads it)
       test-full.log       build output and the output of every test that did not pass
       test-times.tsv      seconds per test
     The summary is also appended to $GITHUB_STEP_SUMMARY. Duplicates are folded (addresses, ids and
     sizes masked) and at most --max-per-algo distinct issues are kept per crate.

Exit status: 0 only when everything built and every test passed. Standard library only.
"""

import argparse
import collections
import concurrent.futures
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time

ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
PANIC = re.compile(r"^thread '([^']*)'(?: \(\d+\))? panicked at (.+?):(\d+):\d+:$")
OVERFLOW = re.compile(r"^thread '([^']*)'(?: \(\d+\))? has overflowed its stack")
SAN_ERR = re.compile(r'^(?:==\d+==)?ERROR: (AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer): (.*)$')
SAN_SUM = re.compile(r'^SUMMARY: (\w+Sanitizer): (.*)$')
UBSAN = re.compile(r'(\S+:\d+:\d+): runtime error: (.*)$')
FRAME = re.compile(r'^\s*#\d+ 0x[0-9a-f]+ in (\S+) (\S+)')
COULD_NOT = re.compile(r'^error: could not compile `([\w.-]+)`')
BUILD_SCRIPT = re.compile(r'^error: failed to run custom build command for `([\w.-]+) v')
MASK = [
    (re.compile(r'0x[0-9a-fA-F]+'), '0x…'),
    (re.compile(r'==\d+=='), '==…=='),
    (re.compile(r'\(\d+\)'), '(…)'),
    (re.compile(r'\b[0-9a-f]{16}\b'), '…'),
    (re.compile(r'\d+ byte\(s\)'), 'N byte(s)'),
    (re.compile(r'in \d+ (allocation|object)'), r'in N \1'),
]
# Windows NTSTATUS codes a crashing test process exits with.
NTSTATUS = {
    0xC0000005: 'access violation',
    0xC00000FD: 'stack overflow',
    0xC0000409: 'stack buffer overrun / fail fast (abort)',
    0xC000001D: 'illegal instruction',
    0xC0000374: 'heap corruption',
    0xC0000094: 'integer divide by zero',
    0x80000003: 'breakpoint',
}


def masked(s):
    for rx, rep in MASK:
        s = rx.sub(rep, s)
    return s


def pkg_name(package_id):
    """`path+file:///…/sha3#nextssl-algo-sha3@0.0.1` or `nextssl-algo-sha3 0.0.1 (path+…)` -> name."""
    m = re.search(r'#([\w.-]+)@', package_id)
    if m:
        return m.group(1)
    m = re.search(r'#([\w.-]+)$', package_id)
    if m and not re.match(r'^\d', m.group(1)):
        return m.group(1)
    if '#' in package_id:  # `…/dir/<name>#0.0.1`: name is the last path element
        return package_id.split('#')[0].rstrip('/').split('/')[-1]
    return package_id.split(' ')[0]


# ---------------------------------------------------------------------------------------------- build

def build(cargo, args, log, timings, extra_env=None):
    cmd = shlex.split(cargo) + ['build', '--tests', '--keep-going', '--message-format=json-render-diagnostics']
    if timings:
        cmd.append('--timings')
    cmd += args
    shown = ' '.join(cmd)
    print('[testrun] build:', shown if len(shown) < 600 else shown[:600] + f' … ({len(args)} arguments)', flush=True)
    log.write('### build: ' + shown + '\n')
    env = dict(os.environ, CARGO_TERM_COLOR='never', **(extra_env or {}))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    binaries = []
    errors = collections.OrderedDict()
    stderr_lines = []

    def pump_stderr():
        for raw in p.stderr:
            text = ANSI.sub('', raw.decode('utf-8', 'replace').rstrip('\r\n'))
            sys.stderr.write(text + '\n')
            stderr_lines.append(text)

    t = threading.Thread(target=pump_stderr, daemon=True)
    t.start()
    for raw in p.stdout:
        line = raw.decode('utf-8', 'replace').strip()
        if not line.startswith('{'):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        reason = msg.get('reason')
        if reason == 'compiler-artifact' and msg.get('profile', {}).get('test') and msg.get('executable'):
            binaries.append({
                'crate': pkg_name(msg['package_id']),
                'target': msg['target']['name'],
                'kind': msg['target']['kind'][0],
                'exe': msg['executable'],
                'dir': os.path.dirname(msg['manifest_path']),
            })
        elif reason == 'compiler-message' and msg.get('message', {}).get('level') == 'error':
            text = (msg['message'].get('rendered') or msg['message'].get('message') or '').strip()
            first = text.splitlines()[0] if text else 'error'
            errors.setdefault(pkg_name(msg['package_id']), []).append(('compile', first))
    rc = p.wait()
    t.join()
    for line in stderr_lines:
        log.write(line + '\n')
        m = COULD_NOT.match(line) or BUILD_SCRIPT.match(line)
        if m and m.group(1) not in errors:
            errors[m.group(1)] = [('compile', line.strip())]
    # A build script failure has no compiler-message; keep the panic/error lines it printed.
    for crate in list(errors):
        if errors[crate] and errors[crate][0][1].startswith('error: failed to run custom build'):
            extra = [x.strip() for x in stderr_lines if crate in x and ('panicked' in x or 'error' in x)]
            errors[crate] += [('compile', x) for x in extra[:3]]
    return rc, binaries, errors


# ---------------------------------------------------------------------------------------------- shards

def load_weights(path):
    """tools/ci_weights.tsv -> ({crate: build seconds}, {(crate, test): seconds}); empty when absent."""
    build_w, test_w = {}, {}
    if not path or not os.path.exists(path):
        return build_w, test_w
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            kind, crate, test, secs = line.rstrip('\n').split('\t')
            if kind == 'build':
                build_w[crate] = float(secs)
            elif kind == 'test':
                test_w[(crate, test)] = float(secs)
    return build_w, test_w


def cargo_metadata(cargo):
    out = subprocess.run(shlex.split(cargo) + ['metadata', '--no-deps', '--format-version', '1'],
                         capture_output=True, check=True).stdout
    return json.loads(out)


def workspace_members(cargo, excluded, meta=None):
    meta = meta or cargo_metadata(cargo)
    members = set(meta['workspace_members'])
    return sorted(p['name'] for p in meta['packages'] if p['id'] in members and p['name'] not in excluded)


# ---------------------------------------------------------------------------------------------- result cache
#
# --result-cache DIR: a crate whose inputs are bit for bit the same as in an earlier run where it
# compiled (clippy included) and every one of its tests passed is not built or run again; the report
# lists it as "cached". The key of a crate is a SHA-256 over
#   * the content of every file of its own directory tree and of every path dependency, transitively
#     (an algorithm's whole family directory algos/<kind>/<family>/, so sibling parameter sets that
#     share sources are covered),
#   * the files every crate can read: third_party/, docker/, Cargo.toml, Cargo.lock,
#     rust-toolchain.toml, .cargo/, tools/testrun.py,
#   * the toolchain (rustc -vV, cc/c++ --version, runner image, Docker image id), every environment
#     variable a build can read (CC*, CXX*, AR*, *FLAGS*, CARGO_*, RUST*, NEXTSSL_* except paths) and
#     the testrun options (cargo command, runner, limits, clippy, features).
# Anything else changes the key, and a crate whose key is new is built and tested in full.
# --result-cache-write-only records results without skipping anything (the scheduled full run).

GLOBAL_INPUTS = ['third_party', 'docker', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo',
                 'tools/testrun.py']
KEY_ENV = re.compile(r'^(CC|CXX|AR|CFLAGS|CXXFLAGS|RUSTFLAGS|RUSTDOCFLAGS|CARGO_|RUST|NEXTSSL_|TARGET_|HOST_|'
                     r'SMOKE_|ASAN_|UBSAN_|LSAN_|MSAN_|MIRI|WASMTIME|ImageOS$|ImageVersion$|RUNNER_OS$|'
                     r'RUNNER_ARCH$|MACOSX_|SDKROOT$)')
KEY_ENV_SKIP = {'CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTUP_HOME', 'NEXTSSL_C_CACHE', 'NEXTSSL_REPORT_DIR',
                'NEXTSSL_RESULT_CACHE', 'NEXTSSL_RESULT_CACHE_WRITE_ONLY', 'NEXTSSL_SHARD', 'CARGO_TERM_COLOR'}


def tree_digest(path, memo):
    """SHA-256 over the relative path and content of every file below `path` (or of the file)."""
    path = os.path.normpath(path)
    if path in memo:
        return memo[path]
    import hashlib
    h = hashlib.sha256()
    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for root, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in ('target', '.git'))
            files += [os.path.join(root, n) for n in sorted(names)]
    for f in files:
        h.update(os.path.relpath(f, path).replace(os.sep, '/').encode() + b'\0')
        with open(f, 'rb') as fh:
            h.update(hashlib.sha256(fh.read()).digest())
    memo[path] = h.hexdigest()
    return memo[path]


def tool_version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ''


def result_keys(cargo, meta, names, options):
    """{crate: key} for `names` (see the result cache comment above)."""
    import hashlib
    root = meta['workspace_root']
    by_name = {p['name']: p for p in meta['packages']}
    by_dir = {os.path.normpath(os.path.dirname(p['manifest_path'])): p for p in meta['packages']}
    algos = os.path.normpath(os.path.join(root, 'algos'))

    def unit_dir(d):
        """An algorithm crate is keyed by its family directory (algos/<kind>/<family>)."""
        d = os.path.normpath(d)
        rel = os.path.relpath(d, algos)
        if not rel.startswith('..') and len(rel.split(os.sep)) >= 3:
            return os.path.join(algos, *rel.split(os.sep)[:2])
        return d

    memo = {}
    toolchain = [x for x in shlex.split(cargo)[1:] if x.startswith('+')]
    common = hashlib.sha256()
    for g in GLOBAL_INPUTS:
        p = os.path.join(root, g)
        if os.path.exists(p):
            common.update(f'{g}={tree_digest(p, memo)}\n'.encode())
    common.update(tool_version(['rustc'] + toolchain + ['-vV']).encode())
    for c in ('cc', 'c++', 'clang', 'clang-cl'):
        common.update(tool_version([c, '--version']).encode())
    for k in sorted(os.environ):
        if KEY_ENV.match(k) and k not in KEY_ENV_SKIP:
            common.update(f'{k}={os.environ[k]}\n'.encode())
    common.update(json.dumps(options, sort_keys=True).encode())
    common = common.hexdigest()

    closure = {}

    def dirs_of(pkg):
        name = pkg['name']
        if name in closure:
            return closure[name]
        closure[name] = set()  # cycle guard (dev-dependencies)
        out = {unit_dir(os.path.dirname(pkg['manifest_path']))}
        for dep in pkg.get('dependencies', []):
            p = dep.get('path')
            if not p:
                continue
            sub = by_dir.get(os.path.normpath(p))
            if sub is not None:
                out |= dirs_of(sub)
            else:
                out.add(unit_dir(p))
        closure[name] = out
        return out

    keys = {}
    for n in names:
        h = hashlib.sha256(common.encode())
        for d in sorted(dirs_of(by_name[n])):
            h.update(f'{os.path.relpath(d, root)}={tree_digest(d, memo)}\n'.encode())
        keys[n] = h.hexdigest()
    return keys


def cache_file(cache_dir, crate):
    return os.path.join(cache_dir, crate + '.pass')


def cached_pass(cache_dir, crate, key):
    try:
        with open(cache_file(cache_dir, crate), encoding='utf-8') as f:
            return f.readline().strip() == key
    except OSError:
        return False


def shard_packages(names, k, n, build_w, test_w):
    """Split the workspace into n shards of about equal expected time; return shard k's packages.

    Every crate that is not an algorithm (registry, ffi, root, ...) links the whole catalog, so they all
    go to shard 1, whose load starts with the build of every algorithm library. The algorithms are then
    placed greedily, heaviest first, on the least loaded shard. A crate missing from the weights gets
    the median weight, so a new algorithm is always placed. Deterministic for the same inputs."""
    per_test = collections.Counter()
    for (crate, _), s in test_w.items():
        per_test[crate] += s
    def weight(c):
        return build_w.get(c, med) + per_test.get(c, 0.0)
    known = sorted(build_w.get(c, 0.0) + per_test.get(c, 0.0) for c in names if c in build_w)
    med = known[len(known) // 2] if known else 1.0
    algos = [c for c in names if c.startswith('nextssl-algo-')]
    others = [c for c in names if not c.startswith('nextssl-algo-')]
    loads = [0.0] * n
    bins = [[] for _ in range(n)]
    bins[0] = list(others)
    loads[0] = sum(weight(c) for c in others) + sum(build_w.get(c, med) for c in algos)
    for c in sorted(algos, key=lambda c: (-weight(c), c)):
        i = min(range(n), key=lambda j: (loads[j], j))
        bins[i].append(c)
        loads[i] += weight(c)
    return sorted(bins[k - 1]), loads


def clippy_env(cargo):
    """RUSTC_WORKSPACE_WRAPPER=clippy-driver: the same compile that builds the tests also runs clippy
    on every workspace crate, with warnings as errors (as `cargo clippy -- -D warnings`)."""
    toolchain = [a[1:] for a in shlex.split(cargo)[1:] if a.startswith('+')]
    cmd = ['rustup', 'which'] + (['--toolchain', toolchain[0]] if toolchain else []) + ['clippy-driver']
    driver = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
    return {'RUSTC_WORKSPACE_WRAPPER': driver, 'CLIPPY_ARGS': '-D__CLIPPY_HACKERY__warnings__CLIPPY_HACKERY__'}


# ---------------------------------------------------------------------------------------------- run

def run_proc(cmd, cwd, env, timeout):
    """Run one process; returns (rc, output, seconds, timed_out). Kills the whole process group on timeout."""
    t0 = time.time()
    kw = {}
    if os.name == 'posix':
        kw['start_new_session'] = True
    else:
        kw['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, **kw)
    except OSError as e:
        return -1, f'could not start: {e}', 0.0, False
    try:
        out, _ = p.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == 'posix':
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
        else:
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)], capture_output=True)
        p.kill()
        out, _ = p.communicate()
    text = ANSI.sub('', out.decode('utf-8', 'replace')).replace('\r\n', '\n')
    return p.returncode, text, time.time() - t0, timed_out


def env_for(b):
    env = dict(os.environ, CARGO_MANIFEST_DIR=b['dir'], CARGO_PKG_NAME=b['crate'], RUST_BACKTRACE='0')
    return env


def list_tests(b, runner, timeout):
    rc, out, _, timed_out = run_proc(runner + [b['exe'], '--list', '--format', 'terse'], b['dir'], env_for(b), timeout)
    if rc != 0 or timed_out:
        return None, out
    names = [ln[:-len(': test')] for ln in out.splitlines() if ln.endswith(': test')]
    return names, out


def exit_issue(rc, timed_out, timeout):
    if timed_out:
        return ('hang', f'killed after {timeout} s (no result)')
    if rc is None:
        return None
    if rc < 0 and os.name == 'posix':
        try:
            name = signal.Signals(-rc).name
        except ValueError:
            name = str(-rc)
        return ('crash', f'signal {-rc} ({name})')
    code = rc & 0xFFFFFFFF
    if code in NTSTATUS:
        return ('crash', f'exit 0x{code:08X} ({NTSTATUS[code]})')
    if rc >= 128 + 1 and rc <= 128 + 64:
        # wasmtime / shells report a signal as 128 + n.
        return ('crash', f'exit status {rc} (signal {rc - 128})')
    if rc not in (0, 101):
        return ('crash', f'exit status {rc}')
    return None


def issues_of(lines, rc, timed_out, timeout, ran_one):
    out = []
    for i, line in enumerate(lines):
        m = PANIC.match(line)
        if m:
            msg = lines[i + 1].strip() if i + 1 < len(lines) else ''
            out.append(('panic', f'panicked at {m.group(2)}:{m.group(3)}: {msg}'))
            continue
        m = OVERFLOW.match(line)
        if m:
            out.append(('stack-overflow', 'stack overflow'))
            continue
        m = SAN_ERR.match(line)
        if m:
            where = ''
            for f in lines[i + 1:i + 40]:
                fm = FRAME.match(f)
                if fm and ('nextssl' in fm.group(1) or '/algos/' in fm.group(2)):
                    where = f' in {fm.group(1)} {fm.group(2)}'
                    break
            out.append(('sanitizer', f'{m.group(1)}: {m.group(2)}{where}'))
            continue
        m = SAN_SUM.match(line)
        if m:
            # UBSan's summary repeats its runtime-error line (listed below); keep the others.
            if m.group(1) != 'UndefinedBehaviorSanitizer':
                out.append(('sanitizer', f'SUMMARY {m.group(1)}: {m.group(2)}'))
            continue
        m = UBSAN.search(line)
        if m:
            out.append(('sanitizer', f'UBSan at {m.group(1)}: {m.group(2)}'))
    e = exit_issue(rc, timed_out, timeout)
    if e:
        out.append(e)
    if not out and rc == 0 and not timed_out and not ran_one:
        out.append(('failed', 'the test filter matched no test (binary out of date?)'))
    if not out and (rc != 0 or timed_out):
        out.append(('failed', f'test failed, exit status {rc} (see test-full.log)'))
    return out


def fold(issues, cap):
    seen = collections.OrderedDict()
    for kind, text in issues:
        key = (kind, masked(text))
        if key in seen:
            seen[key]['count'] += 1
        else:
            seen[key] = {'kind': kind, 'text': text, 'count': 1}
    distinct = list(seen.values())
    return distinct[:cap], max(0, len(distinct) - cap), len(issues)


# ---------------------------------------------------------------------------------------------- report

def markdown(r):
    status = 'PASS' if r['ok'] else 'FAIL'
    out = [
        f'## Test report: {status}',
        '',
        f"build `{r['build_command']}` exit status {r['build_exit_status']}; {r['seconds']} s in total "
        f"(build {r['build_seconds']} s, tests {r['test_seconds']} s, {r['jobs']} at a time, limit {r['timeout']} s per test)",
        '',
        '| test binaries | tests run | passed | failed | hung | crates not compiled | failing crates |',
        '|---|---|---|---|---|---|---|',
        f"| {r['test_binaries']} | {r['tests_run']} | {r['tests_passed']} | {r['tests_failed']} | {r['tests_hung']} "
        f"| {r['crates_not_compiled']} | {r['failing_crates']} |",
        '',
    ]
    if r.get('crates_cached'):
        out += [f"{r['crates_cached']} crate(s) not built or run: their inputs are bit for bit those of an "
                'earlier run where they compiled and every test passed (tools/testrun.py --result-cache).', '']
    if r['failing_crates_by_kind']:
        out += ['| kind | crates |', '|---|---|']
        out += [f'| {k} | {n} |' for k, n in r['failing_crates_by_kind'].items()]
        out.append('')
    if r['build_exit_status'] != 0 and not r['crates_not_compiled']:
        out += ['The build failed but no crate was named; read test-full.log.', '']
    for a in r['failures']:
        tests = ', '.join(a['tests'][:5]) + (' …' if len(a['tests']) > 5 else '')
        out.append(f"### {a['crate']}" + (f' ({tests})' if tests else ''))
        for i in a['issues']:
            times = f" (x{i['count']})" if i['count'] > 1 else ''
            text = i['text'][:400].replace('`', "'")
            out.append(f"- **{i['kind']}**{times}: `{text}`")
        if a['distinct_not_shown']:
            out.append(f"- … {a['distinct_not_shown']} more distinct issue(s) not shown (cap {r['max_issues_per_algo']})")
        out.append('')
    if r['slowest']:
        out += ['### Slowest tests', '', '| seconds | crate | test |', '|---|---|---|']
        out += [f"| {s['seconds']} | {s['crate']} | {s['test']} |" for s in r['slowest']]
        out.append('')
    return '\n'.join(out) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', default='test-report')
    ap.add_argument('--jobs', type=int, default=os.cpu_count() or 2, help='tests run at the same time')
    ap.add_argument('--timeout', type=int, default=600, help='seconds one test may run before it is killed')
    ap.add_argument('--crate-timeout', action='append', default=[], metavar='CRATE=SECONDS',
                    help='a different limit for every test of one crate (e.g. the registry smoke, which '
                         'walks the whole catalog in one test); may be repeated')
    ap.add_argument('--max-per-algo', type=int, default=5)
    ap.add_argument('--cargo', default='cargo', help='cargo command, e.g. "cargo +nightly"')
    ap.add_argument('--runner', default='', help='prefix for every test binary, e.g. "wasmtime run --dir=/src"')
    ap.add_argument('--timings', action='store_true', help='cargo --timings; the HTML report is copied to --out')
    ap.add_argument('--rerun-failed', metavar='JSON', help='run only the crates that failed in this report')
    ap.add_argument('--shard', metavar='K/N', help='build and test only shard K of N (see shard_packages)')
    ap.add_argument('--weights', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ci_weights.tsv'),
                    help='build and test seconds per crate/test (tools/ci_weights.py): shard balance, test order')
    ap.add_argument('--clippy', action='store_true', help='run clippy -D warnings in the same compile')
    ap.add_argument('--umbrella-features', default='',
                    help='cargo features enabled whenever the non-algorithm crates are built, e.g. '
                         'nextssl-registry/copyleft,nextssl-registry/all-heavy')
    ap.add_argument('--result-cache', metavar='DIR', help='skip crates whose inputs passed before (see above)')
    ap.add_argument('--result-cache-write-only', action='store_true',
                    help='with --result-cache: run everything, only record the passes')
    ap.add_argument('cargo_args', nargs=argparse.REMAINDER, help='-- arguments for cargo build')
    a = ap.parse_args()
    args = a.cargo_args[1:] if a.cargo_args[:1] == ['--'] else a.cargo_args
    if not args:
        args = ['--workspace']
    if a.rerun_failed:
        prev = json.load(open(a.rerun_failed, encoding='utf-8'))
        crates = [f['crate'] for f in prev['failures'] if not f['crate'].startswith('(')]
        args = [x for x in args if x != '--workspace']
        for c in crates:
            args += ['-p', c]
    build_w, test_w = load_weights(a.weights)
    limits = {}
    for item in a.crate_timeout:
        crate, _, secs = item.partition('=')
        if not crate or not secs.isdigit():
            ap.error(f'--crate-timeout {item!r}: expected CRATE=SECONDS')
        limits[crate] = int(secs)
    umbrella = '--workspace' in args
    excluded = {args[i + 1] for i, x in enumerate(args[:-1]) if x == '--exclude'}
    rest = []
    skip = False
    for x in args:
        if skip:
            skip = False
        elif x == '--exclude':
            skip = True
        elif x != '--workspace':
            rest.append(x)
    pkgs = None
    meta = None
    if a.shard:
        m = re.fullmatch(r'(\d+)/(\d+)', a.shard)
        if not m or not 1 <= int(m.group(1)) <= int(m.group(2)):
            ap.error('--shard expects K/N with 1 <= K <= N')
        k, n = int(m.group(1)), int(m.group(2))
        meta = cargo_metadata(a.cargo)
        names = workspace_members(a.cargo, excluded, meta)
        pkgs, loads = shard_packages(names, k, n, build_w, test_w)
        print(f'[testrun] shard {k}/{n}: {len(pkgs)} of {len(names)} packages; expected load per shard (s): '
              + ', '.join(f'{x:.0f}' for x in loads), flush=True)
        umbrella = k == 1
    elif a.result_cache and '--workspace' in args and not a.rerun_failed:
        meta = cargo_metadata(a.cargo)
        pkgs = workspace_members(a.cargo, excluded, meta)
    keys, cached = {}, []
    if a.result_cache and pkgs is not None:
        os.makedirs(a.result_cache, exist_ok=True)
        options = {'cargo': a.cargo, 'runner': a.runner, 'timeout': a.timeout, 'limits': limits,
                   'clippy': a.clippy, 'umbrella': a.umbrella_features, 'args': rest}
        t_key = time.time()
        keys = result_keys(a.cargo, meta, pkgs, options)
        if not a.result_cache_write_only:
            cached = [p for p in pkgs if cached_pass(a.result_cache, p, keys[p])]
            pkgs = [p for p in pkgs if p not in set(cached)]
        print(f'[testrun] result cache: {len(cached)} crate(s) unchanged since a passing run, '
              f'{len(pkgs)} to build and test ({time.time() - t_key:.0f} s to hash the inputs)', flush=True)
    if pkgs is not None:
        chunks = [pkgs] if pkgs else []
        # Windows limits a command line to 32767 characters: split very long package lists.
        while chunks and sum(len(p) + 4 for p in chunks[-1]) > 28000:
            last = chunks.pop()
            chunks += [last[:len(last) // 2], last[len(last) // 2:]]
        arg_sets = [rest + [y for p in c for y in ('-p', p)] for c in chunks]
    else:
        arg_sets = [args]
    if a.umbrella_features and umbrella:
        feats = [f for f in a.umbrella_features.split(',') if f]
        # The crates above the registry gate the same algorithms with their own features (root's
        # generated modules, the ffi table): enable them together, or the registry lists algorithms
        # the root does not (run 45377985234: "registry and generated root modules differ").
        if 'nextssl-registry/copyleft' in feats:
            feats += ['nextssl/copyleft', 'nextssl-root/copyleft', 'nextssl-ffi/copyleft']
        if 'nextssl-registry/all-heavy' in feats:
            feats += ['nextssl-root/all-heavy', 'nextssl-ffi/all-heavy']
        feats = list(dict.fromkeys(feats))
        # A long shard is split into several cargo calls, and cargo rejects a feature of a package
        # that call does not select (run 45393949691, wasm 1/2): each call gets the features of its
        # own packages. A --workspace call selects every package.
        for i, s in enumerate(arg_sets):
            if '--workspace' in s:
                mine = feats
            else:
                sel = {s[j + 1] for j, x in enumerate(s[:-1]) if x == '-p'}
                mine = [f for f in feats if f.split('/')[0] in sel]
            if mine:
                arg_sets[i] = s + ['--features', ','.join(mine)]
    extra_env = clippy_env(a.cargo) if a.clippy else None
    runner = shlex.split(a.runner)
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    log = open(os.path.join(a.out, 'test-full.log'), 'w', encoding='utf-8', newline='\n')

    brc, binaries, compile_errs = 0, [], collections.OrderedDict()
    for argv in arg_sets:
        rc, bins, errs = build(a.cargo, argv, log, a.timings, extra_env)
        brc = brc or rc
        binaries += bins
        for c, e in errs.items():
            compile_errs.setdefault(c, []).extend(e)
    t_build = time.time() - t0
    if a.timings:
        for root, _, files in os.walk(os.environ.get('CARGO_TARGET_DIR', 'target')):
            if 'cargo-timing.html' in files:
                import shutil
                shutil.copy(os.path.join(root, 'cargo-timing.html'), os.path.join(a.out, 'cargo-timing.html'))
                break
    print(f'[testrun] build exit {brc} in {t_build:.0f} s: {len(binaries)} test binaries, '
          f'{len(compile_errs)} crate(s) did not compile', flush=True)

    # List every binary's tests (in parallel; listing is cheap but wasm start-up is not).
    jobs = []
    per = collections.OrderedDict((c, list(e)) for c, e in compile_errs.items())
    failed_tests = collections.defaultdict(list)
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        listed = list(ex.map(lambda b: (b, list_tests(b, runner, 300)), binaries))
    for b, (names, out) in listed:
        if names is None:
            per.setdefault(b['crate'], []).append(('crash', f"{b['target']} ({b['kind']}): listing the tests failed"))
            log.write(f"### list {b['crate']} {b['exe']}\n{out}\n")
            continue
        for n in names:
            jobs.append((b, n))
    # Longest first (times from the weights file), so a slow signature test does not start last and
    # hold the run alone at the end. Unknown tests count as slow and also start early.
    known = sorted(test_w.values())
    slow = known[int(len(known) * 0.9)] if known else 0.0
    jobs.sort(key=lambda j: -test_w.get((j[0]['crate'], j[1]), slow))
    print(f'[testrun] {len(jobs)} tests in {len(binaries)} binaries; running {a.jobs} at a time, '
          f'limit {a.timeout} s each', flush=True)

    t1 = time.time()
    times = []
    counts = collections.Counter()
    lock = threading.Lock()
    done = [0]

    def one(job):
        b, name = job
        cmd = runner + [b['exe'], '--exact', name, '--test-threads', '1', '--nocapture']
        limit = limits.get(b['crate'], a.timeout)
        rc, out, secs, timed_out = run_proc(cmd, b['dir'], env_for(b), limit)
        lines = out.splitlines()
        ran_one = any(re.match(r'^test result: ok\. 1 passed', ln) for ln in lines)
        # A sanitizer that recovers (the ASan layer) lets the test pass; any report still fails it.
        reported = 'runtime error:' in out or 'Sanitizer:' in out
        iss = [] if (rc == 0 and not timed_out and ran_one and not reported) else issues_of(lines, rc, timed_out, limit, ran_one)
        with lock:
            done[0] += 1
            times.append((secs, b['crate'], name))
            if iss:
                kind = 'hung' if timed_out else 'failed'
                counts[kind] += 1
                per.setdefault(b['crate'], []).extend(iss)
                failed_tests[b['crate']].append(name)
                log.write(f"### {b['crate']} :: {name} ({b['target']}) exit {rc}{' TIMEOUT' if timed_out else ''} {secs:.1f} s\n")
                log.write(out[-200_000:] + '\n')
                print(f"[testrun] FAIL {b['crate']} :: {name}: {iss[0][0]}: {iss[0][1][:160]}", flush=True)
            else:
                counts['passed'] += 1
            if done[0] % 200 == 0:
                print(f"[testrun] {done[0]}/{len(jobs)} done ({counts['passed']} passed) "
                      f"{time.time() - t1:.0f} s", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        list(ex.map(one, jobs))
    t_test = time.time() - t1

    failures = []
    kinds = collections.Counter()
    for crate, iss in per.items():
        kept, dropped, total = fold(iss, a.max_per_algo)
        for k in {i['kind'] for i in kept}:
            kinds[k] += 1
        failures.append({'crate': crate, 'tests': failed_tests.get(crate, []), 'issues': kept,
                         'distinct_not_shown': dropped, 'raw_issues': total})
    failures.sort(key=lambda f: f['crate'])
    times.sort(reverse=True)
    # Record the passes: a crate that produced test binaries, has no issue of any kind, and whose build
    # either succeeded or failed only in crates that are named (an unexplained build failure records nothing).
    recorded = 0
    if keys and (brc == 0 or compile_errs):
        built = {b['crate'] for b in binaries}
        bad = {f['crate'] for f in failures}
        run_id = os.environ.get('GITHUB_RUN_ID', 'local')
        for p in pkgs:
            if p in built and p not in bad:
                with open(cache_file(a.result_cache, p), 'w', encoding='utf-8', newline='\n') as f:
                    f.write(f'{keys[p]}\nrun {run_id} {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}\n')
                recorded += 1
            elif os.path.exists(cache_file(a.result_cache, p)):
                os.remove(cache_file(a.result_cache, p))
        print(f'[testrun] result cache: recorded {recorded} passing crate(s)', flush=True)
    r = {
        'build_command': ' '.join([a.cargo, 'build', '--tests', '--keep-going'] + args),
        'build_exit_status': brc,
        'seconds': round(time.time() - t0),
        'build_seconds': round(t_build),
        'test_seconds': round(t_test),
        'jobs': a.jobs,
        'timeout': a.timeout,
        'test_binaries': len(binaries),
        'tests_run': len(jobs),
        'tests_passed': counts['passed'],
        'tests_failed': counts['failed'],
        'tests_hung': counts['hung'],
        'crates_not_compiled': len(compile_errs),
        'failing_crates': len(failures),
        'failing_crates_by_kind': dict(kinds.most_common()),
        'crates_cached': len(cached),
        'cached_crates': cached,
        'max_issues_per_algo': a.max_per_algo,
        'failures': failures,
        'slowest': [{'seconds': round(s, 1), 'crate': c, 'test': n} for s, c, n in times[:30]],
    }
    r['ok'] = brc == 0 and not failures and r['tests_passed'] == r['tests_run']
    log.close()
    md = markdown(r)
    with open(os.path.join(a.out, 'test-summary.md'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(md)
    with open(os.path.join(a.out, 'test-failures.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(r, f, indent=1, ensure_ascii=False)
    with open(os.path.join(a.out, 'test-times.tsv'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('seconds\tcrate\ttest\n')
        for s, c, n in times:
            f.write(f'{s:.2f}\t{c}\t{n}\n')
    step = os.environ.get('GITHUB_STEP_SUMMARY')
    if step:
        with open(step, 'a', encoding='utf-8') as f:
            f.write(md if len(md) < 900_000 else md[:900_000] + '\n… truncated; see the test-report artifact\n')
    print(f"[testrun] {r['tests_run']} tests: {r['tests_passed']} passed, {r['tests_failed']} failed, "
          f"{r['tests_hung']} hung; {r['crates_not_compiled']} crate(s) not compiled; "
          f"{r['failing_crates']} failing crate(s); build {r['build_seconds']} s, tests {r['test_seconds']} s; "
          f"report in {a.out}", flush=True)
    return 0 if r['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
