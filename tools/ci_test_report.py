#!/usr/bin/env python3
"""Run a test command to the end and write a per-algorithm failure report.

    python3 tools/ci_test_report.py --out test-report -- cargo test --workspace --no-fail-fast

The command runs unchanged; its output goes to the console and to <out>/test-full.log. The log is then
split per test binary (cargo's "Running ..." lines) and every failing binary is reduced to its distinct
issues: panics (location + message), crashes (exit code / signal), sanitizer reports, compile errors.
Duplicates are folded (addresses, thread ids and hex values are masked before comparing) and at most
--max-per-algo distinct issues are kept per algorithm, with a count of what was left out.

Outputs in --out:
  test-summary.md     totals, failures by kind, one section per failing algorithm
  test-failures.json  the same data for tools
  test-full.log       the complete output (ANSI colours removed)
The summary is also appended to $GITHUB_STEP_SUMMARY when that is set. The exit status is the command's
own exit status, so a CI step still fails when a test fails. Standard library only.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import time

ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
# GitHub's log timestamps, when a downloaded CI log is fed back in with --from-log.
STAMP = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z ')
RUNNING = re.compile(r'^\s*Running (?:unittests )?(\S+) \((.+)\)\s*$')
RERUN = re.compile(r'error: test failed, to rerun pass `-p ([\w.-]+)')
PANIC = re.compile(r"^thread '([^']*)'(?: \(\d+\))? panicked at (.+?):(\d+):\d+:$")
OVERFLOW = re.compile(r"^thread '([^']*)'(?: \(\d+\))? has overflowed its stack")
EXIT = re.compile(r"process didn't exit successfully: .*\((exit (?:code|status): [^)]+|signal: [^)]+)\)")
SAN_ERR = re.compile(r'^(?:==\d+==)?ERROR: (AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer): (.*)$')
SAN_SUM = re.compile(r'^SUMMARY: (\w+Sanitizer): (.*)$')
UBSAN = re.compile(r'^(\S+:\d+:\d+): runtime error: (.*)$')
FRAME = re.compile(r'^\s*#\d+ 0x[0-9a-f]+ in (\S+) (\S+)')
COMPILE = re.compile(r'^error(?:\[E\d+\])?: (.*)$')
COMPILE_CRATE = re.compile(r'^error: could not compile `([\w.-]+)`')
RESULT = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed')
MASK = [
    (re.compile(r'0x[0-9a-fA-F]+'), '0x…'),
    (re.compile(r'==\d+=='), '==…=='),
    (re.compile(r'\(\d+\)'), '(…)'),
    (re.compile(r'\b[0-9a-f]{16}\b'), '…'),
    (re.compile(r'\d+ byte\(s\)'), 'N byte(s)'),
    (re.compile(r'in \d+ (allocation|object)'), r'in N \1'),
]


def crate_of_binary(path):
    """nextssl_algo_3des-a357bea95dd7cf76(.exe) -> nextssl-algo-3des (best effort; `-p` names win)."""
    name = re.split(r'[\\/]', path)[-1]
    name = re.sub(r'\.exe$', '', name)
    name = re.sub(r'-[0-9a-f]{16}$', '', name)
    return name.replace('_', '-')


def masked(s):
    for rx, rep in MASK:
        s = rx.sub(rep, s)
    return s


class Segment:
    def __init__(self, crate, what):
        self.crate = crate
        self.what = what
        self.lines = []
        self.failed = False


def split(lines):
    """Split the log into per-binary segments; text before the first binary is the build phase."""
    segs = [Segment('(build)', 'build')]
    for line in lines:
        m = RUNNING.match(line)
        if m:
            segs.append(Segment(crate_of_binary(m.group(2)), m.group(1)))
            continue
        seg = segs[-1]
        seg.lines.append(line)
        m = RERUN.search(line)
        if m:
            seg.crate = m.group(1)
            seg.failed = True
        r = RESULT.match(line)
        if r and r.group(1) == 'FAILED':
            seg.failed = True
    return segs


def issues_of(seg):
    """Distinct issues of one segment, as (kind, text) in first-seen order."""
    out = []
    L = seg.lines
    for i, line in enumerate(L):
        m = PANIC.match(line)
        if m:
            msg = L[i + 1].strip() if i + 1 < len(L) else ''
            out.append(('panic', f'{m.group(1)}: panicked at {m.group(2)}:{m.group(3)}: {msg}'))
            continue
        m = OVERFLOW.match(line)
        if m:
            out.append(('stack-overflow', f'{m.group(1)}: stack overflow'))
            continue
        m = EXIT.search(line)
        if m:
            out.append(('crash', m.group(1)))
            continue
        m = SAN_ERR.match(line)
        if m:
            # The first frame inside our code or the upstream says where it happened.
            where = ''
            for f in L[i + 1:i + 40]:
                fm = FRAME.match(f)
                if fm and ('nextssl' in fm.group(1) or '/algos/' in fm.group(2)):
                    where = f' in {fm.group(1)} {fm.group(2)}'
                    break
            out.append(('sanitizer', f'{m.group(1)}: {m.group(2)}{where}'))
            continue
        m = SAN_SUM.match(line)
        if m:
            out.append(('sanitizer', f'SUMMARY {m.group(1)}: {m.group(2)}'))
            continue
        m = UBSAN.match(line)
        if m:
            out.append(('sanitizer', f'UBSan at {m.group(1)}: {m.group(2)}'))
            continue
    if seg.failed and not out:
        out.append(('failed', 'test failed (no panic, crash or sanitizer line found; see test-full.log)'))
    return out


def compile_errors(seg):
    """Per-crate compile errors from the build phase: the error lines before each `could not compile`."""
    per = collections.OrderedDict()
    pending = []
    for line in seg.lines:
        m = COMPILE_CRATE.match(line)
        if m:
            per.setdefault(m.group(1), []).extend(pending or [('compile', line.strip())])
            pending = []
            continue
        m = COMPILE.match(line)
        if m and not line.startswith('error: test failed') and 'aborting due to' not in line:
            pending.append(('compile', m.group(1).strip()))
    if pending:
        per.setdefault('(unattributed)', []).extend(pending)
    return per


def fold(issues, cap):
    """Fold duplicates (after masking) and keep at most `cap` distinct issues."""
    seen = collections.OrderedDict()
    for kind, text in issues:
        key = (kind, masked(text))
        if key in seen:
            seen[key]['count'] += 1
        else:
            seen[key] = {'kind': kind, 'text': text, 'count': 1}
    distinct = list(seen.values())
    return distinct[:cap], max(0, len(distinct) - cap), len(issues)


def report(lines, rc, cap, cmd, secs):
    segs = split(lines)
    per = collections.OrderedDict()
    for crate, iss in compile_errors(segs[0]).items():
        per.setdefault(crate, []).extend(iss)
    # Totals over the whole log: they do not depend on which segment a line landed in.
    passed_tests = failed_tests = 0
    for line in lines:
        r = RESULT.match(line)
        if r:
            passed_tests += int(r.group(2))
            failed_tests += int(r.group(3))
    binaries = len(segs) - 1
    for seg in segs[1:]:
        iss = issues_of(seg)
        if seg.failed or iss:
            per.setdefault(seg.crate, []).extend(iss)
    algos = []
    kinds = collections.Counter()
    for crate, iss in per.items():
        kept, dropped, total = fold(iss, cap)
        for k in {i['kind'] for i in kept}:
            kinds[k] += 1
        algos.append({'crate': crate, 'issues': kept, 'distinct_not_shown': dropped, 'raw_issue_lines': total})
    return {
        'command': cmd,
        'exit_status': rc,
        'seconds': round(secs),
        'test_binaries_run': binaries,
        'tests_passed': passed_tests,
        'tests_failed': failed_tests,
        'failing_crates': len(algos),
        'failing_crates_by_kind': dict(kinds.most_common()),
        'max_issues_per_algo': cap,
        'failures': algos,
    }


def markdown(r):
    out = [
        f"## Test report: {'PASS' if r['exit_status'] == 0 and not r['failures'] else 'FAIL'}",
        '',
        f"`{r['command']}` exit status {r['exit_status']}, {r['seconds']} s",
        '',
        '| test binaries run | tests passed | tests failed | failing crates |',
        '|---|---|---|---|',
        f"| {r['test_binaries_run']} | {r['tests_passed']} | {r['tests_failed']} | {r['failing_crates']} |",
        '',
    ]
    if r['failing_crates_by_kind']:
        out += ['| kind | crates |', '|---|---|']
        out += [f'| {k} | {n} |' for k, n in r['failing_crates_by_kind'].items()]
        out.append('')
    if r['exit_status'] != 0 and not r['failures']:
        out += ['The command failed but no failing crate was recognised; read test-full.log.', '']
    for a in r['failures']:
        out.append(f"### {a['crate']}")
        for i in a['issues']:
            times = f" (x{i['count']})" if i['count'] > 1 else ''
            text = i['text'][:400].replace('`', "'")
            out.append(f"- **{i['kind']}**{times}: `{text}`")
        if a['distinct_not_shown']:
            out.append(f"- … {a['distinct_not_shown']} more distinct issue(s) not shown (cap {r['max_issues_per_algo']})")
        out.append('')
    return '\n'.join(out) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', default='test-report', help='output directory')
    ap.add_argument('--max-per-algo', type=int, default=5, help='distinct issues kept per algorithm')
    ap.add_argument('--from-log', help='parse an existing log instead of running a command')
    ap.add_argument('cmd', nargs=argparse.REMAINDER, help='-- command ...')
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd[:1] == ['--'] else a.cmd
    if not cmd and not a.from_log:
        ap.error('give a command after --, or --from-log FILE')
    os.makedirs(a.out, exist_ok=True)
    full = os.path.join(a.out, 'test-full.log')
    t0 = time.time()
    lines = []
    if a.from_log:
        with open(a.from_log, encoding='utf-8', errors='replace') as f:
            for line in f:
                lines.append(STAMP.sub('', ANSI.sub('', line.rstrip('\r\n'))))
        rc = 0 if not any(RERUN.search(x) for x in lines) else 101
        shown = f'(log) {a.from_log}'
    else:
        env = dict(os.environ, CARGO_TERM_COLOR='never')
        with open(full, 'w', encoding='utf-8', newline='\n') as log:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            for raw in p.stdout:
                text = raw.decode('utf-8', 'replace')
                sys.stdout.write(text)
                sys.stdout.flush()
                clean = ANSI.sub('', text.rstrip('\r\n'))
                log.write(clean + '\n')
                lines.append(clean)
            rc = p.wait()
        shown = ' '.join(cmd)
    r = report(lines, rc, a.max_per_algo, shown, time.time() - t0)
    md = markdown(r)
    with open(os.path.join(a.out, 'test-summary.md'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(md)
    with open(os.path.join(a.out, 'test-failures.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(r, f, indent=1, ensure_ascii=False)
    step = os.environ.get('GITHUB_STEP_SUMMARY')
    if step:
        # GitHub caps a step summary at 1 MiB.
        with open(step, 'a', encoding='utf-8') as f:
            f.write(md if len(md) < 900_000 else md[:900_000] + '\n… truncated; see the test-report artifact\n')
    print(f"\n[ci_test_report] {r['test_binaries_run']} binaries, {r['tests_passed']} passed, "
          f"{r['tests_failed']} failed, {r['failing_crates']} failing crate(s); report in {a.out}")
    return rc


if __name__ == '__main__':
    sys.exit(main())
