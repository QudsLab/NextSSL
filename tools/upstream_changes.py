#!/usr/bin/env python3
"""Write docs/UPSTREAM_CHANGES.md: every way NextSSL compiles an upstream differently from its source.

    python3 tools/upstream_changes.py           # (re)write the document
    python3 tools/upstream_changes.py --check   # exit 1 when the document is out of date (CI lint)

The upstream files under algos/**/upstream/ are kept verbatim. What the build changes is recorded in
the crate and collected here:
  1. Patches: `upstream.patches` (exact find/replace, applied to a copy in OUT_DIR, count-checked).
  2. Older build-time rewrites still written inline in a build.rs (to be moved to upstream.patches):
     listed with the build.rs comment that explains them and the replaced text where it is literal.
  3. Compatibility files in compat/ (headers or sources the upstream expects from its own build
     system or platform; on the include path of that crate only).
  4. Force-included preambles and command-line defines (macros the upstream's own build passed, or
     per-target settings).
Standard library only.
"""
import collections
import glob
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, 'docs', 'UPSTREAM_CHANGES.md')


def rel(p):
    return os.path.relpath(p, ROOT).replace(os.sep, '/')


def crate_dirs():
    return sorted(os.path.dirname(p) for p in glob.glob(os.path.join(ROOT, 'algos', '*', '*', '*', 'Cargo.toml')))


def read(p):
    with open(p, encoding='utf-8', errors='replace') as f:
        return f.read().replace('\r\n', '\n')


def parse_patches(text):
    out = []
    for line in text.split('\n'):
        if line.startswith('patch:'):
            out.append({'name': line[6:].strip(), 'why': [], 'file': '', 'count': '', 'find': '', 'replace': ''})
        elif out:
            for k in ('file', 'count', 'find', 'replace'):
                if line.startswith(k + ': '):
                    out[-1][k] = line[len(k) + 2:]
            if line.startswith('why: '):
                out[-1]['why'].append(line[5:])
    return out


def inline_rewrites(src):
    """build.rs functions that read an upstream file and write a changed copy: (doc comment, literal pairs)."""
    found = []
    for m in re.finditer(r'((?:^///[^\n]*\n)*)^fn (\w+)\([^)]*\)[^{]*\{', src, re.M):
        start = m.end()
        depth, i = 1, start
        while i < len(src) and depth:
            depth += {'{': 1, '}': -1}.get(src[i], 0)
            i += 1
        body = src[start:i]
        if 'read_to_string' not in body or 'std::fs::write' not in body:
            continue
        if m.group(2) == 'patched_upstream':
            continue  # the upstream.patches mechanism itself (section 1)
        doc = ' '.join(l[3:].strip() for l in m.group(1).splitlines())
        if not doc:
            # The `//` comment block right above the first read of an upstream file explains it.
            lines = body[:body.index('read_to_string')].split('\n')[:-1]
            block = []
            for l in reversed(lines):
                s = l.strip()
                if s.startswith('//'):
                    block.append(s[2:].strip())
                elif block or s:
                    if block:
                        break
            doc = ' '.join(reversed(block))
        pairs = re.findall(r'\(\s*"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)",?\s*\)', body)
        found.append((m.group(2), doc, pairs))
    return found


def preamble_lines(src):
    lines = []
    for s in re.findall(r'pre\.push_str\(\s*"((?:[^"\\]|\\.)*)"', src):
        for l in s.replace('\\n', '\n').replace('\\"', '"').split('\n'):
            if l.strip():
                lines.append(l.strip())
    return lines


def defines(src):
    m = re.search(r'const DEFINES: &\[\(&str, &str\)\] = &\[(.*?)\];', src, re.S)
    if not m:
        return []
    return [f'{k}={v}' if v else k for k, v in re.findall(r'\(\s*"([^"]*)",\s*"([^"]*)"\s*\)', m.group(1))]


def arm64_msvc_defines(src):
    """Windows-on-ARM64-only defines/flags of a build.rs (the block after its "Windows on ARM64 (cl.exe)" comment)."""
    src = src.replace('\r\n', '\n')
    m = re.search(r'// Windows on ARM64 \(cl\.exe\): (.*?)\n    if std::env::var\("CARGO_CFG_TARGET_ARCH"\)'
                  r'.*?\{\n(.*?)\n    \}\n', src, re.S)
    if not m:
        return None
    why = ' '.join(l.strip().lstrip('/').strip() for l in m.group(1).split('\n'))
    items = []
    for d in re.finditer(r'b\.define\("([^"]+)", (None|"([^"]*)")\)', m.group(2)):
        items.append(d.group(1) + (f'={d.group(3)}' if d.group(3) is not None else ''))
    items += [f.group(1) for f in re.finditer(r'b\.flag\("([^"]+)"\)', m.group(2))]
    return why, tuple(items)


def main():
    check = '--check' in sys.argv
    patches = collections.OrderedDict()   # key (file-less) -> crates
    inline = collections.OrderedDict()    # (fn, doc, pairs) -> crates
    compat = collections.OrderedDict()    # (name, hash) -> (first comment, crates)
    pre = collections.Counter()
    pre_crates = collections.defaultdict(list)
    defs = collections.Counter()
    arm64 = collections.OrderedDict()     # (why, defines) -> crates
    n_patch_crates = 0
    for d in crate_dirs():
        crate = os.path.basename(d)
        b = os.path.join(d, 'build.rs')
        src = read(b) if os.path.exists(b) else ''
        pf = os.path.join(d, 'upstream.patches')
        if os.path.exists(pf):
            n_patch_crates += 1
            for p in parse_patches(read(pf)):
                # Same change in sibling crates (parameter sets of one upstream) is listed once.
                file_tail = re.sub(r'^upstream/[^/]+/', 'upstream/*/', p['file'])
                key = (p['name'], ' '.join(p['why']), file_tail, p['count'], p['find'], p['replace'])
                patches.setdefault(key, []).append(crate)
        for fn, doc, pairs in inline_rewrites(src):
            inline.setdefault((fn, doc, tuple(pairs)), []).append(crate)
        cdir = os.path.join(d, 'compat')
        if os.path.isdir(cdir):
            for f in sorted(glob.glob(os.path.join(cdir, '**', '*'), recursive=True)):
                if os.path.isfile(f):
                    data = read(f)
                    h = hashlib.sha256(data.encode()).hexdigest()[:12]
                    first = ''
                    m = re.search(r'/\*\s*(.*?)(?:\*/|\n)', data) or re.search(r'//\s*(.*)', data)
                    if m:
                        first = m.group(1).strip()[:160]
                    key = (os.path.relpath(f, cdir).replace(os.sep, '/'), h)
                    compat.setdefault(key, [first, []])[1].append(crate)
        for l in preamble_lines(src):
            pre[l] += 1
            pre_crates[l].append(crate)
        for x in defines(src):
            defs[x] += 1
        a64 = arm64_msvc_defines(src)
        if a64:
            arm64.setdefault(a64, []).append(crate)

    out = ['# Changes to upstream sources', '',
           '<!-- Generated by tools/upstream_changes.py; do not edit. CI checks it is current. -->', '',
           'NextSSL keeps every upstream file under `algos/**/upstream/` verbatim (pinned commit, license kept).',
           'This document lists everything the build does differently from compiling those files as they are,',
           'so anyone can see what was changed, where and why, and reproduce or review it.', '',
           '1. **Patches** (`upstream.patches` in the crate): exact text replacements applied to a copy of',
           '   `upstream/` in the build directory. Each patch states how many times its text occurs; any other',
           '   count stops the build, so a changed upstream is never patched blindly.',
           '2. **Build-time rewrites in build.rs**: the same kind of change, written before `upstream.patches`',
           '   existed. They are listed with their explanation and will move to `upstream.patches`.',
           '3. **Compatibility files** (`compat/`): headers or sources the upstream expects from its own build',
           '   system or platform (for example SUPERCOP `crypto_*.h` API headers, `randombytes.h`). They add',
           '   declarations; they do not change upstream code.',
           '4. **Preambles and defines**: macros force-included or passed on the command line, as the',
           "   upstream's own build did, or per-target settings.", '',
           'Glue code (`glue.rs`), shims (`shim.c`) and `build.rs` are NextSSL code, not upstream code.', '']

    out += [f'## 1. Patches ({len(patches)} distinct, in {n_patch_crates} crates)', '']
    if not patches:
        out += ['None.', '']
    for (name, why, file, count, find, repl), crates in patches.items():
        out += [f'### {name}', '', f'Crates: {", ".join(sorted(crates))}', '',
                f'File: `{file}` ({count} occurrence(s))', '', why, '', '```diff', f'- {find}', f'+ {repl}', '```', '']

    out += [f'## 2. Build-time rewrites in build.rs ({len(inline)} distinct, '
            f'{sum(len(c) for c in inline.values())} crates)', '']
    for (fn, doc, pairs), crates in inline.items():
        out += [f'### `{fn}` in {len(crates)} crate(s)', '', f'Crates: {", ".join(sorted(crates))}', '',
                doc or '(no comment in build.rs; see the crate\'s upstream/ORIGIN.md)', '']
        if pairs:
            out.append('```diff')
            for a, b in pairs:
                out += [f'- {a}', f'+ {b}']
            out += ['```', '']

    groups = collections.OrderedDict()
    for (name, h), (first, crates) in compat.items():
        groups.setdefault(name, []).append((h, first, crates))
    out += [f'## 3. Compatibility files ({len(compat)} distinct files, {len(groups)} names)', '',
            '| file | variants | crates | purpose (first comment) |', '|---|---|---|---|']
    for name in sorted(groups):
        vs = groups[name]
        n = sum(len(c) for _, _, c in vs)
        first = next((f for _, f, _ in vs if f), '').replace('|', '\\|')
        out.append(f'| `{name}` | {len(vs)} | {n} | {first} |')
    out.append('')

    out += [f'## 4. Preambles and defines', '', '### Force-included preamble lines', '',
            '| line | crates |', '|---|---|']
    for l, n in sorted(pre.items(), key=lambda x: (-x[1], x[0])):
        out.append(f'| `{l.replace("|", chr(92) + "|")}` | {n} |')
    out += ['', '### Command-line defines', '', '| define | crates |', '|---|---|']
    for x, n in sorted(defs.items(), key=lambda x: (-x[1], x[0])):
        out.append(f'| `{x.replace("|", chr(92) + "|")}` | {n} |')
    out.append('')
    out += [f'### Windows on ARM64 (aarch64-pc-windows-msvc) only ({sum(len(c) for c in arm64.values())} crates)', '',
            'Compiler defines and flags given only when the target is aarch64 with the MSVC environment;',
            'every other target compiles these crates unchanged.', '']
    for (why, items), crates in arm64.items():
        out += [f'- `{" ".join(items)}`: {why}', f'  Crates: {", ".join(sorted(crates))}', '']

    text = '\n'.join(out)
    old = read(DOC) if os.path.exists(DOC) else None
    if check:
        if old != text:
            print('docs/UPSTREAM_CHANGES.md is out of date: run python3 tools/upstream_changes.py')
            return 1
        print('docs/UPSTREAM_CHANGES.md is current')
        return 0
    os.makedirs(os.path.dirname(DOC), exist_ok=True)
    with open(DOC, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    print(f'wrote {rel(DOC)}: {len(patches)} patches, {len(inline)} inline rewrites, '
          f'{len(compat)} compat files, {len(pre)} preamble lines, {len(defs)} defines')
    return 0


if __name__ == '__main__':
    sys.exit(main())
