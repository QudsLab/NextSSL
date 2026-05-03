"""Scan all .c/.h files under src/ for broken references after hash flatten."""
import os
import sys

root = os.path.join(os.path.dirname(__file__), '..', 'src')

OLD_SUBSYS = ['blake/', 'fast/', 'legacy/', 'memory_hard/', 'sponge/', 'sponge_xof/']
results_old = []
results_rel = []
results_hash_root = []

for dirpath, dirnames, filenames in os.walk(root):
    for fname in filenames:
        if not fname.endswith(('.c', '.h')):
            continue
        fpath = os.path.join(dirpath, fname)
        rel = os.path.relpath(fpath, os.path.join(root, '..'))
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            continue
        for i, line in enumerate(lines, 1):
            if '#include' not in line:
                continue
            stripped = line.strip()
            if any(p in stripped for p in OLD_SUBSYS):
                results_old.append((rel, i, stripped))
            if '"../' in stripped:
                results_rel.append((rel, i, stripped))

def show(title, lst):
    print(f'\n=== {title} ({len(lst)}) ===')
    for path, lineno, text in lst:
        print(f'  {path}:{lineno}: {text}')

show('Old subsystem-prefixed includes (stale after flatten)', results_old)
show('Relative ../ includes (potential cross-dir breakage)', results_rel)

total = len(results_old) + len(results_rel)
print(f'\nTotal issues found: {total}')
sys.exit(0 if total == 0 else 1)
