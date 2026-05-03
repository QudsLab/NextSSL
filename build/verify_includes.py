"""Resolve every ../ include and verify the target file exists."""
import os, re

src_root = os.path.join(os.path.dirname(__file__), '..', 'src')
broken = []
ok = 0

pat = re.compile(r'#include\s+"(\.\.[^"]+)"')

for dirpath, dirnames, filenames in os.walk(src_root):
    for fname in filenames:
        if not fname.endswith(('.c', '.h')):
            continue
        fpath = os.path.join(dirpath, fname)
        with open(fpath, encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f, 1):
                if '#include' not in line:
                    continue
                m = pat.search(line)
                if not m:
                    continue
                rel = m.group(1)
                resolved = os.path.normpath(os.path.join(dirpath, rel))
                if os.path.exists(resolved):
                    ok += 1
                else:
                    short_fp = os.path.relpath(fpath, os.path.join(src_root, '..'))
                    broken.append(f'{short_fp}:{i}: {line.strip()}')

print(f'Verified OK: {ok}   BROKEN: {len(broken)}')
for b in broken:
    print('  BROKEN:', b)
