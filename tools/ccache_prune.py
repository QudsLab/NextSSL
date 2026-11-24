#!/usr/bin/env python3
"""Drop C library cache entries (crates/nextssl-cbuild) that the current run did not use.

    python3 tools/ccache_prune.py DIR STAMP

STAMP is a file touched before the build started. Every entry whose manifest is older than STAMP was
neither stored nor hit by this run (the inputs of that crate changed, or the crate is gone), so it is
removed before the cache is saved; the cache then holds exactly one current entry per library.
Standard library only.
"""
import os
import shutil
import sys


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    root, stamp = sys.argv[1], os.path.getmtime(sys.argv[2])
    kept = removed = 0
    size = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if 'manifest' in filenames:
            m = os.path.join(dirpath, 'manifest')
            if os.path.getmtime(m) < stamp:
                shutil.rmtree(dirpath, ignore_errors=True)
                removed += 1
            else:
                kept += 1
                size += sum(os.path.getsize(os.path.join(dirpath, f)) for f in filenames)
            dirnames[:] = []
        elif os.path.basename(dirpath).startswith('.tmp-'):
            shutil.rmtree(dirpath, ignore_errors=True)
            dirnames[:] = []
    print(f'C library cache: {kept} entries kept ({size / 1e6:.0f} MB), {removed} unused entries removed')


if __name__ == '__main__':
    main()
