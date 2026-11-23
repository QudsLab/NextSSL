"""Collect the Windows (MSVC) test binaries into one folder that runs on a bare Windows machine.

    python tools/wintests.py [--out D:/Dev/nextssl-wintests]

Runs `cargo test --workspace --no-run --message-format=json` on the host (cached after fasttest's msvc pass, so
it only links what is missing), then copies every test executable cargo reports for the current commit into
<out>/<commit>/bin, with:
  manifest.tsv  crate, test target, file name, size, sha256
  run_all.ps1   runs every binary, prints one PASS/FAIL line each, writes results.tsv, exits non-zero on a failure
  vcruntime140*.dll from System32 (Rust MSVC binaries link the VC runtime dynamically; a bare Windows without
  the VC++ redistributable lacks it; the UCRT is part of Windows 10/11)

No Rust, cargo or Visual Studio is needed on the machine that runs it. Nothing is written to C:.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

RUNNER = r'''# Runs every NextSSL test binary in .\bin. One line per binary; results.tsv; exit 1 on any failure.
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PATH = "$here\bin;$env:PATH"
$rows = @(); $fail = 0
foreach ($exe in Get-ChildItem "$here\bin\*.exe" | Sort-Object Name) {
    $t0 = Get-Date
    $out = & $exe.FullName --test-threads=4 2>&1 | Out-String
    $code = $LASTEXITCODE
    $s = [int]((Get-Date) - $t0).TotalSeconds
    $res = if ($code -eq 0) { 'PASS' } else { 'FAIL'; $fail++ }
    $sum = ($out -split "`n" | Where-Object { $_ -match '^test result:' } | Select-Object -Last 1)
    "{0} {1} ({2} s) {3}" -f $res, $exe.BaseName, $s, $sum.Trim()
    if ($code -ne 0) { $out | Set-Content "$here\fail-$($exe.BaseName).log" }
    $rows += "$res`t$($exe.Name)`t$code`t$s"
}
$rows | Set-Content "$here\results.tsv"
"{0} binaries, {1} failed" -f $rows.Count, $fail
exit [int]($fail -gt 0)
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', default='D:/Dev/nextssl-wintests')
    a = ap.parse_args()
    out_root = pathlib.Path(a.out)
    if out_root.drive.upper() == 'C:':
        sys.exit('refusing to write to C: (owner rule)')
    commit = subprocess.run(['git', 'rev-parse', '--short=9', 'HEAD'], cwd=ROOT, capture_output=True,
                            text=True, check=True).stdout.strip()
    dirty = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    tag = commit + ('-dirty' if dirty else '')
    dest = out_root / tag
    bindir = dest / 'bin'

    p = subprocess.run(['cargo', 'test', '--workspace', '--no-run', '--no-fail-fast', '--message-format=json'],
                       cwd=ROOT, capture_output=True, text=True, errors='replace')
    exes = []
    for line in p.stdout.splitlines():
        if not line.startswith('{'):
            continue
        m = json.loads(line)
        if m.get('reason') == 'compiler-artifact' and m.get('executable') and m.get('profile', {}).get('test'):
            exes.append((m['package_id'], m['target']['name'], pathlib.Path(m['executable'])))
    if p.returncode != 0:
        sys.stderr.write(p.stderr[-4000:])
        sys.exit(f'cargo test --no-run failed (exit {p.returncode}); nothing copied')

    need = sum(e.stat().st_size for _, _, e in exes)
    free = shutil.disk_usage(out_root.anchor).free
    if need * 1.1 > free:
        sys.exit(f'not enough space on {out_root.anchor}: need {need >> 20} MiB, free {free >> 20} MiB')

    if dest.exists():
        shutil.rmtree(dest)  # only our own previous copy of this same commit
    bindir.mkdir(parents=True)
    rows = []
    for pkg, tgt, exe in sorted(exes, key=lambda x: x[2].name):
        crate = pkg.split('#')[0].rsplit('/', 1)[-1] if '#' in pkg else pkg.split()[0]
        shutil.copy2(exe, bindir / exe.name)
        h = hashlib.sha256(exe.read_bytes()).hexdigest()
        rows.append(f'{crate}\t{tgt}\t{exe.name}\t{exe.stat().st_size}\t{h}')
    for dll in ('vcruntime140.dll', 'vcruntime140_1.dll'):
        src = pathlib.Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / dll
        if src.is_file():
            shutil.copy2(src, bindir / dll)
    (dest / 'manifest.tsv').write_text('crate\ttarget\tfile\tbytes\tsha256\n' + '\n'.join(rows) + '\n')
    (dest / 'run_all.ps1').write_text(RUNNER)
    print(f'{len(rows)} test binaries ({need >> 20} MiB) -> {dest}')
    print(f'run on any Windows 10/11 x64:  powershell -ExecutionPolicy Bypass -File {dest / "run_all.ps1"}')


if __name__ == '__main__':
    main()
