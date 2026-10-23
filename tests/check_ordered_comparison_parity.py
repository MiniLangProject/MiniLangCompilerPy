"""Execute dynamic ordered comparisons and compare every emitted image.

Use --compiler for a Windows native compiler and --reference for the Python
entry point. --linux-compiler adds a native Linux peer through WSL Ubuntu.
No installation binaries are overwritten; every test image is private.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def invoke(command, cwd):
    """Reject compilation errors, runtime errors and hung fixtures uniformly."""
    result = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=180)
    if result.returncode:
        raise AssertionError((command, result.returncode, result.stdout[-3000:], result.stderr[-3000:]))
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--linux-compiler', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / 'tests/ordered_comparison.ml'

    def linux_path(path):
        return invoke(['wsl', '-d', 'Ubuntu', '--', 'wslpath', '-a', '-u', path.resolve().as_posix()], root)

    peers = [('python', [sys.executable, args.reference.resolve()], False, [None]),
             ('ml', [args.compiler.resolve()], False, ['--no-object-pipeline', '--object-pipeline'])]
    if args.linux_compiler:
        if os.name != 'nt':
            parser.error('--linux-compiler is a WSL peer for Windows runs')
        peers.append(('linux-ml', ['wsl', '-d', 'Ubuntu', '--', linux_path(args.linux_compiler)],
                      True, ['--no-object-pipeline', '--object-pipeline']))
    rows = []
    matches = True
    targets = ['windows-x64', 'linux-x64'] if os.name == 'nt' else ['linux-x64']
    with tempfile.TemporaryDirectory(prefix='ml-ordered-parity-') as temp:
        for target in targets:
            modes = [('default', [])]
            if target == 'windows-x64':
                modes.append(('concurrent-gc', ['--gc-concurrent']))
            for mode, options in modes:
                hashes = []
                for host, command, linux, pipelines in peers:
                    for pipeline in pipelines:
                        image = Path(temp) / f'{host}-{target}-{mode}-{pipeline or "direct"}.exe'
                        paths = [source, image, '-I', root]
                        if linux:
                            paths = [linux_path(source), linux_path(image), '-I', linux_path(root)]
                        flags = [pipeline] if pipeline else []
                        invoke(command + paths + ['--target', target] + flags + options, root)
                        if target == 'windows-x64' or os.name != 'nt':
                            execution = [image]
                        else:
                            invoke(['wsl', '-d', 'Ubuntu', '--', 'chmod', '+x', linux_path(image)], root)
                            execution = ['wsl', '-d', 'Ubuntu', '--', linux_path(image)]
                        observed = invoke(execution, root)
                        assert observed == '[OK] dynamic ordered comparisons', observed
                        digest = hashlib.sha256(image.read_bytes()).hexdigest()
                        hashes.append(digest)
                        rows.append(dict(target=target, mode=mode, host=host,
                                         pipeline=pipeline or 'direct', bytes=image.stat().st_size,
                                         sha256=digest, runtime='pass'))
                equal = len(set(hashes)) == 1
                matches = matches and equal
                print(f'[{"OK" if equal else "FAIL"}] {target} {mode}: {len(hashes)} executed images, byte parity={equal}', flush=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(dict(byteParity=matches, images=rows), indent=2) + '\n', encoding='utf-8')
    if not matches:
        raise AssertionError('Ordered-comparison output differs; see report for image hashes')


if __name__ == '__main__':
    main()
