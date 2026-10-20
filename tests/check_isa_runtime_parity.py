"""Execute CRC/copy/fill fixtures across compiler hosts, pipelines and OSes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def invoke(command, cwd=None):
    result = subprocess.run([str(x) for x in command], cwd=cwd, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=180)
    if result.returncode:
        raise AssertionError((command, result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--linux-compiler', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    def command(path):
        return [sys.executable, str(path.resolve())] if path.suffix == '.py' else [str(path.resolve())]
    def linux_path(path):
        return invoke(['wsl', '-d', 'Ubuntu', '--', 'wslpath', '-a', '-u', path.resolve().as_posix()]).strip()
    peers = [('python', command(args.reference), False, False),
             ('self', command(args.compiler), False, True)]
    if args.linux_compiler:
        if os.name != 'nt':
            parser.error('--linux-compiler is a WSL peer for Windows runs')
        peers.append(('linux-self', ['wsl', '-d', 'Ubuntu', '--cd', linux_path(root), '--', linux_path(args.linux_compiler)], True, True))
    rows = []
    with tempfile.TemporaryDirectory(prefix='ml-isa-parity-') as temp:
        fixtures = [('tests/isa_runtime.ml', 'isa_runtime', '[OK] ISA runtime'),
                    ('tests/checksum_runtime.ml', 'checksum_runtime', '[OK] checksum runtime'),
                    ('benchmarks/isa_workloads.ml', 'isa_workloads', 'crc ms=')]
        for source, fixture, marker in fixtures:
            for target in (['windows-x64', 'linux-x64'] if os.name == 'nt' else ['linux-x64']):
                hashes = []
                for name, compiler, linux, objects in peers:
                    for pipeline in (['--no-object-pipeline', '--object-pipeline'] if objects else [None]):
                        path = Path(temp) / f'{fixture}-{target}-{name}-{pipeline or "direct"}.exe'
                        output = linux_path(path) if linux else str(path)
                        flags = [pipeline] if pipeline else []
                        invoke(compiler + [source, output, '--target', target, '-I', '.'] + flags, cwd=root)
                        digest = hashlib.sha256(path.read_bytes()).hexdigest()
                        hashes.append(digest)
                        execution = [str(path)] if target == 'windows-x64' else (['wsl', '-d', 'Ubuntu', '--', linux_path(path)] if os.name == 'nt' else [str(path)])
                        text = invoke(execution, cwd=root)
                        assert marker in text and '[FAIL]' not in text, text[-2000:]
                        rows.append(dict(fixture=fixture, target=target, compiler=name, pipeline=pipeline or 'direct', bytes=path.stat().st_size, sha256=digest))
                assert len(set(hashes)) == 1, (fixture, target, hashes)
                print(f'[OK] {fixture} {target}: {len(hashes)} identical executed images', flush=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(dict(images=rows), indent=2))


if __name__ == '__main__':
    main()
