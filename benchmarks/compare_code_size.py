#!/usr/bin/env python3
"""Compare native file size and paired runtime samples without rebuilding inputs.

Example (from the repository root):
  python benchmarks/compare_code_size.py --baseline build/before.exe \
      --candidate build/after.exe --output build/comparison.json --runs 7

Pass common program arguments after ``--``. ``--wsl`` runs Linux images from
Windows through WSL; wall time then includes WSL process startup. Programs must
validate their own workload and return nonzero on failure. The language
optimizer benchmark additionally exposes per-workload millisecond counters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import struct
import subprocess
import time
from pathlib import Path


def image_info(path: Path) -> dict:
    """Record exact input identity and, for PE, unpadded machine-code size."""
    data = path.read_bytes()
    result = {'path': str(path), 'file_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    if data[:2] == b'MZ':
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        sections = struct.unpack_from('<H', data, pe + 6)[0]
        opt_size = struct.unpack_from('<H', data, pe + 20)[0]
        for index in range(sections):
            offset = pe + 24 + opt_size + 40 * index
            if data[offset:offset + 8].rstrip(b'\0') == b'.text':
                result['text_bytes'] = struct.unpack_from('<I', data, offset + 8)[0]
    return result


def metrics(stdout: str) -> dict:
    """Namespace repeated elapsed_ms keys by their workload's first key."""
    result = {}
    for line in stdout.splitlines():
        pairs = re.findall(r'([a-z_]+)=([0-9]+)', line)
        for key, value in pairs:
            if key == 'elapsed_ms':
                key = pairs[0][0] + '.' + key
            result[key] = int(value)
    return result


def main() -> int:
    """Warm both images, alternate A/B order, and retain every raw sample."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error('--runs must be positive')
    common = args.args[1:] if args.args[:1] == ['--'] else args.args
    paths = {'baseline': args.baseline.resolve(strict=True), 'candidate': args.candidate.resolve(strict=True)}
    commands = {}
    for name, path in paths.items():
        if args.wsl:
            linux_path = subprocess.check_output(['wsl', '--exec', 'wslpath', '-a', str(path)], text=True).strip()
            subprocess.run(['wsl', '--exec', 'chmod', '+x', linux_path], check=True)
            commands[name] = ['wsl', '--exec', linux_path, *common]
        else:
            commands[name] = [str(path), *common]
    report = {'runs': args.runs, 'warmups_per_image': 1, 'order': 'alternating AB/BA',
              'wsl': args.wsl, 'commands': commands, 'images': {k: image_info(p) for k, p in paths.items()}, 'samples': []}
    for iteration in range(-1, args.runs):
        order = ('baseline', 'candidate') if iteration % 2 == 0 else ('candidate', 'baseline')
        for name in order:
            started = time.perf_counter()
            proc = subprocess.run(commands[name], capture_output=True, text=True, timeout=args.timeout)
            elapsed = time.perf_counter() - started
            if proc.returncode != 0:
                raise RuntimeError(f'{name} failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}')
            sample = {'image': name, 'iteration': iteration, 'seconds': elapsed,
                      'metrics': metrics(proc.stdout), 'stdout': proc.stdout, 'stderr': proc.stderr}
            if iteration >= 0:
                report['samples'].append(sample)
            print(f'{name} iteration={iteration} seconds={elapsed:.6f}', flush=True)
    report['medians'] = {}
    for name in paths:
        samples = [s for s in report['samples'] if s['image'] == name]
        keys = sorted(set.intersection(*(set(s['metrics']) for s in samples)))
        report['medians'][name] = {'seconds': statistics.median(s['seconds'] for s in samples),
                                   'metrics': {k: statistics.median(s['metrics'][k] for s in samples) for k in keys}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'images': report['images'], 'medians': report['medians']}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
