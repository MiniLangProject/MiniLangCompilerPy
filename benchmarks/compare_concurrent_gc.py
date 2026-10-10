"""Compare three prebuilt concurrent_gc_pauses images on Windows.

Builds are excluded. Rotating process order reduces drift; intervals include
native counter calls and scheduling and are not a worst-case latency guarantee.
"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import re
import statistics
import time

from compare_runtime_codegen import run_measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'synchronous', 'concurrent'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error('At least three runs per image are required')
    paths = {name: getattr(args, name).resolve() for name in ('baseline', 'synchronous', 'concurrent')}
    samples = []
    for path in paths.values():
        run_measured(path, '')  # Warm page caches before the measured triples.
    versions = list(paths)
    for run in range(args.runs):
        order = versions[run % 3:] + versions[:run % 3]
        for version in order:
            start = time.perf_counter()
            output, peak = run_measured(paths[version], '')
            elapsed = time.perf_counter() - start
            match = re.fullmatch(r'CONCURRENT_PAUSES frames=(\d+) mark_progress=(\d+) max_ms=([\d.eE+-]+) pause_max_ticks=(-?\d+) frequency=(\d+)', output.strip())
            if not match:
                raise AssertionError(output)
            frames, progress, interval, ticks, frequency = match.groups()
            assert int(frequency) > 0 and int(frames) > 0
            if version == 'concurrent':
                assert int(progress) > 0 and int(ticks) > 0, output
            row = dict(version=version, run=run, wall_seconds=elapsed,
                       peak_rss_bytes=peak, max_interval_ms=float(interval),
                       max_handshake_ms=int(ticks) * 1000 / int(frequency) if int(ticks) >= 0 else None,
                       mark_progress=int(progress))
            samples.append(row)
            print(json.dumps(row), flush=True)
    summary = {}
    for version in versions:
        rows = [row for row in samples if row['version'] == version]
        summary[version] = {key: statistics.median(row[key] for row in rows)
                            for key in ('wall_seconds', 'peak_rss_bytes', 'max_interval_ms')}
    payload = dict(platform=platform.platform(), samples=samples, summary=summary,
                   images={name: dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size)
                           for name, path in paths.items()})
    args.output.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
