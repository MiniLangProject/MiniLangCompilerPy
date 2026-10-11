"""Alternate old/new prebuilt reuse probes; distinguish heap growth from RSS.

Run on Windows with idle compiler/build processes. Each image must be compiled
from the same concurrent_gc_reuse.ml source with --gc-concurrent. The optional
--wait control delays allocation until collection finishes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import statistics
import time

from compare_runtime_codegen import run_measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    parser.add_argument('--runs', type=int, default=5)
    parser.add_argument('--wait', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error('At least three runs are required')
    paths = {name: getattr(args, name).resolve() for name in ('before', 'after')}
    argument = 'wait' if args.wait else ''
    for path in paths.values():
        run_measured(path, argument)
    samples = []
    for run in range(args.runs):
        for version in (('before', 'after') if run % 2 == 0 else ('after', 'before')):
            start = time.perf_counter()
            output, peak = run_measured(paths[version], argument)
            elapsed = time.perf_counter() - start
            observed = re.search(r'PROBE \[OK\] concurrent_allocations=(\d+)', output)
            rows = [dict((key, int(value)) for key, value in re.findall(r'(\w+)=(\d+)', line))
                    for line in output.splitlines() if line.startswith('PROBE round=')]
            assert observed and len(rows) == 6 and rows[0]['round'] == 0 and rows[-1]['round'] == 65, output
            assert rows[0]['live'] == rows[-1]['live'], output
            assert (int(observed[1]) == 0 if args.wait else int(observed[1]) >= 8), output
            sample = dict(version=version, run=run, wall_seconds=elapsed, peak_rss_bytes=peak,
                          concurrent_allocations=int(observed[1]), checkpoints=rows,
                          committed_growth=rows[-1]['committed'] - rows[0]['committed'],
                          frontier_growth=rows[-1]['frontier'] - rows[0]['frontier'])
            samples.append(sample)
            print(json.dumps(sample), flush=True)
    summary = {version: {field: statistics.median(row[field] for row in samples if row['version'] == version)
                         for field in ('wall_seconds', 'peak_rss_bytes', 'committed_growth', 'frontier_growth')}
               for version in paths}
    result = dict(platform=platform.platform(), wait=args.wait, samples=samples, summary=summary,
                  images={name: dict(path=str(path), size=path.stat().st_size,
                                     sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                          for name, path in paths.items()})
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
