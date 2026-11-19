#!/usr/bin/env python3
"""Compare old/new MiniLang compilers on the existing, fixed-input suite.

Build and validate before measuring. Each measured pair has the same n, seed,
repeat count and untimed warmup. Alternating AB/BA order and shuffled case order
reduce time/order bias. The driver reports in-process CLOCK_MONOTONIC timings.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import re
import statistics
import struct
import subprocess
import sys
import time

MASK = 2147483647
SEED = 12345


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_command(path):
    return [sys.executable, str(path)] if path.suffix == '.py' else [str(path)]


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def invoke(command, *, cpu=None, env=None, timeout=180):
    if cpu is not None:
        command = ['taskset', '-c', str(cpu), *map(str, command)]
    result = subprocess.run(command, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.returncode}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def text_size(path):
    data = path.read_bytes()
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    return sum(row[5] for i in range(count)
               if (row := struct.unpack_from('<IIQQQQQQ', data, offset + i * size))[0] == 1
               and row[1] & 1)


def run_binary(path, n, reps, seed, args):
    env = os.environ.copy()
    env['LC_ALL'] = 'C'
    env['LD_LIBRARY_PATH'] = str(args.suite/'build') + ':' + env.get('LD_LIBRARY_PATH', '')
    stdout = invoke([path, n, reps, seed], cpu=args.cpu, env=env, timeout=90)
    found = re.search(r'^RESULT (-?\d+) (\d+) (-?\d+)\s*$', stdout, re.M)
    if not found:
        raise AssertionError(stdout)
    return dict(checksum=int(found[1]), elapsed_ns=int(found[2]),
                warmup_checksum=int(found[3]), ns_per_call=int(found[2])/reps,
                n=n, reps=reps, seed=seed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'validate', 'measure', 'summarize', 'all'))
    parser.add_argument('--suite', type=Path, required=True)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--python-compiler', type=Path, required=True)
    parser.add_argument('--stdlib', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--cpu', type=int, default=2)
    parser.add_argument('--rounds', type=int, default=11)
    args = parser.parse_args()
    for key in ('suite', 'before', 'after', 'python_compiler', 'stdlib', 'work'):
        setattr(args, key, getattr(args, key).resolve())
    build, results = args.work/'build', args.work/'results'
    build.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    calibration = json.loads((args.suite/'results/calibration.json').read_text())
    cases = list(calibration)
    if args.cpu not in os.sched_getaffinity(0):
        parser.error('requested CPU is not allowed')

    if args.action in ('build', 'all'):
        builds = []
        for case in cases:
            # Identical source and import paths also keep error provenance equal.
            source = args.suite/'inputs'/(case+'.ml')
            folder = build/case
            folder.mkdir(exist_ok=True)
            row = {'case': case, 'source': str(source), 'source_sha256': sha(source), 'variants': {}}
            for variant, compiler in [('before', args.before), ('after', args.after),
                                      ('python', args.python_compiler)]:
                binary = folder/variant
                command = [*compiler_command(compiler), str(source), str(binary),
                           '--target', 'linux-x64', '--no-object-pipeline', '-I', str(args.stdlib)]
                invoke(command, cpu=4 if 4 in os.sched_getaffinity(0) else min(os.sched_getaffinity(0)))
                binary.chmod(binary.stat().st_mode | 0o111)
                row['variants'][variant] = dict(sha256=sha(binary), bytes=binary.stat().st_size,
                                                executable_segment_bytes=text_size(binary),
                                                command=command)
            row['new_python_native_parity'] = row['variants']['after']['sha256'] == row['variants']['python']['sha256']
            if not row['new_python_native_parity']:
                raise AssertionError(f'Python/native parity failed for {case}')
            builds.append(row)
            save(results/'builds.json', builds)
            print('BUILT', case, 'new Python/native bytes identical', flush=True)
        save(results/'environment.json', dict(platform=platform.platform(), cpu=args.cpu,
            before=str(args.before), before_sha256=sha(args.before), after=str(args.after),
            after_sha256=sha(args.after), date_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            python=sys.version, rounds=args.rounds, calibration_sha256=sha(args.suite/'results/calibration.json'),
            methodology='Fixed original inputs and repeat counts; common warmup, balanced eight-seed cycle; '
                         'paired alternating AB/BA; shuffled cases; default GC; no instrumented allocations. '
                         'Linux shared VM. Internal runtime timings only; no RSS claims.'))

    if args.action in ('validate', 'all'):
        data_ref = load_module('data_reference', args.suite/'verification/data_reference.py')
        other_ref = load_module('other_reference', args.suite/'verification/other_reference.py')
        records = []
        for case in cases:
            oracle = data_ref.expected_checksum if case in data_ref.CASES else other_ref.expected_checksum
            sizes = [32, 67] if case == 'byte_search' else [1, 17, 67]
            for n in sizes:
                for seed in (0, SEED, MASK):
                    expected = sum(oracle(case, n, (seed+(r & 7)) & MASK) for r in range(8)) & MASK
                    warmup = oracle(case, n, (seed+65536) & MASK)
                    for variant in ('before', 'after'):
                        observed = run_binary(build/case/variant, n, 8, seed, args)
                        if (observed['checksum'], observed['warmup_checksum']) != (expected, warmup):
                            raise AssertionError((case, variant, expected, warmup, observed))
                        records.append(dict(case=case, variant=variant, correct=True, **observed))
            c = calibration[case]
            reps = c['configs']['minilang']['reps']
            expected = (c['configs']['minilang']['cycle_checksum']*(reps//8)) & MASK
            for variant in ('before', 'after'):
                observed = run_binary(build/case/variant, c['n'], reps, SEED, args)
                if (observed['checksum'], observed['warmup_checksum']) != (expected, c['configs']['minilang']['warmup_checksum']):
                    raise AssertionError((case, variant, observed))
                records.append(dict(case=case, variant=variant, full_size=True, correct=True, **observed))
            save(results/'validation.json', records)
            print('VALIDATED', case, flush=True)

    if args.action in ('measure', 'all'):
        records = []
        rng = random.Random(20261116)
        with (results/'measurements.jsonl').open('w', encoding='utf-8') as handle:
            for round_number in range(args.rounds):
                order = cases.copy()
                rng.shuffle(order)
                for case in order:
                    c = calibration[case]
                    reps = c['configs']['minilang']['reps']
                    variants = ('before', 'after') if (round_number+cases.index(case)) % 2 == 0 else ('after', 'before')
                    for position, variant in enumerate(variants):
                        observed = run_binary(build/case/variant, c['n'], reps, SEED, args)
                        expected = (c['configs']['minilang']['cycle_checksum']*(reps//8)) & MASK
                        if (observed['checksum'], observed['warmup_checksum']) != (expected, c['configs']['minilang']['warmup_checksum']):
                            raise AssertionError((case, variant, observed))
                        row = dict(case=case, variant=variant, round=round_number, position=position,
                                   correct=True, **observed)
                        handle.write(json.dumps(row)+'\n')
                        handle.flush()
                        records.append(row)
                print('MEASURED round', round_number+1, '/', args.rounds, flush=True)

    if args.action in ('summarize', 'all'):
        records = [json.loads(line) for line in (results/'measurements.jsonl').read_text().splitlines()]
        builds = {row['case']: row for row in json.loads((results/'builds.json').read_text())}
        summary = []
        for case in cases:
            values = {variant: [row['ns_per_call'] for row in records if row['case']==case and row['variant']==variant]
                      for variant in ('before', 'after')}
            if len(values['before']) != args.rounds or len(values['after']) != args.rounds:
                raise AssertionError(f'incomplete measurement set: {case}')
            paired = [values['before'][i]/values['after'][i] for i in range(args.rounds)]
            medians = {key: statistics.median(value)/1e6 for key,value in values.items()}
            iqr = {key: (statistics.quantiles(value, n=4)[2]-statistics.quantiles(value, n=4)[0])/statistics.median(value)
                   for key,value in values.items()}
            row = dict(case=case, n=calibration[case]['n'], reps=calibration[case]['configs']['minilang']['reps'],
                       rounds=args.rounds, median_ms=medians, relative_iqr=iqr,
                       median_speedup=medians['before']/medians['after'],
                       paired_median_speedup=statistics.median(paired),
                       pair_min=min(paired), pair_max=max(paired),
                       faster_pairs=sum(value>1 for value in paired),
                       same_bytes=builds[case]['variants']['before']['sha256']==builds[case]['variants']['after']['sha256'],
                       text_bytes={key: builds[case]['variants'][key]['executable_segment_bytes'] for key in values})
            summary.append(row)
            print(f"{case:18} {medians['before']:9.3f} -> {medians['after']:9.3f} ms "
                  f"({row['median_speedup']:.3f}x), paired {row['paired_median_speedup']:.3f}x; "
                  f"{row['faster_pairs']}/{args.rounds} faster", flush=True)
        save(results/'summary.json', summary)


if __name__ == '__main__':
    main()
