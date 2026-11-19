#!/usr/bin/env python3
"""Preset exploratory ablation of raw-normalizer scalar conversion destinations.

Six source-equivalent variants, two unchanged kernels, seven balanced rounds.
This pilot selects a candidate; it is separate from final validation/timing.
The public helper has portable path defaults; the recorded pilot used its
original private wrapper. Reproduction writes fresh helper/source fingerprints.
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
from pathlib import Path
import random
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_compilers import MASK, SEED, invoke, run_binary, save, sha, text_size, load_module

CASES = ('float_recurrence', 'mandelbrot')
VARIANTS = ('before', 'xmm1', 'xmm2', 'xmm3', 'xmm23', 'all')
SCRATCH = {'before': (), 'xmm1': (1,), 'xmm2': (2,), 'xmm3': (3,),
           'xmm23': (2, 3), 'all': (1, 2, 3)}


def wrapper(compiler_root: Path, scratch: tuple[int, ...]) -> str:
    return f'''import sys
sys.path.insert(0, {str(compiler_root)!r})
from mlc.codegen import Codegen
from mlc.compiler import main
SCRATCH = {scratch!r}
def normalize(self, slow):
    a = self.asm
    a.mark(f'float_tree_normalize_{{self.new_label_id()}}')
    a.cvttsd2si_r64_xmm('rax', 'xmm0')
    if 1 in SCRATCH:
        a.xorpd_xmm_xmm('xmm1', 'xmm1')
    a.cvtsi2sd_xmm_r64('xmm1', 'rax')
    a.ucomisd_xmm_xmm('xmm0', 'xmm1')
    a.jcc('e', slow)
    if 2 in SCRATCH:
        a.xorpd_xmm_xmm('xmm2', 'xmm2')
    a.cvtsd2ss_xmm_xmm('xmm2', 'xmm0')
    if 3 in SCRATCH:
        a.xorpd_xmm_xmm('xmm3', 'xmm3')
    a.cvtss2sd_xmm_xmm('xmm3', 'xmm2')
    a.ucomisd_xmm_xmm('xmm0', 'xmm3')
Codegen._opt_emit_float_tree_normalize = normalize
raise SystemExit(main(sys.argv))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'measure', 'summarize'))
    parser.add_argument('--suite', type=Path, default=Path(__file__).resolve().parent / 'suite')
    parser.add_argument('--compiler-root', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--stdlib', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--cpu', type=int, default=min(os.sched_getaffinity(0)))
    parser.add_argument('--rounds', type=int, default=7)
    args = parser.parse_args()
    for key in ('suite', 'compiler_root', 'baseline', 'stdlib', 'work'):
        setattr(args, key, getattr(args, key).resolve())
    assert args.cpu in os.sched_getaffinity(0) and args.rounds >= 3
    args.work.mkdir(parents=True, exist_ok=True)
    calibration = json.loads((args.suite / 'results/calibration.json').read_text())
    source_hashes = {str(p.relative_to(args.compiler_root)): sha(p) for p in
                     [args.compiler_root / 'mlc_win64.py', *sorted((args.compiler_root / 'mlc').rglob('*.py'))]}

    if args.action == 'prepare':
        builds, checks = [], []
        for variant in VARIANTS:
            (args.work / f'{variant}_compiler.py').write_text(wrapper(args.compiler_root, SCRATCH[variant]))
        oracle = load_module('phase9_pilot_oracle', args.suite / 'verification/other_reference.py')
        for case in CASES:
            folder = args.work / case
            folder.mkdir(exist_ok=True)
            source = args.suite / 'inputs' / f'{case}.ml'
            for variant in (*VARIANTS, 'native_baseline'):
                binary = folder / variant
                compiler = [str(args.baseline)] if variant == 'native_baseline' else [
                    sys.executable, str(args.work / f'{variant}_compiler.py')]
                command = [*compiler, str(source), str(binary), '--target', 'linux-x64',
                           '--no-object-pipeline', '--no-incremental', '-I', str(args.stdlib),
                           '--asm', '--asm-out', str(folder / f'{variant}.asm'),
                           '--dump-labels', str(folder / f'{variant}.labels')]
                invoke(command, cpu=4 if 4 in os.sched_getaffinity(0) else min(os.sched_getaffinity(0)))
                binary.chmod(binary.stat().st_mode | 0o111)
                builds.append(dict(case=case, variant=variant, binary_sha256=sha(binary),
                                   source_sha256=sha(source), executable_segment_bytes=text_size(binary), command=command))
            assert sha(folder / 'before') == sha(folder / 'native_baseline')
            cfg = calibration[case]
            sizes = [(n, seed, 8) for n in (1, 17, 67) for seed in (0, SEED, MASK)]
            sizes.append((cfg['n'], SEED, cfg['configs']['minilang']['reps']))
            for n, seed, reps in sizes:
                expected = sum(oracle.expected_checksum(case, n, (seed + r) & MASK) for r in range(8)) * (reps // 8) & MASK
                warmup = oracle.expected_checksum(case, n, (seed + 65536) & MASK)
                for variant in VARIANTS:
                    result = run_binary(folder / variant, n, reps, seed, args)
                    assert (result['checksum'], result['warmup_checksum']) == (expected, warmup)
                    checks.append(dict(case=case, variant=variant, correct=True, **result))
            print('PREPARED', case, flush=True)
        save(args.work / 'preparation.json', builds)
        save(args.work / 'correctness.json', checks)
        save(args.work / 'method.json', dict(rounds=args.rounds, variants=VARIANTS, cases=CASES,
             scratch_registers=SCRATCH, cpu=args.cpu, compiler_sources=source_hashes,
             calibration_sha256=sha(args.suite / 'results/calibration.json'),
             baseline_compiler_sha256=sha(args.baseline), helper_sha256=sha(Path(__file__)),
             baseline_wrapper_native_exact=True, original_inputs_repeats_seeds=True,
             phase='exploratory fixed-size ablation; separate final confirmation required'))

    if args.action == 'measure':
        method = json.loads((args.work / 'method.json').read_text())
        assert method['rounds'] == args.rounds and method['compiler_sources'] == source_hashes
        assert method['calibration_sha256'] == sha(args.suite / 'results/calibration.json')
        assert method['helper_sha256'] == sha(Path(__file__))
        for row in json.loads((args.work / 'preparation.json').read_text()):
            assert sha(args.work / row['case'] / row['variant']) == row['binary_sha256']
        rng = random.Random(20261119)
        with (args.work / 'measurements.jsonl').open('w') as output:
            for number in range(args.rounds):
                cases = list(CASES)
                rng.shuffle(cases)
                shift = (number // 2) % len(VARIANTS)
                variants = list(VARIANTS[shift:] + VARIANTS[:shift])
                if number % 2:
                    variants.reverse()
                for case in cases:
                    cfg = calibration[case]
                    settings = cfg['configs']['minilang']
                    expected = settings['cycle_checksum'] * (settings['reps'] // 8) & MASK
                    for position, variant in enumerate(variants):
                        result = run_binary(args.work / case / variant, cfg['n'], settings['reps'], SEED, args)
                        assert (result['checksum'], result['warmup_checksum']) == (expected, settings['warmup_checksum'])
                        output.write(json.dumps(dict(case=case, variant=variant, round=number,
                                                     position=position, correct=True, **result)) + '\n')
                        output.flush()
                print('MEASURED', number + 1, '/', args.rounds, flush=True)

    if args.action == 'summarize':
        rows = [json.loads(line) for line in (args.work / 'measurements.jsonl').read_text().splitlines()]
        assert len(rows) == len(CASES) * len(VARIANTS) * args.rounds
        assert len({(r['case'], r['variant'], r['round']) for r in rows}) == len(rows)
        summary = []
        for case in CASES:
            values = {v: [r['ns_per_call'] for r in sorted(rows, key=lambda r: r['round'])
                          if r['case'] == case and r['variant'] == v] for v in VARIANTS}
            comparisons = {}
            for left, right in itertools.combinations(VARIANTS, 2):
                ratios = [a / b for a, b in zip(values[left], values[right])]
                first = sum(next(r['position'] for r in rows if r['case'] == case and r['round'] == n and r['variant'] == left)
                            < next(r['position'] for r in rows if r['case'] == case and r['round'] == n and r['variant'] == right)
                            for n in range(args.rounds))
                assert first in (args.rounds // 2, (args.rounds + 1) // 2)
                comparisons[left + '/' + right] = dict(median_ratio=statistics.median(ratios),
                       ratios_above_one=sum(r > 1 for r in ratios), min_ratio=min(ratios), max_ratio=max(ratios),
                       left_first_pairs=first)
            entry = dict(case=case, rounds=args.rounds,
                         median_ms={k: statistics.median(v) / 1e6 for k, v in values.items()},
                         relative_iqr={k: (statistics.quantiles(v, n=4)[2] - statistics.quantiles(v, n=4)[0]) /
                                       statistics.median(v) for k, v in values.items()}, comparisons=comparisons)
            summary.append(entry)
            print(json.dumps(entry), flush=True)
        save(args.work / 'summary.json', summary)


if __name__ == '__main__':
    main()
