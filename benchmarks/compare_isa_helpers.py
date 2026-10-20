"""Alternate saved/current native helpers, excluding Python from inner loops.

Use tests/native_runtime_harness.py before editing the emitter to save an image.
This is a hot-buffer microbenchmark, not an application FPS/throughput claim.
"""
import argparse
import ctypes
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
from native_runtime_harness import NativeRuntime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=7)
    parser.add_argument('--dispatch', action='store_true', help='Also compare masked REP against vector copy')
    parser.add_argument('--cpu', type=int, help='Pin this process to a logical CPU')
    parser.add_argument('--helpers', nargs='+', default=['copy_bytes', 'fill_bytes', 'crc32_update_raw'],
                        choices=['copy_bytes', 'fill_bytes', 'crc32_update_raw'])
    parser.add_argument('--layout', choices=['unaligned', 'aligned', 'adjacent'], default='unaligned')
    parser.add_argument('--sizes', nargs='+', type=int)
    args = parser.parse_args()
    if args.rounds < 3:
        parser.error('at least three rounds are required')
    if args.cpu is not None:
        if args.cpu < 0:
            parser.error('CPU must be nonnegative')
        if os.name == 'nt':
            if args.cpu >= ctypes.sizeof(ctypes.c_size_t) * 8:
                parser.error('CPU index exceeds the current Windows processor group')
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.GetCurrentProcess.restype = ctypes.c_void_p
            kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            if not kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(), 1 << args.cpu):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.sched_setaffinity(0, {args.cpu})
    old = NativeRuntime(json.loads(args.baseline.read_text()))
    new = NativeRuntime()
    capacity = 4 * 1024 * 1024 + 128
    source = ctypes.create_string_buffer(bytes(range(256)) * (2 * capacity // 256 + 1))
    target = ctypes.create_string_buffer(capacity)
    rows = []
    variants = [('before', old, -1), ('after', new, -1)]
    if args.dispatch:
        variants += [('rep', new, 1), ('vector', new, 127)]
    for name in args.helpers:
        for size in (args.sizes or (8, 16, 32, 33, 63, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 1048576, 4194304)):
            if not 1 <= size <= 4194304:
                parser.error('sizes must be between 1 and 4194304')
            # Non-aligned addresses exercise real buffer/subrange callers.
            src, dst = ctypes.addressof(source) + 3, ctypes.addressof(target) + 5
            if name == 'copy_bytes' and args.layout != 'unaligned':
                src = (ctypes.addressof(source) + 63) & ~63
                dst = src + size if args.layout == 'adjacent' else (ctypes.addressof(target) + 63) & ~63
            params = (dst, src, size) if name == 'copy_bytes' else ((dst, size, 165) if name == 'fill_bytes' else (0, src, size))
            candidates = variants if name == 'copy_bytes' else variants[:2]
            samples, iterations = {}, {}
            for label, runtime, mask in candidates:
                runtime.mask(mask)
                fun = runtime.call('repeat_' + name, 4)
                count = max(32, min(10000, 1048576 // size))
                start = time.perf_counter_ns()
                fun(*params, count)
                elapsed = time.perf_counter_ns() - start
                iterations[label] = max(8, min(20000000, int(count * 20000000 / max(elapsed, 1))))
                samples[label] = []
            for round_ in range(args.rounds):
                for label, runtime, mask in (candidates if round_ % 2 == 0 else candidates[::-1]):
                    runtime.mask(mask)
                    fun = runtime.call('repeat_' + name, 4)
                    count = iterations[label]
                    start = time.perf_counter_ns()
                    fun(*params, count)
                    elapsed = time.perf_counter_ns() - start
                    samples[label].append(elapsed / count)
            medians = {key: statistics.median(values) for key, values in samples.items()}
            row = dict(helper=name, size=size, median_ns=medians, samples_ns=samples, iterations=iterations)
            rows.append(row)
            print(name, size, ' '.join(f'{key}={value:.2f}ns' for key, value in medians.items()), flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(platform=platform.platform(), cpu=platform.processor(),
        detected=new.global_('cpu_features_detected').value, cpu_affinity=args.cpu, layout=args.layout,
        rounds=args.rounds, rows=rows), indent=2))
    old.close()
    new.close()


if __name__ == '__main__':
    main()
