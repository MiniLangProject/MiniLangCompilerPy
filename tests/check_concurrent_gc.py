"""Windows concurrent-GC correctness, pipeline parity, and rejection checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def invoke(command, expected=0, timeout=120):
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                            timeout=timeout, creationflags=flags)
    assert result.returncode == expected, (command, result.returncode,
                                           result.stdout[-3000:], result.stderr[-3000:])
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('compiler', type=Path)
    parser.add_argument('--reference', type=Path, help='also check byte parity with this compiler')
    parser.add_argument('--linux-reference', type=Path, help='Windows only: Linux ML compiler run through WSL Ubuntu')
    parser.add_argument('--output', type=Path, help='save the executed image hashes')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('This runtime matrix requires Windows with WSL Ubuntu')
    root = Path(__file__).resolve().parents[1]
    def command(path):
        path = path.resolve()
        return [sys.executable, str(path)] if path.suffix == '.py' else [str(path)]

    compiler = command(args.compiler)
    peers = []
    if args.reference:
        peers.append(('reference', command(args.reference), False))
    linux_paths = {}
    def path_for(path, linux=False):
        path = Path(path).resolve().as_posix()
        if not linux:
            return path
        if path not in linux_paths:
            linux_paths[path] = invoke(['wsl', '-d', 'Ubuntu', '--', 'wslpath', '-a', '-u', path]).strip()
        return linux_paths[path]
    if args.linux_reference:
        if os.name != 'nt':
            parser.error('--linux-reference requires Windows with WSL Ubuntu')
        peers.append(('linux-ml', ['wsl', '-d', 'Ubuntu', '--', path_for(args.linux_reference, True)], True))
    rows = []
    cases = [
        ('gc_concurrent.ml', [], [], 'GC CONCURRENT [OK]'),
        ('gc_concurrent.ml', ['--gc-satb-limit', '64'], ['overflow'], 'GC CONCURRENT [OK]'),
        ('gc_concurrent_pressure.ml', ['--heap-reserve', '64m', '--heap-commit', '32m'], [], 'GC CONCURRENT PRESSURE [OK]'),
        ('gc_thread_lifetime.ml', [], [], 'GC THREAD LIFETIME [OK]'),
        ('gc_handoff_lifetime.ml', [], [], 'GC HANDOFF LIFETIME [OK]'),
        ('gc_reference_write_roots.ml', [], [], '[OK]'),
        ('gc_nested_graph_roots.ml', [], [], '[OK]'),
        ('gc_box_float_safepoint.ml', [], [], '[OK]'),
        ('gc_float_call_roots.ml', [], [], '[OK]'),
        ('gc_back_to_back_safepoint.ml', [], [], '[OK]'),
        ('tlab_shared_heap.ml', [], [], '[OK]'),
        ('thread_lifecycle_races.ml', [], [], '[OK]'),
        ('thread_pool.ml', [], [], '[OK]'),
        ('memory_management.ml', [], [], 'MEMORY MANAGEMENT [OK]'),
        ('memory_policy.ml', ['--gc-limit', '1m'], ['fixed'], 'MEMORY POLICY [OK]'),
        ('memory_policy.ml', ['--no-gc-periodic'], ['disabled'], 'MEMORY POLICY [OK]'),
        ('memory_heap_ceiling.ml', ['--heap-reserve', '40m', '--heap-commit', '32m'], [], 'MEMORY CEILING [OK]'),
        ('heap_growth_precedes_gc.ml', ['--heap-commit', '8m', '--gc-limit', '1g'], [], '[OK]'),
    ]
    with tempfile.TemporaryDirectory(prefix='ml_concurrent_gc_') as folder:
        folder = Path(folder)
        for index, (fixture, flags, arguments, marker) in enumerate(cases):
            images = []
            for pipeline in ('--no-object-pipeline', '--object-pipeline'):
                image = folder / f'{index}-{pipeline[2:]}.exe'
                invoke([*compiler, str(root / 'tests' / fixture), str(image),
                        '-I', str(root), '--gc-concurrent', pipeline, *flags])
                images.append(image.read_bytes())
                output = invoke([str(image), *arguments])
                assert marker in output, (fixture, output)
                for host, peer_command, linux in peers:
                    peer = folder / f'{index}-{pipeline[2:]}-{host}.exe'
                    invoke([*peer_command, path_for(root / 'tests' / fixture, linux), path_for(peer, linux),
                            '-I', path_for(root, linux), '--target', 'windows-x64', '--gc-concurrent', pipeline, *flags])
                    assert peer.read_bytes() == images[-1], f'Compiler mismatch: {fixture} {flags} {pipeline}'
                    assert marker in invoke([str(peer), *arguments])
                rows.append(dict(fixture=fixture, flags=flags, pipeline=pipeline,
                                 sha256=hashlib.sha256(images[-1]).hexdigest(), size=len(images[-1])))
            assert images[0] == images[1], f'Pipeline mismatch: {fixture} {flags}'
            print(f'[OK] {fixture} {flags}: runtime and normal/object parity', flush=True)
        # The API also works without the option, including native Linux output.
        # Compare each target independently: PE and ELF are not the same format.
        for target in ('windows-x64', 'linux-x64'):
            fallback_bytes = None
            for pipeline in ('--no-object-pipeline', '--object-pipeline'):
                for host, peer_command, linux in [('primary', compiler, False), *peers]:
                    fallback = folder / f'fallback-{target}-{pipeline[2:]}-{host}'
                    invoke([*peer_command, path_for(root / 'tests/gc_async_fallback.ml', linux),
                            path_for(fallback, linux), '-I', path_for(root, linux), '--target', target, pipeline])
                    if fallback_bytes is None:
                        fallback_bytes = fallback.read_bytes()
                    assert fallback.read_bytes() == fallback_bytes, f'Fallback mismatch: {target} {host}'
                    if target == 'windows-x64':
                        output = invoke([str(fallback)])
                    else:
                        output = invoke(['wsl', '-d', 'Ubuntu', '--', path_for(fallback, True)])
                    assert 'GC ASYNC FALLBACK [OK]' in output
        bad_arity = folder / 'bad-arity.ml'
        bad_arity.write_text('gc_collect_async(1)\n', encoding='utf-8')
        # Capacity clamps and disabled-option handling must not alter the image.
        capacity_source = folder / 'capacity.ml'
        capacity_source.write_text('print typeof(gc_stat(16))\n', encoding='utf-8')
        for concurrent, limits in ((True, ('1', '64')), (True, ('64m', '1t')),
                                   (False, ('1', '1t'))):
            expected_bytes = None
            for limit in limits:
                for host, peer_command, linux in [('primary', compiler, False), *peers]:
                    for pipeline in ('--no-object-pipeline', '--object-pipeline'):
                        capacity = folder / 'capacity.exe'
                        invoke([*peer_command, path_for(capacity_source, linux), path_for(capacity, linux),
                                '--target', 'windows-x64', pipeline, '--gc-satb-limit', limit,
                                *(['--gc-concurrent'] if concurrent else [])])
                        if expected_bytes is None:
                            expected_bytes = capacity.read_bytes()
                        assert capacity.read_bytes() == expected_bytes, f'SATB clamp mismatch: {concurrent} {limit} {host}'
                        assert invoke([str(capacity)]).strip() == ('int' if concurrent else 'void')
        for host, peer_command, linux in [('primary', compiler, False), *peers]:
            rejected = folder / f'rejected-{host}.exe'
            output = invoke([*peer_command, path_for(bad_arity, linux), path_for(rejected, linux)], expected=2)
            assert 'gc_collect_async' in output and '0 arguments' in output, output
            for flags, marker in [(['--target', 'linux-x64'], 'requires windows-x64'),
                                  (['--heap-shrink'], 'cannot be combined')]:
                output = invoke([*peer_command, path_for(root / 'tests/gc_concurrent.ml', linux),
                                 path_for(rejected, linux), '--gc-concurrent', *flags], expected=2)
                assert marker in output, output
            for invalid in ('0', '-1', '1.5m', '9' * 100, '４０m'):
                invoke([*peer_command, path_for(bad_arity, linux), path_for(rejected, linux),
                        '--gc-satb-limit', invalid], expected=2)
            assert not rejected.exists(), 'Rejected command wrote an image'
        print('CONCURRENT GC MATRIX [OK]', flush=True)
    if args.output:
        args.output.write_text(json.dumps(dict(images=rows, comparedHosts=1 + len(peers),
                                              fallbackImages=4 * (1 + len(peers)),
                                              capacityImages=12 * (1 + len(peers))), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
