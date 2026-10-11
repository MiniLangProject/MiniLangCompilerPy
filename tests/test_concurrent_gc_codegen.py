"""Check SATB leaf calls and execute native snapshot-reuse boundary helpers."""
import sys
import os
import platform
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc.asm import Asm
from mlc.codegen.codegen_memory import CodegenMemory
from mlc.codegen.codegen_concurrent_gc import CodegenConcurrentGC


class BarrierHarness(CodegenMemory):
    def __init__(self, enabled=True):
        self.asm = Asm()
        self.heap_config = {'gc_concurrent': enabled}
        self.used_helpers = set()

    def new_label_id(self):
        return 1


class ConcurrentGCCodegenTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt' and platform.machine().lower() in ('amd64', 'x86_64'),
                         'native Windows x64 snapshot helper checks')
    def test_native_reuse_bitmap_boundaries_growth_and_oom(self):
        """Execute emitted helpers against an independent bitmap/range model."""
        import ctypes
        import random

        class ReuseHarness(CodegenMemory, CodegenConcurrentGC):
            def __init__(self):
                self.asm, self.used_helpers, self.sequence = Asm(), set(), 0

            def ensure_concurrent_gc_data(self):
                pass  # Globals are materialized below, outside the RX code pages.

            def new_label_id(self):
                self.sequence += 1
                return self.sequence

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
        kernel.VirtualAlloc.restype = ctypes.c_void_p
        kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
        kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
                                         ctypes.POINTER(ctypes.c_uint32)]
        kernel.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        backend = ReuseHarness()
        a = backend.asm
        a.mark('snapshot_entry')
        a.sub_rsp_imm8(0x28)
        a.call('fn_gc_reuse_snapshot')
        a.add_rsp_imm8(0x28)
        a.ret()
        a.mark('range_entry')
        a.mov_r64_r64('rax', 'rcx')
        a.jmp('fn_gc_reuse_end')
        a.mark('contains_entry')
        a.mov_r64_r64('r10', 'rcx')
        backend.emit_gc_reuse_test('r10', 'contains_yes')
        a.xor_r32_r32('eax', 'eax')
        a.ret()
        a.mark('contains_yes')
        a.mov_rax_imm64(1)
        a.ret()
        a.mark('allocation_failure')
        a.xor_r32_r32('eax', 'eax')
        a.ret()
        a.mark('push_entry')
        a.mov_r64_r64('rax', 'rcx')
        a.jmp('fn_gc_free_push')
        a.mark('take_entry')
        a.sub_rsp_imm8(0x28)
        a.call('fn_gc_free_take')
        a.mov_rip_qword_rdx('take_block_size')
        a.mov_r64_r64('rax', 'rcx')
        a.mov_rip_qword_rax('take_actual_size')
        a.mov_r64_r64('rax', 'r8')
        a.add_rsp_imm8(0x28)
        a.ret()
        a.mark('stats_entry')
        a.sub_rsp_imm8(0x28)
        a.call('fn_gc_free_stats')
        a.mov_rip_qword_rax('stats_count')
        a.mov_rip_qword_rdx('stats_bytes')
        a.mov_r64_r64('rax', 'rcx')
        a.add_rsp_imm8(0x28)
        a.ret()
        backend.emit_concurrent_gc_reuse_snapshot()
        backend.emit_concurrent_gc_reuse_end()
        backend.emit_concurrent_gc_free_push()
        backend.emit_concurrent_gc_free_merge()
        backend.emit_concurrent_gc_free_flatten()
        backend.emit_concurrent_gc_free_take()
        backend.emit_concurrent_gc_free_stats()
        a.emit(bytes((-len(a.buf)) % 4096))
        data_offset = len(a.buf)
        names = ('heap_base', 'gc_concurrent_frontier', 'gc_reuse_min', 'gc_reuse_bits',
                 'gc_reuse_capacity', 'gc_free_head', 'iat_VirtualAlloc', 'iat_VirtualFree',
                 'heap_ptr', 'gc_free_bins', 'take_block_size', 'take_actual_size',
                 'stats_count', 'stats_bytes')
        for name in names:
            a.mark(name)
            a.emit(bytes(512 if name == 'gc_free_bins' else 8))
        code = a.finalize()
        address = kernel.VirtualAlloc(None, len(code), 0x3000, 4)
        self.assertTrue(address)
        globals_ = {name: ctypes.c_uint64.from_address(address + a.labels[name]) for name in names}
        try:
            ctypes.memmove(address, code, len(code))
            old_protect = ctypes.c_uint32()
            self.assertTrue(kernel.VirtualProtect(address, data_offset, 0x20, ctypes.byref(old_protect)))
            self.assertTrue(kernel.FlushInstructionCache(ctypes.c_void_p(-1), address, data_offset))
            snapshot = ctypes.CFUNCTYPE(None)(address + a.labels['snapshot_entry'])
            range_end = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(address + a.labels['range_entry'])
            contains = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(address + a.labels['contains_entry'])
            push = ctypes.CFUNCTYPE(None, ctypes.c_uint64)(address + a.labels['push_entry'])
            take = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)(address + a.labels['take_entry'])
            stats = ctypes.CFUNCTYPE(ctypes.c_uint64)(address + a.labels['stats_entry'])
            bins = (ctypes.c_uint64 * 64).from_address(address + a.labels['gc_free_bins'])
            def clear_bins():
                ctypes.memset(ctypes.addressof(bins), 0, ctypes.sizeof(bins))
                globals_['gc_free_head'].value = 0

            def free_ranges(base, limit):
                result = []
                for index, head in enumerate(bins):
                    node = head
                    while node:
                        self.assertLess(len(result), limit + 1, 'cyclic/duplicate bin link')
                        width = ctypes.c_uint64.from_address(node).value & ~7
                        self.assertEqual(width.bit_length() - 1, index)
                        result.append((node - base, node - base + width))
                        node = ctypes.c_uint64.from_address(node + 8).value
                self.assertEqual(len(result), len(set(result)), 'block appears in multiple bins')
                return sorted(result)
            arena = ctypes.create_string_buffer(8 * 1024 * 1024)
            base = ctypes.addressof(arena)
            globals_['heap_base'].value = base
            globals_['iat_VirtualFree'].value = ctypes.cast(kernel.VirtualFree, ctypes.c_void_p).value
            globals_['iat_VirtualAlloc'].value = address + a.labels['allocation_failure']
            globals_['gc_concurrent_frontier'].value = base + 262144
            globals_['gc_free_head'].value = base
            ctypes.c_uint64.from_address(base).value = 262144 | 1
            ctypes.c_uint64.from_address(base + 8).value = 0
            snapshot()
            self.assertEqual(globals_['gc_free_head'].value, 0)
            self.assertEqual(globals_['gc_reuse_capacity'].value, 0)
            self.assertEqual(contains(base + 262136), 0)  # No bitmap exists.

            globals_['iat_VirtualAlloc'].value = ctypes.cast(kernel.VirtualAlloc, ctypes.c_void_p).value
            rng = random.Random(9102026)
            for size in (262144, 262144, 262136, 262152, 524288, 1048576, 65536):
                clear_bins()
                globals_['gc_concurrent_frontier'].value = base + size
                globals_['heap_ptr'].value = base + size
                # Adjacent entries in a shuffled list, partial words and a final
                # free run ending exactly on a bitmap commitment boundary.
                spans = [(0, 16), (16, 16), (56, 16), (248, 264), (528, 32)]
                position = 1024
                while position < min(size // 2, 12000):
                    width = rng.randrange(2, 70) * 8
                    spans.append((position, width))
                    position += width + rng.randrange(0, 8) * 8
                spans.append((size - 4096, 4096))
                ordered = sorted(spans)
                rng.shuffle(spans)
                for index, (start, width) in enumerate(spans):
                    ctypes.c_uint64.from_address(base + start).value = width | 1
                    ctypes.c_uint64.from_address(base + start + 8).value = (
                        base + spans[index + 1][0] if index + 1 < len(spans) else 0)
                globals_['gc_free_head'].value = base + spans[0][0]
                snapshot()
                mask = 0
                runs = []
                for start, width in ordered:
                    mask |= ((1 << (width // 8)) - 1) << (start // 8)
                    if runs and runs[-1][1] == start:
                        runs[-1] = (runs[-1][0], start + width)
                    else:
                        runs.append((start, start + width))
                byte_count = ((size + 511) // 512 + 1) * 8
                bits = globals_['gc_reuse_bits'].value
                self.assertGreaterEqual(globals_['gc_reuse_capacity'].value, byte_count)
                self.assertEqual(int.from_bytes(ctypes.string_at(bits, byte_count), 'little'), mask)
                self.assertEqual(globals_['gc_free_head'].value, 0)
                self.assertEqual(free_ranges(base, len(runs)), runs)
                self.assertEqual(stats(), max(end - start for start, end in runs))
                self.assertEqual(globals_['stats_count'].value, len(runs))
                self.assertEqual(globals_['stats_bytes'].value, sum(end - start for start, end in runs))
                # Re-snapshot the same holes without mutator allocations. An
                # alternating list order changes fragmentation for no semantic
                # reason; repeated snapshots must be idempotent.
                snapshot()
                self.assertEqual(free_ranges(base, len(runs)), runs)
                for start, end in runs:
                    for offset in (start, end - 8):
                        self.assertEqual(contains(base + offset), 1)
                        self.assertEqual(range_end(base + offset), base + end)
                for offset in range(0, min(size, 16384), 8):
                    self.assertEqual(contains(base + offset), (mask >> (offset // 8)) & 1)

            # Entire-heap and empty-list snapshots cover the lower bound and
            # ensure stale exclusions cannot survive a later empty free list.
            size = 262144
            clear_bins()
            globals_['gc_concurrent_frontier'].value = base + size
            globals_['gc_free_head'].value = base
            ctypes.c_uint64.from_address(base).value = size | 1
            ctypes.c_uint64.from_address(base + 8).value = 0
            snapshot()
            self.assertEqual(range_end(base), base + size)
            self.assertEqual(contains(base), 1)
            clear_bins()
            snapshot()
            self.assertEqual(globals_['gc_reuse_min'].value, base + size)
            self.assertEqual(contains(base), 0)
            self.assertEqual(contains(base + size - 8), 0)
            self.assertEqual(ctypes.string_at(globals_['gc_reuse_bits'].value, size // 64 + 8),
                             bytes(size // 64 + 8))

            # Differential size-class selection, including nearly-full retired
            # TLABs, ordinary exact 64 KiB requests, skips within a size class,
            # exhausted bins and removal of non-head entries.
            clear_bins()
            widths = [32, 56, 4096, 8192, 65504, 65536, 1048576]
            widths += [rng.randrange(4, 2048) * 8 for _ in range(40)]
            nodes, position = [], 0
            for width in widths:
                nodes.append((base + position, width))
                ctypes.c_uint64.from_address(base + position).value = width | 1
                position += width + 32
            self.assertLess(position, len(arena))
            globals_['heap_ptr'].value = base + position
            rng.shuffle(nodes)
            model = [[] for _ in range(64)]
            for node, width in nodes:
                push(node)
                model[width.bit_length() - 1].insert(0, (node, width))
            requests = [(65536, 0), (65536, 1), (50000, 0), (48, 0), (40, 0),
                        (65536, 1), (1048576, 0), (2097152, 0)]
            requests += [(rng.randrange(4, 3000) * 8, 0) for _ in range(60)]
            requests += [(65536, 1)] * 50
            for requested, partial in requests:
                minimum = 4096 if partial else requested
                expected = None
                for group in model[minimum.bit_length() - 1:]:
                    for i, item in enumerate(group):
                        if item[1] >= minimum:
                            expected = group.pop(i)
                            break
                    if expected:
                        break
                self.assertEqual(take(requested, partial), expected[0] if expected else 0)
                self.assertEqual(globals_['take_actual_size'].value,
                                 min(requested, expected[1]) if expected else requested)
                if expected:
                    self.assertEqual(globals_['take_block_size'].value, expected[1])
                remaining = [item for group in model for item in group]
                self.assertEqual(stats(), max((w for _, w in remaining), default=0))
                self.assertEqual(globals_['stats_count'].value, len(remaining))
                self.assertEqual(globals_['stats_bytes'].value, sum(w for _, w in remaining))

            # Corrupt diagnostic lists must terminate and return zero, including
            # cycles. The cap derives from the heap's minimum possible block size
            # instead of falsely treating >200,000 legitimate holes as corrupt.
            clear_bins()
            bins[5] = base - 8
            self.assertEqual(stats(), 0)
            self.assertEqual(globals_['stats_count'].value, 0)
            bins[5] = 2**64 - 8  # Header-end arithmetic must not wrap into bounds.
            self.assertEqual(stats(), 0)
            self.assertEqual(globals_['stats_bytes'].value, 0)
            bins[5] = base
            ctypes.c_uint64.from_address(base).value = 33
            ctypes.c_uint64.from_address(base + 8).value = base
            self.assertEqual(stats(), 0)
            self.assertEqual(globals_['stats_bytes'].value, 0)
            clear_bins()
            block_count = 200001
            words = (ctypes.c_uint64 * (block_count * 2)).from_address(base)
            for i in range(block_count):
                words[i * 2] = 17
                words[i * 2 + 1] = base + (i + 1) * 16 if i + 1 < block_count else 0
            bins[4] = base
            globals_['heap_ptr'].value = base + block_count * 16
            self.assertEqual(stats(), 16)
            self.assertEqual(globals_['stats_count'].value, block_count)
            self.assertEqual(globals_['stats_bytes'].value, block_count * 16)
            clear_bins()

            # Reserve, but do not commit, a large fake heap. A free header above
            # 2 GiB checks 64-bit offsets without physically allocating 2 GiB.
            sparse = kernel.VirtualAlloc(None, 8 * 1024**3, 0x2000, 4)
            self.assertTrue(sparse)
            try:
                header = sparse + 2 * 1024**3
                self.assertEqual(kernel.VirtualAlloc(header, 4096, 0x1000, 4), header)
                ctypes.c_uint64.from_address(header).value = 8192 | 1
                ctypes.c_uint64.from_address(header + 8).value = 0
                globals_['heap_base'].value = sparse
                clear_bins()
                globals_['gc_concurrent_frontier'].value = header + 8192
                globals_['gc_free_head'].value = header
                snapshot()
                self.assertEqual(contains(header - 8), 0)
                self.assertEqual(contains(header), 1)
                self.assertEqual(range_end(header), header + 8192)
                self.assertEqual(range_end(header + 8184), header + 8192)
                # Class indices above 31 use the high word; no truncation of
                # requested sizes, headers or statistics is permitted.
                clear_bins()
                width = 4 * 1024**3 + 8192
                ctypes.c_uint64.from_address(header).value = width | 1
                globals_['heap_ptr'].value = header + width
                push(header)
                self.assertEqual(stats(), width)
                self.assertEqual(globals_['stats_bytes'].value, width)
                self.assertEqual(take(4 * 1024**3, 0), header)
                self.assertEqual(globals_['take_actual_size'].value, 4 * 1024**3)
            finally:
                globals_['heap_base'].value = base
                clear_bins()
                kernel.VirtualFree(sparse, 0, 0x8000)

            # A later growth failure must retain the old metadata allocation,
            # disable stale bits, and fall back to freezing the free list.
            old_bits = globals_['gc_reuse_bits'].value
            old_capacity = globals_['gc_reuse_capacity'].value
            ctypes.c_uint64.from_address(base).value = 4097
            push(base)
            globals_['gc_concurrent_frontier'].value = base + old_capacity * 64 + 512
            globals_['iat_VirtualAlloc'].value = address + a.labels['allocation_failure']
            snapshot()
            self.assertEqual(globals_['gc_reuse_bits'].value, old_bits)
            self.assertEqual(globals_['gc_reuse_capacity'].value, old_capacity)
            self.assertEqual(globals_['gc_free_head'].value, 0)
            self.assertFalse(any(bins), 'OOM fallback must withhold every size class')
            self.assertEqual(contains(base + old_capacity * 64), 0)
        finally:
            if globals_['gc_reuse_bits'].value:
                kernel.VirtualFree(globals_['gc_reuse_bits'].value, 0, 0x8000)
            kernel.VirtualFree(address, 0, 0x8000)

    def test_leaf_barriers_preserve_spill_hook(self):
        for method, arguments in (
            ('emit_gc_write_barrier', ('r11', 8)),
            ('emit_gc_write_barrier_index', ('r11', 'r10', 8)),
            ('emit_gc_write_barrier_range', ()),
        ):
            with self.subTest(method=method):
                backend = BarrierHarness()
                spills, calls = [], []
                callback = lambda: spills.append('spill')
                backend.asm._before_call = callback
                backend.asm._on_call_label = calls.append
                getattr(backend, method)(*arguments)
                self.assertEqual(spills, [])
                self.assertEqual(calls, ['fn_gc_satb_record'])
                self.assertIs(backend.asm._before_call, callback)
                backend.asm.call('ordinary_call')
                self.assertEqual(spills, ['spill'])

    def test_disabled_barriers_emit_nothing(self):
        backend = BarrierHarness(enabled=False)
        backend.emit_gc_write_barrier('r11', 8)
        backend.emit_gc_write_barrier_index('r11', 'r10', 8)
        backend.emit_gc_write_barrier_range()
        self.assertEqual(backend.asm.finalize(), b'')
        self.assertEqual(backend.used_helpers, set())

    def test_spill_hook_restored_after_failed_emission(self):
        backend = BarrierHarness()
        callback = lambda: None
        backend.asm._before_call = callback
        def fail(_label):
            raise RuntimeError('emitter failure')
        backend.asm.call = fail
        with self.assertRaises(RuntimeError):
            backend._emit_gc_satb_leaf_call()
        self.assertIs(backend.asm._before_call, callback)


if __name__ == '__main__':
    unittest.main(verbosity=2)
