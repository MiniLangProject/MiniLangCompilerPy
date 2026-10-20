"""Isolated CMOV / SSSE3 Base64 experiments, NOT enabled compiler passes.

Base64 measures only full 12-to-16-byte blocks, excluding allocation, whitespace,
padding, validation and string conversion. Results cannot be treated as the
speedup of std.encoding.base64. Scalar/SIMD outputs are independently checked.
The vector repacking uses the algorithm described in arXiv:1704.00605.
"""
import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import random
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
from native_runtime_harness import Harness, NativeRuntime
from test_isa_runtime import GuardedPage


def image():
    h = Harness()
    a = h.asm
    h.emit_cpu_init_function()
    a.mark('fn_ssse3')
    a.push_reg('rbx')
    a.mov_r32_imm32('eax', 1)
    a.cpuid()
    a.mov_r32_r32('eax', 'ecx')
    a.shr_r32_imm8('eax', 9)
    a.and_r32_imm('eax', 1)
    a.pop_reg('rbx')
    a.ret()
    for variant in ('branch', 'cmov'):
        a.mark('fn_' + variant)
        a.xor_r32_r32('eax', 'eax')
        a.test_r64_r64('r8', 'r8')
        a.jcc('e', variant + '_done')
        a.mark(variant + '_loop')
        a.mov_r64_membase_disp('r9', 'rcx', 0)
        a.mov_r64_membase_disp('r10', 'rdx', 0)
        a.cmp_r64_r64('r9', 'r10')
        if variant == 'branch':
            a.jcc('le', 'keep')
            a.mov_r64_r64('r9', 'r10')
            a.mark('keep')
        else:
            a.emit(bytes.fromhex('4d0f4fca'))  # CMOVG r9,r10: baseline x64.
        a.add_r64_r64('rax', 'r9')
        a.add_r64_imm('rcx', 8)
        a.add_r64_imm('rdx', 8)
        a.dec_r64('r8')
        a.jcc('ne', variant + '_loop')
        a.mark(variant + '_done')
        a.ret()

    constants = [
        bytes([1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10]),
        bytes.fromhex('00fcc00f') * 4, bytes.fromhex('40000004') * 4,
        bytes.fromhex('f0033f00') * 4, bytes.fromhex('10000001') * 4,
        bytes([51]) * 16, bytes([25]) * 16,
        bytes([65, 71] + [252] * 10 + [237, 240, 0, 0]),
    ]
    for index, value in enumerate(constants):
        h.rdata.add_bytes('b64_' + str(index), value)
    h.rdata.add_bytes('alphabet', b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')

    def sse(opcode, dst, src):
        # Prototype-only encodings, deliberately outside the production emitter.
        a.emit(b'\x66\x0f' + bytes.fromhex(opcode) + bytes([0xC0 | (dst << 3) | src]))

    for variant in ('scalar', 'shuffle'):
        a.mark('fn_' + variant)
        a.mov_r64_r64('r9', 'rdx')
        a.lea_r11_rip('b64_0' if variant == 'shuffle' else 'alphabet')
        a.mark(variant + '_loop')
        a.cmp_r64_imm('r8', 16)
        a.jcc('b', variant + '_done')
        if variant == 'shuffle':
            a.movdqu_xmm_membase_disp('xmm0', 'rdx', 0)
            a.movdqu_xmm_membase_disp('xmm1', 'r11', 0)
            sse('3800', 0, 1)  # PSHUFB
            a.movapd_xmm_xmm('xmm2', 'xmm0')
            for index, dst, opcode in [(1, 0, 'db'), (2, 0, 'e4'), (3, 2, 'db'), (4, 2, 'd5')]:
                a.movdqu_xmm_membase_disp('xmm1', 'r11', index * 16)
                sse(opcode, dst, 1)  # PAND, PMULHUW, PAND, PMULLW
            sse('eb', 0, 2)  # POR -> sixteen independent sextets.
            a.movapd_xmm_xmm('xmm2', 'xmm0')
            a.movdqu_xmm_membase_disp('xmm1', 'r11', 5 * 16)
            sse('d8', 2, 1)  # Saturating subtract 51.
            a.movapd_xmm_xmm('xmm3', 'xmm0')
            a.movdqu_xmm_membase_disp('xmm1', 'r11', 6 * 16)
            sse('64', 3, 1)  # PCMPGTB sextet,25
            sse('f8', 2, 3)  # Subtract FF -> add one to the table index.
            a.movdqu_xmm_membase_disp('xmm1', 'r11', 7 * 16)
            sse('3800', 1, 2)
            sse('fc', 0, 1)  # Add the appropriate ASCII bias.
            a.movdqu_membase_disp_xmm('rcx', 0, 'xmm0')
        else:
            for group in range(4):
                # Each 4-byte load is bounded by remaining >=16, including the
                # fourth group at offset 9. Ignore the fourth input byte.
                a.mov_r32_membase_disp('r10d', 'rdx', group * 3)
                for digit in range(4):
                    a.mov_r32_r32('eax', 'r10d')
                    if digit == 0:
                        a.shr_r32_imm8('eax', 2)
                    elif digit == 1:
                        a.and_r32_imm('eax', 3)
                        a.shl_r32_imm8('eax', 4)
                        a.mov_r32_r32('r8d', 'r10d')
                        a.shr_r32_imm8('r8d', 12)
                        a.and_r32_imm('r8d', 15)
                        a.or_r32_r32('eax', 'r8d')
                    elif digit == 2:
                        a.shr_r32_imm8('eax', 8)
                        a.and_r32_imm('eax', 15)
                        a.shl_r32_imm8('eax', 2)
                        a.mov_r32_r32('r8d', 'r10d')
                        a.shr_r32_imm8('r8d', 22)
                        a.and_r32_imm('r8d', 3)
                        a.or_r32_r32('eax', 'r8d')
                    else:
                        a.shr_r32_imm8('eax', 16)
                    a.and_r32_imm('eax', 63)
                    a.lea_r64_mem_bis('rax', 'r11', 'rax', 1, 0)
                    a.mov_r8_membase_disp('al', 'rax', 0)
                    a.mov_membase_disp_r8('rcx', group * 4 + digit, 'al')
        a.add_r64_imm('rdx', 12)
        a.add_r64_imm('rcx', 16)
        # Scalar scratch needs R8, so recover the remaining length from the
        # saved end pointer established by the entry shim below.
        a.mov_r64_r64('r8', 'rdi')
        a.sub_r64_r64('r8', 'rdx')
        a.jmp(variant + '_loop')
        a.mark(variant + '_done')
        a.mov_r64_r64('rax', 'rdx')
        a.sub_r64_r64('rax', 'r9')
        a.ret()
        a.mark('fn_' + variant + '_entry')
        a.push_reg('rdi')
        a.lea_r64_mem_bis('rdi', 'rdx', 'r8', 1, 0)
        a.sub_rsp_imm8(32)
        a.call('fn_' + variant)
        a.add_rsp_imm8(32)
        a.pop_reg('rdi')
        a.ret()
    for name in ('cpu_init', 'ssse3', 'branch', 'cmov', 'scalar_entry', 'shuffle_entry'):
        a.mark('sysv_fn_' + name)
        a.mov_r64_r64('r8', 'rdx')
        a.mov_r64_r64('rdx', 'rsi')
        a.mov_r64_r64('rcx', 'rdi')
        a.jmp('fn_' + name)
    a.emit(bytes((-len(a.buf)) % 4096))
    data_offset = len(a.buf)
    for name in ('cpu_features_detected', 'cpu_features_active', 'cpu_has_avx2'):
        a.mark(name)
        a.emit(bytes(8))
    for name, offset in h.rdata.labels.items():
        a.labels[name] = len(a.buf) + offset
    a.emit(h.rdata.data)
    return dict(code=a.finalize().hex(), labels=a.labels, data_offset=data_offset)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cpu', type=int)
    args = parser.parse_args()
    if args.cpu is not None:
        if os.name == 'nt':
            if not 0 <= args.cpu < ctypes.sizeof(ctypes.c_size_t) * 8:
                parser.error('CPU outside the current processor group')
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.GetCurrentProcess.restype = ctypes.c_void_p
            kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            if not kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(), 1 << args.cpu):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.sched_setaffinity(0, {args.cpu})
    runtime = NativeRuntime(image())
    rng = random.Random(20)
    count = 131072
    rows = []
    for pattern in ('predictable', 'random'):
        left = [1] * count if pattern == 'predictable' else [rng.randrange(10000) for _ in range(count)]
        right = [5000] * count
        a = (ctypes.c_int64 * count)(*left)
        b = (ctypes.c_int64 * count)(*right)
        expected = sum(min(x, y) for x, y in zip(left, right))
        samples = {kind: [] for kind in ('branch', 'cmov')}
        for round_ in range(15):
            for kind in (list(samples) if round_ % 2 == 0 else list(samples)[::-1]):
                fun = runtime.call('fn_' + kind, 3)
                start = time.perf_counter_ns()
                result = fun(ctypes.addressof(a), ctypes.addressof(b), count)
                elapsed = time.perf_counter_ns() - start
                assert result == expected, (kind, result, expected)
                samples[kind].append(elapsed / count)
        rows.append(dict(case=pattern, ns_per_element={k: statistics.median(v) for k, v in samples.items()}, samples=samples))
    if runtime.call('fn_ssse3')():
        data = rng.randbytes(131088)
        source = ctypes.create_string_buffer(data)
        output = ctypes.create_string_buffer(len(data) * 2)
        guarded = GuardedPage()
        try:
            ctypes.memmove(guarded.address, data, 4096)
            for size in range(513):
                consumed = runtime.call('fn_shuffle_entry', 3)(
                    ctypes.addressof(output), guarded.address + 4096 - size, size)
                assert output.raw[:consumed // 3 * 4] == base64.b64encode(data[4096 - size:4096 - size + consumed])
        finally:
            guarded.close()
        for size in range(1025):
            for variant in ('scalar', 'shuffle'):
                consumed = runtime.call('fn_' + variant + '_entry', 3)(ctypes.addressof(output), ctypes.addressof(source), size)
                assert consumed == max(0, (size - 4) // 12) * 12
                assert output.raw[:consumed // 3 * 4] == base64.b64encode(data[:consumed]), (variant, size)
        samples = {kind: [] for kind in ('scalar', 'shuffle')}
        for round_ in range(15):
            for kind in (list(samples) if round_ % 2 == 0 else list(samples)[::-1]):
                fun = runtime.call('fn_' + kind + '_entry', 3)
                start = time.perf_counter_ns()
                consumed = fun(ctypes.addressof(output), ctypes.addressof(source), len(data))
                elapsed = time.perf_counter_ns() - start
                assert output.raw[:consumed // 3 * 4] == base64.b64encode(data[:consumed])
                samples[kind].append(elapsed / consumed)
        rows.append(dict(case='base64-blocks-only', ns_per_byte={k: statistics.median(v) for k, v in samples.items()}, samples=samples))
    args.output.write_text(json.dumps(rows, indent=2))
    for row in rows:
        print({k: v for k, v in row.items() if k != 'samples'})
    runtime.close()


if __name__ == '__main__':
    main()
