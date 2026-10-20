"""Differential native-runtime tests, including page boundaries and fallbacks."""
import ctypes
import os
import platform
import random
import unittest
import zlib

if __package__:
    from .native_runtime_harness import NativeRuntime
else:
    from native_runtime_harness import NativeRuntime


class GuardedPage:
    """Readable/writable pages surrounded by inaccessible pages."""
    def __init__(self, pages=1):
        self.size = pages * 4096
        self.total = self.size + 8192
        if os.name == 'nt':
            self.api = ctypes.WinDLL('kernel32', use_last_error=True)
            self.api.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
            self.api.VirtualAlloc.restype = ctypes.c_void_p
            self.api.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p]
            self.api.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
            self.base = self.api.VirtualAlloc(None, self.total, 0x3000, 1)
            old = ctypes.c_uint32()
            if not self.base or not self.api.VirtualProtect(self.base + 4096, self.size, 4, ctypes.byref(old)):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            self.api = ctypes.CDLL(None, use_errno=True)
            self.api.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
            self.api.mmap.restype = ctypes.c_void_p
            self.api.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            self.api.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self.base = self.api.mmap(None, self.total, 0, 0x22, -1, 0)
            if self.base == ctypes.c_void_p(-1).value or self.api.mprotect(self.base + 4096, self.size, 3):
                raise OSError(ctypes.get_errno(), 'guard page allocation')
        self.address = self.base + 4096

    def close(self):
        if os.name == 'nt':
            self.api.VirtualFree(self.base, 0, 0x8000)
        else:
            self.api.munmap(self.base, self.total)


@unittest.skipUnless(platform.machine().lower() in ('amd64', 'x86_64')
                     and platform.system() in ('Windows', 'Linux'), 'requires Windows/Linux x86-64')
class NativeISATests(unittest.TestCase):
    def setUp(self):
        self.runtime = NativeRuntime()
        self.addCleanup(self.runtime.close)

    def test_copy_fill_all_small_lengths_and_alignments(self):
        copy = self.runtime.call('fn_copy_bytes', 3)
        fill = self.runtime.call('fn_fill_bytes', 3)
        source = bytes(range(256)) * 34
        src = ctypes.create_string_buffer(source)
        dst = ctypes.create_string_buffer(len(source))
        sizes = list(range(513)) + [1023, 1024, 1025, 2047, 2048, 4095, 4096, 4097, 8191]
        for mask in (0, 1, 127, -1):
            self.runtime.mask(mask)
            for size in sizes:
                for alignment in (0, 1, 3, 7, 15, 16, 31):
                    start, offset = 32 + alignment, 35 + alignment
                    ctypes.memset(ctypes.addressof(dst), 0x5A, len(source))
                    copy(ctypes.addressof(dst) + start, ctypes.addressof(src) + offset, size)
                    expected = b'Z' * start + source[offset:offset + size] + b'Z' * (len(source) - start - size)
                    self.assertEqual(dst.raw, expected, ('copy', mask, size, alignment))
                    fill(ctypes.addressof(dst) + start, size, 0xA5)
                    expected = b'Z' * start + b'\xA5' * size + b'Z' * (len(source) - start - size)
                    self.assertEqual(dst.raw, expected, ('fill', mask, size, alignment))

    def test_crc_seeded_random_ranges_and_incremental_splits(self):
        crc = self.runtime.call('fn_crc32_update_raw', 3)
        rng = random.Random(20261020)
        source = rng.randbytes(66000)
        src = ctypes.create_string_buffer(source)
        for mask in (0, -1):
            self.runtime.mask(mask)
            self.assertEqual(crc(0x12345678, 0, 0), 0x12345678)
            for size in list(range(1025)) + [4095, 4096, 4097, 65535, 65536]:
                offset = rng.randrange(32)
                seed = rng.getrandbits(32)
                expected = zlib.crc32(source[offset:offset + size], seed)
                self.assertEqual(crc(seed, ctypes.addressof(src) + offset, size), expected, (mask, size, seed))
                split = rng.randrange(size + 1)
                partial = crc(seed, ctypes.addressof(src) + offset, split)
                self.assertEqual(crc(partial, ctypes.addressof(src) + offset + split, size - split), expected)

    def test_guard_pages_no_read_or_write_outside_ranges(self):
        src, dst = GuardedPage(), GuardedPage()
        self.addCleanup(src.close)
        self.addCleanup(dst.close)
        data = random.Random(17).randbytes(4096)
        ctypes.memmove(src.address, data, len(data))
        copy = self.runtime.call('fn_copy_bytes', 3)
        fill = self.runtime.call('fn_fill_bytes', 3)
        crc = self.runtime.call('fn_crc32_update_raw', 3)
        for mask in (0, 127, -1):
            self.runtime.mask(mask)
            for size in list(range(513)) + [1023, 1024, 1025, 2047, 2048, 4095, 4096]:
                for offset in (0, 4096 - size):
                    ctypes.memset(dst.address, 0x5A, 4096)
                    copy(dst.address + offset, src.address + offset, size)
                    self.assertEqual(ctypes.string_at(dst.address + offset, size), data[offset:offset + size])
                    fill(dst.address + offset, size, 0)
                    self.assertEqual(ctypes.string_at(dst.address + offset, size), bytes(size))
                    self.assertEqual(crc(0, src.address + offset, size), zlib.crc32(data[offset:offset + size]))
            copy(0, 0, 0)
            fill(0, 0, 165)

    def test_baseline_and_extended_opcode_encodings(self):
        from mlc.asm import Asm
        vectors = [
            ('bsf_r64_r64', ('rax', 'rcx'), '480fbcc1'),
            ('bsf_r64_r64', ('r9', 'r10'), '4d0fbcca'),
            ('bsr_r64_r64', ('rdx', 'rax'), '480fbdd0'),
            ('bsr_r64_r64', ('r15', 'r8'), '4d0fbdf8'),
            ('pclmulqdq_xmm_xmm_imm8', ('xmm0', 'xmm3', 16), '660f3a44c310'),
            ('pclmulqdq_xmm_xmm_imm8', ('xmm9', 'xmm14', 1), '66450f3a44ce01'),
            ('pand_xmm_xmm', ('xmm9', 'xmm14'), '66450fdbce'),
            ('psrldq_xmm_imm8', ('xmm9', 8), '66410f73d908'),
            ('pslldq_xmm_imm8', ('xmm9', 4), '66410f73f904'),
        ]
        for name, args, expected in vectors:
            assembler = Asm()
            getattr(assembler, name)(*args)
            self.assertEqual(assembler.finalize().hex(), expected, name)
        for name in ('bsf_r64_r64', 'bsr_r64_r64'):
            with self.assertRaises(ValueError):
                getattr(Asm(), name)('eax', 'rcx')
            with self.assertRaises(ValueError):
                getattr(Asm(), name)('rax', 'ecx')
        for value in (-1, 256):
            with self.assertRaises(ValueError):
                Asm().pclmulqdq_xmm_xmm_imm8('xmm0', 'xmm1', value)
            with self.assertRaises(ValueError):
                Asm().psrldq_xmm_imm8('xmm0', value)

    def test_large_dispatch_boundaries_at_guard_pages(self):
        src, dst = GuardedPage(32), GuardedPage(32)
        self.addCleanup(src.close)
        self.addCleanup(dst.close)
        data = random.Random(912).randbytes(src.size)
        ctypes.memmove(src.address, data, len(data))
        copy, fill, crc = [self.runtime.call(name, 3) for name in
                           ('fn_copy_bytes', 'fn_fill_bytes', 'fn_crc32_update_raw')]
        for mask in (0, 127, -1):
            self.runtime.mask(mask)
            for size in (16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537, 131071, 131072):
                for offset in (0, src.size - size):
                    ctypes.memset(dst.address, 0x5A, dst.size)
                    copy(dst.address + offset, src.address + offset, size)
                    expected = b'Z' * offset + data[offset:offset + size] + b'Z' * (dst.size - offset - size)
                    self.assertEqual(ctypes.string_at(dst.address, dst.size), expected, ('copy', mask, size))
                    fill(dst.address + offset, size, 0xA5)
                    expected = b'Z' * offset + b'\xA5' * size + b'Z' * (dst.size - offset - size)
                    self.assertEqual(ctypes.string_at(dst.address, dst.size), expected, ('fill', mask, size))
                    self.assertEqual(crc(0xDEADBEEF, src.address + offset, size),
                                     zlib.crc32(data[offset:offset + size], 0xDEADBEEF))


    def test_full_width_bit_scan_positions(self):
        forward = self.runtime.call('fn_bsf', 1)
        reverse = self.runtime.call('fn_bsr', 1)
        self.assertEqual(forward(0), 64)  # The caller guards undefined zero scans.
        self.assertEqual(reverse(0), 64)
        for low in range(64):
            for high in range(low, 64):
                value = (1 << low) | (1 << high)
                self.assertEqual(forward(value), low)
                self.assertEqual(reverse(value), high)


if __name__ == '__main__':
    unittest.main()
