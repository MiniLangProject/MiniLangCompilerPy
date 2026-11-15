"""Execute the native string-length helper next to a real inaccessible page."""
import ctypes
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def probe():
    from mlc.asm import Asm
    from mlc.codegen.codegen_runtime import CodegenRuntime

    class Harness(CodegenRuntime):
        def __init__(self):
            self.asm = Asm()
            self.serial = 0

        def new_label_id(self):
            self.serial += 1
            return self.serial

    h = Harness()
    a = h.asm
    if os.name != 'nt':
        a.mov_r64_r64('rcx', 'rdi')
    a.sub_rsp_imm8(40)
    a.call('fn_strlen')
    a.mov_r32_r32('eax', 'edx')
    a.add_rsp_imm8(40)
    a.ret()
    h.emit_strlen_function()
    for offset, label, _ in a.patches:
        struct.pack_into('<i', a.buf, offset, a.labels[label]-(offset+4))
    page = mmap.PAGESIZE
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.VirtualAlloc.restype = ctypes.c_void_p
        kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
        kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        buffer = kernel.VirtualAlloc(None, page*2, 0x3000, 4)
        code = kernel.VirtualAlloc(None, page, 0x3000, 4)
        old = ctypes.c_uint32()
        if not buffer or not code or not kernel.VirtualProtect(buffer+page, page, 1, ctypes.byref(old)):
            raise OSError('could not create guard-page fixture')
        ctypes.memmove(code, bytes(a.buf), len(a.buf))
        if not kernel.VirtualProtect(code, page, 0x20, ctypes.byref(old)):
            raise OSError('could not protect native code')
    else:
        libc = ctypes.CDLL(None)
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        memory = mmap.mmap(-1, page*2, prot=mmap.PROT_READ|mmap.PROT_WRITE)
        executable = mmap.mmap(-1, page, prot=mmap.PROT_READ|mmap.PROT_WRITE)
        buffer = ctypes.addressof(ctypes.c_char.from_buffer(memory))
        code = ctypes.addressof(ctypes.c_char.from_buffer(executable))
        if libc.mprotect(buffer+page, page, 0):
            raise OSError('could not protect guard page')
        ctypes.memmove(code, bytes(a.buf), len(a.buf))
        if libc.mprotect(code, page, mmap.PROT_READ|mmap.PROT_EXEC):
            raise OSError('could not protect native code')
    function = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(code)
    for length in range(65):
        payload = b'x'*length+b'\0'
        pointer = buffer+page-len(payload)
        ctypes.memmove(pointer, payload, len(payload))
        if function(pointer) != length:
            raise AssertionError(f'incorrect native strlen for {length} bytes')
    print('65 native guard-page string lengths passed')


class NativeStringLengthTests(unittest.TestCase):
    def test_nul_immediately_before_guard_page(self):
        result = subprocess.run([sys.executable, __file__, '--probe'],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('65 native guard-page string lengths passed', result.stdout)


if __name__ == '__main__':
    if '--probe' in sys.argv:
        probe()
    else:
        unittest.main()
