"""Execute emitted leaf helpers with real CPU dispatch and guard-page buffers.

The benchmark loop is native: Python/ctypes call overhead is outside the timed
inner loop. Saved images allow alternating old/new measurements in one process.
Only code pages become executable; globals remain writable and non-executable.
"""
import ctypes
import json
import mmap
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc.asm import Asm
from mlc.data import DataBuilder
from mlc.codegen.codegen_runtime import CodegenRuntime


class Harness(CodegenRuntime):
    def __init__(self):
        self.asm, self.rdata, self.sequence = Asm(), DataBuilder(), 0

    def new_label_id(self):
        self.sequence += 1
        return self.sequence


def emit_image():
    h = Harness()
    a = h.asm
    for name in ('cpu_init', 'copy_bytes', 'fill_bytes', 'crc32_update_raw', 'crc32c_update_raw'):
        getattr(h, 'emit_' + name + '_function')()
    for operation in ('bsf', 'bsr'):
        a.mark('fn_' + operation)
        a.test_r64_r64('rcx', 'rcx')
        a.jcc('e', operation + '_zero')
        getattr(a, operation + '_r64_r64')('rax', 'rcx')
        a.ret()
        a.mark(operation + '_zero')
        a.mov_r32_imm32('eax', 64)
        a.ret()
    for name in ('copy_bytes', 'fill_bytes', 'crc32_update_raw', 'crc32c_update_raw'):
        a.mark('repeat_' + name)
        for reg in ('r12', 'r13', 'r14', 'r15'):
            a.push_reg(reg)
        a.sub_rsp_imm8(40)
        for dst, src in zip(('r12', 'r13', 'r14', 'r15'), ('rcx', 'rdx', 'r8', 'r9')):
            a.mov_r64_r64(dst, src)
        a.mark('repeat_loop_' + name)
        for dst, src in zip(('rcx', 'rdx', 'r8'), ('r12', 'r13', 'r14')):
            a.mov_r64_r64(dst, src)
        a.call('fn_' + name)
        a.dec_r64('r15')
        a.jcc('ne', 'repeat_loop_' + name)
        a.add_rsp_imm8(40)
        for reg in ('r15', 'r14', 'r13', 'r12'):
            a.pop_reg(reg)
        a.ret()
    # The runtime uses its own Microsoft-style ABI on both operating systems.
    # Expose SysV bridges for this ctypes harness, not for generated programs.
    names = list(a.labels)
    for name in names:
        if not name.startswith(('fn_', 'repeat_')) or name.startswith('repeat_loop_'):
            continue
        a.mark('sysv_' + name)
        a.mov_r64_r64('r9', 'rcx')
        a.mov_r64_r64('r8', 'rdx')
        a.mov_r64_r64('rdx', 'rsi')
        a.mov_r64_r64('rcx', 'rdi')
        a.jmp(name)
    a.emit(bytes((-len(a.buf)) % 4096))
    data_offset = len(a.buf)
    for name in ('cpu_features_detected', 'cpu_features_active', 'cpu_has_avx2'):
        a.mark(name)
        a.emit(bytes(8))
    for name, offset in h.rdata.labels.items():
        a.labels[name] = len(a.buf) + offset
    a.emit(h.rdata.data)
    return dict(code=a.finalize().hex(), labels=a.labels, data_offset=data_offset)


class NativeRuntime:
    def __init__(self, image=None):
        self.image = image or emit_image()
        code = bytes.fromhex(self.image['code'])
        self.length = len(code)
        if os.name == 'nt':
            self.api = ctypes.WinDLL('kernel32', use_last_error=True)
            self.api.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
            self.api.VirtualAlloc.restype = ctypes.c_void_p
            self.api.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
            self.api.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p]
            self.api.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
            self.address = self.api.VirtualAlloc(None, len(code), 0x3000, 4)
            if not self.address:
                raise ctypes.WinError(ctypes.get_last_error())
            ctypes.memmove(self.address, code, len(code))
            old = ctypes.c_uint32()
            if not self.api.VirtualProtect(self.address, self.image['data_offset'], 0x20, ctypes.byref(old)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.api.FlushInstructionCache(ctypes.c_void_p(-1), self.address, len(code))
        else:
            self.memory = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE)
            self.address = ctypes.addressof(ctypes.c_char.from_buffer(self.memory))
            self.memory[:] = code
            libc = ctypes.CDLL(None, use_errno=True)
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            if libc.mprotect(self.address, self.image['data_offset'], mmap.PROT_READ | mmap.PROT_EXEC):
                raise OSError(ctypes.get_errno(), 'mprotect')
        self.call('fn_cpu_init')()

    def call(self, name, nargs=0):
        if os.name != 'nt':
            name = 'sysv_' + name
        return ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_uint64] * nargs))(
            self.address + self.image['labels'][name])

    def global_(self, name):
        return ctypes.c_uint32.from_address(self.address + self.image['labels'][name])

    def mask(self, requested):
        actual = requested & self.global_('cpu_features_detected').value
        self.global_('cpu_features_active').value = actual
        self.global_('cpu_has_avx2').value = (actual >> 3) & 1
        return actual

    def close(self):
        if os.name == 'nt':
            self.api.VirtualFree(self.address, 0, 0x8000)
        else:
            self.memory.close()


if __name__ == '__main__':
    path = Path(sys.argv[1])
    path.parent.mkdir(parents=True, exist_ok=True)
    image = emit_image()
    path.write_text(json.dumps(image), encoding='utf-8')
    runtime = NativeRuntime(image)
    print('Saved native helper baseline:', path, 'CPU mask:', runtime.global_('cpu_features_detected').value)
    runtime.close()
