"""
Allocation-using language builtins (runtime helpers).

This mixin contains builtins that are part of the MiniLang runtime surface but
*perform heap allocation* (or otherwise strongly couple to heap objects).

Moved out of codegen_memory.py:
- heap init / allocator
- GC globals + root-frame wiring
- GC collect

Builtins in this module:
- input()
- box_float()
- value_to_string()
- add_string()
- add_array()
"""

from __future__ import annotations

from ..constants import (OBJ_STRING, OBJ_ARRAY, OBJ_BYTES, OBJ_FLOAT, OBJ_STRUCTTYPE, OBJ_STRUCT, ERROR_STRUCT_ID,
                         TAG_PTR, TAG_INT, TAG_BOOL, TAG_VOID, TAG_ENUM,
                         ERR_STRINGIFY_UNSUPPORTED, )
from ..tools import enc_void, enc_int

# I/O buffers
INPUT_READ_MAX = 4095  # ReadFile max bytes (keeps NUL space)


class CodegenBuiltinsAlloc:
    """Mixin that emits allocation-using runtime builtins.

    Each `emit_*` method registers (or overwrites) a helper function in the
    generated assembly, typically allocating MiniLang heap objects such as
    strings, arrays, bytes, or boxed floats.
    """

    def emit_input_function(self) -> None:
        """
        Emit builtin fn_input() -> string.

        Reads a single line from STDIN via ReadFile into a static buffer, strips CR/LF,
        allocates a new OBJ_STRING and copies the bytes.

        Correctness requirements:
        - Stack alignment must satisfy Windows x64 ABI (16-byte at CALL, plus 32-byte shadow space).
        - INPUT_READ_MAX must leave room for NUL termination.

Returns:
    Emits or overwrites the `fn_input` helper.
"""
        a = self.asm
        a.mark('fn_input')

        # GUI / windows-subsystem executables should not try to read from an
        # inherited console. Return an empty string instead.
        if getattr(self, 'is_windows_subsystem', False):
            a.sub_rsp_imm8(0x28)
            a.mov_rcx_imm32(9)
            a.call('fn_alloc')
            a.mov_membase_disp_imm32('rax', 0, OBJ_STRING, qword=False)
            a.mov_membase_disp_imm32('rax', 4, 0, qword=False)
            a.mov_membase_disp_imm8('rax', 8, 0)
            a.add_rsp_imm8(0x28)
            a.ret()

        # Windows x64 ABI:
        # - stack must be 16-byte aligned at each CALL instruction
        # - caller must reserve 32 bytes of "shadow space" for callees
        #
        # fn_input is itself a *callee* (called from MiniLang code),
        # so at entry RSP is typically 8 mod 16. We fix alignment and
        # reserve shadow space for the WinAPI calls inside this helper.
        a.sub_rsp_imm8(0x28)

        # GetStdHandle(STD_INPUT_HANDLE=-10)
        a.mov_rcx_imm32(0xFFFFFFF6)
        a.mov_rax_rip_qword('iat_GetStdHandle')
        a.call_rax()

        # ReadFile(handle, inbuf, 4095, &bytesRead, NULL)
        a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
        a.lea_rax_rip('inbuf')
        a.mov_rdx_rax()
        a.mov_r8d_imm32(INPUT_READ_MAX)
        a.lea_r9_rip('bytesRead')
        a.mov_qword_ptr_rsp20_rax_zero()
        a.mov_rax_rip_qword('iat_ReadFile')
        a.call_rax()

        lid = self.new_label_id()
        l_read_ok = f"in_read_ok_{lid}"
        l_scan_top = f"in_scan_top_{lid}"
        l_scan_done = f"in_scan_done_{lid}"
        l_found = f"in_scan_found_{lid}"
        l_copy_done = f"in_copy_done_{lid}"

        # if ReadFile failed -> bytesRead = 0
        a.test_r32_r32("eax", "eax")  # test eax,eax
        a.jcc('ne', l_read_ok)
        a.xor_r32_r32("eax", "eax")  # xor eax,eax
        a.mov_rip_dword_eax('bytesRead')
        a.mark(l_read_ok)

        # r9d = bytesRead
        a.mov_eax_rip_dword('bytesRead')
        a.mov_r32_r32("r9d", "eax")  # mov r9d,eax

        # r10 = &inbuf
        a.lea_rax_rip('inbuf')
        a.mov_r10_rax()

        # scan for first CR/LF, set r9d = effective length
        a.xor_r32_r32("r8d", "r8d")  # xor r8d,r8d (idx)
        a.mark(l_scan_top)
        # cmp r8d, r9d
        a.cmp_r32_r32("r8d", "r9d")  # cmp r8d,r9d
        a.jcc('ge', l_scan_done)
        # al = inbuf[idx]
        a.mov_r64_r64("rax", "r10")  # mov rax,r10
        a.add_r64_r64("rax", "r8")  # add rax,r8
        a.mov_r8_membase_disp("al", "rax", 0)  # mov al,[rax]
        a.cmp_r8_imm8("al", 10)  # cmp al,10
        a.jcc('e', l_found)
        a.cmp_r8_imm8("al", 13)  # cmp al,13
        a.jcc('e', l_found)
        a.inc_r32("r8d")  # inc r8d
        a.jmp(l_scan_top)

        a.mark(l_found)
        # r9d = idx
        a.mov_r32_r32("r9d", "r8d")  # mov r9d,r8d

        a.mark(l_scan_done)

        # allocate size = 8 + len + 1 = len + 9
        a.mov_r32_r32("ecx", "r9d")  # mov ecx,r9d
        a.add_r32_imm("ecx", 9)  # add ecx,9
        a.call('fn_alloc')

        # r11 = base
        a.mov_r11_rax()

        # header: [base]=OBJ_STRING, [base+4]=len
        a.mov_membase_disp_imm32("r11", 0, OBJ_STRING, qword=False)  # mov dword [r11],OBJ_STRING
        a.mov_membase_disp_r32("r11", 4, "r9d")  # mov [r11+4], r9d

        # copy bytes: rep movsb (save rsi/rdi)
        a.lea_rax_rip('inbuf')
        a.mov_r10_rax()
        a.push_reg("rsi")  # push rsi
        a.push_reg("rdi")  # push rdi
        a.mov_r64_r64("rsi", "r10")  # mov rsi,r10
        a.lea_r64_membase_disp("rdi", "r11", 8)  # lea rdi,[r11+8]
        a.mov_r32_r32("ecx", "r9d")  # mov ecx,r9d
        a.rep_movsb()  # rep movsb
        a.pop_reg("rdi")  # pop rdi
        a.pop_reg("rsi")  # pop rsi

        # write NUL terminator at [base+8+len]
        a.mov_rax_r11()
        a.add_r64_r64("rax", "r9")  # add rax,r9
        a.add_rax_imm8(8)
        a.mov_membase_disp_imm8("rax", 0, 0)  # mov byte [rax],0

        # return base
        a.mov_rax_r11()
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_decode_function(self) -> None:
        """Emit builtin fn_decode(bytes) -> string.

        Semantics (native backend):
        - If RCX is a bytes object, allocate a new OBJ_STRING of the same length and
          copy the raw bytes (plus NUL terminator).
        - On unsupported input, return VOID (native backend has no exceptions).

        ABI:
          RCX = value
          RAX = OBJ_STRING* (TAG_PTR) or VOID

Returns:
    Emits or overwrites the `fn_decode` helper.
"""
        a = self.asm
        a.mark('fn_decode')

        # Align stack + shadow space for the internal call (Windows x64 ABI)
        a.sub_rsp_imm8(0x28)

        lid = self.new_label_id()
        l_fail = f"dec_fail_{lid}"

        # rax = rcx
        a.mov_r64_r64('rax', 'rcx')

        # tag check: must be PTR
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_fail)

        # type check: must be OBJ_BYTES
        # IMPORTANT: do NOT clobber RDX here (it holds the 2nd argument: off Value).
        # Using EDX would zero-extend into RDX and destroy the argument.
        a.mov_r32_membase_disp('r11d', 'rax', 0)
        a.cmp_r32_imm('r11d', OBJ_BYTES)
        a.jcc('ne', l_fail)

        # save src ptr across fn_alloc (shadow space is [rsp..rsp+0x1F])
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')

        # len = dword [src+4]
        a.mov_r32_membase_disp('r9d', 'rax', 4)

        # alloc size = len + 9
        a.mov_r32_r32('ecx', 'r9d')
        a.add_r32_imm('ecx', 9)
        a.call('fn_alloc')

        # dest base in r11
        a.mov_r11_rax()

        # reload src ptr + len (fn_alloc clobbers volatile regs)
        a.mov_r64_membase_disp('r10', 'rsp', 0x20)
        a.mov_r32_membase_disp('r9d', 'r10', 4)

        # header: [dest]=OBJ_STRING, [dest+4]=len
        a.mov_membase_disp_imm32('r11', 0, OBJ_STRING, qword=False)
        a.mov_membase_disp_r32('r11', 4, 'r9d')

        # copy bytes payload (preserve nonvolatile rsi/rdi)
        a.push_reg('rsi')
        a.push_reg('rdi')
        a.lea_r64_membase_disp('rsi', 'r10', 8)
        a.lea_r64_membase_disp('rdi', 'r11', 8)
        a.mov_r32_r32('ecx', 'r9d')
        a.rep_movsb()
        a.pop_reg('rdi')
        a.pop_reg('rsi')

        # NUL terminator at [dest+8+len]
        a.mov_rax_r11()
        a.add_r64_r64('rax', 'r9')
        a.add_rax_imm8(8)
        a.mov_membase_disp_imm8('rax', 0, 0)

        # return dest
        a.mov_rax_r11()
        a.add_rsp_imm8(0x28)
        a.ret()

        a.mark(l_fail)
        a.mov_rax_imm64(enc_void())
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_decodeZ_function(self) -> None:
        """Emit builtin fn_decodeZ(bytes) -> string.

        Like decode(bytes) but only copies up to the first NUL byte (0x00), or the
        end of the bytes object.

        ABI:
          RCX = bytes value
          RAX = OBJ_STRING* (TAG_PTR) or VOID

Returns:
    Emits or overwrites the `fn_decodeZ` helper.
"""
        a = self.asm
        a.mark('fn_decodeZ')

        # Align stack + shadow space for the internal call (Windows x64 ABI)
        a.sub_rsp_imm8(0x28)

        lid = self.new_label_id()
        l_fail = f"decZ_fail_{lid}"
        l_loop = f"decZ_loop_{lid}"
        l_done_scan = f"decZ_done_scan_{lid}"

        # rax = rcx
        a.mov_r64_r64('rax', 'rcx')

        # tag check: must be PTR
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_fail)

        # type check: must be OBJ_BYTES
        a.mov_r32_membase_disp('r11d', 'rax', 0)
        a.cmp_r32_imm('r11d', OBJ_BYTES)
        a.jcc('ne', l_fail)

        # save src ptr across fn_alloc
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')

        # maxlen = dword [src+4]
        a.mov_r32_membase_disp('r9d', 'rax', 4)

        # scan payload for NUL
        a.lea_r64_membase_disp('r11', 'rax', 8)  # r11 = p
        a.xor_r32_r32('r8d', 'r8d')  # r8d = n

        a.mark(l_loop)
        a.cmp_r32_r32('r8d', 'r9d')
        a.jcc('ge', l_done_scan)

        a.mov_r8_membase_disp('r10b', 'r11', 0)
        a.test_r8_r8('r10b', 'r10b')
        a.jcc('e', l_done_scan)

        a.add_r64_imm8('r11', 1)
        a.add_r32_imm('r8d', 1)
        a.jmp(l_loop)

        a.mark(l_done_scan)

        # len = n
        a.mov_r32_r32('r9d', 'r8d')

        # alloc size = len + 9
        a.mov_r32_r32('ecx', 'r9d')
        a.add_r32_imm('ecx', 9)
        a.call('fn_alloc')

        # dest base in r11
        a.mov_r11_rax()

        # reload src ptr + len (fn_alloc clobbers volatile regs)
        a.mov_r64_membase_disp('r10', 'rsp', 0x20)
        a.mov_r32_r32('r8d', 'r9d')  # keep len in r8d for later

        # header: [dest]=OBJ_STRING, [dest+4]=len
        a.mov_membase_disp_imm32('r11', 0, OBJ_STRING, qword=False)
        a.mov_membase_disp_r32('r11', 4, 'r9d')

        # copy bytes payload (preserve nonvolatile rsi/rdi)
        a.push_reg('rsi')
        a.push_reg('rdi')
        a.lea_r64_membase_disp('rsi', 'r10', 8)
        a.lea_r64_membase_disp('rdi', 'r11', 8)
        a.mov_r32_r32('ecx', 'r8d')
        a.rep_movsb()
        a.pop_reg('rdi')
        a.pop_reg('rsi')

        # NUL terminator at [dest+8+len]
        a.mov_rax_r11()
        a.add_r64_r64('rax', 'r8')
        a.add_rax_imm8(8)
        a.mov_membase_disp_imm8('rax', 0, 0)

        # return dest
        a.mov_rax_r11()
        a.add_rsp_imm8(0x28)
        a.ret()

        a.mark(l_fail)
        a.mov_rax_imm64(enc_void())
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_decode16Z_function(self) -> None:
        """Emit builtin fn_decode16Z(bytes) -> string.

        Interprets bytes payload as UTF-16LE and copies up to the first NUL wide
        char (0x0000), then converts to UTF-8 via WideCharToMultiByte.

        ABI:
          RCX = bytes value
          RAX = OBJ_STRING* (TAG_PTR) or VOID

Returns:
    Emits or overwrites the `fn_decode16Z` helper.
"""
        a = self.asm
        a.mark('fn_decode16Z')

        # Need shadow space + 4 stack args for WideCharToMultiByte, plus locals.
        a.sub_rsp_imm8(0x68)

        lid = self.new_label_id()
        l_fail = f"dec16Z_fail_{lid}"
        l_scan = f"dec16Z_scan_{lid}"
        l_scan_done = f"dec16Z_scan_done_{lid}"
        l_empty = f"dec16Z_empty_{lid}"

        # rax = rcx
        a.mov_r64_r64('rax', 'rcx')

        # tag check: must be PTR
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_fail)

        # type check: must be OBJ_BYTES
        a.mov_r32_membase_disp('r11d', 'rax', 0)
        a.cmp_r32_imm('r11d', OBJ_BYTES)
        a.jcc('ne', l_fail)

        # len_bytes = dword [src+4]
        a.mov_r32_membase_disp('r9d', 'rax', 4)

        # payload ptr
        a.lea_r64_membase_disp('r11', 'rax', 8)  # r11 = p

        # max_wchars = len_bytes >> 1
        a.shr_r64_imm8('r9', 1)

        # scan for 0x0000
        a.xor_r32_r32('r8d', 'r8d')  # wlen

        a.mark(l_scan)
        a.cmp_r32_r32('r8d', 'r9d')
        a.jcc('ge', l_scan_done)

        a.mov_r8_membase_disp('r10b', 'r11', 0)
        a.mov_r8_membase_disp('dl', 'r11', 1)
        a.or_r8_r8('r10b', 'dl')
        a.test_r8_r8('r10b', 'r10b')
        a.jcc('e', l_scan_done)

        a.add_r64_imm8('r11', 2)
        a.add_r32_imm('r8d', 1)
        a.jmp(l_scan)

        a.mark(l_scan_done)

        # save src payload ptr and wlen for later calls
        a.lea_r64_membase_disp('r11', 'rax', 8)
        a.mov_membase_disp_r64('rsp', 0x40, 'r11')  # src payload
        a.mov_membase_disp_r64('rsp', 0x48, 'r8')  # wlen (qword)

        # if wlen == 0 => empty string
        a.cmp_r32_imm('r8d', 0)
        a.jcc('e', l_empty)

        # First call: WideCharToMultiByte(CP_UTF8,0,src,wlen,NULL,0,NULL,NULL)
        a.mov_rcx_imm32(65001)
        a.xor_r32_r32('edx', 'edx')
        a.mov_r64_membase_disp('r8', 'rsp', 0x40)  # src
        a.mov_r64_membase_disp('rax', 'rsp', 0x48)  # wlen
        a.mov_r32_r32('r9d', 'eax')

        a.mov_membase_disp_imm32('rsp', 0x20, 0, qword=True)  # dst
        a.mov_membase_disp_imm32('rsp', 0x28, 0, qword=True)  # dst cap
        a.mov_membase_disp_imm32('rsp', 0x30, 0, qword=True)  # default char
        a.mov_membase_disp_imm32('rsp', 0x38, 0, qword=True)  # used default

        a.mov_rax_rip_qword('iat_WideCharToMultiByte')
        a.call_rax()

        a.cmp_r64_imm8('rax', 0)
        a.jcc('e', l_fail)

        # needed bytes in eax
        a.mov_r32_r32('r9d', 'eax')
        a.mov_membase_disp_r64('rsp', 0x58, 'rax')  # save needed

        # alloc size = needed + 9
        a.mov_r32_r32('ecx', 'r9d')
        a.add_r32_imm('ecx', 9)
        a.call('fn_alloc')

        a.mov_r11_rax()  # dest base

        # header
        a.mov_membase_disp_imm32('r11', 0, OBJ_STRING, qword=False)
        a.mov_membase_disp_r32('r11', 4, 'r9d')

        # Second call: WideCharToMultiByte(..., dst, needed, NULL, NULL)
        a.mov_rcx_imm32(65001)
        a.xor_r32_r32('edx', 'edx')
        a.mov_r64_membase_disp('r8', 'rsp', 0x40)  # src
        a.mov_r64_membase_disp('rax', 'rsp', 0x48)  # wlen
        a.mov_r32_r32('r9d', 'eax')

        a.lea_r64_membase_disp('rax', 'r11', 8)
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')
        a.mov_r64_membase_disp('rax', 'rsp', 0x58)
        a.mov_membase_disp_r64('rsp', 0x28, 'rax')
        a.mov_membase_disp_imm32('rsp', 0x30, 0, qword=True)
        a.mov_membase_disp_imm32('rsp', 0x38, 0, qword=True)

        a.mov_rax_rip_qword('iat_WideCharToMultiByte')
        a.call_rax()

        a.cmp_r64_imm8('rax', 0)
        a.jcc('e', l_fail)

        # NUL terminator at [dest+8+len]
        a.mov_r64_membase_disp('rax', 'rsp', 0x58)  # needed
        a.lea_r64_membase_disp('r10', 'r11', 8)
        a.add_r64_r64('r10', 'rax')
        a.mov_membase_disp_imm8('r10', 0, 0)

        a.mov_rax_r11()
        a.add_rsp_imm8(0x68)
        a.ret()

        a.mark(l_empty)
        # alloc empty string (size 9)
        a.mov_rcx_imm32(9)
        a.call('fn_alloc')
        a.mov_r11_rax()
        a.mov_membase_disp_imm32('r11', 0, OBJ_STRING, qword=False)
        a.mov_membase_disp_imm32('r11', 4, 0, qword=False)
        a.mov_membase_disp_imm8('r11', 8, 0)
        a.mov_rax_r11()
        a.add_rsp_imm8(0x68)
        a.ret()

        a.mark(l_fail)
        a.mov_rax_imm64(enc_void())
        a.add_rsp_imm8(0x68)
        a.ret()

    def emit_hex_function(self) -> None:
        """Emit builtin fn_hex(bytes) -> string.

        Semantics:
        - If RCX is a bytes object, return a new OBJ_STRING containing lowercase hex.
        - On unsupported input, return VOID.

        ABI:
          RCX = value
          RAX = OBJ_STRING* (TAG_PTR) or VOID

Returns:
    Emits or overwrites the `fn_hex` helper.
"""
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_hex')

        # 32B shadow + 24B locals (alignment)
        a.sub_rsp_imm8(0x38)

        lid = self.new_label_id()
        l_fail = f"hex_fail_{lid}"
        l_top = f"hex_top_{lid}"
        l_done = f"hex_done_{lid}"

        # rax = rcx
        a.mov_r64_r64('rax', 'rcx')

        # tag check: must be PTR
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_fail)

        # type check: must be OBJ_BYTES
        # IMPORTANT: do NOT clobber RDX here (it holds the 2nd argument: off Value).
        # Using EDX would zero-extend into RDX and destroy the argument.
        a.mov_r32_membase_disp('r11d', 'rax', 0)
        a.cmp_r32_imm('r11d', OBJ_BYTES)
        a.jcc('ne', l_fail)

        # Root src for GC safety
        a.mov_rip_qword_rax('gc_tmp2')

        # save src ptr
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')

        # len = dword [src+4] -> r8d
        a.mov_r32_membase_disp('r8d', 'rax', 4)

        # overflow guard: outLen = len*2 must fit signed 32-bit (conservative)
        a.cmp_r32_imm('r8d', 0x3FFFFFFF)
        a.jcc('a', l_fail)

        # outLen = len*2 -> r9d
        a.mov_r32_r32('r9d', 'r8d')
        a.add_r32_r32('r9d', 'r8d')
        a.mov_membase_disp_r32('rsp', 0x28, 'r9d')  # spill outLen

        # alloc size = outLen + 9
        a.mov_r32_r32('ecx', 'r9d')
        a.add_r32_imm('ecx', 9)
        a.call('fn_alloc')

        # dest base in r11
        a.mov_r11_rax()

        # reload src ptr + len/outLen (fn_alloc clobbers volatile regs)
        a.mov_r64_membase_disp('r10', 'rsp', 0x20)  # src
        a.mov_r32_membase_disp('r8d', 'r10', 4)  # len
        a.mov_r32_membase_disp('r9d', 'rsp', 0x28)  # outLen

        # header: [dest]=OBJ_STRING, [dest+4]=outLen
        a.mov_membase_disp_imm32('r11', 0, OBJ_STRING, qword=False)
        a.mov_membase_disp_r32('r11', 4, 'r9d')

        # Preserve nonvolatile regs we use
        a.push_reg('rsi')
        a.push_reg('rdi')
        a.push_reg('r12')

        # r12 = &hex_tbl
        a.lea_rax_rip('hex_tbl')
        a.mov_r64_r64('r12', 'rax')

        # rsi = src payload, rdi = dest payload
        a.lea_r64_membase_disp('rsi', 'r10', 8)
        a.lea_r64_membase_disp('rdi', 'r11', 8)

        # r10d = remaining = len
        a.mov_r32_r32('r10d', 'r8d')

        a.mark(l_top)
        a.test_r32_r32('r10d', 'r10d')
        a.jcc('e', l_done)

        # r8d = byte value (0..255)
        a.movzx_r32_membase_disp('r8d', 'rsi', 0)

        # r9d = hi nibble, r8d = lo nibble
        a.mov_r32_r32('r9d', 'r8d')
        a.shr_r64_imm8('r9', 4)
        a.and_r32_imm('r8d', 0x0F)

        # write hi char
        a.lea_r64_mem_bis('rax', 'r12', 'r9', 1, 0)
        a.mov_r8_membase_disp('al', 'rax', 0)
        a.mov_membase_disp_r8('rdi', 0, 'al')
        a.inc_r64('rdi')

        # write lo char
        a.lea_r64_mem_bis('rax', 'r12', 'r8', 1, 0)
        a.mov_r8_membase_disp('al', 'rax', 0)
        a.mov_membase_disp_r8('rdi', 0, 'al')
        a.inc_r64('rdi')

        # advance src, remaining--
        a.inc_r64('rsi')
        a.dec_r32('r10d')
        a.jmp(l_top)

        a.mark(l_done)

        a.pop_reg('r12')
        a.pop_reg('rdi')
        a.pop_reg('rsi')

        # NUL terminator at [dest+8+outLen]
        a.mov_rax_r11()
        a.add_rax_imm8(8)
        a.mov_r32_membase_disp('r9d', 'rsp', 0x28)
        a.add_r64_r64('rax', 'r9')
        a.mov_membase_disp_imm8('rax', 0, 0)

        # return dest
        a.mov_rax_r11()
        a.add_rsp_imm8(0x38)
        a.ret()

        a.mark(l_fail)
        a.mov_rax_imm64(enc_void())
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_fromHex_function(self) -> None:
        """Emit builtin fn_fromHex(string) -> bytes.

        Accepts ASCII hex digits with optional separators (space, tab, CR/LF, '_', '-', ':')
        and an optional leading '0x' / '0X'. Case-insensitive.

        On invalid input (non-hex, odd number of digits, wrong type), returns VOID.

        ABI:
          RCX = value
          RAX = OBJ_BYTES* (TAG_PTR) or VOID

Returns:
    Emits or overwrites the `fn_fromHex` helper.
"""
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_fromHex')

        # Preserve nonvolatile regs (Win64 ABI): rsi, rdi, r12-r15
        a.push_reg('rsi')
        a.push_reg('rdi')
        a.push_reg('r12')
        a.push_reg('r13')
        a.push_reg('r14')
        a.push_reg('r15')

        # 32B shadow + 56B locals (alignment)
        a.sub_rsp_imm8(0x58)

        lid = self.new_label_id()
        l_fail = f"fh_fail_{lid}"
        l_count_top = f"fh_count_top_{lid}"
        l_count_done = f"fh_count_done_{lid}"
        l_parse_top = f"fh_parse_top_{lid}"
        l_parse_prefix_done = f"fh_parse_prefix_done_{lid}"
        l_parse_skip = f"fh_parse_skip_{lid}"
        l_parse_next = f"fh_parse_next_{lid}"
        l_parse_done = f"fh_parse_done_{lid}"
        l_is_sep = f"fh_is_sep_{lid}"
        l_not_sep = f"fh_not_sep_{lid}"
        l_is_digit = f"fh_is_digit_{lid}"
        l_set_hi = f"fh_set_hi_{lid}"
        l_have_hi = f"fh_have_hi_{lid}"

        # rax = rcx
        a.mov_r64_r64('rax', 'rcx')

        # tag check: must be PTR
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_fail)

        # type check: must be OBJ_STRING
        a.mov_r32_membase_disp('edx', 'rax', 0)
        a.cmp_r32_imm('edx', OBJ_STRING)
        a.jcc('ne', l_fail)

        # Root src string for GC safety
        a.mov_rip_qword_rax('gc_tmp2')

        # save src ptr
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')

        # len -> r8d, data -> rsi
        a.mov_r32_membase_disp('r8d', 'rax', 4)
        a.lea_r64_membase_disp('rsi', 'rax', 8)

        # start idx = 0 (r9d)
        a.xor_r32_r32('r9d', 'r9d')

        # optional 0x / 0X prefix at start (only if len >= 2)
        a.cmp_r32_imm('r8d', 2)
        l_no_prefix = f"fh_no_prefix_{lid}"
        a.jcc('b', l_no_prefix)

        # c0 = s[0]
        a.movzx_r32_membase_disp('r10d', 'rsi', 0)
        a.cmp_r32_imm('r10d', ord('0'))
        a.jcc('ne', l_no_prefix)
        # c1 = s[1]
        a.movzx_r32_membase_disp('r10d', 'rsi', 1)
        a.cmp_r32_imm('r10d', ord('x'))
        l_chk_X = f"fh_chk_X_{lid}"
        a.jcc('e', l_chk_X)
        a.cmp_r32_imm('r10d', ord('X'))
        a.jcc('ne', l_no_prefix)
        a.mark(l_chk_X)
        # start idx = 2
        a.mov_r32_imm32('r9d', 2)

        a.mark(l_no_prefix)

        # digit_count = 0 (r10d)
        a.xor_r32_r32('r10d', 'r10d')

        # ---------------- pass 1: count digits + validate ----------------
        a.mark(l_count_top)
        a.cmp_r32_r32('r9d', 'r8d')
        a.jcc('ge', l_count_done)

        # ch -> r11d
        a.lea_r64_mem_bis('rax', 'rsi', 'r9', 1, 0)
        a.movzx_r32_membase_disp('r11d', 'rax', 0)

        # separator?
        a.cmp_r32_imm('r11d', 32)  # space
        a.jcc('e', l_is_sep)
        a.cmp_r32_imm('r11d', 9)  # tab
        a.jcc('e', l_is_sep)
        a.cmp_r32_imm('r11d', 10)  # \n
        a.jcc('e', l_is_sep)
        a.cmp_r32_imm('r11d', 13)  # \r
        a.jcc('e', l_is_sep)
        a.cmp_r32_imm('r11d', ord('_'))
        a.jcc('e', l_is_sep)
        a.cmp_r32_imm('r11d', ord('-'))
        a.jcc('e', l_is_sep)
        a.cmp_r32_imm('r11d', ord(':'))
        a.jcc('e', l_is_sep)
        a.jmp(l_not_sep)

        a.mark(l_is_sep)
        a.inc_r32('r9d')
        a.jmp(l_count_top)

        a.mark(l_not_sep)

        # hex digit?
        # '0'..'9'
        a.cmp_r32_imm('r11d', ord('0'))
        l_chk_a = f"fh_chk_a_{lid}"
        a.jcc('b', l_chk_a)
        a.cmp_r32_imm('r11d', ord('9'))
        a.jcc('be', l_is_digit)

        a.mark(l_chk_a)
        # 'a'..'f'
        a.cmp_r32_imm('r11d', ord('a'))
        l_chk_A = f"fh_chk_A_{lid}"
        a.jcc('b', l_chk_A)
        a.cmp_r32_imm('r11d', ord('f'))
        a.jcc('be', l_is_digit)

        a.mark(l_chk_A)
        # 'A'..'F'
        a.cmp_r32_imm('r11d', ord('A'))
        a.jcc('b', l_fail)
        a.cmp_r32_imm('r11d', ord('F'))
        a.jcc('a', l_fail)

        a.mark(l_is_digit)
        a.inc_r32('r10d')  # digit_count++
        a.inc_r32('r9d')  # idx++
        a.jmp(l_count_top)

        a.mark(l_count_done)

        # require even digit_count
        a.test_r64_imm32('r10', 1)
        a.jcc('nz', l_fail)

        # outLen = digit_count/2 (r10d >>= 1)
        a.shr_r64_imm8('r10', 1)

        # allocate bytes(outLen, 0)
        a.mov_r32_r32('ecx', 'r10d')
        a.xor_r32_r32('edx', 'edx')
        a.call('fn_bytes_alloc')

        # dest bytes in r11
        a.mov_r11_rax()
        a.mov_rip_qword_rax('gc_tmp3')  # root dest too

        # reload src ptr + len + data ptr
        a.mov_r64_membase_disp('r12', 'rsp', 0x20)
        a.mov_r32_membase_disp('r8d', 'r12', 4)
        a.lea_r64_membase_disp('rsi', 'r12', 8)

        # recompute start idx (r9d) with same prefix rule
        a.xor_r32_r32('r9d', 'r9d')
        a.cmp_r32_imm('r8d', 2)
        a.jcc('b', l_parse_prefix_done)  # no prefix possible
        a.movzx_r32_membase_disp('r13d', 'rsi', 0)
        a.cmp_r32_imm('r13d', ord('0'))
        a.jcc('ne', l_parse_prefix_done)
        a.movzx_r32_membase_disp('r13d', 'rsi', 1)
        a.cmp_r32_imm('r13d', ord('x'))
        l_pchk_X = f"fh_pchk_X_{lid}"
        a.jcc('e', l_pchk_X)
        a.cmp_r32_imm('r13d', ord('X'))
        a.jcc('ne', l_parse_prefix_done)
        a.mark(l_pchk_X)
        a.mov_r32_imm32('r9d', 2)

        a.mark(l_parse_prefix_done)

        # dest payload pointer in rdi
        a.lea_r64_membase_disp('rdi', 'r11', 8)

        # state: have_hi (r14d) = 0, hi_nibble (r15d) = 0
        a.xor_r32_r32('r14d', 'r14d')
        a.xor_r32_r32('r15d', 'r15d')

        # ---------------- pass 2: parse + store ----------------
        a.mark(l_parse_top)
        a.cmp_r32_r32('r9d', 'r8d')
        a.jcc('ge', l_parse_done)

        # ch -> r13d
        a.lea_r64_mem_bis('rax', 'rsi', 'r9', 1, 0)
        a.movzx_r32_membase_disp('r13d', 'rax', 0)

        # separator? (same set)
        a.cmp_r32_imm('r13d', 32)
        a.jcc('e', l_parse_skip)
        a.cmp_r32_imm('r13d', 9)
        a.jcc('e', l_parse_skip)
        a.cmp_r32_imm('r13d', 10)
        a.jcc('e', l_parse_skip)
        a.cmp_r32_imm('r13d', 13)
        a.jcc('e', l_parse_skip)
        a.cmp_r32_imm('r13d', ord('_'))
        a.jcc('e', l_parse_skip)
        a.cmp_r32_imm('r13d', ord('-'))
        a.jcc('e', l_parse_skip)
        a.cmp_r32_imm('r13d', ord(':'))
        a.jcc('e', l_parse_skip)
        # else hex digit decode to nibble in r13d
        # '0'..'9'
        a.cmp_r32_imm('r13d', ord('0'))
        l_pchk_a = f"fh_pchk_a_{lid}"
        a.jcc('b', l_pchk_a)
        a.cmp_r32_imm('r13d', ord('9'))
        l_pis_a = f"fh_pis_a_{lid}"
        a.jcc('be', l_pis_a)

        a.mark(l_pchk_a)
        # 'a'..'f'
        a.cmp_r32_imm('r13d', ord('a'))
        l_pchk_A2 = f"fh_pchk_A2_{lid}"
        a.jcc('b', l_pchk_A2)
        a.cmp_r32_imm('r13d', ord('f'))
        l_pis_f = f"fh_pis_f_{lid}"
        a.jcc('be', l_pis_f)

        a.mark(l_pchk_A2)
        # 'A'..'F'
        a.cmp_r32_imm('r13d', ord('A'))
        a.jcc('b', l_fail)
        a.cmp_r32_imm('r13d', ord('F'))
        a.jcc('a', l_fail)

        # decode A..F
        a.sub_r32_imm('r13d', ord('A') - 10)
        a.jmp(l_have_hi)

        a.mark(l_pis_a)
        a.sub_r32_imm('r13d', ord('0'))
        a.jmp(l_have_hi)

        a.mark(l_pis_f)
        a.sub_r32_imm('r13d', ord('a') - 10)

        # have nibble in r13d
        a.mark(l_have_hi)
        # if have_hi==0 -> set hi_nibble
        a.test_r32_r32('r14d', 'r14d')
        a.jcc('z', l_set_hi)

        # else: byte = (hi<<4) + nibble
        a.mov_r32_r32('eax', 'r15d')
        a.shl_r32_imm8('eax', 4)
        a.add_r32_r32('eax', 'r13d')
        a.mov_membase_disp_r8('rdi', 0, 'al')
        a.inc_r64('rdi')
        a.xor_r32_r32('r14d', 'r14d')  # have_hi=0
        a.jmp(l_parse_next)

        a.mark(l_set_hi)
        a.mov_r32_r32('r15d', 'r13d')
        a.mov_r32_imm32('r14d', 1)  # have_hi=1

        a.mark(l_parse_next)
        a.inc_r32('r9d')
        a.jmp(l_parse_top)

        # skip separators
        a.mark(l_parse_skip)
        a.inc_r32('r9d')
        a.jmp(l_parse_top)

        a.mark(l_parse_done)
        # must not end in half-byte
        a.test_r32_r32('r14d', 'r14d')
        a.jcc('nz', l_fail)

        # return dest
        a.mov_rax_r11()
        a.add_rsp_imm8(0x58)
        a.pop_reg('r15')
        a.pop_reg('r14')
        a.pop_reg('r13')
        a.pop_reg('r12')
        a.pop_reg('rdi')
        a.pop_reg('rsi')
        a.ret()

        a.mark(l_fail)
        a.mov_rax_imm64(enc_void())
        a.add_rsp_imm8(0x58)
        a.pop_reg('r15')
        a.pop_reg('r14')
        a.pop_reg('r13')
        a.pop_reg('r12')
        a.pop_reg('rdi')
        a.pop_reg('rsi')
        a.ret()

    # ------------------------------------------------------------------
    # Debug helpers: heap_count(), heap_bytes_used()
    # ------------------------------------------------------------------

    def emit_box_float_function(self) -> None:
        """
        Emit fn_box_float(): box XMM0 into a heap OBJ_FLOAT.

        - Allocates 16 bytes payload (type+pad + f64).
        - Stores OBJ_FLOAT and writes the double.

        Correctness requirements:
        - Ensure XMM0 is used according to the calling convention used by your compiler.

Returns:
    Emits or overwrites the `fn_box_float` helper.
"""
        a = self.asm
        a.mark('fn_box_float')
        # Align stack + shadow space for the internal call (Windows x64 ABI)
        a.sub_rsp_imm8(0x28)
        # allocate 16 bytes
        a.mov_rcx_imm32(16)
        a.call('fn_alloc')
        # [rax] = OBJ_FLOAT, [rax+4]=0
        a.mov_membase_disp_imm32("rax", 0, 4, qword=False)  # mov dword [rax],OBJ_FLOAT
        a.mov_membase_disp_imm32("rax", 4, 0, qword=False)
        # store f64
        a.movsd_membase_disp_xmm("rax", 8, "xmm0")  # movsd [rax+8],xmm0
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_value_to_string_function(self) -> None:
        """
        Emit fn_value_to_string(value) -> OBJ_STRING* (TAG_PTR).

        Converts a tagged value into a string object:
        - string: returns itself
        - int: allocates decimal string via fn_int_to_dec
        - bool: returns boxed constants "true"/"false"
        - float: uses _gcvt into a temp buffer and allocates a new string
        - array: returns boxed "<array>"
        - other: returns boxed "<unsupported>"

        Correctness notes:
        - Any path that calls fn_alloc may trigger GC; keep temporaries either in
          shadow-stack roots or in globals scanned by GC.

Returns:
    Emits or overwrites the `fn_value_to_string` helper.
"""
        # Ensure boxed strings for enum variants exist in .rdata (for enum -> string conversion).
        # This is emitted once per compilation (helpers are emitted once).
        if not getattr(self, "_enum_obj_strings_emitted", False):
            for enum_qname, eid in self.enum_id.items():
                variants = self.enum_variants.get(enum_qname, [])
                for vid, vname in enumerate(variants):
                    lbl = f"enumv_{eid}_{vid}"
                    if lbl not in self.rdata.labels:
                        # enum_qname is already namespace-qualified (e.g. "geom.Color")
                        self.rdata.add_obj_string(lbl, f"{enum_qname}.{vname}")
            self._enum_obj_strings_emitted = True

        a = self.asm
        a.mark('fn_value_to_string')

        # 32 bytes shadow space + 16 bytes locals (keep 16-byte alignment for CALLs)
        # locals: [rsp+0x20] = tmp ptr, [rsp+0x28] = tmp len (u32)
        a.sub_rsp_imm8(0x38)

        # rax = rcx (value)
        a.mov_r64_r64("rax", "rcx")  # mov rax,rcx

        lid = self.new_label_id()
        l_ptr = f"v2s_ptr_{lid}"
        l_int = f"v2s_int_{lid}"
        l_bool = f"v2s_bool_{lid}"
        l_enum = f"v2s_enum_{lid}"
        l_void = f"v2s_void_{lid}"
        l_float = f"v2s_float_{lid}"
        l_array = f"v2s_array_{lid}"
        l_bytes = f"v2s_bytes_{lid}"
        l_stt = f"v2s_stt_{lid}"
        l_uns = f"v2s_uns_{lid}"
        l_done = f"v2s_done_{lid}"

        # void?
        a.cmp_rax_imm8(TAG_VOID)
        a.jcc('e', l_void)

        # tag = rdx = rax & 7
        a.mov_r64_r64("rdx", "rax")  # mov rdx,rax
        a.and_r64_imm("rdx", 7)  # and rdx,7

        # ptr?
        a.cmp_r64_imm("rdx", 0)  # cmp rdx,TAG_PTR
        a.jcc('e', l_ptr)
        # int?
        a.cmp_r64_imm("rdx", 1)  # cmp rdx,TAG_INT
        a.jcc('e', l_int)
        # bool?
        a.cmp_r64_imm("rdx", 2)  # cmp rdx,TAG_BOOL
        a.jcc('e', l_bool)
        # enum?
        a.cmp_r64_imm("rdx", TAG_ENUM)  # cmp rdx,TAG_ENUM
        a.jcc('e', l_enum)
        a.jmp(l_uns)

        # --- void -> "void" ---
        a.mark(l_void)
        a.lea_rax_rip('obj_void')
        a.jmp(l_done)

        # --- ptr cases: string / float / array ---
        a.mark(l_ptr)
        # edx = [rax] (obj type)
        a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
        # if OBJ_STRING => return as-is
        a.cmp_r32_imm("edx", OBJ_STRING)
        a.jcc('e', l_done)
        # if OBJ_FLOAT => convert via _gcvt
        a.cmp_r32_imm("edx", OBJ_FLOAT)
        a.jcc('e', l_float)
        # if OBJ_ARRAY => <array>
        a.cmp_r32_imm("edx", OBJ_ARRAY)
        a.jcc('e', l_array)
        a.cmp_r32_imm("edx", OBJ_BYTES)
        a.jcc('e', l_bytes)
        # if OBJ_STRUCTTYPE => "struct"
        a.cmp_r32_imm("edx", OBJ_STRUCTTYPE)
        a.jcc('e', l_stt)

        a.jmp(l_uns)

        # --- array -> <array> ---
        a.mark(l_array)
        a.lea_rax_rip('obj_array')
        a.jmp(l_done)

        # --- bytes -> <bytes> ---
        a.mark(l_bytes)
        a.lea_rax_rip('obj_bytes')
        a.jmp(l_done)

        # --- bool -> boxed constant true/false ---
        a.mark(l_bool)
        # test bit3 (0x8): true if set
        a.test_rax_imm32(8)
        l_bfalse = f"v2s_bfalse_{lid}"
        a.jcc('z', l_bfalse)
        a.lea_rax_rip('obj_true')
        a.jmp(l_done)
        a.mark(l_bfalse)
        a.lea_rax_rip('obj_false')
        a.jmp(l_done)

        # --- enum -> boxed constant "Enum.Variant" (no heap alloc) ---
        a.mark(l_enum)
        # Decode payload: (value >> 3) = enum_id | (variant_id << 16)
        a.mov_r64_r64("r8", "rax")  # mov r8,rax
        a.shr_r64_imm8("r8", 3)  # shr r8,3
        a.mov_r64_r64("r9", "r8")  # mov r9,r8
        a.shr_r64_imm8("r9", 16)  # shr r9,16
        a.and_r32_imm("r8d", 0xFFFF)  # enum_id
        a.and_r32_imm("r9d", 0xFFFF)  # variant_id

        # Select pre-boxed string for this enum value.
        # Use a compare chain to keep runtime simple (enum counts are expected to be small).
        for enum_qname, eid in self.enum_id.items():
            variants = self.enum_variants.get(enum_qname, [])
            for vid, _vname in enumerate(variants):
                lbl = f"enumv_{eid}_{vid}"
                l_next = f"v2s_enum_next_{lid}_{eid}_{vid}"
                a.cmp_r32_imm("r8d", eid)
                a.jcc('ne', l_next)
                a.cmp_r32_imm("r9d", vid)
                a.jcc('ne', l_next)
                a.lea_rax_rip(lbl)
                a.jmp(l_done)
                a.mark(l_next)

        # Fallback (should not happen): <unsupported>
        a.lea_rax_rip('obj_uns')
        a.jmp(l_done)

        # --- int -> decimal string (allocate) ---
        a.mark(l_int)
        # fn_int_to_dec(rcx=value) -> rax=ptr, edx=len
        a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
        a.call('fn_int_to_dec')

        # SAVE across fn_alloc (fn_alloc clobbers r10/r11)
        a.mov_membase_disp_r64("rsp", 32, "rax")  # mov [rsp+0x20],rax   ; ptr
        a.mov_membase_disp_r32("rsp", 40, "edx")  # mov [rsp+0x28],edx   ; len (u32)

        # r9d = len (reload from EDX now)
        a.mov_r32_r32("r9d", "edx")  # mov r9d,edx

        # ecx = len + 9
        a.mov_r32_r32("ecx", "edx")  # mov ecx,edx
        a.add_r32_imm("ecx", 9)  # add ecx,9
        a.call('fn_alloc')

        # RESTORE src ptr + len (fn_alloc may clobber volatile regs)
        a.mov_r64_membase_disp("r10", "rsp", 32)  # mov r10,[rsp+0x20]
        a.mov_r32_membase_disp("r9d", "rsp", 40)  # mov r9d,[rsp+0x28]

        # header
        a.mov_membase_disp_imm32("rax", 0, OBJ_STRING, qword=False)  # mov dword [rax],OBJ_STRING
        a.mov_membase_disp_r32("rax", 4, "r9d")  # mov [rax+4],r9d
        # copy digits from r10 -> [rax+8]
        a.push_reg("rsi")  # push rsi
        a.push_reg("rdi")  # push rdi
        a.mov_r64_r64("rsi", "r10")  # mov rsi,r10
        a.lea_r64_membase_disp("rdi", "rax", 8)  # lea rdi,[rax+8]
        a.mov_r32_r32("ecx", "r9d")  # mov ecx,r9d
        a.rep_movsb()  # rep movsb
        a.mov_membase_disp_imm8("rdi", 0, 0)  # mov byte [rdi],0
        a.pop_reg("rdi")  # pop rdi
        a.pop_reg("rsi")  # pop rsi
        a.jmp(l_done)

        # --- float -> decimal string via _gcvt (allocate) ---
        a.mark(l_float)
        # xmm0 = [rax+8]
        a.movsd_xmm_membase_disp("xmm0", "rax", 8)  # movsd xmm0,[rax+8]
        # edx = digits (15)
        a.mov_r32_imm32("edx", 15)
        # r8 = &floatbuf
        a.lea_r8_rip('floatbuf')
        # call _gcvt(xmm0, edx, r8)
        a.mov_rax_rip_qword('iat__gcvt')
        a.call_rax()

        # SAVE c-string pointer across fn_alloc (fn_alloc clobbers r10/r11)
        a.mov_membase_disp_r64("rsp", 32, "rax")  # mov [rsp+0x20],rax

        # strlen(rcx=rax) -> edx=len
        a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
        a.call('fn_strlen')

        # save len
        a.mov_membase_disp_r32("rsp", 40, "edx")  # mov [rsp+0x28],edx

        # r9d = len
        a.mov_r32_r32("r9d", "edx")  # mov r9d,edx
        # ecx = len + 9
        a.mov_r32_r32("ecx", "edx")  # mov ecx,edx
        a.add_r32_imm("ecx", 9)  # add ecx,9
        a.call('fn_alloc')

        # RESTORE src ptr + len after alloc
        a.mov_r64_membase_disp("r11", "rsp", 32)  # mov r11,[rsp+0x20]
        a.mov_r32_membase_disp("r9d", "rsp", 40)  # mov r9d,[rsp+0x28]

        # header
        a.mov_membase_disp_imm32("rax", 0, OBJ_STRING, qword=False)
        a.mov_membase_disp_r32("rax", 4, "r9d")  # [rax+4]=r9d
        # copy bytes from r11 -> [rax+8]
        a.push_reg("rsi")  # push rsi
        a.push_reg("rdi")  # push rdi
        a.mov_r64_r64("rsi", "r11")  # mov rsi,r11
        a.lea_r64_membase_disp("rdi", "rax", 8)  # lea rdi,[rax+8]
        a.mov_r32_r32("ecx", "r9d")  # mov ecx,r9d
        a.rep_movsb()  # rep movsb
        a.mov_membase_disp_imm8("rdi", 0, 0)  # mov byte [rdi],0
        a.pop_reg("rdi")  # pop rdi
        a.pop_reg("rsi")  # pop rsi
        a.jmp(l_done)

        # --- unsupported -> <unsupported> ---
        # --- structtype -> "struct" ---
        a.mark(l_stt)
        a.lea_rax_rip('obj_type_struct')
        a.jmp(l_done)

        a.mark(l_uns)
        a.lea_rax_rip('obj_uns')

        a.mark(l_done)
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_string_add_function(self) -> None:
        """
        Emit fn_add_string(a,b) -> concatenated string.

        - Converts both operands via fn_value_to_string.
        - Allocates a new OBJ_STRING with len = len(s1)+len(s2).
        - Copies bytes and writes a NUL terminator.

        Correctness requirements:
        - Total allocation size must include header + len + NUL.
        - If GC can run during fn_alloc, s1/s2 must remain live (either conservative scan
          or explicit rooting).

Returns:
    Emits or overwrites the `fn_add_string` helper.
"""
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_add_string')
        # reserve 32B shadow + 24B locals (keep alignment)
        a.sub_rsp_imm8(0x38)

        # If stringification produces <unsupported> or "void", return an `error(...)`
        # value instead of silently concatenating placeholder strings.
        lid = self.new_label_id()
        l_fail_uns = f"addstr_fail_uns_{lid}"
        l_fail_void = f"addstr_fail_void_{lid}"

        lbl_msg_uns = f"objstr_{len(self.rdata.labels)}"
        self.rdata.add_obj_string(lbl_msg_uns, "Cannot stringify unsupported value for string concatenation")
        lbl_msg_void = f"objstr_{len(self.rdata.labels)}"
        self.rdata.add_obj_string(lbl_msg_void, "Cannot stringify void for string concatenation")

        # Save b (RDX) at [rsp+0x20] (non-shadow local)
        a.mov_membase_disp_r64("rsp", 32, "rdx")  # mov [rsp+0x20],rdx

        # s1 = value_to_string(a)
        a.call('fn_value_to_string')

        # Reject placeholder conversions (<unsupported> / void)
        a.lea_r11_rip('obj_uns')
        a.cmp_r64_r64('rax', 'r11')
        a.jcc('e', l_fail_uns)
        a.lea_r11_rip('obj_void')
        a.cmp_r64_r64('rax', 'r11')
        a.jcc('e', l_fail_void)

        # save s1 across calls (callee may clobber volatile r10)
        a.mov_membase_disp_r64("rsp", 40, "rax")  # mov [rsp+0x28],rax

        # Root s1 for GC (stack locals are NOT scanned)
        a.mov_rip_qword_rax('gc_tmp2')

        # rcx = saved b
        a.mov_r64_membase_disp("rcx", "rsp", 32)  # mov rcx,[rsp+0x20]
        a.call('fn_value_to_string')

        # Reject placeholder conversions (<unsupported> / void)
        a.lea_r11_rip('obj_uns')
        a.cmp_r64_r64('rax', 'r11')
        a.jcc('e', l_fail_uns)
        a.lea_r11_rip('obj_void')
        a.cmp_r64_r64('rax', 'r11')
        a.jcc('e', l_fail_void)

        a.mov_r11_rax()  # r11 = s2
        # save s2 across calls
        a.mov_membase_disp_r64("rsp", 48, "r11")  # mov [rsp+0x30],r11

        # Root s2 for GC
        a.mov_rip_qword_r11('gc_tmp3')

        # reload s1 into r10
        a.mov_r64_membase_disp("r10", "rsp", 40)  # mov r10,[rsp+0x28]

        # r8d = len1, r9d = len2
        a.mov_r32_membase_disp("r8d", "r10", 4)  # mov r8d,[r10+4]
        a.mov_r32_membase_disp("r9d", "r11", 4)  # mov r9d,[r11+4]

        # ecx = totalLen = len1 + len2
        a.mov_r32_r32("ecx", "r8d")  # mov ecx,r8d
        a.add_r32_r32("ecx", "r9d")  # add ecx,r9d

        # Save totalLen across the alloc call.
        # Note: R8/R9 are volatile and fn_alloc may clobber them.
        # We can reuse the old "saved b" slot at [rsp+0x20] now.
        a.mov_membase_disp_r32("rsp", 32, "ecx")  # mov [rsp+0x20],ecx

        # ecx = totalLen + 9
        a.add_r32_imm("ecx", 9)  # add ecx,9
        a.call('fn_alloc')

        # reload totalLen into r8d
        a.mov_r32_membase_disp("r8d", "rsp", 32)  # mov r8d,[rsp+0x20]

        # rdx = base
        a.mov_rdx_rax()

        # header: [base]=OBJ_STRING ; [base+4]=totalLen
        a.mov_membase_disp_imm32("rdx", 0, OBJ_STRING, qword=False)  # mov dword [rdx],OBJ_STRING
        a.mov_membase_disp_r32("rdx", 4, "r8d")  # mov [rdx+4],r8d

        # IMPORTANT: Reload s1/s2 BEFORE pushing anything.
        # push/pop changes RSP and would shift our local offsets.
        # fn_alloc may have clobbered volatile registers, but our stack locals are stable.
        a.mov_r64_membase_disp("r10", "rsp", 40)  # mov r10,[rsp+0x28]
        a.mov_r64_membase_disp("r11", "rsp", 48)  # mov r11,[rsp+0x30]

        # dest = base+8
        a.push_reg("rsi")  # push rsi
        a.push_reg("rdi")  # push rdi
        a.lea_r64_membase_disp("rdi", "rdx", 8)  # lea rdi,[rdx+8]

        # copy s1 bytes
        a.lea_r64_membase_disp("rsi", "r10", 8)  # lea rsi,[r10+8]
        a.mov_r32_membase_disp("ecx", "r10", 4)  # mov ecx,[r10+4]
        a.rep_movsb()  # rep movsb

        # copy s2 bytes (len2)
        a.lea_r64_membase_disp("rsi", "r11", 8)  # lea rsi,[r11+8]
        a.mov_r32_membase_disp("ecx", "r11", 4)  # mov ecx,[r11+4]
        a.rep_movsb()  # rep movsb

        # NUL terminator
        a.mov_membase_disp_imm8("rdi", 0, 0)  # mov byte [rdi],0

        a.pop_reg("rdi")  # pop rdi
        a.pop_reg("rsi")  # pop rsi

        # return rax = base
        a.mov_r64_r64("rax", "rdx")  # mov rax,rdx

        # IMPORTANT: Don't clobber the return value while clearing GC temp roots.
        # Save the newly allocated string pointer, clear roots, then restore RAX.
        a.mov_r11_rax()  # r11 = return value (base)
        a.mov_rax_imm64(enc_void())
        a.mov_rip_qword_rax('gc_tmp2')
        a.mov_rip_qword_rax('gc_tmp3')
        a.mov_rax_r11()  # restore return value

        a.add_rsp_imm8(0x38)
        a.ret()

        # ---- failure paths: build error(code,msg,script,func,line) and return it ----
        def _emit_addstr_error(msg_lbl: str) -> None:
            # Clear GC temp roots (avoid pinning old values)
            a.mov_rax_imm64(enc_void())
            a.mov_rip_qword_rax('gc_tmp2')
            a.mov_rip_qword_rax('gc_tmp3')

            # Allocate error struct (5 fields)
            a.mov_rcx_imm32(56)
            a.call('fn_alloc')
            a.mov_r11_rax()
            a.mov_membase_disp_imm32('r11', 0, OBJ_STRUCT, qword=False)
            a.mov_membase_disp_imm32('r11', 4, 5, qword=False)
            a.mov_membase_disp_imm32('r11', 8, ERROR_STRUCT_ID, qword=False)
            a.mov_membase_disp_imm32('r11', 12, 0, qword=False)

            a.mov_rax_imm64(enc_int(int(ERR_STRINGIFY_UNSUPPORTED)))
            a.mov_membase_disp_r64('r11', 16, 'rax')

            a.lea_rax_rip(msg_lbl)
            a.mov_membase_disp_r64('r11', 24, 'rax')

            a.mov_rax_rip_qword('dbg_loc_script')
            a.mov_membase_disp_r64('r11', 32, 'rax')
            a.mov_rax_rip_qword('dbg_loc_func')
            a.mov_membase_disp_r64('r11', 40, 'rax')
            a.mov_rax_rip_qword('dbg_loc_line')
            a.mov_membase_disp_r64('r11', 48, 'rax')

            a.mov_rax_r11()
            a.add_rsp_imm8(0x38)
            a.ret()

        a.mark(l_fail_uns)
        _emit_addstr_error(lbl_msg_uns)

        a.mark(l_fail_void)
        _emit_addstr_error(lbl_msg_void)

    def emit_array_add_function(self) -> None:
        """
        Emit fn_add_array(a,b) -> concatenated array.

        - Expects RCX/RDX to be TAG_PTR arrays.
        - Allocates OBJ_ARRAY with totalLen elements.
        - Copies elements from both arrays using a counted loop.

        Correctness requirements:
        - Allocation size must be 8 + totalLen*8 bytes (type/len + elements).
        - Array elements must be tagged values; the GC scans them in emit_gc_collect_function.

Returns:
    Emits or overwrites the `fn_add_array` helper.
"""
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_add_array')

        # 32B shadow + 24B locals (alignment)
        a.sub_rsp_imm8(0x38)

        # Root arr1/arr2 for GC (stack locals are NOT scanned)
        a.mov_r64_r64("rax", "rcx")  # mov rax,rcx
        a.mov_rip_qword_rax('gc_tmp2')
        a.mov_rip_qword_rdx('gc_tmp3')

        # save arr1/arr2
        a.mov_membase_disp_r64("rsp", 32, "rcx")  # mov [rsp+0x20],rcx
        a.mov_membase_disp_r64("rsp", 40, "rdx")  # mov [rsp+0x28],rdx

        # r8d=len1, r9d=len2
        a.mov_r32_membase_disp("r8d", "rcx", 4)  # mov r8d,[rcx+4]
        a.mov_r32_membase_disp("r9d", "rdx", 4)  # mov r9d,[rdx+4]

        # eax = totalLen
        a.mov_r32_r32("eax", "r8d")  # mov eax,r8d
        a.add_r32_r32("eax", "r9d")  # add eax,r9d
        a.mov_membase_disp_r32("rsp", 48, "eax")  # mov [rsp+0x30],eax

        # rcx = sizeBytes = 8 + totalLen*8
        a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
        a.shl_r64_imm8("rcx", 3)  # shl rcx,3
        a.add_r64_imm("rcx", 8)  # add rcx,8

        a.call('fn_alloc')

        # rdx = base
        a.mov_rdx_rax()

        # header
        a.mov_membase_disp_imm32("rdx", 0, OBJ_ARRAY, qword=False)  # mov dword [rdx],OBJ_ARRAY
        a.mov_r32_membase_disp("ecx", "rsp", 48)  # mov ecx,[rsp+0x30]
        a.mov_membase_disp_r32("rdx", 4, "ecx")  # mov [rdx+4],ecx

        # reload arr1/arr2 pointers
        a.mov_r64_membase_disp("r10", "rsp", 32)  # mov r10,[rsp+0x20]
        a.mov_r64_membase_disp("r11", "rsp", 40)  # mov r11,[rsp+0x28]

        # preserve non-volatile regs we will use (RSI/RDI)
        a.push_reg("rsi")  # push rsi
        a.push_reg("rdi")  # push rdi

        # rdi = dest data start
        a.lea_r64_membase_disp("rdi", "rdx", 8)  # lea rdi,[rdx+8]

        # ---------------- copy arr1 ----------------
        # rsi = arr1 data
        a.lea_r64_membase_disp("rsi", "r10", 8)  # lea rsi,[r10+8]
        # r9d = len1
        a.mov_r32_membase_disp("r9d", "r10", 4)  # mov r9d,[r10+4]
        # r8d = i = 0
        a.xor_r32_r32("r8d", "r8d")  # xor r8d,r8d

        lid = self.new_label_id()
        l1_top = f"arrcat1_top_{lid}"
        l1_done = f"arrcat1_done_{lid}"

        a.mark(l1_top)
        # if i >= len1 -> done
        a.cmp_r32_r32("r8d", "r9d")  # cmp r8d,r9d
        a.jcc('ge', l1_done)
        # rax = [rsi + i*8]
        a.mov_r64_mem_bis("rax", "rsi", "r8", 8, 0)  # mov rax,[rsi+r8*8]
        # [rdi + i*8] = rax
        a.mov_mem_bis_r64("rdi", "r8", 8, 0, "rax")  # mov [rdi+r8*8],rax
        # i++
        a.inc_r32("r8d")  # inc r8d
        a.jmp(l1_top)

        a.mark(l1_done)

        # ---------------- copy arr2 ----------------
        # rsi = arr2 data
        a.lea_r64_membase_disp("rsi", "r11", 8)  # lea rsi,[r11+8]
        # r10d = len2
        a.mov_r32_membase_disp("r10d", "r11", 4)  # mov r10d,[r11+4]
        # r8d = j = 0
        a.xor_r32_r32("r8d", "r8d")  # xor r8d,r8d

        l2_top = f"arrcat2_top_{lid}"
        l2_done = f"arrcat2_done_{lid}"

        a.mark(l2_top)
        # if j >= len2 -> done
        a.cmp_r32_r32("r8d", "r10d")  # cmp r8d,r10d
        a.jcc('ge', l2_done)
        # rax = [rsi + j*8]
        a.mov_r64_mem_bis("rax", "rsi", "r8", 8, 0)  # mov rax,[rsi+r8*8]
        # r11d = len1
        a.mov_r32_r32("r11d", "r9d")  # mov r11d,r9d
        # r11d += j
        a.add_r32_r32("r11d", "r8d")  # add r11d,r8d
        # [rdi + r11*8] = rax
        a.mov_mem_bis_r64("rdi", "r11", 8, 0, "rax")  # mov [rdi+r11*8],rax
        # j++
        a.inc_r32("r8d")  # inc r8d
        a.jmp(l2_top)

        a.mark(l2_done)

        a.pop_reg("rdi")  # pop rdi
        a.pop_reg("rsi")  # pop rsi

        # return base in rax
        a.mov_r64_r64("rax", "rdx")  # mov rax,rdx

        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_bytes_alloc_function(self) -> None:
        """
        Emit fn_bytes_alloc(len_u32, fill_u8) -> OBJ_BYTES*

        ABI:
          RCX = length (u32, must be >= 0)
          RDX = fill byte (uses low 8 bits)
        Returns:
          RAX = pointer to OBJ_BYTES (TAG_PTR)
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_bytes_alloc')

        # 32B shadow + 24B locals (alignment)
        a.sub_rsp_imm8(0x38)

        # locals:
        #   [rsp+0x20] len (u32)
        #   [rsp+0x24] fill (u8 in low byte)
        a.mov_membase_disp_r32("rsp", 0x20, "ecx")
        a.mov_membase_disp_r32("rsp", 0x24, "edx")

        # rcx = alloc payload bytes = 8 + len
        a.mov_r32_membase_disp("ecx", "rsp", 0x20)
        a.add_r32_imm("ecx", 8)
        a.call('fn_alloc')

        # r11 = base
        a.mov_r11_rax()

        # header
        a.mov_membase_disp_imm32("r11", 0, OBJ_BYTES, qword=False)
        a.mov_r32_membase_disp("ecx", "rsp", 0x20)
        a.mov_membase_disp_r32("r11", 4, "ecx")

        # r8 = data ptr
        a.lea_r64_membase_disp("r8", "r11", 8)

        # r9d = remaining count
        a.mov_r32_r32("r9d", "ecx")

        # dl = fill byte
        a.mov_r8_membase_disp("dl", "rsp", 0x24)

        lid = self.new_label_id()
        l_top = f"bfill_top_{lid}"
        l_done = f"bfill_done_{lid}"

        a.mark(l_top)
        a.test_r32_r32("r9d", "r9d")
        a.jcc('e', l_done)
        a.mov_membase_disp_r8("r8", 0, "dl")
        a.inc_r64("r8")
        a.dec_r32("r9d")
        a.jmp(l_top)

        a.mark(l_done)

        a.mov_rax_r11()
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_bytes_add_function(self) -> None:
        """
        Emit fn_add_bytes(a,b) -> concatenated bytes.

        - Expects RCX/RDX to be TAG_PTR to OBJ_BYTES.
        - Allocates OBJ_BYTES with totalLen bytes.
        - Copies payload using rep movsb.

        Correctness requirements:
        - Allocation size must be 8 + totalLen bytes (type/len + payload).
        - Payload contains raw bytes (no GC pointers).

Returns:
    Emits or overwrites the `fn_bytes_add` helper.
"""
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_add_bytes')

        # 32B shadow + 24B locals (alignment)
        a.sub_rsp_imm8(0x38)

        # Root b1/b2 for GC (stack locals are NOT scanned)
        a.mov_r64_r64("rax", "rcx")
        a.mov_rip_qword_rax('gc_tmp2')
        a.mov_rip_qword_rdx('gc_tmp3')

        # save b1/b2
        a.mov_membase_disp_r64("rsp", 0x20, "rcx")
        a.mov_membase_disp_r64("rsp", 0x28, "rdx")

        # r8d=len1, r9d=len2
        a.mov_r32_membase_disp("r8d", "rcx", 4)
        a.mov_r32_membase_disp("r9d", "rdx", 4)

        # eax = totalLen
        a.mov_r32_r32("eax", "r8d")
        a.add_r32_r32("eax", "r9d")
        a.mov_membase_disp_r32("rsp", 0x30, "eax")

        # rcx = sizeBytes = 8 + totalLen
        a.mov_r32_r32("ecx", "eax")
        a.add_r32_imm("ecx", 8)
        a.call('fn_alloc')

        # rdx = base
        a.mov_rdx_rax()

        # header
        a.mov_membase_disp_imm32("rdx", 0, OBJ_BYTES, qword=False)
        a.mov_r32_membase_disp("ecx", "rsp", 0x30)
        a.mov_membase_disp_r32("rdx", 4, "ecx")

        # reload b1/b2 pointers
        a.mov_r64_membase_disp("r10", "rsp", 0x20)
        a.mov_r64_membase_disp("r11", "rsp", 0x28)

        # NOTE: r8/r9 are volatile across CALLs on Win64 ABI.
        # We used r8d/r9d before the fn_alloc call to compute totalLen,
        # but must reload them now for the copy counts.
        a.mov_r32_membase_disp("r8d", "r10", 4)  # len1
        a.mov_r32_membase_disp("r9d", "r11", 4)  # len2

        # preserve non-volatile regs we will use (RSI/RDI)
        a.push_reg("rsi")
        a.push_reg("rdi")

        # rdi = dest start
        a.lea_r64_membase_disp("rdi", "rdx", 8)

        # copy b1 payload
        a.lea_r64_membase_disp("rsi", "r10", 8)
        a.mov_r32_r32("ecx", "r8d")
        a.rep_movsb()

        # copy b2 payload
        a.lea_r64_membase_disp("rsi", "r11", 8)
        a.mov_r32_r32("ecx", "r9d")
        a.rep_movsb()

        a.pop_reg("rdi")
        a.pop_reg("rsi")

        # return base in rax
        a.mov_r64_r64("rax", "rdx")

        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_bytes_eq_function(self) -> None:
        """Emit fn_bytes_eq(a,b) -> bool (value equality by content).

        Semantics:
        - If both args are OBJ_BYTES, compare length and payload bytes.
        - Otherwise return false.

        ABI:
          RCX = a (Value)
          RDX = b (Value)
          RAX = TAG_BOOL

Returns:
    Emits or overwrites the `fn_bytes_eq` helper.
"""
        a = self.asm
        a.mark('fn_bytes_eq')

        # Keep Win64 ABI stack alignment even though we don't call out.
        a.sub_rsp_imm8(0x28)

        lid = self.new_label_id()
        l_fail = f"beq_fail_{lid}"
        l_loop = f"beq_loop_{lid}"
        l_ok = f"beq_ok_{lid}"

        # ---- type checks: both must be TAG_PTR to OBJ_BYTES ----
        # a in r8, b in r9
        a.mov_r64_r64('r8', 'rcx')
        a.mov_r64_r64('r9', 'rdx')

        # tag check a
        a.mov_r64_r64('rax', 'r8')
        a.and_r64_imm('rax', 7)
        a.cmp_r64_imm('rax', TAG_PTR)
        a.jcc('ne', l_fail)
        # tag check b
        a.mov_r64_r64('rax', 'r9')
        a.and_r64_imm('rax', 7)
        a.cmp_r64_imm('rax', TAG_PTR)
        a.jcc('ne', l_fail)

        # type check a
        a.mov_r32_membase_disp('eax', 'r8', 0)
        a.cmp_r32_imm('eax', OBJ_BYTES)
        a.jcc('ne', l_fail)
        # type check b
        a.mov_r32_membase_disp('eax', 'r9', 0)
        a.cmp_r32_imm('eax', OBJ_BYTES)
        a.jcc('ne', l_fail)

        # len1 in ecx, len2 in edx
        a.mov_r32_membase_disp('ecx', 'r8', 4)
        a.mov_r32_membase_disp('edx', 'r9', 4)
        a.cmp_r32_r32('ecx', 'edx')
        a.jcc('ne', l_fail)

        # r8 = p1, r9 = p2
        a.lea_r64_membase_disp('r8', 'r8', 8)
        a.lea_r64_membase_disp('r9', 'r9', 8)

        # loop ecx times
        a.mark(l_loop)
        a.test_r32_r32('ecx', 'ecx')
        a.jcc('e', l_ok)
        a.movzx_r32_membase_disp('eax', 'r8', 0)
        a.movzx_r32_membase_disp('edx', 'r9', 0)
        a.cmp_r32_r32('eax', 'edx')
        a.jcc('ne', l_fail)
        a.inc_r64('r8')
        a.inc_r64('r9')
        a.dec_r32('ecx')
        a.jmp(l_loop)

        # equal
        a.mark(l_ok)
        a.xor_r32_r32('eax', 'eax')
        a.inc_r32('eax')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(TAG_BOOL)
        a.add_rsp_imm8(0x28)
        a.ret()

        # not equal / unsupported
        a.mark(l_fail)
        a.xor_r32_r32('eax', 'eax')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(TAG_BOOL)
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_slice_function(self) -> None:
        """Emit builtin fn_slice(bytes, off, len) -> bytes.

        Semantics (strict):
        - Only supports bytes for now.
        - off may be negative (like indexing): off < 0 => off += len(bytes)
        - Requires: 0 <= off <= srcLen and 0 <= len and off+len <= srcLen
        - Returns VOID on any type/bounds error.

        ABI:
          RCX = src value
          RDX = off (Value)
          R8  = len (Value)
          RAX = OBJ_BYTES* (TAG_PTR) or VOID

Returns:
    Emits or overwrites the `fn_slice` helper.
"""
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_slice')

        # Preserve nonvolatile regs we use (Win64 ABI)
        a.push_reg('rsi')
        a.push_reg('rdi')

        # 32B shadow + 40B locals (alignment)
        a.sub_rsp_imm8(0x48)

        lid = self.new_label_id()
        l_fail = f"slice_fail_{lid}"
        l_done = f"slice_done_{lid}"
        l_off_nonneg = f"slice_off_nonneg_{lid}"

        # --- type check src: must be TAG_PTR to OBJ_BYTES ---
        a.mov_r64_r64('rax', 'rcx')

        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_fail)

        # IMPORTANT: do NOT clobber RDX here (it holds the 2nd argument: off Value).
        # Using EDX would zero-extend into RDX and destroy the argument, causing slice()
        # to always fail its tag checks and return void.
        a.mov_r32_membase_disp('r11d', 'rax', 0)
        a.cmp_r32_imm('r11d', OBJ_BYTES)
        a.jcc('ne', l_fail)

        # Root src for GC safety
        a.mov_rip_qword_rax('gc_tmp2')

        # spill src
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')

        # srcLen -> r9d/r9
        a.mov_r32_membase_disp('r9d', 'rax', 4)

        # --- decode off (RDX) ---
        a.mov_r64_r64('rax', 'rdx')
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_INT)
        a.jcc('ne', l_fail)
        a.sar_r64_imm8('rax', 3)  # off (signed)
        a.mov_membase_disp_r64('rsp', 0x28, 'rax')

        # --- decode len (R8) ---
        a.mov_r64_r64('rax', 'r8')
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_INT)
        a.jcc('ne', l_fail)
        a.sar_r64_imm8('rax', 3)  # len (signed)
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_fail)
        a.cmp_r64_imm('rax', 0x7FFFFFFF)
        a.jcc('g', l_fail)
        a.mov_membase_disp_r32('rsp', 0x30, 'eax')  # store len as u32

        # --- normalize off (allow negative) ---
        a.mov_r64_membase_disp('rax', 'rsp', 0x28)  # off
        a.cmp_r64_imm('rax', 0)
        a.jcc('ge', l_off_nonneg)
        # off += srcLen
        a.add_r64_r64('rax', 'r9')
        a.mark(l_off_nonneg)

        # bounds: 0 <= off <= srcLen
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_fail)
        a.cmp_r64_r64('rax', 'r9')
        a.jcc('g', l_fail)

        # ensure off + len <= srcLen
        a.mov_r64_r64('r11', 'rax')  # off
        a.mov_r32_membase_disp('r10d', 'rsp', 0x30)  # len (u32) -> r10
        a.add_r64_r64('r11', 'r10')  # off+len
        a.cmp_r64_r64('r11', 'r9')
        a.jcc('g', l_fail)

        # spill normalized off back
        a.mov_membase_disp_r64('rsp', 0x28, 'rax')

        # --- allocate dest bytes(len, fill=0) ---
        a.mov_r32_membase_disp('ecx', 'rsp', 0x30)  # len u32
        a.xor_r32_r32('edx', 'edx')  # fill = 0
        a.call('fn_bytes_alloc')

        # dest in r11
        a.mov_r11_rax()

        # if len == 0 -> return dest
        a.mov_r32_membase_disp('ecx', 'rsp', 0x30)
        a.test_r32_r32('ecx', 'ecx')
        a.jcc('e', l_done)

        # reload src + off
        a.mov_r64_membase_disp('r10', 'rsp', 0x20)  # src
        a.mov_r64_membase_disp('r9', 'rsp', 0x28)  # off

        # rsi = src + 8 + off
        a.lea_r64_mem_bis('rsi', 'r10', 'r9', 1, 8)
        # rdi = dest + 8
        a.lea_r64_membase_disp('rdi', 'r11', 8)

        # rcx already has len (u32)
        a.rep_movsb()

        a.mark(l_done)
        a.mov_rax_r11()
        a.add_rsp_imm8(0x48)
        a.pop_reg('rdi')
        a.pop_reg('rsi')
        a.ret()

        a.mark(l_fail)
        a.mov_rax_imm64(enc_void())
        a.add_rsp_imm8(0x48)
        a.pop_reg('rdi')
        a.pop_reg('rsi')
        a.ret()
