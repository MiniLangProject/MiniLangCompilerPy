"""Runtime/builtins codegen mixin.

This module emits small helper routines and language builtins that are shared across
programs (e.g. typeof(), toNumber(), value/string equality helpers, argv init, and
an unhandled-error abort helper).
"""

from __future__ import annotations

from ..constants import (CALLSTAT_STRUCT_ID, ERROR_STRUCT_ID, GC_BLOCK_SIZE_MASK, GC_HEADER_SIZE, GC_OFF_BLOCK_SIZE,
                         OBJ_ARRAY, OBJ_BUILTIN, OBJ_BYTES, OBJ_CLOSURE, OBJ_FLOAT, OBJ_FUNCTION, OBJ_STRING, OBJ_STRUCT,
                         OBJ_STRUCTTYPE, TAG_BOOL, TAG_ENUM, TAG_FLOAT, TAG_INT, TAG_PTR, TAG_VOID, )
from ..tools import enc_bool, enc_int, enc_void


class CodegenRuntime:
    """Codegen mixin for small runtime helpers and builtins.

    This mixin is composed into :class:`mlc.codegen.codegen.Codegen`. It assumes
    helpers/fields provided by other mixins (notably CodegenCore), such as:

    - ``self.asm``: instruction emitter
    - ``self.new_label_id()``: unique label generator
    - ``self.rdata`` / ``self.data``: constant & global builders
    - helper emitters like ``emit_writefile`` / ``emit_writefile_ptr_len``
    """

    def emit_cpu_init_function(self) -> None:
        """Probe optional SIMD features once at startup."""
        a = self.asm
        a.mark('fn_cpu_init')

        lid = self.new_label_id()
        l_no = f"cpuinit_no_{lid}"
        l_done = f"cpuinit_done_{lid}"

        a.push_reg('rbx')
        a.xor_r32_r32('eax', 'eax')
        a.xor_r32_r32('ecx', 'ecx')
        a.cpuid()
        a.cmp_r32_imm('eax', 7)
        a.jcc('b', l_no)

        a.mov_r32_imm32('eax', 1)
        a.xor_r32_r32('ecx', 'ecx')
        a.cpuid()
        a.mov_r32_r32('r10d', 'ecx')
        a.and_r32_imm('r10d', (1 << 27) | (1 << 28))
        a.cmp_r32_imm('r10d', (1 << 27) | (1 << 28))
        a.jcc('ne', l_no)

        a.xor_r32_r32('ecx', 'ecx')
        a.xgetbv()
        a.and_r32_imm('eax', 0x6)
        a.cmp_r32_imm('eax', 0x6)
        a.jcc('ne', l_no)

        a.mov_r32_imm32('eax', 7)
        a.xor_r32_r32('ecx', 'ecx')
        a.cpuid()
        a.mov_r32_r32('eax', 'ebx')
        a.shr_r32_imm8('eax', 5)
        a.and_r32_imm('eax', 1)
        a.mov_rip_dword_eax('cpu_has_avx2')
        a.jmp(l_done)

        a.mark(l_no)
        a.xor_r32_r32('eax', 'eax')
        a.mov_rip_dword_eax('cpu_has_avx2')

        a.mark(l_done)
        a.pop_reg('rbx')
        a.ret()

    def emit_mem_eq_bytes_function(self) -> None:
        """Emit fn_mem_eq_bytes(p1, p2, len) -> bool."""
        a = self.asm
        a.mark('fn_mem_eq_bytes')

        lid = self.new_label_id()
        l_true = f"memeq_true_{lid}"
        l_false = f"memeq_false_{lid}"
        l_false_avx = f"memeq_false_avx_{lid}"
        l_avx_check = f"memeq_avx_check_{lid}"
        l_avx_loop = f"memeq_avx_loop_{lid}"
        l_avx_done = f"memeq_avx_done_{lid}"
        l_sse_loop = f"memeq_sse_loop_{lid}"
        l_tail = f"memeq_tail_{lid}"
        l_tail_loop = f"memeq_tail_loop_{lid}"
        l_done = f"memeq_done_{lid}"

        a.cmp_r64_r64('rcx', 'rdx')
        a.jcc('e', l_true)
        a.test_r32_r32('r8d', 'r8d')
        a.jcc('e', l_true)

        a.mov_r64_r64('r9', 'rcx')
        a.mov_r64_r64('r10', 'rdx')
        a.mov_r32_r32('r11d', 'r8d')

        a.mov_eax_rip_dword('cpu_has_avx2')
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_sse_loop)
        a.cmp_r32_imm('r11d', 32)
        a.jcc('b', l_sse_loop)

        a.mark(l_avx_check)
        a.cmp_r32_imm('r11d', 32)
        a.jcc('b', l_avx_done)
        a.mark(l_avx_loop)
        a.vmovdqu_ymm_membase_disp('ymm0', 'r9', 0)
        a.vmovdqu_ymm_membase_disp('ymm1', 'r10', 0)
        a.vpcmpeqb_ymm_ymm_ymm('ymm0', 'ymm0', 'ymm1')
        a.vpmovmskb_r32_ymm('eax', 'ymm0')
        a.cmp_r32_imm('eax', 0xFFFFFFFF)
        a.jcc('ne', l_false_avx)
        a.add_r64_imm('r9', 32)
        a.add_r64_imm('r10', 32)
        a.sub_r32_imm('r11d', 32)
        a.cmp_r32_imm('r11d', 32)
        a.jcc('ae', l_avx_loop)

        a.mark(l_avx_done)
        a.vzeroupper()

        a.mark(l_sse_loop)
        a.cmp_r32_imm('r11d', 16)
        a.jcc('b', l_tail)
        a.movdqu_xmm_membase_disp('xmm0', 'r9', 0)
        a.movdqu_xmm_membase_disp('xmm1', 'r10', 0)
        a.pcmpeqb_xmm_xmm('xmm0', 'xmm1')
        a.pmovmskb_r32_xmm('eax', 'xmm0')
        a.cmp_r32_imm('eax', 0xFFFF)
        a.jcc('ne', l_false)
        a.add_r64_imm('r9', 16)
        a.add_r64_imm('r10', 16)
        a.sub_r32_imm('r11d', 16)
        a.jmp(l_sse_loop)

        a.mark(l_tail)
        a.test_r32_r32('r11d', 'r11d')
        a.jcc('e', l_true)
        a.mark(l_tail_loop)
        a.movzx_r32_membase_disp('eax', 'r9', 0)
        a.movzx_r32_membase_disp('edx', 'r10', 0)
        a.cmp_r32_r32('eax', 'edx')
        a.jcc('ne', l_false)
        a.inc_r64('r9')
        a.inc_r64('r10')
        a.dec_r32('r11d')
        a.jcc('ne', l_tail_loop)
        a.jmp(l_true)

        a.mark(l_false_avx)
        a.vzeroupper()
        a.jmp(l_false)

        a.mark(l_false)
        a.mov_rax_imm64(enc_bool(False))
        a.jmp(l_done)

        a.mark(l_true)
        a.mov_rax_imm64(enc_bool(True))

        a.mark(l_done)
        a.ret()

    def emit_scan_nul_bytes_function(self) -> None:
        """Emit fn_scan_nul_bytes(ptr, maxlen) -> EDX index of first NUL or maxlen."""
        a = self.asm
        a.mark('fn_scan_nul_bytes')

        lid = self.new_label_id()
        l_avx_setup = f"scan0b_avx_setup_{lid}"
        l_avx_loop = f"scan0b_avx_loop_{lid}"
        l_avx_found = f"scan0b_avx_found_{lid}"
        l_avx_done = f"scan0b_avx_done_{lid}"
        l_sse_setup = f"scan0b_sse_setup_{lid}"
        l_sse_loop = f"scan0b_sse_loop_{lid}"
        l_sse_found = f"scan0b_sse_found_{lid}"
        l_tail = f"scan0b_tail_{lid}"
        l_tail_loop = f"scan0b_tail_loop_{lid}"
        l_done = f"scan0b_done_{lid}"

        a.mov_r64_r64('r8', 'rcx')
        a.mov_r32_r32('r10d', 'edx')
        a.xor_r32_r32('r9d', 'r9d')

        a.mov_eax_rip_dword('cpu_has_avx2')
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_sse_setup)
        a.cmp_r32_imm('r10d', 32)
        a.jcc('b', l_sse_setup)

        a.mark(l_avx_setup)
        a.vpxor_ymm_ymm_ymm('ymm0', 'ymm0', 'ymm0')
        a.mark(l_avx_loop)
        a.mov_r32_r32('eax', 'r10d')
        a.sub_r32_imm('eax', 32)
        a.cmp_r32_r32('eax', 'r9d')
        a.jcc('l', l_avx_done)
        a.lea_r64_mem_bis('r11', 'r8', 'r9', 1, 0)
        a.vmovdqu_ymm_membase_disp('ymm1', 'r11', 0)
        a.vpcmpeqb_ymm_ymm_ymm('ymm1', 'ymm1', 'ymm0')
        a.vpmovmskb_r32_ymm('eax', 'ymm1')
        a.test_r32_r32('eax', 'eax')
        a.jcc('ne', l_avx_found)
        a.add_r32_imm('r9d', 32)
        a.jmp(l_avx_loop)

        a.mark(l_avx_found)
        a.bsf_r32_r32('eax', 'eax')
        a.add_r32_r32('eax', 'r9d')
        a.mov_r32_r32('edx', 'eax')
        a.vzeroupper()
        a.ret()

        a.mark(l_avx_done)
        a.vzeroupper()

        a.mark(l_sse_setup)
        a.pxor_xmm_xmm('xmm0', 'xmm0')
        a.mark(l_sse_loop)
        a.mov_r32_r32('eax', 'r10d')
        a.sub_r32_imm('eax', 16)
        a.cmp_r32_r32('eax', 'r9d')
        a.jcc('l', l_tail)
        a.lea_r64_mem_bis('r11', 'r8', 'r9', 1, 0)
        a.movdqu_xmm_membase_disp('xmm1', 'r11', 0)
        a.pcmpeqb_xmm_xmm('xmm1', 'xmm0')
        a.pmovmskb_r32_xmm('eax', 'xmm1')
        a.test_r32_r32('eax', 'eax')
        a.jcc('ne', l_sse_found)
        a.add_r32_imm('r9d', 16)
        a.jmp(l_sse_loop)

        a.mark(l_sse_found)
        a.bsf_r32_r32('eax', 'eax')
        a.add_r32_r32('eax', 'r9d')
        a.mov_r32_r32('edx', 'eax')
        a.ret()

        a.mark(l_tail)
        a.mark(l_tail_loop)
        a.cmp_r32_r32('r9d', 'r10d')
        a.jcc('ge', l_done)
        a.lea_r64_mem_bis('r11', 'r8', 'r9', 1, 0)
        a.movzx_r32_membase_disp('eax', 'r11', 0)
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_done)
        a.inc_r32('r9d')
        a.jmp(l_tail_loop)

        a.mark(l_done)
        a.mov_r32_r32('edx', 'r9d')
        a.ret()

    def emit_scan_byte2_bytes_function(self) -> None:
        """Emit fn_scan_byte2_bytes(ptr, maxlen, b1, b2) -> EDX index of first match or maxlen."""
        a = self.asm
        a.mark('fn_scan_byte2_bytes')

        lid = self.new_label_id()
        l_sse_loop = f"scan2b_sse_loop_{lid}"
        l_sse_found = f"scan2b_sse_found_{lid}"
        l_tail = f"scan2b_tail_{lid}"
        l_tail_loop = f"scan2b_tail_loop_{lid}"
        l_done = f"scan2b_done_{lid}"

        a.mov_r64_r64('r10', 'rcx')
        a.mov_r32_r32('r11d', 'edx')

        # Broadcast b1 into xmm0
        a.movzx_r32_r8('eax', 'r8b')
        a.mov_r64_r64('rdx', 'rax')
        a.shl_r64_imm8('rdx', 8)
        a.or_r64_r64('rax', 'rdx')
        a.mov_r64_r64('rdx', 'rax')
        a.shl_r64_imm8('rdx', 16)
        a.or_r64_r64('rax', 'rdx')
        a.mov_r64_r64('rdx', 'rax')
        a.shl_r64_imm8('rdx', 32)
        a.or_r64_r64('rax', 'rdx')
        a.movq_xmm_r64('xmm0', 'rax')
        a.punpcklqdq_xmm_xmm('xmm0', 'xmm0')

        # Broadcast b2 into xmm2
        a.movzx_r32_r8('eax', 'r9b')
        a.mov_r64_r64('rdx', 'rax')
        a.shl_r64_imm8('rdx', 8)
        a.or_r64_r64('rax', 'rdx')
        a.mov_r64_r64('rdx', 'rax')
        a.shl_r64_imm8('rdx', 16)
        a.or_r64_r64('rax', 'rdx')
        a.mov_r64_r64('rdx', 'rax')
        a.shl_r64_imm8('rdx', 32)
        a.or_r64_r64('rax', 'rdx')
        a.movq_xmm_r64('xmm2', 'rax')
        a.punpcklqdq_xmm_xmm('xmm2', 'xmm2')

        a.xor_r32_r32('ecx', 'ecx')

        a.mark(l_sse_loop)
        a.mov_r32_r32('eax', 'r11d')
        a.sub_r32_imm('eax', 16)
        a.cmp_r32_r32('eax', 'ecx')
        a.jcc('l', l_tail)
        a.lea_r64_mem_bis('rax', 'r10', 'rcx', 1, 0)
        a.movdqu_xmm_membase_disp('xmm1', 'rax', 0)
        a.movdqu_xmm_membase_disp('xmm3', 'rax', 0)
        a.pcmpeqb_xmm_xmm('xmm1', 'xmm0')
        a.pcmpeqb_xmm_xmm('xmm3', 'xmm2')
        a.pmovmskb_r32_xmm('eax', 'xmm1')
        a.pmovmskb_r32_xmm('edx', 'xmm3')
        a.or_r64_r64('rax', 'rdx')
        a.test_r32_r32('eax', 'eax')
        a.jcc('ne', l_sse_found)
        a.add_r32_imm('ecx', 16)
        a.jmp(l_sse_loop)

        a.mark(l_sse_found)
        a.bsf_r32_r32('eax', 'eax')
        a.add_r32_r32('eax', 'ecx')
        a.mov_r32_r32('edx', 'eax')
        a.ret()

        a.mark(l_tail)
        a.mark(l_tail_loop)
        a.cmp_r32_r32('ecx', 'r11d')
        a.jcc('ge', l_done)
        a.lea_r64_mem_bis('rax', 'r10', 'rcx', 1, 0)
        a.movzx_r32_membase_disp('eax', 'rax', 0)
        a.movzx_r32_r8('edx', 'r8b')
        a.cmp_r32_r32('eax', 'edx')
        a.jcc('e', l_done)
        a.movzx_r32_r8('edx', 'r9b')
        a.cmp_r32_r32('eax', 'edx')
        a.jcc('e', l_done)
        a.inc_r32('ecx')
        a.jmp(l_tail_loop)

        a.mark(l_done)
        a.mov_r32_r32('edx', 'ecx')
        a.ret()

    def emit_scan_nul_wchars_function(self) -> None:
        """Emit fn_scan_nul_wchars(ptr, max_wchars) -> EDX index of first UTF-16 NUL or max."""
        a = self.asm
        a.mark('fn_scan_nul_wchars')

        lid = self.new_label_id()
        l_avx_setup = f"scan0w_avx_setup_{lid}"
        l_avx_loop = f"scan0w_avx_loop_{lid}"
        l_avx_found = f"scan0w_avx_found_{lid}"
        l_avx_done = f"scan0w_avx_done_{lid}"
        l_sse_setup = f"scan0w_sse_setup_{lid}"
        l_sse_loop = f"scan0w_sse_loop_{lid}"
        l_sse_found = f"scan0w_sse_found_{lid}"
        l_tail = f"scan0w_tail_{lid}"
        l_tail_loop = f"scan0w_tail_loop_{lid}"
        l_done = f"scan0w_done_{lid}"
        l_tail_cont = f"scan0w_tail_cont_{lid}"

        a.mov_r64_r64('r8', 'rcx')
        a.mov_r32_r32('r10d', 'edx')
        a.xor_r32_r32('r9d', 'r9d')

        a.mov_eax_rip_dword('cpu_has_avx2')
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_sse_setup)
        a.cmp_r32_imm('r10d', 16)
        a.jcc('b', l_sse_setup)

        a.mark(l_avx_setup)
        a.vpxor_ymm_ymm_ymm('ymm0', 'ymm0', 'ymm0')
        a.mark(l_avx_loop)
        a.mov_r32_r32('eax', 'r10d')
        a.sub_r32_imm('eax', 16)
        a.cmp_r32_r32('eax', 'r9d')
        a.jcc('l', l_avx_done)
        a.lea_r64_mem_bis('r11', 'r8', 'r9', 2, 0)
        a.vmovdqu_ymm_membase_disp('ymm1', 'r11', 0)
        a.vpcmpeqw_ymm_ymm_ymm('ymm1', 'ymm1', 'ymm0')
        a.vpmovmskb_r32_ymm('eax', 'ymm1')
        a.test_r32_r32('eax', 'eax')
        a.jcc('ne', l_avx_found)
        a.add_r32_imm('r9d', 16)
        a.jmp(l_avx_loop)

        a.mark(l_avx_found)
        a.bsf_r32_r32('eax', 'eax')
        a.shr_r32_imm8('eax', 1)
        a.add_r32_r32('eax', 'r9d')
        a.mov_r32_r32('edx', 'eax')
        a.vzeroupper()
        a.ret()

        a.mark(l_avx_done)
        a.vzeroupper()

        a.mark(l_sse_setup)
        a.pxor_xmm_xmm('xmm0', 'xmm0')
        a.mark(l_sse_loop)
        a.mov_r32_r32('eax', 'r10d')
        a.sub_r32_imm('eax', 8)
        a.cmp_r32_r32('eax', 'r9d')
        a.jcc('l', l_tail)
        a.lea_r64_mem_bis('r11', 'r8', 'r9', 2, 0)
        a.movdqu_xmm_membase_disp('xmm1', 'r11', 0)
        a.pcmpeqw_xmm_xmm('xmm1', 'xmm0')
        a.pmovmskb_r32_xmm('eax', 'xmm1')
        a.test_r32_r32('eax', 'eax')
        a.jcc('ne', l_sse_found)
        a.add_r32_imm('r9d', 8)
        a.jmp(l_sse_loop)

        a.mark(l_sse_found)
        a.bsf_r32_r32('eax', 'eax')
        a.shr_r32_imm8('eax', 1)
        a.add_r32_r32('eax', 'r9d')
        a.mov_r32_r32('edx', 'eax')
        a.ret()

        a.mark(l_tail)
        a.mark(l_tail_loop)
        a.cmp_r32_r32('r9d', 'r10d')
        a.jcc('ge', l_done)
        a.lea_r64_mem_bis('r11', 'r8', 'r9', 2, 0)
        a.movzx_r32_membase_disp('eax', 'r11', 0)
        a.test_r32_r32('eax', 'eax')
        a.jcc('ne', l_tail_cont)
        a.movzx_r32_membase_disp('eax', 'r11', 1)
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_done)
        a.mark(l_tail_cont)
        a.inc_r32('r9d')
        a.jmp(l_tail_loop)

        a.mark(l_done)
        a.mov_r32_r32('edx', 'r9d')
        a.ret()

    def emit_copy_bytes_function(self) -> None:
        """Emit fn_copy_bytes(dst, src, len)."""
        a = self.asm
        a.mark('fn_copy_bytes')

        lid = self.new_label_id()
        l_ret = f"cpy_ret_{lid}"
        l_scalar_small = f"cpy_scalar_small_{lid}"
        l_scalar_loop = f"cpy_scalar_loop_{lid}"
        l_qword_small = f"cpy_qword_small_{lid}"
        l_xmm_small = f"cpy_xmm_small_{lid}"
        l_large = f"cpy_large_{lid}"
        l_avx_loop = f"cpy_avx_loop_{lid}"
        l_avx_done = f"cpy_avx_done_{lid}"
        l_sse_loop = f"cpy_sse_loop_{lid}"
        l_tail = f"cpy_tail_{lid}"
        l_rep = f"cpy_rep_{lid}"

        a.test_r32_r32('r8d', 'r8d')
        a.jcc('e', l_ret)
        a.cmp_r32_imm('r8d', 8)
        a.jcc('b', l_scalar_small)
        a.cmp_r32_imm('r8d', 16)
        a.jcc('b', l_qword_small)
        a.cmp_r32_imm('r8d', 32)
        a.jcc('be', l_xmm_small)
        a.jmp(l_large)

        a.mark(l_scalar_small)
        a.mov_r64_r64('r9', 'rcx')
        a.mov_r64_r64('r10', 'rdx')
        a.mov_r32_r32('r11d', 'r8d')
        a.mark(l_scalar_loop)
        a.mov_r8_membase_disp('al', 'r10', 0)
        a.mov_membase_disp_r8('r9', 0, 'al')
        a.inc_r64('r9')
        a.inc_r64('r10')
        a.dec_r32('r11d')
        a.jcc('ne', l_scalar_loop)
        a.ret()

        a.mark(l_qword_small)
        a.mov_r64_membase_disp('rax', 'rdx', 0)
        a.mov_membase_disp_r64('rcx', 0, 'rax')
        a.mov_r32_r32('r11d', 'r8d')
        a.sub_r32_imm('r11d', 8)
        a.lea_r64_mem_bis('r10', 'rdx', 'r11', 1, 0)
        a.mov_r64_membase_disp('rax', 'r10', 0)
        a.lea_r64_mem_bis('r9', 'rcx', 'r11', 1, 0)
        a.mov_membase_disp_r64('r9', 0, 'rax')
        a.ret()

        a.mark(l_xmm_small)
        a.movdqu_xmm_membase_disp('xmm0', 'rdx', 0)
        a.movdqu_membase_disp_xmm('rcx', 0, 'xmm0')
        a.cmp_r32_imm('r8d', 16)
        a.jcc('e', l_ret)
        a.mov_r32_r32('r11d', 'r8d')
        a.sub_r32_imm('r11d', 16)
        a.lea_r64_mem_bis('r10', 'rdx', 'r11', 1, 0)
        a.movdqu_xmm_membase_disp('xmm0', 'r10', 0)
        a.lea_r64_mem_bis('r9', 'rcx', 'r11', 1, 0)
        a.movdqu_membase_disp_xmm('r9', 0, 'xmm0')
        a.ret()

        a.mark(l_large)
        a.mov_r64_r64('r9', 'rcx')
        a.mov_r64_r64('r10', 'rdx')
        a.mov_r32_r32('r11d', 'r8d')
        a.mov_eax_rip_dword('cpu_has_avx2')
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_rep)
        a.cmp_r32_imm('r11d', 64)
        a.jcc('b', l_sse_loop)

        a.mark(l_avx_loop)
        a.cmp_r32_imm('r11d', 32)
        a.jcc('b', l_avx_done)
        a.vmovdqu_ymm_membase_disp('ymm0', 'r10', 0)
        a.vmovdqu_membase_disp_ymm('r9', 0, 'ymm0')
        a.add_r64_imm('r9', 32)
        a.add_r64_imm('r10', 32)
        a.sub_r32_imm('r11d', 32)
        a.jmp(l_avx_loop)

        a.mark(l_avx_done)
        a.vzeroupper()

        a.mark(l_sse_loop)
        a.cmp_r32_imm('r11d', 16)
        a.jcc('b', l_tail)
        a.movdqu_xmm_membase_disp('xmm0', 'r10', 0)
        a.movdqu_membase_disp_xmm('r9', 0, 'xmm0')
        a.add_r64_imm('r9', 16)
        a.add_r64_imm('r10', 16)
        a.sub_r32_imm('r11d', 16)
        a.jmp(l_sse_loop)

        a.mark(l_tail)
        a.test_r32_r32('r11d', 'r11d')
        a.jcc('e', l_ret)
        a.mov_r8_membase_disp('al', 'r10', 0)
        a.mov_membase_disp_r8('r9', 0, 'al')
        a.inc_r64('r9')
        a.inc_r64('r10')
        a.dec_r32('r11d')
        a.jmp(l_tail)

        a.mark(l_rep)
        a.push_reg('rsi')
        a.push_reg('rdi')
        a.mov_r64_r64('rdi', 'rcx')
        a.mov_r64_r64('rsi', 'rdx')
        a.mov_r32_r32('ecx', 'r8d')
        a.rep_movsb()
        a.pop_reg('rdi')
        a.pop_reg('rsi')

        a.mark(l_ret)
        a.ret()

    def emit_fill_bytes_function(self) -> None:
        """Emit fn_fill_bytes(dst, len, fill_u8)."""
        a = self.asm
        a.mark('fn_fill_bytes')

        lid = self.new_label_id()
        l_ret = f"fillb_ret_{lid}"
        l_scalar = f"fillb_scalar_{lid}"
        l_scalar_loop = f"fillb_scalar_loop_{lid}"
        l_after_pattern = f"fillb_after_pattern_{lid}"
        l_qword = f"fillb_qword_{lid}"
        l_xmm = f"fillb_xmm_{lid}"
        l_xmm_loop = f"fillb_xmm_loop_{lid}"
        l_tail = f"fillb_tail_{lid}"
        l_rep = f"fillb_rep_{lid}"

        a.test_r32_r32('edx', 'edx')
        a.jcc('e', l_ret)
        a.cmp_r32_imm('edx', 8)
        a.jcc('b', l_scalar)

        a.movzx_r32_r8('eax', 'r8b')
        a.mov_r64_r64('r10', 'rax')
        a.shl_r64_imm8('r10', 8)
        a.or_r64_r64('rax', 'r10')
        a.mov_r64_r64('r10', 'rax')
        a.shl_r64_imm8('r10', 16)
        a.or_r64_r64('rax', 'r10')
        a.mov_r64_r64('r10', 'rax')
        a.shl_r64_imm8('r10', 32)
        a.or_r64_r64('rax', 'r10')
        a.jmp(l_after_pattern)

        a.mark(l_scalar)
        a.mov_r64_r64('r9', 'rcx')
        a.mov_r32_r32('r10d', 'edx')
        a.mark(l_scalar_loop)
        a.mov_membase_disp_r8('r9', 0, 'r8b')
        a.inc_r64('r9')
        a.dec_r32('r10d')
        a.jcc('ne', l_scalar_loop)
        a.ret()

        a.mark(l_after_pattern)
        a.cmp_r32_imm('edx', 16)
        a.jcc('b', l_qword)

        a.movq_xmm_r64('xmm0', 'rax')
        a.punpcklqdq_xmm_xmm('xmm0', 'xmm0')
        a.cmp_r32_imm('edx', 32)
        a.jcc('be', l_xmm)
        a.cmp_r32_imm('edx', 64)
        a.jcc('a', l_rep)

        a.mov_r64_r64('r9', 'rcx')
        a.mov_r32_r32('r10d', 'edx')
        a.mark(l_xmm_loop)
        a.cmp_r32_imm('r10d', 16)
        a.jcc('b', l_tail)
        a.movdqu_membase_disp_xmm('r9', 0, 'xmm0')
        a.add_r64_imm('r9', 16)
        a.sub_r32_imm('r10d', 16)
        a.jmp(l_xmm_loop)

        a.mark(l_qword)
        a.mov_membase_disp_r64('rcx', 0, 'rax')
        a.mov_r32_r32('r10d', 'edx')
        a.sub_r32_imm('r10d', 8)
        a.lea_r64_mem_bis('r9', 'rcx', 'r10', 1, 0)
        a.mov_membase_disp_r64('r9', 0, 'rax')
        a.ret()

        a.mark(l_xmm)
        a.movdqu_membase_disp_xmm('rcx', 0, 'xmm0')
        a.cmp_r32_imm('edx', 16)
        a.jcc('e', l_ret)
        a.mov_r32_r32('r10d', 'edx')
        a.sub_r32_imm('r10d', 16)
        a.lea_r64_mem_bis('r9', 'rcx', 'r10', 1, 0)
        a.movdqu_membase_disp_xmm('r9', 0, 'xmm0')
        a.ret()

        a.mark(l_tail)
        a.test_r32_r32('r10d', 'r10d')
        a.jcc('e', l_ret)
        a.mov_membase_disp_r8('r9', 0, 'r8b')
        a.inc_r64('r9')
        a.dec_r32('r10d')
        a.jmp(l_tail)

        a.mark(l_rep)
        a.push_reg('rdi')
        a.mov_r64_r64('rdi', 'rcx')
        a.mov_r8_r8('al', 'r8b')
        a.mov_r32_r32('ecx', 'edx')
        a.rep_stosb()
        a.pop_reg('rdi')

        a.mark(l_ret)
        a.ret()

    def emit_fill_qwords_function(self) -> None:
        """Emit fn_fill_qwords(dst, count, value64)."""
        a = self.asm
        a.mark('fn_fill_qwords')

        lid = self.new_label_id()
        l_ret = f"fillq_ret_{lid}"
        l_small = f"fillq_small_{lid}"
        l_rep = f"fillq_rep_{lid}"

        a.test_r32_r32('edx', 'edx')
        a.jcc('e', l_ret)
        a.mov_r64_r64('rax', 'r8')
        a.cmp_r32_imm('edx', 1)
        a.jcc('e', l_small)
        a.cmp_r32_imm('edx', 4)
        a.jcc('a', l_rep)

        a.movq_xmm_r64('xmm0', 'rax')
        a.punpcklqdq_xmm_xmm('xmm0', 'xmm0')
        a.movdqu_membase_disp_xmm('rcx', 0, 'xmm0')
        a.cmp_r32_imm('edx', 2)
        a.jcc('e', l_ret)
        a.mov_r32_r32('r10d', 'edx')
        a.shl_r32_imm8('r10d', 3)
        a.sub_r32_imm('r10d', 16)
        a.lea_r64_mem_bis('r9', 'rcx', 'r10', 1, 0)
        a.movdqu_membase_disp_xmm('r9', 0, 'xmm0')
        a.ret()

        a.mark(l_small)
        a.mov_membase_disp_r64('rcx', 0, 'rax')
        a.ret()

        a.mark(l_rep)
        a.push_reg('rdi')
        a.mov_r64_r64('rdi', 'rcx')
        a.mov_r32_r32('ecx', 'edx')
        a.rep_stosq()
        a.pop_reg('rdi')

        a.mark(l_ret)
        a.ret()

    def emit_int_to_dec_function(self) -> None:
        """Emit an internal function:

        int_to_dec:
          input: RCX = tagged int
          output: RAX = ptr (into intbuf), EDX = length

        Uses only volatile regs, preserves RDI.
        """
        a = self.asm
        a.mark('fn_int_to_dec')

        # push rdi (nonvolatile)
        a.push_reg("rdi")

        # rax = rcx
        a.mov_r64_r64("rax", "rcx")
        # decode: sar rax,3
        a.sar_rax_imm8(3)

        # r9 = &intbuf_end
        a.lea_r9_rip('intbuf_end')
        # rdi = r9
        a.mov_r64_r64("rdi", "r9")

        # if rax == 0 -> write '0'
        a.test_r64_r64("rax", "rax")  # test rax,rax
        a.jcc('nz', 'itd_nonzero')

        # dec rdi
        a.dec_r64("rdi")
        # mov byte [rdi], '0'
        a.mov_membase_disp_imm8("rdi", 0, 0x30)
        # mov rax, rdi
        a.mov_r64_r64("rax", "rdi")
        # mov edx, 1
        a.mov_r32_imm32("edx", 1)
        # pop rdi ; ret
        a.pop_reg("rdi")
        a.ret()

        a.mark('itd_nonzero')

        # r10d = 0 (sign flag)
        a.xor_r32_r32("r10d", "r10d")  # xor r10d,r10d

        # if rax < 0: neg rax; sign=1
        a.test_r64_r64("rax", "rax")
        a.jcc('ge', 'itd_pos')
        a.neg_r64("rax")  # neg rax
        a.mov_r32_imm32("r10d", 1)  # mov r10d,1
        a.mark('itd_pos')

        a.mark('itd_loop')
        # edx = 0
        a.xor_r32_r32("edx", "edx")
        # r11d = 10
        a.mov_r32_imm32("r11d", 10)
        # div r11  (rdx:rax / r11)
        a.div_r64("r11")
        # dl += '0'
        a.add_r8_imm8("dl", 48)
        # dec rdi
        a.dec_r64("rdi")
        # mov [rdi], dl
        a.mov_membase_disp_r8("rdi", 0, "dl")
        # test rax,rax
        a.test_r64_r64("rax", "rax")
        a.jcc('nz', 'itd_loop')

        # if sign flag == 0 -> done
        a.cmp_r32_imm("r10d", 0)  # cmp r10d,0
        a.jcc('e', 'itd_done')
        # dec rdi; mov byte [rdi], '-'
        a.dec_r64("rdi")
        a.mov_membase_disp_imm8("rdi", 0, 0x2D)

        a.mark('itd_done')

        # rax = rdi (ptr)
        a.mov_r64_r64("rax", "rdi")

        # r11 = r9; r11 -= rdi; edx = r11d
        a.mov_r64_r64("r11", "r9")  # mov r11,r9
        a.sub_r64_r64("r11", "rdi")  # sub r11,rdi
        a.mov_r32_r32("edx", "r11d")  # mov edx,r11d

        # pop rdi; ret
        a.pop_reg("rdi")
        a.ret()

    def emit_toNumber_function(self) -> None:
        r"""Builtin: toNumber(x) -> int or float

        Supported inputs:
        - int: returned unchanged
        - float: normalized (10.0 -> 10) else unchanged
        - string: trims ASCII whitespace, parses:
            - -?\d+   -> int
            - -?\d+\.\d+ -> float (normalized if exact int)

        On unsupported inputs, returns VOID (native compiler currently has no exceptions).

        ABI:
          RCX = value
          RAX = result
        """
        a = self.asm
        a.mark('fn_toNumber')

        # Align stack + provide shadow space for internal calls (fn_box_float)
        a.sub_rsp_imm8(0x28)

        lid = self.new_label_id()
        l_immf = f"ton_immf_{lid}"
        l_ptr = f"ton_ptr_{lid}"
        l_float = f"ton_float_{lid}"
        l_str = f"ton_str_{lid}"
        l_fail = f"ton_fail_{lid}"
        l_done = f"ton_done_{lid}"

        # rax = rcx
        a.mov_r64_r64("rax", "rcx")

        # rdx = tag = rax & 7
        a.mov_r64_r64("rdx", "rax")
        a.and_r64_imm("rdx", 7)

        # if tag == TAG_INT -> return input
        a.cmp_r64_imm("rdx", 1)
        a.jcc('e', l_done)
        a.cmp_r64_imm("rdx", TAG_FLOAT)
        a.jcc('e', l_immf)

        # if tag == TAG_PTR -> inspect object type
        a.cmp_r64_imm("rdx", 0)
        a.jcc('e', l_ptr)

        # else fail
        a.jmp(l_fail)

        a.mark(l_immf)
        self.emit_to_double_xmm(0, l_fail)
        self.emit_normalize_xmm0_to_value()
        a.jmp(l_done)

        # --- ptr case ---
        a.mark(l_ptr)
        # edx = [rax] (obj type)
        a.mov_r32_membase_disp("edx", "rax", 0)
        # if OBJ_FLOAT
        a.cmp_r32_imm("edx", OBJ_FLOAT)
        a.jcc('e', l_float)
        # if OBJ_STRING
        a.cmp_r32_imm("edx", OBJ_STRING)
        a.jcc('e', l_str)
        a.jmp(l_fail)

        # --- boxed float: normalize ---
        a.mark(l_float)
        self.emit_to_double_xmm(0, l_fail)
        self.emit_normalize_xmm0_to_value()
        a.jmp(l_done)

        # --- string parse ---
        a.mark(l_str)
        # edx = len
        a.mov_r32_membase_disp("edx", "rax", 4)
        # r8 = start = &bytes
        a.lea_r64_membase_disp("r8", "rax", 8)
        # r9 = end = start + len
        a.mov_r64_r64("r9", "r8")  # mov r9,r8
        a.add_r64_r64("r9", "rdx")  # add r9,rdx

        # trim left: while r8<r9 and *r8 <= 32
        l_tl = f"ton_tl_{lid}"
        l_tl_done = f"ton_tl_done_{lid}"
        a.mark(l_tl)
        a.cmp_r64_r64("r8", "r9")  # cmp r8,r9
        a.jcc('ge', l_tl_done)
        a.mov_r8_membase_disp("al", "r8", 0)  # mov al,[r8]
        a.cmp_r8_imm8("al", 32)  # cmp al,32
        a.jcc('g', l_tl_done)
        a.inc_r64("r8")  # inc r8
        a.jmp(l_tl)
        a.mark(l_tl_done)

        # trim right: while r9>r8 and *(r9-1) <= 32: r9--
        l_tr = f"ton_tr_{lid}"
        l_tr_done = f"ton_tr_done_{lid}"
        a.mark(l_tr)
        a.cmp_r64_r64("r9", "r8")  # cmp r9,r8
        a.jcc('le', l_tr_done)
        a.mov_r8_membase_disp("al", "r9", -1)  # mov al,[r9-1]
        a.cmp_r8_imm8("al", 32)
        a.jcc('g', l_tr_done)
        a.dec_r64("r9")  # dec r9
        a.jmp(l_tr)
        a.mark(l_tr_done)

        # if empty -> fail
        a.cmp_r64_r64("r8", "r9")  # cmp r8,r9
        a.jcc('e', l_fail)

        # sign flag r10d = 0
        a.xor_r32_r32("r10d", "r10d")  # xor r10d,r10d
        # if *r8 == '-'
        a.mov_r8_membase_disp("al", "r8", 0)  # mov al,[r8]
        a.cmp_r8_imm8("al", 45)  # cmp al,'-'
        l_nosign = f"ton_nosign_{lid}"
        a.jcc('ne', l_nosign)
        a.mov_r32_imm32("r10d", 1)  # mov r10d,1
        a.inc_r64("r8")  # inc r8
        a.mark(l_nosign)

        # parse integer digits: rax=0, edx=digitcount
        a.xor_r32_r32("eax", "eax")  # xor eax,eax
        a.xor_r32_r32("edx", "edx")  # xor edx,edx

        l_dig = f"ton_dig_{lid}"
        l_dig_done = f"ton_dig_done_{lid}"
        a.mark(l_dig)
        a.cmp_r64_r64("r8", "r9")  # cmp r8,r9
        a.jcc('ge', l_dig_done)
        a.movzx_r32_membase_disp("ecx", "r8", 0)  # movzx ecx, byte [r8]
        a.cmp_r8_imm8("cl", 48)  # cmp cl,'0'
        a.jcc('l', l_dig_done)
        a.cmp_r8_imm8("cl", 57)  # cmp cl,'9'
        a.jcc('g', l_dig_done)
        # rax = rax*10 + digit
        a.imul_r64_r64_imm("rax", "rax", 10)  # imul rax,rax,10
        a.sub_r32_imm("ecx", 48)  # sub ecx,'0'
        a.add_r64_r64("rax", "rcx")  # add rax,rcx
        a.inc_r64("r8")  # inc r8
        a.inc_r32("edx")  # inc edx
        a.jmp(l_dig)
        a.mark(l_dig_done)

        # require at least 1 digit
        a.test_r32_r32("edx", "edx")  # test edx,edx
        a.jcc('z', l_fail)

        # if r8==r9 => integer
        l_make_int = f"ton_make_int_{lid}"
        a.cmp_r64_r64("r8", "r9")
        a.jcc('e', l_make_int)

        # else must be '.' for float
        a.cmp_membase_disp_imm8("r8", 0, 46)  # cmp byte [r8],'.'
        a.jcc('ne', l_fail)
        a.inc_r64("r8")  # inc r8

        # parse frac digits: r11=frac_accum, edx=frac_count
        a.xor_r32_r32("r11d", "r11d")  # xor r11d,r11d
        a.xor_r32_r32("edx", "edx")  # xor edx,edx

        l_fd = f"ton_fd_{lid}"
        l_fd_done = f"ton_fd_done_{lid}"
        a.mark(l_fd)
        a.cmp_r64_r64("r8", "r9")
        a.jcc('ge', l_fd_done)
        a.movzx_r32_membase_disp("ecx", "r8", 0)  # movzx ecx, byte [r8]
        a.cmp_r8_imm8("cl", 48)  # cmp cl,'0'
        a.jcc('l', l_fd_done)
        a.cmp_r8_imm8("cl", 57)  # cmp cl,'9'
        a.jcc('g', l_fd_done)
        a.imul_r64_r64_imm("r11", "r11", 10)  # imul r11,r11,10
        a.sub_r32_imm("ecx", 48)  # sub ecx,'0'
        a.add_r64_r64("r11", "rcx")  # add r11,rcx
        a.inc_r64("r8")  # inc r8
        a.inc_r32("edx")  # inc edx
        a.jmp(l_fd)
        a.mark(l_fd_done)

        # need at least 1 frac digit and no trailing
        a.test_r32_r32("edx", "edx")
        a.jcc('z', l_fail)
        a.cmp_r64_r64("r8", "r9")
        a.jcc('ne', l_fail)

        # --- build double in xmm0 ---
        # xmm0 = float(int_accum)
        a.cvtsi2sd_xmm_r64("xmm0", "rax")
        # xmm1 = float(frac_accum)
        a.cvtsi2sd_xmm_r64("xmm1", "r11")
        # xmm2 = 1.0
        a.mov_rax_imm64(0x3FF0000000000000)
        a.movq_xmm_r64("xmm2", "rax")  # movq xmm2,rax
        # xmm3 = 10.0
        a.mov_rax_imm64(0x4024000000000000)
        a.movq_xmm_r64("xmm3", "rax")  # movq xmm3,rax

        # ecx = frac_count
        a.mov_r32_r32("ecx", "edx")
        l_pow = f"ton_pow_{lid}"
        l_pow_done = f"ton_pow_done_{lid}"
        a.mark(l_pow)
        a.test_r32_r32("ecx", "ecx")
        a.jcc('z', l_pow_done)
        a.mulsd_xmm_xmm("xmm2", "xmm3")  # mulsd xmm2,xmm3
        a.dec_r32("ecx")  # dec ecx
        a.jmp(l_pow)
        a.mark(l_pow_done)

        # xmm1 /= xmm2; xmm0 += xmm1
        a.divsd_xmm_xmm("xmm1", "xmm2")  # divsd xmm1,xmm2
        a.addsd_xmm_xmm("xmm0", "xmm1")  # addsd xmm0,xmm1

        # if signflag: xmm0 *= -1.0
        a.cmp_r32_imm("r10d", 0)  # cmp r10d,0
        l_pos = f"ton_pos_{lid}"
        a.jcc('e', l_pos)
        a.mov_rax_imm64(0xBFF0000000000000)  # -1.0
        a.movq_xmm_r64("xmm3", "rax")  # movq xmm3,rax
        a.mulsd_xmm_xmm("xmm0", "xmm3")  # mulsd xmm0,xmm3
        a.mark(l_pos)

        # normalize parsed float via the shared numeric normalization path
        self.emit_normalize_xmm0_to_value()
        a.jmp(l_done)

        # --- make integer return from parsed digits ---
        a.mark(l_make_int)
        # if signflag: neg rax
        a.cmp_r32_imm("r10d", 0)
        l_mi_pos = f"ton_mi_pos_{lid}"
        a.jcc('e', l_mi_pos)
        a.neg_r64("rax")  # neg rax
        a.mark(l_mi_pos)
        a.shl_rax_imm8(3)
        a.or_rax_imm8(TAG_INT)
        a.jmp(l_done)

        # --- fail: return void ---
        a.mark(l_fail)
        a.mov_rax_imm64(enc_void())

        # --- epilogue ---
        a.mark(l_done)
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_typeof_function(self) -> None:
        """Builtin: typeof(x) -> boxed string (from .rdata)

        ABI:
          RCX = value
          RAX = pointer to boxed string object (TAG_PTR)
        """
        a = self.asm
        a.mark('fn_typeof')

        lid = self.new_label_id()
        l_int = f"tof_int_{lid}"
        l_bool = f"tof_bool_{lid}"
        l_void = f"tof_void_{lid}"
        l_enum = f"tof_enum_{lid}"
        l_immf = f"tof_immf_{lid}"
        l_ptr = f"tof_ptr_{lid}"
        l_str = f"tof_str_{lid}"
        l_arr = f"tof_arr_{lid}"
        l_flt = f"tof_flt_{lid}"
        l_bytes = f"tof_bytes_{lid}"
        l_fun = f"tof_fun_{lid}"
        l_sti = f"tof_sti_{lid}"
        l_stt = f"tof_stt_{lid}"
        l_unk = f"tof_unk_{lid}"

        # rax = rcx
        a.mov_r64_r64("rax", "rcx")  # mov rax,rcx

        # rdx = tag(rax) = rax & 7
        a.mov_r64_r64("rdx", "rax")  # mov rdx,rax
        a.and_r64_imm("rdx", 7)  # and rdx,7

        # tag dispatch
        a.cmp_r64_imm("rdx", TAG_INT)
        a.jcc('e', l_int)
        a.cmp_r64_imm("rdx", TAG_BOOL)
        a.jcc('e', l_bool)
        a.cmp_r64_imm("rdx", TAG_VOID)
        a.jcc('e', l_void)
        a.cmp_r64_imm("rdx", TAG_ENUM)
        a.jcc('e', l_enum)
        a.cmp_r64_imm("rdx", TAG_FLOAT)
        a.jcc('e', l_immf)
        a.cmp_r64_imm("rdx", TAG_PTR)
        a.jcc('e', l_ptr)
        a.jmp(l_unk)

        a.mark(l_int)
        a.lea_rax_rip('obj_type_int')
        a.ret()

        a.mark(l_bool)
        a.lea_rax_rip('obj_type_bool')
        a.ret()

        a.mark(l_void)
        a.lea_rax_rip('obj_type_void')
        a.ret()

        a.mark(l_enum)
        a.lea_rax_rip('obj_type_enum')
        a.ret()

        a.mark(l_immf)
        a.lea_rax_rip('obj_type_float')
        a.ret()

        a.mark(l_ptr)
        # edx = [rax] (object type)
        a.mov_r32_membase_disp("edx", "rax", 0)

        a.cmp_r32_imm("edx", OBJ_STRING)
        a.jcc('e', l_str)
        a.cmp_r32_imm("edx", OBJ_ARRAY)
        a.jcc('e', l_arr)
        a.cmp_r32_imm("edx", OBJ_BYTES)
        a.jcc('e', l_bytes)
        a.cmp_r32_imm("edx", OBJ_FLOAT)
        a.jcc('e', l_flt)
        a.cmp_r32_imm("edx", OBJ_FUNCTION)
        a.jcc('e', l_fun)
        a.cmp_r32_imm("edx", OBJ_CLOSURE)
        a.jcc('e', l_fun)
        a.cmp_r32_imm("edx", OBJ_BUILTIN)
        a.jcc('e', l_fun)
        a.cmp_r32_imm("edx", OBJ_STRUCT)
        a.jcc('e', l_sti)

        a.cmp_r32_imm("edx", OBJ_STRUCTTYPE)
        a.jcc('e', l_stt)
        a.jmp(l_unk)

        a.mark(l_str)
        a.lea_rax_rip('obj_type_string')
        a.ret()

        a.mark(l_arr)
        a.lea_rax_rip('obj_type_array')
        a.ret()

        a.mark(l_bytes)
        a.lea_rax_rip('obj_type_bytes')
        a.ret()

        a.mark(l_flt)
        a.lea_rax_rip('obj_type_float')
        a.ret()

        a.mark(l_fun)
        a.lea_rax_rip('obj_type_function')
        a.ret()

        a.mark(l_sti)
        # Special-case: built-in error struct instance => typeof(x) == "error"
        l_err = f"tof_err_{lid}"
        a.mov_r32_membase_disp("edx", "rax", 4)  # struct_id (u32)
        a.cmp_r32_imm("edx", ERROR_STRUCT_ID)
        a.jcc('e', l_err)
        a.lea_rax_rip('obj_type_struct')
        a.ret()
        a.mark(l_err)
        a.lea_rax_rip('obj_type_error')
        a.ret()

        a.mark(l_stt)
        a.lea_rax_rip('obj_type_struct')
        a.ret()

        a.mark(l_unk)
        a.lea_rax_rip('obj_type_unknown')
        a.ret()

    def emit_typeName_function(self) -> None:
        """Builtin: typeName(x) -> boxed string (from .rdata)

        Behavior:
          - struct instance / struct type: returns the concrete struct name
          - enum value: returns the enum name
          - all other values: identical to typeof(x)

        ABI:
          RCX = value
          RAX = pointer to boxed string object (TAG_PTR)
        """
        a = self.asm
        a.mark('fn_typeName')

        lid = self.new_label_id()
        l_int = f"tna_int_{lid}"
        l_bool = f"tna_bool_{lid}"
        l_void = f"tna_void_{lid}"
        l_enum = f"tna_enum_{lid}"
        l_immf = f"tna_immf_{lid}"
        l_ptr = f"tna_ptr_{lid}"
        l_str = f"tna_str_{lid}"
        l_arr = f"tna_arr_{lid}"
        l_flt = f"tna_flt_{lid}"
        l_bytes = f"tna_bytes_{lid}"
        l_fun = f"tna_fun_{lid}"
        l_sti = f"tna_sti_{lid}"
        l_stt = f"tna_stt_{lid}"
        l_unk = f"tna_unk_{lid}"

        # rax = rcx
        a.mov_r64_r64("rax", "rcx")

        # rdx = tag(rax)
        a.mov_r64_r64("rdx", "rax")
        a.and_r64_imm("rdx", 7)

        a.cmp_r64_imm("rdx", TAG_INT)
        a.jcc('e', l_int)
        a.cmp_r64_imm("rdx", TAG_BOOL)
        a.jcc('e', l_bool)
        a.cmp_r64_imm("rdx", TAG_VOID)
        a.jcc('e', l_void)
        a.cmp_r64_imm("rdx", TAG_ENUM)
        a.jcc('e', l_enum)
        a.cmp_r64_imm("rdx", TAG_FLOAT)
        a.jcc('e', l_immf)
        a.cmp_r64_imm("rdx", TAG_PTR)
        a.jcc('e', l_ptr)
        a.jmp(l_unk)

        a.mark(l_int)
        a.lea_rax_rip('obj_type_int')
        a.ret()

        a.mark(l_bool)
        a.lea_rax_rip('obj_type_bool')
        a.ret()

        a.mark(l_void)
        a.lea_rax_rip('obj_type_void')
        a.ret()

        a.mark(l_enum)
        # Extract enum_id from payload: ((v >> 3) & 0xFFFF)
        a.mov_r64_r64("rdx", "rax")
        a.shr_r64_imm8("rdx", 3)
        a.and_r64_imm("rdx", 0xFFFF)

        # Compare against known enum IDs, return enum name.
        enum_map = getattr(self, 'typename_enum_by_id', {})
        if isinstance(enum_map, dict) and enum_map:
            # deterministic order for stable binaries
            for eid in sorted(enum_map.keys()):
                lbl = enum_map.get(eid)
                if not isinstance(lbl, str) or not lbl:
                    continue
                l_next = f"tna_e_next_{eid}_{lid}"
                a.cmp_r32_imm("edx", int(eid) & 0xFFFFFFFF)
                a.jcc('ne', l_next)
                a.lea_rax_rip(lbl)
                a.ret()
                a.mark(l_next)

        # fallback: "enum"
        a.lea_rax_rip('obj_type_enum')
        a.ret()

        a.mark(l_immf)
        a.lea_rax_rip('obj_type_float')
        a.ret()

        a.mark(l_ptr)
        # edx = [rax] (object type)
        a.mov_r32_membase_disp("edx", "rax", 0)

        a.cmp_r32_imm("edx", OBJ_STRING)
        a.jcc('e', l_str)
        a.cmp_r32_imm("edx", OBJ_ARRAY)
        a.jcc('e', l_arr)
        a.cmp_r32_imm("edx", OBJ_BYTES)
        a.jcc('e', l_bytes)
        a.cmp_r32_imm("edx", OBJ_FLOAT)
        a.jcc('e', l_flt)
        a.cmp_r32_imm("edx", OBJ_FUNCTION)
        a.jcc('e', l_fun)
        a.cmp_r32_imm("edx", OBJ_CLOSURE)
        a.jcc('e', l_fun)
        a.cmp_r32_imm("edx", OBJ_BUILTIN)
        a.jcc('e', l_fun)
        a.cmp_r32_imm("edx", OBJ_STRUCT)
        a.jcc('e', l_sti)
        a.cmp_r32_imm("edx", OBJ_STRUCTTYPE)
        a.jcc('e', l_stt)
        a.jmp(l_unk)

        a.mark(l_str)
        a.lea_rax_rip('obj_type_string')
        a.ret()

        a.mark(l_arr)
        a.lea_rax_rip('obj_type_array')
        a.ret()

        a.mark(l_bytes)
        a.lea_rax_rip('obj_type_bytes')
        a.ret()

        a.mark(l_flt)
        a.lea_rax_rip('obj_type_float')
        a.ret()

        a.mark(l_fun)
        a.lea_rax_rip('obj_type_function')
        a.ret()

        a.mark(l_sti)
        # struct_id at [rax+4]
        a.mov_r32_membase_disp("edx", "rax", 4)
        struct_map = getattr(self, 'typename_struct_by_id', {})
        if isinstance(struct_map, dict) and struct_map:
            for sid in sorted(struct_map.keys()):
                lbl = struct_map.get(sid)
                if not isinstance(lbl, str) or not lbl:
                    continue
                l_next = f"tna_s_next_{sid}_{lid}"
                a.cmp_r32_imm("edx", int(sid) & 0xFFFFFFFF)
                a.jcc('ne', l_next)
                a.lea_rax_rip(lbl)
                a.ret()
                a.mark(l_next)
        # fallback: "struct" (or "error" for built-in error structs is handled by map above)
        a.lea_rax_rip('obj_type_struct')
        a.ret()

        a.mark(l_stt)
        # struct_id at [rax+8]
        a.mov_r32_membase_disp("edx", "rax", 8)
        struct_map = getattr(self, 'typename_struct_by_id', {})
        if isinstance(struct_map, dict) and struct_map:
            for sid in sorted(struct_map.keys()):
                lbl = struct_map.get(sid)
                if not isinstance(lbl, str) or not lbl:
                    continue
                l_next = f"tna_t_next_{sid}_{lid}"
                a.cmp_r32_imm("edx", int(sid) & 0xFFFFFFFF)
                a.jcc('ne', l_next)
                a.lea_rax_rip(lbl)
                a.ret()
                a.mark(l_next)
        a.lea_rax_rip('obj_type_struct')
        a.ret()

        a.mark(l_unk)
        a.lea_rax_rip('obj_type_unknown')
        a.ret()

    def emit_unhandled_error_exit_function(self) -> None:
        """Internal helper: abort on an unhandled MiniLang `error` value.

        ABI:
          RCX = value (expected: TAG_PTR to OBJ_STRUCT with struct_id == ERROR_STRUCT_ID)
          Does not return (calls ExitProcess).

        Prints:
          Error occured: no=<code> message=<message>
        """
        a = self.asm
        a.mark('fn_unhandled_error_exit')

        # Stack: shadow space + locals (keep 16B alignment for Win64 calls).
        # Locals used: [rsp+0x30..0x50] (code/message/script/func/line)
        a.sub_rsp_imm8(0x68)

        # Save error fields into locals.
        a.mov_r64_r64('r11', 'rcx')
        a.mov_r64_membase_disp('rax', 'r11', 8)  # code
        a.mov_membase_disp_r64('rsp', 0x30, 'rax')
        a.mov_r64_membase_disp('rax', 'r11', 16)  # message
        a.mov_membase_disp_r64('rsp', 0x38, 'rax')

        # The error struct historically had only 2 fields (code, message).
        # Newer compilers may emit 5 fields (code, message, script, func, line).
        # We *must* guard reads past the declared field count to avoid crashes.
        lid_nf = self.new_label_id()
        l_nf_old = f"unh_nf_old_{lid_nf}"
        l_nf_done = f"unh_nf_done_{lid_nf}"

        a.mov_r64_membase_disp('rdx', 'r11', GC_OFF_BLOCK_SIZE)
        a.and_r64_imm('rdx', GC_BLOCK_SIZE_MASK)
        a.sub_r64_imm('rdx', GC_HEADER_SIZE + 8)
        a.shr_r64_imm8('rdx', 3)
        a.cmp_r32_imm('edx', 5)
        a.jcc('l', l_nf_old)

        # nfields >= 5 -> load origin fields
        a.mov_r64_membase_disp('rax', 'r11', 24)  # script
        a.mov_membase_disp_r64('rsp', 0x40, 'rax')
        a.mov_r64_membase_disp('rax', 'r11', 32)  # func
        a.mov_membase_disp_r64('rsp', 0x48, 'rax')
        a.mov_r64_membase_disp('rax', 'r11', 40)  # line
        a.mov_membase_disp_r64('rsp', 0x50, 'rax')
        a.jmp(l_nf_done)

        # nfields < 5 -> set origin locals to void
        a.mark(l_nf_old)
        a.mov_rax_imm64(enc_void())
        a.mov_membase_disp_r64('rsp', 0x40, 'rax')
        a.mov_membase_disp_r64('rsp', 0x48, 'rax')
        a.mov_membase_disp_r64('rsp', 0x50, 'rax')

        a.mark(l_nf_done)

        # "Error occured: no="
        self.emit_writefile('err_occ_prefix', 18)

        # Print code as decimal
        a.mov_r64_membase_disp('rcx', 'rsp', 0x30)
        a.call('fn_int_to_dec')  # RAX=ptr, EDX=len
        a.mov_r32_r32('r8d', 'edx')
        a.mov_r64_r64('rdx', 'rax')
        self.emit_writefile_ptr_len()

        # " message="
        self.emit_writefile('err_occ_mid', 9)

        # Print message via value_to_string
        a.mov_r64_membase_disp('rcx', 'rsp', 0x38)
        a.call('fn_value_to_string')
        # r8d=len, rdx=ptr
        a.mov_r32_membase_disp('r8d', 'rax', 4)
        a.lea_r64_membase_disp('rdx', 'rax', 8)
        self.emit_writefile_ptr_len()

        # Newline
        self.emit_writefile('nl', 1)

        # Optional origin line: "  at <script>:<line> in <func>"
        lid = self.new_label_id()
        l_skip = f"unh_loc_skip_{lid}"
        l_exit = f"unh_loc_exit_{lid}"

        # script must be a non-empty string
        a.mov_r64_membase_disp('r11', 'rsp', 0x40)
        a.mov_r64_r64('r10', 'r11')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_skip)
        a.mov_r32_membase_disp('edx', 'r11', 0)
        a.cmp_r32_imm('edx', OBJ_STRING)
        a.jcc('ne', l_skip)

        # script length must be > 0
        a.mov_r32_membase_disp('edx', 'r11', 4)
        a.cmp_r32_imm('edx', 0)
        a.jcc('e', l_skip)

        # line must be a positive tagged int
        a.mov_r64_membase_disp('r10', 'rsp', 0x50)
        a.mov_r64_r64('r9', 'r10')
        a.and_r64_imm('r9', 7)
        a.cmp_r64_imm('r9', TAG_INT)
        a.jcc('ne', l_skip)
        a.cmp_r64_imm('r10', enc_int(0))
        a.jcc('le', l_skip)

        # "  at "
        self.emit_writefile('err_occ_at', 5)

        # NOTE: emit_writefile() performs Win64 calls and clobbers volatile regs.
        # Reload script ptr from locals before using it.
        a.mov_r64_membase_disp('r11', 'rsp', 0x40)

        # print script
        a.mov_r32_membase_disp('r8d', 'r11', 4)
        a.lea_r64_membase_disp('rdx', 'r11', 8)
        self.emit_writefile_ptr_len()

        # ':'
        self.emit_writefile('err_occ_colon', 1)

        # print line as decimal (tagged int)
        # Reload line value from locals (previous calls may clobber r10).
        a.mov_r64_membase_disp('r10', 'rsp', 0x50)
        a.mov_r64_r64('rcx', 'r10')
        a.call('fn_int_to_dec')
        a.mov_r32_r32('r8d', 'edx')
        a.mov_r64_r64('rdx', 'rax')
        self.emit_writefile_ptr_len()

        # func must be a string
        a.mov_r64_membase_disp('r11', 'rsp', 0x48)
        a.mov_r64_r64('r10', 'r11')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_exit)
        a.mov_r32_membase_disp('edx', 'r11', 0)
        a.cmp_r32_imm('edx', OBJ_STRING)
        a.jcc('ne', l_exit)

        # " in "
        self.emit_writefile('err_occ_in', 4)
        # Reload func ptr from locals (emit_writefile clobbers volatile regs).
        a.mov_r64_membase_disp('r11', 'rsp', 0x48)
        a.mov_r32_membase_disp('r8d', 'r11', 4)
        a.lea_r64_membase_disp('rdx', 'r11', 8)
        self.emit_writefile_ptr_len()

        self.emit_writefile('nl', 1)
        a.jmp(l_exit)

        a.mark(l_skip)
        a.jmp(l_exit)

        a.mark(l_exit)

        # Exit code for unhandled MiniLang error is always 1 (even if error.code is different).
        a.mov_rcx_imm32(1)
        a.call_rip_qword('iat_ExitProcess')

        # Should never return
        a.add_rsp_imm8(0x68)
        a.ret()

    def emit_strlen_function(self) -> None:
        """Helper: strlen for NUL-terminated ascii/utf8. RCX=ptr, returns EDX=len."""
        a = self.asm
        a.mark('fn_strlen')
        a.mov_r32_imm32('edx', 0x7FFFFFFF)
        a.call('fn_scan_nul_bytes')
        a.ret()

    def emit_string_eq_function(self) -> None:
        """Internal helper: fn_str_eq(s1, s2) -> bool (content equality)

        Input : RCX = ptr to OBJ_STRING
                RDX = ptr to OBJ_STRING
        Output: RAX = encoded bool (TAG_BOOL)

        Semantics:
        - Returns true iff the strings have the same length and identical bytes.
        - This is required for MiniLang semantics (`==` compares string contents).
        """
        a = self.asm
        a.mark('fn_str_eq')

        # 32B shadow space (alignment) - no calls, but keep ABI-consistent.
        a.sub_rsp_imm8(0x28)

        # Same object => equal.
        a.cmp_r64_r64("rcx", "rdx")
        lid = self.new_label_id()
        l_true = f"streq_true_{lid}"
        l_false = f"streq_false_{lid}"
        l_done = f"streq_done_{lid}"
        a.jcc('e', l_true)

        # r8d = len1, r9d = len2
        a.mov_r32_membase_disp("r8d", "rcx", 4)  # mov r8d,[rcx+4]
        a.mov_r32_membase_disp("r9d", "rdx", 4)  # mov r9d,[rdx+4]
        # if len1 != len2 -> false
        a.cmp_r32_r32("r8d", "r9d")  # cmp r8d,r9d
        a.jcc('ne', l_false)

        # if len == 0 -> true
        a.test_r32_r32("r8d", "r8d")  # test r8d,r8d
        a.jcc('e', l_true)

        a.lea_r64_membase_disp("rcx", "rcx", 8)
        a.lea_r64_membase_disp("rdx", "rdx", 8)
        a.call('fn_mem_eq_bytes')
        a.jmp(l_done)

        a.mark(l_false)
        a.mov_rax_imm64(enc_bool(False))
        a.jmp(l_done)

        a.mark(l_true)
        a.mov_rax_imm64(enc_bool(True))

        a.mark(l_done)
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_value_eq_function(self) -> None:
        """Internal helper: fn_val_eq(v1, v2) -> bool (value equality)

        Input : RCX = tagged Value v1
                RDX = tagged Value v2
        Output: RAX = encoded bool (TAG_BOOL)

        Semantics:
        - ints/bools compare by numeric value (bool behaves as 0/1)
        - floats compare numerically against ints/bools (mixed numeric ok)
        - strings compare by content
        - arrays compare by length and element-wise equality (deep, supports nesting)
        - other heap objects fall back to identity (already handled by fast-path)

        Implementation note:
        We implement deep array equality *iteratively* using an explicit pair-stack in the
        function's stack frame to avoid recursion pitfalls and to be robust for nested arrays.
        """
        a = self.asm
        a.mark('fn_val_eq')

        # Save non-volatile regs (Windows x64 ABI)
        a.push_rbx()
        a.push_reg("rsi")  # push rsi
        a.push_reg("rdi")  # push rdi
        a.push_r12()
        a.push_r13()
        a.push_r14()
        a.push_r15()

        # Frame: shadow(0x20) + align(0x8) + pair stack (0x1000)
        PAIR_STACK_BYTES = 0x1000
        FRAME_BYTES = 0x28 + PAIR_STACK_BYTES
        a.sub_rsp_imm32(FRAME_BYTES)

        # r14 = pair_stack_base = rsp + 0x28
        a.lea_r64_membase_disp("r14", "rsp", 40)  # lea r14,[rsp+0x28]
        # r13 = pair_stack_top = r14
        a.mov_r64_r64("r13", "r14")  # mov r13,r14
        # r15 = pair_stack_end = r14 + PAIR_STACK_BYTES
        a.mov_r64_r64("r15", "r14")  # mov r15,r14
        a.add_r64_imm("r15", PAIR_STACK_BYTES)  # add r15, imm32

        # push initial pair (RCX, RDX) onto stack
        a.mov_membase_disp_r64("r13", 0, "rcx")  # mov [r13+0],rcx
        a.mov_membase_disp_r64("r13", 8, "rdx")  # mov [r13+8],rdx
        a.add_r64_imm("r13", 16)  # add r13,16

        lid = self.new_label_id()
        l_loop = f"vale_it_loop_{lid}"
        l_pop = f"vale_it_pop_{lid}"
        l_false = f"vale_it_false_{lid}"
        l_true = f"vale_it_true_{lid}"
        l_done = f"vale_it_done_{lid}"
        l_ptr = f"vale_it_ptr_{lid}"
        l_num = f"vale_it_num_{lid}"
        l_arr_push = f"vale_it_arr_push_{lid}"
        l_cont = f"vale_it_cont_{lid}"
        l_enum = f"vale_it_enum_{lid}"

        a.mark(l_loop)
        # while top != base
        a.cmp_r64_r64("r13", "r14")  # cmp r13,r14
        a.jcc('e', l_true)

        a.mark(l_pop)
        a.sub_r64_imm("r13", 16)  # sub r13,16
        # r10 = v1, r11 = v2
        a.mov_r64_membase_disp("r10", "r13", 0)  # mov r10,[r13+0]
        a.mov_r64_membase_disp("r11", "r13", 8)  # mov r11,[r13+8]

        # Fast path: identical tagged values -> continue
        a.cmp_r64_r64("r10", "r11")  # cmp r10,r11
        a.jcc('e', l_loop)

        # tag1 -> r8, tag2 -> r9
        a.mov_r64_r64("rax", "r10")  # mov rax,r10
        a.and_rax_imm8(7)
        a.mov_r64_r64("r8", "rax")  # mov r8,rax
        a.mov_r64_r64("rax", "r11")  # mov rax,r11
        a.and_rax_imm8(7)
        a.mov_r64_r64("r9", "rax")  # mov r9,rax

        # Enums are not numeric: enum == enum only by identity (handled by fast-path)
        # If either operand is TAG_ENUM here, values differ -> not equal.
        a.cmp_r64_imm("r8", TAG_ENUM)
        a.jcc('e', l_enum)
        a.cmp_r64_imm("r9", TAG_ENUM)
        a.jcc('e', l_enum)

        # If both pointers -> pointer path else numeric path
        a.cmp_r64_imm("r8", 0)  # cmp r8,0
        a.jcc('ne', l_num)
        a.cmp_r64_imm("r9", 0)  # cmp r9,0
        a.jcc('e', l_ptr)
        a.jmp(l_num)

        # ---- pointer path ----
        a.mark(l_ptr)
        # type1 in eax, type2 in edx
        a.mov_r32_membase_disp("eax", "r10", 0)  # mov eax,[r10]
        a.mov_r32_membase_disp("edx", "r11", 0)  # mov edx,[r11]
        a.cmp_r32_r32("eax", "edx")  # cmp eax,edx
        a.jcc('ne', l_false)

        # if type == OBJ_STRING
        a.cmp_r32_imm("eax", OBJ_STRING)  # cmp eax,imm8
        l_is_arr = f"vale_it_is_arr_{lid}"
        l_is_flt = f"vale_it_is_flt_{lid}"
        l_is_other = f"vale_it_is_other_{lid}"
        a.jcc('ne', l_is_arr)
        # call fn_str_eq(r10,r11) -> bool in rax
        a.mov_r64_r64("rcx", "r10")  # mov rcx,r10
        a.mov_r64_r64("rdx", "r11")  # mov rdx,r11
        a.call('fn_str_eq')
        a.cmp_rax_imm32(enc_bool(True))
        a.jcc('ne', l_false)
        a.jmp(l_loop)

        # if type == OBJ_ARRAY
        a.mark(l_is_arr)
        a.cmp_r32_imm("eax", OBJ_ARRAY)
        a.jcc('ne', l_is_flt)
        # Compare lengths
        a.mov_r32_membase_disp("ebx", "r10", 4)  # mov ebx,[r10+4]
        a.mov_r32_membase_disp("ecx", "r11", 4)  # mov ecx,[r11+4]
        a.cmp_r32_r32("ebx", "ecx")  # cmp ebx,ecx
        a.jcc('ne', l_false)
        # if len==0 -> continue
        a.test_r32_r32("ebx", "ebx")  # test ebx,ebx
        a.jcc('e', l_loop)

        # rsi = base1, rdi = base2
        a.lea_r64_membase_disp("rsi", "r10", 8)  # lea rsi,[r10+8]
        a.lea_r64_membase_disp("rdi", "r11", 8)  # lea rdi,[r11+8]
        # r9d = i = 0
        # NOTE: rsp/r12 cannot be used as SIB index (index field == 4 encodes "no index").
        # Use r9 for the loop index to allow base+index*8 addressing.
        a.xor_r32_r32("r9d", "r9d")  # xor r9d,r9d

        l_ap_loop = f"vale_it_ap_loop_{lid}"
        l_ap_done = f"vale_it_ap_done_{lid}"
        a.mark(l_ap_loop)
        a.cmp_r32_r32("r9d", "ebx")  # cmp r9d,ebx
        a.jcc('ge', l_ap_done)

        # Check stack capacity: if top+16 > end -> false
        a.mov_r64_r64("rax", "r13")  # mov rax,r13
        a.add_r64_imm("rax", 16)  # add rax,16
        a.cmp_r64_r64("rax", "r15")  # cmp rax,r15
        # Addresses should be compared as *unsigned*.
        a.jcc('a', l_false)

        # load elements into rax (v1) and rdx (v2)
        # NOTE: must use SIB addressing (base + index*scale) for array element access.
        a.mov_r64_mem_bis("rax", "rsi", "r9", 8, 0)  # mov rax,[rsi+r9*8]
        a.mov_r64_mem_bis("rdx", "rdi", "r9", 8, 0)  # mov rdx,[rdi+r9*8]

        # push pair (rax, rdx)
        a.mov_membase_disp_r64("r13", 0, "rax")  # mov [r13+0],rax
        a.mov_membase_disp_r64("r13", 8, "rdx")  # mov [r13+8],rdx
        a.add_r64_imm("r13", 16)  # add r13,16

        a.inc_r32("r9d")  # inc r9d
        a.jmp(l_ap_loop)

        a.mark(l_ap_done)
        a.jmp(l_loop)

        # if type == OBJ_FLOAT
        a.mark(l_is_flt)
        a.cmp_r32_imm("eax", OBJ_FLOAT)
        a.jcc('ne', l_is_other)
        # Compare doubles: NaN => false
        a.movsd_xmm_membase_disp("xmm0", "r10", 8)  # movsd xmm0,[r10+8]
        a.movsd_xmm_membase_disp("xmm1", "r11", 8)  # movsd xmm1,[r11+8]
        a.ucomisd_xmm_xmm("xmm0", "xmm1")  # ucomisd xmm0,xmm1
        a.jcc('p', l_false)  # unordered
        a.jcc('ne', l_false)  # not equal
        a.jmp(l_loop)

        # unknown ptr types -> false (identity already handled)
        a.mark(l_is_other)
        a.jmp(l_false)

        # ---- numeric path (int/bool/float mix) ----
        a.mark(l_num)
        # If both immediates (non-pointer) -> compare raw integers
        a.cmp_r64_imm("r8", 0)  # cmp r8,0
        l_num_mix = f"vale_it_num_mix_{lid}"
        a.jcc('e', l_num_mix)
        a.cmp_r64_imm("r9", 0)  # cmp r9,0
        a.jcc('e', l_num_mix)
        a.cmp_r64_imm("r8", TAG_FLOAT)
        a.jcc('e', l_num_mix)
        a.cmp_r64_imm("r9", TAG_FLOAT)
        a.jcc('e', l_num_mix)
        # rax = v1>>3, rdx = v2>>3
        a.mov_r64_r64("rax", "r10")  # mov rax,r10
        a.sar_r64_imm8("rax", 3)  # sar rax,3
        a.mov_r64_r64("rdx", "r11")  # mov rdx,r11
        a.sar_r64_imm8("rdx", 3)  # sar rdx,3
        a.cmp_r64_r64("rax", "rdx")  # cmp rax,rdx
        a.jcc('ne', l_false)
        a.jmp(l_loop)

        # Mixed numeric or float: convert both to double and compare
        a.mark(l_num_mix)
        # v1 -> xmm0
        l_v1_imm = f"vale_it_v1_imm_{lid}"
        l_v1_immf = f"vale_it_v1_immf_{lid}"
        l_v1_done = f"vale_it_v1_done_{lid}"
        a.cmp_r64_imm("r8", 0)  # cmp r8,0
        a.jcc('ne', l_v1_imm)
        # pointer: must be float
        a.mov_r32_membase_disp("eax", "r10", 0)  # mov eax,[r10]
        a.cmp_r32_imm("eax", OBJ_FLOAT)
        a.jcc('ne', l_false)
        a.movsd_xmm_membase_disp("xmm0", "r10", 8)  # movsd xmm0,[r10+8]
        a.jmp(l_v1_done)

        a.mark(l_v1_imm)
        a.cmp_r64_imm("r8", TAG_FLOAT)
        a.jcc('e', l_v1_immf)
        a.mov_r64_r64("rax", "r10")  # mov rax,r10
        a.sar_r64_imm8("rax", 3)  # sar rax,3
        a.cvtsi2sd_xmm_r64("xmm0", "rax")  # cvtsi2sd xmm0,rax
        a.jmp(l_v1_done)

        a.mark(l_v1_immf)
        a.mov_r64_r64("rax", "r10")
        self.emit_to_double_xmm(0, l_false)

        a.mark(l_v1_done)

        # v2 -> xmm1
        l_v2_imm = f"vale_it_v2_imm_{lid}"
        l_v2_immf = f"vale_it_v2_immf_{lid}"
        l_v2_done = f"vale_it_v2_done_{lid}"
        a.cmp_r64_imm("r9", 0)  # cmp r9,0
        a.jcc('ne', l_v2_imm)
        a.mov_r32_membase_disp("edx", "r11", 0)  # mov edx,[r11]
        a.cmp_r32_imm("edx", OBJ_FLOAT)
        a.jcc('ne', l_false)
        a.movsd_xmm_membase_disp("xmm1", "r11", 8)  # movsd xmm1,[r11+8]
        a.jmp(l_v2_done)

        a.mark(l_v2_imm)
        a.cmp_r64_imm("r9", TAG_FLOAT)
        a.jcc('e', l_v2_immf)
        a.mov_r64_r64("rax", "r11")  # mov rax,r11
        a.sar_r64_imm8("rax", 3)  # sar rax,3
        a.cvtsi2sd_xmm_r64("xmm1", "rax")  # cvtsi2sd xmm1,rax
        a.jmp(l_v2_done)

        a.mark(l_v2_immf)
        a.mov_r64_r64("rax", "r11")
        self.emit_to_double_xmm(1, l_false)

        a.mark(l_v2_done)
        a.ucomisd_xmm_xmm("xmm0", "xmm1")  # ucomisd xmm0,xmm1
        a.jcc('p', l_false)
        a.jcc('ne', l_false)
        a.jmp(l_loop)

        # ---- return paths ----
        a.mark(l_true)
        a.mov_rax_imm64(enc_bool(True))
        a.jmp(l_done)

        a.mark(l_enum)
        a.jmp(l_false)

        a.mark(l_false)
        a.mov_rax_imm64(enc_bool(False))

        a.mark(l_done)
        a.add_rsp_imm32(FRAME_BYTES)
        a.pop_r15()
        a.pop_r14()
        a.pop_r13()
        a.pop_r12()
        a.pop_reg("rdi")  # pop rdi
        a.pop_reg("rsi")  # pop rsi
        a.pop_rbx()
        a.ret()

    # ------------------------------------------------------------------
    # Program arguments (main(args))
    # ------------------------------------------------------------------

    def emit_init_argvw_function(self) -> None:
        """Internal helper: initialize argv/argc globals for main(args).

        Calls Windows APIs:
          - GetCommandLineW()
          - CommandLineToArgvW(cmdline, &ml_argc)  -> argvW
        Stores:
          - ml_argc (u32)
          - ml_argvw (u64 pointer to LPWSTR*)
        Note: argvW must be freed with LocalFree.
        """
        a = self.asm
        a.mark('fn_init_argvw')

        # Windows x64 ABI: keep 16-byte alignment at CALLs + 32-byte shadow space.
        a.sub_rsp_imm8(0x28)

        lid = self.new_label_id()
        l_ok = f"argvw_ok_{lid}"
        l_done = f"argvw_done_{lid}"

        # cmd = GetCommandLineW()
        a.call_rip_qword('iat_GetCommandLineW')

        # argvw = CommandLineToArgvW(cmd, &ml_argc)
        a.mov_r64_r64("rcx", "rax")  # rcx = cmdline
        a.lea_rdx_rip('ml_argc')  # rdx = &argc (int*)
        a.call_rip_qword('iat_CommandLineToArgvW')

        # if argvw == NULL: argc=0; ml_argvw=0
        a.test_r64_r64("rax", "rax")
        a.jcc('ne', l_ok)
        a.xor_r32_r32("eax", "eax")
        a.mov_rip_dword_eax('ml_argc')
        a.xor_r64_r64("rax", "rax")
        a.mov_rip_qword_rax('ml_argvw')
        a.jmp(l_done)

        a.mark(l_ok)
        # store argvw ptr
        a.mov_rip_qword_rax('ml_argvw')

        a.mark(l_done)
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_build_args_function(self) -> None:
        """Internal helper: build MiniLang args array (array<string>) from Windows argv.

        - Calls fn_init_argvw() internally to populate ml_argc/ml_argvw.
        - Builds a heap OBJ_ARRAY of heap OBJ_STRING items (UTF-8).
        - Uses argv[1..] (skips program path).
        - Frees argvw buffer via LocalFree and clears ml_argc/ml_argvw.
        - Returns: RAX = tagged pointer to OBJ_ARRAY.
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_build_args')

        # Stack frame:
        #  - keep 32B shadow space for calls
        #  - keep 0x20..0x38 available for extra call args (WideCharToMultiByte has 8 params)
        # Locals:
        #   [rsp+0x40] array_base (qword)
        #   [rsp+0x48] n (dword)
        #   [rsp+0x4C] i (dword)
        #   [rsp+0x50] argvw (qword)
        #   [rsp+0x58] wide_ptr (qword)
        #   [rsp+0x60] tmp (dword)
        #   [rsp+0x64] len (dword)
        a.sub_rsp_imm32(0x88)

        lid = self.new_label_id()
        l_n0 = f"args_n0_{lid}"
        l_loop = f"args_loop_{lid}"
        l_done = f"args_done_{lid}"
        l_len0 = f"args_len0_{lid}"
        l_free = f"args_free_{lid}"

        # init argv/argc globals (ml_argc, ml_argvw)
        a.call('fn_init_argvw')

        # n = max(ml_argc - 1, 0)
        a.mov_eax_rip_dword('ml_argc')
        a.cmp_r32_imm('eax', 1)
        a.jcc('le', l_n0)
        a.dec_r32('eax')
        a.mov_membase_disp_r32('rsp', 0x48, 'eax')
        a.jmp(l_done + "_alloc")

        a.mark(l_n0)
        a.xor_r32_r32('eax', 'eax')
        a.mov_membase_disp_r32('rsp', 0x48, 'eax')

        a.mark(l_done + "_alloc")
        # argvw ptr
        a.mov_rax_rip_qword('ml_argvw')
        a.mov_membase_disp_r64('rsp', 0x50, 'rax')

        # i = 0
        a.mov_membase_disp_imm32('rsp', 0x4C, 0, qword=False)

        # Allocate OBJ_ARRAY: size = 8 + n*8
        a.mov_r32_membase_disp('ecx', 'rsp', 0x48)
        a.shl_r32_imm8('ecx', 3)
        a.add_r32_imm('ecx', 8)
        a.call('fn_alloc')

        a.mov_r11_rax()
        # header: [base]=OBJ_ARRAY, [base+4]=n
        a.mov_membase_disp_imm32('r11', 0, OBJ_ARRAY, qword=False)
        a.mov_r32_membase_disp('eax', 'rsp', 0x48)
        a.mov_membase_disp_r32('r11', 4, 'eax')

        # store + root array
        a.mov_membase_disp_r64('rsp', 0x40, 'r11')
        a.mov_rip_qword_r11('gc_tmp0')

        # if n == 0 => skip loop
        a.mov_r32_membase_disp('eax', 'rsp', 0x48)
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_free)

        # loop i=0..n-1
        a.mark(l_loop)
        a.mov_r32_membase_disp('eax', 'rsp', 0x4C)  # eax=i
        a.mov_r32_membase_disp('ecx', 'rsp', 0x48)  # ecx=n
        a.cmp_r32_r32('eax', 'ecx')
        a.jcc('ge', l_free)

        # wide_ptr = argvw[i+1]
        a.mov_r32_r32('edx', 'eax')  # edx=i
        a.inc_r32('edx')  # edx=i+1
        a.mov_r64_membase_disp('r10', 'rsp', 0x50)  # r10=argvw
        a.shl_r64_imm8('rdx', 3)  # rdx=(i+1)*8
        a.mov_r64_r64('rax', 'r10')
        a.add_r64_r64('rax', 'rdx')
        a.mov_r64_membase_disp('r8', 'rax', 0)  # r8 = wide_ptr
        a.mov_membase_disp_r64('rsp', 0x58, 'r8')

        # bytes_with_nul = WideCharToMultiByte(CP_UTF8,0,wide_ptr,-1,NULL,0,NULL,NULL)
        a.mov_r32_imm32('ecx', 65001)  # CP_UTF8
        a.xor_r32_r32('edx', 'edx')  # flags=0
        a.mov_r32_imm32('r9d', 0xFFFFFFFF)  # -1 (include NUL)
        a.mov_membase_disp_imm32('rsp', 0x20, 0, qword=True)  # lpMultiByteStr=NULL
        a.mov_membase_disp_imm32('rsp', 0x28, 0, qword=True)  # cbMultiByte=0
        a.mov_membase_disp_imm32('rsp', 0x30, 0, qword=True)  # defaultChar=NULL
        a.mov_membase_disp_imm32('rsp', 0x38, 0, qword=True)  # usedDefaultChar=NULL
        a.call_rip_qword('iat_WideCharToMultiByte')
        a.mov_membase_disp_r32('rsp', 0x60, 'eax')

        # len = max(bytes_with_nul - 1, 0)
        a.test_r32_r32('eax', 'eax')
        a.jcc('e', l_len0)
        a.dec_r32('eax')
        a.mov_membase_disp_r32('rsp', 0x64, 'eax')
        a.jmp(l_len0 + "_done")

        a.mark(l_len0)
        a.xor_r32_r32('eax', 'eax')
        a.mov_membase_disp_r32('rsp', 0x64, 'eax')

        a.mark(l_len0 + "_done")

        # Allocate OBJ_STRING: size = 9 + len
        a.mov_r32_membase_disp('ecx', 'rsp', 0x64)
        a.add_r32_imm('ecx', 9)
        a.call('fn_alloc')

        a.mov_r11_rax()

        # header: [base]=OBJ_STRING, [base+4]=len
        a.mov_membase_disp_imm32('r11', 0, OBJ_STRING, qword=False)
        a.mov_r32_membase_disp('eax', 'rsp', 0x64)
        a.mov_membase_disp_r32('r11', 4, 'eax')

        # save string base across API call (r11 is volatile)
        a.mov_membase_disp_r64('rsp', 0x68, 'r11')

        # dest_ptr = base+8
        a.lea_r64_membase_disp('r10', 'r11', 8)
        a.mov_membase_disp_r64('rsp', 0x70, 'r10')  # save dest_ptr across API call (r10 is volatile)

        # WideCharToMultiByte(CP_UTF8,0,wide_ptr,-1,dest,len+1,NULL,NULL)
        a.mov_r32_imm32('ecx', 65001)
        a.xor_r32_r32('edx', 'edx')
        a.mov_r64_membase_disp('r8', 'rsp', 0x58)  # wide_ptr
        a.mov_r32_imm32('r9d', 0xFFFFFFFF)
        a.mov_membase_disp_r64('rsp', 0x20, 'r10')  # dest
        a.mov_membase_disp_imm32('rsp', 0x28, 0, qword=True)
        a.mov_r32_membase_disp('eax', 'rsp', 0x64)
        a.inc_r32('eax')
        a.mov_membase_disp_r32('rsp', 0x28, 'eax')  # len+1
        a.mov_membase_disp_imm32('rsp', 0x30, 0, qword=True)
        a.mov_membase_disp_imm32('rsp', 0x38, 0, qword=True)
        a.call_rip_qword('iat_WideCharToMultiByte')

        # ensure NUL at dest[len]
        a.mov_r64_membase_disp('r10', 'rsp', 0x70)  # restore dest_ptr (r10 is volatile across call)
        a.mov_r64_r64('rax', 'r10')
        a.mov_r32_membase_disp('ecx', 'rsp', 0x64)
        a.add_r64_r64('rax', 'rcx')
        a.mov_membase_disp_imm8('rax', 0, 0)

        # store element: array_base[ i ] = string_ptr
        a.mov_r64_membase_disp('r10', 'rsp', 0x40)  # array_base
        a.lea_r64_membase_disp('rax', 'r10', 8)  # elems base
        a.mov_r32_membase_disp('edx', 'rsp', 0x4C)  # i
        a.shl_r64_imm8('rdx', 3)
        a.add_r64_r64('rax', 'rdx')
        a.mov_r64_membase_disp('r11', 'rsp', 0x68)  # restore string_base (r11 is volatile across call)
        a.mov_membase_disp_r64('rax', 0, 'r11')

        # i++
        a.mov_r32_membase_disp('eax', 'rsp', 0x4C)
        a.inc_r32('eax')
        a.mov_membase_disp_r32('rsp', 0x4C, 'eax')
        a.jmp(l_loop)

        # free argvw buffer if present
        a.mark(l_free)
        a.mov_rax_rip_qword('ml_argvw')
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_free + "_skip")

        a.mov_r64_r64('rcx', 'rax')
        a.call_rip_qword('iat_LocalFree')

        a.mark(l_free + "_skip")
        # clear argc/argv globals
        a.xor_r32_r32('eax', 'eax')
        a.mov_rip_dword_eax('ml_argc')
        a.xor_r64_r64('rax', 'rax')
        a.mov_rip_qword_rax('ml_argvw')

        # return array_base
        a.mov_r64_membase_disp('rax', 'rsp', 0x40)
        a.add_rsp_imm32(0x88)
        a.ret()

    # ============================================================
    # First-class builtin function values (OBJ_BUILTIN)
    # ============================================================

    def emit_builtin_len_function(self) -> None:
        """Emit fn_builtin_len(x):

        RCX = tagged value (expects array/string)
        RAX = tagged int length (0 if unsupported)

        Note: This is used as the code_ptr of the OBJ_BUILTIN for `len`.
        """
        a = self.asm
        a.mark('fn_builtin_len')
        lid = self.new_label_id()
        l_ok = f"bl_ok_{lid}"
        l_ret0 = f"bl_ret0_{lid}"

        # rax = rcx
        a.mov_r64_r64('rax', 'rcx')

        # tag check: (rax & 7) == TAG_PTR
        a.mov_r64_r64('r10', 'rax')
        a.and_r64_imm('r10', 7)
        a.cmp_r64_imm('r10', TAG_PTR)
        a.jcc('ne', l_ret0)

        # edx = [rax] (object type)
        a.mov_r32_membase_disp('edx', 'rax', 0)
        a.cmp_r32_imm('edx', OBJ_STRING)
        a.jcc('e', l_ok)
        a.cmp_r32_imm('edx', OBJ_ARRAY)
        a.jcc('e', l_ok)
        a.cmp_r32_imm('edx', OBJ_BYTES)
        a.jcc('e', l_ok)
        a.jmp(l_ret0)

        a.mark(l_ok)
        # edx = dword [rax+4] (len)
        a.mov_r32_membase_disp('edx', 'rax', 4)
        a.mov_r32_r32('eax', 'edx')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(TAG_INT)
        a.ret()

        a.mark(l_ret0)
        a.mov_rax_imm64(TAG_INT)  # enc_int(0)
        a.ret()

    def emit_builtin_input_function(self) -> None:
        """Emit fn_builtin_input(...):

        Calling convention:
        - Args are in RCX/RDX/R8/R9 like normal.
        - Additionally, R10D contains nargs (set by the indirect-call dispatcher).

        For now we accept 0 or 1 args and ignore the prompt argument.
        """
        a = self.asm
        a.mark('fn_builtin_input')
        lid = self.new_label_id()
        l_call = f"bi_call_{lid}"
        l_ret_void = f"bi_ret_void_{lid}"

        a.cmp_r32_imm('r10d', 0)
        a.jcc('e', l_call)
        a.cmp_r32_imm('r10d', 1)
        a.jcc('e', l_call)
        a.jmp(l_ret_void)

        a.mark(l_call)
        a.call('fn_input')
        a.ret()

        a.mark(l_ret_void)
        a.mov_rax_imm64(enc_void())
        a.ret()

    def emit_builtin_gc_collect_function(self) -> None:
        """Emit fn_builtin_gc_collect():

        Calls the GC and returns VOID.
        """
        a = self.asm
        a.mark('fn_builtin_gc_collect')
        a.call('fn_gc_collect')
        a.mov_rax_imm64(enc_void())
        a.ret()

    def emit_builtin_copyBytes_function(self) -> None:
        """Emit fn_builtin_copyBytes(dst, dstOff, src, srcOff, len).

        Calling convention:
        - RCX/RDX/R8/R9 = first four tagged MiniLang args
        - [rsp+0x28]    = 5th tagged MiniLang arg
        - R10D          = nargs

        Returns VOID and treats invalid arguments as a no-op.
        """
        a = self.asm
        a.mark('fn_builtin_copyBytes')
        lid = self.new_label_id()
        l_ret_void = f"bcopy_ret_void_{lid}"
        l_len_dst = f"bcopy_len_dst_{lid}"
        l_len_src = f"bcopy_len_src_{lid}"

        a.cmp_r32_imm('r10d', 5)
        a.jcc('ne', l_ret_void)

        a.mov_r64_r64('r11', 'rcx')  # dst object
        a.mov_r64_r64('r10', 'r8')   # src object
        a.mov_r64_r64('r8', 'r9')    # srcOff tagged

        # dst must be OBJ_BYTES
        a.mov_r64_r64('rax', 'r11')
        a.mov_r64_r64('r9', 'rax')
        a.and_r64_imm('r9', 7)
        a.cmp_r64_imm('r9', TAG_PTR)
        a.jcc('ne', l_ret_void)
        a.mov_r32_membase_disp('eax', 'r11', 0)
        a.cmp_r32_imm('eax', OBJ_BYTES)
        a.jcc('ne', l_ret_void)

        # dstOff -> r9d
        a.mov_r64_r64('rax', 'rdx')
        a.mov_r64_r64('r9', 'rax')
        a.and_r64_imm('r9', 7)
        a.cmp_r64_imm('r9', TAG_INT)
        a.jcc('ne', l_ret_void)
        a.sar_r64_imm8('rax', 3)
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_ret_void)
        a.cmp_r64_imm('rax', 0x7FFFFFFF)
        a.jcc('g', l_ret_void)
        a.mov_r32_r32('r9d', 'eax')

        # src must be OBJ_BYTES
        a.mov_r64_r64('rax', 'r10')
        a.mov_r64_r64('rcx', 'rax')
        a.and_r64_imm('rcx', 7)
        a.cmp_r64_imm('rcx', TAG_PTR)
        a.jcc('ne', l_ret_void)
        a.mov_r32_membase_disp('eax', 'r10', 0)
        a.cmp_r32_imm('eax', OBJ_BYTES)
        a.jcc('ne', l_ret_void)

        # srcOff -> r8d
        a.mov_r64_r64('rax', 'r8')
        a.mov_r64_r64('rcx', 'rax')
        a.and_r64_imm('rcx', 7)
        a.cmp_r64_imm('rcx', TAG_INT)
        a.jcc('ne', l_ret_void)
        a.sar_r64_imm8('rax', 3)
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_ret_void)
        a.cmp_r64_imm('rax', 0x7FFFFFFF)
        a.jcc('g', l_ret_void)
        a.mov_r32_r32('r8d', 'eax')

        # len -> edx
        a.mov_r64_membase_disp('rax', 'rsp', 0x28)
        a.mov_r64_r64('rcx', 'rax')
        a.and_r64_imm('rcx', 7)
        a.cmp_r64_imm('rcx', TAG_INT)
        a.jcc('ne', l_ret_void)
        a.sar_r64_imm8('rax', 3)
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_ret_void)
        a.cmp_r64_imm('rax', 0x7FFFFFFF)
        a.jcc('g', l_ret_void)
        a.mov_r32_r32('edx', 'eax')

        # Clamp length to available tail room in both buffers.
        a.mov_r32_membase_disp('eax', 'r11', 4)
        a.cmp_r32_r32('r9d', 'eax')
        a.jcc('ge', l_ret_void)
        a.sub_r32_r32('eax', 'r9d')

        a.mov_r32_membase_disp('ecx', 'r10', 4)
        a.cmp_r32_r32('r8d', 'ecx')
        a.jcc('ge', l_ret_void)
        a.sub_r32_r32('ecx', 'r8d')

        a.cmp_r32_r32('edx', 'eax')
        a.jcc('le', l_len_dst)
        a.mov_r32_r32('edx', 'eax')
        a.mark(l_len_dst)
        a.cmp_r32_r32('edx', 'ecx')
        a.jcc('le', l_len_src)
        a.mov_r32_r32('edx', 'ecx')
        a.mark(l_len_src)
        a.test_r32_r32('edx', 'edx')
        a.jcc('le', l_ret_void)

        a.mov_membase_disp_r32('rsp', 0x20, 'edx')
        a.lea_r64_membase_disp('rcx', 'r11', 8)
        a.add_r64_r64('rcx', 'r9')
        a.lea_r64_membase_disp('rdx', 'r10', 8)
        a.add_r64_r64('rdx', 'r8')
        a.mov_r32_membase_disp('r8d', 'rsp', 0x20)
        a.call('fn_copy_bytes')

        a.mark(l_ret_void)
        a.mov_rax_imm64(enc_void())
        a.ret()

    def emit_builtin_fillBytes_function(self) -> None:
        """Emit fn_builtin_fillBytes(dst, off, len, fill).

        Calling convention:
        - RCX/RDX/R8/R9 = tagged MiniLang args
        - R10D          = nargs

        Returns VOID and treats invalid arguments as a no-op.
        """
        a = self.asm
        a.mark('fn_builtin_fillBytes')
        lid = self.new_label_id()
        l_ret_void = f"bfill_ret_void_{lid}"
        l_len_ok = f"bfill_len_ok_{lid}"

        a.cmp_r32_imm('r10d', 4)
        a.jcc('ne', l_ret_void)

        a.mov_r64_r64('r11', 'rcx')  # dst object
        a.mov_r64_r64('r10', 'r9')   # fill tagged

        # dst must be OBJ_BYTES
        a.mov_r64_r64('rax', 'r11')
        a.mov_r64_r64('rcx', 'rax')
        a.and_r64_imm('rcx', 7)
        a.cmp_r64_imm('rcx', TAG_PTR)
        a.jcc('ne', l_ret_void)
        a.mov_r32_membase_disp('eax', 'r11', 0)
        a.cmp_r32_imm('eax', OBJ_BYTES)
        a.jcc('ne', l_ret_void)

        # off -> r9d
        a.mov_r64_r64('rax', 'rdx')
        a.mov_r64_r64('r9', 'rax')
        a.and_r64_imm('r9', 7)
        a.cmp_r64_imm('r9', TAG_INT)
        a.jcc('ne', l_ret_void)
        a.sar_r64_imm8('rax', 3)
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_ret_void)
        a.cmp_r64_imm('rax', 0x7FFFFFFF)
        a.jcc('g', l_ret_void)
        a.mov_r32_r32('r9d', 'eax')

        # len -> edx
        a.mov_r64_r64('rax', 'r8')
        a.mov_r64_r64('rcx', 'rax')
        a.and_r64_imm('rcx', 7)
        a.cmp_r64_imm('rcx', TAG_INT)
        a.jcc('ne', l_ret_void)
        a.sar_r64_imm8('rax', 3)
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_ret_void)
        a.cmp_r64_imm('rax', 0x7FFFFFFF)
        a.jcc('g', l_ret_void)
        a.mov_r32_r32('edx', 'eax')

        # fill -> r8d
        a.mov_r64_r64('rax', 'r10')
        a.mov_r64_r64('rcx', 'rax')
        a.and_r64_imm('rcx', 7)
        a.cmp_r64_imm('rcx', TAG_INT)
        a.jcc('ne', l_ret_void)
        a.sar_r64_imm8('rax', 3)
        a.cmp_r64_imm('rax', 0)
        a.jcc('l', l_ret_void)
        a.cmp_r64_imm('rax', 255)
        a.jcc('g', l_ret_void)
        a.mov_r32_r32('r8d', 'eax')

        # Clamp len to destination tail room and dispatch.
        a.mov_r32_membase_disp('eax', 'r11', 4)
        a.cmp_r32_r32('r9d', 'eax')
        a.jcc('ge', l_ret_void)
        a.sub_r32_r32('eax', 'r9d')
        a.cmp_r32_r32('edx', 'eax')
        a.jcc('le', l_len_ok)
        a.mov_r32_r32('edx', 'eax')
        a.mark(l_len_ok)
        a.test_r32_r32('edx', 'edx')
        a.jcc('le', l_ret_void)

        a.lea_r64_membase_disp('rcx', 'r11', 8)
        a.add_r64_r64('rcx', 'r9')
        a.call('fn_fill_bytes')

        a.mark(l_ret_void)
        a.mov_rax_imm64(enc_void())
        a.ret()

    def emit_builtin_gc_set_limit_function(self) -> None:
        """Emit fn_builtin_gc_set_limit(limit_bytes):

        - Accepts exactly 1 argument (R10D = nargs).
        - Argument must be an int (TAG_INT). Non-int disables periodic GC.
        - If limit_bytes <= 0: disables periodic GC by setting a very large limit.

        Side effects:
        - Updates gc_bytes_limit
        - Resets gc_bytes_since to 0
        - Returns VOID
        """
        a = self.asm
        a.mark('fn_builtin_gc_set_limit')
        lid = self.new_label_id()
        l_call = f"bgsl_call_{lid}"
        l_ret_void = f"bgsl_ret_void_{lid}"
        l_disable = f"bgsl_disable_{lid}"
        l_done = f"bgsl_done_{lid}"
        l_not_int = f"bgsl_not_int_{lid}"

        # Require exactly 1 arg
        a.cmp_r32_imm('r10d', 1)
        a.jcc('e', l_call)
        a.jmp(l_ret_void)

        a.mark(l_call)

        # Check tag == TAG_INT
        a.mov_r64_r64('rax', 'rcx')
        a.mov_r64_r64('rdx', 'rax')
        a.and_r64_imm('rdx', 7)
        a.cmp_r64_imm('rdx', TAG_INT)
        a.jcc('ne', l_not_int)

        # decode: sar rax,3
        a.sar_rax_imm8(3)

        # if rax <= 0 -> disable
        a.cmp_r64_imm('rax', 0)
        a.jcc('le', l_disable)

        # gc_bytes_limit = rax
        a.mov_rip_qword_rax('gc_bytes_limit')
        # gc_bytes_since = 0
        a.mov_rax_imm64(0)
        a.mov_rip_qword_rax('gc_bytes_since')
        a.jmp(l_done)

        a.mark(l_not_int)
        # fallthrough to disable
        a.jmp(l_disable)

        a.mark(l_disable)
        # gc_bytes_limit = very large (effectively disables periodic GC)
        a.mov_rax_imm64(0x7FFFFFFFFFFFFFFF)
        a.mov_rip_qword_rax('gc_bytes_limit')
        # gc_bytes_since = 0
        a.mov_rax_imm64(0)
        a.mov_rip_qword_rax('gc_bytes_since')

        a.mark(l_done)
        a.mov_rax_imm64(enc_void())
        a.ret()

        a.mark(l_ret_void)
        a.mov_rax_imm64(enc_void())
        a.ret()


    def emit_callStats_function(self) -> None:
        """Internal helper for call profiling: callStats() -> array<callStat>.

        Only meaningful when compiling with --profile-calls / call_profile=True.
        When disabled, this helper returns void (callStats() should not be reachable).
        """
        a = self.asm

        a.mark('fn_callStats')

        if not bool(getattr(self, 'call_profile', False)):
            a.mov_rax_imm64(enc_void())
            a.ret()
            return

        n = int(getattr(self, '_callprof_n', 0) or 0)
        name_labels = list(getattr(self, '_callprof_name_labels', []) or [])

        # Win64 ABI: 32B shadow space + 8B local (keep 16B alignment for calls)
        a.sub_rsp_imm8(0x28)

        # Allocate OBJ_ARRAY: size = 8 + n*8
        a.mov_r32_imm32('ecx', n)
        a.shl_r32_imm8('ecx', 3)
        a.add_r32_imm('ecx', 8)
        a.call('fn_alloc')

        a.mov_r11_rax()

        # header: [base]=OBJ_ARRAY, [base+4]=n
        a.mov_membase_disp_imm32('r11', 0, OBJ_ARRAY, qword=False)
        a.mov_membase_disp_imm32('r11', 4, n, qword=False)

        # Save array pointer to local slot and root it across allocations.
        a.mov_membase_disp_r64('rsp', 0x20, 'r11')
        a.mov_rip_qword_r11('gc_tmp0')

        # Build entries (unrolled; n is compile-time known in the compiler output).
        for i in range(n):
            # Allocate callStat struct (8-byte header + 2 fields): size = 24
            a.mov_rcx_imm32(24)
            a.call('fn_alloc')
            a.mov_r64_r64('r10', 'rax')  # r10 = struct

            # header: type / struct_id
            a.mov_membase_disp_imm32('r10', 0, OBJ_STRUCT, qword=False)
            a.mov_membase_disp_imm32('r10', 4, CALLSTAT_STRUCT_ID, qword=False)

            # field0: name (boxed string constant in .rdata)
            if i < len(name_labels) and name_labels[i]:
                a.lea_rax_rip(str(name_labels[i]))
                a.mov_membase_disp_r64('r10', 8, 'rax')
            else:
                a.mov_membase_disp_imm32('r10', 8, enc_void(), qword=True)

            # field1: calls (load u64 counter, tag as int)
            a.lea_r11_rip('callprof_counts')
            a.mov_r64_membase_disp('rax', 'r11', i * 8)
            a.shl_r64_imm8('rax', 3)
            a.or_rax_imm8(TAG_INT)
            a.mov_membase_disp_r64('r10', 16, 'rax')

            # store struct into array element slot
            a.mov_r64_membase_disp('r11', 'rsp', 0x20)  # arr ptr
            a.mov_membase_disp_r64('r11', 8 + i * 8, 'r10')

        # Unroot temp
        a.mov_rax_imm64(enc_void())
        a.mov_rip_qword_rax('gc_tmp0')

        # Return array pointer
        a.mov_r64_membase_disp('rax', 'rsp', 0x20)

        a.add_rsp_imm8(0x28)
        a.ret()
