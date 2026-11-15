"""Shared Win64-like MiniLang to SysV bridge for ELF targets.

Linux resolves through library-local handles. MinUX binds its global ELF
namespace at process startup. Register, stack, FP and out-parameter marshalling
and nonvolatile-register preservation are identical in both modes.
"""
from __future__ import annotations
from typing import Any

_CORE_IMPORTS = (
    'GetStdHandle', 'ReadFile', 'WriteFile', 'WriteConsoleW',
    'MultiByteToWideChar', 'SetConsoleOutputCP', 'FreeConsole', 'ExitProcess',
    'VirtualAlloc', 'VirtualFree', 'GetCommandLineW', 'LocalFree',
    'WideCharToMultiByte', 'CreateThread', 'WaitForSingleObject', 'CloseHandle',
    'Sleep', 'InitializeCriticalSection', 'EnterCriticalSection',
    'LeaveCriticalSection', '_gcvt', 'fmod', 'CommandLineToArgvW',
)

def _extern_param_type(param: Any) -> str:
    if isinstance(param, dict):
        # An out parameter carries an address even when its pointee is double.
        if bool(param.get('out', False)):
            return 'pointer'
        for key in ('ty', 'type', 'abi_ty', 'abi'):
            value = param.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return str(param or '').strip().lower()


def emit_extern_thunks(cg: Any, *, eager: bool = False) -> None:
    """Translate MiniLang's stable Win64-like native ABI to SysV."""
    a = cg.asm
    win_regs = ('rcx', 'rdx', 'r8', 'r9')
    sysv_regs = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
    sysv_xregs = tuple(f'xmm{i}' for i in range(8))

    for qname, sig in dict(getattr(cg, 'extern_sigs', {}) or {}).items():
        if not isinstance(sig, dict):
            continue
        library = str(sig.get('dll', '') or '')
        symbol = str(sig.get('symbol', '') or str(qname).split('.')[-1])
        if not library.strip() or not symbol.strip():
            continue
        iat_label = cg._extern_iat_label(library, symbol)
        thunk_label = f'linux_extern_thunk_{iat_label[4:]}'
        if thunk_label in a.labels:
            continue
        loader_label = f'elfiat_{iat_label[4:]}'
        suffix = iat_label[4:]
        library_label = f'linux_extern_library_{suffix}'
        symbol_label = f'linux_extern_symbol_{suffix}'
        params = list(sig.get('params', []) or [])

        int_index = 0
        xmm_index = 0
        destinations: list[tuple[str, int | str]] = []
        stack_count = 0
        for param in params:
            is_double = _extern_param_type(param) == 'double'
            if is_double and xmm_index < len(sysv_xregs):
                destinations.append(('xmm', sysv_xregs[xmm_index]))
                xmm_index += 1
            elif not is_double and int_index < len(sysv_regs):
                destinations.append(('reg', sysv_regs[int_index]))
                int_index += 1
            else:
                destinations.append(('stack', stack_count))
                stack_count += 1

        native_base = stack_count * 8
        xmm_save_base = native_base + len(params) * 8
        loader_handle_offset = xmm_save_base + 10 * 16
        frame_min = loader_handle_offset + 8
        # Two pushes retain entry's 8-mod-16 alignment. A frame congruent to 8
        # leaves RSP 16-byte aligned at the SysV call site.
        frame = ((frame_min + 7) // 16) * 16 + 8

        a.mark(thunk_label)
        a.push_reg('rdi')
        a.push_reg('rsi')
        if frame <= 0x7F:
            a.sub_rsp_imm8(frame)
        else:
            a.sub_rsp_imm32(frame)

        for index, param in enumerate(params):
            destination = native_base + index * 8
            if index < 4:
                if _extern_param_type(param) == 'double':
                    a.movsd_membase_disp_xmm('rsp', destination, f'xmm{index}')
                else:
                    a.mov_membase_disp_r64('rsp', destination, win_regs[index])
            else:
                original_stack = frame + 0x38 + (index - 4) * 8
                a.mov_r64_membase_disp('rax', 'rsp', original_stack)
                a.mov_membase_disp_r64('rsp', destination, 'rax')

        for index in range(6, 16):
            a.movdqu_membase_disp_xmm('rsp', xmm_save_base + (index - 6) * 16, f'xmm{index}')

        if not eager:
            # Resolve through the declared library's handle, not the ELF global
            # symbol namespace. The shared slot has four states: 0=unresolved,
            # 1=one thread resolving, 2=permanent failure, pointer=resolved. A
            # compare/exchange claim prevents concurrent first calls from leaking
            # loader references or publishing a partially initialized pointer.
            resolve_retry = f'{thunk_label}_resolve_retry'
            resolve_claim = f'{thunk_label}_resolve_claim'
            resolve_wait = f'{thunk_label}_resolve_wait'
            resolved = f'{thunk_label}_resolved'
            resolve_symbol_failed = f'{thunk_label}_resolve_symbol_failed'
            resolve_publish_failed = f'{thunk_label}_resolve_publish_failed'
            resolve_failed = f'{thunk_label}_resolve_failed'
            epilogue = f'{thunk_label}_epilogue'
            a.mark(resolve_retry)
            a.mov_rax_rip_qword(loader_label)
            a.test_r64_r64('rax', 'rax')
            a.jcc('e', resolve_claim)
            a.cmp_r64_imm('rax', 1)
            a.jcc('e', resolve_wait)
            a.cmp_r64_imm('rax', 2)
            a.jcc('e', resolve_failed)
            a.jmp(resolved)
            a.mark(resolve_wait)
            a.emit(b'\xf3\x90')  # PAUSE while the owning resolver is in libdl.
            a.jmp(resolve_retry)
            a.mark(resolve_claim)
            a.lea_r11_rip(loader_label)
            a.mov_r32_imm32('edx', 1)
            a.lock_cmpxchg_membase_disp_r64('r11', 0, 'rdx')
            a.jcc('ne', resolve_retry)
            a.lea_rax_rip(library_label)
            a.mov_r64_r64('rdi', 'rax')
            a.mov_r32_imm32('esi', 2)  # RTLD_NOW | RTLD_LOCAL
            a.call_rip_qword('elfiat_runtime_dlopen')
            a.test_r64_r64('rax', 'rax')
            a.jcc('e', resolve_publish_failed)
            a.mov_membase_disp_r64('rsp', loader_handle_offset, 'rax')
            a.mov_r64_r64('rdi', 'rax')
            a.lea_rax_rip(symbol_label)
            a.mov_r64_r64('rsi', 'rax')
            a.call_rip_qword('elfiat_runtime_dlsym')
            a.test_r64_r64('rax', 'rax')
            a.jcc('e', resolve_symbol_failed)
            a.mov_rip_qword_rax(loader_label)
            a.mark(resolved)

        for index, (kind, destination) in enumerate(destinations):
            source = native_base + index * 8
            if kind == 'xmm':
                a.movsd_xmm_membase_disp(str(destination), 'rsp', source)
            elif kind == 'reg':
                a.mov_r64_membase_disp(str(destination), 'rsp', source)
            else:
                a.mov_r64_membase_disp('rax', 'rsp', source)
                a.mov_membase_disp_r64('rsp', int(destination) * 8, 'rax')
        a.mov_r32_imm32('eax', xmm_index)
        a.call_rip_qword(loader_label)
        # R11D carries a private success bit to the shared epilogue. Shifting
        # it immediately before RET publishes resolution failure in CF without
        # disturbing the native return value in RAX/XMM0.
        a.mov_r32_imm32('r11d', 0)
        if not eager:
            a.jmp(epilogue)
            a.mark(resolve_symbol_failed)
            a.mov_r64_membase_disp('rdi', 'rsp', loader_handle_offset)
            a.call_rip_qword('elfiat_runtime_dlclose')
            a.mark(resolve_publish_failed)
            a.mov_r32_imm32('eax', 2)
            a.mov_rip_qword_rax(loader_label)
            a.jmp(resolve_failed)
            a.mark(resolve_failed)
            a.mov_r32_imm32('r11d', 1)
            a.mark(epilogue)

        for index in range(6, 16):
            a.movdqu_xmm_membase_disp(f'xmm{index}', 'rsp', xmm_save_base + (index - 6) * 16)
        if frame <= 0x7F:
            a.add_rsp_imm8(frame)
        else:
            a.add_rsp_imm32(frame)
        a.pop_reg('rsi')
        a.pop_reg('rdi')
        a.shr_r32_imm8('r11d', 1)
        a.ret()
