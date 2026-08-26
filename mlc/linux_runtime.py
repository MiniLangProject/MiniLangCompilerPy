"""Linux-x64 process startup and syscall-backed compatibility thunks.

MiniLang's internal native ABI deliberately remains the established Win64-like
ABI on every target.  These small leaf thunks translate OS-facing operations to
Linux syscalls, which keeps optimized language code identical across targets.
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

_RUNTIME_DYNAMIC_IMPORTS = (
    ('libpthread.so.0', 'pthread_create', 'elfiat_runtime_pthread_create'),
    ('libpthread.so.0', 'pthread_join', 'elfiat_runtime_pthread_join'),
)


def linux_dynamic_imports(cg: Any) -> list[tuple[str, str, int]]:
    """Return ``(library, symbol, data-slot-offset)`` records for source externs."""
    result: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str, int]] = set()
    # MiniLang workers must be real pthreads. Raw clone(2) workers do not own a
    # glibc TLS block, so libc sees every worker as the creating thread; that
    # breaks recursive mutex ownership and can corrupt malloc state when native
    # libraries are called concurrently.
    for library, symbol, loader_label in _RUNTIME_DYNAMIC_IMPORTS:
        if loader_label not in cg.data.labels:
            cg.data.pad_align(8)
            cg.data.add_u64(loader_label, 0)
        item = (library, symbol, int(cg.data.labels[loader_label]))
        seen.add(item)
        result.append(item)
    for qname, sig in dict(getattr(cg, 'extern_sigs', {}) or {}).items():
        if not isinstance(sig, dict):
            continue
        library = str(sig.get('dll', '') or '').strip()
        symbol = str(sig.get('symbol', '') or str(qname).split('.')[-1]).strip()
        if not library or not symbol:
            continue
        label = cg._extern_iat_label(library, symbol)
        thunk_label = f'linux_extern_thunk_{label[4:]}'
        if label not in cg.data.labels:
            cg.data.pad_align(8)
            patch_offset = len(cg.data.data)
            cg.data.add_u64(label, 0)
            cg.data.add_abs64_patch(patch_offset, thunk_label)
        loader_label = f'elfiat_{label[4:]}'
        if loader_label not in cg.data.labels:
            cg.data.pad_align(8)
            cg.data.add_u64(loader_label, 0)
        item = (library, symbol, int(cg.data.labels[loader_label]))
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _extern_param_type(param: Any) -> str:
    if isinstance(param, dict):
        for key in ('ty', 'type', 'abi_ty', 'abi'):
            value = param.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return str(param or '').strip().lower()


def _emit_extern_thunks(cg: Any) -> None:
    """Translate MiniLang's stable Win64-like native ABI to Linux SysV."""
    a = cg.asm
    win_regs = ('rcx', 'rdx', 'r8', 'r9')
    sysv_regs = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
    sysv_xregs = tuple(f'xmm{i}' for i in range(8))

    for qname, sig in dict(getattr(cg, 'extern_sigs', {}) or {}).items():
        if not isinstance(sig, dict):
            continue
        library = str(sig.get('dll', '') or '').strip()
        symbol = str(sig.get('symbol', '') or str(qname).split('.')[-1]).strip()
        if not library or not symbol:
            continue
        iat_label = cg._extern_iat_label(library, symbol)
        thunk_label = f'linux_extern_thunk_{iat_label[4:]}'
        if thunk_label in a.labels:
            continue
        loader_label = f'elfiat_{iat_label[4:]}'
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
        frame_min = xmm_save_base + 10 * 16
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

        for index in range(6, 16):
            a.movdqu_xmm_membase_disp(f'xmm{index}', 'rsp', xmm_save_base + (index - 6) * 16)
        if frame <= 0x7F:
            a.add_rsp_imm8(frame)
        else:
            a.add_rsp_imm32(frame)
        a.pop_reg('rsi')
        a.pop_reg('rdi')
        a.ret()


def _syscall(a: Any) -> None:
    a.emit(b'\x0f\x05')


def emit_linux_startup(cg: Any) -> None:
    """Emit the ELF ``_start`` prefix before the ordinary MiniLang entry."""
    a = cg.asm
    d = cg.data
    if 'linux_sigpipe_action' not in d.labels:
        # Linux kernel_sigaction: handler=SIG_IGN, flags/restorer/mask=0.
        d.add_bytes('linux_sigpipe_action', (1).to_bytes(8, 'little') + b'\x00' * 24)
    a.mark('_start')
    # Preserve the kernel-provided argc/argv before adapting stack alignment to
    # the internal ABI (which enters with RSP == 8 mod 16).
    a.mov_r64_membase_disp('rax', 'rsp', 0)
    a.mov_rip_dword_eax('ml_argc')
    a.lea_r64_membase_disp('rax', 'rsp', 8)
    a.mov_rip_qword_rax('ml_argvw')
    a.mov_r64_r64('r11', 'rsp')
    a.mov_rip_qword_r11('linux_initial_rsp')

    # Network libraries may write after a peer has closed its socket. Ignore
    # SIGPIPE process-wide so those writes return EPIPE to MiniLang/OpenSSL
    # instead of terminating the server with signal 13.
    a.mov_r32_imm32('edi', 13)  # SIGPIPE
    a.lea_rax_rip('linux_sigpipe_action')
    a.mov_r64_r64('rsi', 'rax')
    a.xor_r32_r32('edx', 'edx')
    a.mov_r32_imm32('r10d', 8)  # kernel sigset size on x86-64
    a.mov_r32_imm32('eax', 13)  # rt_sigaction
    _syscall(a)

    # arch_prctl(ARCH_SET_GS, &linux_gs_area).  MiniLang stores its current
    # managed-thread context at gs:[0x28], matching its Windows representation.
    a.mov_r32_imm32('edi', 0x1001)
    a.lea_rax_rip('linux_gs_area')
    a.mov_r64_r64('rsi', 'rax')
    a.mov_r32_imm32('eax', 158)
    _syscall(a)
    ok = 'linux_gs_ready'
    a.test_r64_r64('rax', 'rax')
    a.jcc('e', ok)
    a.mov_r32_imm32('eax', 60)
    a.mov_r32_imm32('edi', 127)
    _syscall(a)
    a.emit(b'\x0f\x0b')  # ud2
    a.mark(ok)
    a.sub_rsp_imm8(8)
    a.jmp('linux_program_entry')
    a.mark('linux_program_entry')


def _emit_bool_success(a: Any, label: str) -> None:
    a.mark(label)
    a.mov_r32_imm32('eax', 1)
    a.ret()


def emit_linux_runtime(cg: Any) -> None:
    """Append syscall thunks and materialize their IAT-compatible data slots."""
    a = cg.asm
    d = cg.data

    for name in _CORE_IMPORTS:
        slot = f'iat_{name}'
        if slot in d.labels:
            continue
        d.pad_align(8)
        off = len(d.data)
        d.add_u64(slot, 0)
        d.add_abs64_patch(off, f'linux_{name}')

    # Source-declared externs use the same indirect-call representation as PE
    # imports.  The ELF writer asks the dynamic loader to fill these slots.
    linux_dynamic_imports(cg)

    # HANDLE GetStdHandle(DWORD): translate Win32 standard-handle constants to fds.
    a.mark('linux_GetStdHandle')
    l_in, l_out = 'linux_std_in', 'linux_std_out'
    a.cmp_r32_imm32('ecx', -10)
    a.jcc('e', l_in)
    a.cmp_r32_imm32('ecx', -11)
    a.jcc('e', l_out)
    a.mov_r32_imm32('eax', 2)
    a.ret()
    a.mark(l_in)
    a.xor_r32_r32('eax', 'eax')
    a.ret()
    a.mark(l_out)
    a.mov_r32_imm32('eax', 1)
    a.ret()

    # BOOL WriteFile(fd, buffer, count, &written, ...)
    a.mark('linux_WriteFile')
    a.push_reg('rdi')
    a.push_reg('rsi')
    a.mov_r64_r64('rdi', 'rcx')
    a.mov_r64_r64('rsi', 'rdx')
    a.mov_r32_r32('edx', 'r8d')
    a.mov_r32_imm32('eax', 1)
    _syscall(a)
    l_write_fail, l_write_done = 'linux_write_fail', 'linux_write_done'
    a.test_r64_r64('rax', 'rax')
    a.jcc('s', l_write_fail)
    a.mov_membase_disp_r32('r9', 0, 'eax')
    a.mov_r32_imm32('eax', 1)
    a.jmp(l_write_done)
    a.mark(l_write_fail)
    a.xor_r32_r32('eax', 'eax')
    a.mark(l_write_done)
    a.pop_reg('rsi')
    a.pop_reg('rdi')
    a.ret()

    # BOOL ReadFile(fd, buffer, count, &read, ...)
    a.mark('linux_ReadFile')
    a.push_reg('rdi')
    a.push_reg('rsi')
    a.mov_r64_r64('rdi', 'rcx')
    a.mov_r64_r64('rsi', 'rdx')
    a.mov_r32_r32('edx', 'r8d')
    a.xor_r32_r32('eax', 'eax')
    _syscall(a)
    l_read_fail, l_read_done = 'linux_read_fail', 'linux_read_done'
    a.test_r64_r64('rax', 'rax')
    a.jcc('s', l_read_fail)
    a.mov_membase_disp_r32('r9', 0, 'eax')
    a.mov_r32_imm32('eax', 1)
    a.jmp(l_read_done)
    a.mark(l_read_fail)
    a.xor_r32_r32('eax', 'eax')
    a.mark(l_read_done)
    a.pop_reg('rsi')
    a.pop_reg('rdi')
    a.ret()

    a.mark('linux_ExitProcess')
    a.mov_r32_r32('edi', 'ecx')
    # Win32 ExitProcess terminates every process thread. Linux SYS_exit only
    # ends the caller and would leave blocked workers behind, so use exit_group.
    a.mov_r32_imm32('eax', 231)
    _syscall(a)
    a.emit(b'\x0f\x0b')

    # VirtualAlloc reserve/commit maps naturally to mmap/mprotect.
    a.mark('linux_VirtualAlloc')
    l_commit = 'linux_valloc_commit'
    l_vfail = 'linux_valloc_fail'
    a.test_r32_r32('r8d', 'r8d')
    a.mov_r32_r32('eax', 'r8d')
    a.and_r32_imm('eax', 0x2000)
    a.jcc('e', l_commit)
    a.push_reg('rdi')
    a.push_reg('rsi')
    a.mov_r64_r64('rdi', 'rcx')
    a.mov_r64_r64('rsi', 'rdx')
    a.mov_r32_r32('eax', 'r8d')
    a.and_r32_imm('eax', 0x1000)
    a.mov_r32_imm32('edx', 0)
    l_res_prot = 'linux_valloc_res_prot'
    a.test_r32_r32('eax', 'eax')
    a.jcc('e', l_res_prot)
    a.mov_r32_imm32('edx', 3)
    a.mark(l_res_prot)
    a.mov_r32_imm32('r10d', 0x22)
    a.mov_r64_imm64('r8', -1)
    a.xor_r32_r32('r9d', 'r9d')
    a.mov_r32_imm32('eax', 9)
    _syscall(a)
    a.mov_r64_r64('r11', 'rax')
    a.pop_reg('rsi')
    a.pop_reg('rdi')
    a.mov_r64_r64('rax', 'r11')
    a.cmp_r64_imm32('rax', -4095)
    a.jcc('ae', l_vfail)
    a.ret()
    a.mark(l_commit)
    a.push_reg('rdi')
    a.push_reg('rsi')
    a.mov_r64_r64('rdi', 'rcx')
    a.mov_r64_r64('rsi', 'rdx')
    a.mov_r32_imm32('edx', 3)
    a.mov_r32_imm32('eax', 10)
    _syscall(a)
    a.mov_r64_r64('r11', 'rax')
    a.pop_reg('rsi')
    a.pop_reg('rdi')
    a.test_r64_r64('r11', 'r11')
    a.jcc('ne', l_vfail)
    a.mov_r64_r64('rax', 'rcx')
    a.ret()
    a.mark(l_vfail)
    a.xor_r32_r32('eax', 'eax')
    a.ret()

    # Decommit pages with madvise(DONTNEED) followed by PROT_NONE.
    a.mark('linux_VirtualFree')
    a.push_reg('rdi')
    a.push_reg('rsi')
    a.mov_r64_r64('rdi', 'rcx')
    a.mov_r64_r64('rsi', 'rdx')
    a.mov_r32_imm32('edx', 4)
    a.mov_r32_imm32('eax', 28)
    _syscall(a)
    a.xor_r32_r32('edx', 'edx')
    a.mov_r32_imm32('eax', 10)
    _syscall(a)
    a.pop_reg('rsi')
    a.pop_reg('rdi')
    a.mov_r32_imm32('eax', 1)
    a.ret()

    # Sleep(milliseconds). Windows Sleep(0) yields the remainder of the current
    # time slice; poll(NULL, 0, 0) merely returns and can starve a mutator while
    # the collector waits for it to reach a cooperative safepoint.
    a.mark('linux_Sleep')
    a.push_reg('rdi')
    a.push_reg('rsi')
    a.test_r32_r32('ecx', 'ecx')
    a.jcc('ne', 'linux_sleep_poll')
    a.mov_r32_imm32('eax', 24)  # sched_yield
    _syscall(a)
    a.jmp('linux_sleep_done')
    a.mark('linux_sleep_poll')
    a.xor_r32_r32('edi', 'edi')
    a.xor_r32_r32('esi', 'esi')
    a.mov_r32_r32('edx', 'ecx')
    a.mov_r32_imm32('eax', 7)
    _syscall(a)
    a.mark('linux_sleep_done')
    a.pop_reg('rsi')
    a.pop_reg('rdi')
    a.ret()

    # The process-wide monitors use a recursive spin mutex in their first 12
    # bytes: lock, owner tid, recursion depth.
    a.mark('linux_InitializeCriticalSection')
    a.mov_membase_disp_imm32('rcx', 0, 0, qword=False)
    a.ret()
    a.mark('linux_EnterCriticalSection')
    lock_loop = 'linux_cs_lock_loop'
    a.mov_r64_r64('r10', 'rcx')
    a.mov_r32_imm32('eax', 186)  # gettid
    _syscall(a)
    a.mov_r32_r32('r9d', 'eax')
    a.mov_r32_membase_disp('eax', 'r10', 4)
    a.cmp_r32_r32('eax', 'r9d')
    a.jcc('ne', lock_loop)
    a.mov_r32_membase_disp('eax', 'r10', 8)
    a.inc_r32('eax')
    a.mov_membase_disp_r32('r10', 8, 'eax')
    a.ret()
    a.mark(lock_loop)
    a.xor_r32_r32('eax', 'eax')
    a.mov_r32_imm32('edx', 1)
    a.lock_cmpxchg_membase_disp_r32('r10', 0, 'edx')
    a.jcc('e', 'linux_cs_lock_done')
    a.emit(b'\xf3\x90')
    # A pure PAUSE loop can monopolize a constrained WSL/Linux scheduler while
    # the lock owner is parked. Yield after each failed acquisition so GC and
    # mutator threads can always hand the runtime monitor back to one another.
    a.mov_r32_imm32('eax', 24)  # sched_yield
    _syscall(a)
    a.jmp(lock_loop)
    a.mark('linux_cs_lock_done')
    a.mov_membase_disp_r32('r10', 4, 'r9d')
    a.mov_membase_disp_imm32('r10', 8, 1, qword=False)
    a.ret()
    a.mark('linux_LeaveCriticalSection')
    a.mov_r64_r64('r10', 'rcx')
    a.mov_r32_imm32('eax', 186)
    _syscall(a)
    a.mov_r32_membase_disp('edx', 'r10', 4)
    a.cmp_r32_r32('edx', 'eax')
    a.jcc('ne', 'linux_cs_leave_done')
    a.mov_r32_membase_disp('edx', 'r10', 8)
    a.cmp_r32_imm('edx', 1)
    a.jcc('le', 'linux_cs_leave_release')
    a.dec_r32('edx')
    a.mov_membase_disp_r32('r10', 8, 'edx')
    a.ret()
    a.mark('linux_cs_leave_release')
    a.mov_membase_disp_imm32('r10', 8, 0, qword=False)
    a.mov_membase_disp_imm32('r10', 4, 0, qword=False)
    a.mov_membase_disp_imm32('r10', 0, 0, qword=False)
    a.mark('linux_cs_leave_done')
    a.ret()

    # CreateThread is backed by pthread_create so every worker receives a valid
    # glibc TLS block. The private page stores pthread_t, completion/join state,
    # the internal callback, its managed context, and MiniLang's GS scratch area.
    a.mark('linux_CreateThread')
    for reg in ('rbx', 'r12', 'r13', 'r14', 'r15', 'rdi', 'rsi'):
        a.push_reg(reg)
    # SysV treats every XMM register as volatile, whereas MiniLang's stable
    # internal ABI follows Win64 and requires XMM6-XMM15 to survive a call.
    # Preserve that non-volatile set around pthread_create.
    a.sub_rsp_imm32(0xA0)
    for index in range(6, 16):
        a.movdqu_membase_disp_xmm('rsp', (index - 6) * 16, f'xmm{index}')
    a.mov_r64_r64('r13', 'r8')       # start routine
    a.mov_r64_r64('r14', 'r9')       # argument/context
    a.mov_r64_membase_disp('r15', 'rsp', 0x108)  # lpThreadId
    a.xor_r32_r32('edi', 'edi')
    a.mov_r32_imm32('esi', 0x1000)
    a.mov_r32_imm32('edx', 3)
    a.mov_r32_imm32('r10d', 0x22)
    a.mov_r64_imm64('r8', -1)
    a.xor_r32_r32('r9d', 'r9d')
    a.mov_r32_imm32('eax', 9)
    _syscall(a)
    a.cmp_r64_imm32('rax', -4095)
    a.jcc('ae', 'linux_thread_create_fail')
    a.mov_r64_r64('r12', 'rax')
    a.mov_membase_disp_imm32('r12', 8, 1, qword=False)
    a.mov_membase_disp_r64('r12', 16, 'r13')
    a.mov_membase_disp_r64('r12', 24, 'r14')
    a.mov_r64_r64('rdi', 'r12')
    a.xor_r32_r32('esi', 'esi')
    a.lea_rax_rip('linux_pthread_start')
    a.mov_r64_r64('rdx', 'rax')
    a.mov_r64_r64('rcx', 'r12')
    a.call_rip_qword('elfiat_runtime_pthread_create')
    a.test_r32_r32('eax', 'eax')
    a.jcc('ne', 'linux_thread_create_cleanup')
    a.mov_r64_membase_disp('rax', 'r12', 0)
    a.mov_membase_disp_r32('r15', 0, 'eax')
    a.mov_r64_r64('r11', 'r12')
    for index in range(6, 16):
        a.movdqu_xmm_membase_disp(f'xmm{index}', 'rsp', (index - 6) * 16)
    a.add_rsp_imm32(0xA0)
    for reg in ('rsi', 'rdi', 'r15', 'r14', 'r13', 'r12', 'rbx'):
        a.pop_reg(reg)
    a.mov_r64_r64('rax', 'r11')
    a.ret()

    # SysV pthread entry bridge to MiniLang's stable internal ABI.
    a.mark('linux_pthread_start')
    a.push_reg('r12')
    a.sub_rsp_imm8(0x20)
    a.mov_r64_r64('r12', 'rdi')
    a.lea_r64_membase_disp('rax', 'r12', 0x40)
    a.mov_r64_r64('rsi', 'rax')
    a.mov_r32_imm32('edi', 0x1001)
    a.mov_r32_imm32('eax', 158)
    _syscall(a)
    a.mov_r64_membase_disp('rcx', 'r12', 24)
    a.mov_r64_membase_disp('rax', 'r12', 16)
    a.call_rax()
    a.mov_membase_disp_imm32('r12', 8, 0, qword=False)
    a.xor_r64_r64('rax', 'rax')
    a.add_rsp_imm8(0x20)
    a.pop_reg('r12')
    a.ret()

    a.mark('linux_thread_create_cleanup')
    a.mov_r64_r64('rdi', 'r12')
    a.mov_r32_imm32('esi', 0x1000)
    a.mov_r32_imm32('eax', 11)
    _syscall(a)
    a.mark('linux_thread_create_fail')
    for index in range(6, 16):
        a.movdqu_xmm_membase_disp(f'xmm{index}', 'rsp', (index - 6) * 16)
    a.add_rsp_imm32(0xA0)
    for reg in ('rsi', 'rdi', 'r15', 'r14', 'r13', 'r12', 'rbx'):
        a.pop_reg(reg)
    a.xor_r32_r32('eax', 'eax')
    a.ret()

    a.mark('linux_WaitForSingleObject')
    a.push_reg('r12')
    a.push_reg('r13')
    a.push_reg('r14')
    a.sub_rsp_imm32(0xA0)
    for index in range(6, 16):
        a.movdqu_membase_disp_xmm('rsp', (index - 6) * 16, f'xmm{index}')
    a.mov_r64_r64('r12', 'rcx')
    a.mov_r32_r32('r13d', 'edx')
    a.mark('linux_thread_wait_loop')
    a.mov_r32_membase_disp('eax', 'r12', 8)
    a.test_r32_r32('eax', 'eax')
    a.jcc('e', 'linux_thread_wait_join')
    a.test_r32_r32('r13d', 'r13d')
    a.jcc('e', 'linux_thread_wait_timeout')
    a.mov_r32_imm32('ecx', 1)
    a.call('linux_Sleep')
    a.cmp_r32_imm32('r13d', -1)
    a.jcc('e', 'linux_thread_wait_loop')
    a.dec_r32('r13d')
    a.jmp('linux_thread_wait_loop')
    a.mark('linux_thread_wait_join')
    a.mov_r32_membase_disp('eax', 'r12', 32)
    a.test_r32_r32('eax', 'eax')
    a.jcc('ne', 'linux_thread_wait_ok')
    a.mov_r64_membase_disp('rdi', 'r12', 0)
    a.xor_r32_r32('esi', 'esi')
    a.call_rip_qword('elfiat_runtime_pthread_join')
    a.test_r32_r32('eax', 'eax')
    a.jcc('ne', 'linux_thread_wait_failed')
    a.mov_membase_disp_imm32('r12', 32, 1, qword=False)
    a.mark('linux_thread_wait_ok')
    a.xor_r32_r32('eax', 'eax')
    a.jmp('linux_thread_wait_done')
    a.mark('linux_thread_wait_failed')
    a.mov_r32_imm32('eax', 0xFFFFFFFF)
    a.jmp('linux_thread_wait_done')
    a.mark('linux_thread_wait_timeout')
    a.mov_r32_imm32('eax', 0x102)
    a.mark('linux_thread_wait_done')
    for index in range(6, 16):
        a.movdqu_xmm_membase_disp(f'xmm{index}', 'rsp', (index - 6) * 16)
    a.add_rsp_imm32(0xA0)
    a.pop_reg('r14')
    a.pop_reg('r13')
    a.pop_reg('r12')
    a.ret()

    a.mark('linux_CloseHandle')
    a.push_reg('r12')
    a.push_reg('rdi')
    a.push_reg('rsi')
    a.sub_rsp_imm32(0xA0)
    for index in range(6, 16):
        a.movdqu_membase_disp_xmm('rsp', (index - 6) * 16, f'xmm{index}')
    a.mov_r64_r64('r12', 'rcx')
    a.mov_r32_membase_disp('eax', 'r12', 8)
    a.test_r32_r32('eax', 'eax')
    a.jcc('ne', 'linux_thread_close_fail')
    a.mov_r32_membase_disp('eax', 'r12', 32)
    a.test_r32_r32('eax', 'eax')
    a.jcc('ne', 'linux_thread_close_unmap')
    a.mov_r64_membase_disp('rdi', 'r12', 0)
    a.xor_r32_r32('esi', 'esi')
    a.call_rip_qword('elfiat_runtime_pthread_join')
    a.test_r32_r32('eax', 'eax')
    a.jcc('ne', 'linux_thread_close_fail')
    a.mark('linux_thread_close_unmap')
    a.mov_r64_r64('rdi', 'r12')
    a.mov_r32_imm32('esi', 0x1000)
    a.mov_r32_imm32('eax', 11)
    _syscall(a)
    a.test_r64_r64('rax', 'rax')
    a.jcc('ne', 'linux_thread_close_fail')
    a.mov_r32_imm32('eax', 1)
    a.jmp('linux_thread_close_done')
    a.mark('linux_thread_close_fail')
    a.xor_r32_r32('eax', 'eax')
    a.mark('linux_thread_close_done')
    for index in range(6, 16):
        a.movdqu_xmm_membase_disp(f'xmm{index}', 'rsp', (index - 6) * 16)
    a.add_rsp_imm32(0xA0)
    a.pop_reg('rsi')
    a.pop_reg('rdi')
    a.pop_reg('r12')
    a.ret()

    # fmod has the same floating-register argument layout in both x64 ABIs.
    a.mark('linux_fmod')
    a.movsd_xmm_xmm('xmm2', 'xmm0')
    a.divsd_xmm_xmm('xmm2', 'xmm1')
    a.roundsd_xmm_xmm_imm8('xmm2', 'xmm2', 3)
    a.mulsd_xmm_xmm('xmm2', 'xmm1')
    a.subsd_xmm_xmm('xmm0', 'xmm2')
    a.ret()

    # Compact dependency-free gcvt replacement. MiniLang requests 15
    # significant digits; six fractional digits cover the runtime's ordinary
    # decimal form while trailing zeroes are removed deterministically.
    a.mark('linux__gcvt')
    for reg in ('rbx', 'r12', 'r13', 'r14', 'r15', 'rsi', 'rdi'):
        a.push_reg(reg)
    a.mov_r64_r64('r12', 'r8')
    a.mov_r64_r64('r13', 'r8')
    a.movq_r64_xmm('rax', 'xmm0')
    a.mov_r64_r64('r11', 'rax')
    a.shr_r64_imm8('r11', 63)
    a.shl_r64_imm8('rax', 1)
    a.shr_r64_imm8('rax', 1)
    a.movq_xmm_r64('xmm0', 'rax')
    a.test_r64_r64('r11', 'r11')
    a.jcc('e', 'linux_gcvt_abs')
    a.mov_membase_disp_imm8('r13', 0, 45)
    a.inc_r64('r13')
    a.mark('linux_gcvt_abs')
    a.cvttsd2si_r64_xmm('r14', 'xmm0')
    a.mov_r64_r64('r15', 'r13')
    a.test_r64_r64('r14', 'r14')
    a.jcc('ne', 'linux_gcvt_int_loop')
    a.mov_membase_disp_imm8('r13', 0, 48)
    a.inc_r64('r13')
    a.jmp('linux_gcvt_int_done')
    a.mark('linux_gcvt_int_loop')
    a.mov_r64_r64('rax', 'r14')
    a.cqo()
    a.mov_r32_imm32('ebx', 10)
    a.div_r64('rbx')
    a.add_r32_imm('edx', 48)
    a.mov_membase_disp_r8('r13', 0, 'dl')
    a.inc_r64('r13')
    a.mov_r64_r64('r14', 'rax')
    a.test_r64_r64('r14', 'r14')
    a.jcc('ne', 'linux_gcvt_int_loop')

    # Reverse the integer digits accumulated least-significant first.
    a.mov_r64_r64('r10', 'r15')
    a.mov_r64_r64('r11', 'r13')
    a.dec_r64('r11')
    a.mark('linux_gcvt_reverse_loop')
    a.cmp_r64_r64('r10', 'r11')
    a.jcc('ae', 'linux_gcvt_int_done')
    a.mov_r8_membase_disp('al', 'r10', 0)
    a.mov_r8_membase_disp('dl', 'r11', 0)
    a.mov_membase_disp_r8('r10', 0, 'dl')
    a.mov_membase_disp_r8('r11', 0, 'al')
    a.inc_r64('r10')
    a.dec_r64('r11')
    a.jmp('linux_gcvt_reverse_loop')

    a.mark('linux_gcvt_int_done')
    # frac6 = round((abs(value) - integer_part) * 1_000_000)
    a.cvttsd2si_r64_xmm('r14', 'xmm0')
    a.cvtsi2sd_xmm_r64('xmm1', 'r14')
    a.subsd_xmm_xmm('xmm0', 'xmm1')
    a.mov_r32_imm32('eax', 1000000)
    a.cvtsi2sd_xmm_r64('xmm1', 'rax')
    a.mulsd_xmm_xmm('xmm0', 'xmm1')
    a.roundsd_xmm_xmm_imm8('xmm0', 'xmm0', 0)
    a.cvttsd2si_r64_xmm('r14', 'xmm0')
    a.test_r64_r64('r14', 'r14')
    a.jcc('e', 'linux_gcvt_terminate')
    a.mov_membase_disp_imm8('r13', 0, 46)
    a.inc_r64('r13')
    a.mov_r32_imm32('r15d', 100000)
    a.mark('linux_gcvt_frac_loop')
    a.mov_r64_r64('rax', 'r14')
    a.cqo()
    a.div_r64('r15')
    a.add_r32_imm('eax', 48)
    a.mov_membase_disp_r8('r13', 0, 'al')
    a.inc_r64('r13')
    a.mov_r64_r64('r14', 'rdx')
    a.mov_r64_r64('rax', 'r15')
    a.cqo()
    a.mov_r32_imm32('ebx', 10)
    a.div_r64('rbx')
    a.mov_r64_r64('r15', 'rax')
    a.test_r64_r64('r15', 'r15')
    a.jcc('ne', 'linux_gcvt_frac_loop')
    a.mark('linux_gcvt_trim')
    a.mov_r8_membase_disp('al', 'r13', -1)
    a.cmp_r8_imm8('al', 48)
    a.jcc('ne', 'linux_gcvt_terminate')
    a.dec_r64('r13')
    a.jmp('linux_gcvt_trim')
    a.mark('linux_gcvt_terminate')
    a.mov_membase_disp_imm8('r13', 0, 0)
    a.mov_r64_r64('rax', 'r12')
    for reg in ('rdi', 'rsi', 'r15', 'r14', 'r13', 'r12', 'rbx'):
        a.pop_reg(reg)
    a.ret()

    # Harmless compatibility operations. Target-specific argv construction does
    # not call the Windows command-line functions.
    for name in ('SetConsoleOutputCP', 'FreeConsole', 'LocalFree'):
        _emit_bool_success(a, f'linux_{name}')
    for name in ('GetCommandLineW', 'CommandLineToArgvW',
                 'WriteConsoleW', 'MultiByteToWideChar',
                 'WideCharToMultiByte'):
        a.mark(f'linux_{name}')
        a.xor_r32_r32('eax', 'eax')
        a.ret()

    _emit_extern_thunks(cg)
