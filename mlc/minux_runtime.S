# Copyright 2026 Nils Kopal. Apache-2.0.
# MinUX x64 boundary. Managed calls retain MiniLang's Win64-like ABI.
# Native ELF externs use SysV; int 80h follows include/user/lib.h.
.intel_syntax noprefix

.section .text.startup,"ax"
.global _start
_start:
    mov DWORD PTR [rip+ml_argc], edi
    mov QWORD PTR [rip+ml_argvw], rsi
    xor eax, eax
    test rsi, rsi
    jz .Lsave_executable
    mov rax, QWORD PTR [rsi]
.Lsave_executable:
    mov QWORD PTR [rip+minux_executable_name], rax
    sub rsp, 8
    mov rdi, rdx
    call QWORD PTR [rip+elfiat_runtime_set_environ]
    xor edi, edi
    lea rsi, [rip+linux_gs_area]
    mov eax, 484                  # thread_environment(SET_GS, address)
    int 0x80
    test rax, rax
    jnz .Lstartup_fail
    mov edi, 13                   # SIGPIPE -> SIG_IGN
    mov esi, 1
    mov eax, 412
    int 0x80
    add rsp, 8
    jmp minux_program_entry
.Lstartup_fail:
    mov edi, 127
    mov eax, 60
    int 0x80
    ud2

.section .text.runtime,"ax"
.global minux_executable_path
minux_executable_path:
    # fn_build_args consumes and clears the transient argv globals. Keep the
    # original argv[0] pointer independently for process APIs and child MLOs.
    mov rax, QWORD PTR [rip+minux_executable_name]
    ret
.macro PUBLIC name
.global minux_\name
minux_\name:
.endm

# Preserve the additional Win64 nonvolatiles across SysV calls.
.macro NATIVE_ENTER
    push rdi
    push rsi
    sub rsp, 168
    .irp n,6,7,8,9,10,11,12,13,14,15
    movdqu [rsp+16*(\n-6)], xmm\n
    .endr
.endm
.macro NATIVE_LEAVE
    .irp n,6,7,8,9,10,11,12,13,14,15
    movdqu xmm\n, [rsp+16*(\n-6)]
    .endr
    add rsp, 168
    pop rsi
    pop rdi
.endm

PUBLIC GetStdHandle
    mov eax, 2
    cmp ecx, -10
    jne .Lstdout
    xor eax, eax
    ret
.Lstdout:
    cmp ecx, -11
    jne .Lhandle_done
    mov eax, 1
.Lhandle_done:
    ret

.macro IO name, number
PUBLIC \name
    push rdi
    push rsi
    mov rdi, rcx
    mov rsi, rdx
    mov edx, r8d
    mov eax, \number
    int 0x80
    test rax, rax
    js .Lio_fail\@
    test r9, r9
    jz .Lio_ok\@
    mov DWORD PTR [r9], eax
.Lio_ok\@:
    mov eax, 1
    jmp .Lio_done\@
.Lio_fail\@:
    xor eax, eax
.Lio_done\@:
    pop rsi
    pop rdi
    ret
.endm
IO ReadFile, 0
IO WriteFile, 1

PUBLIC ExitProcess
    mov edi, ecx
    mov eax, 60
    int 0x80
    ud2

# Request {address,length,operation,protection}; Information has the same size.
# RCX/RDX/R8D/R9D -> address/length/op/protection. CF reports failure.
.Lvm:
    test r8d, r8d
    jnz .Lvm_one
    cmp rdx, 0x40000000
    ja .Lreserve_split
.Lvm_one:
    push rdi
    push rsi
    sub rsp, 56
    mov [rsp], rcx
    mov [rsp+8], rdx
    mov [rsp+16], r8d
    mov [rsp+20], r9d
    lea rdi, [rsp]
    lea rsi, [rsp+24]
    mov eax, 485
    int 0x80
    test rax, rax
    jnz .Lvm_fail
    mov rax, [rsp]
    add rsp, 56
    pop rsi
    pop rdi
    clc
    ret
.Lvm_fail:
    xor eax, eax
    add rsp, 56
    pop rsi
    pop rdi
    stc
    ret

# MinUX bounds each VM operation to 1 GiB. Split large virtual reservations;
# roll back every completed extent if any part cannot be reserved.
.Lreserve_split:
    push r12
    push r13
    push r14
    sub rsp, 32
    mov r12, rcx
    mov r13, rdx
    mov r14, rcx
.Lreserve_next:
    mov rcx, r14
    mov rdx, r13
    cmp rdx, 0x40000000
    jbe .Lreserve_chunk
    mov edx, 0x40000000
.Lreserve_chunk:
    xor r8d, r8d
    xor r9d, r9d
    call .Lvm_one
    jc .Lreserve_rollback
    add r14, rdx
    sub r13, rdx
    jnz .Lreserve_next
    mov rax, r12
    clc
    jmp .Lreserve_return
.Lreserve_rollback:
    sub r14, r12
    mov r13, r14
    mov r14, r12
.Lrollback_next:
    test r13, r13
    jz .Lreserve_failed
    mov rcx, r14
    mov rdx, r13
    cmp rdx, 0x40000000
    jbe .Lrollback_chunk
    mov edx, 0x40000000
.Lrollback_chunk:
    mov r8d, 3
    xor r9d, r9d
    call .Lvm_one
    jc .Lthread_fatal
    add r14, rdx
    sub r13, rdx
    jmp .Lrollback_next
.Lreserve_failed:
    xor eax, eax
    stc
.Lreserve_return:
    lea rsp, [rsp+32]
    pop r14
    pop r13
    pop r12
    ret

PUBLIC VirtualAlloc
    # GC requests PAGE_READWRITE. Reject other contracts explicitly.
    cmp r9d, 4
    jne .Lalloc_fail
    test r8d, 0x80000              # MEM_RESET is an optional discard hint.
    jnz .Lreset
    push rbx
    push r12
    push r13
    sub rsp, 32
    mov r12, rdx
    mov ebx, r8d
    test ebx, 0x2000
    jz .Lcommit
    test rcx, rcx
    jnz .Lreserve_address
    mov rax, rdx
    lock xadd QWORD PTR [rip+minux_reserve_cursor], rax
    mov rcx, rax
.Lreserve_address:
    xor r8d, r8d                  # Reserve; no physical backing.
    xor r9d, r9d
    call .Lvm
    jc .Lalloc_restore
    mov rcx, rax
    test ebx, 0x1000
    jz .Lalloc_restore
.Lcommit:
    mov r13, rcx
    mov rdx, r12
    mov r8d, 1                    # Commit
    mov r9d, 3                    # READ | WRITE
    call .Lvm
    jnc .Lalloc_committed
    test ebx, 0x2000
    jz .Lalloc_restore
    mov rcx, r13                  # Roll back a failed reserve+commit.
    mov rdx, r12
    mov r8d, 3                    # Release
    xor r9d, r9d
    call .Lvm
    xor eax, eax
    jmp .Lalloc_restore
.Lalloc_committed:
    mov rax, r13
.Lalloc_restore:
    add rsp, 32
    pop r13
    pop r12
    pop rbx
    ret
.Lreset:
    # Keeping dead pages resident is valid MEM_RESET behavior; they remain RW.
    mov rax, rcx
    ret
.Lalloc_fail:
    xor eax, eax
    ret

PUBLIC VirtualFree
    # GC decommits page-aligned spans; it retains its reserved address range.
    cmp r8d, 0x4000
    jne .Lfree_fail
    sub rsp, 40
    mov r8d, 2                    # Decommit
    xor r9d, r9d
    call .Lvm
    setnc al
    movzx eax, al
    add rsp, 40
    ret
.Lfree_fail:
    xor eax, eax
    ret

PUBLIC Sleep
    push rdi
    push rsi
    test ecx, ecx
    jz .Lyield
    mov eax, 449                  # tick frequency
    int 0x80
    mov esi, ecx
    imul rax, rsi
    add rax, 999
    xor edx, edx
    mov esi, 1000
    div rsi
    mov rdi, rax
    mov eax, 443                  # sleep ticks
    int 0x80
    jmp .Lsleep_done
.Lyield:
    mov eax, 24
    int 0x80
.Lsleep_done:
    pop rsi
    pop rdi
    ret

PUBLIC InitializeCriticalSection
    mov QWORD PTR [rcx], 0
    mov DWORD PTR [rcx+8], 0
    ret
PUBLIC EnterCriticalSection
    mov eax, 39                   # thread id; process id is syscall 438
    int 0x80
    mov r10d, eax
    cmp [rcx+4], eax
    jne .Llock
    inc DWORD PTR [rcx+8]
    ret
.Llock:
    xor eax, eax
    mov edx, 1
    lock cmpxchg [rcx], edx
    je .Llocked
    pause
    mov eax, 24
    int 0x80
    jmp .Llock
.Llocked:
    mov [rcx+4], r10d
    mov DWORD PTR [rcx+8], 1
    ret
PUBLIC LeaveCriticalSection
    dec DWORD PTR [rcx+8]
    jnz .Lunlock_done
    mov DWORD PTR [rcx+4], 0
    mov DWORD PTR [rcx], 0
.Lunlock_done:
    ret

# Handle: pthread_t, running:u32, padding, callback, context, join_state:u32,
# padding; private GS storage begins at +64. All publication is x86 TSO.
PUBLIC CreateThread
    push r12
    push r13
    push r14
    push r15
    NATIVE_ENTER
    mov r13, r8
    mov r14, r9
    mov r15, [rsp+264]            # original RSP+48: lpThreadId
    mov edi, 128
    mov esi, 1
    call QWORD PTR [rip+elfiat_runtime_calloc]
    test rax, rax
    jz .Lcreate_done
    mov r12, rax
    mov DWORD PTR [r12+8], 1
    mov [r12+16], r13
    mov [r12+24], r14
    mov rdi, r12
    xor esi, esi
    lea rdx, [rip+.Lpthread_start]
    mov rcx, r12
    call QWORD PTR [rip+elfiat_runtime_pthread_create]
    test eax, eax
    jnz .Lcreate_cleanup
    test r15, r15
    jz .Lcreate_ok
    mov eax, [r12]
    mov [r15], eax
.Lcreate_ok:
    mov rax, r12
    jmp .Lcreate_done
.Lcreate_cleanup:
    mov rdi, r12
    call QWORD PTR [rip+elfiat_runtime_free]
    xor eax, eax
.Lcreate_done:
    NATIVE_LEAVE
    pop r15
    pop r14
    pop r13
    pop r12
    ret
.Lpthread_start:
    push r12
    sub rsp, 32
    mov r12, rdi
    xor edi, edi
    lea rsi, [r12+64]
    mov eax, 484
    int 0x80
    test rax, rax
    jnz .Lthread_fatal
    mov rcx, [r12+24]
    call QWORD PTR [r12+16]
    mov DWORD PTR [r12+8], 0
    xor eax, eax
    add rsp, 32
    pop r12
    ret
.Lthread_fatal:
    mov edi, 127
    mov eax, 60
    int 0x80
    ud2

PUBLIC WaitForSingleObject
    push r12
    push r13
    push r14
    push r15
    NATIVE_ENTER
    mov r12, rcx
    mov r13d, edx
    mov eax, 440
    int 0x80
    mov r14, rax
    mov eax, 449
    int 0x80
    imul rax, r13
    add rax, 999
    xor edx, edx
    mov esi, 1000
    div rsi
    mov r15, rax
.Lwait:
    cmp DWORD PTR [r12+8], 0
    je .Ljoin_claim
    test r13d, r13d
    jz .Ltimeout
    cmp r13d, -1
    je .Lwait_sleep
    mov eax, 440
    int 0x80
    sub rax, r14
    cmp rax, r15
    jae .Ltimeout
.Lwait_sleep:
    sub rsp, 32
    mov ecx, 1
    call minux_Sleep
    add rsp, 32
    jmp .Lwait
.Ljoin_claim:
    mov eax, [r12+32]
    cmp eax, 2
    je .Lwait_ok
    test eax, eax
    jnz .Ljoin_yield
    mov edx, 1
    lock cmpxchg [r12+32], edx
    jne .Ljoin_claim
    mov rdi, [r12]
    xor esi, esi
    call QWORD PTR [rip+elfiat_runtime_pthread_join]
    test eax, eax
    jnz .Ljoin_fail
    mov DWORD PTR [r12+32], 2
.Lwait_ok:
    xor eax, eax
    jmp .Lwait_done
.Ljoin_yield:
    test r13d, r13d
    jz .Ltimeout
    cmp r13d, -1
    je .Ljoin_sleep
    mov eax, 440
    int 0x80
    sub rax, r14
    cmp rax, r15
    jae .Ltimeout
.Ljoin_sleep:
    mov eax, 24
    int 0x80
    jmp .Ljoin_claim
.Ljoin_fail:
    mov DWORD PTR [r12+32], 0
    mov eax, -1
    jmp .Lwait_done
.Ltimeout:
    mov eax, 258
.Lwait_done:
    NATIVE_LEAVE
    pop r15
    pop r14
    pop r13
    pop r12
    ret

PUBLIC CloseHandle
    push r12
    sub rsp, 32
    mov r12, rcx
    cmp DWORD PTR [r12+8], 0
    jne .Lclose_fail
    mov edx, -1
    call minux_WaitForSingleObject
    test eax, eax
    jnz .Lclose_fail
    mov rcx, r12
    add rsp, 32
    pop r12
    NATIVE_ENTER
    mov rdi, rcx
    call QWORD PTR [rip+elfiat_runtime_free]
    mov eax, 1
    NATIVE_LEAVE
    ret
.Lclose_fail:
    xor eax, eax
    add rsp, 32
    pop r12
    ret

PUBLIC fmod
    movsd xmm2, xmm0
    divsd xmm2, xmm1
    roundsd xmm2, xmm2, 3
    mulsd xmm2, xmm1
    subsd xmm0, xmm2
    ret

PUBLIC _gcvt
    # Same deterministic decimal helper as the Linux runtime (generated below).
    jmp minux_number_gcvt

PUBLIC SetConsoleOutputCP
PUBLIC FreeConsole
PUBLIC LocalFree
    mov eax, 1
    ret
PUBLIC GetCommandLineW
PUBLIC CommandLineToArgvW
PUBLIC WriteConsoleW
PUBLIC MultiByteToWideChar
PUBLIC WideCharToMultiByte
    xor eax, eax
    ret

# Private SysV semaphore adapter used by std.threading. MinUX libc supplies
# pthreads but no sem_* API. The count is lock-free and waiters yield to the
# scheduler; no kernel resources or global errno are involved.
.global minux_sem_init
minux_sem_init:
    test esi, esi
    jnz .Lsem_fail
    test edx, edx
    js .Lsem_fail
    mov [rdi], edx
    xor eax, eax
    ret
.global minux_sem_trywait
minux_sem_trywait:
    mov eax, [rdi]
.Lsem_take:
    test eax, eax
    jz .Lsem_fail
    lea edx, [rax-1]
    lock cmpxchg [rdi], edx
    jne .Lsem_take
    xor eax, eax
    ret
.Lsem_fail:
    mov eax, -1
    ret
.global minux_sem_wait
minux_sem_wait:
    sub rsp, 8
.Lsem_wait:
    call minux_sem_trywait
    test eax, eax
    jz .Lsem_wait_done
    mov eax, 24
    int 0x80
    jmp .Lsem_wait
.Lsem_wait_done:
    add rsp, 8
    ret
.global minux_sem_post
minux_sem_post:
    mov eax, [rdi]
.Lsem_give:
    cmp eax, 0x7fffffff
    je .Lsem_fail
    lea edx, [rax+1]
    lock cmpxchg [rdi], edx
    jne .Lsem_give
    xor eax, eax
    ret
.global minux_sem_getvalue
minux_sem_getvalue:
    mov eax, [rdi]
    mov [rsi], eax
    xor eax, eax
    ret
.global minux_sem_destroy
minux_sem_destroy:
    xor eax, eax
    ret
