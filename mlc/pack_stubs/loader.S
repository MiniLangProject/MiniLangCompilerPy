// MiniLang fixed-layout x64 startup loader. Built at development time only;
// compilers embed its bytes and never invoke an external assembler.
.intel_syntax noprefix
.section .text
.global stub_start
stub_start:
#ifdef WINDOWS_STUB
    sub rsp, 56
    lea rbx, [rip + params]
    call verify_payload
    test eax, eax
    jz failed
    mov rcx, [rbx + 8]
    mov rdx, [rbx + 56]
    mov r8d, 4                 // PAGE_READWRITE
    lea r9, [rsp + 32]
    mov rax, [rbx + 40]
    mov rax, [rax]
    call rax
    test eax, eax
    jz failed
#else
    push rdx                   // Preserve rtld's finalizer register.
    lea rbx, [rip + params]
    call verify_payload
    test eax, eax
    jz failed
    mov eax, 10               // mprotect
    mov rdi, [rbx + 8]
    mov rsi, [rbx + 56]
    mov edx, 3                // PROT_READ | PROT_WRITE
    syscall
    test rax, rax
    js failed
#endif
    mov rsi, [rbx + 0]        // Compressed LZ4 block.
    mov rcx, [rbx + 24]
    mov rdi, [rbx + 8]        // Original .text address.
    mov rdx, [rbx + 16]
    call decode_lz4
    test eax, eax
    jz failed
#ifdef WINDOWS_STUB
    mov rcx, [rbx + 8]
    mov rdx, [rbx + 56]
    mov r8d, 32               // PAGE_EXECUTE_READ
    lea r9, [rsp + 32]
    mov rax, [rbx + 40]
    mov rax, [rax]
    call rax
    test eax, eax
    jz failed
    add rsp, 56
#else
    mov eax, 10
    mov rdi, [rbx + 8]
    mov rsi, [rbx + 56]
    mov edx, 5                // PROT_READ | PROT_EXEC
    syscall
    test rax, rax
    js failed
    pop rdx
#endif
    jmp QWORD PTR [rbx + 32]
failed:
#ifdef WINDOWS_STUB
    mov ecx, 127
    mov rax, [rbx + 48]
    mov rax, [rax]
    call rax
    ud2
#else
    mov eax, 60
    mov edi, 127
    syscall
    ud2
#endif

// Verify the compressed code before changing protections or executing it.
verify_payload:
    mov rsi, [rbx]
    mov rcx, [rbx + 24]
    mov eax, 2166136261
.hash_next:
    test rcx, rcx
    jz .hash_done
    movzx edx, BYTE PTR [rsi]
    xor eax, edx
    imul eax, eax, 16777619
    inc rsi
    dec rcx
    jmp .hash_next
.hash_done:
    cmp eax, DWORD PTR [rbx + 64]
    sete al
    movzx eax, al
    ret

// Inputs: RSI/RCX = compressed data/length; RDI/RDX = output/length.
// Returns EAX=1 only after consuming input and filling output exactly.
decode_lz4:
    lea r8, [rsi + rcx]       // input end
    lea r9, [rdi + rdx]       // output end
    mov r10, rdi              // output start
.sequence:
    cmp rsi, r8
    jae .invalid
    movzx r11d, BYTE PTR [rsi]
    inc rsi
    mov r12, r11
    shr r12, 4
    cmp r12, 15
    jne .literal_ready
.literal_extension:
    cmp rsi, r8
    jae .invalid
    movzx r13d, BYTE PTR [rsi]
    inc rsi
    add r12, r13
    cmp r13, 255
    je .literal_extension
.literal_ready:
    mov r13, r8
    sub r13, rsi
    cmp r12, r13
    ja .invalid
    mov r13, r9
    sub r13, rdi
    cmp r12, r13
    ja .invalid
    mov rcx, r12
    rep movsb
    cmp rsi, r8
    je .done
    mov r13, r8
    sub r13, rsi
    cmp r13, 2
    jb .invalid
    movzx r12d, WORD PTR [rsi]
    add rsi, 2
    test r12, r12
    jz .invalid
    mov r13, rdi
    sub r13, r10
    cmp r12, r13
    ja .invalid
    and r11d, 15
    mov r13, r11
    add r13, 4
    cmp r11d, 15
    jne .match_ready
.match_extension:
    cmp rsi, r8
    jae .invalid
    movzx r11d, BYTE PTR [rsi]
    inc rsi
    add r13, r11
    cmp r11d, 255
    je .match_extension
.match_ready:
    mov rcx, r9
    sub rcx, rdi
    cmp r13, rcx
    ja .invalid
    mov rcx, rdi
    sub rcx, r12
.match_copy:
    mov al, BYTE PTR [rcx]
    mov BYTE PTR [rdi], al
    inc rcx
    inc rdi
    dec r13
    jnz .match_copy
    jmp .sequence
.done:
    cmp rdi, r9
    jne .invalid
    mov eax, 1
    ret
.invalid:
    xor eax, eax
    ret

.balign 8
params:
    .quad 0x1111111111111111 // payload address
    .quad 0x2222222222222222 // text address
    .quad 0x3333333333333333 // text decoded length
    .quad 0x4444444444444444 // packed length
    .quad 0x5555555555555555 // original entry address
    .quad 0x6666666666666666 // VirtualProtect IAT slot (Windows)
    .quad 0x7777777777777777 // ExitProcess IAT slot (Windows)
    .quad 0x8888888888888888 // page-aligned text length
    .quad 0x9999999999999999 // FNV-1a of compressed code
