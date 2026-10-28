; mmap_anon(4096) -> write 'X' -> write_debug -> getpid -> munmap -> exit(0)
bits 64
    mov eax, 4
    mov edi, 4096
    xor esi, esi
    syscall
    test rax, rax
    js fail
    mov rbx, rax
    mov byte [rbx], 'X'
    mov rdi, rbx
    mov esi, 1
    mov eax, 3
    syscall
    mov eax, 9
    syscall
    mov r12, rax            ; pid (preserved across syscalls)
    mov eax, 5
    mov rdi, rbx
    mov esi, 4096
    syscall
    test rax, rax
    jnz fail
    mov eax, 0
    xor edi, edi
    syscall
fail:
    mov eax, 0
    mov edi, 99
    syscall
    jmp $
