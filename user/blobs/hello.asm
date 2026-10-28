; write_debug("hello from ring 3\n"); exit(42)
bits 64
start:
    lea rdi, [rel msg]
    mov esi, msg_end - msg
    mov eax, 3
    syscall
    mov eax, 0
    mov edi, 42
    syscall
    jmp $
msg: db "hello from ring 3", 10
msg_end:
