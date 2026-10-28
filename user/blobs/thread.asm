; spawn a second thread; child prints "child" and exits its thread; main sleeps 50ms, prints "main", exit(7)
bits 64
    mov eax, 6
    lea rdi, [rel child]
    mov rsi, rsp
    sub rsi, 8192
    syscall
    mov eax, 2
    mov edi, 50
    syscall
    lea rdi, [rel msg_main]
    mov esi, 5
    mov eax, 3
    syscall
    mov eax, 0
    mov edi, 7
    syscall
    jmp $
child:
    lea rdi, [rel msg_child]
    mov esi, 6
    mov eax, 3
    syscall
    mov eax, 7
    xor edi, edi
    syscall
    jmp $
msg_child: db "child", 10
msg_main:  db "main", 10
