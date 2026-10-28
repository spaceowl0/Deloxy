; user-mode null dereference -> #PF -> process killed
bits 64
    xor eax, eax
    mov byte [rax], 1
    jmp $
