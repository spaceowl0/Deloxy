; privileged instruction in ring 3 -> #GP -> process killed
bits 64
    cli
    jmp $
