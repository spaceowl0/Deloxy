/* Flat-binary link script for Deloxy user programs (loaded at 0x400000, entry = first byte).
   .data/.bss are folded into one PROGBITS section: the alpha loader maps the image R+X only,
   so user programs must not write to statics (use the stack / mmap). */
ENTRY(_start)
SECTIONS
{
    . = 0x400000;
    .text : {
        *(.text._start)
        *(.text .text.*)
    }
    .rodata : ALIGN(16) { *(.rodata .rodata.*) }
    .data : ALIGN(16) { *(.data .data.*) *(.bss .bss.*) *(COMMON) }
    /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) }
}
