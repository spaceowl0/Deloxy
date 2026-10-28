/* ELF link script for native Deloxy programs: page-aligned R+X / R / R+W segments (W^X),
   program headers inside the first segment (AT_PHDR), and a PT_NOTE marking the Deloxy ABI. */
ENTRY(_start)
PHDRS
{
    text   PT_LOAD FILEHDR PHDRS FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
    note   PT_NOTE FLAGS(4);
}
SECTIONS
{
    . = 0x400000 + SIZEOF_HEADERS;
    .text : { *(.text._start) *(.text .text.*) } :text
    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) } :rodata
    .note.deloxy : { KEEP(*(.note.deloxy)) } :rodata :note
    . = ALIGN(4096);
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note.gnu*) }
}
