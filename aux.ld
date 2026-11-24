OUTPUT_FORMAT(elf32-i386)
ENTRY(tls_dispatch)
SECTIONS {
 . = 0x40000;
 .text : { KEEP(*(.entry)) *(.text*) }
 .rodata : { *(.rodata*) }
 .data : { *(.data*) }
 .bss : { *(.bss*) *(COMMON) }
 /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
 ASSERT(tls_dispatch == 0x40000, "ABI entry mismatch")
 ASSERT(. <= 0x80000, "auxiliary region overflow")
}
