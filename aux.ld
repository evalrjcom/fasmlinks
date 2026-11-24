OUTPUT_FORMAT(elf32-i386)
ENTRY(tls_platform_probe)
SECTIONS {
 . = 0x40000;
 .text : { KEEP(*(.entry)) *(.text*) }
 .rodata : { *(.rodata*) }
 .data : { *(.data*) }
 .bss : { *(.bss*) *(COMMON) }
 /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
 ASSERT(tls_platform_probe == 0x40000, "ABI entry mismatch")
 ASSERT(. <= 0x50000, "auxiliary region overflow")
}
