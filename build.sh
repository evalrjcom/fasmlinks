#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -x "${FASM:-}" ]; then :; elif command -v fasm >/dev/null 2>&1; then FASM=fasm; else echo "Set FASM=/path/to/fasm.x64" >&2; exit 1; fi
"$FASM" boot.asm boot.bin
"$FASM" kernel.asm kernel.bin
[ "$(wc -c < boot.bin)" -eq 512 ] || { echo 'Boot sector not 512 bytes' >&2; exit 1; }
sectors=$(awk '$1 == "KERNEL_SECTORS" && $2 == "=" {print $3}' kernel_layout.inc)
case "$sectors" in ''|*[!0-9]*) echo 'Invalid kernel sector limit' >&2; exit 1;; esac
[ "$sectors" -ge 1 ] && [ "$sectors" -le 128 ] || { echo 'Kernel load region exceeds segment or overlaps scratch RAM' >&2; exit 1; }
size=$(wc -c < kernel.bin)
[ "$size" -gt 0 ] && [ "$size" -le "$((sectors * 512))" ] || { echo "Kernel exceeds $sectors-sector loader capacity" >&2; exit 1; }
# Compile freestanding C without host runtime dependencies.
cc -m32 -march=i686 -Os -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -c tls_platform.c -o tls_platform.o
ld -m elf_i386 -T aux.ld --no-undefined -o aux.elf tls_platform.o
objcopy -O binary aux.elf aux.bin
aux_sectors=$(awk '$1 == "AUX_SECTORS" && $2 == "=" {print $3}' kernel_layout.inc)
[ "$aux_sectors" -eq 128 ] || { echo 'Unexpected auxiliary layout' >&2; exit 1; }
aux_size=$(wc -c < aux.bin)
[ "$aux_size" -gt 0 ] && [ "$aux_size" -le "$((aux_sectors * 512))" ] || { echo 'Auxiliary payload exceeds loader capacity' >&2; exit 1; }
dd if=/dev/zero of=textos.img bs=1024 count=1440 status=none
dd if=boot.bin of=textos.img conv=notrunc status=none
dd if=kernel.bin of=textos.img bs=512 seek=1 conv=notrunc status=none
dd if=aux.bin of=textos.img bs=512 seek="$((sectors + 1))" conv=notrunc status=none
printf 'Created %s/textos.img\n' "$PWD"