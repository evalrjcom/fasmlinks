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
dd if=/dev/zero of=textos.img bs=1024 count=1440 status=none
dd if=boot.bin of=textos.img conv=notrunc status=none
dd if=kernel.bin of=textos.img bs=512 seek=1 conv=notrunc status=none
printf 'Created %s/textos.img\n' "$PWD"