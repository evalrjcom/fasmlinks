#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -x "${FASM:-}" ]; then :; elif command -v fasm >/dev/null 2>&1; then FASM=fasm; else echo "Set FASM=/path/to/fasm.x64" >&2; exit 1; fi
"$FASM" boot.asm boot.bin
"$FASM" kernel.asm kernel.bin
[ "$(wc -c < boot.bin)" -eq 512 ] || { echo 'Boot sector not 512 bytes' >&2; exit 1; }
[ "$(wc -c < kernel.bin)" -le 16384 ] || { echo 'Kernel exceeds 32-sector loader capacity' >&2; exit 1; }
dd if=/dev/zero of=textos.img bs=1024 count=1440 status=none
dd if=boot.bin of=textos.img conv=notrunc status=none
dd if=kernel.bin of=textos.img bs=512 seek=1 conv=notrunc status=none
printf 'Created %s/textos.img\n' "$PWD"