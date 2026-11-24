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
# Fetch the pinned upstream release and verify its archive before compiling.
sh fetch_bearssl.sh
bear=vendor/bearssl-0.6
flags='-m32 -march=i686 -Os -ffreestanding -fno-builtin -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections'
mkdir -p build/bearssl
# Compile actual upstream SHA-256 and HMAC code, plus their common codec helpers.
# No OS entropy, socket or filesystem code is linked into the guest.
for src in "$bear"/src/hash/*.c "$bear"/src/mac/*.c; do
  # Some codec functions are inline in upstream; only compile existing files.
  [ -f "$src" ] || continue
  cc $flags -I"$bear/inc" -I"$bear/src" -c "$src" -o "build/bearssl/$(basename "$src" .c).o"
done
# Include the full codec directory to cover upstream range helpers.
for src in "$bear"/src/codec/*.c; do
  cc $flags -I"$bear/inc" -I"$bear/src" -c "$src" -o "build/bearssl/$(basename "$src" .c).o"
done
cc $flags -I"$bear/inc" -c tls_platform.c -o tls_platform.o
cc $flags -c runtime.c -o runtime.o
ld -m elf_i386 -T aux.ld --gc-sections --no-undefined -o aux.elf tls_platform.o runtime.o build/bearssl/*.o
# Exercise the exact freestanding self-test as a host executable too.
cc -O2 -I"$bear/inc" -I"$bear/src" -DHOST_TEST tls_platform.c "$bear"/src/hash/*.c "$bear"/src/mac/*.c "$bear"/src/codec/*.c -o build/bearssl-selftest
./build/bearssl-selftest
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