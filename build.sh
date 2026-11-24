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
# Explicit freestanding configuration: no glibc fortification, OS RNG or CPU RNG.
flags='-m32 -march=i686 -Os -ffreestanding -fno-builtin -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -DBR_USE_URANDOM=0 -DBR_USE_GETENTROPY=0 -DBR_USE_WIN32_RAND=0 -DBR_USE_RDRAND=0 -DBR_USE_UNIX_TIME=0 -DBR_USE_WIN32_TIME=0'
rm -rf build/bearssl
mkdir -p build/bearssl
# Compile upstream sources into an archive; only reachable functions enter aux.elf.
for src in "$bear"/src/*/*.c; do
  obj="build/bearssl/$(basename "$(dirname "$src")")_$(basename "$src" .c).o"
  cc $flags -I"$bear/inc" -I"$bear/src" -c "$src" -o "$obj"
done
ar rcs build/bearssl/libbearssl.a build/bearssl/*.o
# Generate actual CA anchors from the runner's packaged trust store.
make -C "$bear" -j2
"$bear/build/brssl" ta /etc/ssl/certs/ca-certificates.crt > build/trust_anchors.h
cc $flags -Ibuild -I"$bear/inc" -c tls_platform.c -o tls_platform.o
cc $flags -c runtime.c -o runtime.o
# Compiler integer helpers are freestanding machine code, not libc.
cc -m32 -nostdlib -static -no-pie -Wl,-T,aux.ld,--gc-sections,--no-undefined -o aux.elf tls_platform.o runtime.o build/bearssl/libbearssl.a -lgcc
# Test the same code in a 32-bit host process, with OS entropy disabled in BearSSL.
cc -m32 -O2 -fno-pie -no-pie -I"$bear/inc" -DHOST_TEST tls_platform.c build/bearssl/libbearssl.a -o build/bearssl-selftest
./build/bearssl-selftest
# Reject unresolved runtime references before publishing a guest binary.
test -z "$(nm -u aux.elf)"
size aux.elf
objcopy -O binary aux.elf aux.bin
aux_sectors=$(awk '$1 == "AUX_SECTORS" && $2 == "=" {print $3}' kernel_layout.inc)
[ "$aux_sectors" -eq 512 ] || { echo 'Unexpected auxiliary layout' >&2; exit 1; }
aux_size=$(wc -c < aux.bin)
[ "$aux_size" -gt 0 ] && [ "$aux_size" -le "$((aux_sectors * 512))" ] || { echo 'Auxiliary payload exceeds loader capacity' >&2; exit 1; }
dd if=/dev/zero of=textos.img bs=1024 count=1440 status=none
dd if=boot.bin of=textos.img conv=notrunc status=none
dd if=kernel.bin of=textos.img bs=512 seek=1 conv=notrunc status=none
dd if=aux.bin of=textos.img bs=512 seek="$((sectors + 1))" conv=notrunc status=none
printf 'Created %s/textos.img\n' "$PWD"