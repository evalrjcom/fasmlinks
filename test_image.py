#!/usr/bin/env python3
"""Offline structural smoke tests; does not validate v86 runtime."""
from pathlib import Path

p = Path(__file__).resolve().parent
boot = (p / 'boot.bin').read_bytes()
kernel = (p / 'kernel.bin').read_bytes()
image = (p / 'textos.img').read_bytes()

# FIX: parse the shared assembler constant without a regex replacement.
entries = []
for line in (p / 'kernel_layout.inc').read_text().splitlines():
    key, sep, value = line.split(';', 1)[0].partition('=')
    if sep and key.strip() == 'KERNEL_SECTORS':
        entries.append(int(value.strip()))
assert len(entries) == 1, 'expected exactly one kernel sector limit'
sectors = entries[0]
assert 1 <= sectors <= 128, 'kernel load overlaps scratch RAM'
assert len(boot) == 512, 'boot sector must be exactly 512 bytes'
assert boot[510:512] == b'\x55\xaa', 'x86 boot-sector signature missing'
assert 0 < len(kernel) <= sectors * 512, 'kernel exceeds loader capacity'
assert len(image) == 1440 * 1024, 'unexpected floppy geometry'
assert image[:512] == boot, 'boot sector not written correctly'
assert image[512:512 + len(kernel)] == kernel, 'kernel not written at LBA1'
assert not any(image[512 + len(kernel):512 + sectors * 512]), 'kernel padding must be zero'
aux = (p / 'aux.bin').read_bytes()
assert 0 < len(aux) <= 128 * 512, 'auxiliary payload size'
aux_start = (sectors + 1) * 512
assert image[aux_start:aux_start + len(aux)] == aux, 'auxiliary payload placement'
assert not any(image[aux_start + len(aux):aux_start + 128 * 512]), 'auxiliary padding'
expected_version = b'FASM TEXTOS 0.7.9 |'
assert expected_version in kernel, f'wrong build version: expected {expected_version!r}'
print('PASS: boot signature, sizes, image content, padding, kernel version')
