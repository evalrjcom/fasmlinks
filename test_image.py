#!/usr/bin/env python3
"""Offline structural smoke tests; does not claim to validate v86 or networking."""
from pathlib import Path
p = Path(__file__).resolve().parent
boot = (p / 'boot.bin').read_bytes()
kernel = (p / 'kernel.bin').read_bytes()
image = (p / 'textos.img').read_bytes()
assert len(boot) == 512, 'boot sector must be exactly 512 bytes'
assert boot[510:512] == b'\x55\xaa', 'x86 boot-sector signature missing'
assert len(kernel) <= 32 * 512, 'bootloader can load only 32 kernel sectors'
assert len(image) == 1440 * 1024, 'unexpected floppy geometry'
assert image[:512] == boot, 'boot sector not written correctly'
assert image[512:512 + len(kernel)] == kernel, 'kernel not written at LBA1'
# Keep the expected release version explicit: do not bypass version validation.
expected_version = b'FASM TEXTOS 0.6.6 |'
assert expected_version in kernel, f'wrong build version: expected {expected_version!r}'
print('PASS: boot signature, sizes, image content, kernel version')
