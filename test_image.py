#!/usr/bin/env python3
"""Offline structural smoke tests; does not claim to validate v86 or networking."""
from pathlib import Path
p = Path(__file__).resolve().parent
boot = (p / 'boot.bin').read_bytes()
kernel = (p / 'kernel.bin').read_bytes()
image = (p / 'textos.img').read_bytes()
assert len(boot) == 512, 'boot sector must be exactly 512 bytes'
assert boot[510:512] == b'\x55\xaa', 'x86 boot-sector signature missing'
import re
layout = (p / 'kernel_layout.inc').read_text()
match = re.search(r'^KERNEL_SECTORS\s*=\s*(\d+)\s*
assert len(image) == 1440 * 1024, 'unexpected floppy geometry'
assert image[:512] == boot, 'boot sector not written correctly'
assert image[512:512 + len(kernel)] == kernel, 'kernel not written at LBA1'
# Keep the expected release version explicit: do not bypass version validation.
expected_version = b'FASM TEXTOS 0.7.2 |'
assert expected_version in kernel, f'wrong build version: expected {expected_version!r}'
print('PASS: boot signature, sizes, image content, kernel version')
, layout, re.M)
assert match, 'kernel layout constant missing'
sectors = int(match.group(1))
assert 1 <= sectors <= 128, 'kernel load overlaps scratch RAM'
assert 0 < len(kernel) <= sectors * 512, 'kernel exceeds loader capacity'
assert not any(image[512 + len(kernel):512 + sectors * 512]), 'kernel padding must be zero'
assert len(image) == 1440 * 1024, 'unexpected floppy geometry'
assert image[:512] == boot, 'boot sector not written correctly'
assert image[512:512 + len(kernel)] == kernel, 'kernel not written at LBA1'
# Keep the expected release version explicit: do not bypass version validation.
expected_version = b'FASM TEXTOS 0.7.2 |'
assert expected_version in kernel, f'wrong build version: expected {expected_version!r}'
print('PASS: boot signature, sizes, image content, kernel version')
