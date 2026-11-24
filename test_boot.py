#!/usr/bin/env python3
"""Boot the actual floppy in QEMU and require the guest TLS test to pass."""
import pathlib
import subprocess
import tempfile
import time

root = pathlib.Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as tmp:
    log = pathlib.Path(tmp) / "debug.log"
    cmd = ["qemu-system-i386", "-machine", "pc", "-m", "32M",
           "-drive", f"file={root / 'textos.img'},format=raw,if=floppy,readonly=on",
           "-boot", "a", "-display", "none", "-serial", "none",
           "-monitor", "none", "-nic", "none", "-no-reboot",
           "-debugcon", f"file:{log}", "-global", "isa-debugcon.iobase=0xe9"]
    with subprocess.Popen(cmd, stdout=subprocess.DEVNULL) as proc:
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                data = log.read_bytes() if log.exists() else b""
                if b"TEXTOS TLS SELFTEST FAIL" in data:
                    raise SystemExit("FAIL: guest BearSSL self-test")
                if b"TEXTOS TLS SELFTEST PASS" in data:
                    print("PASS: real-mode loader, protected-mode kernel and guest BearSSL self-test")
                    break
                if proc.poll() is not None:
                    raise SystemExit(f"FAIL: QEMU exited early ({proc.returncode}), log={data!r}")
                time.sleep(0.25)
            else:
                raise SystemExit(f"FAIL: guest boot test timed out, log={data!r}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
