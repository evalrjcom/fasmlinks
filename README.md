# FASM Links / TextOS 0.6.5 (experimental)

This is a 32-bit FASM bootable floppy prototype for the ne2k interface emulated by copy.sh/v86. It has a VGA text console, PCI discovery, NE2000 transmit/receive, ARP, and an incomplete DHCP/IPv4/TCP prototype.

## Building

Install FASM (1.73.35 known to compile this source) and run `sh build.sh` from this folder. `textos.img` is a 1.44 MB raw floppy disk image; select it as the floppy in https://copy.sh/v86/, using the **ne2k** network adapter.

## Changes in 0.6.5

* `ip.asm`: `; FIX` comments mark checks for truncated packets, IPv4 total length, UDP length, invalid headers, fragmentation, and checksum validation. Reject IPv4 options rather than parsing them as a fixed 20-byte header.
* `dhcp.asm`: `; FIX` comments mark DHCP source-MAC loopback rejection, BOOTP hardware-address validation, and DHCP receive checks; manual D-key retransmission is available in the latest repair, but a real retry/lease timer is still needed.
* `kernel.asm`: version and diagnostic text update; displays count of locally looped-back frames.

## Known limitations

Do **not** assume DHCP is fixed simply because the source assembles. Testing with the relay and WISP networking backends is still needed. The DHCP transaction ID is static and lease renewal, rebinding and expiration are not implemented. DHCP retries currently require manual D-key input; a clock-driven state machine is required. TCP has no retransmission timers, checksum validation of received segments, robust sequence/window handling, or out-of-order reassembly. HTTP is experimental and TLS/HTTPS are unimplemented. The NE2000 implementation is a prototype and has incomplete DMA/interrupt error recovery. It should not be used for security-sensitive networking.

## Diagnostics

On v86 choose NE2K; press `D` once to start DHCP, `4` for network diagnostics, `R` to poll. `Loopback MAC` counts frames whose Ethernet source MAC matches this guest's address, rather than treating these frames as a DHCP offer.

## Auditing and reproducibility

Run `sh build.sh` and `python3 test_image.py`; verify the image boots and the NIC receives/sends packets in v86 separately. Build success alone does not prove network protocol correctness.
## GitHub Actions IMG download

The `Build bootable TextOS IMG` workflow runs on branch pushes, pull requests, and manual dispatch. Open the latest successful workflow run and download the `fasmlinks-textos-img` artifact ZIP; extract `textos.img` and load it as a floppy in copy.sh/v86. This artifact is an experimental build, not a verified DHCP lease implementation.
