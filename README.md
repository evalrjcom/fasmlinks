# FASM Links / TextOS 0.6.8 (experimental)

This is a 32-bit FASM bootable floppy prototype for the ne2k interface emulated by copy.sh/v86. It has a VGA text console, PCI discovery, NE2000 transmit/receive, ARP, and an incomplete DHCP/IPv4/TCP prototype.

## Building

Install FASM (1.73.35 known to compile this source) and run `sh build.sh` from this folder. `textos.img` is a 1.44 MB raw floppy disk image; select it as the floppy in https://copy.sh/v86/, using the **ne2k** network adapter.

## Changes in 0.6.6

* `ip.asm`: `; FIX` comments mark checks for truncated packets, IPv4 total length, UDP length, invalid headers, fragmentation, and checksum validation. Reject IPv4 options rather than parsing them as a fixed 20-byte header.
* `dhcp.asm`: `; FIX` comments mark DHCP source-MAC loopback rejection, BOOTP hardware-address validation, and DHCP receive checks; manual D-key retransmission is available in the latest repair, but a real retry/lease timer is still needed.
* `kernel.asm`: version and diagnostic text update; displays count of locally looped-back frames.

## Known limitations

Do **not** assume DHCP is fixed simply because the source assembles. Testing with the relay and WISP networking backends is still needed. DHCP acquisition and automatic retries are implemented in 0.6.7; lease renewal, rebinding and expiration are not yet implemented. RTC polling is approximate during VM suspension. TCP has no retransmission timers, checksum validation of received segments, robust sequence/window handling, or out-of-order reassembly. HTTP is experimental and TLS/HTTPS are unimplemented. The NE2000 implementation is a prototype and has incomplete DMA/interrupt error recovery. It should not be used for security-sensitive networking.

## Diagnostics

On v86 choose NE2K; DHCP starts automatically. Press `D` for a manual retry before BOUND, `4` for DHCP trace, `5` for IP/TCP details, `A` to retry gateway ARP, and `C` for the experimental HTTP TCP probe. `Loopback MAC` counts frames whose Ethernet source MAC matches this guest's address, rather than treating these frames as a DHCP offer.

## Auditing and reproducibility

Run `sh build.sh` and `python3 test_image.py`; verify the image boots and the NIC receives/sends packets in v86 separately. Build success alone does not prove network protocol correctness.
## GitHub Actions IMG download

The `Build bootable TextOS IMG` workflow runs on branch pushes, pull requests, and manual dispatch. Open the latest successful workflow run and download the `fasmlinks-textos-img` artifact ZIP; extract `textos.img` and load it as a floppy in copy.sh/v86. This artifact is an experimental build, not a verified DHCP lease implementation.

## 0.6.6 patch integration

The 0.6.6 kernel displays raw little-endian hexadecimal IPv4 values followed by dotted-decimal addresses for the last source IP, last destination IP, and configured local IP. The preceding DHCP repair is retained (manual `D` retries, DHCP client identifier, maximum-message-size option, NAK cleanup). This is not proof of DHCP success: automatic retry scheduling, lease renewal and live Relay/WISP verification remain open.

## 0.6.7

Preserves the 0.6.6 TX-memory repair. Adds automatic startup acquisition, RTC-driven retries capped at 32 seconds, per-exchange transaction IDs, staged DHCP options, selected-server ACK/NAK validation, and a separate IP/TCP diagnostics page. User testing of audited 0.6.6 showed two successful OFFER/REQUEST/ACK exchanges; 0.6.7 needs its own runtime test. TCP is experimental and HTTPS unimplemented.

## 0.6.8

User runtime test of 0.6.7 confirmed DHCP BOUND with gateway/DNS/subnet and a 900-second lease. Gateway ARP remained unresolved after a single attempt. This build retries unresolved gateway ARP every three RTC seconds, validates directed ARP requests/replies and source MAC consistency, and adds page 6 ARP diagnostics. Press A to retry and show ARP diagnostics; C shows IP/TCP status. No live verification of 0.6.8 yet. Lease renewal/expiry and full TCP remain outstanding.
