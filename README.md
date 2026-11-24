# FASM Links / TextOS 0.7.8 (experimental)

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

## 0.6.9

User test of 0.6.8 showed 30 ARP requests, zero replies, and 22 gateway-originated ARP frames rejected. Allow learning the configured gateway's mapping from broadcast requests for other IP addresses while retaining source MAC consistency, unicast sender validation, and directed reply validation. Do not replace an established mapping silently. Page 6 shows the opcode used to learn the gateway. ARP is not authenticated; this does not establish gateway identity against a malicious LAN peer. Runtime verification of 0.6.9 is pending.

## 0.7.0

Preserves tested DHCP and gateway ARP. Experimental TCP probe gains checksum and tuple validation, variable initial sequence, bounded SYN retries and idle timeout, cumulative ACKs, and 4096-byte raw HTTP capture in scratch RAM. Press C to connect to the existing 1.1.1.1:80 target, 5 for status, 7 for response preview. TCP state 4=reset, 5=timeout. No complete TCP retransmission/close state machine, DNS, HTML renderer, TLS or DHCP renewal yet. Runtime verification pending.

## 0.7.1

User verified a real Cloudflare HTTP 301 response in 0.7.0. This version retains C for that probe, adds 8 for a DNS A lookup of info.cern.ch followed by HTTP, 9 for basic body text preview, N/P for raw response page navigation, 64 KiB capture, and a fresh ephemeral TCP port per connection. DNS supports a direct first A answer only, not CNAME or general resolution. Plain HTTP only, no arbitrary URL input, TLS, redirect following or complete HTML parser. Runtime testing pending.

## 0.7.2

DNS UDP checksum generation and verification, bounded retries, fallback to 1.1.1.1 after two DHCP resolver attempts, and detailed rejection counters. Press 8 to start and G to refresh without restarting. Direct first A answer only; CNAME and arbitrary URLs still pending. Runtime verification pending.

### 0.7.2 loader capacity fix

The kernel exceeds the previous 32-sector limit. The bootloader, build script and image tests now share `kernel_layout.inc`: 128 sectors (64 KiB) at physical 0x10000 through 0x1FFFF, below the HTTP buffer at 0x20000. Single-sector CHS reads avoid track crossing; the final offset is 0xFE00. Runtime boot testing remains required.

## 0.7.3

Adds DNS transmit-submission counts, pre-IP-filter UDP port 53 counts and an experimental DNS-over-TCP fallback to 1.1.1.1:53 after four UDP attempts. Uses a bounded 4096-byte scratch buffer at 0x30000 and the existing single TCP connection. Direct first A answer only; full TCP close/retransmission, CNAME, interactive URL input and TLS remain incomplete. Press 8 to start, G to refresh; DNS state 4 means TCP fallback. C retains the known HTTP regression probe. Runtime verification pending.

## 0.7.4

Fix HTTP regression: preserve captured HTTP during DNS TCP fallback; C cancels pending DNS and restarts the known Cloudflare HTTP probe. Guard DNS fallback against replacing active TCP tuples. Show an explicit empty response message in both viewers. Runtime verification pending.

## 0.7.5

F2 opens a bounded interactive IPv4/path editor for remote HTTP port 80. Enter submits, Backspace edits, Esc cancels. Existing C regression probe and 8 DNS experiment remain. Numeric IPv4 only, no on-link host ARP, arbitrary hostname entry, HTTPS or full URL syntax yet. Runtime verification pending.

## 0.7.6

F2 accepts lowercase hostname/path or numeric IPv4/path with optional http:// (Shift+semicolon for colon). Builds a validated dynamic DNS question and retains the entered Host and path through UDP/TCP fallback. F5 shows the HTTP status and Location header without auto-following. Direct A answers only; DNS transport still unverified, CNAME, full HTML layout, links, DHCP renewal and TLS pending. Runtime verification pending.

## 0.7.7

Adds bounded DNS compression decoding and owner-matched CNAME chains within a single answer message (eight hops maximum), plus a CNAME diagnostic count. Text preview adds simple block breaks and amp/lt/gt decoding. DNS transport remains unverified; aliases requiring a separate query, full HTML parsing, automatic redirects, TLS and DHCP renewal remain pending. Existing C HTTP regression probe retained.

## 0.7.8

Separate bounded assembly text renderer suppresses style/script content and comments, honors quoted tag attributes, wraps words, adds block/title breaks, and supports PgUp/PgDn text pagination. Raw HTTP and DNS remain unchanged apart from resetting text pagination when a new HTTP connection starts. Limited ASCII HTML preview, not a standards-complete parser; links, history, automatic redirects, TLS and lease renewal remain pending.
