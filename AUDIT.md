# FASM Links source audit — 2026-11-23

## Scope

Repository `evalrjcom/fasmlinks` initially contained only `README.md` and no source code, workflows, issues, or PRs. This staged prototype baseline is sourced from the conversation's TextOS 0.6.4 source archive, which is distinct from the GitHub initial state.

### Applied corrections in the new 0.6.5 source

- **High — IP out-of-bounds/invalid parsing:** Check the Ethernet frame length, IPv4 total length and IPv4 header checksum before dispatching transport packets. Explicitly refuse IPv4 options, fragmentation, and UDP lengths extending beyond the IPv4 datagram.
- **Medium — DHCP receive ambiguity:** Separate self-originating MAC-looped-back UDP from genuine DHCP messages; validate BOOTP `chaddr` before accepting an OFFER or ACK.
- **Medium — DHCP repeated starts:** Suppress repeated manual DHCP DISCOVER while in SELECTING/REQUESTING to reduce packet floods. **Limitation:** a timer-based retry and lease scheduler must replace this guard.
- **Medium — reproducibility:** Add offline boot-sector/image consistency checks to the build package.

### Remaining issues requiring separate work

1. **High:** DHCP lease negotiation is unverified with Relay/WISP. Add packet fixtures, transaction-ID generation, DHCP client-ID, standardized retry/backoff and lease lifecycle (T1/T2).
2. **High:** The TCP prototype is incomplete and should not be used for real traffic without TCP checksum verification, timeout/retransmission, sequence/window validation and graceful teardown.
3. **High:** HTTP/TLS/PKI are not implemented. Certificate-verified HTTPS requires secure randomness, a tested TLS implementation and trust-store/hostname/path validation.
4. **Medium:** The NE2000 driver needs error/timeouts handling, protection against corrupted ring headers, and better DMA/interrupt status checking.
5. **Medium:** The kernel uses a fixed MAC, fixed DHCP transaction ID and hardcoded HTTP test target; make configuration explicit and test multi-instance collision.
6. **Medium:** Kernel boot loading assumes a maximum of 32 sectors and 1.44MB floppy geometry, which the build script tests but does not make extensible.
7. **Medium:** The VGA diagnostic screen can overflow 80x25 for larger outputs; add scrolling and clipping.

### Test evidence

- FASM 1.73.35 compiled `boot.bin` (512 bytes), `kernel.bin` (9,933 bytes) and generated 1,474,560-byte floppy image.
- No live v86 emulation, DHCP lease, reliable TCP, HTTP or HTTPS functionality has been verified for this patch.

## Efficiency and innovation suggestions

- Provide host-based packet-fixture tests for Ethernet/ARP/IPv4/UDP/DHCP, plus emulator smoke tests using QEMU (ne2k_pci) with serial logging.
- Split packet parsing from I/O operations, provide bounded ring buffers, trace counters, and deterministic fuzz cases for truncated/malformed packets.
- Add simple URL/search input, keyboard navigation and read-only text HTML rendering once HTTP works.
- Expose a compact packet-trace view and exportable diagnostics; eventually support a lightweight dual-stack IPv4/IPv6 environment.
## 0.8.1 focused audit (baseline b7dbaa9)

| Finding | Repair / status |
|---|---|
| TCP request loss | Bounded suffix retransmission, monotonic SND.UNA; no general TCP queue |
| DNS case-sensitive question | Canonical name compare, exact QTYPE/QCLASS |
| DNS on-link result | Reject unsupported gateway-only path |
| DNS TCP tuple replacement | Abort old established DNS connection before new tuple |
| DHCP unchecked nonzero UDP checksum | Verify pseudo-header checksum |
| Expired DHCP lease | Approximate RTC expiry and fresh acquisition; T1/T2 not implemented |
| Raw style/script closing tag | Correct minimum length and accept whitespace |
| Custom HTML tag prefix | Reject invalid tag delimiters for classification |
| Redirect header rescanning | Keep original matched cursor |
| VGA overflow / footer clearing | Bound print and preserve footer when clearing views |

Remaining: reliable general TCP including send window, congestion control, FIN and out-of-order handling; lease renewal/rebinding and reliable monotonic time; HTTP framing/chunking/compression; robust HTML parsing, links and forms; real TLS transport with CSPRNG, trust anchors, hostname/time validation; malformed-input tests for assembly routines. Current BearSSL self-test uses offline fixtures only. Build and QEMU smoke test required; v86 network regression is not covered by CI.
