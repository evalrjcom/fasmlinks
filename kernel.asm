format binary
use32
org 0x10000
start:
 cld ; FIX: keep LODS/STOS/MOVS direction explicit
 mov edi,0xb8000
 mov ecx,80*25
 mov ax,0x1f20
 rep stosw
 mov esi,header
 mov edi,0xb8000
 call print
 mov esi,menu
 mov edi,0xb8000+160*2
 call print
 call net_probe
 ; NEW: start DHCP automatically after NIC initialization.
 call dhcp_clock_init
 call dhcp_discover
 mov esi,footer
 mov edi,0xb8000+160*24
 call print
main:
 cmp byte [net_present],1
 jne .keyboard
 call ne_poll
 call dhcp_tick ; NEW: nonblocking RTC retry scheduler
.keyboard:
 in al,0x64
 test al,1
 jz main
 in al,0x60
 cmp al,0x02
 je home
 cmp al,0x03
 je sites
 cmp al,0x04
 je about
 cmp al,0x05
 je network
 cmp al,0x06
 je network_detail
 cmp al,0x07
 je arp_detail
 cmp al,0x14
 je tx_test
 cmp al,0x13
 je rx_test
 cmp al,0x1e
 je arp_test
 cmp al,0x2e
 je syn_test
 cmp al,0x20
 je dhcp_test
 jmp main
home:
 mov esi,home_text
 jmp show
sites:
 mov esi,sites_text
 jmp show
tx_test:
 cmp byte [net_present],1 ; FIX: never access absent/reset-failed NIC
 jne network
 call ne_send
 jmp diagnostics
rx_test:
 cmp byte [net_present],1
 jne diagnostics
 call ne_poll
 jmp diagnostics
arp_test:
 call arp_gateway
 jmp arp_detail
dhcp_test:
 call dhcp_discover
 jmp diagnostics
syn_test:
 call tcp_syn_probe
 jmp network_detail
network:
 jmp diagnostics
diagnostics:
 mov edi,0xb8000+160*4
 mov ecx,80*20 ; FIX: clear through last body row, preserve footer
 mov ax,0x1f20
 rep stosw
 mov edi,0xb8000+160*4
 mov esi,diag_title
 call print
 mov esi,[net_message]
 call print
 mov esi,dhcp_label_tx
 call print
 mov eax,[dhcp_discover_tx]
 call print_hex32
 mov esi,dhcp_label_ipseen
 call print
 mov eax,[ipv4_seen]
 call print_hex32
 mov esi,dhcp_label_udp
 call print
 mov eax,[dhcp_udp_seen]
 call print_hex32
 mov esi,diag_udp_src
 call print
 mov eax,[udp_last_src]
 call print_hex32
 mov esi,diag_udp_dst
 call print
 mov eax,[udp_last_dst]
 call print_hex32
 mov esi,diag_echo
 call print
 mov eax,[dhcp_own_frames]
 call print_hex32
 mov esi,diag_src_ip
 call print
 mov eax,[rx_last_src_ip]
 call print_hex32
 ; FIX 0.6.6: show dotted-decimal after raw little-endian hex
 mov eax,dword [rx_last_src_ip]
 call print_ipv4
 mov esi,diag_dst_ip
 call print
 mov eax,[rx_last_dst_ip]
 call print_hex32
 ; FIX 0.6.6: show dotted-decimal after raw little-endian hex
 mov eax,dword [rx_last_dst_ip]
 call print_ipv4
 mov esi,diag_port_match
 call print
 mov eax,[dhcp_port_match]
 call print_hex32
 mov esi,diag_wrong_xid
 call print
 mov eax,[dhcp_wrong_xid]
 call print_hex32
 mov esi,dhcp_label_offer
 call print
 mov eax,[dhcp_offer_rx]
 call print_hex32
 mov esi,dhcp_label_req
 call print
 mov eax,[dhcp_request_tx]
 call print_hex32
 mov esi,dhcp_label_ack
 call print
 mov eax,[dhcp_ack_rx]
 call print_hex32
 mov esi,dhcp_label_bad
 call print
 mov eax,[dhcp_rejected]
 call print_hex32
 mov esi,diag_dhcp
 call print
 movzx eax,byte [dhcp_state]
 call print_hex32
 mov esi,diag_local
 call print
 mov eax,dword [local_ip]
 call print_hex32
 ; FIX 0.6.6: show dotted-decimal after raw little-endian hex
 mov eax,dword [local_ip]
 call print_ipv4
 jmp main
network_detail:
 ; NEW: independent status page fits within the 80x25 screen.
 mov edi,0xb8000+160*4
 mov ecx,80*20
 mov ax,0x1f20
 rep stosw
 mov edi,0xb8000+160*4
 mov esi,detail_title
 call print
 mov esi,detail_state
 call print
 movzx eax,byte [dhcp_state]
 call print_hex32
 mov esi,detail_local
 call print
 mov eax,dword [local_ip]
 call print_ipv4
 mov esi,detail_mask
 call print
 mov eax,[dhcp_subnet]
 call print_ipv4
 mov esi,detail_gateway
 call print
 mov eax,dword [gateway_ip]
 call print_ipv4
 mov esi,detail_dns
 call print
 mov eax,[dhcp_dns_ip]
 call print_ipv4
 mov esi,detail_server
 call print
 mov eax,[dhcp_server_ip]
 call print_ipv4
 mov esi,detail_lease
 call print
 mov eax,[dhcp_lease_seconds]
 call print_hex32
 mov esi,detail_xid
 call print
 mov eax,[dhcp_xid]
 bswap eax
 call print_hex32
 mov esi,diag_gateway
 call print
 movzx eax,byte [gateway_known]
 call print_hex32
 mov esi,diag_arp_tx
 call print
 mov eax,[arp_tx_request]
 call print_hex32
 mov esi,diag_tcpstate
 call print
 movzx eax,byte [tcp_state]
 call print_hex32
 mov esi,diag_syn
 call print
 mov eax,[tcp_syn_sent]
 call print_hex32
 mov esi,diag_tcp
 call print
 mov eax,[tcp_packets]
 call print_hex32
 mov esi,diag_http
 call print
 mov eax,[http_bytes]
 call print_hex32
 mov esi,detail_txerr
 call print
 mov eax,[net_tx_errors]
 call print_hex32
 mov esi,diag_err
 call print
 mov eax,[net_rx_errors]
 call print_hex32
 jmp main
arp_detail:
 mov edi,0xb8000+160*4
 mov ecx,80*20
 mov ax,0x1f20
 rep stosw
 mov edi,0xb8000+160*4
 mov esi,arp_detail_title
 call print
 mov esi,arp_detail_local
 call print
 mov eax,dword [local_ip]
 call print_ipv4
 mov esi,arp_detail_gateway
 call print
 mov eax,dword [gateway_ip]
 call print_ipv4
 mov esi,diag_gateway
 call print
 movzx eax,byte [gateway_known]
 call print_hex32
 mov esi,diag_arp_tx
 call print
 mov eax,[arp_tx_request]
 call print_hex32
 mov esi,arp_detail_seen
 call print
 mov eax,[arp_frames_seen]
 call print_hex32
 mov esi,diag_arp_req
 call print
 mov eax,[arp_rx_request]
 call print_hex32
 mov esi,diag_arp_rep
 call print
 mov eax,[arp_rx_reply]
 call print_hex32
 mov esi,arp_detail_gwseen
 call print
 mov eax,[arp_gateway_seen]
 call print_hex32
 mov esi,arp_detail_reject
 call print
 mov eax,[arp_gateway_rejected]
 call print_hex32
 mov esi,arp_detail_learned
 call print
 mov eax,[arp_gateway_learned]
 call print_hex32
 mov esi,arp_detail_sender
 call print
 mov eax,[arp_last_sender]
 call print_ipv4
 mov esi,arp_detail_target
 call print
 mov eax,[arp_last_target]
 call print_ipv4
 mov esi,arp_detail_op
 call print
 mov eax,[arp_last_opcode]
 call print_hex32
 mov esi,arp_detail_mac
 call print
 mov esi,net_mac
 call print_mac
 mov esi,diag_gateway_mac
 call print
 mov esi,gateway_mac
 call print_mac
 jmp main

; NEW: six MAC octets, preserving the VGA destination cursor.
print_mac:
 push eax
 push ecx
 push esi
 mov ecx,6
.next:
 movzx eax,byte [esi]
 inc esi
 call print_hex8
 dec ecx
 jz .done
 mov ax,01f3ah
 stosw
 jmp .next
.done:
 pop esi
 pop ecx
 pop eax
 ret

; FIX 0.6.6: raw DWORD has octets in memory order (low byte first).
; Display a space and four decimal octets. EDI points at VGA text memory.
print_ipv4:
 pushad
 mov ebx,eax
 mov ax,01f20h
 stosw
 mov ecx,4
.next:
 movzx eax,bl
 call print_dec_octet
 shr ebx,8
 dec ecx
 jz .done
 mov ax,01f2eh
 stosw
 jmp .next
.done:
 popad
 ret

; FIX: print decimal octet 0..255 without leading zeroes.
print_dec_octet:
 push ebx
 push ecx
 push edx
 xor edx,edx
 mov ecx,100
 div ecx
 mov ebx,eax
 mov eax,edx
 xor edx,edx
 mov ecx,10
 div ecx
 push edx
 push eax
 test ebx,ebx
 jz .tens
 mov al,bl
 add al,'0'
 mov ah,01fh
 stosw
.tens:
 pop eax
 test ebx,ebx
 jnz .write_tens
 test eax,eax
 jz .units
.write_tens:
 add al,'0'
 mov ah,01fh
 stosw
.units:
 pop eax
 add al,'0'
 mov ah,01fh
 stosw
 pop edx
 pop ecx
 pop ebx
 ret
print_hex8:
 push ecx
 mov ecx,2
 shl eax,24
 jmp print_hex_common
print_hex32:
 push ecx
 mov ecx,8
print_hex_common:
 push ebx
 mov ebx,eax
.hex:
 rol ebx,4
 mov al,bl
 and al,15
 cmp al,9
 jbe .digit
 add al,7
.digit:
 add al,48
 mov ah,0x1f
 stosw
 loop .hex
 pop ebx
 pop ecx
 ret
about:
 mov esi,about_text
show:
 mov edi,0xb8000+160*4
 mov ecx,80*20 ; FIX: clear through last body row, preserve footer
 mov ax,0x1f20
 rep stosw
 mov edi,0xb8000+160*4
 call print
 jmp main
; 0x0a starts a new VGA row
print:
 mov ah,0x1f
.next:
 lodsb
 test al,al
 jz .done
 cmp al,10
 jne .char
 mov eax,edi
 sub eax,0xb8000
 xor edx,edx
 mov ecx,160
 div ecx
 inc eax
 imul eax,160
 lea edi,[eax+0xb8000]
 mov ah,0x1f
 jmp .next
.char:
 stosw
 jmp .next
.done:
 ret
header db 'FASM TEXTOS 0.6.8 |  32-bit protected mode',0
menu db '[1] Home [2] Sites [3] About [4] DHCP trace [5] IP/TCP [6] ARP',0
footer db '1 Home 2 Sites 3 About 4 Trace 5 IP/TCP 6 ARP D DHCP A ARP C TCP T TX R RX',0
arp_detail_title db 'Gateway ARP diagnostics (6 refresh, A retry)',0
arp_detail_local db 10,'Local IP: ',0
arp_detail_gateway db 10,'Gateway IP: ',0
arp_detail_seen db 10,'ARP frames seen: 0x',0
arp_detail_gwseen db 10,'Gateway sender seen: 0x',0
arp_detail_reject db 10,'Gateway rejected: 0x',0
arp_detail_learned db 10,'Gateway learned: 0x',0
arp_detail_sender db 10,'Last ARP sender IP: ',0
arp_detail_target db 10,'Last ARP target IP: ',0
arp_detail_op db 10,'Last ARP opcode: 0x',0
arp_detail_mac db 10,'Local MAC: ',0
detail_title db 'IP configuration / TCP diagnostics (press 5 to refresh)',0
detail_state db 10,'DHCP state (3=BOUND): 0x',0
detail_local db 10,'Local IP: ',0
detail_mask db 10,'Subnet: ',0
detail_gateway db 10,'Gateway: ',0
detail_dns db 10,'DNS: ',0
detail_server db 10,'DHCP server: ',0
detail_lease db 10,'Lease seconds (hex): 0x',0
detail_xid db 10,'Transaction ID: 0x',0
detail_txerr db 10,'TX errors: 0x',0
diag_title db 'NE2000 PCI diagnostics',10,0
diag_tx db 10,'TX attempted: 0x',0
diag_rx db 10,'RX frames:    0x',0
diag_err db 10,'RX errors:    0x',0
diag_curr db 10,'CURR:         0x',0
diag_bnry db 10,'RX page:      0x',0
diag_status db 10,'Last status:  0x',0
diag_length db 10,'Last length:  0x',0
diag_type db 10,'EtherType:    0x',0
diag_arp_tx db 10,'ARP TX req:    0x',0
diag_arp_rx db 10,'ARP RX total:  0x',0
diag_arp_req db 10,'ARP RX req:    0x',0
diag_arp_rep db 10,'ARP RX reply:  0x',0
diag_gateway db 10,'Gateway known: 0x',0
diag_gateway_mac db 10,'Gateway MAC:   ',0
diag_ip db 10,'IPv4 packets: 0x',0
diag_icmp db 10,'ICMP replies: 0x',0
diag_udp_src db 10,'UDP source port: 0x',0
diag_udp_dst db 10,'UDP dest port:   0x',0
diag_port_match db 10,'DHCP port match: 0x',0
diag_echo db 10,'Loopback MAC:  0x',0
diag_src_ip db 10,'Last source IP:0x',0
diag_dst_ip db 10,'Last dest IP:  0x',0
diag_wrong_xid db 10,'DHCP wrong XID:  0x',0
dhcp_label_tx db 10,'DISCOVER TX:   0x',0
dhcp_label_ipseen db 10,'IPv4 seen:     0x',0
dhcp_label_udp db 10,'UDP handler:   0x',0
dhcp_label_offer db 10,'OFFER RX:      0x',0
dhcp_label_req db 10,'REQUEST TX:    0x',0
dhcp_label_ack db 10,'ACK RX:        0x',0
dhcp_label_nak db 10,'NAK RX:        0x',0
dhcp_label_bad db 10,'DHCP rejected: 0x',0
dhcp_label_router db 10,'Gateway IP:    0x',0
dhcp_label_dns db 10,'DNS IP:        0x',0
diag_dhcp db 10,'DHCP state:    0x',0
diag_local db 10,'Local IP raw:  0x',0
diag_tcpstate db 10,'TCP state:     0x',0
diag_http db 10,'HTTP bytes:    0x',0
diag_syn db 10,'TCP SYN sent: 0x',0
diag_tcp db 10,'TCP RX:       0x',0
tx_text db 'Diagnostic Ethernet frame queued for transmission.',0
rx_text db 'Receive ring polled. Counters are internal (no HTTP yet).',0
home_text db 'HOME  |  DuckDuckGo search',10,10,'https://lite.duckduckgo.com/lite/',10,10,'Search is not connected yet.',0
sites_text db 'TEXT-FRIENDLY WEBSITES',10,10,'https://lite.duckduckgo.com/lite/',10,'https://www.wikipedia.org/',10,'https://www.gutenberg.org/',10,'https://text.npr.org/',10,'https://info.cern.ch/',10,'https://example.com/',0
about_text db 'FASM TextOS 0.6.8 - RX validation and DHCP trace',10,10,'No DNS, TLS, or reliable general-purpose TCP yet.',0

include 'net.asm'
include 'ip.asm'
include 'dhcp.asm'