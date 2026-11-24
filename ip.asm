; TextOS 0.5: Ethernet/ARP/IPv4/ICMP, TCP SYN probe (static addressing).
; IPv4 configured as 10.0.2.15/24, gateway 10.0.2.2 for test networks.
; No DHCP, DNS, retransmission, TLS, or general-purpose TCP stack yet.

ip_receive:
 cmp word [net_rx_length],18 ; FIX: Ethernet header before EtherType
 jb .short
 mov esi,net_rx_buffer
 mov ax,[esi+12]
 cmp ax,0x0608
 je arp_receive
 cmp ax,0x0008
 je ipv4_receive
.short:
 ret

arp_receive:
 ; FIX: validate full Ethernet/ARP header before learning or replying.
 cmp word [net_rx_length],46
 jb .end
 cmp word [net_rx_buffer+14],0100h
 jne .end
 cmp word [net_rx_buffer+16],0008h
 jne .end
 cmp word [net_rx_buffer+18],0406h
 jne .end
 cmp dword [local_ip],0
 je .end
 inc dword [arp_rx_total]
 cmp word [net_rx_buffer+20],0x0100
 jne .not_request
 inc dword [arp_rx_request]
.not_request:
 cmp word [net_rx_buffer+20],0x0200
 jne .not_reply
 inc dword [arp_rx_reply]
.not_reply:
 call arp_learn
 mov esi,net_rx_buffer
 cmp word [esi+14],0x0100  ; hardware Ethernet
 jne .end
 cmp word [esi+16],0x0008  ; IPv4
 jne .end
 cmp byte [esi+18],6
 jne .end
 cmp byte [esi+19],4
 jne .end
 cmp word [esi+20],0x0100  ; request
 jne .end
 mov eax,[esi+38]
 cmp eax,dword [local_ip]
 jne .end
 inc dword [arp_requests]
 mov esi,net_rx_buffer
 lea esi,[esi+22]
 mov edi,tx_frame
 mov ecx,6
 rep movsb
 mov esi,net_mac
 mov ecx,6
 rep movsb
 mov word [tx_frame+12],0x0608
 mov word [tx_frame+14],0x0100
 mov word [tx_frame+16],0x0008
 mov word [tx_frame+18],0x0406
 mov word [tx_frame+20],0x0200
 mov esi,net_mac
 mov edi,tx_frame+22
 mov ecx,6
 rep movsb
 mov eax,dword [local_ip]
 mov [tx_frame+28],eax
 mov esi,net_rx_buffer+22
 mov edi,tx_frame+32
 mov ecx,6
 rep movsb
 mov eax,dword [net_rx_buffer+28]
 mov [tx_frame+38],eax
 mov esi,tx_frame
 mov ecx,42 ; FIX: sender zero-pads Ethernet minimum length
 call ne_send_buffer
.end:
 ret

ipv4_receive:
 ; FIX: The old path trusted a packet's IPv4 header before checking RX bounds.
 ; NE2000 receive length includes its 4-byte ring header, and can include
 ; a 4-byte Ethernet FCS. A frame must hold Ethernet + a 20-byte IPv4 header.
 movzx ecx,word [net_rx_length]
 cmp ecx,38
 jb .short
 sub ecx,4
 cmp ecx,1518
 ja .short
 mov esi,net_rx_buffer
 cmp byte [esi+14],045h   ; FIX: intentionally reject IP options (IHL != 5)
 jne .invalid
 movzx edx,word [esi+16]
 xchg dl,dh                 ; network-order IPv4 total length
 cmp edx,20
 jb .invalid
 lea eax,[edx+14]
 cmp eax,ecx
 ja .short
 ; FIX: Convert network-order fragmentation flags before testing offset/MF.
 mov ax,[esi+20]
 xchg al,ah
 test ax,03fffh
 jnz .invalid
 ; FIX: Require a valid IPv4 header checksum before parsing transport data.
 push ecx
 push edx
 mov ecx,20
 lea esi,[net_rx_buffer+14]
 call checksum
 pop edx
 pop ecx
 test ax,ax
 jnz .bad_checksum
 inc dword [ipv4_seen]
 mov eax,dword [net_rx_buffer+26]
 mov [rx_last_src_ip],eax
 mov eax,dword [net_rx_buffer+30]
 mov [rx_last_dst_ip],eax
 cmp eax,dword [local_ip]
 je .dest_ok
 cmp eax,0ffffffffh
 je .dest_ok
 ; FIX: DHCP can be unicast to the offered address before configuration,
 ; but only UDP is forwarded while SELECTING/REQUESTING.
 cmp byte [dhcp_state],1
 je .unbound
 cmp byte [dhcp_state],2
 jne .done
.unbound:
 cmp byte [net_rx_buffer+23],17
 jne .done
.dest_ok:
 inc dword [ip_packets]
 cmp byte [net_rx_buffer+23],1
 je icmp_receive
 cmp byte [net_rx_buffer+23],6
 je tcp_receive
 cmp byte [net_rx_buffer+23],17
 jne .done
 ; FIX: Ensure UDP header and datagram are contained within IPv4 total length.
 cmp edx,28
 jb .invalid
 movzx eax,word [net_rx_buffer+38]
 xchg al,ah
 cmp eax,8
 jb .invalid
 lea eax,[eax+20]
 cmp eax,edx
 ja .invalid
 jmp udp_receive
.short:
 inc dword [ip_truncated]
 ret
.bad_checksum:
 inc dword [ip_checksum_bad]
 ret
.invalid:
 inc dword [ip_malformed]
.done:
 ret

icmp_receive:
 cmp edx,28 ; FIX: before reading ICMP type/code
 jb .end
 cmp dword [local_ip],0
 je .end
 mov eax,dword [net_rx_buffer+30]
 cmp eax,dword [local_ip] ; no broadcast echo responses
 jne .end
 mov esi,net_rx_buffer
 cmp byte [esi+34],8
 jne .end
 cmp byte [esi+35],0
 jne .end
 movzx ecx,word [esi+16]
 xchg cl,ch
 cmp ecx,28
 jb .end
 cmp ecx,1480
 ja .end
 mov [ip_len],cx
 ; Copy Ethernet and IP packet (no options supported).
 lea esi,[net_rx_buffer]
 lea edi,[tx_frame]
 add ecx,14
 rep movsb
 mov esi,net_rx_buffer+6
 mov edi,tx_frame
 mov ecx,6
 rep movsb
 mov esi,net_mac
 mov ecx,6
 rep movsb
 mov eax,[tx_frame+26]
 xchg eax,[tx_frame+30]
 mov [tx_frame+26],eax
 mov byte [tx_frame+34],0
 mov word [tx_frame+36],0
 movzx ecx,word [ip_len]
 sub ecx,20
 mov esi,tx_frame+34
 call checksum
 mov [tx_frame+36],ax
 mov word [tx_frame+24],0
 mov ecx,20
 mov esi,tx_frame+14
 call checksum
 mov [tx_frame+24],ax
 movzx ecx,word [ip_len]
 add ecx,14
 mov esi,tx_frame
 call ne_send_buffer
 inc dword [icmp_replies]
.end:
 ret

; One's-complement checksum: ESI bytes, ECX length; return AX ready to store.
checksum:
 push ebx
 push edx
 xor edx,edx
.next:
 cmp ecx,2
 jb .odd
 movzx ebx,word [esi]
 rol bx,8
 add edx,ebx
 add esi,2
 sub ecx,2
 jmp .next
.odd:
 test ecx,ecx
 jz .fold
 movzx ebx,byte [esi]
 shl ebx,8
 add edx,ebx
.fold:
 mov eax,edx
 shr eax,16
 and edx,0xffff
 add eax,edx
 mov edx,eax
 shr edx,16
 add ax,dx
 not ax
 xchg al,ah
 pop edx
 pop ebx
 ret

tcp_receive:
 ; FIX: reject short TCP headers and traffic not addressed to our IP.
 cmp edx,40
 jb .end
 movzx eax,byte [net_rx_buffer+46]
 shr eax,4
 cmp eax,5
 jb .end
 shl eax,2
 add eax,20
 cmp eax,edx
 ja .end
 mov eax,dword [net_rx_buffer+30]
 cmp eax,dword [local_ip]
 jne .end
 inc dword [tcp_packets]
 mov al,[net_rx_buffer+47]
 mov [tcp_last_flags],al
 cmp byte [tcp_state],0
 je .end
 ; accept only remote port 80 -> local port 12345
 cmp word [net_rx_buffer+34],0x5000
 jne .end
 cmp word [net_rx_buffer+36],0x3930
 jne .end
 mov eax,dword [net_rx_buffer+26]
 cmp eax,dword [remote_ip]
 jne .end
 test byte [net_rx_buffer+47],4
 jz .not_rst
 mov byte [tcp_state],0
 jmp .end
.not_rst:
 cmp byte [tcp_state],1
 jne .established
 ; SYN+ACK expected, ACK must match initial seq+1
 mov al,[net_rx_buffer+47]
 and al,0x12
 cmp al,0x12
 jne .end
 cmp dword [net_rx_buffer+42],0x02000000
 jne .end
 mov eax,dword [net_rx_buffer+38]
 bswap eax
 inc eax
 mov [tcp_ack_num],eax
 mov dword [tcp_seq_num],2
 mov byte [tcp_state],2
 mov byte [tcp_flags],0x10
 xor ecx,ecx ; FIX: ACK-only segment has no payload
 call tcp_send_segment
 ; send GET after ACK
 mov byte [tcp_flags],0x18
 mov esi,http_get_request
 mov ecx,http_get_end-http_get_request
 call tcp_send_segment
 add dword [tcp_seq_num],http_get_end-http_get_request
 jmp .end
.established:
 cmp byte [tcp_state],2
 jne .end
 ; data length = IPv4 total - 20 IP - TCP header length
 movzx ecx,word [net_rx_buffer+16]
 xchg cl,ch
 sub ecx,20
 jc .end
 movzx edx,byte [net_rx_buffer+46]
 shr edx,4
 shl edx,2
 cmp edx,20
 jb .end
 sub ecx,edx
 jc .end
 cmp ecx,0
 je .check_fin
 ; only accept in-order data
 mov eax,dword [net_rx_buffer+38]
 bswap eax
 cmp eax,[tcp_ack_num]
 jne .end
 add dword [tcp_ack_num],ecx
 add dword [http_bytes],ecx
 mov byte [tcp_flags],0x10
 xor ecx,ecx ; FIX: ACK-only segment has no payload
 call tcp_send_segment
.check_fin:
 test byte [net_rx_buffer+47],1
 jz .end
 inc dword [tcp_ack_num]
 mov byte [tcp_flags],0x10
 xor ecx,ecx ; FIX: ACK-only segment has no payload
 call tcp_send_segment
 mov byte [tcp_state],3
.end:
 ret

; Send ARP request for gateway IP, if configured.
arp_gateway:
 cmp byte [net_present],1
 jne .end
 cmp dword [local_ip],0
 je .end
 cmp dword [gateway_ip],0
 je .end
 mov edi,tx_frame
 mov ecx,6
 mov al,0xff
 rep stosb
 mov esi,net_mac
 mov ecx,6
 rep movsb
 mov word [tx_frame+12],0x0608
 mov word [tx_frame+14],0x0100
 mov word [tx_frame+16],0x0008
 mov word [tx_frame+18],0x0406
 mov word [tx_frame+20],0x0100
 mov esi,net_mac
 mov ecx,6
 rep movsb
 mov eax,dword [local_ip]
 mov [tx_frame+28],eax
 mov dword [tx_frame+32],0
 mov word [tx_frame+36],0
 mov eax,dword [gateway_ip]
 mov [tx_frame+38],eax
 mov esi,tx_frame
 mov ecx,42 ; FIX: sender pads safely
 call ne_send_buffer
 inc dword [arp_tx_request]
.end:
 ret

; Capture gateway ARP replies.
; Called from receive routine for ARP frames before normal request processing.
arp_learn:
 cmp word [net_rx_buffer+20],0x0200
 jne .end
 mov eax,dword [net_rx_buffer+28]
 cmp eax,dword [gateway_ip]
 jne .end
 mov eax,dword [net_rx_buffer+38]
 cmp eax,dword [local_ip] ; FIX: gateway reply must target our address
 jne .end
 mov esi,net_rx_buffer+22
 mov edi,gateway_mac
 mov ecx,6
 rep movsb
 mov byte [gateway_known],1
 inc dword [arp_gateway_learned]
.end:
 ret

tcp_syn_probe:
 cmp byte [gateway_known],1
 jne .end
 cmp byte [dhcp_state],3
 jne .end
 mov byte [tcp_state],1
 mov dword [tcp_seq_num],1
 mov dword [tcp_ack_num],0
 mov byte [tcp_flags],2
 xor ecx,ecx
 call tcp_send_segment
 inc dword [tcp_syn_sent]
.end:
 ret

; TCP sender: flags tcp_flags; optional payload ESI, length ECX.
; No retransmission or out-of-order reassembly in this prototype.
tcp_send_segment:
 pushad
 cmp ecx,1460 ; FIX: bounded TCP payload for 1500-byte MTU
 ja .abort
 mov [tcp_payload_len],cx
 mov edi,tx_frame
 mov esi,gateway_mac
 mov ecx,6
 rep movsb
 mov esi,net_mac
 mov ecx,6
 rep movsb
 mov word [tx_frame+12],0x0008
 mov edi,tx_frame+14
 mov ecx,40
 xor eax,eax
 rep stosb
 mov byte [tx_frame+14],0x45
 mov byte [tx_frame+22],64
 mov byte [tx_frame+23],6
 mov eax,dword [local_ip]
 mov [tx_frame+26],eax
 mov eax,dword [remote_ip]
 mov [tx_frame+30],eax
 mov word [tx_frame+34],0x3930
 mov word [tx_frame+36],0x5000
 mov eax,[tcp_seq_num]
 bswap eax
 mov [tx_frame+38],eax
 mov eax,[tcp_ack_num]
 bswap eax
 mov [tx_frame+42],eax
 mov byte [tx_frame+46],0x50
 mov al,[tcp_flags]
 mov [tx_frame+47],al
 mov word [tx_frame+48],0x0040
 ; optional payload pointer was saved in PUSHAD, ESI at ESP+4
 movzx ecx,word [tcp_payload_len]
 test ecx,ecx
 jz .payload_done
 mov esi,[esp+4]
 mov edi,tx_frame+54
 rep movsb
.payload_done:
 movzx eax,word [tcp_payload_len]
 add eax,40
 mov [tcp_ip_len],ax
 xchg al,ah
 mov [tx_frame+16],ax
 mov esi,tx_frame+14
 mov ecx,20
 call checksum
 mov [tx_frame+24],ax
 mov esi,tx_frame+26
 mov ecx,8
 call sum_words
 mov edx,eax
 add edx,6
 movzx eax,word [tcp_payload_len]
 add eax,20
 add edx,eax
 mov esi,tx_frame+34
 mov ecx,20
 add ecx,eax
 sub ecx,20
 ; sum_words only supports even lengths (HTTP GET length padded if odd)
 test ecx,1
 jz .even
 mov byte [esi+ecx],0 ; FIX: pad checksum at actual segment end
 inc ecx
.even:
 call sum_words
 add edx,eax
 mov eax,edx
 shr eax,16
 and edx,0xffff
 add eax,edx
 mov edx,eax
 shr edx,16
 add ax,dx
 not ax
 xchg al,ah
 mov [tx_frame+50],ax
 movzx ecx,word [tcp_ip_len]
 add ecx,14
 mov esi,tx_frame
 call ne_send_buffer
.abort:
 popad
 ret

http_get_request db 'GET / HTTP/1.0',13,10,'Host: one.one.one.one',13,10,'Connection: close',13,10,13,10
http_get_end:
tcp_state db 0
tcp_flags db 0
tcp_seq_num dd 0
tcp_ack_num dd 0
tcp_payload_len dw 0
tcp_ip_len dw 0
http_bytes dd 0

sum_words:
 push ebx
 xor eax,eax
.loop:
 movzx ebx,word [esi]
 rol bx,8
 add eax,ebx
 add esi,2
 sub ecx,2
 jnz .loop
 pop ebx
 ret

local_ip db 0,0,0,0 ; FIX: unconfigured until DHCP ACK
gateway_ip db 0,0,0,0
remote_ip db 1,1,1,1
gateway_mac rb 6
gateway_known db 0
arp_requests dd 0
arp_tx_request dd 0
arp_rx_total dd 0
arp_rx_request dd 0
arp_rx_reply dd 0
arp_gateway_learned dd 0
ipv4_seen dd 0
ip_packets dd 0
icmp_replies dd 0
tcp_packets dd 0
tcp_syn_sent dd 0
tcp_last_flags db 0
ip_len dw 0
tx_frame: rb 1516

rx_last_src_ip dd 0
rx_last_dst_ip dd 0

; FIX: Independent counters distinguish bad frames from missing DHCP replies.
ip_truncated dd 0
ip_malformed dd 0
ip_checksum_bad dd 0