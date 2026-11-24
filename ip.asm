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
 inc dword [arp_frames_seen] ; NEW: includes rejected ARP frames
 ; FIX: validate full Ethernet/ARP header before learning or replying.
 cmp word [net_rx_length],46
 jb .end
 cmp word [net_rx_buffer+14],0100h
 jne .end
 cmp word [net_rx_buffer+16],0008h
 jne .end
 cmp word [net_rx_buffer+18],0406h
 jne .end
 mov eax,dword [net_rx_buffer+28]
 mov [arp_last_sender],eax
 mov eax,dword [net_rx_buffer+38]
 mov [arp_last_target],eax
 movzx eax,word [net_rx_buffer+20]
 xchg al,ah
 mov [arp_last_opcode],eax
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
 ; Count plausible DNS UDP frames before IPv4 checksum/destination filtering.
 cmp ecx,42
 jb .pre_dns_done
 cmp byte [esi+14],45h
 jne .pre_dns_done
 cmp byte [esi+23],17
 jne .pre_dns_done
 cmp word [esi+34],3500h
 jne .pre_dns_done
 inc dword [dns_wire_seen]
.pre_dns_done:
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
 cmp word [net_rx_buffer+34],3500h
 jne .dhcp_udp
 jmp dns_receive
.dhcp_udp:
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
 ; 0.7.0: validate tuple, header and pseudo-header checksum first.
 cmp edx,40
 jb .end
 cmp byte [tcp_state],1
 jb .end
 cmp byte [tcp_state],2
 ja .end
 mov eax,dword [net_rx_buffer+30]
 cmp eax,dword [local_ip]
 jne .end
 mov eax,dword [net_rx_buffer+26]
 cmp eax,dword [remote_ip]
 jne .end
 mov ax,[tcp_remote_port]
 cmp word [net_rx_buffer+34],ax
 jne .end
 mov ax,[tcp_local_port]
 cmp word [net_rx_buffer+36],ax
 jne .end
 movzx eax,byte [net_rx_buffer+46]
 shr eax,4
 cmp eax,5
 jb .end
 shl eax,2
 mov [tcp_rx_header],eax
 add eax,20
 cmp eax,edx
 ja .end
 sub edx,20
 mov [tcp_rx_length],edx
 mov esi,net_rx_buffer+26
 mov ecx,8
 call sum_words
 mov edx,eax
 add edx,6
 add edx,[tcp_rx_length]
 mov esi,net_rx_buffer+34
 mov ecx,[tcp_rx_length]
 call sum_words
 add eax,edx
 mov edx,eax
 shr eax,16
 and edx,0ffffh
 add eax,edx
 mov edx,eax
 shr edx,16
 add ax,dx
 cmp ax,0ffffh
 jne .bad_checksum
 inc dword [tcp_packets]
 mov al,[net_rx_buffer+47]
 mov [tcp_last_flags],al
 cmp byte [tcp_state],1
 jne .established
 ; SYN-ACK or RST must acknowledge our actual initial sequence.
 mov eax,dword [net_rx_buffer+42]
 bswap eax
 mov edx,[tcp_seq_num]
 inc edx
 cmp eax,edx
 jne .end
 test byte [net_rx_buffer+47],4
 jnz .reset
 mov al,[net_rx_buffer+47]
 and al,13h
 cmp al,12h
 jne .end
 mov eax,dword [net_rx_buffer+38]
 bswap eax
 inc eax
 mov [tcp_ack_num],eax
 inc dword [tcp_seq_num]
 mov eax,[tcp_seq_num]
 mov [tcp_request_seq],eax
 mov [tcp_snd_una],eax
 mov byte [tcp_data_retries],0
 mov byte [tcp_data_elapsed],0
 mov byte [tcp_state],2
 mov byte [tcp_elapsed],0
 mov byte [tcp_flags],10h
 xor ecx,ecx
 call tcp_send_segment
 mov byte [tcp_flags],18h
 mov esi,[http_request_ptr]
 mov ecx,[http_request_len]
 call tcp_send_segment
 mov eax,[http_request_len]
 add [tcp_seq_num],eax
 jmp .end
.established:
 mov eax,dword [net_rx_buffer+38]
 bswap eax
 cmp eax,[tcp_ack_num]
 jne .duplicate
 test byte [net_rx_buffer+47],4
 jnz .reset
 test byte [net_rx_buffer+47],10h
 jz .end
 ; FIX: reject unexpected SYN and ACK beyond SND.NXT; old ACKs cannot rewind SND.UNA.
 test byte [net_rx_buffer+47],2
 jnz .end
 mov eax,dword [net_rx_buffer+42]
 bswap eax
 mov edx,eax
 sub edx,[tcp_seq_num]
 jg .end
 mov edx,eax
 sub edx,[tcp_snd_una]
 jle .ack_unchanged
 mov [tcp_snd_una],eax
 mov byte [tcp_data_elapsed],0
 mov byte [tcp_data_retries],0
.ack_unchanged:
 mov byte [tcp_elapsed],0
 mov ecx,[tcp_rx_length]
 sub ecx,[tcp_rx_header]
 mov ebx,ecx
 test ecx,ecx
 jz .fin
 cmp word [tcp_remote_port],3500h
 je .dns_payload
 ; Bounded raw HTTP capture at dedicated scratch RAM, not in boot image.
 mov esi,net_rx_buffer+34
 add esi,[tcp_rx_header]
 mov edi,[http_stored]
 mov eax,HTTP_CAPACITY
 sub eax,edi
 cmp ecx,eax
 jbe .copy
 mov ecx,eax
.copy:
 add [http_stored],ecx
 add edi,HTTP_BUFFER
 rep movsb
 add [http_bytes],ebx
 add [tcp_ack_num],ebx
 jmp .fin
.dns_payload:
 ; Capture TCP DNS stream, including its two-byte network-order length.
 mov esi,net_rx_buffer+34
 add esi,[tcp_rx_header]
 mov edi,[dns_tcp_stored]
 mov eax,4096
 sub eax,edi
 cmp ecx,eax
 jbe .dns_copy
 mov ecx,eax
.dns_copy:
 add [dns_tcp_stored],ecx
 add edi,DNS_TCP_BUFFER
 rep movsb
 add [tcp_ack_num],ebx
.fin:
 test byte [net_rx_buffer+47],1
 jz .data_ack
 inc dword [tcp_ack_num]
 mov byte [tcp_state],3
.data_ack:
 test ebx,ebx
 jnz .send_ack
 cmp byte [tcp_state],3
 jne .end
.send_ack:
 mov byte [tcp_flags],10h
 xor ecx,ecx
 call tcp_send_segment
 cmp word [tcp_remote_port],3500h
 jne .end
 call dns_tcp_check
 jmp .end
.duplicate:
 ; No out-of-order buffer: advertise current cumulative ACK.
 cmp byte [tcp_state],2
 jne .end
 test byte [net_rx_buffer+47],4
 jnz .end
 jmp .send_ack
.reset:
 mov byte [tcp_state],4
 jmp .end
.bad_checksum:
 inc dword [tcp_bad_checksum]
.end:
 ret

; Send ARP request for gateway IP, if configured.
arp_gateway:
 mov byte [arp_retry_elapsed],0 ; NEW: restart timer on each attempt
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
 ; FIX 0.6.9: a broadcast ARP request from the configured gateway
 ; can supply its sender mapping even when asking about another host.
 ; RFC 826 sender mapping is useful independently of the target.
 ; Require matching Ethernet/ARP source and valid unicast MAC.
 ; This is ordinary ARP learning, not authentication.
 cmp dword [gateway_ip],0
 je .end
 mov eax,dword [net_rx_buffer+28]
 cmp eax,dword [gateway_ip]
 jne .end
 inc dword [arp_gateway_seen]
 cmp word [net_rx_buffer+20],0100h
 jne .reply
 ; FIX: allow broadcast gateway requests addressed to other IPs.
 ; Directed requests must still target our local IPv4 address.
 mov eax,dword [net_rx_buffer+38]
 cmp eax,dword [local_ip]
 je .check_sender
 cmp dword [net_rx_buffer],0ffffffffh
 jne .reject
 cmp word [net_rx_buffer+4],0ffffh
 jne .reject
 jmp .check_sender
.reply:
 cmp word [net_rx_buffer+20],0200h
 jne .reject
 mov eax,dword [net_rx_buffer+38]
 cmp eax,dword [local_ip]
 jne .reject
 ; Replies must explicitly name this guest's hardware address.
 mov esi,net_rx_buffer+32
 mov edi,net_mac
 mov ecx,6
 repe cmpsb
 jne .reject
.check_sender:
 test byte [net_rx_buffer+22],1
 jnz .reject
 mov eax,dword [net_rx_buffer+22]
 movzx edx,word [net_rx_buffer+26]
 or eax,edx
 jz .reject
 mov esi,net_rx_buffer+6
 mov edi,net_rx_buffer+22
 mov ecx,6
 repe cmpsb
 jne .reject
 ; FIX: do not silently replace an established gateway mapping.
 cmp byte [gateway_known],1
 jne .learn
 mov esi,net_rx_buffer+22
 mov edi,gateway_mac
 mov ecx,6
 repe cmpsb
 jne .reject
 ret
.learn:
 mov esi,net_rx_buffer+22
 mov edi,gateway_mac
 mov ecx,6
 rep movsb
 mov byte [gateway_known],1
 inc dword [arp_gateway_learned]
 ; Record whether the mapping came from request or reply.
 mov eax,[arp_last_opcode]
 mov [arp_learn_opcode],eax
 ret
.reject:
 inc dword [arp_gateway_rejected]
.end:
 ret

; NEW: AL is elapsed RTC seconds, provided by dhcp_tick.
; Retry unresolved gateway at three-second intervals without blocking.
arp_tick:
 cmp byte [dhcp_state],3
 jne .done
 cmp byte [gateway_known],1
 je .done
 cmp dword [gateway_ip],0
 je .done
 add al,[arp_retry_elapsed]
 cmp al,3
 jae .retry
 mov [arp_retry_elapsed],al
 ret
.retry:
 call arp_gateway
.done:
 ret

arp_retry_elapsed db 0
arp_frames_seen dd 0
arp_last_sender dd 0
arp_last_target dd 0
arp_last_opcode dd 0
arp_gateway_seen dd 0
arp_gateway_rejected dd 0
arp_learn_opcode dd 0

tcp_syn_probe:
 cmp byte [gateway_known],1
 jne .end
 cmp byte [dhcp_state],3
 jne .end
 cmp byte [tcp_state],1
 je .end
 cmp byte [tcp_state],2
 je .end
 mov byte [tcp_state],1
 rdtsc
 xor eax,edx
 mov [tcp_seq_num],eax
 ; NEW: select a fresh ephemeral port for each connection.
 and ax,3fffh
 or ax,0c000h
 xchg al,ah
 mov [tcp_local_port],ax
 mov dword [tcp_ack_num],0
 ; FIX: DNS transport must not invalidate the previous HTTP response.
 cmp word [tcp_remote_port],3500h
 je .dns_reset
 mov dword [render_page],0
 mov byte [render_more],0
 mov dword [http_scroll],0
 mov dword [http_page_end],0
 mov dword [http_bytes],0
 mov dword [http_stored],0
 jmp .reset_done
.dns_reset:
 mov dword [dns_tcp_stored],0
.reset_done:
 mov byte [tcp_elapsed],0
 mov byte [tcp_retries],0
 call tcp_send_syn
.end:
 ret

tcp_send_syn:
 mov byte [tcp_flags],2
 xor ecx,ecx
 call tcp_send_segment
 inc dword [tcp_syn_sent]
 ret

; AL elapsed RTC seconds. Bounded SYN retry and idle timeout.
tcp_tick:
 mov [tcp_tick_delta],al
 cmp byte [tcp_state],1
 je .syn
 cmp byte [tcp_state],2
 jne .done
 add al,[tcp_elapsed]
 mov [tcp_elapsed],al
 cmp al,30
 jae .timeout
 ; FIX: bounded retries for the outstanding request (not a general TCP send queue).
 mov eax,[tcp_snd_una]
 cmp eax,[tcp_seq_num]
 je .done
 ; Idle elapsed is an upper bound; independent counter uses caller's elapsed seconds.
 mov al,[tcp_tick_delta]
 add al,[tcp_data_elapsed]
 mov [tcp_data_elapsed],al
 cmp al,5
 jb .done
 mov byte [tcp_data_elapsed],0
 cmp byte [tcp_data_retries],3
 jae .timeout
 inc byte [tcp_data_retries]
 call tcp_retry_request
 jmp .done
.syn:
 add al,[tcp_elapsed]
 mov [tcp_elapsed],al
 cmp al,5
 jb .done
 mov byte [tcp_elapsed],0
 cmp byte [tcp_retries],3
 jae .timeout
 inc byte [tcp_retries]
 call tcp_send_syn
 jmp .done
.timeout:
 mov byte [tcp_state],5
.done:
 ret

 ; Retransmit only the unacknowledged suffix of the immutable HTTP/DNS request.
tcp_retry_request:
 pushad
 mov eax,[tcp_snd_una]
 mov edx,eax
 sub edx,[tcp_request_seq]
 cmp edx,[http_request_len]
 jae .done
 mov ecx,[http_request_len]
 sub ecx,edx
 mov esi,[http_request_ptr]
 add esi,edx
 push dword [tcp_seq_num]
 mov [tcp_seq_num],eax
 mov byte [tcp_flags],18h
 call tcp_send_segment
 pop dword [tcp_seq_num]
.done:
 popad
 ret

; TCP sender: flags tcp_flags; optional payload ESI, length ECX.
; Bounded single-request retry; no general send queue or out-of-order reassembly.
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
 mov ax,[tcp_local_port]
 mov word [tx_frame+34],ax
 mov ax,[tcp_remote_port]
 mov word [tx_frame+36],ax
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
 ; FIX: sum_words already handles odd lengths; no mutation past payload.
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
tcp_remote_port dw 5000h
tcp_local_port dw 0
tcp_state db 0
tcp_flags db 0
tcp_seq_num dd 0
tcp_ack_num dd 0
tcp_payload_len dw 0
tcp_ip_len dw 0
http_bytes dd 0
HTTP_BUFFER = 20000h ; scratch RAM outside loaded kernel and stack
HTTP_CAPACITY = 65536 ; 20000h..2FFFFh
http_request_ptr dd http_get_request
http_request_len dd http_get_end-http_get_request
http_stored dd 0
tcp_bad_checksum dd 0
tcp_rx_length dd 0
tcp_rx_header dd 0
tcp_elapsed db 0
tcp_retries db 0
tcp_tick_delta db 0
tcp_data_elapsed db 0
tcp_data_retries db 0
tcp_request_seq dd 0
tcp_snd_una dd 0

sum_words:
 ; Handles zero and odd lengths without reading outside the segment.
 push ebx
 xor eax,eax
.loop:
 cmp ecx,2
 jb .tail
 movzx ebx,word [esi]
 rol bx,8
 add eax,ebx
 add esi,2
 sub ecx,2
 jmp .loop
.tail:
 test ecx,ecx
 jz .done
 movzx ebx,byte [esi]
 shl ebx,8
 add eax,ebx
.done:
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