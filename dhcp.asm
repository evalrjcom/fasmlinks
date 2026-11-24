; TextOS 0.6.7 DHCPv4 client: automatic acquisition/retries; no lease renewal yet.
; States: 0 idle, 1 selecting, 2 requesting, 3 bound, 4 NAK.
; All IPv4 addresses stored as network-order bytes.
dhcp_discover:
 ; FIX: D retries SELECTING/REQUESTING without resetting the exchange.
 cmp byte [net_present],1
 jne .end
 cmp byte [dhcp_state],3 ; NEW: D cannot discard a bound lease
 je .end
 cmp byte [dhcp_state],1
 je .retry_discover
 cmp byte [dhcp_state],2
 je .retry_request
 cmp byte [net_present],1
 jne .end
 ; NEW: per-exchange XID; v86 provides RDTSC.
 rdtsc
 xor eax,edx
 xor eax,dword [net_mac]
 movzx edx,word [net_mac+4]
 xor eax,edx
 or eax,1
 mov [dhcp_xid],eax
 mov byte [dhcp_retry_interval],4
 mov byte [dhcp_retry_elapsed],0
 mov byte [dhcp_request_retries],0
 mov byte [dhcp_state],1
 mov dword [local_ip],0
 mov dword [gateway_ip],0
 mov dword [dhcp_offered_ip],0
 mov dword [dhcp_server_ip],0
 mov dword [dhcp_router_ip],0
 mov dword [dhcp_dns_ip],0
 mov dword [dhcp_subnet],0 ; FIX: clear previous lease metadata
 mov dword [dhcp_lease_seconds],0
 mov dword [dhcp_lease_left],0
 mov byte [dns_state],0
 mov byte [gateway_known],0
 mov byte [tcp_state],0
 mov byte [stream_mode],0
 call stream_reset
 mov byte [dhcp_message_type],1
 inc dword [dhcp_discover_tx]
 call dhcp_send
 jmp .end
.retry_discover:
 mov byte [dhcp_retry_elapsed],0
 inc dword [dhcp_discover_tx]
 mov byte [dhcp_message_type],1
 call dhcp_send
 jmp .end
.retry_request:
 mov byte [dhcp_retry_elapsed],0
 inc dword [dhcp_request_tx]
 mov byte [dhcp_message_type],3
 call dhcp_send
.end:
 ret

dhcp_request:
 mov byte [dhcp_retry_interval],4
 mov byte [dhcp_retry_elapsed],0
 mov byte [dhcp_request_retries],0
 mov byte [dhcp_message_type],3
 mov byte [dhcp_state],2
 inc dword [dhcp_request_tx]
 call dhcp_send
 ret

dhcp_send:
 pushad
 mov edi,tx_frame
 mov ecx,6
 mov al,0ffh
 rep stosb
 mov esi,net_mac
 mov ecx,6
 rep movsb
 mov word [tx_frame+12],0008h
 mov edi,tx_frame+14
 mov ecx,20+8+320
 xor eax,eax
 rep stosb
 mov byte [tx_frame+14],45h
 mov byte [tx_frame+22],64
 mov byte [tx_frame+23],17
 mov dword [tx_frame+30],0ffffffffh
 mov word [tx_frame+34],4400h ; 68
 mov word [tx_frame+36],4300h ; 67
 mov byte [tx_frame+42],1
 mov byte [tx_frame+43],1
 mov byte [tx_frame+44],6
 mov eax,[dhcp_xid]
 mov dword [tx_frame+46],eax ; NEW: same XID throughout exchange
 mov word [tx_frame+52],0080h ; broadcast flag
 mov esi,net_mac
 mov edi,tx_frame+70
 mov ecx,6
 rep movsb
 mov dword [tx_frame+278],63538263h
 mov byte [tx_frame+282],53
 mov byte [tx_frame+283],1
 mov al,[dhcp_message_type]
 mov [tx_frame+284],al
 mov edi,tx_frame+285
 cmp al,3
 jne .common
 mov byte [edi],50
 mov byte [edi+1],4
 mov eax,[dhcp_offered_ip]
 mov [edi+2],eax
 add edi,6
 mov byte [edi],54
 mov byte [edi+1],4
 mov eax,[dhcp_server_ip]
 mov [edi+2],eax
 add edi,6
.common:
 ; FIX: Include RFC 2132 client identifier and maximum DHCP message size.
 mov byte [edi],61
 mov byte [edi+1],7
 mov byte [edi+2],1
 push esi
 push ecx
 lea esi,[net_mac]
 add edi,3
 mov ecx,6
 rep movsb
 pop ecx
 pop esi
 mov byte [edi],57
 mov byte [edi+1],2
 mov word [edi+2],0DC05h ; FIX: wire bytes 05 DC = 1500 (big endian)
 add edi,4
 mov byte [edi],55
 mov byte [edi+1],5
 mov byte [edi+2],1 ; subnet
 mov byte [edi+3],3 ; router
 mov byte [edi+4],6 ; DNS
 mov byte [edi+5],51 ; lease
 mov byte [edi+6],54 ; server id
 add edi,7
 mov byte [edi],255
 inc edi
 ; BOOTP payload padded to 300 bytes for compatibility
 mov eax,tx_frame+42+300
 cmp edi,eax
 jae .lengths
 mov edi,eax
.lengths:
 mov eax,edi
 sub eax,tx_frame+42
 add eax,8
 mov [dhcp_udp_len],ax
 xchg al,ah
 mov [tx_frame+38],ax
 mov eax,edi
 sub eax,tx_frame+14
 mov [dhcp_ip_len],ax
 xchg al,ah
 mov [tx_frame+16],ax
 mov esi,tx_frame+14
 mov ecx,20
 call checksum
 mov [tx_frame+24],ax
 mov esi,tx_frame
 mov ecx,edi
 sub ecx,tx_frame
 call ne_send_buffer
 popad
 ret

; Only called after Ethernet and IPv4 dispatch. Validate packet bounds
; before inspecting DHCP fixed header and options.
udp_receive:
 inc dword [dhcp_udp_seen]
 ; FIX: Detect our own outgoing DISCOVER looped back by a relay.
 ; Never reinterpret it as a server OFFER, regardless of address filtering.
 mov esi,net_rx_buffer+6
 mov edi,net_mac
 mov ecx,6
 repe cmpsb
 jne .not_self
 inc dword [dhcp_own_frames]
 ret
.not_self:
 ; Detect received client-originated DHCP traffic without treating it as an OFFER.
 cmp word [net_rx_buffer+34],4400h
 jne .not_client
 cmp word [net_rx_buffer+36],4300h
 jne .not_client
 inc dword [dhcp_client_echo]
.not_client:
 mov esi,net_rx_buffer+6
 mov edi,rx_last_src_mac
 mov ecx,6
 rep movsb
 ; Capture the most recent UDP ports before DHCP filtering.
 movzx eax,word [net_rx_buffer+34]
 xchg al,ah
 mov [udp_last_src],eax
 movzx eax,word [net_rx_buffer+36]
 xchg al,ah
 mov [udp_last_dst],eax
 movzx ebx,word [net_rx_length]
 sub ebx,4 ; NE2000 count includes 4-byte ring header
 jc .bad
 cmp ebx,42 ; minimum Ethernet+IPv4+UDP
 jb .bad
 cmp ebx,1514
 ja .bad
 cmp word [net_rx_buffer+34],4300h
 jne .wrong_port
 cmp word [net_rx_buffer+36],4400h
 jne .wrong_port
 inc dword [dhcp_port_match]
 cmp ebx,282
 jb .bad
 ; UDP length is network byte order and must cover fixed BOOTP + cookie
 movzx eax,word [net_rx_buffer+38]
 xchg al,ah
 cmp eax,248
 jb .bad
 lea edx,[eax+34]
 cmp edx,ebx
 ja .bad
 mov ebx,edx ; end of UDP payload (exclusive)
 ; FIX: verify nonzero IPv4 UDP checksum before accepting lease data.
 cmp word [net_rx_buffer+40],0
 je .checksum_ok
 push ebx
 mov esi,net_rx_buffer+26
 mov ecx,8
 call sum_words
 mov edx,eax
 add edx,17
 movzx ecx,word [net_rx_buffer+38]
 xchg cl,ch
 add edx,ecx
 mov esi,net_rx_buffer+34
 call sum_words
 add eax,edx
 mov edx,eax
 shr eax,16
 and edx,0ffffh
 add eax,edx
 mov edx,eax
 shr edx,16
 add ax,dx
 pop ebx
 cmp ax,0ffffh
 jne .bad
.checksum_ok:
 cmp byte [net_rx_buffer+42],2
 jne .bad
 cmp byte [net_rx_buffer+43],1
 jne .bad
 cmp byte [net_rx_buffer+44],6
 jne .bad
 mov eax,[dhcp_xid]
 cmp dword [net_rx_buffer+46],eax
 jne .wrong_xid
 ; FIX: BOOTP client hardware address must match our NIC to avoid
 ; accepting DHCP packets intended for another client on the relay.
 mov esi,net_rx_buffer+70
 mov edi,net_mac
 mov ecx,6
 repe cmpsb
 jne .bad
 cmp dword [net_rx_buffer+278],63538263h
 jne .bad
 mov esi,net_rx_buffer+282
 lea ebx,[net_rx_buffer+ebx]
 ; NEW: stage options until the complete packet is accepted.
 mov dword [opt_server],0
 mov dword [opt_router],0
 mov dword [opt_dns],0
 mov dword [opt_subnet],0
 mov dword [opt_lease],0
 xor edx,edx ; message type in DL
.scan:
 cmp esi,ebx
 jae .bad
 movzx eax,byte [esi]
 inc esi
 cmp al,255
 je .parsed
 test al,al
 jz .scan
 cmp esi,ebx
 jae .bad
 movzx ecx,byte [esi]
 inc esi
 lea edi,[esi+ecx]
 cmp edi,ebx
 ja .bad
 cmp eax,53
 jne .server
 cmp ecx,1
 jne .bad
 test dl,dl ; NEW: reject duplicate message-type options
 jnz .bad
 mov dl,[esi]
 jmp .next
.server:
 cmp eax,54
 jne .router
 cmp ecx,4
 jne .bad
 mov eax,[esi]
 mov [opt_server],eax
 jmp .next
.router:
 cmp eax,3
 jne .dns
 cmp ecx,4
 jb .bad
 test ecx,3 ; FIX: IPv4 address list length is a multiple of four
 jnz .bad
 mov eax,[esi]
 mov [opt_router],eax
 jmp .next
.dns:
 cmp eax,6
 jne .subnet
 cmp ecx,4
 jb .bad
 test ecx,3
 jnz .bad
 mov eax,[esi]
 mov [opt_dns],eax
 jmp .next
.subnet:
 cmp eax,1
 jne .lease
 cmp ecx,4
 jne .bad
 mov eax,[esi]
 mov [opt_subnet],eax
 jmp .next
.lease:
 cmp eax,51
 jne .next
 cmp ecx,4
 jne .bad
 mov eax,[esi]
 bswap eax
 mov [opt_lease],eax
.next:
 mov esi,edi
 jmp .scan
.parsed:
 ; FIX: A DHCP message type is mandatory.
 test dl,dl
 jz .bad
 cmp dl,2
 jne .ack
 cmp byte [dhcp_state],1
 jne .done
 mov eax,dword [net_rx_buffer+58]
 test eax,eax
 jz .bad
 cmp eax,0ffffffffh
 je .bad
 cmp dword [opt_server],0
 je .bad
 mov [dhcp_offered_ip],eax
 mov eax,[opt_server]
 mov [dhcp_server_ip],eax
 inc dword [dhcp_offer_rx]
 call dhcp_request
 jmp .done
.ack:
 cmp dl,5
 jne .nak
 cmp byte [dhcp_state],2
 jne .done
 mov eax,dword [net_rx_buffer+58]
 cmp eax,[dhcp_offered_ip]
 jne .bad
 mov ecx,[opt_server]
 cmp ecx,[dhcp_server_ip] ; NEW: validate selected server before committing options
 jne .bad
 ; FIX: reject zero/missing lease and subnet rather than binding unusable config.
 cmp dword [opt_lease],0
 je .bad
 cmp dword [opt_subnet],0
 je .bad
 inc dword [dhcp_ack_rx]
 mov dword [local_ip],eax
 mov eax,[opt_subnet]
 mov [dhcp_subnet],eax
 mov eax,[opt_dns]
 mov [dhcp_dns_ip],eax
 mov eax,[opt_lease]
 mov [dhcp_lease_seconds],eax
 mov [dhcp_lease_left],eax
 mov eax,[opt_router]
 mov [dhcp_router_ip],eax
 mov dword [gateway_ip],eax
 mov byte [dhcp_state],3
 cmp dword [gateway_ip],0
 je .done
 call arp_gateway
 jmp .done
.nak:
 cmp dl,6
 jne .done
 cmp byte [dhcp_state],2 ; FIX: ignore unsolicited NAK outside REQUESTING
 jne .done
 mov eax,[opt_server]
 cmp eax,[dhcp_server_ip]
 jne .bad
 inc dword [dhcp_nak_rx]
 mov byte [dhcp_retry_elapsed],0
 mov byte [dhcp_retry_interval],4
 mov byte [dhcp_state],4
 mov dword [local_ip],0
 mov dword [gateway_ip],0
 mov byte [gateway_known],0
 jmp .done
.wrong_port:
 inc dword [dhcp_wrong_port]
 jmp .done
.wrong_xid:
 inc dword [dhcp_wrong_xid]
 jmp .done
.bad:
 inc dword [dhcp_rejected]
.done:
 ret

; NEW: RTC seconds polling works with interrupts disabled.
; Approximate during VM suspension; no lease expiry/renewal yet.
dhcp_clock_init:
 pushad
 call dhcp_rtc_seconds
 mov [dhcp_clock_last],al
 popad
 ret

dhcp_rtc_seconds:
 mov al,0ah
 out 70h,al
 in al,71h
 test al,80h
 jnz .invalid
 mov al,0bh
 out 70h,al
 in al,71h
 mov ah,al
 xor al,al
 out 70h,al
 in al,71h
 test ah,4
 jnz .binary
 mov ah,al
 and al,0fh
 shr ah,4
 aad
.binary:
 cmp al,60
 jae .invalid
 ret
.invalid:
 mov al,0ffh
 ret

dhcp_tick:
 pushad
 call dhcp_rtc_seconds
 cmp al,60
 jae .done
 cmp byte [dhcp_clock_last],60
 jae .init
 mov bl,al
 sub al,[dhcp_clock_last]
 jnc .elapsed
 add al,60
.elapsed:
 mov [dhcp_clock_last],bl
 test al,al
 jz .done
 cmp byte [dhcp_state],3
 jne .acquiring
 ; FIX: expire finite leases instead of keeping stale IP indefinitely.
 ; Approximate RTC polling; renewal/rebinding before expiry is still TODO.
 cmp dword [dhcp_lease_left],0ffffffffh
 je .lease_valid
 movzx ecx,al
 cmp ecx,[dhcp_lease_left]
 jae .lease_expired
 sub [dhcp_lease_left],ecx
.lease_valid:
 push eax
 call arp_tick ; keep gateway discovery alive after DHCP ACK
 pop eax
 push eax
 call tcp_tick
 pop eax
 call dns_tick
 jmp .done
.lease_expired:
 mov byte [dhcp_state],0
 call dhcp_discover
 jmp .done
.acquiring:
 cmp byte [dhcp_state],0
 je .done
 add al,[dhcp_retry_elapsed]
 cmp al,[dhcp_retry_interval]
 jae .retry
 mov [dhcp_retry_elapsed],al
 jmp .done
.init:
 mov [dhcp_clock_last],al
 jmp .done
.retry:
 mov byte [dhcp_retry_elapsed],0
 cmp byte [dhcp_state],2
 jne .send
 inc byte [dhcp_request_retries]
 cmp byte [dhcp_request_retries],4
 jb .send
 ; NEW: abandoned server; restart selection with fresh XID.
 mov byte [dhcp_state],0
.send:
 call dhcp_discover
 mov al,[dhcp_retry_interval]
 cmp al,32
 jae .done
 shl al,1
 mov [dhcp_retry_interval],al
.done:
 popad
 ret

dhcp_clock_last db 0ffh
dhcp_retry_elapsed db 0
dhcp_retry_interval db 4
dhcp_request_retries db 0
dhcp_xid dd 0
opt_server dd 0
opt_router dd 0
opt_dns dd 0
opt_subnet dd 0
opt_lease dd 0
dhcp_state db 0
dhcp_message_type db 0
dhcp_offered_ip dd 0
dhcp_server_ip dd 0
dhcp_router_ip dd 0
dhcp_dns_ip dd 0
dhcp_subnet dd 0
dhcp_lease_seconds dd 0
dhcp_lease_left dd 0
dhcp_udp_len dw 0
dhcp_ip_len dw 0
dhcp_discover_tx dd 0
dhcp_request_tx dd 0
dhcp_udp_seen dd 0
dhcp_offer_rx dd 0
dhcp_ack_rx dd 0
dhcp_nak_rx dd 0
dhcp_rejected dd 0

; Additional receive-path diagnostics (values in host order for ports).
udp_last_src dd 0
udp_last_dst dd 0
dhcp_port_match dd 0
dhcp_wrong_port dd 0
dhcp_wrong_xid dd 0

dhcp_client_echo dd 0
; FIX: looped-back packets are counted separately from genuine offers.
dhcp_own_frames dd 0
rx_last_src_mac rb 6