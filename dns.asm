; 0.7.1: one outstanding DNS A query for info.cern.ch.
; Source/destination tuple, transaction ID, question and answer owner verified.
; Supports directly returned A records, including compressed owner pointer to question.
; No CNAME following, TCP fallback, DNSSEC or arbitrary hostname entry.
dns_start:
 ; Default CERN probe; interactive editor uses dns_start_custom.
 cmp byte [dns_state],1
 je .default_done
 cmp byte [dns_state],4
 je .default_done
 cmp byte [tcp_state],1
 je .default_done
 cmp byte [tcp_state],2
 je .default_done
 mov esi,dns_default_question
 mov edi,dns_question
 mov ecx,dns_default_end-dns_default_question
 rep movsb
 mov dword [dns_question_len],dns_default_end-dns_default_question
 mov byte [dns_custom],0
 jmp dns_start_custom
.default_done:
 ret
dns_start_custom:
 cmp byte [dhcp_state],3
 jne .done
 cmp byte [gateway_known],1
 jne .done
 cmp dword [dhcp_dns_ip],0
 je .done
 cmp byte [tcp_state],1
 je .done
 cmp byte [tcp_state],2
 je .done
 cmp byte [dns_state],1
 je .done
 cmp byte [dns_state],4
 je .done
 rdtsc
 xor eax,edx
 mov [dns_id],ax
 shr eax,16
 and ax,3fffh
 or ax,0c000h
 xchg al,ah
 mov [dns_port],ax
 mov byte [dns_elapsed],0
 mov byte [dns_attempt],0
 mov eax,[dhcp_dns_ip]
 mov [dns_server],eax
 mov dword [dns_result],0
 mov byte [dns_state],1
 call dns_send
.done:
 ret

dns_send:
 pushad
 mov esi,gateway_mac
 mov edi,tx_frame
 mov ecx,6
 rep movsb
 mov esi,net_mac
 mov ecx,6
 rep movsb
 mov word [tx_frame+12],0008h
 mov ecx,28
 xor eax,eax
 rep stosb
 mov byte [tx_frame+14],45h
 mov byte [tx_frame+22],64
 mov byte [tx_frame+23],17
 mov eax,dword [local_ip]
 mov [tx_frame+26],eax
 mov eax,[dns_server]
 mov [tx_frame+30],eax
 mov ax,[dns_port]
 mov [tx_frame+34],ax
 mov word [tx_frame+36],3500h
 mov eax,[dns_question_len]
 add eax,20
 xchg al,ah
 mov [tx_frame+38],ax
 mov eax,[dns_question_len]
 add eax,40
 xchg al,ah
 mov [tx_frame+16],ax
 mov esi,dns_query
 mov edi,tx_frame+42
 mov ecx,[dns_question_len]
 add ecx,12
 rep movsb
 mov ax,[dns_id]
 mov [tx_frame+42],ax
 ; FIX: calculate UDP pseudo-header checksum, including odd tail.
 mov esi,tx_frame+26
 mov ecx,8
 call sum_words
 mov edx,eax
 add edx,37
 add edx,[dns_question_len]
 mov esi,tx_frame+34
 mov ecx,[dns_question_len]
 add ecx,20
 call sum_words
 add eax,edx
 mov edx,eax
 shr eax,16
 and edx,0ffffh
 add eax,edx
 mov edx,eax
 shr edx,16
 add ax,dx
 not ax
 jnz .udp_nonzero
 mov ax,0ffffh
.udp_nonzero:
 xchg al,ah
 mov [tx_frame+40],ax
 mov esi,tx_frame+14
 mov ecx,20
 call checksum
 mov [tx_frame+24],ax
 ; Record actual successful DMA submission, not only query attempts.
 mov eax,[net_tx_count]
 push eax
 mov esi,tx_frame
 mov ecx,[dns_question_len]
 add ecx,54
 call ne_send_buffer
 pop eax
 cmp eax,[net_tx_count]
 je .tx_failed
 inc dword [dns_tx_ok]
.tx_failed:
 inc dword [dns_tx]
 popad
 ret

dns_receive:
 inc dword [dns_seen]
 cmp byte [dns_state],1
 jne .done
 mov eax,dword [net_rx_buffer+26]
 cmp eax,[dns_server]
 jne .udp_tuple_bad
 mov eax,dword [net_rx_buffer+30]
 cmp eax,dword [local_ip]
 jne .udp_tuple_bad
 mov ax,[dns_port]
 cmp word [net_rx_buffer+36],ax
 jne .udp_tuple_bad
 cmp word [net_rx_buffer+38],0 ; length already bounded by IP layer
 je .udp_failed
 movzx ecx,word [net_rx_buffer+38]
 xchg cl,ch
 cmp ecx,20 ; UDP + DNS fixed header before reading ID
 jb .udp_failed
 mov ax,[dns_id]
 cmp word [net_rx_buffer+42],ax
 jne .udp_id_bad
 inc dword [dns_matched]
 movzx ecx,word [net_rx_buffer+38]
 xchg cl,ch
 mov eax,[dns_question_len]
 add eax,20
 cmp ecx,eax
 jb .done
 lea ebx,[net_rx_buffer+34+ecx] ; exclusive UDP end
 ; Validate nonzero UDP checksum (zero legal for IPv4).
 cmp word [net_rx_buffer+40],0
 je .checksum_ok
 push ebx
 push ecx
 mov esi,net_rx_buffer+26
 mov ecx,8
 call sum_words
 mov edx,eax
 add edx,17
 pop ecx
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
 jne .udp_checksum_bad
 .checksum_ok:
 mov esi,net_rx_buffer+42
 call dns_parse_message
 ret
.udp_tuple_bad:
 inc dword [dns_tuple_bad]
 ret
.udp_id_bad:
 inc dword [dns_id_bad]
 ret
.udp_checksum_bad:
 inc dword [dns_checksum_bad]
 ret
.udp_failed:
 inc dword [dns_parse_bad]
.done:
 ret


; ESI = DNS message base; EBX = exclusive end. Shared UDP/TCP parser.
dns_parse_message:
 mov [dns_msg_base],esi
 mov [dns_msg_end],ebx
 mov eax,[dns_question_len]
 lea eax,[esi+eax+12]
 cmp eax,ebx
 ja .failed
 mov ax,[esi]
 cmp ax,[dns_id]
 jne .id_bad
 mov ax,[esi+2]
 xchg al,ah
 test ax,8000h
 jz .done
 mov [dns_flags],ax
 test ax,7a0fh ; unsupported opcode, truncated, or error
 jnz .failed
 cmp word [esi+4],0100h
 jne .failed
 movzx eax,word [esi+6]
 xchg al,ah
 test eax,eax
 jz .failed
 cmp eax,128
 ja .failed
 mov [dns_answer_count],eax
 ; Match exact question (fixed lower-case wire name).
 add esi,12
 mov edi,dns_question
 mov ecx,[dns_question_len]
 repe cmpsb
 jne .failed
 inc dword [dns_rx]
 ; Follow only owner-matched CNAME/A records within the answer section.
 mov [dns_answers],esi
 mov esi,dns_question
 mov edi,dns_expected_name
 mov ecx,[dns_question_len]
 sub ecx,4
 rep movsb
 mov byte [dns_chain_depth],0
.scan_pass:
 mov esi,[dns_answers]
 mov eax,[dns_answer_count]
 mov [dns_remaining],eax
.scan_rr:
 mov edi,dns_owner_name
 call dns_expand_name
 jc .failed
 ; ESI is the first byte after encoded owner, EBX remains message end.
 lea eax,[esi+10]
 cmp eax,ebx
 ja .failed
 movzx ecx,word [esi+8]
 xchg cl,ch
 lea eax,[esi+10+ecx]
 cmp eax,ebx
 ja .failed
 mov [dns_next_rr],eax
 mov [dns_rr_header],esi
 mov esi,dns_owner_name
 mov edi,dns_expected_name
 call dns_names_equal
 jne .next_rr
 mov esi,[dns_rr_header]
 cmp word [esi+2],0100h
 jne .next_rr
 cmp word [esi],0100h
 jne .cname
 cmp word [esi+8],0400h
 jne .failed
 mov eax,dword [esi+10]
 test eax,eax
 jz .failed
 cmp eax,0ffffffffh
 je .failed
 jmp .found
.cname:
 cmp word [esi],0500h
 jne .next_rr
 inc byte [dns_chain_depth]
 cmp byte [dns_chain_depth],8
 ja .failed
 add esi,10
 mov edi,dns_expected_name
 call dns_expand_name
 jc .failed
 cmp esi,[dns_next_rr]
 jne .failed
 inc dword [dns_cname_count]
 jmp .scan_pass
.next_rr:
 mov esi,[dns_next_rr]
 dec dword [dns_remaining]
 jnz .scan_rr
 jmp .failed
.found:
 mov [dns_result],eax
 ; Defer new HTTP connection until the DNS TCP ACK has been sent.
 cmp byte [dns_state],4
 jne .open_http
 mov byte [tcp_state],3
.open_http:
 mov word [tcp_remote_port],5000h
 mov dword [remote_ip],eax
 cmp byte [dns_custom],1
 jne .default_http
 mov dword [http_request_ptr],url_request
 mov eax,[url_request_length]
 mov [http_request_len],eax
 jmp .launch
.default_http:
 mov dword [http_request_ptr],cern_get
 mov dword [http_request_len],cern_get_end-cern_get
.launch:
 mov byte [dns_state],2
 call tcp_syn_probe
 ret
.tuple_bad:
 inc dword [dns_tuple_bad]
 ret
.id_bad:
 inc dword [dns_id_bad]
 ret
.checksum_bad:
 inc dword [dns_checksum_bad]
 ret
.failed:
 inc dword [dns_parse_bad]
 ; Leave pending so timer can retry or switch resolver.
.done:
 ret

; Expand a DNS wire name into a bounded canonical wire-name buffer.
; ESI input cursor, EDI output (256 bytes), EBX exclusive packet end.
; Return ESI after original encoded name, CF set on malformed input.
dns_expand_name:
 push eax
 push ecx
 push edx
 push ebp
 xor ebp,ebp ; original continuation after first pointer
 mov ecx,255
 mov edx,128 ; bound compression hops and labels
.step:
 dec edx
 jz .bad
 cmp esi,[dns_msg_base]
 jb .bad
 cmp esi,ebx
 jae .bad
 movzx eax,byte [esi]
 inc esi
 test al,0c0h
 jz .label
 and al,0c0h
 cmp al,0c0h
 jne .bad
 dec esi
 lea eax,[esi+2]
 cmp eax,ebx
 ja .bad
 test ebp,ebp
 jnz .pointer
 mov ebp,eax
.pointer:
 movzx eax,word [esi]
 xchg al,ah
 and eax,3fffh
 add eax,[dns_msg_base]
 cmp eax,esi ; backward pointers only, disallow loops/forward references
 jae .bad
 mov esi,eax
 jmp .step
.label:
 test eax,eax
 jz .finish
 cmp eax,63
 ja .bad
 sub ecx,eax
 jbe .bad
 dec ecx
 jz .bad
 stosb
 push ecx
 mov ecx,eax
 lea eax,[esi+ecx]
 cmp eax,ebx
 ja .bad_pop
.copy:
 lodsb
 cmp al,'A'
 jb .store
 cmp al,'Z'
 ja .store
 or al,20h
.store:
 stosb
 loop .copy
 pop ecx
 jmp .step
.bad_pop:
 pop ecx
 jmp .bad
.finish:
 xor eax,eax
 stosb
 test ebp,ebp
 jz .ok
 mov esi,ebp
.ok:
 clc
 jmp .exit
.bad:
 stc
.exit:
 pop ebp
 pop edx
 pop ecx
 pop eax
 ret

; Compare two validated canonical wire names label by label.
dns_names_equal:
 movzx ecx,byte [esi]
 cmp cl,[edi]
 jne .done
 test ecx,ecx
 jz .done
 inc esi
 inc edi
 repe cmpsb
 jne .done
 jmp dns_names_equal
.done:
 ret

dns_msg_base dd 0
dns_msg_end dd 0
dns_answers dd 0
dns_answer_count dd 0
dns_remaining dd 0
dns_next_rr dd 0
dns_rr_header dd 0
dns_chain_depth db 0
dns_cname_count dd 0
dns_owner_name rb 256
dns_expected_name rb 256

dns_tick:
 cmp byte [dns_state],4
 jne .udp
 cmp byte [tcp_state],4
 jae .timeout
 cmp byte [tcp_state],3
 je .timeout
 ret
.udp:
 cmp byte [dns_state],1
 jne .done
 add al,[dns_elapsed]
 mov [dns_elapsed],al
 cmp al,5
 jb .done
 mov byte [dns_elapsed],0
 inc byte [dns_attempt]
 cmp byte [dns_attempt],4
 jae .tcp_fallback
 cmp byte [dns_attempt],2
 jne .retry
 ; Explicit fallback to public Cloudflare resolver after two local attempts.
 mov dword [dns_server],01010101h
.retry:
 call dns_send
 ret
.tcp_fallback:
 ; FIX: never replace the tuple of an active TCP connection.
 cmp byte [tcp_state],1
 je .timeout
 cmp byte [tcp_state],2
 je .timeout
 ; Standard DNS over TCP, port 53, with length-prefixed query.
 mov byte [dns_state],4
 mov dword [remote_ip],01010101h
 mov dword [dns_server],01010101h
 mov word [tcp_remote_port],3500h
 mov ax,[dns_id]
 mov word [dns_query],ax
 mov dword [http_request_ptr],dns_tcp_query
 mov eax,[dns_question_len]
 add eax,12
 mov edx,eax
 xchg al,ah
 mov word [dns_tcp_query],ax
 add edx,2
 mov [http_request_len],edx
 inc dword [dns_tcp_attempts]
 call tcp_syn_probe
 ret
.timeout:
 mov byte [dns_state],3
.done:
 ret

dns_tcp_check:
 cmp byte [dns_state],4
 jne .done
 cmp dword [dns_tcp_stored],2
 jb .done
 movzx eax,word [DNS_TCP_BUFFER]
 xchg al,ah
 cmp eax,12
 jb .bad
 cmp eax,4094
 ja .bad
 lea edx,[eax+2]
 cmp edx,[dns_tcp_stored]
 ja .done
 mov esi,DNS_TCP_BUFFER+2
 lea ebx,[esi+eax]
 call dns_parse_message
 ret
.bad:
 inc dword [dns_parse_bad]
 mov byte [dns_state],3
.done:
 ret

DNS_TCP_BUFFER = 30000h
dns_tcp_stored dd 0
dns_tcp_attempts dd 0
dns_tx_ok dd 0
dns_wire_seen dd 0
dns_server dd 0
dns_seen dd 0
dns_matched dd 0
dns_tuple_bad dd 0
dns_id_bad dd 0
dns_checksum_bad dd 0
dns_parse_bad dd 0
dns_flags dw 0
dns_attempt db 0
dns_state db 0
dns_elapsed db 0
dns_id dw 0
dns_port dw 0
dns_result dd 0
dns_tx dd 0
dns_rx dd 0
dns_custom db 0
dns_question_len dd 0
dns_tcp_query dw 0
dns_query:
 dw 0,0001h,0100h,0,0,0
dns_question rb 80
dns_default_question db 4,'info',4,'cern',2,'ch',0
 dw 0100h,0100h
dns_default_end:
cern_get db 'GET / HTTP/1.0',13,10,'Host: info.cern.ch',13,10,'Connection: close',13,10,13,10
cern_get_end:
