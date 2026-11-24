; TextOS 0.8.2: bounded stop-and-wait TCP byte-stream adapter.
; A single connection; no out-of-order queue, congestion algorithm or zero-window
; persist probes. Unsent input stays with caller. Not a complete RFC 9293 stack.
STREAM_CAPACITY = 8192
STREAM_RX = 31000h ; 31000h..32FFFh, after DNS scratch
STREAM_TX = 33000h ; 536 bytes, before C payload
STREAM_MSS = 536

; Caller configures remote_ip/port. CF=1 if not ready or busy.
stream_open:
 cmp byte [dhcp_state],3
 jne .bad
 cmp byte [gateway_known],1
 jne .bad
 cmp byte [tcp_state],1
 je .bad
 cmp byte [tcp_state],2
 je .bad
 cmp byte [dns_state],1
 je .bad
 cmp byte [dns_state],4
 je .bad
 call stream_reset
 mov byte [stream_mode],1
 call tcp_connect_common
 clc
 ret
.bad:
 stc
 ret
stream_reset:
 mov dword [stream_rx_head],0
 mov dword [stream_rx_tail],0
 mov dword [stream_rx_used],0
 mov dword [stream_peer_window],0
 mov byte [stream_eof],0
 mov byte [stream_http_probe],0
 ret

; ESI=source, ECX=count. Preserve registers. CF=1 if no space.
stream_rx_push:
 pushad
 mov eax,STREAM_CAPACITY
 sub eax,[stream_rx_used]
 cmp ecx,eax
 ja .full
 add [stream_rx_used],ecx
 mov edx,[stream_rx_tail]
 test ecx,ecx
 jz .done
.copy:
 lodsb
 mov [STREAM_RX+edx],al
 inc edx
 and edx,STREAM_CAPACITY-1
 loop .copy
 mov [stream_rx_tail],edx
.done:
 popad
 clc
 ret
.full:
 popad
 stc
 ret

; EDI=destination, ECX=max, EAX=bytes copied. Preserves other registers.
; Does not transmit; caller advertises freed window after consuming bytes.
stream_rx_read:
 push ebx
 push ecx
 push edx
 push edi
 xor eax,eax
 cmp ecx,[stream_rx_used]
 jbe .bounded
 mov ecx,[stream_rx_used]
.bounded:
 mov ebx,ecx
 sub [stream_rx_used],ecx
 mov edx,[stream_rx_head]
 test ecx,ecx
 jz .done
.copy:
 mov al,[STREAM_RX+edx]
 stosb
 inc edx
 and edx,STREAM_CAPACITY-1
 loop .copy
 mov [stream_rx_head],edx
.done:
 mov eax,ebx
 pop edi
 pop edx
 pop ecx
 pop ebx
 ret

; ESI=source, ECX=available. EAX=bytes accepted (0 = would block).
; Copy into immutable retransmission slot; one segment in flight.
stream_write:
 pushad
 xor eax,eax
 mov [stream_write_result],eax
 cmp byte [stream_mode],1
 jne .done
 cmp byte [tcp_state],2
 jne .done
 mov eax,[tcp_snd_una]
 cmp eax,[tcp_seq_num]
 jne .done
 cmp ecx,STREAM_MSS
 jbe .mss
 mov ecx,STREAM_MSS
.mss:
 cmp ecx,[stream_peer_window]
 jbe .window
 mov ecx,[stream_peer_window]
.window:
 test ecx,ecx
 jz .done
 mov [stream_write_result],ecx
 mov [http_request_len],ecx
 mov dword [http_request_ptr],STREAM_TX
 mov edi,STREAM_TX
 rep movsb
 mov eax,[tcp_seq_num]
 mov [tcp_request_seq],eax
 mov byte [tcp_data_elapsed],0
 mov byte [tcp_data_retries],0
 mov byte [tcp_flags],18h
 mov esi,STREAM_TX
 mov ecx,[http_request_len]
 call tcp_send_segment
 mov eax,[http_request_len]
 add [tcp_seq_num],eax
.done:
 popad
 mov eax,[stream_write_result]
 ret

; F6: real HTTP regression probe over new adapter. No TLS traffic.
stream_probe_open:
 cmp byte [tcp_state],1
 je network_detail
 cmp byte [tcp_state],2
 je network_detail
 cmp byte [dns_state],1
 je dns_detail
 cmp byte [dns_state],4
 je dns_detail
 mov dword [remote_ip],01010101h
 mov word [tcp_remote_port],5000h
 call stream_open
 jc network_detail
 mov byte [stream_http_probe],1
 mov dword [stream_http_offset],0
 jmp network_detail

; Main loop adapter. Drains received stream into legacy HTTP capture.
stream_probe_poll:
 cmp byte [stream_mode],1
 jne .done
 cmp byte [stream_http_probe],1
 jne .done
 cmp byte [tcp_state],2
 jne .drain
 mov eax,[stream_http_offset]
 cmp eax,http_get_end-http_get_request
 jae .drain
 lea esi,[http_get_request+eax]
 mov ecx,http_get_end-http_get_request
 sub ecx,eax
 call stream_write
 add [stream_http_offset],eax
.drain:
 mov edi,[http_stored]
 mov ecx,HTTP_CAPACITY
 sub ecx,edi
 add edi,HTTP_BUFFER
 call stream_rx_read
 test eax,eax
 jz .done
 add [http_stored],eax
 add [http_bytes],eax
 cmp byte [tcp_state],2
 jne .done
 ; Window update after consuming bytes.
 mov byte [tcp_flags],10h
 xor ecx,ecx
 call tcp_send_segment
.done:
 ret

; Offline boot self-test exercises real assembly FIFO code, including wrap,
; capacity rejection and partial read. Does not simulate a TCP peer.
stream_selftest:
 call stream_reset
 mov dword [stream_rx_head],STREAM_CAPACITY-2
 mov dword [stream_rx_tail],STREAM_CAPACITY-2
 mov esi,stream_fixture
 mov ecx,4
 call stream_rx_push
 jc .fail
 cmp dword [stream_rx_tail],2
 jne .fail
 mov edi,stream_test_out
 mov ecx,2
 call stream_rx_read
 cmp eax,2
 jne .fail
 cmp word [stream_test_out],0201h
 jne .fail
 cmp dword [stream_rx_used],2
 jne .fail
 mov ecx,STREAM_CAPACITY-1
 call stream_rx_push
 jnc .fail
 cmp dword [stream_rx_used],2
 jne .fail
 mov edi,stream_test_out+2
 mov ecx,4
 call stream_rx_read
 cmp eax,2
 jne .fail
 cmp dword [stream_test_out],04030201h
 jne .fail
 cmp dword [stream_rx_used],0
 jne .fail
 call stream_reset
 mov esi,stream_test_pass
 jmp .emit
.fail:
 call stream_reset
 mov esi,stream_test_fail
.emit:
 lodsb
 test al,al
 jz .return
 out 0e9h,al
 jmp .emit
.return:
 ret
stream_fixture db 1,2,3,4
stream_test_out rb 4
stream_test_pass db 'TEXTOS STREAM SELFTEST PASS',10,0
stream_test_fail db 'TEXTOS STREAM SELFTEST FAIL',10,0
stream_mode db 0
stream_eof db 0
stream_http_probe db 0
stream_http_offset dd 0
stream_rx_head dd 0
stream_rx_tail dd 0
stream_rx_used dd 0
stream_peer_window dd 0
stream_write_result dd 0
