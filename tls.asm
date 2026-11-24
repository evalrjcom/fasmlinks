; 0.8.3: BearSSL diagnostic transport. No trust anchors; no app data.
; ABI: eax=op, edx=count. C returns eax, clobbers ecx/edx.
tls_call:
 push edx
 push tls_mailbox
 push eax
 mov eax,40000h
 call eax
 add esp,12
 ret

; F7 starts only after entropy preflight and network readiness.
tls_probe_open:
 cmp byte [tcp_state],1
 je tls_info
 cmp byte [tcp_state],2
 je tls_info
 cmp byte [dns_state],1
 je tls_info
 cmp byte [dns_state],4
 je tls_info
 cmp byte [dhcp_state],3
 jne .not_ready
 cmp byte [gateway_known],1
 jne .not_ready
 mov esi,tls_fixed_host
 mov edi,tls_hostname
 mov ecx,15
 rep movsb
 mov dword [tls_hostname_len],15
 mov dword [remote_ip],01010101h
 mov dword [tls_request_ptr],http_get_request
 mov dword [tls_request_len],http_get_end-http_get_request
 call tls_connect
 jmp tls_info
.not_ready:
 mov dword [tls_live_status],0bad00103h
 jmp tls_info

tls_url_connect:
 mov dword [tls_request_ptr],url_request
 mov eax,[url_request_length]
 mov [tls_request_len],eax
 jmp tls_connect
tls_connect:
 mov dword [tls_engine_state],0
 mov dword [tls_record_tx],0
 mov dword [tls_record_rx],0
 mov dword [tls_last_error],0
 mov dword [tls_mailbox],tls_hostname
 mov eax,[tls_hostname_len]
 mov [tls_mailbox+4],eax
 mov eax,1
 xor edx,edx
 call tls_call
 cmp eax,1
 jne .preflight_failed
 mov word [tcp_remote_port],0bb01h ; network-order port 443
 call stream_open
 jc .cancel_ready
 mov byte [stream_tls_probe],1
 mov dword [tls_live_status],1
 mov dword [tls_request_offset],0
 mov dword [http_stored],0
 mov dword [http_bytes],0
 mov dword [render_page],0
 mov dword [http_scroll],0
 mov dword [http_page_end],0
 ret
.cancel_ready:
 call tls_cancel
 mov dword [tls_live_status],0bad00103h
 ret
.preflight_failed:
 mov [tls_live_status],eax
 ret

; Poll bounded work; BearSSL spans remain valid until acknowledged.
tls_poll:
 cmp byte [stream_tls_probe],1
 jne .done
 cmp byte [stream_mode],1
 jne .aborted
 cmp word [tcp_remote_port],0bb01h
 jne .aborted
 cmp byte [tcp_state],1
 je .done
 cmp byte [tcp_state],2
 je .state
 cmp byte [tcp_state],5
 je .timeout
 cmp byte [tcp_state],4
 je .reset
 cmp byte [tcp_state],3
 jne .aborted
 cmp dword [stream_rx_used],0
 je .aborted
.state:
 mov eax,2
 xor edx,edx
 call tls_call
 mov [tls_engine_state],eax
 test eax,1 ; BR_SSL_CLOSED
 jnz .closed
 test eax,2
 jnz .record_state
 test eax,24
 jnz .application
 cmp dword [tls_live_status],4
 je .record_state
 mov dword [tls_live_status],2
.record_state:
 test eax,2 ; BR_SSL_SENDREC
 jz .receive
 mov eax,3
 xor edx,edx
 call tls_call
 test eax,eax
 jz .receive
 mov esi,[tls_mailbox]
 mov ecx,eax
 call stream_write
 test eax,eax
 jz .receive
 add [tls_record_tx],eax
 mov edx,eax
 mov eax,4
 call tls_call
 test eax,eax
 jz .aborted
.receive:
 mov eax,5
 xor edx,edx
 call tls_call
 test eax,eax
 jz .done
 mov edi,[tls_mailbox]
 mov ecx,eax
 call stream_rx_read
 test eax,eax
 jz .done
 add [tls_record_rx],eax
 mov edx,eax
 mov eax,6
 call tls_call
 test eax,eax
 jz .aborted
 cmp byte [tcp_state],2
 jne .done
 mov byte [tcp_flags],10h
 xor ecx,ecx
 call tcp_send_segment
.done:
 ret
.application:
 ; BearSSL exposes application spans only after successful authentication.
 mov dword [tls_live_status],4
 test eax,8 ; SENDAPP
 jz .read_app
 mov eax,[tls_request_offset]
 cmp eax,[tls_request_len]
 jae .read_app
 mov eax,9
 xor edx,edx
 call tls_call
 mov ecx,[tls_request_len]
 sub ecx,[tls_request_offset]
 cmp ecx,eax
 jbe .app_count
 mov ecx,eax
.app_count:
 test ecx,ecx
 jz .read_app
 mov esi,[tls_request_ptr]
 add esi,[tls_request_offset]
 mov edi,[tls_mailbox]
 add [tls_request_offset],ecx
 mov edx,ecx
 rep movsb
 mov eax,10
 call tls_call
 test eax,eax
 jz .aborted
.read_app:
 mov eax,11
 xor edx,edx
 call tls_call
 test eax,eax
 jz .done
 mov ecx,HTTP_CAPACITY
 sub ecx,[http_stored]
 cmp eax,ecx
 jbe .read_count
 mov eax,ecx
.read_count:
 test eax,eax
 jz .aborted
 mov esi,[tls_mailbox]
 mov edi,HTTP_BUFFER
 add edi,[http_stored]
 add [http_stored],eax
 add [http_bytes],eax
 mov ecx,eax
 mov edx,eax
 rep movsb
 mov eax,12
 call tls_call
 test eax,eax
 jz .aborted
 ret
.closed:
 mov eax,7
 xor edx,edx
 call tls_call
 mov [tls_last_error],eax
 mov dword [tls_live_status],3 ; engine closed, inspect error
 jmp tls_cancel
.unexpected_app:
 mov dword [tls_live_status],0bad00104h
 jmp tls_cancel
.timeout:
 mov dword [tls_live_status],0bad00106h
 jmp tls_cancel
.reset:
 mov dword [tls_live_status],0bad00107h
 jmp tls_cancel
.aborted:
 mov dword [tls_live_status],0bad00105h
 jmp tls_cancel

; Do not touch a replacement HTTP connection.
tls_cancel:
 cmp byte [stream_tls_probe],1
 jne .disable
 mov byte [stream_tls_probe],0
 cmp byte [stream_mode],1
 jne .disable
 cmp word [tcp_remote_port],0bb01h
 jne .disable
 cmp byte [tcp_state],2
 jne .stop
 mov byte [tcp_flags],14h
 xor ecx,ecx
 call tcp_send_segment
.stop:
 ; Preserve timeout/reset state for diagnosis.
 cmp byte [tcp_state],5
 je .disable
 mov byte [tcp_state],4
.disable:
 mov eax,8
 xor edx,edx
 call tls_call
 ret

tls_fixed_host db 'one.one.one.one'
tls_hostname rb 74
tls_hostname_len dd 0
tls_url_pending db 0
tls_request_ptr dd 0
tls_request_len dd 0
tls_request_offset dd 0
stream_tls_probe db 0
tls_mailbox dd 0,0
tls_live_status dd 0
tls_engine_state dd 0
tls_last_error dd 0
tls_record_tx dd 0
tls_record_rx dd 0
tls_live_label db 10,'F7 live diagnostic status: 0x',0
tls_error_label db 10,'BearSSL error: 0x',0
tls_tx_label db 10,'TLS record bytes queued: 0x',0
tls_rx_label db 10,'TLS record bytes received: 0x',0

tls_tcp_label db 10,'TCP state: 0x',0
tls_engine_label db 10,'BearSSL state bits: 0x',0
