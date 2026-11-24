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
 mov dword [tls_engine_state],0
 mov dword [tls_record_tx],0
 mov dword [tls_record_rx],0
 mov dword [tls_last_error],0
 mov eax,1
 xor edx,edx
 call tls_call
 cmp eax,1
 jne .preflight_failed
 mov dword [remote_ip],01010101h
 mov word [tcp_remote_port],0bb01h ; network-order port 443
 call stream_open
 jc .cancel_ready
 mov byte [stream_tls_probe],1
 mov dword [tls_live_status],1
 jmp tls_info
.cancel_ready:
 call tls_cancel
.not_ready:
 mov dword [tls_live_status],0bad00103h
 jmp tls_info
.preflight_failed:
 mov [tls_live_status],eax
 jmp tls_info

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
 test eax,24 ; BR_SSL_SENDAPP or RECVAPP: never allowed in this diagnostic
 jnz .unexpected_app
 mov dword [tls_live_status],2
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
