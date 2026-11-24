; F12 automated end-to-end diagnostic suite. One connection at a time.
; Results: 0 pending, 1 pass, 2 fail, 3 skipped. No TLS bypass.
suite_start:
 call tls_cancel
 call suite_abort_tcp
 mov byte [url_editing],0
 mov edi,suite_results
 xor eax,eax
 mov ecx,8
 rep stosd
 mov dword [suite_http_bytes],0
 mov dword [suite_https_bytes],0
 mov dword [suite_tls_tx],0
 mov dword [suite_tls_rx],0
 mov dword [suite_tls_error],0
 mov dword [suite_tls_status],0
 mov byte [suite_stage],1
 mov dword [suite_elapsed],0
 mov byte [suite_dirty],1
 cmp dword [tls_probe_result],544c5333h
 jne .offline_bad
 mov byte [suite_results+0],1
 jmp main
.offline_bad:
 mov byte [suite_results+0],2
 jmp main
suite_abort_tcp:
 cmp byte [tcp_state],2
 jne .clear
 mov byte [tcp_flags],14h
 xor ecx,ecx
 call tcp_send_segment
.clear:
 mov byte [tcp_state],0
 mov byte [dns_state],0
 mov byte [stream_mode],0
 call stream_reset
 ret
suite_cancel:
 call tls_cancel
 call suite_abort_tcp
 mov byte [suite_stage],0
 jmp home
; called once per elapsed RTC second, even before DHCP bound.
suite_tick:
 cmp byte [suite_stage],0
 je .done
 cmp byte [suite_stage],9
 je .done
 movzx eax,al
 add [suite_elapsed],eax
 mov byte [suite_dirty],1
.done:
 ret
suite_poll:
 cmp byte [suite_stage],0
 je .done
 cmp byte [suite_stage],9
 je .draw
 cmp byte [suite_stage],1
 je .dhcp
 cmp byte [suite_stage],2
 je .arp
 cmp byte [suite_stage],3
 je .http
 cmp byte [suite_stage],4
 je .dns
 cmp byte [suite_stage],5
 je .port
 cmp byte [suite_stage],6
 je .tls
 jmp .draw
.dhcp:
 cmp byte [dhcp_state],3
 je .dhcp_ok
 cmp dword [suite_elapsed],60
 jb .draw
 mov byte [suite_results+1],2
 jmp .skip_network
.dhcp_ok:
 mov byte [suite_results+1],1
 mov byte [suite_stage],2
 jmp .advance
.arp:
 cmp byte [gateway_known],1
 je .arp_ok
 cmp dword [suite_elapsed],30
 jb .draw
 mov byte [suite_results+2],2
 jmp .skip_network
.arp_ok:
 mov byte [suite_results+2],1
 call suite_abort_tcp
 mov dword [remote_ip],01010101h
 mov word [tcp_remote_port],5000h
 call stream_open
 jc .http_failed
 mov byte [stream_http_probe],1
 mov dword [stream_http_offset],0
 mov byte [suite_stage],3
 jmp .advance
.http:
 cmp dword [http_stored],12
 jb .http_wait
 cmp dword [HTTP_BUFFER],50545448h
 jne .http_wait
 mov byte [suite_results+3],1
 jmp .http_next
.http_wait:
 cmp byte [tcp_state],3
 jae .http_failed
 cmp dword [suite_elapsed],45
 jb .draw
.http_failed:
 mov byte [suite_results+3],2
.http_next:
 mov eax,[http_stored]
 mov [suite_http_bytes],eax
 call suite_abort_tcp
 call dns_start
 mov byte [suite_stage],4
 jmp .advance
.dns:
 cmp byte [dns_state],2
 je .dns_ok
 cmp byte [dns_state],3
 je .dns_bad
 cmp dword [suite_elapsed],55
 jb .draw
.dns_bad:
 mov byte [suite_results+4],2
 jmp .port_start
.dns_ok:
 mov byte [suite_results+4],1
.port_start:
 call suite_abort_tcp
 mov dword [remote_ip],01010101h
 mov word [tcp_remote_port],0bb01h
 call stream_open
 jc .port_failed
 mov byte [port443_active],1
 mov byte [suite_stage],5
 jmp .advance
.port:
 cmp dword [probe_syn_ack],0
 jne .port_ok
 cmp byte [tcp_state],3
 jae .port_failed
 cmp dword [suite_elapsed],30
 jb .draw
.port_failed:
 mov byte [suite_results+5],2
 jmp .tls_start
.port_ok:
 mov byte [suite_results+5],1
.tls_start:
 call suite_abort_tcp
 mov esi,tls_fixed_host
 mov edi,tls_hostname
 mov ecx,15
 rep movsb
 mov dword [tls_hostname_len],15
 mov dword [remote_ip],01010101h
 mov dword [tls_request_ptr],http_get_request
 mov dword [tls_request_len],http_get_end-http_get_request
 call tls_connect
 mov byte [suite_stage],6
 jmp .advance
.tls:
 mov eax,[tls_record_tx]
 mov [suite_tls_tx],eax
 mov eax,[tls_record_rx]
 mov [suite_tls_rx],eax
 mov eax,[tls_last_error]
 mov [suite_tls_error],eax
 mov eax,[tls_live_status]
 mov [suite_tls_status],eax
 cmp byte [tls_authenticated],1
 jne .tls_wait
 mov byte [suite_results+6],1
 cmp dword [http_stored],12
 jb .tls_wait
 cmp dword [HTTP_BUFFER],50545448h
 jne .tls_wait
 mov byte [suite_results+7],1
 mov eax,[http_stored]
 mov [suite_https_bytes],eax
 ; Allow the remaining response to arrive; stop only on terminal state or deadline.
.tls_wait:
 cmp byte [stream_tls_probe],0
 je .tls_finish
 cmp dword [suite_elapsed],90
 jb .draw
.tls_finish:
 cmp byte [suite_results+6],1
 je .app_result
 mov byte [suite_results+6],2
.app_result:
 cmp byte [suite_results+7],1
 je .finish
 mov byte [suite_results+7],2
 jmp .finish
.skip_network:
 mov ecx,1
.skip_loop:
 cmp ecx,8
 jae .finish
 cmp byte [suite_results+ecx],0
 jne .skip_next
 mov byte [suite_results+ecx],3
.skip_next:
 inc ecx
 jmp .skip_loop
.finish:
 call tls_cancel
 call suite_abort_tcp
 mov byte [suite_stage],9
.advance:
 mov dword [suite_elapsed],0
 mov byte [suite_dirty],1
.draw:
 cmp byte [suite_dirty],1
 jne .done
 mov byte [suite_dirty],0
 call suite_draw
.done:
 ret
suite_draw:
 pushad
 mov edi,0b8000h+160*4
 mov ecx,80*20
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h+160*4
 mov esi,suite_title
 call print
 xor ebp,ebp
.row:
 mov esi,[suite_labels+ebp*4]
 call print
 movzx eax,byte [suite_results+ebp]
 mov esi,[suite_words+eax*4]
 call print
 inc ebp
 cmp ebp,8
 jb .row
 mov esi,suite_http_label
 call print
 mov eax,[suite_http_bytes]
 call print_hex32
 mov esi,suite_https_label
 call print
 mov eax,[suite_https_bytes]
 call print_hex32
 mov esi,suite_tx_label
 call print
 mov eax,[suite_tls_tx]
 call print_hex32
 mov esi,suite_rx_label
 call print
 mov eax,[suite_tls_rx]
 call print_hex32
 mov esi,suite_error_label
 call print
 mov eax,[suite_tls_error]
 call print_hex32
 mov esi,suite_status_label
 call print
 mov eax,[suite_tls_status]
 call print_hex32
 mov esi,suite_running
 cmp byte [suite_stage],9
 jne .state
 mov esi,suite_finished
.state:
 call print
 mov edi,0b8000h+160*24
 mov esi,suite_footer
 call print
 popad
 ret
suite_stage db 0
suite_dirty db 0
suite_elapsed dd 0
suite_results: times 32 db 0
suite_http_bytes dd 0
suite_https_bytes dd 0
suite_tls_tx dd 0
suite_tls_rx dd 0
suite_tls_error dd 0
suite_tls_status dd 0
suite_title db 'AUTOMATIC NETWORK / HTTPS TEST SUITE',10,0
suite_l0 db 10,'BearSSL offline self-test   : ',0
suite_l1 db 10,'DHCP lease                  : ',0
suite_l2 db 10,'Gateway ARP                 : ',0
suite_l3 db 10,'HTTP stream response        : ',0
suite_l4 db 10,'DNS info.cern.ch             : ',0
suite_l5 db 10,'TCP port 443                 : ',0
suite_l6 db 10,'TLS authenticated handshake  : ',0
suite_l7 db 10,'HTTPS response prefix        : ',0
suite_labels dd suite_l0,suite_l1,suite_l2,suite_l3,suite_l4,suite_l5,suite_l6,suite_l7
suite_words dd suite_pending,suite_pass,suite_fail,suite_skip
suite_pending db 'WAIT',0
suite_pass db 'PASS',0
suite_fail db 'FAIL',0
suite_skip db 'SKIP',0
suite_http_label db 10,10,'HTTP bytes : 0x',0
suite_https_label db '  HTTPS bytes : 0x',0
suite_tx_label db 10,'TLS TX     : 0x',0
suite_rx_label db '  TLS RX      : 0x',0
suite_error_label db 10,'TLS error  : 0x',0
suite_status_label db '  TLS status  : 0x',0
suite_running db 10,10,'Running automatically; no keys needed.',0
suite_finished db 10,10,'Finished. PASS response means prefix only, not full body.',0
suite_footer db 'F12 Run all | Esc Exit | 7 Raw HTTPS | 9 Text',0
