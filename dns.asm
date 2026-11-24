; 0.7.1: one outstanding DNS A query for info.cern.ch.
; Source/destination tuple, transaction ID, question and answer owner verified.
; Supports directly returned A records, including compressed owner pointer to question.
; No CNAME following, TCP fallback, DNSSEC or arbitrary hostname entry.
dns_start:
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
 rdtsc
 xor eax,edx
 mov [dns_id],ax
 shr eax,16
 and ax,3fffh
 or ax,0c000h
 xchg al,ah
 mov [dns_port],ax
 mov byte [dns_elapsed],0
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
 mov eax,[dhcp_dns_ip]
 mov [tx_frame+30],eax
 mov ax,[dns_port]
 mov [tx_frame+34],ax
 mov word [tx_frame+36],3500h
 mov ax,dns_query_end-dns_query+8
 xchg al,ah
 mov [tx_frame+38],ax
 mov ax,dns_query_end-dns_query+28
 xchg al,ah
 mov [tx_frame+16],ax
 mov esi,dns_query
 mov edi,tx_frame+42
 mov ecx,dns_query_end-dns_query
 rep movsb
 mov ax,[dns_id]
 mov [tx_frame+42],ax
 ; IPv4 UDP checksum zero is permitted.
 mov esi,tx_frame+14
 mov ecx,20
 call checksum
 mov [tx_frame+24],ax
 mov esi,tx_frame
 mov ecx,42+dns_query_end-dns_query
 call ne_send_buffer
 inc dword [dns_tx]
 popad
 ret

dns_receive:
 cmp byte [dns_state],1
 jne .done
 mov eax,dword [net_rx_buffer+26]
 cmp eax,[dhcp_dns_ip]
 jne .done
 mov eax,dword [net_rx_buffer+30]
 cmp eax,dword [local_ip]
 jne .done
 mov ax,[dns_port]
 cmp word [net_rx_buffer+36],ax
 jne .done
 mov ax,[dns_id]
 cmp word [net_rx_buffer+42],ax
 jne .done
 movzx ecx,word [net_rx_buffer+38]
 xchg cl,ch
 cmp ecx,8+dns_query_end-dns_query
 jb .done
 lea ebx,[net_rx_buffer+34+ecx] ; exclusive UDP end
 mov ax,word [net_rx_buffer+44]
 xchg al,ah
 test ax,8000h
 jz .done
 test ax,7a0fh ; unsupported opcode, truncated, or error
 jnz .failed
 cmp word [net_rx_buffer+46],0100h
 jne .failed
 cmp word [net_rx_buffer+48],0
 je .failed
 ; Match exact question (fixed lower-case wire name).
 mov esi,net_rx_buffer+54
 mov edi,dns_question
 mov ecx,dns_query_end-dns_question
 repe cmpsb
 jne .failed
 inc dword [dns_rx]
 ; First answer must match the queried name, compressed or uncompressed.
 lea eax,[esi+2]
 cmp eax,ebx
 ja .failed
 cmp word [esi],0cc0h
 je .compressed
 mov edi,dns_question
 mov ecx,dns_qname_end-dns_question
 lea eax,[esi+ecx]
 cmp eax,ebx
 ja .failed
 repe cmpsb
 jne .failed
 jmp .record
.compressed:
 add esi,2
.record:
 lea eax,[esi+14]
 cmp eax,ebx
 ja .failed
 cmp word [esi],0100h
 jne .failed
 cmp word [esi+2],0100h
 jne .failed
 cmp word [esi+8],0400h
 jne .failed
 mov eax,dword [esi+10]
 test eax,eax
 jz .failed
 cmp eax,0ffffffffh
 je .failed
 mov [dns_result],eax
 mov dword [remote_ip],eax
 mov dword [http_request_ptr],cern_get
 mov dword [http_request_len],cern_get_end-cern_get
 mov byte [dns_state],2
 call tcp_syn_probe
 ret
.failed:
 mov byte [dns_state],3
.done:
 ret

dns_tick:
 cmp byte [dns_state],1
 jne .done
 add al,[dns_elapsed]
 mov [dns_elapsed],al
 cmp al,8
 jb .done
 mov byte [dns_state],3
.done:
 ret

dns_state db 0
dns_elapsed db 0
dns_id dw 0
dns_port dw 0
dns_result dd 0
dns_tx dd 0
dns_rx dd 0
dns_query:
 dw 0,0001h,0100h,0,0,0
dns_question:
 db 4,'info',4,'cern',2,'ch',0
dns_qname_end:
 dw 0100h,0100h
dns_query_end:
cern_get db 'GET / HTTP/1.0',13,10,'Host: info.cern.ch',13,10,'Connection: close',13,10,13,10
cern_get_end:
