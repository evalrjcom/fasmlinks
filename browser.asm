; 0.7.5: bounded interactive numeric IPv4 HTTP address entry.
; Syntax: IPv4/path, optional http:// prefix. Port 80 only.
; DNS and HTTPS are not silently substituted.
url_open:
 mov byte [url_editing],1
 mov byte [url_len],0
 mov byte [url_input],0
 mov esi,url_prompt
 jmp url_draw
url_key:
 test al,80h
 jnz main
 cmp al,1
 je .escape
 cmp al,1ch
 je url_submit
 cmp al,0eh
 je .back
 cmp al,58
 jae main
 movzx eax,al
 mov al,[url_keys+eax]
 test al,al
 jz main
 movzx ecx,byte [url_len]
 cmp ecx,72
 jae main
 mov [url_input+ecx],al
 inc ecx
 mov byte [url_input+ecx],0
 mov [url_len],cl
 jmp .redraw
.back:
 cmp byte [url_len],0
 je main
 dec byte [url_len]
 movzx ecx,byte [url_len]
 mov byte [url_input+ecx],0
.redraw:
 mov esi,url_prompt
 jmp url_draw
.escape:
 mov byte [url_editing],0
 jmp home
url_draw:
 mov edi,0b8000h+160*4
 mov ecx,80*20
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h+160*4
 call print
 mov edi,0b8000h+160*9
 mov esi,url_input
 call print
 jmp main

url_submit:
 ; Parse exactly four decimal octets; no overflow, signs or empty fields.
 mov esi,url_input
 cmp dword [esi],70747468h
 jne .parse
 cmp word [esi+4],2f3ah
 jne .parse
 cmp byte [esi+6],'/'
 jne .parse
 add esi,7
.parse:
 mov [url_host_start],esi
 mov edi,url_ip
 mov ecx,4
.octet:
 xor eax,eax
 xor ebx,ebx
.digit:
 movzx edx,byte [esi]
 sub edx,'0'
 cmp edx,9
 ja .end_octet
 inc ebx
 cmp ebx,3
 ja .bad
 imul eax,10
 add eax,edx
 cmp eax,255
 ja .bad
 inc esi
 jmp .digit
.end_octet:
 test ebx,ebx
 jz .bad
 stosb
 dec ecx
 jz .host_done
 cmp byte [esi],'.'
 jne .bad
 inc esi
 jmp .octet
.host_done:
 mov [url_host_end],esi
 cmp byte [esi],0
 je .path_ok
 cmp byte [esi],'/'
 jne .bad
.path_ok:
 mov [url_path],esi
 cmp dword [url_ip],0
 je .bad
 cmp dword [url_ip],0ffffffffh
 je .bad
 ; Only use established gateway routing; reject on-link destinations
 ; since the current transport has no per-host ARP cache.
 mov eax,dword [url_ip]
 xor eax,dword [local_ip]
 and eax,[dhcp_subnet]
 jz .bad
 cmp byte [dhcp_state],3
 jne .not_ready
 cmp byte [gateway_known],1
 jne .not_ready
 cmp byte [tcp_state],1
 je .busy
 cmp byte [tcp_state],2
 je .busy
 cmp byte [dns_state],1
 je .busy
 cmp byte [dns_state],4
 je .busy
 ; Construct bounded request from validated input (no CR/LF possible).
 mov edi,url_request
 mov esi,url_get
 mov ecx,url_get_end-url_get
 rep movsb
 mov esi,[url_path]
 cmp byte [esi],0
 jne .copy_path
 mov al,'/'
 stosb
 jmp .version
.copy_path:
 lodsb
 test al,al
 jz .version
 stosb
 jmp .copy_path
.version:
 mov esi,url_version
 mov ecx,url_version_end-url_version
 rep movsb
 mov esi,[url_host_start]
 mov ecx,[url_host_end]
 sub ecx,esi
 rep movsb
 mov esi,url_tail
 mov ecx,url_tail_end-url_tail
 rep movsb
 mov eax,edi
 sub eax,url_request
 mov [http_request_len],eax
 mov dword [http_request_ptr],url_request
 mov eax,dword [url_ip]
 mov dword [remote_ip],eax
 mov word [tcp_remote_port],5000h
 mov byte [url_editing],0
 call tcp_syn_probe
 jmp network_detail
.bad:
 mov esi,url_bad
 jmp url_draw
.not_ready:
 mov esi,url_not_ready
 jmp url_draw
.busy:
 mov esi,url_busy
 jmp url_draw

url_prompt db 'OPEN HTTP ADDRESS',10,10,'Enter IPv4/path (port 80 only).',10,'Enter: connect   Backspace: edit   Esc: cancel',10,0
url_bad db 'Invalid address. Use a remote IPv4 address and optional /path.',10,'HTTPS, hostnames and custom ports are not supported here.',0
url_not_ready db 'Network not ready. Escape and check DHCP / ARP.',0
url_busy db 'Connection busy. Retry after timeout or Escape.',0
url_editing db 0
url_len db 0
url_ip dd 0
url_host_start dd 0
url_host_end dd 0
url_path dd 0
url_input rb 73
url_request rb 256
url_get db 'GET '
url_get_end:
url_version db ' HTTP/1.0',13,10,'Host: '
url_version_end:
url_tail db 13,10,'Connection: close',13,10,13,10
url_tail_end:
; Set-1 unshifted scan code table. Only safe ASCII URL characters.
url_keys:
 db 0,0,49,50,51,52,53,54,55,56,57,48,45,0,0,0,113,119,101,114,116,121,117,105,111,112,0,0,0,0,97,115,100,102,103,104,106,107,108,0,0,0,0,0,122,120,99,118,98,110,109,0,46,47,0,0,0,0
