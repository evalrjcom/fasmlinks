; TextOS 0.9.2 keyboard Links-style navigation. 72-byte URL ceiling.
; First nine supported links per document, absolute HTTP(S) or root-relative.
; No script execution, POST forms, cookies, or automatic redirect following.
nav_commit:
 pushad
 cmp byte [nav_no_history],1
 je .current
 mov esi,nav_current
 mov edi,nav_previous
 mov ecx,73
 rep movsb
.current:
 mov byte [nav_no_history],0
 mov esi,url_input
 mov edi,nav_current
 mov ecx,73
 rep movsb
 mov byte [nav_search],0
 mov dword [nav_link_count],0
 popad
 ret
nav_loading:
 mov byte [nav_loading_flag],1
 mov byte [nav_view],0
 mov dword [http_stored],0
 mov edi,0b8000h+160*4
 mov ecx,80*20
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h+160*4
 mov esi,nav_loading_msg
 call print
 mov esi,nav_current
 call print
 jmp main
nav_poll:
 cmp byte [nav_loading_flag],1
 jne .done
 cmp byte [suite_stage],0
 jne .cancel
 cmp byte [dns_state],1
 je .done
 cmp byte [dns_state],4
 je .done
 cmp byte [tcp_state],1
 je .done
 cmp byte [tcp_state],2
 je .done
 cmp byte [stream_tls_probe],1
 je .done
 mov byte [nav_loading_flag],0
 ; Reuse the existing renderer's jump to main only when no return address remains.
 cmp dword [http_stored],0
 je .done
 pop eax
 jmp text_view
.cancel:
 mov byte [nav_loading_flag],0
.done:
 ret
nav_reload:
 mov esi,nav_current
 jmp nav_reopen
nav_back:
 mov esi,nav_previous
nav_reopen:
 cmp byte [esi],0
 je main
 mov edi,url_input
 xor ecx,ecx
.copy:
 lodsb
 stosb
 test al,al
 jz .submit
 inc ecx
 cmp ecx,72
 jb .copy
 mov byte [edi],0
.submit:
 mov [url_len],cl
 mov byte [url_editing],1
 jmp url_submit
nav_search_open:
 mov byte [nav_search],1
 mov byte [url_editing],1
 mov byte [url_shift],0
 mov byte [url_len],0
 mov byte [url_input],0
 mov esi,nav_search_prompt
 jmp url_draw
nav_search_submit:
 ; Only alnum, space and hyphen; spaces converted to +. Reject other input.
 mov esi,url_input
 mov edi,nav_search_tmp
 xor ecx,ecx
.loop:
 lodsb
 test al,al
 jz .build
 cmp ecx,37
 jae .bad
 cmp al,' '
 jne .check
 mov al,'+'
 jmp .put
.check:
 cmp al,'-'
 je .put
 cmp al,'0'
 jb .bad
 cmp al,'9'
 jbe .put
 or al,20h
 cmp al,'a'
 jb .bad
 cmp al,'z'
 ja .bad
.put:
 stosb
 inc ecx
 jmp .loop
.build:
 test ecx,ecx
 jz .bad
 mov byte [edi],0
 mov edi,url_input
 mov esi,nav_ddg
 mov ecx,nav_ddg_end-nav_ddg
 rep movsb
 mov esi,nav_search_tmp
.copy:
 lodsb
 stosb
 test al,al
 jnz .copy
 mov eax,edi
 sub eax,url_input+1
 mov [url_len],al
 mov byte [nav_search],0
 jmp url_submit
.bad:
 mov esi,nav_search_bad
 jmp url_draw

; Called only on visible opening A tags after bounded tag scan.
; Parse complete attribute names and quoted/unquoted values; never execute HTML.
nav_capture_link:
 pushad
 cmp dword [nav_link_count],9
 jae .done
 mov ebp,esi ; exclusive end of tag
 mov esi,[nav_attr_start]
.attr:
 cmp esi,ebp
 jae .done
 lodsb
 cmp al,32
 jbe .attr
 cmp al,'>'
 je .done
 dec esi
 mov ebx,esi
.name:
 cmp esi,ebp
 jae .done
 mov al,[esi]
 cmp al,32
 jbe .name_end
 cmp al,'='
 je .name_end
 cmp al,'>'
 je .done
 inc esi
 jmp .name
.name_end:
 mov edx,esi
 sub edx,ebx
.skip_ws:
 cmp esi,ebp
 jae .done
 cmp byte [esi],32
 ja .eq
 inc esi
 jmp .skip_ws
.eq:
 cmp byte [esi],'='
 jne .attr
 inc esi
.val_ws:
 cmp esi,ebp
 jae .done
 cmp byte [esi],32
 ja .quote
 inc esi
 jmp .val_ws
.quote:
 xor ecx,ecx
 mov al,[esi]
 cmp al,34
 je .quoted
 cmp al,39
 jne .value
.quoted:
 mov cl,al
 inc esi
.value:
 mov edi,esi
.scan:
 cmp esi,ebp
 jae .done
 mov al,[esi]
 test cl,cl
 jz .unquoted
 cmp al,cl
 je .end_value
 inc esi
 jmp .scan
.unquoted:
 cmp al,32
 jbe .end_value
 cmp al,'>'
 je .end_value
 inc esi
 jmp .scan
.end_value:
 push esi
 cmp edx,4
 jne .next
 mov eax,[ebx]
 or eax,20202020h
 cmp eax,66657268h ; href
 jne .next
 mov ecx,esi
 sub ecx,edi
 cmp ecx,1
 jb .next
 cmp ecx,72
 ja .next
 mov esi,edi
 call nav_store_link
 pop esi
 jmp .done
.next:
 pop esi
 inc esi
 jmp .attr
.done:
 popad
 ret
; ESI raw href, ECX length. Accept safe ASCII only, no fragment or entity decoding.
nav_store_link:
 pushad
 mov ebx,[nav_link_count]
 imul ebx,73
 lea edi,[nav_links+ebx]
 mov edx,edi
 cmp ecx,7
 jb .relative
 cmp dword [esi],70747468h
 jne .relative
 cmp word [esi+4],2f3ah
 jne .https
 cmp byte [esi+6],'/'
 je .copy
.https:
 cmp ecx,8
 jb .bad
 cmp dword [esi+4],2f2f3a73h
 je .copy
.relative:
 cmp byte [esi],'/'
 jne .bad
 cmp ecx,2
 jb .root
 cmp byte [esi+1],'/'
 je .bad
.root:
 push esi
 push ecx
 mov esi,nav_current
 xor ecx,ecx
 ; copy authority with scheme, stopping at first path slash after prefix.
 cmp dword [esi],70747468h
 jne .root_bad
 mov ecx,7
 cmp byte [esi+4],'s'
 jne .prefix
 inc ecx
.prefix:
 rep movsb
.authority:
 lodsb
 test al,al
 jz .root_done
 cmp al,'/'
 je .root_done
 stosb
 jmp .authority
.root_done:
 pop ecx
 pop esi
 mov eax,edi
 sub eax,edx
 add eax,ecx
 cmp eax,72
 ja .bad
 jmp .copy
.root_bad:
 pop ecx
 pop esi
 jmp .bad
.copy:
 lodsb
 cmp al,33
 jb .bad
 cmp al,126
 ja .bad
 cmp al,'#'
 je .bad
 cmp al,'&'
 je .bad
 stosb
 loop .copy
 mov byte [edi],0
 inc dword [nav_link_count]
 ; Insert a numbered marker before link label.
 call render_flush
 mov al,'['
 call render_append
 mov eax,[nav_link_count]
 add al,'0'
 call render_append
 mov al,']'
 call render_append
 call render_flush
 mov byte [render_space],1
.bad:
 popad
 ret
nav_links_view:
 mov byte [nav_choosing],1
 mov edi,0b8000h+160*4
 mov ecx,80*20
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h+160*4
 mov esi,nav_links_title
 call print
 xor ebp,ebp
.row:
 cmp ebp,[nav_link_count]
 jae .done
 mov esi,nav_link_line
 call print
 mov eax,ebp
 add al,'1'
 mov ah,1fh
 stosw
 mov al,' '
 stosw
 imul esi,ebp,73
 add esi,nav_links
 call print
 inc ebp
 jmp .row
.done:
 jmp main
nav_link_key:
 cmp al,1
 je .exit
 cmp al,2
 jb main
 cmp al,10
 ja main
 movzx eax,al
 sub eax,2
 cmp eax,[nav_link_count]
 jae main
 mov byte [nav_choosing],0
 imul esi,eax,73
 add esi,nav_links
 jmp nav_reopen
.exit:
 mov byte [nav_choosing],0
 jmp text_view
nav_current rb 73
nav_previous rb 73
nav_search_tmp rb 38
nav_links rb 9*73
nav_link_count dd 0
nav_attr_start dd 0
nav_no_history db 0
nav_search db 0
nav_view db 0
nav_choosing db 0
nav_loading_flag db 0
nav_last_scan db 0
nav_address_label db 'URL: ',0
nav_loading_msg db 'Loading: ',0
nav_search_prompt db 'DuckDuckGo Lite search (letters, digits, spaces; max 37)',10,'Enter to search; Esc cancels',0
nav_search_bad db 'Use 1-37 letters, digits, spaces or hyphens.',0
nav_ddg db 'https://lite.duckduckgo.com/lite/?q='
nav_ddg_end:
nav_links_title db 'LINKS: select 1-9; Esc returns to page',0
nav_link_line db 10,0
nav_shift_keys:
 db 0,0,'!','@','#','$','%','^','&','*','(',')','_','+',0,0
 db 'Q','W','E','R','T','Y','U','I','O','P',0,0,0,0
 db 'A','S','D','F','G','H','J','K','L',':',0,0,0,0
 db 'Z','X','C','V','B','N','M',0,0,'?',0,0,0,0,0,0,0,0
