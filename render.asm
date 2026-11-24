; 0.7.8: bounded non-executing HTML text renderer.
; Render from scratch each time; page index is independent of raw view.
; Only ASCII output, bounded word buffer and screen writes.
text_page_up:
 cmp dword [render_page],0
 je text_view
 dec dword [render_page]
 jmp text_view
text_page_down:
 cmp byte [render_more],1
 jne text_view
 inc dword [render_page]
 jmp text_view
text_view:
 cmp byte [diagnostic_mode],1
 je .keep_diag
 call browser_chrome
.keep_diag:
 mov edi,0xb8000+160*4
 mov ecx,80*20
 mov ax,1f20h
 rep stosw
 mov edi,0xb8000+160*4
 mov esi,nav_address_label
 call print
 mov esi,nav_current
 call print
 mov byte [nav_view],1
 mov dword [nav_link_count],0
 mov byte [render_anchor],0
 mov byte [render_more],0 ; FIX: stale scroll state after empty/partial response.
 mov esi,HTTP_BUFFER
 mov ecx,[http_stored]
 test ecx,ecx
 jnz .find_body
 mov esi,http_empty_msg
 call print
 jmp main
.find_body:
 cmp ecx,4
 jb .done
 cmp dword [esi],0a0d0a0dh
 je .body
 inc esi
 dec ecx
 jmp .find_body
.body:
 add esi,4
 sub ecx,4
 mov [render_end],esi
 add [render_end],ecx
 mov dword [render_row],0
 mov dword [render_col],0
 mov dword [render_word_len],0
 mov byte [render_space],0
 mov byte [render_hidden],0
 mov byte [render_select],0
 mov byte [render_more],0
.loop:
 cmp esi,[render_end]
 jae .finish
 lodsb
 cmp al,'<'
 je .tag
 cmp byte [render_hidden],0
 jne .loop
 cmp byte [render_select],0
 jne .loop
 cmp al,'&'
 je .entity
 cmp al,32
 jbe .whitespace
 cmp al,126
 jbe .char
 mov al,'.'
.char:
 call render_append
 jmp .loop
.whitespace:
 call render_flush
 mov byte [render_space],1
 jmp .loop
.entity:
 mov edx,[render_end]
 sub edx,esi
 cmp edx,5
 jb .amp_check
 cmp dword [esi],7073626eh ; nbsp
 jne .amp_check
 cmp byte [esi+4],';'
 jne .amp_check
 add esi,5
 jmp .whitespace
.amp_check:
 cmp edx,4
 jb .entity_short
 cmp dword [esi],3b706d61h
 jne .entity_short
 add esi,4
 mov al,'&'
 jmp .char
.entity_short:
 cmp edx,3
 jb .literal
 cmp byte [esi+2],';'
 jne .literal
 cmp word [esi],746ch
 jne .gt
 mov al,'<'
 jmp .consume3
.gt:
 cmp word [esi],7467h
 jne .literal
 mov al,'>'
.consume3:
 add esi,3
 jmp .char
.literal:
 mov al,'&'
 jmp .char
.tag:
 cmp byte [render_hidden],0
 je .normal_tag
 mov eax,[render_end]
 sub eax,esi
 cmp eax,7
 jb .finish
 cmp byte [esi],'/'
 jne .loop
 mov eax,[esi+1]
 or eax,20202020h
 cmp byte [render_hidden],1
 jne .raw_script
 cmp eax,6c797473h
 jne .loop
 mov al,[esi+5]
 or al,20h
 cmp al,'e'
 jne .loop
 lea edx,[esi+6]
 jmp .raw_delimiter
.raw_script:
 mov edx,[render_end]
 sub edx,esi
 cmp edx,8
 jb .finish
 cmp eax,69726373h
 jne .loop
 mov ax,[esi+5]
 or ax,2020h
 cmp ax,7470h
 jne .loop
 lea edx,[esi+7]
.raw_delimiter:
 ; FIX: closing raw tags may have ASCII whitespace before >.
 mov al,[edx]
 cmp al,'>'
 je .normal_tag
 cmp al,32
 je .normal_tag
 cmp al,9
 je .normal_tag
 cmp al,10
 je .normal_tag
 cmp al,13
 jne .loop
.normal_tag:
 ; Comments: consume through -->, including embedded > characters.
 mov eax,[render_end]
 sub eax,esi
 cmp eax,3
 jb .finish
 cmp word [esi],2d21h
 jne .tag_name
 cmp byte [esi+2],'-'
 jne .tag_name
 add esi,3
.comment:
 mov eax,[render_end]
 sub eax,esi
 cmp eax,3
 jb .finish
 cmp word [esi],2d2dh
 jne .comment_next
 cmp byte [esi+2],'>'
 je .comment_end
.comment_next:
 inc esi
 jmp .comment
.comment_end:
 add esi,3
 jmp .loop
.tag_name:
 ; Parse exact tag name; case-insensitive, bounded to 15 chars.
 mov byte [render_closing],0
 cmp byte [esi],'/'
 jne .name_start
 inc esi
 mov byte [render_closing],1
.name_start:
 mov edi,render_tag
 xor eax,eax
 mov ecx,4
 rep stosd
 mov edi,render_tag
 xor ecx,ecx
.name_loop:
 cmp esi,[render_end]
 jae .finish
 mov al,[esi]
 or al,20h
 cmp al,'a'
 jb .number
 cmp al,'z'
 jbe .name_char
.number:
 cmp al,'0'
 jb .name_done
 cmp al,'9'
 ja .name_done
.name_char:
 cmp ecx,15
 jae .name_skip
 stosb
 inc ecx
.name_skip:
 inc esi
 jmp .name_loop
.name_done:
 mov byte [edi],0
 ; FIX: custom tags such as style-custom must not be treated as style.
 mov al,[esi]
 cmp al,'>'
 je .valid_delimiter
 cmp al,'/'
 je .valid_delimiter
 cmp al,32
 jbe .valid_delimiter
 mov byte [render_tag],0
.valid_delimiter:
 mov [nav_attr_start],esi
 ; Skip attributes, respecting single/double quotes.
 xor edx,edx
.attr:
 cmp esi,[render_end]
 jae .finish
 lodsb
 test dl,dl
 jnz .quoted
 cmp al,34
 je .quote
 cmp al,39
 je .quote
 cmp al,'>'
 je .classify
 jmp .attr
.quote:
 mov dl,al
 jmp .attr
.quoted:
 cmp al,dl
 jne .attr
 xor edx,edx
 jmp .attr
.classify:
 ; Style/script are raw-text blocks. Suppress their content until matching close.
 cmp dword [render_tag],6c797473h ; styl
 jne .script
 cmp word [render_tag+4],0065h
 jne .script
 mov al,1
 jmp .hidden_tag
.script:
 cmp dword [render_tag],69726373h ; scri
 jne .visible
 cmp dword [render_tag+4],00007470h
 jne .visible
 mov al,2
.hidden_tag:
 cmp byte [render_closing],1
 je .close_hidden
 cmp byte [render_hidden],0
 jne .loop
 mov [render_hidden],al
 jmp .loop
.close_hidden:
 cmp al,[render_hidden]
 jne .loop
 mov byte [render_hidden],0
 jmp .loop
.visible:
 cmp byte [render_hidden],0
 jne .loop
 cmp dword [render_tag],656c6573h ; sele
 jne .select_done
 cmp dword [render_tag+4],00007463h ; ct
 jne .select_done
 cmp byte [render_closing],1
 je .select_close
 mov byte [render_select],1
 jmp .loop
.select_close:
 mov byte [render_select],0
 jmp .loop
.select_done:
 cmp byte [render_select],0
 jne .loop
 cmp word [render_tag],0061h
 jne .not_anchor
 cmp byte [render_closing],0
 jne .anchor_close
 call render_flush
 mov eax,[nav_link_count]
 push eax
 call nav_capture_link
 pop eax
 cmp eax,[nav_link_count]
 je .not_anchor
 mov byte [render_anchor],1
 jmp .not_anchor
.anchor_close:
 call render_flush
 mov byte [render_anchor],0
.not_anchor:
 ; Exact block tag names, not prefixes.
 cmp word [render_tag],0070h
 je .block
 cmp dword [render_tag],00766964h
 je .block
 cmp dword [render_tag],00007262h
 je .block
 cmp dword [render_tag],00007268h
 je .block
 cmp dword [render_tag],0000696ch
 je .block
 cmp dword [render_tag],6c746974h ; titl
 jne .heading
 cmp word [render_tag+4],0065h
 je .block
.heading:
 cmp byte [render_tag],'h'
 jne .loop
 cmp byte [render_tag+2],0
 jne .loop
 mov al,[render_tag+1]
 cmp al,'1'
 jb .loop
 cmp al,'6'
 ja .loop
.block:
 call render_flush
 call render_break
 jmp .loop
.finish:
 call render_flush
.done:
 jmp main

; AL character. Buffer a word, split very long tokens safely.
render_append:
 push eax
 cmp dword [render_word_len],80
 jb .room
 call render_flush
.room:
 pop eax
 mov edx,[render_word_len]
 mov [render_word+edx],al
 inc dword [render_word_len]
 ret
render_flush:
 pushad
 mov ecx,[render_word_len]
 test ecx,ecx
 jz .done
 mov eax,[render_col]
 test eax,eax
 jz .emit
 mov edx,eax
 add edx,ecx
 movzx ebx,byte [render_space]
 add edx,ebx
 cmp edx,80
 jbe .space
 call render_break
 jmp .emit
.space:
 test ebx,ebx
 jz .emit
 mov al,' '
 call render_emit
.emit:
 mov esi,render_word
 mov ecx,[render_word_len]
.next:
 lodsb
 call render_emit
 loop .next
 mov dword [render_word_len],0
 mov byte [render_space],0
.done:
 popad
 ret
render_break:
 cmp dword [render_col],0
 je .done
 inc dword [render_row]
 mov dword [render_col],0
.done:
 mov byte [render_space],0
 ret
render_emit:
 pushad
 mov ebx,[render_page]
 imul ebx,18
 mov edx,[render_row]
 sub edx,ebx
 jc .advance
 cmp edx,18
 jb .write
 mov byte [render_more],1
 jmp .advance
.write:
 imul edx,160
 mov ebx,[render_col]
 lea edi,[0xb8000+160*6+edx+ebx*2]
 mov ah,1fh
 cmp byte [render_anchor],1
 jne .plain
 mov ah,1bh ; cyan text on blue
.plain:
 stosw
.advance:
 inc dword [render_col]
 cmp dword [render_col],80
 jb .done
 inc dword [render_row]
 mov dword [render_col],0
.done:
 popad
 ret
render_end dd 0
render_page dd 0
render_row dd 0
render_col dd 0
render_word_len dd 0
render_space db 0
render_hidden db 0
render_select db 0
render_anchor db 0
render_closing db 0
render_more db 0
render_tag rb 16
render_word rb 80
