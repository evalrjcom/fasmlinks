; 0.9.3: separate browser and diagnostic modes. F10 toggles; F12 opens tests.
browser_tests:
 mov byte [diagnostic_mode],1
 mov byte [nav_loading_flag],0
 call diagnostic_chrome
 jmp suite_start
mode_toggle:
 cmp byte [suite_stage],0
 je .switch
 cmp byte [suite_stage],9
 jne main ; active tests must finish or be cancelled
 mov byte [suite_stage],0
.switch:
 mov byte [url_editing],0
 mov byte [nav_choosing],0
 xor byte [diagnostic_mode],1
 cmp byte [diagnostic_mode],1
 jne .browser
 mov byte [nav_loading_flag],0
 call diagnostic_chrome
 jmp network_detail
.browser:
 call browser_chrome
 cmp byte [nav_current],0
 je browser_home
 jmp text_view
browser_chrome:
 pushad
 mov edi,0b8000h
 mov ecx,80*25
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h
 mov esi,browser_brand
 call print
 mov edi,0b8000h+160*2
 mov esi,browser_menu
 call print
 call browser_footer_draw
 popad
 ret
browser_footer_draw:
 pushad
 mov edi,0b8000h+160*24
 mov ecx,80
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h+160*24
 mov esi,browser_footer
 call print
 popad
 ret
diagnostic_chrome:
 pushad
 mov edi,0b8000h
 mov ecx,80*25
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h
 mov esi,header
 call print
 mov edi,0b8000h+160*2
 mov esi,menu
 call print
 mov edi,0b8000h+160*24
 mov esi,diag_footer
 call print
 popad
 ret
browser_keys:
 cmp al,1
 je browser_help
 cmp al,3ch
 je url_open
 cmp al,3dh
 je nav_search_open
 cmp al,3eh
 je nav_back
 cmp al,3fh
 je nav_reload
 cmp al,57h
 je nav_links_view
 cmp al,49h
 je text_page_up
 cmp al,51h
 je text_page_down
 cmp al,48h
 je text_page_up
 cmp al,50h
 je text_page_down
 cmp al,0ah
 je text_view
 cmp al,3bh
 je browser_help
 cmp al,23h
 je browser_home
 jmp main
browser_home:
 call browser_chrome
 mov edi,0b8000h+160*5
 mov esi,browser_home_text
 call print
 jmp main
browser_help:
 call browser_chrome
 mov edi,0b8000h+160*4
 mov esi,browser_help_text
 call print
 jmp main
diagnostic_mode db 0
browser_brand db 'FASM Links 0.9.3 | Text browser',0
browser_menu db 'File     View     Link     Navigate     Search     Help',0
browser_footer db 'F2 Open | F3 Search | F4 Back | F5 Reload | F11 Links | F10 Mode | F1 Help',0
diag_footer db 'F10 Browser | F12 Tests | F6 HTTP | F7 TLS | F8 443 | F9 TCP | T TLS info',0
browser_home_text db 'DuckDuckGo Lite',10,10,'F3 Search the web',10,10,'F2 Open a website',10,'F11 Select links on the current page',10,10,'Press H for this home screen.',10,'F10 opens the separate diagnostics mode.',0
browser_help_text db 'Browser commands',10,10,'F2 Open URL     F3 Search     F4 Back     F5 Reload',10,'F11 Links      Up/Down or Page Up/Down scroll',10,'H Home         9 Current page',10,'F10 Diagnostics mode (toggle back with F10)',10,10,'Press Esc or F1 for help. F12 runs network tests.',0
