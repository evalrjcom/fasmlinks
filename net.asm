; PCI-discovered NE2000 register-compatible device used by v86.
net_probe:
 ; v86 NE2K is a PCI device. Scan bus 0, device 0..31, function 0.
 ; PCI ID 10EC:8029 identifies its NE2000 register-compatible interface.
 mov dword [pci_cfg_addr],0x80000000
.scan:
 mov eax,[pci_cfg_addr]
 mov dx,0xCF8
 out dx,eax
 mov dx,0xCFC
 in eax,dx
 cmp eax,0x802910EC
 je .found
 add dword [pci_cfg_addr],0x800
 cmp dword [pci_cfg_addr],0x80010000
 jb .scan
 mov esi,net_missing
 mov [net_message],esi
 ret
.found:
 ; Read BAR0 and enable PCI I/O decoding (command bit 0).
 mov eax,[pci_cfg_addr]
 add eax,0x10
 mov dx,0xCF8
 out dx,eax
 mov dx,0xCFC
 in eax,dx
 test al,1
 jz .no_bar
 and eax,0xFFFFFFFC
 test ax,ax
 jz .no_bar
 cmp eax,0ffe0h ; FIX: require a representable I/O window including offset 1Fh
 ja .no_bar
 mov [net_port],ax
 mov eax,[pci_cfg_addr]
 add eax,4
 mov dx,0xCF8
 out dx,eax
 mov dx,0xCFC
 in ax,dx
 or ax,1
 out dx,ax ; FIX: do not write PCI status W1C bits
 ; Check whether the reset port produces an NE2000 reset-complete flag.
 mov dx,[net_port]
 add dx,0x1F
 in al,dx
 out dx,al
 mov bl,7
 mov ecx,100000
.wait_reset:
 call ne_in
 test al,0x80
 jnz .reset_ok
 loop .wait_reset
 mov esi,net_reset_fail
 mov [net_message],esi
 ret
.reset_ok:
 mov al,0x80
 call ne_out
 call ne_init
 mov byte [net_present],1
 mov esi,net_found
 mov [net_message],esi
 ret
.no_bar:
 mov esi,net_bar_fail
 mov [net_message],esi
 ret

; NE2000 register access, offset in BL, value AL
ne_out:
 push edx
 mov dx,[net_port]
 movzx bx,bl
 add dx,bx
 out dx,al
 pop edx
 ret
ne_in:
 push edx
 mov dx,[net_port]
 movzx bx,bl
 add dx,bx
 in al,dx
 pop edx
 ret

ne_init:
 ; Stop and reset; disable interrupts, monitor mode, loopback.
 mov bl,0x1f
 call ne_in
 call ne_out
 mov bl,0
 mov al,0x21
 call ne_out
 mov bl,0x0e
 mov al,0x49            ; DCR: FIFO 8, 16-bit DMA
 call ne_out
 mov bl,0x0c
 mov al,0x20            ; RCR monitor mode
 call ne_out
 mov bl,0x0d
 mov al,2               ; TCR internal loopback
 call ne_out
 mov bl,1
 mov al,0x46            ; FIX: RX starts after six TX pages 40h..45h
 call ne_out
 mov bl,2
 mov al,0x80            ; RX ring end
 call ne_out
 mov bl,3
 mov al,0x46
 call ne_out
 mov bl,0x0f
 xor al,al
 call ne_out
 mov bl,7
 mov al,0xff
 call ne_out
 ; FIX: preserve v86's assigned MAC; the backend may route by this address.
 mov bl,0
 mov al,0x61
 call ne_out
 mov edi,net_mac
 mov ecx,6
 mov bl,1
.mac:
 call ne_in
 stosb
 inc bl
 loop .mac
 mov bl,7
 mov al,0x47
 call ne_out
 mov bl,8
 mov ecx,8
.mcast:
 mov al,0xff
 call ne_out
 inc bl
 loop .mcast
 mov bl,0
 mov al,0x21
 call ne_out
 ; Enable reception and TX; stop loopback
 mov bl,0x0c
 mov al,0x04            ; accept broadcast
 call ne_out
 mov bl,0x0d
 xor al,al
 call ne_out
 mov bl,0
 mov al,0x22
 call ne_out
 ret

; FIX: route diagnostic frames through the same validated transmit path.
ne_send:
 cmp byte [net_present],1
 jne .done
 mov esi,net_mac
 mov edi,net_frame+6
 mov ecx,6
 rep movsb
 mov esi,net_frame
 mov ecx,60
 call ne_send_buffer
.done:
 ret

; Poll receive ring: read CURR on page 1, compare BNRY+1, then
; remote-DMA read 4-byte packet header and payload into 1600-byte buffer.
; This is a bounded single-frame poll, intended for repeated calls.
ne_poll:
 cmp byte [net_present],1
 jne .done
 mov bl,0
 mov al,0x62
 call ne_out
 mov bl,7
 call ne_in
 mov [net_current],al
 mov bl,0
 mov al,0x22
 call ne_out
 mov bl,3
 call ne_in
 inc al
 cmp al,0x80
 jb .page_ok
 mov al,0x46
.page_ok:
 cmp al,[net_current]
 je .done
 mov [net_rx_page],al
 ; remote DMA read first 4 bytes of receive ring header
 mov bl,8
 xor al,al
 call ne_out
 mov bl,9
 mov al,[net_rx_page]
 call ne_out
 mov bl,0x0a
 mov al,4
 call ne_out
 mov bl,0x0b
 xor al,al
 call ne_out
 mov bl,0
 mov al,0x0a
 call ne_out
 mov dx,[net_port]
 add dx,0x10
 in ax,dx
 mov [net_rx_status],al
 mov [net_rx_next],ah
 in ax,dx
 mov [net_rx_length],ax
 ; Reject corrupt ring headers and avoid buffer overrun
 cmp byte [net_rx_next],0x46
 jb .recover
 cmp byte [net_rx_next],0x80
 jae .recover
 ; FIX: require a complete Ethernet header and successful RX status.
 cmp word [net_rx_length],18
 jb .recover
 cmp word [net_rx_length],1522
 ja .recover
 test byte [net_rx_status],1
 jz .recover
 mov al,[net_rx_next]
 cmp al,[net_rx_page]
 je .recover
 ; DMA read packet from offset 4 (round up to even bytes)
 mov bl,8
 mov al,4
 call ne_out
 mov bl,9
 mov al,[net_rx_page]
 call ne_out
 mov ax,[net_rx_length]
 sub ax,4
 add ax,1
 and ax,0xfffe
 mov [net_dma_length],ax
 mov bl,0x0a
 call ne_out
 mov bl,0x0b
 mov al,ah
 call ne_out
 mov bl,0
 mov al,0x0a
 call ne_out
 mov dx,[net_port]
 add dx,0x10
 mov edi,net_rx_buffer
 movzx ecx,word [net_dma_length]
 shr ecx,1
.rx_words:
 in ax,dx
 stosw
 loop .rx_words
 inc dword [net_rx_count]
 pushad
 call ip_receive
 popad
 jmp .advance
.recover:
 inc dword [net_rx_errors]
 mov al,[net_current]
 mov [net_rx_next],al
.advance:
 mov al,[net_rx_next]
 dec al
 cmp al,0x46
 jae .boundary_ok
 mov al,0x7f
.boundary_ok:
 mov bl,3
 call ne_out
.done:
 ret

net_present db 0
net_port dw 0 ; FIX: no default port before PCI discovery
net_message dd net_missing
net_tx_count dd 0
net_rx_count dd 0
net_rx_errors dd 0
net_current db 0
net_rx_page db 0
net_rx_next db 0
net_rx_status db 0
net_rx_length dw 0
net_dma_length dw 0
net_mac db 0x02,0x54,0x45,0x58,0x54,0x01
pci_cfg_addr dd 0
net_missing db 'PCI NE2000 (10EC:8029) not found.',10,0
net_bar_fail db 'PCI NE2000 BAR0 is not an I/O BAR.',10,0
net_reset_fail db 'PCI NE2000 found; reset timed out.',10,0
net_found db 'PCI NE2000 detected; reset completed.',10,'T: send test frame  R: poll and show counters',10,0
net_frame:
 times 6 db 0xff
 db 0x02,0x54,0x45,0x58,0x54,0x01
 db 0x88,0xb5
 db 'TEXTOS NE2000 TEST FRAME'
 times 60-($-net_frame) db 0
net_rx_buffer rb 1604

; Send a complete Ethernet frame from ESI with length ECX (60..1514).
; 16-bit NE2000 remote DMA; FIX: packet RAM starts at page 40h.
ne_send_buffer:
 pushad
 cmp byte [net_present],1
 jne .done
 cmp ecx,14
 jb .done
 cmp ecx,1514
 ja .done
 ; FIX: pad short frames and odd DMA writes with zero, never stale bytes.
 mov edi,net_tx_buffer
 rep movsb
 mov ecx,edi
 sub ecx,net_tx_buffer
 cmp ecx,60
 jae .length_ok
 mov ecx,60
.length_ok:
 mov [tx_size],cx
 lea eax,[net_tx_buffer+ecx+1]
 cmp edi,eax
 jae .padding_done
.pad:
 mov byte [edi],0
 inc edi
 cmp edi,eax
 jb .pad
.padding_done:
 ; Wait for previous TX to finish before overwriting its packet RAM.
 mov bl,0
 mov ecx,100000
.wait_tx:
 call ne_in
 test al,4
 jz .tx_ready
 loop .wait_tx
 inc dword [net_tx_errors]
 jmp .done
.tx_ready:
 mov esi,net_tx_buffer
 mov bl,0
 mov al,0x22
 call ne_out
 mov bl,8
 xor al,al
 call ne_out
 mov bl,9
 mov al,0x40 ; FIX: DMA writes to valid TX RAM
 call ne_out
 mov bl,0x0a
 mov ax,[tx_size]
 add ax,1
 and ax,0xfffe
 call ne_out
 mov bl,0x0b
 mov al,ah
 call ne_out
 mov bl,7
 mov al,40h ; FIX: clear old RDC status before DMA starts
 call ne_out
 mov bl,0
 mov al,0x12
 call ne_out
 mov dx,[net_port]
 add dx,0x10
 movzx ecx,word [tx_size]
 add ecx,1
 shr ecx,1
.tx:
 lodsw
 out dx,ax
 loop .tx
 ; FIX: confirm remote DMA completion before transmitting.
 mov bl,7
 mov ecx,100000
.wait_dma:
 call ne_in
 test al,40h
 jnz .dma_ready
 loop .wait_dma
 inc dword [net_tx_errors]
 jmp .done
.dma_ready:
 mov al,0x40
 call ne_out
 mov bl,4
 mov al,0x40
 call ne_out
 mov bl,5
 mov al,byte [tx_size]
 call ne_out
 mov bl,6
 mov al,byte [tx_size+1]
 call ne_out
 mov bl,0
 mov al,0x26
 call ne_out
 inc dword [net_tx_count]
.done:
 popad
 ret
tx_size dw 0
net_tx_errors dd 0
net_tx_buffer rb 1516