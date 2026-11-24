; TextOS 0.8.4: isolated TCP port-443 diagnostics, no application data.
probe_counters_reset:
 pushad
 mov edi,probe_counters
 xor eax,eax
 mov ecx,(probe_counters_end-probe_counters)/4
 rep stosd
 mov byte [probe_last_flags],0
 popad
 ret

port443_open:
 cmp byte [tcp_state],1
 je port443_info
 cmp byte [tcp_state],2
 je port443_info
 cmp byte [dns_state],1
 je port443_info
 cmp byte [dns_state],4
 je port443_info
 cmp byte [dhcp_state],3
 jne port443_info
 cmp byte [gateway_known],1
 jne port443_info
 mov dword [remote_ip],01010101h
 mov word [tcp_remote_port],0bb01h
 call stream_open
 jc port443_info
 mov byte [port443_active],1
 jmp port443_info

port443_poll:
 cmp byte [port443_active],1
 jne .done
 cmp byte [stream_mode],1
 jne .stop
 cmp word [tcp_remote_port],0bb01h
 jne .stop
 cmp byte [tcp_state],1
 je .done
 cmp byte [tcp_state],2
 jne .stop
 ; SYN-ACK proves TCP reachability. Close this diagnostic without sending data.
 mov byte [tcp_flags],14h
 xor ecx,ecx
 call tcp_send_segment
 mov byte [tcp_state],3
.stop:
 mov byte [port443_active],0
.done:
 ret

port443_info:
 mov edi,0b8000h+160*4
 mov ecx,80*19
 mov ax,1f20h
 rep stosw
 mov edi,0b8000h+160*4
 mov esi,probe_title
 call print
 mov esi,probe_dest_label
 call print
 mov eax,[remote_ip]
 call print_ipv4
 mov esi,probe_port_label
 call print
 movzx eax,word [tcp_remote_port]
 xchg al,ah
 call print_hex32
 mov esi,probe_src_label
 call print
 movzx eax,word [tcp_local_port]
 xchg al,ah
 call print_hex32
 mov esi,probe_state_label
 call print
 movzx eax,byte [tcp_state]
 call print_hex32
 mov esi,probe_attempt_label
 call print
 mov eax,[probe_syn_attempt]
 call print_hex32
 mov esi,probe_tx_label
 call print
 mov eax,[probe_syn_tx]
 call print_hex32
 mov esi,probe_wire_label
 call print
 mov eax,[probe_wire]
 call print_hex32
 mov esi,probe_rx_label
 call print
 mov eax,[probe_port_rx]
 call print_hex32
 mov esi,probe_tuple_label
 call print
 mov eax,[probe_tuple_rx]
 call print_hex32
 mov esi,probe_bad_tuple_label
 call print
 mov eax,[probe_tuple_bad]
 call print_hex32
 mov esi,probe_checksum_label
 call print
 mov eax,[probe_checksum_bad]
 call print_hex32
 mov esi,probe_ack_bad_label
 call print
 mov eax,[probe_ack_bad]
 call print_hex32
 mov esi,probe_flags_bad_label
 call print
 mov eax,[probe_flags_bad]
 call print_hex32
 mov esi,probe_synack_label
 call print
 mov eax,[probe_syn_ack]
 call print_hex32
 mov esi,probe_rst_label
 call print
 mov eax,[probe_rst]
 call print_hex32
 mov esi,probe_seq_label
 call print
 mov eax,[probe_initial_seq]
 call print_hex32
 mov esi,probe_ack_label
 call print
 mov eax,[probe_last_ack]
 call print_hex32
 mov esi,probe_last_label
 call print
 movzx eax,byte [probe_last_flags]
 call print_hex32
 jmp main

probe_title db 'TCP diagnostic: F8 connect-only 443 | F9 refresh (hex counters)',0
probe_dest_label db 10,'Destination IP: ',0
probe_port_label db 10,'Destination port: 0x',0
probe_src_label db 10,'Local port: 0x',0
probe_state_label db 10,'TCP state: 0x',0
probe_attempt_label db 10,'SYN attempts: 0x',0
probe_tx_label db 10,'SYN submitted to NIC: 0x',0
probe_wire_label db 10,'Wire destination-port matches: 0x',0
probe_rx_label db 10,'IP-validated port matches: 0x',0
probe_tuple_label db 10,'Full tuple matches: 0x',0
probe_bad_tuple_label db 10,'Tuple rejected: 0x',0
probe_checksum_label db 10,'TCP checksum rejected: 0x',0
probe_ack_bad_label db 10,'SYN ACK number rejected: 0x',0
probe_flags_bad_label db 10,'SYN flags rejected: 0x',0
probe_synack_label db 10,'Accepted SYN-ACK: 0x',0
probe_rst_label db 10,'Accepted RST: 0x',0
probe_seq_label db 10,'Initial send sequence: 0x',0
probe_ack_label db 10,'Last received ACK: 0x',0
probe_last_label db 10,'Last validated flags: 0x',0
probe_counters:
probe_syn_attempt dd 0
probe_syn_tx dd 0
probe_wire dd 0
probe_port_rx dd 0
probe_tuple_rx dd 0
probe_tuple_bad dd 0
probe_checksum_bad dd 0
probe_ack_bad dd 0
probe_flags_bad dd 0
probe_syn_ack dd 0
probe_rst dd 0
probe_initial_seq dd 0
probe_last_ack dd 0
probe_last_seq dd 0
probe_counters_end:
probe_last_flags db 0
port443_active db 0
