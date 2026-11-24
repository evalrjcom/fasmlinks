format binary
use16
org 0x7c00
include 'kernel_layout.inc'
start:
 cli
 cld ; FIX: BIOS does not guarantee forward string operations
 xor ax,ax
 mov ds,ax
 mov es,ax
 mov ss,ax
 mov sp,0x7c00
 mov [drive],dl
 mov ax,0x1000
 mov es,ax
 xor bx,bx
 ; Read KERNEL_SECTORS sectors individually using floppy CHS geometry (18 sectors/track).
 mov word [sector_index],1
.read_sector:
 mov ax,[sector_index]
 xor dx,dx
 mov cx,18
 div cx
 mov cl,dl
 inc cl
 xor dx,dx
 mov bx,2
 div bx
 mov ch,al
 mov dh,dl
 mov dl,[drive]
 mov ax,0x1000
 mov es,ax
 mov bx,[sector_index]
 dec bx
 shl bx,9
 mov ax,0x0201
 int 0x13
 jc error
 inc word [sector_index]
 cmp word [sector_index],KERNEL_SECTORS+1
 jb .read_sector
 ; Load separate auxiliary payload at 40000h, after kernel on disk.
 mov word [sector_index],KERNEL_SECTORS+1
.read_aux:
 mov ax,[sector_index]
 xor dx,dx
 mov cx,18
 div cx
 mov cl,dl
 inc cl
 xor dx,dx
 mov bx,2
 div bx
 mov ch,al
 mov dh,dl
 mov dl,[drive]
 ; Each sector gets its own segment, avoiding 64 KiB offset wrap.
 mov ax,[sector_index]
 sub ax,KERNEL_SECTORS+1
 shl ax,5
 add ax,4000h
 mov es,ax
 xor bx,bx
 mov ax,0201h
 int 13h
 jc error
 inc word [sector_index]
 cmp word [sector_index],KERNEL_SECTORS+AUX_SECTORS+1
 jb .read_aux
 lgdt [gdtr]
 mov eax,cr0
 or eax,1
 mov cr0,eax
 jmp 0x08:protected
error:
 mov si,disk_error_message
.loop:
 lodsb
 test al,al
 jz $
 mov ah,0x0e
 int 0x10
 jmp .loop
disk_error_message db 'Disk read error',0
drive db 0
sector_index dw 0
align 8
gdt:
 dq 0
 dq 0x00cf9a000000ffff
 dq 0x00cf92000000ffff
gdt_end:
gdtr:
 dw gdt_end-gdt-1
 dd gdt
use32
protected:
 mov ax,0x10
 mov ds,ax
 mov es,ax
 mov ss,ax
 mov esp,0x90000
 jmp 0x08:0x10000
 times 510-($-$$) db 0
 dw 0xaa55