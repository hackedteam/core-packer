option casemap :none

hermit64 SEGMENT READ EXECUTE ALIAS('.pedll64')

;public _VirtualProtect
;public _VirtualAlloc
public g_hKernel32

public _FakeEntryPoint0
public _FakeEntryPoint1
public _FakeEntryPoint2
public _FakeEntryPoint3
public _FakeEntryPoint4
public _FakeEntryPoint5
public _FakeEntryPoint6
public _FakeEntryPoint7
public _FakeEntryPoint8
public _FakeEntryPoint9
public _EntryPoint

extern DELAYDECRYPT : PROC

g_hKernel32	dq	?	; symbol!

; jmp to KERNEL32!VirtualProtect in relocated module

;_VirtualProtect PROC
;	db 0e9h
;	dq 0babecafe00000005h
;_VirtualProtect ENDP

;_VirtualAlloc PROC
;	db 0e9h
;	dq 0BABECAFEBAD00002h
;_VirtualAlloc ENDP

; LoadLibraryA
_LoadLibraryA PROC
	mov rax, qword ptr [g_hKernel32]
	add rax, 11223344h
	jmp qword ptr [rax]
_LoadLibraryA ENDP

_GetProcAddress PROC
	mov rax, qword ptr [g_hKernel32]
	add rax, 11223344h
	jmp qword ptr [rax]
_GetProcAddress ENDP

_EntryPoint PROC
	db 0e9h
	dq 0BABECAFEBAD00000h
_EntryPoint ENDP

_FakeEntryPoint0 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx

	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint0 ENDP

_FakeEntryPoint1 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint1 ENDP

_FakeEntryPoint2 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint2 ENDP

_FakeEntryPoint3 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint3 ENDP

_FakeEntryPoint4 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint4 ENDP

_FakeEntryPoint5 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint5 ENDP

_FakeEntryPoint6 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint6 ENDP

_FakeEntryPoint7 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint7 ENDP

_FakeEntryPoint8 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint8 ENDP

_FakeEntryPoint9 PROC
	push rcx
	push rdx
	push r8
	push r9
	call DELAYDECRYPT
	pop r9
	pop r8
	pop rdx
	pop rcx
	db 0e9h
	dq 0BABECAFEBAD00000h
_FakeEntryPoint9 ENDP

end
