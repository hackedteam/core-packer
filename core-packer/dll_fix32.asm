.model flat, stdcall

option casemap :none

hermit SEGMENT PUBLIC READ EXECUTE ALIAS('.hermit')

;public _VirtualProtect
;public _VirtualAlloc
public g_hKernel32
public _LoadLibraryA
public _GetProcAddress
public _EntryPoint

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

extern DELAYDECRYPT@0 : PROC
extern DELAYENCRYPT@0 : PROC

g_hKernel32	dd	?	; symbol!

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
_LoadLibraryA PROC param1: DWORD
	mov esp, ebp
	pop ebp
	mov eax, dword ptr [g_hKernel32]
	add eax, 11223340h
	jmp dword ptr ds:[eax]
	nop
	nop
	nop
	nop
	nop
_LoadLibraryA ENDP

_GetProcAddress PROC param1: DWORD, param2: DWORD
	mov esp, ebp
	pop ebp
	mov eax, dword ptr [g_hKernel32]
	add eax, 11223341h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_GetProcAddress ENDP


_SetFilePointer PROC param1: DWORD, param2: DWORD, param3: DWORD, p4: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [g_hKernel32]
	add eax, 11223342h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_SetFilePointer ENDP

_CloseHandle PROC param1: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [g_hKernel32]
	add eax, 11223343h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_CloseHandle ENDP

_ReadFile PROC param1: DWORD, param2: DWORD, param3: DWORD, p4: DWORD, p5: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [g_hKernel32]
	add eax, 11223344h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_ReadFile ENDP

_GetModuleFileNameA PROC param1: DWORD, param2: DWORD, param3: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [g_hKernel32]
	add eax, 11223345h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_GetModuleFileNameA ENDP

_CreateFileA PROC lpFileName: DWORD, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttribytes: DWORD, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [g_hKernel32]
	add eax, 11223346h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_CreateFileA ENDP

_EntryPoint PROC param1: DWORD, param2: DWORD, param3: DWORD, param4: DWORD
	push dword ptr [ebp+14h]
	push dword ptr [ebp+10h]
	push dword ptr [ebp+0ch]
	mov eax, dword ptr [ebp+08h]
	add eax, 10101010h
	call eax
	ret
_EntryPoint ENDP

_FakeEntryPoint0 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint0 ENDP

_FakeEntryPoint1 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint1 ENDP

_FakeEntryPoint2 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint2 ENDP

_FakeEntryPoint3 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint3 ENDP

_FakeEntryPoint4 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint4 ENDP

_FakeEntryPoint5 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint5 ENDP

_FakeEntryPoint6 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint6 ENDP

_FakeEntryPoint7 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint7 ENDP

_FakeEntryPoint8 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint8 ENDP

_FakeEntryPoint9 PROC
	push ebp
	mov ebp, esp
	;pushad
	call DELAYDECRYPT@0

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FakeEntryPoint9 ENDP

end
