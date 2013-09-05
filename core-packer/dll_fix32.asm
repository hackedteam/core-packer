.model flat, stdcall

option casemap :none

code SEGMENT PUBLIC READ EXECUTE ALIAS('.pedll32')

;public _VirtualProtect
;public _VirtualAlloc
public g_hKernel32
;public _dll32_LoadLibraryA
public _dll32_GetProcAddress
public _EntryPoint

extern DELAYDECRYPT@4 : PROC
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

_dll32_GetProcAddress PROC param1: DWORD, param2: DWORD
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
_dll32_GetProcAddress ENDP


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

end
