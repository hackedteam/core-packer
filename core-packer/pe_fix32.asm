.model flat, stdcall

option casemap :none

peexe SEGMENT PUBLIC READ EXECUTE ALIAS('.peexe')

public exe_g_hKernel32
public _exe_LoadLibraryA
public _exe_GetProcAddress
public _exe_EntryPoint

public _FX0
public _FX1
public _FX2
public _FX3
public _FX4
public _FX5
public _FX6
public _FX7
public _FX8
public _FX9

exe_g_hKernel32	dd	?	; symbol!

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
_exe_LoadLibraryA PROC param1: DWORD
	mov esp, ebp
	pop ebp
	mov eax, dword ptr [exe_g_hKernel32]
	add eax, 11223340h
	jmp dword ptr ds:[eax]
	nop
	nop
	nop
	nop
	nop
_exe_LoadLibraryA ENDP

_exe_GetProcAddress PROC param1: DWORD, param2: DWORD
	mov esp, ebp
	pop ebp
	mov eax, dword ptr [exe_g_hKernel32]
	add eax, 11223341h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_exe_GetProcAddress ENDP


_exe_SetFilePointer PROC param1: DWORD, param2: DWORD, param3: DWORD, p4: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [exe_g_hKernel32]
	add eax, 11223342h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_exe_SetFilePointer ENDP

_exe_CloseHandle PROC param1: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [exe_g_hKernel32]
	add eax, 11223343h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_exe_CloseHandle ENDP

_exe_ReadFile PROC param1: DWORD, param2: DWORD, param3: DWORD, p4: DWORD, p5: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [exe_g_hKernel32]
	add eax, 11223344h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_exe_ReadFile ENDP

_exe_GetModuleFileNameA PROC param1: DWORD, param2: DWORD, param3: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [exe_g_hKernel32]
	add eax, 11223345h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_exe_GetModuleFileNameA ENDP

_exe_CreateFileA PROC lpFileName: DWORD, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttribytes: DWORD, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: DWORD
	mov esp, ebp
	pop	ebp
	mov eax, dword ptr [exe_g_hKernel32]
	add eax, 11223346h
	jmp dword ptr [eax]
	nop
	nop
	nop
	nop
	nop
_exe_CreateFileA ENDP

_exe_EntryPoint PROC param1: DWORD, param2: DWORD, param3: DWORD, param4: DWORD
	push dword ptr [ebp+14h]
	push dword ptr [ebp+10h]
	push dword ptr [ebp+0ch]
	mov eax, dword ptr [ebp+08h]
	add eax, 10101010h
	call eax
	ret
_exe_EntryPoint ENDP

_GETBASE PROC
	mov ecx, 11223346h
	call @next
@next:
	pop eax
	sub eax, ecx
	and eax, 0fffff000h
	ret
_GETBASE ENDP

_CrtStartup PROC param1: DWORD
	mov eax, dword ptr [ebp+08h]
	mov esp, ebp
	pop ebp
	add eax, 10101010h
	jmp eax
_CrtStartup ENDP

_FX0 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX0 ENDP

_FX1 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX1 ENDP

_FX2 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX2 ENDP

_FX3 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX3 ENDP

_FX4 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX4 ENDP

_FX5 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX5 ENDP

_FX6 PROC
	push ebp
	mov ebp, esp
	;pushad

	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX6 ENDP

_FX7 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX7 ENDP

_FX8 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX8 ENDP

_FX9 PROC
	push ebp
	mov ebp, esp
	;pushad
	
	;popad
	mov esp, ebp
	pop ebp
	add eax, 10001000h
	jmp eax
_FX9 ENDP

end
