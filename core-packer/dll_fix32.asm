.model flat, stdcall

option casemap :none

code SEGMENT PUBLIC READ EXECUTE ALIAS('.pedll32')

;public _VirtualProtect
;public _VirtualAlloc
;public g_hKernel32
;public _dll32_LoadLibraryA
;public _dll32_GetProcAddress
;public _EntryPoint

extern DELAYDECRYPT@4 : PROC
extern DELAYENCRYPT@0 : PROC

;g_hKernel32	dd	?	; symbol!

; jmp to KERNEL32!VirtualProtect in relocated module

;_VirtualProtect PROC
;	db 0e9h
;	dq 0babecafe00000005h
;_VirtualProtect ENDP

;_VirtualAlloc PROC
;	db 0e9h
;	dq 0BABECAFEBAD00002h
;_VirtualAlloc ENDP

end
