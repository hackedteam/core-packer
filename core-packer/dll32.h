#ifndef __DLL32_H_
#define __DLL32_H_

extern ULONG64		dwRelocSize;
extern ULONG64		lpRelocAddress;
extern ULONG64		_rc4key0;
extern ULONG64		_rc4key1;
extern ULONG64		_baseAddress;

extern "C" HMODULE g_hKernel32;

//extern "C" VirtualAlloc_ptr	_VirtualAlloc;
extern VirtualProtect_ptr _VirtualProtect;
extern VirtualAlloc_ptr	_VirtualAlloc;

extern "C" BOOL WINAPI _EntryPoint(LPVOID, HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
extern "C" HMODULE g_hKernel32;
extern "C" BYTE	g_decrypted;
extern "C" LPVOID g_lpTextBaseAddr;

extern "C" VOID WINAPI _FakeEntryPoint0();
extern "C" VOID WINAPI _FakeEntryPoint1();
extern "C" VOID WINAPI _FakeEntryPoint2();
extern "C" VOID WINAPI _FakeEntryPoint3();
extern "C" VOID WINAPI _FakeEntryPoint4();
extern "C" VOID WINAPI _FakeEntryPoint5();
extern "C" VOID WINAPI _FakeEntryPoint6();
extern "C" VOID WINAPI _FakeEntryPoint7();
extern "C" VOID WINAPI _FakeEntryPoint8();
extern "C" VOID WINAPI _FakeEntryPoint9();


#endif
