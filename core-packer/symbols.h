#ifndef __SYMBOLS_H_
	#define __SYMBOLS_H_

typedef HMODULE (WINAPI *LoadLibraryA_ptr)(LPCTSTR lpFileName);
typedef FARPROC (WINAPI *GetProcAddress_ptr)(HMODULE hModule, LPCSTR lpProcName);

typedef LPVOID (WINAPI *VirtualAlloc_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *VirtualProtect_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef BOOL (WINAPI *DllMain_ptr)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

extern ULONG64		dwRelocSize;
extern ULONG64		lpRelocAddress;
extern ULONG64		_rc4key0;
extern ULONG64		_rc4key1;
#ifdef _BUILD32
extern "C" 
{
HMODULE WINAPI _LoadLibraryA(LPCTSTR lpFileName);
FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HANDLE WINAPI _CreateFileA(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DWORD WINAPI _GetModuleFileNameA(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
DWORD WINAPI _SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL WINAPI _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
BOOL WINAPI _EntryPoint(LPVOID lpBase, HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI _CloseHandle(HANDLE hObject);
}

extern "C" HMODULE g_hKernel32;

#else
extern "C" HMODULE WINAPI _LoadLibraryA(LPCTSTR lpFileName);
extern "C" FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
extern "C" BOOL WINAPI _EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
extern "C" HMODULE g_hKernel32;
#endif

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
