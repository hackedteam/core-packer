#ifndef __SYMBOLS_H_
	#define __SYMBOLS_H_

typedef HMODULE (WINAPI *LoadLibraryA_ptr)(LPCTSTR lpFileName);
typedef FARPROC (WINAPI *GetProcAddress_ptr)(HMODULE hModule, LPCSTR lpProcName);

typedef LPVOID (WINAPI *VirtualAlloc_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *VirtualProtect_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

/////////////////////////////////////////////////////////////////////
// Critical section pointers
typedef void (WINAPI *InitializeCriticalSection_ptr)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI *EnterCriticalSection_ptr)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI *LeaveCriticalSection_ptr)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI *DeleteCriticalSection_ptr)(LPCRITICAL_SECTION lpCriticalSection);

typedef BOOL (WINAPI *DllMain_ptr)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

typedef HMODULE (WINAPI *GetModuleHandleA_ptr)(LPCTSTR lpModuleName);

typedef HANDLE (WINAPI *CreateFileA_ptr)(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

typedef DWORD (WINAPI *SetFilePointer_ptr)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

#ifdef _BUILD32
HMODULE WINAPI _dll32_LoadLibraryA(LPCTSTR lpFileName);	// C porting

extern "C" 
{
HMODULE WINAPI _exe_LoadLibraryA(LPCTSTR lpFileName);

FARPROC WINAPI _dll32_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
FARPROC WINAPI _exe_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

HANDLE WINAPI _CreateFileA(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI _exe_CreateFileA(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

DWORD WINAPI _GetModuleFileNameA(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
DWORD WINAPI _exe_GetModuleFileNameA(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

DWORD WINAPI _SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
DWORD WINAPI _exe_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

BOOL WINAPI _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
BOOL WINAPI _exe_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

BOOL WINAPI _CloseHandle(HANDLE hObject);
BOOL WINAPI _exe_CloseHandle(HANDLE hObject);

BOOL WINAPI _EntryPoint(LPVOID lpBase, HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI _exe_EntryPoint(LPVOID lpBase, HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

int WINAPI _CrtStartup(LPVOID lpBase);	// NO EXIT!
LPVOID WINAPI _GETBASE();
}

extern "C" HMODULE exe_g_hKernel32;

#else
extern "C" HMODULE WINAPI _LoadLibraryA(LPCTSTR lpFileName);
extern "C" FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
//extern "C" BOOL WINAPI _EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
//extern "C" HMODULE g_hKernel32;
#endif

extern VirtualProtect_ptr _VirtualProtect;
extern VirtualAlloc_ptr _VirtualAlloc;

extern VirtualProtect_ptr exe_VirtualProtect;
extern VirtualAlloc_ptr exe_VirtualAlloc;

#endif
