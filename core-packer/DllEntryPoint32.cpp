#include <Windows.h>
#include "symbols.h"

#include "rva.h"
#include "reloc.h"
#include "rc4.h"
#include "macro.h"
#include "decrypt.h"

#pragma section(".hermit", read, write, execute)

#ifdef _BUILD32

#pragma code_seg(".hermit")
BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	char szKernel32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0x00 };
	char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };
	char szDisableThreadLibraryCalls[] = { 'D', 'i', 's', 'a', 'b', 'l', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'C', 'a', 'l', 'l', 's', 00 };
	char szGetModuleFileNameA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x00 };

	typedef BOOL (WINAPI *DisableThreadLibraryCalls_ptr)(HMODULE hModule);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (g_hKernel32 == NULL)
		{
			g_hKernel32 = hinstDLL;

			HMODULE h = _LoadLibraryA(szKernel32);
			_VirtualProtect = (VirtualProtect_ptr) _GetProcAddress(h, szVirtualProtect);
			
			szVirtualProtect[7] = 'A';
			szVirtualProtect[8] = 'l';
			szVirtualProtect[9] = 'l';
			szVirtualProtect[0x0a] = 'o';
			szVirtualProtect[0x0b] = 'c';
			szVirtualProtect[0x0c] = 0x00;

			_VirtualAlloc = (VirtualAlloc_ptr) _GetProcAddress(h, szVirtualProtect);

			DisableThreadLibraryCalls_ptr _DisableThreadLibraryCalls = (DisableThreadLibraryCalls_ptr) _GetProcAddress(h, szDisableThreadLibraryCalls);
			_DisableThreadLibraryCalls(hinstDLL);
			//decrypt(hinstDLL, fdwReason, lpvReserved);
			
			return TRUE;

		}
	}
	if (g_decrypted == TRUE)
		return _EntryPoint(g_lpTextBaseAddr, hinstDLL, fdwReason, lpvReserved);
	else
		return TRUE;
}

#pragma code_seg(".hermit")
extern "C" 
LPVOID WINAPI DELAYDECRYPT()
{
	if (g_decrypted == FALSE)
	{
		g_decrypted = decrypt(g_hKernel32, DLL_PROCESS_ATTACH, NULL);
		_EntryPoint(g_lpTextBaseAddr, g_hKernel32, DLL_PROCESS_ATTACH, NULL);
	}
	else if (g_decrypted == 2)
	{
		decrypt(g_hKernel32, DLL_PROCESS_ATTACH, NULL);
	}

	return g_lpTextBaseAddr;
}

#pragma codeseg(".hermit")
extern "C"
void WINAPI DELAYENCRYPT()
{
	g_decrypted = 2;
	decrypt(g_hKernel32, DLL_PROCESS_ATTACH, NULL);
}

#endif
