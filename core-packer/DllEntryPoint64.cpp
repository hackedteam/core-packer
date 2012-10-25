#include <Windows.h>
#include "symbols.h"

#include "rva.h"
#include "reloc.h"
#include "rc4.h"
#include "macro.h"

#pragma section(".hermit", read, execute)


#ifdef _BUILD64

#pragma code_seg(".hermit")
BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS64 pImageNtHeaders64 = CALC_OFFSET(PIMAGE_NT_HEADERS64, pImageDosHeader, pImageDosHeader->e_lfanew);

	if (pImageNtHeaders64->Signature != IMAGE_NT_SIGNATURE)
	{	// I'm invalid file?
		return FALSE;	
	}
	
	short NumberOfSections = pImageNtHeaders64->FileHeader.NumberOfSections-1;	// I'm on tail!!! please don't patch myself!

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders64); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if ((pSection->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)	// shared memory!
			continue;

		DWORD dwOldPermissions = NULL, dwDummy = 0;
		LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders64, (LPVOID) pSection->VirtualAddress);

		_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

		BYTE sbox[256];
		ULONG64 rc4key[2] = { _rc4key0, _rc4key1 };

		init_sbox(sbox);
		init_sbox_key(sbox, (PBYTE) &rc4key, 16);

		if ((pSection->Characteristics & 0x03) == 3)
		{
			DWORD sizeOfSection = 
				pImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
					- pSection->VirtualAddress 
					- pImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
						
			LPVOID lpNewAddress = CALC_OFFSET(LPVOID, lpAddress, pImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);

			cypher_msg(sbox, (PBYTE) lpNewAddress, sizeOfSection);	// decrypt done!

		} 
		else if (pSection->Characteristics & 0x02)
		{	// packed section!
			
			cypher_msg(sbox, (PBYTE) lpAddress, pSection->SizeOfRawData);	// decrypt done!
		}

				// apply reloc in current section!
		ULONG64 ptrReloc = CALC_OFFSET(ULONG64, pImageDosHeader, (ULONG64) lpRelocAddress);
		Reloc_Process((LPVOID) pImageDosHeader, pImageNtHeaders64, pSection, (LPVOID) ptrReloc, dwRelocSize);
			
		_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);
	}
	
	return TRUE;
}

#pragma code_seg(".hermit")
BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	char szKernel32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0x00 };
	char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };
	char szDisableThreadLibraryCalls[] = { 'D', 'i', 's', 'a', 'b', 'l', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'C', 'a', 'l', 'l', 's', 00 };

	typedef BOOL (WINAPI *DisableThreadLibraryCalls_ptr)(HMODULE hModule);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (g_hKernel32 == NULL)
		{
			g_hKernel32 = hinstDLL;

			HMODULE h = _LoadLibraryA(szKernel32);
			_VirtualProtect = (VirtualProtect_ptr) _GetProcAddress(h, szVirtualProtect);
			DisableThreadLibraryCalls_ptr _DisableThreadLibraryCalls = (DisableThreadLibraryCalls_ptr) _GetProcAddress(h, szDisableThreadLibraryCalls);
			_DisableThreadLibraryCalls(hinstDLL);
			//decrypt(hinstDLL, fdwReason, lpvReserved);
			
			return TRUE;

		}
	}

	if (g_decrypted == TRUE)
		return _EntryPoint(hinstDLL, fdwReason, lpvReserved);
	else
		return TRUE;
}

#pragma code_seg(".hermit")
extern "C" 
void WINAPI DELAYDECRYPT()
{
	if (g_decrypted == FALSE)
	{
		g_decrypted = decrypt(g_hKernel32, DLL_PROCESS_ATTACH, NULL);
		_EntryPoint(g_hKernel32, DLL_PROCESS_ATTACH, NULL);
	}
}

#endif
