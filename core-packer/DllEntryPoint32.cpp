#include <Windows.h>

#ifdef _BUILD32

#include "symbols.h"
#include "dll32.h"

#include "rva.h"
#include "reloc.h"
#include "rc4.h"
#include "macro.h"
#include "decrypt.h"

#pragma section(".hermit", read, write, execute)



#pragma code_seg(".hermit")
void __memcpy(char *dst, char *src, int size)
{
	while(size-- > 0)
	{
		*dst++=*src++;
	}
}

#pragma code_seg(".hermit")
BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS32 pImageNtHeaders32 = CALC_OFFSET(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);

	if (pImageNtHeaders32->Signature != IMAGE_NT_SIGNATURE)
	{	// I'm invalid file?
		return FALSE;	
	}
	
	short NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections-1;	// I'm on tail!!! please don't patch myself!

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if ((pSection->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)	// shared memory!
			continue;

		DWORD dwOldPermissions = NULL, dwDummy = 0;

		LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders32, (LPVOID) pSection->VirtualAddress);

		_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

		BYTE sbox[256];
		ULONG64 rc4key[2] = { _rc4key0, _rc4key1 };

		init_sbox(sbox);
		init_sbox_key(sbox, (PBYTE) &rc4key, 16);

		if ((pSection->Characteristics & 0x03) == 3)
		{
			DWORD sizeOfSection = 
				pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
					- pSection->VirtualAddress 
					- pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
						
			LPVOID lpNewAddress = CALC_OFFSET(LPVOID, lpAddress, pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);

			cypher_msg(sbox, (PBYTE) lpNewAddress, sizeOfSection);	// decrypt done!

		} 
		else if (pSection->Characteristics & 0x02)
		{	// packed section!
			LPDWORD lpSectionName = (LPDWORD) pSection->Name;
			if (*lpSectionName == 0x7865742e)
			{	// text section! load from disk!!
				char szFileName[MAX_PATH];
				DWORD dw = _GetModuleFileNameA(hinstDLL, szFileName, MAX_PATH);
				HANDLE h = _CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

				g_lpTextBaseAddr = _VirtualAlloc(0x0, pSection->Misc.VirtualSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

				_SetFilePointer(h, 0x400, 0, SEEK_SET);			//	<< 0x400 - offset on physical disk of first section
				_ReadFile(h, g_lpTextBaseAddr, pSection->Misc.VirtualSize, &dw, NULL); //_ReadFile(h, lpAddress, pSection->Misc.VirtualSize, &dw, NULL);
				_CloseHandle(h);
				cypher_msg(sbox, (PBYTE) g_lpTextBaseAddr, pSection->Misc.VirtualSize); // cypher_msg(sbox, (PBYTE) lpAddress, pSection->Misc.VirtualSize);
///////////	
			}
			else
				cypher_msg(sbox, (PBYTE) lpAddress, pSection->SizeOfRawData);	// decrypt done!
		}

		// apply reloc in current section!
		ULONG ptrReloc = CALC_OFFSET(ULONG, pImageDosHeader, (ULONG) lpRelocAddress);

		if (g_decrypted == 0)	// relocation must be done only 1st time!
		{	// it's first time?
			if (pSection == IMAGE_FIRST_SECTION(pImageNtHeaders32))
			{
				reloctext((LPVOID) pImageDosHeader, pImageNtHeaders32, pSection, (LPVOID) ptrReloc, dwRelocSize, g_lpTextBaseAddr);
			}
			else
				Reloc_Process((LPVOID) pImageDosHeader, pImageNtHeaders32, pSection, (LPVOID) ptrReloc, dwRelocSize, IMAGE_FIRST_SECTION(pImageNtHeaders32), g_lpTextBaseAddr);
		}
			
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
	char szGetModuleFileNameA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x00 };

	typedef BOOL (WINAPI *DisableThreadLibraryCalls_ptr)(HMODULE hModule);

	// find patterns!
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS pNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
	_baseAddress = pNtHeader->OptionalHeader.ImageBase;

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
