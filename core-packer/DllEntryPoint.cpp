#include <Windows.h>
#include "rva.h"
#include "reloc.h"
#include "rc4.h"
#include "macro.h"

#pragma section(".hermit", read, execute)

typedef HMODULE (WINAPI *LoadLibraryA_ptr)(LPCTSTR lpFileName);
typedef FARPROC (WINAPI *GetProcAddress_ptr)(HMODULE hModule, LPCSTR lpProcName);

typedef LPVOID (WINAPI *VirtualAlloc_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *VirtualProtect_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef BOOL (WINAPI *DllMain_ptr)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);


__declspec(allocate(".hermit"))
ULONG64				dwRelocSize			= 0xBABECAFEBAD00021;

__declspec(allocate(".hermit"))
LPVOID				lpRelocAddress		= (LPVOID) 0xBABECAFEBAD00020;

__declspec(allocate(".hermit"))
ULONG64				_rc4key0			= 0xBABECAFEBAD00010;

__declspec(allocate(".hermit"))
ULONG64				_rc4key1			= 0xBABECAFEBAD00011;

// Fixed symbols from loader
__declspec(allocate(".hermit"))
LoadLibraryA_ptr	_LoadLibraryA		= (LoadLibraryA_ptr) 0xBABECAFEBAD00004;

__declspec(allocate(".hermit"))
GetProcAddress_ptr	_GetProcAddress		= (GetProcAddress_ptr) 0xBABECAFEBAD00003;

__declspec(allocate(".hermit"))
VirtualAlloc_ptr	_VirtualAlloc		= (VirtualAlloc_ptr) 0xBABECAFEBAD00002;

__declspec(allocate(".hermit"))
DllMain_ptr			_EntryPoint			= (DllMain_ptr) 0xBABECAFEBAD00000;


__declspec(allocate(".hermit"))
HMODULE g_hKernel32 = NULL;

#pragma code_seg(".hermit")
BOOL WINAPI _VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

#pragma code_seg(".hermit")
BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS64 pImageNtHeaders64 = CALC_OFFSET(PIMAGE_NT_HEADERS64, pImageDosHeader, pImageDosHeader->e_lfanew);

	if (pImageNtHeaders64->Signature != IMAGE_NT_SIGNATURE)
	{	// I'm invalid file?
		return FALSE;	
	}
	
	short NumberOfSections = pImageNtHeaders64->FileHeader.NumberOfSections;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders64); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (pSection->Characteristics & 0x02)
		{	// packed section!
			DWORD dwOldPermissions = NULL, dwDummy = 0;

			LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders64, (LPVOID) pSection->VirtualAddress);

			_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

			BYTE sbox[256];
			ULONG64 rc4key[2] = { _rc4key0, _rc4key1 };

			init_sbox(sbox);
			init_sbox_key(sbox, (PBYTE) &rc4key, sizeof(rc4key));
			
			cypher_msg(sbox, (PBYTE) lpAddress, pSection->SizeOfRawData);	// decrypt done!


			// apply reloc in current directory!
			Reloc_Process((LPVOID) pImageDosHeader, pImageNtHeaders64, pSection, lpRelocAddress, dwRelocSize);
			
			_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);
		}
	}
	
	return TRUE;
}

#pragma code_seg(".hermit")
BOOL WINAPI DLLCIPPA(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	BOOL bReturn = TRUE;

	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			if (g_hKernel32 == NULL)
			{	// decrypt code and fix all data!
				if (decrypt(hinstDLL, fdwReason, lpvReserved) == FALSE)
					return FALSE;	// error in loading!

				// restore reloc data in header and process old entries!
			}
			
			bReturn = _EntryPoint(hinstDLL, fdwReason, lpvReserved);
			break;

		case DLL_THREAD_ATTACH:
			bReturn = _EntryPoint(hinstDLL, fdwReason, lpvReserved);
			break;

		case DLL_THREAD_DETACH:
			bReturn = _EntryPoint(hinstDLL, fdwReason, lpvReserved);
			break;

		case DLL_PROCESS_DETACH:
			bReturn = _EntryPoint(hinstDLL, fdwReason, lpvReserved);
			break;
	}

	return TRUE;
}
