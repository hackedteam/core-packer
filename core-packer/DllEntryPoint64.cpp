#include <Windows.h>
#include "symbols.h"
#include "dll64.h"
#include "rva.h"
#include "reloc.h"
//#include "rc4.h"
#include "macro.h"

#ifdef _BUILD64

#pragma section(".pedll64", read, write, execute)

typedef struct _configuration
{
	ULONG64			dwRelocSize;
	ULONG64			lpRelocAddress;
	ULONG64			_key0;
	ULONG64			_key1;
	ULONG64			_baseAddress;
	BYTE			decrypted;
	LPVOID			lpTextBaseAddr;
} CONFIGURATION;


/*CONFIGURATION dll32_configuration = {
		0xBABECAFEBAD00021,
		0xBABECAFEBAD00020,
		0xBABECAFEBAD00010,
		0xBABECAFEBAD00011,
		0xBABECAFEBAD00100,
		FALSE,
		NULL
};*/

__declspec(allocate(".pedll64"))
ULONG64				dwRelocSize			= 0xBABECAFEBAD00021;

__declspec(allocate(".pedll64"))
ULONG64				lpRelocAddress		= 0xBABECAFEBAD00020;

__declspec(allocate(".pedll64"))
ULONG64				_rc4key0			= 0xBABECAFEBAD00010;

__declspec(allocate(".pedll64"))
ULONG64				_rc4key1			= 0xBABECAFEBAD00011;


__declspec(allocate(".pedll64"))
ULONG64				_baseAddress		= 0xBABECAFEBAD00100;

// Fixed symbols from loader
//__declspec(allocate(".hermit"))
//LoadLibraryA_ptr	_LoadLibraryA		= (LoadLibraryA_ptr) 0xBABECAFEBAD00004;

//__declspec(allocate(".hermit"))
//GetProcAddress_ptr	_GetProcAddress		= (GetProcAddress_ptr) 0xBABECAFEBAD00003;

//__declspec(allocate(".hermit"))
//HMODULE g_hKernel32 = NULL;

__declspec(allocate(".pedll64"))
VirtualProtect_ptr	_VirtualProtect;

__declspec(allocate(".pedll64"))
VirtualAlloc_ptr	_VirtualAlloc;

extern "C" {

__declspec(allocate(".pedll64"))
BYTE	g_decrypted = FALSE;

__declspec(allocate(".pedll64"))
LPVOID	g_lpTextBaseAddr = (LPVOID) 0L;

}

__declspec(allocate(".pedll64"))
CRITICAL_SECTION	_critical_section;

#pragma code_seg(".pedll64")
static void _InitializeCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll64")
static void _LeaveCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'L', 'e', 'a', 'v', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll64")
static void _DeleteCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'D', 'e', 'l', 'e', 't', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll64")
static void _EnterCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'E', 'n', 't', 'e', 'r', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _GetProcAddress(h, szApi);

	f(lpCriticalSection);
}


#pragma code_seg(".pedll64")
static LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG64) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG64) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders64->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders64->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

#pragma code_seg(".pedll64")
static void swap(PBYTE a, PBYTE b)
{
	BYTE tmp = *a;

	*a = *b;
	*b = tmp;
}

#pragma code_seg(".pedll64")
static void init_sbox(LPBYTE RC4_SBOX)
{
	for (int i = 0; i < 256; i++)
		RC4_SBOX[i] = i;
}

#pragma code_seg(".pedll64")
static void init_sbox_key(LPBYTE RC4_SBOX, PBYTE key, int length)
{
	int j = 0;

	for(int i = 0; i < 256; i++)
	{
		j = (j + RC4_SBOX[i] + key[i % length]) % 256;
		swap(&RC4_SBOX[i], &RC4_SBOX[j]);
	}
}

#pragma code_seg(".pedll64")
static void cypher_msg(LPBYTE RC4_SBOX, PBYTE msg, int length)
{
	int i=0, j=0;

	while(length > 0)
	{
		i = (i+1) % 256;
		j = (j+RC4_SBOX[i]) % 256;
		swap(&RC4_SBOX[i], &RC4_SBOX[j]);
		*msg++ ^= RC4_SBOX[(RC4_SBOX[i] + RC4_SBOX[j]) % 256];
		length--;
	}
}

#pragma code_seg(".pedll64")
void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS64 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize)
{
	if (dwRelocSize == 0 || lpRelocAddress == NULL)
		return;	// no reloc table here!

	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;

	if (relocation_page == NULL)
		return;	// no relocation page available!

	// for each page!
	while(relocation_page->BlockSize > 0)
	{
		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA > (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
		{	// skip current page!
			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
		}
		else
		{	// ok.. we can process this page!
			typedef short relocation_entry;

			int BlockSize = relocation_page->BlockSize - 8;
			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);

			while(BlockSize > 0)
			{
				short type = ((*entries & 0xf000) >> 12);
				long offset = (*entries & 0x0fff);

				ULONG64 *ptr = CALC_OFFSET(PULONG64, pModule, offset + relocation_page->PageRVA);
				ULONG64 value = *ptr;
				ULONG64 dwNewValue = 0;

				switch(type)
				{
					case IMAGE_REL_BASED_HIGHLOW:
						value = value - pImageNtHeader->OptionalHeader.ImageBase;
						value = value + (DWORD) pModule;
						*ptr = value;
						break;
					case IMAGE_REL_BASED_DIR64:
						dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG64) pModule;
						*ptr = dwNewValue;
						break;
				}

				entries++;
				BlockSize -= 2;
			}

			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
		}
	}

}



#pragma code_seg(".pedll64")
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

#pragma code_seg(".pedll64")
void _DisableThreadLibraryCalls(HMODULE hKernel32, HINSTANCE hInstance)
{
	char szDisableThreadLibraryCalls[] = { 'D', 'i', 's', 'a', 'b', 'l', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'C', 'a', 'l', 'l', 's', 00 };
	typedef BOOL (WINAPI *DisableThreadLibraryCalls_ptr)(HMODULE hModule);

	DisableThreadLibraryCalls_ptr f = (DisableThreadLibraryCalls_ptr) _GetProcAddress(hKernel32, szDisableThreadLibraryCalls);
	f(hInstance);
}

#pragma code_seg(".pedll64")
BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	__declspec(align(16)) char szKernel32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0x00 };
	__declspec(align(16)) char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (g_hKernel32 == NULL)
		{
			g_hKernel32 = hinstDLL;

			HMODULE h = _LoadLibraryA(szKernel32);
			_VirtualProtect = (VirtualProtect_ptr) _GetProcAddress(h, szVirtualProtect);
			_DisableThreadLibraryCalls(h, hinstDLL);
			//decrypt(hinstDLL, fdwReason, lpvReserved);
			
			_InitializeCriticalSection(h, &_critical_section);
			return TRUE;

		}
	}

	if (fdwReason == DLL_PROCESS_DETACH)
	{
		HMODULE h = _LoadLibraryA(szKernel32);
		_DeleteCriticalSection(h, &_critical_section);
	}

	if (g_decrypted == TRUE)
		return _EntryPoint(hinstDLL, fdwReason, lpvReserved);
	else
		return TRUE;
}

#pragma code_seg(".pedll64")
extern "C" 
void WINAPI DELAYDECRYPT()
{
	if (g_decrypted == FALSE)
	{
		char szKernel32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0x00 };
		HMODULE h = _LoadLibraryA(szKernel32);
		_EnterCriticalSection(h, &_critical_section);
		g_decrypted = decrypt(g_hKernel32, DLL_PROCESS_ATTACH, NULL);
		_EntryPoint(g_hKernel32, DLL_PROCESS_ATTACH, NULL);
		_LeaveCriticalSection(h, &_critical_section);
	}
}

#endif
