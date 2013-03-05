#include <Windows.h>

#include "symbols.h"

#include "rva.h"
#include "tea.h"
#include "macro.h"

#pragma section(".peexe32", read, write, execute)

typedef short relocation_entry;

/**
 *	!_configuration
 **/
typedef struct _configuration
{
	ULONG64			dwRelocSize;
	ULONG64			lpRelocAddress;
	ULONG64			_key0;
	ULONG64			_key1;
	ULONG64			_baseAddress;
	BYTE			decrypted;
} CONFIGURATION;

__declspec(allocate(".peexe32"))
CONFIGURATION exe_configuration = {
		0xBABECAFEBAD00021,
		0xBABECAFEBAD00020,
		0xBABECAFEBAD00010,
		0xBABECAFEBAD00011,
		0xBABECAFEBAD00100,
		FALSE
};

__declspec(allocate(".peexe32"))
VirtualProtect_ptr	_exe_VirtualProtect;

__declspec(allocate(".peexe32"))
VirtualAlloc_ptr	_exe_VirtualAlloc;


typedef struct base_relocation_block
{
	DWORD PageRVA;
	DWORD BlockSize;
} base_relocation_block_t;

typedef struct base_relocation_entry
{
	WORD offset : 12;
	WORD type : 4;
} base_relocation_entry_t;

#define relocation_block_t base_relocation_block_t
#define relocation_entry_t base_relocation_entry_t

#ifdef _BUILD32


typedef SIZE_T (WINAPI *VirtualQuery_ptr)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

#pragma code_seg(".peexe32")
static LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders32->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders32->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

#pragma code_seg(".peexe32")
void reloc_entry_get(relocation_entry *entry, short *type, long *offset)
{
	*type = ((*entry & 0xf000) >> 12);
	*offset = (*entry & 0x0fff);
	return;
}

#pragma code_seg(".peexe32")
static void Reloc_Process_Entry()
{

}

#pragma code_seg(".peexe32")
static void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer)
{
	if (dwRelocSize == 0 || lpRelocAddress == NULL)
	{
		return;	// no reloc table here!
	}

	DWORD ImageBase = (DWORD) exe_configuration._baseAddress;

	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;

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
				short type;
				long offset;

				reloc_entry_get(entries, &type, &offset);

				ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
				ULONG value = *ptr;
				ULONG dwNewValue = 0;

				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					value = value - ImageBase;
					value = value + (DWORD) pModule;
					*ptr = value;
				}
				else
				{	// nothing!
				}
		
				entries++;
				BlockSize -= 2;
			}

			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
		}
	}

}

#pragma code_seg(".peexe32")
static void __memcpy(char *dst, char *src, int size)
{
	while(size-- > 0)
	{
		*dst++=*src++;
	}
}

typedef void (tea_decrypt_ptr)(uint32_t* v, uint32_t* k);

#pragma code_seg(".peexe32")
static tea_decrypt_ptr *load_decrypt()
{
	char *decrypt = (char *)_exe_VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	void *start = static_cast<void *>(&tea_decrypt);
	void *end = static_cast<void *>(&tea_decrypt_end_marker);
	int size = static_cast<int>((int) end - (int) start);

	char *src = static_cast<char *>(start);
	char *dst = decrypt;

	while(size-- > 0) 
	{
		*dst ++ = (*src++ ^ 0x66); 
	}

	return (tea_decrypt_ptr *) decrypt;
}


#pragma code_seg(".peexe32")
static BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS32 pImageNtHeaders32 = CALC_OFFSET(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);
	
	tea_decrypt_ptr *decrypt = load_decrypt();

	if (pImageNtHeaders32->Signature != IMAGE_NT_SIGNATURE)
	{	// I'm invalid file?
		return FALSE;	
	}
	
	//short NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections - 1;	// I'm on tail!!! please don't patch myself!
	short NumberOfSections = 2;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32);
		
	DWORD dwOldPermissions = NULL, dwDummy = 0;

	while(NumberOfSections > 0)
	{
		pSection++;
		LPDWORD NameDW = (LPDWORD) (pSection->Name);
		if (!((NameDW[1] == 0x74 && NameDW[0] == 0x7865742e) ||
			(NameDW[1] == 0x61 && NameDW[0] == 0x7461642e)))
		{
			continue;
		}

		
		NumberOfSections--;
		dwOldPermissions = 0;
		dwDummy = 0;

		//if ((pSection->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)	// shared memory!
		//	continue;
		
		LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders32, (LPVOID) pSection->VirtualAddress);

		_exe_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

		ULONG64 rc4key[2] = { exe_configuration._key0, exe_configuration._key1 };

		DWORD sbox[4];

		uint32_t *key = (uint32_t *) sbox;
		__memcpy((char *)key, (char *) rc4key, 16);
		LPDWORD encptr = (LPDWORD) lpAddress;

		for(DWORD dwPtr = 0; dwPtr < pSection->SizeOfRawData; dwPtr += 8, encptr += 2)
			decrypt((uint32_t *) encptr, key);

		_exe_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);
		//pSection++;

	}
	

	NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections - 1;	// I'm on tail!!! please don't patch myself!
	pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32);
		
	while(NumberOfSections > 0)
	{
		pSection++;
		dwOldPermissions = 0;
		dwDummy = 0;
		NumberOfSections--;
		if (exe_configuration.decrypted == 0)	// relocation must be done only 1st time!
		{
			// apply reloc in current section!
			LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders32, (LPVOID) pSection->VirtualAddress);
			_exe_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

			ULONG ptrReloc = CALC_OFFSET(ULONG, pImageDosHeader, (ULONG) exe_configuration.lpRelocAddress);
			Reloc_Process((LPVOID) pImageDosHeader, pImageNtHeaders32, pSection, (LPVOID) ptrReloc, exe_configuration.dwRelocSize, IMAGE_FIRST_SECTION(pImageNtHeaders32));
			_exe_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);
		}
	}

	//
	return TRUE;
}

#endif

#pragma code_seg(".peexe32")
char*	_strVirtualProtect()
{	
	char dummy[128];
	char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };


	for(int i = 0; i < sizeof(dummy); i++)
	{
		i += ('a' + ( i % 27));
	}

	for(int i = 64; i < sizeof(szVirtualProtect); i++)
	{
		dummy[i] = szVirtualProtect[i-64];
	}

	return &dummy[64];
}

#ifdef _BUILD32
//#pragma code_seg(".peexe32")
//static BOOL bProcessed = FALSE;

struct _strings
{
	DWORD szKernel32[3];
	char szVirtualProtect[0x20];
	char szVirtualQuery[0x20];
	char szGetModuleFileNameA[0x40];
	char szGetModuleHandleA[0x40];
};

#pragma code_seg(".peexe32")
void WINAPI __fuckcrt0startup(struct _strings *ptr)
{
	ptr->szKernel32[0] = 0x4E52454B;
	ptr->szKernel32[1] = 0x32334C45;
	ptr->szKernel32[2] = 0x0;
	
	char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };
	char szVirtualQuery[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', 0x00 };
	char szGetModuleFileNameA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x00 };
	char szGetModuleHandleA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x00 };

	__memcpy(ptr->szVirtualProtect, szVirtualProtect, sizeof(szVirtualProtect));
	__memcpy(ptr->szVirtualQuery, szVirtualQuery, sizeof(szVirtualQuery));
	__memcpy(ptr->szGetModuleFileNameA, szGetModuleFileNameA, sizeof(szGetModuleFileNameA));
	__memcpy(ptr->szGetModuleHandleA, szGetModuleHandleA, sizeof(szGetModuleHandleA));
}

#pragma code_seg(".peexe32")
extern "C"
void WINAPI __crt0Startup(DWORD dwParam)
{
	struct _strings init;

	__fuckcrt0startup(&init);
		
	HMODULE h = _exe_LoadLibraryA((char *) init.szKernel32);
	VirtualProtect_ptr p = (VirtualProtect_ptr) _exe_GetProcAddress(h, init.szVirtualProtect);
	VirtualQuery_ptr _vquery = (VirtualQuery_ptr) _exe_GetProcAddress(h, init.szVirtualQuery);

	MEMORY_BASIC_INFORMATION buffer;

	_vquery((LPVOID) _GETBASE(), &buffer, sizeof(buffer));
	
	DWORD newptr = buffer.RegionSize + (DWORD) buffer.BaseAddress;

	_vquery((LPVOID) newptr, &buffer, sizeof(buffer));
	
	DWORD ignore0 = 0x32323232;
	DWORD ignore1 = 0x64646464;

	p((LPVOID) newptr, buffer.RegionSize, PAGE_EXECUTE_READWRITE, &ignore0);
	p((LPVOID) h, 0x1000, PAGE_READONLY, &ignore1);
	_exe_VirtualProtect = p;
	
	exe_g_hKernel32 = (HMODULE) _GETBASE();
		
	GetModuleHandleA_ptr _GetModuleHandleA = (GetModuleHandleA_ptr) _exe_GetProcAddress(h, init.szGetModuleHandleA);

	 //= _GetModuleHandleA(NULL);
			
	init.szVirtualProtect[7] = 'A';
	init.szVirtualProtect[8] = 'l';
	init.szVirtualProtect[9] = 'l';
	init.szVirtualProtect[0x0a] = 'o';
	init.szVirtualProtect[0x0b] = 'c';
	init.szVirtualProtect[0x0c] = 0x00;

	_exe_VirtualAlloc = (VirtualAlloc_ptr) _exe_GetProcAddress(h, init.szVirtualProtect);

	LPBYTE lpEntry = (LPBYTE) _exe_CreateFileA;

	if (*lpEntry == '~')
	{
		__memcpy((char *)lpEntry+7, (char *)lpEntry+11, 14); 

		LPVOID lpSymbol = _exe_GetProcAddress(h, (char *)(lpEntry+1));
		*lpEntry++ = 0xB8;	// mov eax, imm32
		(*(LPDWORD)lpEntry) = (DWORD)lpSymbol;
		lpEntry+=4;
		*lpEntry++ = 0xff;	// jmp eax
		*lpEntry = 0xe0;	
	}
	
	if (exe_configuration.decrypted == 0)
		exe_configuration.decrypted = decrypt(exe_g_hKernel32, DLL_PROCESS_ATTACH, NULL);

	BOOL bConditions[4];
	bConditions[0] = ((dwParam >> 24) == 0x60);
	bConditions[1] = ((dwParam >> 16) & 0xff) == 0x0d;
	bConditions[2] = ((dwParam >> 8) & 0xff) == 0xb4;
	bConditions[3] = (dwParam & 0xff) == 0xb3;
	
	if (bConditions[0] && bConditions[1] && bConditions[2] && bConditions[3])
	{
		return;
	}
	_CrtStartup(exe_g_hKernel32);
}

#endif
