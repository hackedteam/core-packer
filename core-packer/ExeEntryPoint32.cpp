#include <Windows.h>

#include "symbols.h"

#include "rva.h"
#include "tea.h"
#include "macro.h"

#pragma section(".peexe", read, write, execute)

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

__declspec(allocate(".peexe"))
CONFIGURATION exe_configuration = {
		0xBABECAFEBAD00021,
		0xBABECAFEBAD00020,
		0xBABECAFEBAD00010,
		0xBABECAFEBAD00011,
		0xBABECAFEBAD00100,
		FALSE
};

__declspec(allocate(".peexe"))
VirtualProtect_ptr	_exe_VirtualProtect;

__declspec(allocate(".peexe"))
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

#pragma code_seg(".peexe")
static LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders32->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders32->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

//#pragma code_seg(".peexe")
//static BOOL reloc_is_text(PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionText, DWORD offset)
//{
//	DWORD ImageBase = (DWORD) exe_configuration._baseAddress;
//
//	DWORD minVirtualAddress = pSectionText->VirtualAddress;
//	DWORD maxVirtualAddress = pSectionText->VirtualAddress + pSectionText->Misc.VirtualSize;
//
//	offset -= ImageBase;
//	
//	if (minVirtualAddress <= offset && offset < maxVirtualAddress)
//		return TRUE;
//
//	return FALSE;
//}

//#pragma code_seg(".peexe")
//static void reloctext(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, LPVOID lpTextAddr)
//{
//	DWORD ImageBase = (DWORD) exe_configuration._baseAddress;
//
//	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;
//
//	if (dwRelocSize == 0 || relocation_page == NULL)
//		return;	// no reloc table here!
//
//	// for each page!
//	while(relocation_page->BlockSize > 0)
//	{
//		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA >= (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
//		{	// skip current page!
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//		else
//		{	// ok.. we can process this page!
//			typedef short relocation_entry;
//
//			int BlockSize = relocation_page->BlockSize - 8;
//			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);
//
//			while(BlockSize > 0)
//			{
//				short type = ((*entries & 0xf000) >> 12);
//				long offset = (*entries & 0x0fff);
//
//				//ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
//				ULONG *ptr = CALC_OFFSET(PULONG, lpTextAddr, offset + relocation_page->PageRVA - 0x1000);	// base address of .text
//				ULONG value = *ptr;
//				ULONG dwNewValue = 0;
//
//				if (reloc_is_text(pImageNtHeader, pSectionPointer, (DWORD) value) == FALSE)
//				{
//					switch(type)
//					{
//						case IMAGE_REL_BASED_HIGHLOW:
//							value = value - ImageBase;
//							value = value + (DWORD) pModule;
//							*ptr = value;
//							break;
//						case IMAGE_REL_BASED_DIR64:
//							dwNewValue = value - ImageBase + (ULONG) pModule;
//							*ptr = dwNewValue;
//							break;
//						default:
//							break;
//					}
//				}
//				else
//				{	// applying different patch!
//					if (type == IMAGE_REL_BASED_HIGHLOW) 
//					{
//							value = value - ImageBase - 0x1000;
//							value = value + (DWORD) lpTextAddr;
//							*ptr = value;
//					}
//				}
//				
//				entries++;
//
//				BlockSize -= 2;
//			}
//
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//	}
//
//}



#pragma code_seg(".peexe")
void reloc_entry_get(relocation_entry *entry, short *type, long *offset)
{
	*type = ((*entry & 0xf000) >> 12);
	*offset = (*entry & 0x0fff);
	return;
}

#pragma code_seg(".peexe")
static void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer)
{
	DWORD ImageBase = (DWORD) exe_configuration._baseAddress;

	if (dwRelocSize == 0 || lpRelocAddress == NULL)
		return;	// no reloc table here!

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

				switch(type)
				{
					case IMAGE_REL_BASED_HIGHLOW:
						value = value - ImageBase;
						value = value + (DWORD) pModule;
						*ptr = value;
						break;
					case IMAGE_REL_BASED_DIR64:
						dwNewValue = value - ImageBase + (ULONG) pModule;
						*ptr = dwNewValue;
						break;
					default:
						break;
				}
		
				entries++;
				BlockSize -= 2;
			}

			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
		}
	}

}

#pragma code_seg(".peexe")
static void __memcpy(char *dst, char *src, int size)
{
	while(size-- > 0)
	{
		*dst++=*src++;
	}
}

typedef void (tea_decrypt_ptr)(uint32_t* v, uint32_t* k);

#pragma code_seg(".peexe")
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


#pragma code_seg(".peexe")
static BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS32 pImageNtHeaders32 = CALC_OFFSET(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);
	
	tea_decrypt_ptr *decrypt = load_decrypt();

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

		_exe_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

		ULONG64 rc4key[2] = { exe_configuration._key0, exe_configuration._key1 };

		DWORD sbox[4];

		uint32_t *key = (uint32_t *) sbox;
		__memcpy((char *)key, (char *) rc4key, 16);

		if ((pSection->Characteristics & 0x03) == 3)
		{
			DWORD sizeOfSection = 
				pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
					- pSection->VirtualAddress 
					- pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
						
			LPVOID lpNewAddress = CALC_OFFSET(LPVOID, lpAddress, pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
			
			LPDWORD encptr = (LPDWORD) lpNewAddress;

			for(DWORD dwPtr = 0; dwPtr < sizeOfSection; dwPtr += 8, encptr += 2)
				decrypt((uint32_t *) encptr, key);

		} 
		else if (pSection->Characteristics & 0x02)
		{	// packed section!
			LPDWORD lpSectionName = (LPDWORD) pSection->Name;
			if (*lpSectionName == 0x7865742e)
			{	// text section! load from disk!!
				char szFileName[MAX_PATH];
				DWORD dw = _exe_GetModuleFileNameA(hinstDLL, szFileName, MAX_PATH);
				HANDLE h = _exe_CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
				_exe_SetFilePointer(h, 0x400, 0, SEEK_SET);			//	<< 0x400 - offset on physical disk of first section
				_exe_ReadFile(h, lpAddress, pSection->Misc.VirtualSize, &dw, NULL); //_ReadFile(h, lpAddress, pSection->Misc.VirtualSize, &dw, NULL);
				_exe_CloseHandle(h);
				//cypher_msg(sbox, (PBYTE) g_lpTextBaseAddr, pSection->Misc.VirtualSize); // cypher_msg(sbox, (PBYTE) lpAddress, pSection->Misc.VirtualSize);
				LPDWORD encptr = (LPDWORD) lpAddress;

				for(DWORD dwPtr = 0; dwPtr < pSection->Misc.VirtualSize; dwPtr += 8, encptr += 2)
					decrypt((uint32_t *) encptr, key);
///////////	
			}
			else
			{

				LPDWORD encptr = (LPDWORD) lpAddress;

				for(DWORD dwPtr = 0; dwPtr < pSection->SizeOfRawData; dwPtr += 8, encptr += 2)
					decrypt((uint32_t *) encptr, key);
			}
		}

		// apply reloc in current section!
		ULONG ptrReloc = CALC_OFFSET(ULONG, pImageDosHeader, (ULONG) exe_configuration.lpRelocAddress);

		if (exe_configuration.decrypted == 0)	// relocation must be done only 1st time!
		{	// it's first time?
				Reloc_Process((LPVOID) pImageDosHeader, pImageNtHeaders32, pSection, (LPVOID) ptrReloc, exe_configuration.dwRelocSize, IMAGE_FIRST_SECTION(pImageNtHeaders32));
		}
			
		_exe_VirtualProtect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);

	}
	
	//
	return TRUE;
}

#endif


#ifdef _BUILD32

#pragma code_seg(".peexe")
extern "C"
void WINAPI __crt0Startup(DWORD dwParam)
{

	DWORD szKernel32[] = { 0x4E52454B, 0x32334C45, 0x00 };
	char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };
	char szGetModuleFileNameA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x00 };
	char szGetModuleHandleA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x00 };
	
	exe_g_hKernel32 = (HMODULE) _GETBASE();

	HMODULE h = _exe_LoadLibraryA((char *) szKernel32);
	_exe_VirtualProtect = (VirtualProtect_ptr) _exe_GetProcAddress(h, szVirtualProtect);
	GetModuleHandleA_ptr _GetModuleHandleA = (GetModuleHandleA_ptr) _exe_GetProcAddress(h, szGetModuleHandleA);

	 //= _GetModuleHandleA(NULL);
			
	szVirtualProtect[7] = 'A';
	szVirtualProtect[8] = 'l';
	szVirtualProtect[9] = 'l';
	szVirtualProtect[0x0a] = 'o';
	szVirtualProtect[0x0b] = 'c';
	szVirtualProtect[0x0c] = 0x00;

	_exe_VirtualAlloc = (VirtualAlloc_ptr) _exe_GetProcAddress(h, szVirtualProtect);

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
	decrypt(exe_g_hKernel32, DLL_PROCESS_ATTACH, NULL);

	BOOL bConditions[4];
	bConditions[0] = ((dwParam >> 24) == 0xf1);
	bConditions[1] = ((dwParam >> 16) & 0xff) == 0xc4;
	bConditions[2] = ((dwParam >> 8) & 0xff) == 0xb4;
	bConditions[3] = (dwParam & 0xff) == 0xb3;
	
	if (bConditions[0] && bConditions[1] && bConditions[2] && bConditions[3])
	{
		return;
	}
	_CrtStartup(exe_g_hKernel32 + 0x1000);
}

#endif
