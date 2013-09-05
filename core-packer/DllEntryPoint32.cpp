#include <Windows.h>

#define _UNPACKERSECTION

#ifdef _BUILD32

#include "symbols.h"
#include "dll32.h"

#include "reloc.h"
//#include "macro.h"
#include "decrypt.h"

#pragma section(".pedll32", read, write, execute)

struct _vtbl
{
	VirtualProtect_ptr	mem_protect;
	VirtualAlloc_ptr	mem_alloc;

	CreateFileA_ptr		file_open;
	SetFilePointer_ptr	file_seek;

};

//__declspec(allocate(".pedll32"))

//CONFIGURATION dll32_configuration = {
//		0xBABECAFEBAD00021,
//		0xBABECAFEBAD00020,
//		0xBABECAFEBAD00010,
//		0xBABECAFEBAD00011,
//		0xBABECAFEBAD00100,
//		FALSE,
//		NULL
//};

__declspec(allocate(".pedll32"))
ULONG64				dwRelocSize			= 0xBABECAFEBAD00021;

__declspec(allocate(".pedll32"))
ULONG64				lpRelocAddress		= 0xBABECAFEBAD00020;

__declspec(allocate(".pedll32"))
ULONG64				_rc4key0			= 0xBABECAFEBAD00010;

__declspec(allocate(".pedll32"))
ULONG64				_rc4key1			= 0xBABECAFEBAD00011;

__declspec(allocate(".pedll32"))
ULONG64				_baseAddress		= 0xBABECAFEBAD00100;

// Fixed symbols from loader
//__declspec(allocate(".pedll32"))
//LoadLibraryA_ptr	_dll32_LoadLibraryA		= (LoadLibraryA_ptr) 0xBABECAFEBAD00004;

//__declspec(allocate(".pedll32"))
//GetProcAddress_ptr	_dll32_GetProcAddress		= (GetProcAddress_ptr) 0xBABECAFEBAD00003;


__declspec(allocate(".pedll32"))
VirtualProtect_ptr	_VirtualProtect;

__declspec(allocate(".pedll32"))
VirtualAlloc_ptr	_VirtualAlloc;

extern "C" {

__declspec(allocate(".pedll32"))
BYTE	g_decrypted = FALSE;

__declspec(allocate(".pedll32"))
LPVOID	g_lpTextBaseAddr = (LPVOID) 0L;
}

__declspec(allocate(".pedll32"))
CRITICAL_SECTION _critical_section;

#pragma code_seg(".pedll32")
void __memcpy(char *dst, char *src, int size)
{
	int dw = size / 4;

	if (dw > 0)
	{
		size -= dw * 4;
		DWORD *dDST = (DWORD *) dst;
		DWORD *dSRC = (DWORD *) src;
				
		while(dw-- > 0)
			*dDST++ = *dSRC++;
	}

	while(size-- > 0)
	{
		*dst++=*src++;
	}
}

#pragma code_seg(".pedll32")
int __memcmp(char *dst, char *src, int size)
{
	if ((size % 4) == 0)
	{	// optimized version ..
		size /= 4;
		DWORD *dDST = (DWORD *) dst;
		DWORD *dSRC = (DWORD *) src;

		while(size-- > 0)
		{
			if (*dDST != *dSRC)
				goto error;

			dDST++; dSRC++;
		}
		
		goto done;
	}
	else if ((size % 2) == 0)
	{	// optimized version ..
		size /= 4;
		WORD *wDST = (WORD *) dst;
		WORD *wSRC = (WORD *) src;

		while(size-- > 0)
		{
			if (*wDST != *wSRC)
				goto error;

			wDST++;
			wSRC++;
		}
		
		goto done;
	}
	else
	{
		while(size-- > 0)
		{
			if (*dst != *src)
				goto error;
			dst++;
			src++;
		}
	}

	goto done;
error:
	return -1;
done:
	return 0;
}

#pragma code_seg(".pedll32")
__declspec(naked)
HMODULE WINAPI _dll32_LoadLibraryA(LPCTSTR lpFileName)
{
	__asm
	{
		mov esp, ebp
		pop ebp
		mov eax, dword ptr [g_hKernel32]
		add eax, 11223340h
		jmp dword ptr ds:[eax]
		nop
		nop
		nop
		nop
		nop
	}
}

#pragma code_seg(".pedll32")
__declspec(naked)
static LPVOID _CALC_OFFSET(LPVOID base, DWORD disp)
{
	__asm {
		mov	eax, dword ptr [esp+4]
		add eax, dword ptr [esp+8]
		ret 8
	}
}

#define CALC_OFFSET(TYPE, base, disp) (TYPE) _CALC_OFFSET((LPVOID) base, disp)

#pragma code_seg(".pedll32")
__declspec(naked)
static void __forceinline swap(PBYTE a, PBYTE b)
{
	__asm
	{
		mov al, byte ptr [esp+4]
		mov ah, byte ptr [esp+8]
		xchg al, ah
		mov byte ptr [esp+4], al
		mov byte ptr [esp+8], ah
		ret 8
	}
}

#pragma code_seg(".pedll32")
static void __forceinline init_sbox(LPBYTE RC4_SBOX)
{
	for (int i = 0; i < 256; i++)
		RC4_SBOX[i] = i;
}

#pragma code_seg(".pedll32")
static void __forceinline rc4_sbox_key(LPBYTE RC4_SBOX, PBYTE key, int length)
{
	for(int i = 0, j=0; i < 256; i++)
	{
		j = (j + RC4_SBOX[i] + key[i % length]) % 256;
		swap(&RC4_SBOX[i], &RC4_SBOX[j]);
	}
}

#pragma code_seg(".pedll32")
static void __forceinline cypher_msg(LPBYTE RC4_SBOX, PBYTE msg, int length)
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
#pragma code_seg(".pedll32")
static LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG64) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG64) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders64->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders64->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

#pragma code_seg(".pedll32")
static BOOL reloc_is_text(PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionText, DWORD offset)
{
	DWORD ImageBase = (DWORD) _baseAddress;

	DWORD minVirtualAddress = pSectionText->VirtualAddress;
	DWORD maxVirtualAddress = pSectionText->VirtualAddress + pSectionText->Misc.VirtualSize;

	offset -= ImageBase;
	
	if (minVirtualAddress <= offset && offset < maxVirtualAddress)
		return TRUE;

	return FALSE;
}

#pragma code_seg(".pedll32")

#pragma code_seg(".pedll32")
static void reloctext(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, LPVOID lpTextAddr)
{
	DWORD ImageBase = (DWORD) _baseAddress;

	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;

	if (dwRelocSize == 0 || relocation_page == NULL)
		return;	// no reloc table here!

	// for each page!
	while(relocation_page->BlockSize > 0)
	{
		if (relocation_page->PageRVA >= pSectionPointer->VirtualAddress && relocation_page->PageRVA < (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
		{	// ok.. we can process this page!
			typedef short relocation_entry;

			int BlockSize = relocation_page->BlockSize - 8;
			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);

			while(BlockSize > 0)
			{
				short type = ((*entries & 0xf000) >> 12);
				long offset = (*entries & 0x0fff);

				//ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
				ULONG *ptr = CALC_OFFSET(PULONG, lpTextAddr, offset + relocation_page->PageRVA - 0x1000);	// base address of .text
				ULONG value = *ptr;
				ULONG dwNewValue = 0;

				if (reloc_is_text(pImageNtHeader, pSectionPointer, (DWORD) value) == FALSE)
				{
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
				}
				else
				{	// applying different patch!
					if (type == IMAGE_REL_BASED_HIGHLOW) 
					{
							value = value - ImageBase - 0x1000;
							value = value + (DWORD) lpTextAddr;
							*ptr = value;
					}
				}
				
				entries++;

				BlockSize -= 2;
			}

		}

		// move cursor on next page
		relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
	}

}

#pragma code_seg(".pedll32")
static void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer, LPVOID lpTextAddr)
{
	DWORD ImageBase = (DWORD) _baseAddress;

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

				ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
				ULONG value = *ptr;
				ULONG dwNewValue = 0;

				if (reloc_is_text(pImageNtHeader, pTextPointer, (DWORD) value) == FALSE)
				{
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
				}
				else
				{	// applying different patch!
					if (type == IMAGE_REL_BASED_HIGHLOW) 
					{
							value = value - ImageBase - 0x1000;
							value = value + (DWORD) lpTextAddr;
							*ptr = value;
					}
				}


				/*switch(type)
				{
					case IMAGE_REL_BASED_HIGHLOW:
						value = value - pImageNtHeader->OptionalHeader.ImageBase;
						value = value + (DWORD) pModule;
						*ptr = value;
						break;
					case IMAGE_REL_BASED_DIR64:
						dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG) pModule;
						*ptr = dwNewValue;
						break;
				}*/
				entries++;
				BlockSize -= 2;
			}

			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
		}
	}

}

#pragma code_seg(".pedll32")
static LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders32->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders32->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

#pragma code_seg(".pedll32")
BOOL WINAPI decrypt(struct _vtbl *vtbl, HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
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

		vtbl->mem_protect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

		BYTE sbox[256];
		ULONG64 rc4key[2] = { _rc4key0, _rc4key1 };

		init_sbox(sbox);
		rc4_sbox_key(sbox, (PBYTE) &rc4key, 16);

		char szText[] = { '.', 't', 'e', 'x', 't', 0x00 };
		char szData[] = { '.', 'd', 'a', 't', 'a', 0x00 };

		if (__memcmp((char *) pSection->Name, szText, 5) == 0)
		{
			g_lpTextBaseAddr = vtbl->mem_alloc(0x0, pSection->Misc.VirtualSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			__memcpy((char *) g_lpTextBaseAddr, (char *) lpAddress, pSection->SizeOfRawData);	// transfer data into new section "block"
			cypher_msg(sbox, (PBYTE) g_lpTextBaseAddr, pSection->SizeOfRawData);	// decrypt done!
		}
		else if (__memcmp((char *) pSection->Name, szData, 5) == 0)
		{
			cypher_msg(sbox, (PBYTE) lpAddress, pSection->SizeOfRawData);	// decrypt done!
		}

//
//		if ((pSection->Characteristics & 0x03) == 3)
//		{
//			DWORD sizeOfSection = 
//				pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
//					- pSection->VirtualAddress 
//					- pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
//						
//			LPVOID lpNewAddress = CALC_OFFSET(LPVOID, lpAddress, pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
//
//			cypher_msg(sbox, (PBYTE) lpNewAddress, sizeOfSection);	// decrypt done!
//
//		} 
//		else if (pSection->Characteristics & 0x02)
//		{	// packed section!
//			LPDWORD lpSectionName = (LPDWORD) pSection->Name;
//			if (*lpSectionName == 0x7865742e)
//			{	// text section! load from disk!!
//				char szFileName[MAX_PATH];
//				DWORD dw = _GetModuleFileNameA(hinstDLL, szFileName, MAX_PATH);
//				HANDLE h = vtbl->file_open(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
//
//				g_lpTextBaseAddr = vtbl->mem_alloc(0x0, pSection->Misc.VirtualSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//
//				vtbl->file_seek(h, 0x400, 0, SEEK_SET);			//	<< 0x400 - offset on physical disk of first section
//				_ReadFile(h, g_lpTextBaseAddr, pSection->Misc.VirtualSize, &dw, NULL); //_ReadFile(h, lpAddress, pSection->Misc.VirtualSize, &dw, NULL);
//				_CloseHandle(h);
//				cypher_msg(sbox, (PBYTE) g_lpTextBaseAddr, pSection->Misc.VirtualSize); // cypher_msg(sbox, (PBYTE) lpAddress, pSection->Misc.VirtualSize);
/////////////	
//			}
//			else
//				
//		}

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
			
		vtbl->mem_protect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);

	}
	
	return TRUE;
}

#pragma code_seg(".pedll32")
static void _InitializeCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll32")
static void _LeaveCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'L', 'e', 'a', 'v', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll32")
static void _DeleteCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'D', 'e', 'l', 'e', 't', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll32")
static void _EnterCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[] = { 'E', 'n', 't', 'e', 'r', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll32")
static HMODULE get_Kernel32(void)
{
	char szKernel32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0x00 };
	return _dll32_LoadLibraryA(szKernel32);
}

#pragma code_seg(".pedll32")
static BOOL _DisableThreadLibraryCalls(HMODULE hKernel32, HMODULE hModule)
{
	char szDisableThreadLibraryCalls[] = { 'D', 'i', 's', 'a', 'b', 'l', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'C', 'a', 'l', 'l', 's', 00 };

	typedef BOOL (WINAPI *DisableThreadLibraryCalls_ptr)(HMODULE hModule);
	DisableThreadLibraryCalls_ptr f = (DisableThreadLibraryCalls_ptr) _dll32_GetProcAddress(hKernel32, szDisableThreadLibraryCalls);

	return f(hModule);
}

#pragma code_seg(".pedll32")
BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	char szGetModuleFileNameA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x00 };

	// find patterns!
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS pNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
	_baseAddress = pNtHeader->OptionalHeader.ImageBase;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (g_hKernel32 == NULL)
		{
			g_hKernel32 = hinstDLL;

			HMODULE h = get_Kernel32();
			
			_InitializeCriticalSection(h, &_critical_section);

			_DisableThreadLibraryCalls(h, hinstDLL);
			//decrypt(hinstDLL, fdwReason, lpvReserved);
			
			return TRUE;

		}
	}

	if (fdwReason == DLL_PROCESS_DETACH)
	{
		HMODULE h = get_Kernel32();

		_DeleteCriticalSection(h, &_critical_section);
	}

	if (g_decrypted == TRUE)
		return _EntryPoint(g_lpTextBaseAddr, hinstDLL, fdwReason, lpvReserved);
	else
		return TRUE;	
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) 
LPVOID WINAPI DELAYDECRYPT(DWORD dwX)
{
	struct _vtbl vtable;
	LPVOID dwResult;

	// prolog
	__asm
	{
		push	ebp
		mov		ebp, esp
		sub		esp, 40h

	}

	vtable.mem_protect = _VirtualProtect;
	vtable.mem_alloc = _VirtualAlloc;
	vtable.file_open = _CreateFileA;
	vtable.file_seek = _SetFilePointer;
	
	//{ , _VirtualAlloc, _CreateFileA, _SetFilePointer };

	_EnterCriticalSection(get_Kernel32(), &_critical_section);

	if (g_decrypted == FALSE)
	{
		char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };
		_VirtualProtect = (VirtualProtect_ptr) _dll32_GetProcAddress(get_Kernel32(), szVirtualProtect);
		szVirtualProtect[7] = 'A';
		szVirtualProtect[8] = 'l';
		szVirtualProtect[9] = 'l';
		szVirtualProtect[0x0a] = 'o';
		szVirtualProtect[0x0b] = 'c';
		szVirtualProtect[0x0c] = 0x00;

		_VirtualAlloc = (VirtualAlloc_ptr) _dll32_GetProcAddress(get_Kernel32(), szVirtualProtect);

		vtable.mem_protect	= _VirtualProtect;
		vtable.mem_alloc	= _VirtualAlloc;

		g_decrypted = decrypt(&vtable, g_hKernel32, DLL_PROCESS_ATTACH, NULL);

		_EntryPoint(g_lpTextBaseAddr, g_hKernel32, DLL_PROCESS_ATTACH, NULL);
	}
	else if (g_decrypted == 2)
	{
		decrypt(&vtable, g_hKernel32, DLL_PROCESS_ATTACH, NULL);
	}

	_LeaveCriticalSection(get_Kernel32(), &_critical_section);

	dwResult =  CALC_OFFSET(LPVOID, g_lpTextBaseAddr, dwX);
	
	// epilogue
	// restore stack, remove from stack our ret. address and jmp into original function
	__asm
	{
		mov eax, dwResult
		mov	esp, ebp
		pop	ebp
		pop ecx
		jmp eax
	}
	
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint0(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint1(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint2(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint3(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint4(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint5(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint6(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint7(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint8(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPoint9(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPointA(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPointB(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPointC(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPointD(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPointE(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}

#pragma code_seg(".pedll32")
extern "C"
__declspec(naked) VOID WINAPI _FakeEntryPointF(VOID)
{
	__asm
	{
		push 0x10001000
		call DELAYDECRYPT
		//jmp	eax
	}
}



#pragma code_seg(".pedll32")
extern "C"
void WINAPI DELAYENCRYPT()
{
	struct _vtbl vtable = { _VirtualProtect, _VirtualAlloc, _CreateFileA, _SetFilePointer };
	g_decrypted = 2;
	decrypt(&vtable, g_hKernel32, DLL_PROCESS_ATTACH, NULL);
}


#endif
