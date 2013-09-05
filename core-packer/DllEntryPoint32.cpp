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
void __memcpy(LPVOID dst, LPVOID src, int size)
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

	char *cDST = (char *)dst;
	char *cSRC = (char *) src;
	while(size-- > 0)
	{
		*cDST++ = *cSRC++;
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
char *__strcpy(char *destination, const char *source)
{
	char *d = destination;

	while(*source != 0x00)
	{
		*destination++ = *source++;
	}

	*destination = 0x00;

	return d;
}

#pragma code_seg(".pedll32")
char *__strcat(char *destination, const char *source)
{
	char *d = destination;

	for(;*destination != 0x00; destination++);
	{
		__asm {
			nop
		}
	}
	__strcpy(destination, source);
	return d;
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
LPVOID WINAPI _dll32_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	__asm {
		mov esp, ebp
		pop ebp
		mov eax, dword ptr [g_hKernel32]
		add eax, 11223341h
		jmp dword ptr [eax]
		nop
		nop
		nop
		nop
		nop
	}
}

#pragma code_seg(".pedll32")
__declspec(naked)
DWORD WINAPI _SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
	__asm {
		mov esp, ebp
		pop	ebp
		mov eax, dword ptr [g_hKernel32]
		add eax, 11223342h
		jmp dword ptr [eax]
		nop
		nop
		nop
		nop
		nop
	}
}

#pragma code_seg(".pedll32")
__declspec(naked)
BOOL WINAPI _CloseHandle(HANDLE hObject)
{
	__asm {
		mov esp, ebp
		pop	ebp
		mov eax, dword ptr [g_hKernel32]
		add eax, 11223343h
		jmp dword ptr [eax]
		nop
		nop
		nop
		nop
		nop
	}
}

#pragma code_seg(".pedll32")
__declspec(naked)
BOOL WINAPI _ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	__asm {
		mov esp, ebp
		pop	ebp
		mov eax, dword ptr [g_hKernel32]
		add eax, 11223344h
		jmp dword ptr [eax]
		nop
		nop
		nop
		nop
		nop
	}
}

#pragma code_seg(".pedll32")
__declspec(naked)
DWORD WINAPI _GetModuleFileNameA(HMODULE hModule, LPTSTR lpFileName, DWORD nSize)
{
	__asm {
		mov esp, ebp
		pop	ebp
		mov eax, dword ptr [g_hKernel32]
		add eax, 11223345h
		jmp dword ptr [eax]
		nop
		nop
		nop
		nop
		nop
	}
}

#pragma code_seg(".pedll32")
__declspec(naked)
HANDLE WINAPI _CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttribytes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	_asm {
		mov esp, ebp
		pop	ebp
		mov eax, dword ptr [g_hKernel32]
		add eax, 11223346h
		jmp dword ptr [eax]
		nop
		nop
		nop
		nop
		nop
	}
}

#pragma code_seg(".pedll32")
__declspec(naked)
BOOL WINAPI _EntryPoint(LPVOID lpBase, HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	__asm {
		push dword ptr [ebp+14h]
		push dword ptr [ebp+10h]
		push dword ptr [ebp+0ch]
		mov eax, dword ptr [ebp+08h]
		add eax, 10101010h
		call eax
		ret
	}
}


#pragma code_seg(".pedll32")
__declspec(naked)
static LPVOID _CALC_OFFSET(LPVOID base, DWORD disp)
{
	__asm {
		lea eax, dword ptr [esp+4]
		mov eax, dword ptr [eax]
		mov dword ptr [esp+4], eax
		mov eax, dword ptr [esp+8]
		add eax, dword ptr [esp+4]
		ret 8
	}
}

#define CALC_OFFSET(TYPE, base, disp) (TYPE) _CALC_OFFSET((LPVOID) base, disp)

#pragma code_seg(".pedll32")
static void __forceinline __fastcall swap(PBYTE a, PBYTE b)
{
	BYTE c;
	c = *a;
	*a = *b;
	*b = c;
}

#pragma code_seg(".pedll32")
static void __forceinline init_sbox(LPBYTE RC4_SBOX)
{
	__declspec(allocate(".pedll32"))
	static BYTE sbox[256] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	};

	__memcpy(RC4_SBOX, sbox, 256);

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
static LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, DWORD ImageBase, LPVOID lpAddress)
{
	ULONG dwImageDosHeader = (ULONG) pImageDosHeader;	// new base address!
	ULONG dwAddress = (ULONG) lpAddress;	// rva

	if (dwAddress > ImageBase)
		dwAddress -= ImageBase;

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

		LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders32->OptionalHeader.ImageBase, (LPVOID) pSection->VirtualAddress);

		vtbl->mem_protect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

		BYTE sbox[256];
		ULONG64 rc4key[2] = { _rc4key0, _rc4key1 };

		init_sbox(sbox);
		rc4_sbox_key(sbox, (PBYTE) &rc4key, 16);

		__declspec(allocate(".pedll32"))
		static char szText[] = { '.', 't', 'e', 'x', 't', 0x00 };
		__declspec(allocate(".pedll32"))
		static char szData[] = { '.', 'd', 'a', 't', 'a', 0x00 };

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

__declspec(allocate(".pedll32"))
	char szInitialize[] = { 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 0x00 };

__declspec(allocate(".pedll32"))
	char szCritical[] = { 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 0x00 };

__declspec(allocate(".pedll32"))
	char szSection[] = { 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

__declspec(allocate(".pedll32"))
	char szLeave[] = { 'L', 'e', 'a', 'v', 'e', 0x00 };

__declspec(allocate(".pedll32"))
	char szDelete[] = {'D', 'e', 'l', 'e', 't', 'e', 0x00 };
__declspec(allocate(".pedll32"))
	char szEnter[] = { 'E', 'n', 't', 'e', 'r', 0x00 };


#pragma code_seg(".pedll32")
static void _InitializeCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[32];
	__strcpy(szApi, szInitialize);
	__strcat(szApi, szCritical);
	__strcat(szApi, szSection);
	//char szApi[] = { 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'C', 'r', 'i', 't', 'i', 'c', 'a', 'l', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x00 };

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll32")
static void _LeaveCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[23];
	__strcpy(szApi, szLeave);
	__strcat(szApi, szCritical);
	__strcat(szApi, szSection);

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll32")
static void _DeleteCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[24];
	__strcpy(szApi, szDelete);
	__strcat(szApi, szCritical);
	__strcat(szApi, szSection);


	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

#pragma code_seg(".pedll32")
static void _EnterCriticalSection(HMODULE h, LPCRITICAL_SECTION lpCriticalSection)
{
	char szApi[23];
	__strcpy(szApi, szEnter);
	__strcat(szApi, szCritical);
	__strcat(szApi, szSection);

	InitializeCriticalSection_ptr f = (InitializeCriticalSection_ptr) _dll32_GetProcAddress(h, szApi);

	f(lpCriticalSection);
}

__declspec(allocate(".pedll32"))
char szKernel32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0x00 };

#pragma code_seg(".pedll32")
static HMODULE get_Kernel32(void)
{
	return _dll32_LoadLibraryA(szKernel32);
}

__declspec(allocate(".pedll32"))
char szDisableThreadLibraryCalls[] = { 'D', 'i', 's', 'a', 'b', 'l', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'C', 'a', 'l', 'l', 's', 00 };

#pragma code_seg(".pedll32")
static BOOL _DisableThreadLibraryCalls(HMODULE hKernel32, HMODULE hModule)
{
	typedef BOOL (WINAPI *DisableThreadLibraryCalls_ptr)(HMODULE hModule);
	DisableThreadLibraryCalls_ptr f = (DisableThreadLibraryCalls_ptr) _dll32_GetProcAddress(hKernel32, szDisableThreadLibraryCalls);

	return f(hModule);
}

__declspec(allocate(".pedll32"))
char szGetModuleFileNameA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x00 };

#pragma code_seg(".pedll32")
BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
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


__declspec(allocate(".pedll32"))
char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };

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
		
		char szVirtualAlloc[0x14];
		__strcpy(szVirtualAlloc, szVirtualProtect);

		_VirtualProtect = (VirtualProtect_ptr) _dll32_GetProcAddress(get_Kernel32(), szVirtualProtect);
		szVirtualAlloc[7] = 'A';
		szVirtualAlloc[8] = 'l';
		szVirtualAlloc[9] = 'l';
		szVirtualAlloc[0x0a] = 'o';
		szVirtualAlloc[0x0b] = 'c';
		szVirtualAlloc[0x0c] = 0x00;

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
