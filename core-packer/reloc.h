#ifndef __RELOC_H_
	#define __RELOC_H_


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

typedef short relocation_entry;

#ifndef _UNPACKERSECTION

	#ifdef _BUILD64
	void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS64 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize);
	#else
	//void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize);
	void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer, LPVOID lpTextAddr);
	void reloctext(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, LPVOID lpTextAddr);

	#endif

#endif

#endif

