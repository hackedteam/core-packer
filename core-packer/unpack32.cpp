#include <Windows.h>
#include <iostream>
#include "library.h"
#include "macro.h"
#include "rva.h"
#include "rc4.h"
#include "symbols.h"
#include "dll32.h"
#include "tea.h"
#include "patchutils.h"

#ifdef _BUILD32
// reloc table
typedef struct _relocation_block {
	DWORD	PageRVA;
	DWORD	BlockSize;
} relocation_block_t;

typedef short relocation_entry;

PIMAGE_SECTION_HEADER lookup_unpack_section(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32)
{
	short NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pResult = NULL;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (memcmp(".textbss", pSection->Name, 8) == 0)
		{
			std::cout << pSection->Name << "/32bit section found in code" << std::endl;
			
			std::cout << "\tSize of raw data: " << std::hex << pSection->SizeOfRawData << std::endl;
			std::cout << "\t    Virtual size: " << std::hex << pSection->Misc.VirtualSize << std::endl;
			std::cout << "\t             RVA: " << std::hex << pSection->VirtualAddress << std::endl;
			std::cout << "\t Virtual Address: " << std::hex << rva2addr(pImageDosHeader, pImageNtHeaders32, CALC_OFFSET(LPVOID, pImageDosHeader, pSection->VirtualAddress)) << std::endl;

			pResult = pSection;
			break;
		}
	}

	return pResult;
}

int unpack32(int argc, char *argv[])
{
	std::cout << "unpack32/ht " << std::endl;

	if (argc != 4)
	{
		std::cout << "unpack32 -u infile outfile" << std::endl;
	}

	// find patterns!
	PIMAGE_DOS_HEADER pInfectMe = (PIMAGE_DOS_HEADER) InternalLoadLibrary(argv[2], 0);
	PIMAGE_NT_HEADERS pInfectMeNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS, pInfectMe, pInfectMe->e_lfanew);
	
	PIMAGE_SECTION_HEADER pSectionInput = lookup_unpack_section(pInfectMe, pInfectMeNtHeader);

	if (pSectionInput == NULL)
	{
		std::cout << "Cannot find .textbss section" << std::endl;
		return -1;
	}

	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader);
	PIMAGE_SECTION_HEADER pLastSection = CALC_OFFSET(PIMAGE_SECTION_HEADER, pFirstSection, sizeof(IMAGE_SECTION_HEADER) * pInfectMeNtHeader->FileHeader.NumberOfSections);

	BYTE rc4sbox[256];
	
	PIMAGE_IMPORT_DESCRIPTOR ImportAddressTable = CALC_OFFSET(PIMAGE_IMPORT_DESCRIPTOR, pInfectMe, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	PIMAGE_SECTION_HEADER pDestSection = NULL;

	LPBYTE ptrTextBss = (LPBYTE) rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pSectionInput->VirtualAddress);
	
	ULONG64 _rc4key0, _rc4key1;
	memcpy(&_rc4key1, CALC_OFFSET(LPVOID, ptrTextBss, 8), sizeof(ULONG64));
	memcpy(&_rc4key0, CALC_OFFSET(LPVOID, ptrTextBss, 8 + sizeof(ULONG64)), sizeof(ULONG64));

	ULONG64 rc4key[2] = { _rc4key0, _rc4key1 };

	for(PIMAGE_SECTION_HEADER pProcessSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader); pProcessSection < pLastSection; pProcessSection++)
	{	// each section must be packed
		init_sbox(rc4sbox);
		init_sbox_key(rc4sbox, (BYTE *) rc4key, sizeof(rc4key));

		if ((pProcessSection->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
		{	// skip current section

		}
		else if ((pProcessSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{
			if (strcmp((char *) pProcessSection->Name, ".text") == 0)
			{
				HANDLE h = CreateFile(argv[2], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

				SetFilePointer(h, 0x400, NULL, SEEK_SET);

				PIMAGE_SECTION_HEADER next = pProcessSection + 1;

				while(next->PointerToRawData == 0)
				{
					std::cout << "Skip " << next->Name << std::endl;
					next++;
				}

				DWORD dummy = 0;

				ReadFile(h, rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pProcessSection->VirtualAddress), next->PointerToRawData - 0x400, &dummy, NULL);
				CloseHandle(h);

				pProcessSection->SizeOfRawData = next->PointerToRawData - 0x400;;
				pProcessSection->PointerToRawData = 0x400;

			}

			cypher_msg(rc4sbox, (PBYTE) rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pProcessSection->VirtualAddress), pProcessSection->SizeOfRawData);

		}
		else if (memcmp(pProcessSection->Name, ".data", 5) == 0)
		{
			pProcessSection->Characteristics ^= 0x02;

			cypher_msg(rc4sbox, (PBYTE) rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pProcessSection->VirtualAddress), pProcessSection->SizeOfRawData);
		}
		else if (memcmp(pProcessSection->Name, ".rdata", 6) == 0)
		{
			pProcessSection->Characteristics ^= 0x03;

			DWORD sizeOfSection = 
				pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
					- pProcessSection->VirtualAddress 
					- pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
						
			LPVOID sectionAddress = rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) (pProcessSection->VirtualAddress + pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size));

				cypher_msg(rc4sbox, (PBYTE) sectionAddress, sizeOfSection);
		}

	}

	SaveLibraryToFile(pInfectMe, argv[3]);

	return 0;
}
#endif
