#include <Windows.h>
#include <iostream>
#include "library.h"
#include "macro.h"
#include "rva.h"
#include "rc4.h"
#include "symbols.h"
#include "reloc.h"
#include "patchutils.h"

#ifdef _BUILD64

#include "dll64.h"

extern BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
extern DWORD NextPointerToRawData64(PIMAGE_NT_HEADERS64 pHeader);
extern DWORD NextVirtualAddress(PIMAGE_NT_HEADERS pHeader);
extern DWORD NextVirtualAddress64(PIMAGE_NT_HEADERS64 pHeader);

void Patch_EXPORT_SYMBOL(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD newOffset, DWORD oldOffset)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, 0x16);

	if (lpInitialByte != NULL)
	{
		LPBYTE c = CALC_OFFSET(LPBYTE, lpInitialByte, 0x11);
		DWORD dwNewValue = diff_rva32(NULL, NULL, oldOffset, newOffset+0x16);
		Patch_JMP(c, dwNewValue);
	}

}

int main64(int argc, char *argv[])
{
	if (argc != 3)
	{
		std::cout << "packer64 infile outfile" << std::endl;
		std::cout << "packer64 in/outfile" << std::endl;
	}

	HMODULE hModule = GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hModule;
	PIMAGE_NT_HEADERS64 pImageNtHeaders64 = CALC_OFFSET(PIMAGE_NT_HEADERS64, pImageDosHeader, pImageDosHeader->e_lfanew);

	if (pImageNtHeaders64->Signature != IMAGE_NT_SIGNATURE)
	{	
		std::cout << "Sorry! I can't check myself!";
		return FALSE;	
	}
	
	char szHermitName[] = ".hermit";

	short NumberOfSections = pImageNtHeaders64->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pSectionHermit64 = NULL;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders64); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (memcmp(szHermitName, pSection->Name, 8) == 0)
		{
			std::cout << ".hermit 64bit section found in code" << std::endl;
			
			std::cout << "\tSize of raw data: " << std::hex << pSection->SizeOfRawData << std::endl;
			std::cout << "\t    Virtual size: " << std::hex << pSection->Misc.VirtualSize << std::endl;
			std::cout << "\t             RVA: " << std::hex << pSection->VirtualAddress << std::endl;
			std::cout << "\t Virtual Address: " << std::hex << rva2addr(pImageDosHeader, pImageNtHeaders64, CALC_OFFSET(LPVOID, pImageDosHeader, pSection->VirtualAddress)) << std::endl;

			pSectionHermit64 = pSection;
			break;
		}
	}

	if (pSectionHermit64 == NULL)
	{	//  break!
		std::cout << "Cannot find in module .hermit section" << std::endl;
		return 0;
	}

	// find patterns!
	PIMAGE_DOS_HEADER pInfectMe = (PIMAGE_DOS_HEADER) InternalLoadLibrary(argv[1], RoundUp(pSectionHermit64->Misc.VirtualSize, 4096) / 4096);

	PIMAGE_NT_HEADERS64 pInfectMeNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS64, pInfectMe, pInfectMe->e_lfanew);
	
	PIMAGE_SECTION_HEADER pInfectSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader);
	pInfectSection = CALC_OFFSET(PIMAGE_SECTION_HEADER, pInfectSection, sizeof(IMAGE_SECTION_HEADER) * pInfectMeNtHeader->FileHeader.NumberOfSections);
	PIMAGE_SECTION_HEADER pLastSection = CALC_OFFSET(PIMAGE_SECTION_HEADER, pInfectSection, sizeof(IMAGE_SECTION_HEADER) * pInfectMeNtHeader->FileHeader.NumberOfSections - 1);

	char passKey[16];

	srand(GetTickCount());
	
	for(int i =0; i < sizeof(passKey); i++)
		passKey[i] = rand() % 256;

	BYTE rc4sbox[256];
	
	ULONG64 *passKeyPtr = (ULONG64*) &passKey;

	for(PIMAGE_SECTION_HEADER pProcessSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader); pProcessSection <= pLastSection; pProcessSection++)
	{	// each section must be packed
		init_sbox(rc4sbox);
		init_sbox_key(rc4sbox, (BYTE *) passKey, 16);

		if ((pProcessSection->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
		{	// skip current section
		}
		else if ((pProcessSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{
			pProcessSection->Characteristics |= 0x02;

			cypher_msg(rc4sbox, (PBYTE) rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pProcessSection->VirtualAddress), pProcessSection->SizeOfRawData);
		}
		else if (memcmp(pProcessSection->Name, ".data", 5) == 0)
		{
			pProcessSection->Characteristics |= 0x02;

			cypher_msg(rc4sbox, (PBYTE) rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pProcessSection->VirtualAddress), pProcessSection->SizeOfRawData);
		}
		else if (memcmp(pProcessSection->Name, ".rdata", 6) == 0)
		{
			pProcessSection->Characteristics |= 0x03;

			DWORD sizeOfSection = 
				pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
					- pProcessSection->VirtualAddress 
					- pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
						
			LPVOID sectionAddress = rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) (pProcessSection->VirtualAddress + pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size));

			cypher_msg(rc4sbox, (PBYTE) sectionAddress, sizeOfSection);
		}
	}

	//memcpy(pInfectSection->Name, szHermitName, 8);

	memcpy(pInfectSection, pSectionHermit64, sizeof(IMAGE_SECTION_HEADER));

	char *szSectionName = ".textbss";

	memcpy(pInfectSection, pSectionHermit64, sizeof(IMAGE_SECTION_HEADER));

	memcpy(pInfectSection->Name, szSectionName, 8);
	//pInfectSection->Misc.VirtualSize = pSectionHermit64->Misc.VirtualSize;
	pInfectSection->VirtualAddress = NextVirtualAddress64(pInfectMeNtHeader);
	pInfectSection->PointerToRawData = NextPointerToRawData64(pInfectMeNtHeader);
	pInfectSection->SizeOfRawData = RoundUp(pSectionHermit64->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.FileAlignment);
	pInfectSection->Characteristics = 0xE0000020;
	pInfectMeNtHeader->OptionalHeader.SizeOfCode += RoundUp(pSectionHermit64->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.FileAlignment);
	pInfectMeNtHeader->OptionalHeader.SizeOfImage += RoundUp(pSectionHermit64->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.SectionAlignment);
	

	pInfectMeNtHeader->FileHeader.NumberOfSections++;

	LPVOID lpRawSource = rva2addr(pImageDosHeader, pImageNtHeaders64, CALC_OFFSET(LPVOID, pImageDosHeader, pSectionHermit64->VirtualAddress));
	LPVOID lpRawDestin = rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pInfectSection->VirtualAddress);

	memcpy(lpRawDestin, lpRawSource, pSectionHermit64->SizeOfRawData);

	ULONG64 offsetEntryPoint = (ULONG64) (&DllEntryPoint);

	ULONG64 rvaEntryPoint = offsetEntryPoint - ((ULONG64) pImageDosHeader) - pSectionHermit64->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 


	DWORD AddressOfEntryPoint = pInfectMeNtHeader->OptionalHeader.AddressOfEntryPoint;

	pInfectMeNtHeader->OptionalHeader.AddressOfEntryPoint = pInfectSection->VirtualAddress + rvaEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =  CALC_OFFSET(PIMAGE_EXPORT_DIRECTORY, pInfectMe, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD AddressOfFunctions = CALC_OFFSET(LPDWORD, pInfectMe, ExportDirectory->AddressOfFunctions);

	ULONG64 table[10] =
	{
		(ULONG64) _FakeEntryPoint0,
		(ULONG64) _FakeEntryPoint1,
		(ULONG64) _FakeEntryPoint2,
		(ULONG64) _FakeEntryPoint3,
		(ULONG64) _FakeEntryPoint4,
		(ULONG64) _FakeEntryPoint5,
		(ULONG64) _FakeEntryPoint6,
		(ULONG64) _FakeEntryPoint7,
		(ULONG64) _FakeEntryPoint8,
		(ULONG64) _FakeEntryPoint9
	};

	for(int i=0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		ULONG64 exportRVA = table[i];

		ULONG64 exportSymbolEntryPoint = exportRVA - ((ULONG64) pImageDosHeader) - pSectionHermit64->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
		exportSymbolEntryPoint = pInfectSection->VirtualAddress + exportSymbolEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
		
		DWORD dwOldValue = AddressOfFunctions[i];
		AddressOfFunctions[i] = exportSymbolEntryPoint;
		
		Patch_EXPORT_SYMBOL(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, (LPVOID) table[i], exportSymbolEntryPoint, dwOldValue);
	}


	// lpRawDestination PATCH!

	// Patch Entry point
	
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_EntryPoint, 9, AddressOfEntryPoint);
	
	// Process export table
	std::cout << "IAT Size: " << std::hex << pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size << std::endl;
	std::cout << "IAT Addr.: " << std::hex << pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;

	DWORD kernel32LoadLibraryA_Offset = 0;
	DWORD kernel32GetProcAddress_Offset = 0;

	PIMAGE_IMPORT_DESCRIPTOR ImportAddressTable = CALC_OFFSET(PIMAGE_IMPORT_DESCRIPTOR, pInfectMe, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(ImportAddressTable->Characteristics != 0)
	{
		std::cout << "Name " << CALC_OFFSET(char *, pInfectMe, ImportAddressTable->Name) << std::endl;
		
		std::cout << "\tEntries: " << std::endl;

		PULONG64 rvaName = CALC_OFFSET(PULONG64, pInfectMe, ImportAddressTable->Characteristics);
		PULONG64 iatRVA = CALC_OFFSET(PULONG64, pInfectMe, ImportAddressTable->FirstThunk);

		while(*rvaName != 0)
		{
			char *name = CALC_OFFSET(char *, pInfectMe, (*rvaName & 0x7fffffff) + 2);

			std::cout << "\t " << std::hex << CALC_DISP(LPVOID, iatRVA, pInfectMe) << " " << std::hex << *iatRVA << " " << name << std::endl;

			if (strcmp(name, "LoadLibraryA") == 0) 
				kernel32LoadLibraryA_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);
			else if (strcmp(name, "GetProcAddress") == 0)
				kernel32GetProcAddress_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);

			rvaName++;
			iatRVA++;
		}

		ImportAddressTable++;
	}

	if (kernel32GetProcAddress_Offset == 0 || kernel32LoadLibraryA_Offset == 0)
	{
		std::cout << "Error! KERNEL32!GetProcAddress/LoadLibraryA not found in IAT" << std::endl;
		return 0;
	}

	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_EntryPoint, 9, AddressOfEntryPoint);

#ifdef _BUILD64
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_LoadLibraryA, 0x0F, kernel32LoadLibraryA_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_GetProcAddress, 0x0F, kernel32GetProcAddress_Offset);
#else
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_LoadLibraryA, 0x0F, kernel32LoadLibraryA_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_GetProcAddress, 0x0F, kernel32GetProcAddress_Offset);
#endif

	Patch_MARKER_QWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_rc4key0, passKeyPtr[0]);
	Patch_MARKER_QWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_rc4key1, passKeyPtr[1]);

	Patch_MARKER_DWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &dwRelocSize, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	Patch_MARKER_DWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &lpRelocAddress, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	relocation_block_t *ImageRelocation = CALC_OFFSET(relocation_block_t *, pInfectMe, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while(ImageRelocation != NULL)
	{
		std::cout << "Base Address: " << std::hex << ImageRelocation->PageRVA << " " << std::hex << ImageRelocation->BlockSize << std::endl;
		
		int BlockSize = ImageRelocation->BlockSize - 8;
		relocation_entry *entries = CALC_OFFSET(relocation_entry *, ImageRelocation, 8);

		while(BlockSize > 0)
		{
			std::cout << "\t" << std::hex << "Type " << ((*entries & 0xf000) >> 12) << " " << std::hex << (*entries & 0x0fff) << std::endl;
			entries++;
			BlockSize -= 2;
		}

		ImageRelocation = CALC_OFFSET(relocation_block_t *, ImageRelocation, ImageRelocation->BlockSize);
		if (ImageRelocation->BlockSize == 0) ImageRelocation = NULL;
	}

	pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;

	
	if (argc > 2)
		SaveLibrary64ToFile(pInfectMe, argv[2]);
	else
		SaveLibrary64ToFile(pInfectMe, argv[1]);

	return 0;
}

#endif
