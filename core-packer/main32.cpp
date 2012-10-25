#include <Windows.h>
#include <iostream>
#include "library.h"
#include "macro.h"
#include "rva.h"
#include "rc4.h"
#include "symbols.h"

#ifdef _BUILD32

extern BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
extern "C" VOID WINAPI DELAYDECRYPT();
extern DWORD NextPointerToRawData(PIMAGE_NT_HEADERS pHeader);
extern DWORD NextVirtualAddress(PIMAGE_NT_HEADERS pHeader);
extern LPVOID FindBlockMem(LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize);
extern void Patch_JMP(LPBYTE lpInstruction, DWORD dwNewOffset);
extern void Patch_MOV(LPBYTE lpInstruction, DWORD dwNewOffset);
extern void Patch_MARKER_QWORD(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, ULONG64 value);
extern void Patch_MARKER_DWORD(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD value);
extern void Patch_MARKER(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset);
extern void Patch_Entry(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset);

// reloc table
typedef struct _relocation_block {
	DWORD	PageRVA;
	DWORD	BlockSize;
} relocation_block_t;

typedef short relocation_entry;




void Patch_EXPORT_SYMBOL(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD newOffset, DWORD oldOffset)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, 0x12);

	if (lpInitialByte != NULL)
	{
		LPDWORD c = CALC_OFFSET(LPDWORD, lpInitialByte, 0x0c);
		//
		//DWORD dwNewValue = diff_rva32(NULL, NULL, oldOffset, newOffset+0x12);
		//Patch_JMP(c, dwNewValue);
		*c = oldOffset;
	}

}
DWORD Transfer_Reloc_Table(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection, LPVOID lpOutput, DWORD dwNewVirtualAddress, LPVOID lpNewBaseAddress, PIMAGE_NT_HEADERS32 pNewFile)
{
	DWORD dwSize = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD dwImageBase = pSelf->OptionalHeader.ImageBase;

	if (dwImageBase != (DWORD) hProcessModule)
		dwImageBase = (DWORD) hProcessModule;

	while(reloc != NULL)
	{
		if (reloc->PageRVA >= pSection->VirtualAddress && reloc->PageRVA < (pSection->VirtualAddress + pSection->Misc.VirtualSize))
		{	// good! add this page!
			memcpy(lpOutput, reloc, reloc->BlockSize);
			
			relocation_block_t *newReloc= CALC_OFFSET(relocation_block_t *, lpOutput, 0);

			newReloc->PageRVA = reloc->PageRVA - pSection->VirtualAddress + dwNewVirtualAddress;
			
			DWORD blocksize = newReloc->BlockSize - 8;
			relocation_entry *entry = CALC_OFFSET(relocation_entry *, newReloc, 8);
			
			while(blocksize > 0)
			{	// fetch instruction and patch!
				short type = ((*entry & 0xf000) >> 12);
				long offset = (*entry & 0x0fff);

				ULONG *ptr = CALC_OFFSET(ULONG *, lpNewBaseAddress, offset + newReloc->PageRVA);
				ULONG value = *ptr;
				ULONG dwNewValue = 0;

				switch(type)
				{
					case 0x03:
						value = value - dwImageBase - reloc->PageRVA;
						value = value + pNewFile->OptionalHeader.ImageBase + newReloc->PageRVA;
						*ptr = value;
						break;
					case 0x0a:
						//dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG64) pModule;
						//*ptr = dwNewValue;
						break;
				}
				entry++;
				blocksize -= 2;
			}

			lpOutput = CALC_OFFSET(LPVOID, lpOutput, reloc->BlockSize);

			dwSize += reloc->BlockSize;
		}

		reloc = CALC_OFFSET(relocation_block_t *, reloc, reloc->BlockSize);
		if (reloc->BlockSize == 0) reloc = NULL;
	}
	return dwSize;
}

int main32(int argc, char *argv[])
{
	if (argc == 1)
	{
		std::cout << "packer32 infile outfile" << std::endl;
		std::cout << "packer32 in/outfile" << std::endl;
	}

	HMODULE hModule = GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hModule;
	PIMAGE_NT_HEADERS32 pImageNtHeaders32 = CALC_OFFSET(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);

	if (pImageNtHeaders32->Signature != IMAGE_NT_SIGNATURE)
	{	
		std::cout << "Sorry! I can't check myself!";
		return FALSE;	
	}
	
	char szHermitName[] = ".hermit";

	short NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pSectionHermit64 = NULL;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (memcmp(szHermitName, pSection->Name, 8) == 0)
		{
			std::cout << ".hermit 64bit section found in code" << std::endl;
			
			std::cout << "\tSize of raw data: " << std::hex << pSection->SizeOfRawData << std::endl;
			std::cout << "\t    Virtual size: " << std::hex << pSection->Misc.VirtualSize << std::endl;
			std::cout << "\t             RVA: " << std::hex << pSection->VirtualAddress << std::endl;
			std::cout << "\t Virtual Address: " << std::hex << rva2addr(pImageDosHeader, pImageNtHeaders32, CALC_OFFSET(LPVOID, pImageDosHeader, pSection->VirtualAddress)) << std::endl;

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
	PIMAGE_DOS_HEADER pInfectMe = (PIMAGE_DOS_HEADER) InternalLoadLibrary(argv[1], RoundUp(pSectionHermit64->Misc.VirtualSize, 16384) / 4096);

	PIMAGE_NT_HEADERS pInfectMeNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS, pInfectMe, pInfectMe->e_lfanew);
	

	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader);

	PIMAGE_SECTION_HEADER pLastSection = CALC_OFFSET(PIMAGE_SECTION_HEADER, pFirstSection, sizeof(IMAGE_SECTION_HEADER) * pInfectMeNtHeader->FileHeader.NumberOfSections);

	//// move all sections from 0x1000 to 0x3000
	//for(PIMAGE_SECTION_HEADER pProcessSection = pLastSection; pProcessSection >= IMAGE_FIRST_SECTION( pInfectMeNtHeader); pProcessSection--)
	//{
	//	DWORD oldVirtualAddress = pProcessSection->VirtualAddress;
	//	pProcessSection->VirtualAddress += 0x2000;

	//	memmove(rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pProcessSection->VirtualAddress), rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) oldVirtualAddress), pProcessSection->SizeOfRawData);

	//	pProcessSection->VirtualAddress += 0x2000;
	//	pProcessSection->PointerToRawData += 0x2000;

	//	memcpy(pProcessSection + 1, pProcessSection, sizeof(IMAGE_SECTION_HEADER));
	//}


	//pInfectMeNtHeader->FileHeader.NumberOfSections ++;
	//pFirstSection->Misc.VirtualSize = 0x2000;
	//pFirstSection->VirtualAddress = 0x1000;
	//pFirstSection->SizeOfRawData = 0x2000;
	//pFirstSection->Name[0] = '!';
	//pFirstSection->PointerToRawData = 0x400;

	//if (argc > 2)
	//	SaveLibraryToFile(pInfectMe, argv[2]);
	//else
	//	SaveLibraryToFile(pInfectMe, argv[1]);


	//return 0;
	/*relocation_block_t *ImageRelocation = CALC_OFFSET(relocation_block_t *, pInfectMe, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

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
	}*/

	char passKey[16];

	srand(GetTickCount());
	
	for(int i =0; i < sizeof(passKey); i++)
		passKey[i] = rand() % 256;

	BYTE rc4sbox[256];
	
	PIMAGE_IMPORT_DESCRIPTOR ImportAddressTable = CALC_OFFSET(PIMAGE_IMPORT_DESCRIPTOR, pInfectMe, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	PIMAGE_SECTION_HEADER pDestSection = NULL;

	for(PIMAGE_SECTION_HEADER pProcessSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader); pProcessSection <= pLastSection; pProcessSection++)
	{	// each section must be packed
		init_sbox(rc4sbox);
		init_sbox_key(rc4sbox, (BYTE *) passKey, 16);

		if ((pProcessSection->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
		{	// skip current section
		}
		else if ((pProcessSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{
			if (
				(RoundUp(pProcessSection->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.SectionAlignment) - pProcessSection->Misc.VirtualSize) >= pSectionHermit64->Misc.VirtualSize)
			{
				std::cout << "TEXT section of process can contain ourself!!!" << std::endl;
				//pDestSection = pProcessSection;
			}

			pProcessSection->Characteristics |= 0x02;
			
			cypher_msg(rc4sbox, (PBYTE) rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pProcessSection->VirtualAddress), pProcessSection->SizeOfRawData);

			if (strcmp((char *) pProcessSection->Name, ".text") == 0)
			{	// text section!
				pProcessSection->Misc.VirtualSize = pProcessSection->SizeOfRawData;
				pProcessSection->SizeOfRawData = 0;
				pProcessSection->PointerToRawData = 0;

			}

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

	char *szSectionName = ".textbss";
	
	PIMAGE_SECTION_HEADER pInfectSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader);
	
	if (pDestSection == NULL)
	{	// text section cannot contain ourself! increase counter and add on tail new section!
		pInfectSection = CALC_OFFSET(PIMAGE_SECTION_HEADER, pInfectSection, sizeof(IMAGE_SECTION_HEADER) * pInfectMeNtHeader->FileHeader.NumberOfSections);
		pInfectMeNtHeader->FileHeader.NumberOfSections++;
		memcpy(pInfectSection, pSectionHermit64, sizeof(IMAGE_SECTION_HEADER));
		memcpy(pInfectSection->Name, szSectionName, 8);
		//pInfectSection->Misc.VirtualSize = pSectionHermit64->Misc.VirtualSize;
		pInfectSection->VirtualAddress = NextVirtualAddress(pInfectMeNtHeader);
		pInfectSection->PointerToRawData = NextPointerToRawData(pInfectMeNtHeader);
		pInfectSection->SizeOfRawData = RoundUp(pSectionHermit64->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.FileAlignment);
		pInfectSection->Characteristics = 0xE0000020;
	}
	else
	{	// we can stay inside section!
		pInfectSection = (PIMAGE_SECTION_HEADER) malloc(sizeof(IMAGE_SECTION_HEADER));
		memcpy(pInfectSection, pDestSection, sizeof(IMAGE_SECTION_HEADER));
		pInfectSection->VirtualAddress = pDestSection->VirtualAddress + pDestSection->Misc.VirtualSize;
		pDestSection->Misc.VirtualSize += pSectionHermit64->Misc.VirtualSize;
		DWORD dwAddSizeOfRawData = RoundUp(pDestSection->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.FileAlignment) - pDestSection->SizeOfRawData;
		pDestSection->SizeOfRawData = RoundUp(pDestSection->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.FileAlignment);

		for(PIMAGE_SECTION_HEADER pProcess = pDestSection+1; pProcess < pLastSection; pProcess++)
		{
			pProcess->PointerToRawData += dwAddSizeOfRawData;
		}

	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =  CALC_OFFSET(PIMAGE_EXPORT_DIRECTORY, pInfectMe, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD AddressOfFunctions = CALC_OFFSET(LPDWORD, pInfectMe, ExportDirectory->AddressOfFunctions);

	ULONG table[10] =
	{
		(ULONG) _FakeEntryPoint0,
		(ULONG) _FakeEntryPoint1,
		(ULONG) _FakeEntryPoint2,
		(ULONG) _FakeEntryPoint3,
		(ULONG) _FakeEntryPoint4,
		(ULONG) _FakeEntryPoint5,
		(ULONG) _FakeEntryPoint6,
		(ULONG) _FakeEntryPoint7,
		(ULONG) _FakeEntryPoint8,
		(ULONG) _FakeEntryPoint9
	};

	//pInfectMeNtHeader->FileHeader.SizeOfOptionalHeader += sizeof(IMAGE_SECTION_HEADER);
	

	LPVOID lpRawSource = rva2addr(pImageDosHeader, pImageNtHeaders32, CALC_OFFSET(LPVOID, pImageDosHeader, pSectionHermit64->VirtualAddress));
	LPVOID lpRawDestin = rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) pInfectSection->VirtualAddress);
		
	
	//pSectionHermit64->SizeOfRawData = RoundUp(pSectionHermit64->SizeOfRawData, pInfectMeNtHeader->OptionalHeader.SectionAlignment);

	memcpy(lpRawDestin, lpRawSource, pSectionHermit64->SizeOfRawData);

	for(int i=0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		ULONG exportRVA = table[i];

		ULONG exportSymbolEntryPoint = exportRVA - ((ULONG) pImageDosHeader) - pSectionHermit64->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
		exportSymbolEntryPoint = pInfectSection->VirtualAddress + exportSymbolEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
		
		DWORD dwOldValue = AddressOfFunctions[i];
		AddressOfFunctions[i] = exportSymbolEntryPoint;
		
		Patch_EXPORT_SYMBOL(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, (LPVOID) table[i], exportSymbolEntryPoint, dwOldValue - 0x1000);
	}
	

	DWORD dwOffset = RoundUp(pSectionHermit64->SizeOfRawData, 16);

	ULONG offsetEntryPoint = (ULONG) (DllEntryPoint);

	ULONG rvaEntryPoint = offsetEntryPoint - ((ULONG) pImageDosHeader) - pSectionHermit64->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
	
	DWORD AddressOfEntryPoint = pInfectMeNtHeader->OptionalHeader.AddressOfEntryPoint;

	pInfectMeNtHeader->OptionalHeader.AddressOfEntryPoint = pInfectSection->VirtualAddress + rvaEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;

	//pInfectMeNtHeader->OptionalHeader.AddressOfEntryPoint = pInfectSection->VirtualAddress + rvaEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;

	// lpRawDestination PATCH!

	// Patch Entry point
	
	//Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_EntryPoint, 9, AddressOfEntryPoint);
	
	// Process export table
	std::cout << "IAT Size: " << std::hex << pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size << std::endl;
	std::cout << "IAT Addr.: " << std::hex << pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;

	DWORD kernel32LoadLibraryA_Offset = 0;
	DWORD kernel32GetProcAddress_Offset = 0;
	DWORD kernel32CreateFileA_Offset = 0;
	DWORD kernel32GetModuleFileNameA_Offset = 0;
	DWORD kernel32ReadFile_Offset = 0;
	DWORD kernel32SetFilePointer_Offset = 0;
	DWORD kernel32CloseHandle_Offset = 0;

	while(ImportAddressTable->Characteristics != 0)
	{
		std::cout << "Name " << CALC_OFFSET(char *, pInfectMe, ImportAddressTable->Name) << std::endl;
		
		std::cout << "\tEntries: " << std::endl;

#ifdef _BUILD64
		PULONG64 rvaName = CALC_OFFSET(PULONG64, pInfectMe, ImportAddressTable->Characteristics);
		PULONG64 iatRVA = CALC_OFFSET(PULONG64, pInfectMe, ImportAddressTable->FirstThunk);
#else
		PULONG rvaName = CALC_OFFSET(PULONG, pInfectMe, ImportAddressTable->Characteristics);
		PULONG iatRVA = CALC_OFFSET(PULONG, pInfectMe, ImportAddressTable->FirstThunk);
#endif


		while(*rvaName != 0)
		{
			char *name = CALC_OFFSET(char *, pInfectMe, (*rvaName & 0x7fffffff) + 2);

			std::cout << "\t " << std::hex << CALC_DISP(LPVOID, iatRVA, pInfectMe) << " " << std::hex << *iatRVA << " " << name << std::endl;

			if (strcmp(name, "LoadLibraryA") == 0) 
				kernel32LoadLibraryA_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);
			else if (strcmp(name, "GetProcAddress") == 0)
				kernel32GetProcAddress_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);
			else if (strcmp(name, "CreateFileA") == 0)
				kernel32CreateFileA_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);
			else if (strcmp(name, "GetModuleFileNameA") == 0)
				kernel32GetModuleFileNameA_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);
			else if (strcmp(name, "SetFilePointer") == 0)
				kernel32SetFilePointer_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);
			else if (strcmp(name, "ReadFile") == 0)
				kernel32ReadFile_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);
			else if (strcmp(name, "CloseHandle") == 0)
				kernel32CloseHandle_Offset = (DWORD) CALC_DISP(LPVOID, iatRVA, pInfectMe);

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

	ULONG64 *passKeyPtr = (ULONG64*) &passKey;

	//Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_EntryPoint, 9, AddressOfEntryPoint);
	Patch_Entry(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_EntryPoint, 0x10, AddressOfEntryPoint-0x1000);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_LoadLibraryA, 0x12, kernel32LoadLibraryA_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_GetProcAddress, 0x12, kernel32GetProcAddress_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_GetModuleFileNameA, 0x12, kernel32GetModuleFileNameA_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_CreateFileA, 0x12, kernel32CreateFileA_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_SetFilePointer, 0x12, kernel32SetFilePointer_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_ReadFile, 0x12, kernel32ReadFile_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_CloseHandle, 0x12, kernel32CloseHandle_Offset);

	Patch_MARKER_QWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_rc4key0, passKeyPtr[0]);
	Patch_MARKER_QWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &_rc4key1, passKeyPtr[1]);
	Patch_MARKER_DWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &dwRelocSize, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	Patch_MARKER_DWORD(pInfectMe, (LPBYTE) lpRawDestin, pSectionHermit64->SizeOfRawData, &lpRelocAddress, pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD dwNewRelocSize = Transfer_Reloc_Table(pImageDosHeader, pImageNtHeaders32, pSectionHermit64, CALC_OFFSET(LPVOID, lpRawDestin, dwOffset), pInfectSection->VirtualAddress, pInfectMe, pInfectMeNtHeader);
	DWORD dwNewRelocOffset = pInfectSection->VirtualAddress + dwOffset;
	pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = dwNewRelocSize;
	pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = dwNewRelocOffset;

	pInfectSection->SizeOfRawData += RoundUp(dwNewRelocSize, pInfectMeNtHeader->OptionalHeader.FileAlignment);
	pInfectSection->Misc.VirtualSize += RoundUp(dwNewRelocSize, pInfectMeNtHeader->OptionalHeader.SectionAlignment);

	pInfectMeNtHeader->OptionalHeader.SizeOfCode += RoundUp(pInfectSection->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.FileAlignment);
	pInfectMeNtHeader->OptionalHeader.SizeOfImage += RoundUp(pInfectSection->Misc.VirtualSize, pInfectMeNtHeader->OptionalHeader.SectionAlignment);
	//pInfectSection->

	if (argc > 2)
		SaveLibraryToFile(pInfectMe, argv[2]);
	else
		SaveLibraryToFile(pInfectMe, argv[1]);


	//DllEntryPoint((HINSTANCE) pInfectMe, DLL_PROCESS_ATTACH, NULL);

	return 0;
}
#endif
