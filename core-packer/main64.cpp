#include <Windows.h>
#include <iostream>
#include "peasm/peasm.h"
#include "peasm/pesection.h"

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

#define DIFF(b, a) (DWORD)((ULONG64) b - (ULONG64) a)

#define MAGIC_EXPORT_SYMBOL 0x0BABECAFEBAD00000

DWORD OffsetMagic(LPVOID lpBlock, DWORD dwSignature, ULONG64 magic)
{
	LPVOID x = FindBlockMem((LPBYTE) lpBlock, dwSignature, &magic, sizeof(ULONG64));

	if (x != NULL)
	{	// block found
		return DIFF(x, lpBlock);		
	}

	return -1;
}

void Patch_EXPORT_SYMBOL(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD newOffset, DWORD oldOffset)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, dwSignatureSize);

	if (lpInitialByte != NULL)
	{
		DWORD MagicJumpOffset = OffsetMagic(lpInitialByte, dwSignatureSize, MAGIC_EXPORT_SYMBOL) - 1;
		LPBYTE c = CALC_OFFSET(LPBYTE, lpInitialByte, MagicJumpOffset);
		DWORD dwNewValue = diff_rva32(NULL, NULL, oldOffset, newOffset+MagicJumpOffset+5);
		Patch_JMP(c, dwNewValue);
	}
}

#define SECTION_RANDOM_NAME	15

static char *szSectionNames[SECTION_RANDOM_NAME] = 
{
	".textbss",
	".pages",
	".visical",
	".inferno",
	".calc",
	".notepad",
	".word",
	".viper0",
	".venom",
	".text0",
	".uspack0",
	".hermit",
	".locals",
	".stack1",
	".GLOBAL"
};

/**
 *	Return size required for relocation
 **/
size_t SizeOfRelocSection(LPVOID hProcessModule, PIMAGE_NT_HEADERS64 pSelf, PIMAGE_SECTION_HEADER pSection)
{
	size_t size = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	ULONGLONG dwImageBase = pSelf->OptionalHeader.ImageBase;

	if (dwImageBase != (DWORD) hProcessModule)
		dwImageBase = (DWORD) hProcessModule;


	while(reloc != NULL)
	{
		if (reloc->PageRVA >= pSection->VirtualAddress && reloc->PageRVA < (pSection->VirtualAddress + pSection->Misc.VirtualSize))
		{	// good! add this page!
			size+= reloc->BlockSize;
		}

		reloc = CALC_OFFSET(relocation_block_t *, reloc, reloc->BlockSize);
		if (reloc->BlockSize == 0) reloc = NULL;
	}
	return size;
}

char *szSectionName[] = { ".hermit\0", ".pedll32\0", ".pedll64\0", ".peexe32\0", ".peexe64\0" };

PIMAGE_SECTION_HEADER lookup_core_section(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, BOOL dllTARGET)
{
	short NumberOfSections = pImageNtHeaders64->FileHeader.NumberOfSections;

	char *szHermitName = szSectionName[2];

	if (dllTARGET == FALSE)
		szHermitName = szSectionName[4];

	PIMAGE_SECTION_HEADER pResult = NULL;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders64); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (memcmp(szHermitName, pSection->Name, 8) == 0)
		{
			std::cout << szHermitName << "/64bit section found in code" << std::endl;
			
			std::cout << "\tSize of raw data: " << std::hex << pSection->SizeOfRawData << std::endl;
			std::cout << "\t    Virtual size: " << std::hex << pSection->Misc.VirtualSize << std::endl;
			std::cout << "\t             RVA: " << std::hex << pSection->VirtualAddress << std::endl;
			std::cout << "\t Virtual Address: " << std::hex << rva2addr(pImageDosHeader, pImageNtHeaders64, CALC_OFFSET(LPVOID, pImageDosHeader, pSection->VirtualAddress)) << std::endl;

			pResult = pSection;
			break;
		}
	}

	return pResult;
}

BOOL lookup_rand_file(char *szOutFile, int maxsize)
{
	memset(szOutFile, 0, maxsize);
	
	char szWindirPath[MAX_PATH];

	DWORD dwIgnore = GetEnvironmentVariableA("windir", szWindirPath, MAX_PATH);

	if (dwIgnore == 0)
	{	// try default c:\windows
		strcpy_s(szWindirPath, "C:\\windows\\");
	}
	else
	{
		int i = (int) strlen(szWindirPath);

		if (szWindirPath[i-1] != '\\')
			strcat_s(szWindirPath, "\\");
	}

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");

	strcat_s(szWindirPath, "system32\\");

	char szFindPath[MAX_PATH];
	sprintf_s(szFindPath, "%s*.dll", szWindirPath);

	WIN32_FIND_DATA findfiledata;
	WIN32_FIND_DATA _previous_findfiledata;
	HANDLE hLook = FindFirstFileA(szFindPath, &findfiledata);

	int l = rand() % 256;

	if (hLook == INVALID_HANDLE_VALUE)
		return FALSE;

	do
	{	// perform a backup!
		memcpy(&_previous_findfiledata, &findfiledata, sizeof(WIN32_FIND_DATA));
		if (l  == 0)
			break;

		l--;
	} while(FindNextFileA(hLook, &findfiledata));

	FindClose(hLook);

	strcat_s(szWindirPath, _previous_findfiledata.cFileName);

	strcpy(szOutFile, szWindirPath);

	return TRUE;
}

CPeAssembly *load_random(char *param)
{
	if (param != NULL)
	{
		CPeAssembly *obj = new CPeAssembly();
		obj->Load(param);
		return obj;
	}
	else
	{
		char randfile[MAX_PATH];

		CPeAssembly *obj = NULL;

		while(obj == NULL)
		{
			lookup_rand_file(randfile, MAX_PATH);

			obj = new CPeAssembly();

			if (obj->Load(randfile) == false)
			{	// failed!
				std::cout << "Error loading " << randfile << std::endl;
				delete obj;
				obj = NULL;
			}

			if (obj->NumberOfSections() == 0)
			{	// failed!
				std::cout << "Error loading " << randfile << std::endl;
				delete obj;
				obj = NULL;
			}
		}

		return obj;
	}

	return NULL;
}

DWORD Transfer_Reloc_Table(LPVOID hProcessModule, PIMAGE_NT_HEADERS64 pSelf, PIMAGE_SECTION_HEADER pSection, LPVOID lpOutput, DWORD dwNewVirtualAddress, CPeAssembly *destination, PIMAGE_NT_HEADERS64 pNewFile)
{
	DWORD dwSize = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	ULONGLONG dwImageBase = pSelf->OptionalHeader.ImageBase;

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

				ULONG *ptr = (PULONG) destination->RawPointer(offset + newReloc->PageRVA);
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


int main64(int argc, char *argv[])
{
	srand(GetTickCount());	// initialize for (rand)

	if (argc == 1)
	{
		std::cout << "packer32 infile outfile" << std::endl;
		std::cout << "packer32 in/outfile" << std::endl;
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

	CPeAssembly *pTarget = new CPeAssembly();

	pTarget->Load(argv[1]);

	CPeAssembly *morph = NULL;

	if (argc > 3)
		morph = load_random(argv[3]);
	else
		morph = load_random(NULL);

	PIMAGE_SECTION_HEADER pUnpackerCode = NULL;
	
	if (pTarget->IsDLL())
	{	// it's a DLL?!?!?
		std::cout << "Input file is DLL!" << std::endl;

		pUnpackerCode = lookup_core_section(pImageDosHeader, pImageNtHeaders64, TRUE);
	}
	else if (pTarget->IsEXE())
	{
		std::cout << "Input file is EXECUTABLE!" << std::endl;
		pUnpackerCode = lookup_core_section(pImageDosHeader, pImageNtHeaders64, FALSE);
	}
	else
	{
		std::cout << "Unsupported input file!" << std::endl;
		return 0;
	}

	if (pUnpackerCode == NULL)
	{	//  break!
		std::cout << "Cannot find <PACKER> in sections" << std::endl;
		return 0;
	}

	size_t required_reloc_space = SizeOfRelocSection(pImageDosHeader, pImageNtHeaders64, pUnpackerCode);
	CPeSection *relocSection = pTarget->LookupSectionByName(".reloc");

	size_t relocsize = relocSection->VirtualSize();
		
	if (relocsize + required_reloc_space > relocSection->SizeOfRawData())
	{	// expande
		relocSection->AddSize(required_reloc_space);
	}


	char passKey[16];

	for(int i =0; i < sizeof(passKey); i++)
		passKey[i] = rand() % 256;

	BYTE rc4sbox[256];
	
	PIMAGE_DATA_DIRECTORY DataDir = pTarget->DataDirectory64();

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pTarget->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	PIMAGE_SECTION_HEADER pDestSection = NULL;

	char *szSectionName = szSectionNames[rand() % 15];
	
	int newVirtualSize = RoundUp(pUnpackerCode->Misc.VirtualSize + ((rand() % 16) * 1024), 1024);

	CPeSection *pTargetSection = NULL;

	if (pTarget->IsDLL())
	{
		pTargetSection = pTarget->AddSection(szSectionName, 0x0, newVirtualSize);	// move section in "head"
	}
	else if (pTarget->IsEXE())
	{
		pTargetSection = pTarget->AddSection(szSectionName, 0x1000, newVirtualSize);	// move section in "head"

		CPeSection *pMorphSection = morph->getSection(0);

		memset(pTargetSection->RawData(), 0x90, newVirtualSize);
		memcpy(pTargetSection->RawData(), pMorphSection->RawData(), (pMorphSection->SizeOfRawData() < newVirtualSize) ? pMorphSection->SizeOfRawData() : newVirtualSize);
	}

	DWORD dwOffset = RoundUp(pUnpackerCode->SizeOfRawData, 16);

	ULONG offsetEntryPoint = (ULONG) (DllEntryPoint);

	ULONG rvaEntryPoint = offsetEntryPoint - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
	
	DWORD AddressOfEntryPoint = pTarget->NtHeader64()->OptionalHeader.AddressOfEntryPoint;
	
	pTargetSection->GetSectionHeader()->Characteristics = 0xE0000020;
	
	PIMAGE_NT_HEADERS64 pTargetNtHeader = pTarget->NtHeader64();

	pTargetNtHeader->OptionalHeader.AddressOfEntryPoint = pTargetSection->VirtualAddress() + rvaEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;

	LPVOID lpRawSource = rva2addr(pImageDosHeader, pImageNtHeaders64, CALC_OFFSET(LPVOID, pImageDosHeader, pUnpackerCode->VirtualAddress));

	memcpy(pTargetSection->RawData(), lpRawSource, pUnpackerCode->SizeOfRawData);

	ULONG64 *passKeyPtr = (ULONG64*) &passKey;

	
	// Process export table
	std::cout << "IAT Size: " << std::hex << pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size << std::endl;
	std::cout << "IAT Addr.: " << std::hex << pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;

	DWORD kernel32LoadLibraryA_Offset = 0;
	DWORD kernel32GetProcAddress_Offset = 0;

	PIMAGE_IMPORT_DESCRIPTOR ImportAddressTable = (PIMAGE_IMPORT_DESCRIPTOR) pTarget->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(ImportAddressTable->Characteristics != 0)
	{
		std::cout << "Name " << pTarget->RawPointer(ImportAddressTable->Name) << std::endl;
		
		std::cout << "\tEntries: " << std::endl;

		PULONG64 rvaName = (PULONG64) pTarget->RawPointer(ImportAddressTable->Characteristics);
		PULONG64 iatRVA = (PULONG64) pTarget->RawPointer(ImportAddressTable->FirstThunk);
		PULONG64 iat = (PULONG64) ImportAddressTable->FirstThunk;

		while(*rvaName != 0)
		{
			char *name = (char *) pTarget->RawPointer((*rvaName & 0x7fffffff) + 2);

			std::cout << "\t " << std::hex << CALC_DISP(LPVOID, iatRVA, pTarget) << " " << std::hex << *iatRVA << " " << name << std::endl;

			if (strcmp(name, "LoadLibraryA") == 0) 
				kernel32LoadLibraryA_Offset = (DWORD) iat;
			else if (strcmp(name, "GetProcAddress") == 0)
				kernel32GetProcAddress_Offset = (DWORD) iat;

			rvaName++;
			iatRVA++;
			iat++;
		}

		ImportAddressTable++;
	}

	for(int i = 0; i < pTarget->NumberOfSections(); i++)
	{	// each section must be packed
		if (pTarget->IsDLL())
		{
			init_sbox(rc4sbox);
			init_sbox_key(rc4sbox, (BYTE *) passKey, 16);
		}
		else
		{
			uint32_t *key = (uint32_t *) rc4sbox;
			memcpy(key, passKey, 16);
		}

		CPeSection *pProcessSection = pTarget->getSection(i);
		PIMAGE_SECTION_HEADER pSectionHeader = pProcessSection->GetSectionHeader();

		if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
		{	// skip current section
		}
		else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{
			pSectionHeader->Characteristics |= 0x02;
			
			if (pTarget->IsDLL())
				cypher_msg(rc4sbox, (PBYTE) pProcessSection->RawData(), pProcessSection->SizeOfRawData());
			else
			{
				/*uint32_t *key = (uint32_t *) rc4sbox;
				LPDWORD encptr = (LPDWORD) pProcessSection->RawData();

				for(DWORD dwPtr = 0; dwPtr < pProcessSection->SizeOfRawData(); dwPtr += 8, encptr += 2)
					tea_encrypt((uint32_t *) encptr, key);*/
			}

			//pSectionHeader->Characteristics ^= IMAGE_SCN_MEM_EXECUTE;
			if (strcmp((char *) pSectionHeader->Name, ".text") == 0)
			{	// text section!
				//pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData;
			}

		}
		else if (memcmp(pSectionHeader->Name, ".data", 5) == 0)
		{
			pSectionHeader->Characteristics |= 0x02;

			if (pTarget->IsDLL())
				cypher_msg(rc4sbox, (PBYTE) pProcessSection->RawData(), pProcessSection->SizeOfRawData());
			else
			{
				/*uint32_t *key = (uint32_t *) rc4sbox;
				LPDWORD encptr = (LPDWORD) pProcessSection->RawData();

				for(DWORD dwPtr = 0; dwPtr < pProcessSection->SizeOfRawData(); dwPtr += 8, encptr += 2)
					tea_encrypt((uint32_t *) encptr, key);*/
			}

		}
	}

	if (pTarget->IsDLL())
	{	// DLL stub .. SECTION RWX
		pTargetSection->GetSectionHeader()->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
	}
	else
	{	// EXE STUB ... SECTION RX
		pTargetSection->GetSectionHeader()->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
	}

	// Laod Config Data <-> REMOVE!!!
	if (DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != 0 && pTarget->IsDLL() == FALSE)
	{
		std::cout << "\t**WARNING**\tLOAD_CONFIG Data Directory isn't NULL! Removing! " << std::endl;

		DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
		DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =  
		(PIMAGE_EXPORT_DIRECTORY) pTarget->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
	LPDWORD AddressOfFunctions = (LPDWORD) pTarget->RawPointer(ExportDirectory->AddressOfFunctions);

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
			
	int maxoffset = (pTargetSection->VirtualSize() - pUnpackerCode->SizeOfRawData);
	
	int basesize  = 0;

	if (maxoffset == 0)
		basesize = 0;
	else
		basesize = rand() % maxoffset;	// offset

	LPVOID lpRawDestin = CALC_OFFSET(LPVOID, pTargetSection->RawData(), basesize);	// an offset inside acceptable range


	/*******************************************************************************************
	 * WARNING!!!
	 *	The next memcpy transfer section from our binary into target!
	 *	All patch/modification must be done after next line!
	 ******************************************************************************************/
	memcpy(lpRawDestin, lpRawSource, pUnpackerCode->SizeOfRawData);

	/**
	 *	Decryption routine
	 **/
	if (pTarget->IsDLL())
	{	// process code for encryption of "RC4"
	
	}
	else
	{	// process code for encryption of TEA
		
	}

	//////////////////////
	// write new entry point!
	pTarget->NtHeader64()->OptionalHeader.AddressOfEntryPoint = pTargetSection->VirtualAddress() + basesize + rvaEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
	///////////////////////
	
	if (kernel32GetProcAddress_Offset == 0 || kernel32LoadLibraryA_Offset == 0)
	{
		std::cout << "Error! KERNEL32!GetProcAddress/LoadLibraryA not found in IAT" << std::endl;
		return 0;
	}

	Patch_MARKER_QWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key0, passKeyPtr[0]);
	Patch_MARKER_QWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key1, passKeyPtr[1]);
	Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &dwRelocSize, DataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &lpRelocAddress, DataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	if (pTarget->IsDLL())
	{	// nothing!!!
	}
	else
	{	// save preferred image base
		Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_baseAddress, pTarget->NtHeader64()->OptionalHeader.ImageBase);
	}

	// Transfer our .reloc into .reloc of target
	
	DWORD dwNewRelocSize = 0;
	DWORD dwNewRelocOffset = 0;
	
	if (relocSection != NULL)
	{	// there are a relocation
		// space available into section!
		dwOffset = RoundUp(relocSection->VirtualSize(), 0x10);
		dwNewRelocOffset = relocSection->VirtualAddress() + dwOffset;
		LPVOID lpWriteInto = CALC_OFFSET(LPVOID, relocSection->RawData(), dwOffset);
		dwNewRelocSize = Transfer_Reloc_Table(pImageDosHeader, pImageNtHeaders64, pUnpackerCode, lpWriteInto, pTargetSection->VirtualAddress() + basesize, pTarget, (PIMAGE_NT_HEADERS64)  pTarget->NtHeader64());
		relocSection->GetSectionHeader()->Misc.VirtualSize = dwOffset + dwNewRelocSize;
	}
	else
	{	// allocate new section inside ".text" section
		dwOffset = RoundUp(pUnpackerCode->Misc.VirtualSize, 16);
		dwNewRelocSize = Transfer_Reloc_Table(pImageDosHeader, pImageNtHeaders64, pUnpackerCode, CALC_OFFSET(LPVOID, lpRawDestin, dwOffset + basesize ), pTargetSection->VirtualAddress(), pTarget, (PIMAGE_NT_HEADERS64) pTarget->NtHeader64());
		dwNewRelocOffset = pTargetSection->VirtualAddress() + dwOffset;
	}

	pTarget->NtHeader64()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = dwNewRelocSize;
	pTarget->NtHeader64()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = dwNewRelocOffset;

	/**
	 *	EXPORT SYMBOLS
	 **/
	if (pTarget->IsDLL())
	{	// DLL - Patch 
		DWORD dwSignatureSize = table[1] - table[0];

		for(int i=0; i < ExportDirectory->NumberOfFunctions; i++)
		{
			ULONG64 exportRVA = table[i];
			ULONG64 exportSymbolEntryPoint = exportRVA - ((ULONG64) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
			exportSymbolEntryPoint = pTargetSection->VirtualAddress() + basesize + exportSymbolEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
			DWORD dwOldValue = AddressOfFunctions[i];
			AddressOfFunctions[i] = exportSymbolEntryPoint;
			Patch_EXPORT_SYMBOL(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (LPVOID) table[i], dwSignatureSize, exportSymbolEntryPoint, dwOldValue);

		}
	}

	
	// lpRawDestination PATCH!

	// Patch Entry point
	
	if (kernel32GetProcAddress_Offset == 0 || kernel32LoadLibraryA_Offset == 0)
	{
		std::cout << "Error! KERNEL32!GetProcAddress/LoadLibraryA not found in IAT" << std::endl;
		return 0;
	}

	Patch_MARKER((LPVOID)(pTargetSection->VirtualAddress()+basesize), (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_EntryPoint, 9, AddressOfEntryPoint);

	Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_LoadLibraryA, 0x0F, kernel32LoadLibraryA_Offset);
	Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_GetProcAddress, 0x0F, kernel32GetProcAddress_Offset);

	Patch_MARKER_QWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key0, passKeyPtr[0]);
	Patch_MARKER_QWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key1, passKeyPtr[1]);

	Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &dwRelocSize, pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &lpRelocAddress, pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	relocation_block_t *ImageRelocation = (relocation_block_t *)pTarget->RawPointer(pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

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


	if (argc > 2)
	{
		char tmpName[MAX_PATH];

		strcpy(tmpName, argv[2]);
		int lentmp = strlen(tmpName);

		if (tmpName[lentmp-1] == '\\')
		{	// random name!
			SYSTEMTIME time;
			GetSystemTime(&time);
			sprintf_s(tmpName, "%s%04i%02i%02i_%02i%02i.exe", argv[2], time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute);
		}
		pTarget->Save(tmpName);
	}
	else
		pTarget->Save(argv[1]);

	delete pTarget;	// destroy and release memory!
	delete morph;		// destroy and release memory!

	return 0;
}

#endif
