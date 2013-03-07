#include <Windows.h>
#include <iostream>
#include "peasm/peasm.h"
#include "peasm/pesection.h"
#include "library.h"
#include "macro.h"
#include "rva.h"
#include "rc4.h"
#include "symbols.h"
#include "dll32.h"
#include "tea.h"
#include "patchutils.h"

#ifdef _BUILD32

extern BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
extern "C" VOID WINAPI __crt0Startup(DWORD);
extern "C" VOID WINAPI DELAYDECRYPT();


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

// reloc table
typedef struct _relocation_block {
	DWORD	PageRVA;
	DWORD	BlockSize;
} relocation_block_t;

typedef short relocation_entry;


ULONG dll32_FakeExport[14] =
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
	(ULONG) _FakeEntryPoint9,
	(ULONG) _FakeEntryPointA,
	(ULONG) _FakeEntryPointB,
	(ULONG) _FakeEntryPointC,
	NULL
};

ULONG exe32_FakeExport[11] =
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
	(ULONG) _FakeEntryPoint9,
	NULL
};


void Patch_EXPORT_SYMBOL(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD newOffset, DWORD oldOffset)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, 0x12);

	if (lpInitialByte != NULL)
	{
		for(int i = 0; i < 0x20; i++)
		{
			DWORD dwMarker = 0x10001000;
			if (memcmp(CALC_OFFSET(LPVOID, lpInitialByte, i), &dwMarker, sizeof(DWORD))	== 0)
			{
				LPDWORD c = CALC_OFFSET(LPDWORD, lpInitialByte, i);
				*c = oldOffset;
				return;
			}
		}

	}

}

/**
 *	Return size required for relocation
 **/
size_t SizeOfRelocSection(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection)
{
	size_t size = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD dwImageBase = pSelf->OptionalHeader.ImageBase;

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


DWORD Transfer_Reloc_Table(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection, LPVOID lpOutput, DWORD dwNewVirtualAddress, CPeAssembly *destination, PIMAGE_NT_HEADERS32 pNewFile)
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

char *szSectionName[] = { ".hermit\0", ".pedll32\0", ".pedll64\0", ".peexe32\0", ".peexe64\0" };

PIMAGE_SECTION_HEADER lookup_core_section(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, BOOL dllTARGET)
{
	short NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections;

	char *szHermitName = szSectionName[1];

	if (dllTARGET == FALSE)
		szHermitName = szSectionName[3];

	PIMAGE_SECTION_HEADER pResult = NULL;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (memcmp(szHermitName, pSection->Name, 8) == 0)
		{
			std::cout << szHermitName << "/32bit section found in code" << std::endl;
			
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


BOOL lookup_rand_file(char *szOutFile, int maxsize)
{
	memset(szOutFile, 0, maxsize);
	
	char szWindirPath[MAX_PATH];

	DWORD dwIgnore = GetEnvironmentVariableA("windir", szWindirPath, MAX_PATH);

	if (dwIgnore == 0)
	{	// try default c:\windows
		strcpy(szWindirPath, "C:\\windows\\");
	}
	else
	{
		int i = strlen(szWindirPath);

		if (szWindirPath[i-1] != '\\')
			strcat(szWindirPath, "\\");
	}

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");

	if(NULL != fnIsWow64Process)
    {
		BOOL bIsWow64 = FALSE;

		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);

		if (bIsWow64)
			strcat(szWindirPath, "syswow64\\");
		else
			strcat(szWindirPath, "system32\\");
    }
	else
	{
		strcat(szWindirPath, "system32\\");
	}

	char szFindPath[MAX_PATH];
	sprintf(szFindPath, "%s*.dll", szWindirPath);

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

	strcat(szWindirPath, _previous_findfiledata.cFileName);

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

int main32(int argc, char *argv[])
{
	srand(GetTickCount());	// initialize for (rand)

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

	
	CPeAssembly *pInfectMe = new CPeAssembly();

	pInfectMe->Load(argv[1]);

	CPeAssembly *morph = NULL;

	if (argc > 3)
		morph = load_random(argv[3]);
	else
		morph = load_random(NULL);

	// find patterns!
	//PIMAGE_DOS_HEADER pInfectMe = (PIMAGE_DOS_HEADER) InternalLoadLibrary(argv[1], 0);
	//PIMAGE_NT_HEADERS pInfectMeNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS, pInfectMe, pInfectMe->e_lfanew);
	
	PIMAGE_SECTION_HEADER pUnpackerCode = NULL;
	
	if (pInfectMe->IsDLL())
	{	// it's a DLL?!?!?
		std::cout << "Input file is DLL!" << std::endl;

		pUnpackerCode = lookup_core_section(pImageDosHeader, pImageNtHeaders32, TRUE);
	}
	else if (pInfectMe->IsEXE())
	{
		std::cout << "Input file is EXECUTABLE!" << std::endl;
		pUnpackerCode = lookup_core_section(pImageDosHeader, pImageNtHeaders32, FALSE);
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

	size_t required_reloc_space = SizeOfRelocSection(pImageDosHeader, pImageNtHeaders32, pUnpackerCode);
	CPeSection *relocSection = pInfectMe->LookupSectionByName(".reloc");

	size_t relocsize = relocSection->VirtualSize();
		
	if (relocsize + required_reloc_space > relocSection->SizeOfRawData())
	{	// expande
		relocSection->AddSize(required_reloc_space);
	}


	char passKey[16];

	for(int i =0; i < sizeof(passKey); i++)
		passKey[i] = rand() % 256;

	BYTE rc4sbox[256];
	
	PIMAGE_DATA_DIRECTORY DataDir = pInfectMe->DataDirectory();

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pInfectMe->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	PIMAGE_SECTION_HEADER pDestSection = NULL;

	char *szSectionName = szSectionNames[rand() % 15];
	
	CPeSection *pInfectSection = NULL;

	int newVirtualSize = RoundUp(pUnpackerCode->Misc.VirtualSize + ((rand() % 16) * 1024), 1024);

	if (pInfectMe->IsDLL())
	{
		pInfectSection = pInfectMe->AddSection(szSectionName, 0x0, newVirtualSize);	// move section in "head"
	}
	else if (pInfectMe->IsEXE())
	{
		pInfectSection = pInfectMe->AddSection(szSectionName, 0x1000, newVirtualSize);	// move section in "head"

		CPeSection *pMorphSection = morph->getSection(0);

		memset(pInfectSection->RawData(), 0x90, newVirtualSize);
		memcpy(pInfectSection->RawData(), pMorphSection->RawData(), (pMorphSection->SizeOfRawData() < newVirtualSize) ? pMorphSection->SizeOfRawData() : newVirtualSize);
	}
	
	DWORD kernel32LoadLibraryA_Offset = 0;
	DWORD kernel32GetProcAddress_Offset = 0;
	DWORD kernel32CreateFileA_Offset = 0;
	DWORD kernel32GetModuleFileNameA_Offset = 0;
	DWORD kernel32ReadFile_Offset = 0;
	DWORD kernel32SetFilePointer_Offset = 0;
	DWORD kernel32CloseHandle_Offset = 0;

	while(pImportDescriptor->Characteristics != 0)
	{
		//std::cout << "Name " << (char *) pInfectMe->RawPointer(pImportDescriptor->Name) << std::endl;
		
		//std::cout << "\tEntries: " << std::endl;

#ifdef _BUILD64
		PULONG64 rvaName = CALC_OFFSET(PULONG64, pInfectMe, pImportDescriptor->Characteristics);
		PULONG64 iatRVA = CALC_OFFSET(PULONG64, pInfectMe, pImportDescriptor->FirstThunk);
#else
		PULONG rvaName = (PULONG) pInfectMe->RawPointer(pImportDescriptor->Characteristics);
		PULONG iatRVA = (PULONG) pInfectMe->RawPointer(pImportDescriptor->FirstThunk);
		PULONG iat = (PULONG) pImportDescriptor->FirstThunk;
#endif


		while(*rvaName != 0)
		{
			char *name = (char *) pInfectMe->RawPointer((*rvaName & 0x7fffffff) + 2);

			if (name != NULL)
			{
				//std::cout << "\t " << std::hex << CALC_DISP(LPVOID, iatRVA, pInfectMe) << " " << std::hex << *iatRVA << " " << name << std::endl;

				if (strcmp(name, "LoadLibraryA") == 0) 
					kernel32LoadLibraryA_Offset = (DWORD) iat;
				else if (strcmp(name, "GetProcAddress") == 0)
					kernel32GetProcAddress_Offset = (DWORD) iat;
				else if (strcmp(name, "CreateFileA") == 0)
					kernel32CreateFileA_Offset = (DWORD) iat;
				else if (strcmp(name, "GetModuleFileNameA") == 0)
					kernel32GetModuleFileNameA_Offset = (DWORD) iat;
				else if (strcmp(name, "SetFilePointer") == 0)
					kernel32SetFilePointer_Offset = (DWORD) iat;
				else if (strcmp(name, "ReadFile") == 0)
					kernel32ReadFile_Offset = (DWORD) iat;
				else if (strcmp(name, "CloseHandle") == 0)
					kernel32CloseHandle_Offset = (DWORD) iat;
			}
			else
			{	// by ordinal
				//LPDWORD sticazzi = (LPDWORD) pInfectMe->RawPointer((*rvaName & 0x7fffffff) + 2);
				//std::cout << "\t [ORDINAL] " << std::hex << CALC_DISP(LPVOID, iatRVA, pInfectMe) << " " << std::hex << *x << " " << std::endl;
			}

			rvaName++;
			iatRVA++;
			iat++;
		}

		pImportDescriptor++;
	}

	for(int i = 0; i < pInfectMe->NumberOfSections(); i++)
	{	// each section must be packed
		if (pInfectMe->IsDLL())
		{
			init_sbox(rc4sbox);
			init_sbox_key(rc4sbox, (BYTE *) passKey, 16);
		}
		else
		{
			uint32_t *key = (uint32_t *) rc4sbox;
			memcpy(key, passKey, 16);
		}

		CPeSection *pProcessSection = pInfectMe->getSection(i);
		PIMAGE_SECTION_HEADER pSectionHeader = pProcessSection->GetSectionHeader();

		if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
		{	// skip current section
		}
		else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{
			//pSectionHeader->Characteristics |= 0x02;
			
			if (pInfectMe->IsDLL())
				cypher_msg(rc4sbox, (PBYTE) pProcessSection->RawData(), pProcessSection->SizeOfRawData());
			else
			{
				uint32_t *key = (uint32_t *) rc4sbox;
				LPDWORD encptr = (LPDWORD) pProcessSection->RawData();

				for(DWORD dwPtr = 0; dwPtr < pProcessSection->SizeOfRawData(); dwPtr += 8, encptr += 2)
					tea_encrypt((uint32_t *) encptr, key);
			}

			//pSectionHeader->Characteristics ^= IMAGE_SCN_MEM_EXECUTE;
			if (strcmp((char *) pSectionHeader->Name, ".text") == 0)
			{	// text section!
				//pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData;
			}

		}
		else if (memcmp(pSectionHeader->Name, ".data", 5) == 0)
		{
			//pSectionHeader->Characteristics |= 0x02;

			if (pInfectMe->IsDLL())
				cypher_msg(rc4sbox, (PBYTE) pProcessSection->RawData(), pProcessSection->SizeOfRawData());
			else
			{
				uint32_t *key = (uint32_t *) rc4sbox;
				LPDWORD encptr = (LPDWORD) pProcessSection->RawData();

				for(DWORD dwPtr = 0; dwPtr < pProcessSection->SizeOfRawData(); dwPtr += 8, encptr += 2)
					tea_encrypt((uint32_t *) encptr, key);
			}

		}

		//else if (memcmp(pSectionHeader->Name, ".rdata", 6) == 0)
		//{
		//	pSectionHeader->Characteristics |= 0x03;

		//	/*DWORD sizeOfSection = 
		//		pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
		//			- pProcessSection->VirtualAddress 
		//			- pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
		//				
		//	LPVOID sectionAddress = rva2addr(pInfectMe, pInfectMeNtHeader, (LPVOID) (pProcessSection->VirtualAddress + pInfectMeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size));*/

		//	if (pInfectMe->IsDLL())
		//		cypher_msg(rc4sbox, (PBYTE) sectionAddress, sizeOfSection);
		//	else
		//	{
		//		uint32_t *key = (uint32_t *) rc4sbox;
		//		LPDWORD encptr = (LPDWORD) sectionAddress;

		//		for(DWORD dwPtr = 0; dwPtr < sizeOfSection; dwPtr += 8, encptr += 2)
		//			tea_encrypt((uint32_t *) encptr, key);
		//	}
		//}

	}
	
	//memcpy(pInfectSection->Name, szHermitName, 8);
	
	//PIMAGE_SECTION_HEADER pInfectSection = IMAGE_FIRST_SECTION(pInfectMeNtHeader);
	
	if (pInfectMe->IsDLL())
	{	// DLL stub .. SECTION RWX
		pInfectSection->GetSectionHeader()->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
	}
	else
	{	// EXE STUB ... SECTION RX
		pInfectSection->GetSectionHeader()->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
	}

	// Laod Config Data <-> REMOVE!!!
	if (DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != 0 && pInfectMe->IsDLL() == FALSE)
	{
		std::cout << "\t**WARNING**\tLOAD_CONFIG Data Directory isn't NULL! Removing! " << std::endl;

		DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
		DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =  
		(PIMAGE_EXPORT_DIRECTORY) pInfectMe->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
	LPDWORD AddressOfFunctions = (LPDWORD) pInfectMe->RawPointer(ExportDirectory->AddressOfFunctions);


	ULONG *table = NULL;

	if (pInfectMe->IsDLL()) 
		table = dll32_FakeExport;
	else
		table = exe32_FakeExport;

	LPVOID lpRawSource = rva2addr(pImageDosHeader, pImageNtHeaders32, CALC_OFFSET(LPVOID, pImageDosHeader, pUnpackerCode->VirtualAddress));
	
	int maxoffset = (pInfectSection->VirtualSize() - pUnpackerCode->SizeOfRawData);
	
	int basesize  = 0;

	if (maxoffset == 0)
		basesize = 0;
	else
		basesize = rand() % maxoffset;	// offset

	LPVOID lpRawDestin = CALC_OFFSET(LPVOID, pInfectSection->RawData(), basesize);	// an offset inside acceptable range


	/*******************************************************************************************
	 * WARNING!!!
	 *	The next memcpy transfer section from our binary into target!
	 *	All patch/modification must be done after next line!
	 ******************************************************************************************/
	memcpy(lpRawDestin, lpRawSource, pUnpackerCode->SizeOfRawData);

	/**
	 *	Decryption routine
	 **/
	if (pInfectMe->IsDLL())
	{	// process code for encryption of "RC4"
	
	}
	else
	{	// process code for encryption of TEA
		void *start = static_cast<void *>(&tea_decrypt);
		void *end = static_cast<void *>(&tea_decrypt_end_marker);
		int size = static_cast<int>((int) end - (int) start);

		char *encrypt = (char *) FindBlockMem((LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, start, size);

		while(size-- > 0) 
		{
			*encrypt++ ^= 0x66;
		}

	}

	/**
	 *	EXPORT SYMBOLS
	 **/
	if (pInfectMe->IsDLL())
	{	// DLL - Patch 
		for(int i=0; i < ExportDirectory->NumberOfFunctions; i++)
		{
			ULONG exportRVA = table[i];

			if (exportRVA == NULL)
			{
				std::cout << "Warning -> more exports into module!" << std::endl;
				continue;	// no more symbols!
			}

			ULONG exportSymbolEntryPoint = exportRVA - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
			exportSymbolEntryPoint = pInfectSection->VirtualAddress() + basesize + exportSymbolEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
		
			DWORD dwOldValue = AddressOfFunctions[i];
			AddressOfFunctions[i] = exportSymbolEntryPoint;
		
			Patch_EXPORT_SYMBOL(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (LPVOID) table[i], exportSymbolEntryPoint, dwOldValue - 0x1000);
		}
	}
	else
	{	// EXE - overwrite "export"
		int stubsize = (int)(table[1] - table[0]);

		PIMAGE_DATA_DIRECTORY dir = pInfectMe->DataDirectory();

		BYTE watermark[8];

		if (dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
		{
			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY) pInfectMe->RawPointer(dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			memcpy(watermark, pInfectMe->RawPointer(pExportDir->Name), 8);
		}

		for(int i = 0; i < (sizeof(table) / sizeof(ULONG)); i++)
		{	//
			ULONG exportRVA = table[i];
			ULONG exportSymbolEntryPoint = exportRVA - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
			exportSymbolEntryPoint = pInfectSection->VirtualAddress() + basesize + exportSymbolEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;

			LPVOID lp = FindBlockMem((LPBYTE)lpRawDestin, pUnpackerCode->SizeOfRawData, (LPVOID) table[i], stubsize);

			if (lp != NULL)
				memset(lp, 0xCC, stubsize);
		}
	}

	DWORD dwOffset = RoundUp(pUnpackerCode->SizeOfRawData, 16);

	ULONG offsetEntryPoint = (ULONG) (DllEntryPoint);

	ULONG rvaEntryPoint = offsetEntryPoint - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
	
	DWORD AddressOfEntryPoint = pInfectMe->NtHeader()->OptionalHeader.AddressOfEntryPoint;
	
	if (pInfectMe->IsDLL() == FALSE)
	{	// it's a dll!!
		offsetEntryPoint = (ULONG) (__crt0Startup);
		rvaEntryPoint = offsetEntryPoint - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
	}
	

	//////////////////////
	// write new entry point!
	pInfectMe->NtHeader()->OptionalHeader.AddressOfEntryPoint = pInfectSection->VirtualAddress() + basesize + rvaEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
	///////////////////////
	
	if (kernel32GetProcAddress_Offset == 0 || kernel32LoadLibraryA_Offset == 0)
	{
		std::cout << "Error! KERNEL32!GetProcAddress/LoadLibraryA not found in IAT" << std::endl;
		return 0;
	}

	ULONG64 *passKeyPtr = (ULONG64*) &passKey;

	//Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pSectionInput->SizeOfRawData, &_EntryPoint, 9, AddressOfEntryPoint);

	/**
	 *	patch code
	 **/
	if (pInfectMe->IsDLL())
	{	// DLL ! FIX entry point
		Patch_Entry(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_EntryPoint, 0x10, AddressOfEntryPoint-0x1000);
		Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_dll32_LoadLibraryA, 0x12, kernel32LoadLibraryA_Offset);
		Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_dll32_GetProcAddress, 0x12, kernel32GetProcAddress_Offset);
		Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_GetModuleFileNameA, 0x12, kernel32GetModuleFileNameA_Offset);
	}
	else
	{	// EXE ! FIX entry point
		Patch_Entry(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_CrtStartup, 0x0A, AddressOfEntryPoint, 0x0a);
		Patch_Entry(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_GETBASE, 0x0a, pInfectSection->VirtualAddress() + basesize, 0x01);
		Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_exe_LoadLibraryA, 0x0c, kernel32LoadLibraryA_Offset);
		Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_exe_GetProcAddress, 0x0c, kernel32GetProcAddress_Offset);
		Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_exe_GetModuleFileNameA, 0x0c, kernel32GetModuleFileNameA_Offset);
	}

	
	if (kernel32CreateFileA_Offset == 0)
	{
		ULONG exportRVA = (pInfectMe->IsDLL()) ? (ULONG) _CreateFileA : (ULONG) _exe_CreateFileA;

		ULONG exportSymbolEntryPoint = exportRVA - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
		exportSymbolEntryPoint = pInfectSection->VirtualAddress() + basesize + exportSymbolEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
		LPBYTE lp = (LPBYTE) FindBlockMem((LPBYTE)lpRawDestin, pInfectSection->SizeOfRawData(), (pInfectMe->IsDLL()) ? (LPVOID) _CreateFileA : (LPVOID) _exe_CreateFileA, 0x12);
		char symbolname[17] = { '~', 'C', 'r', 'e', 'a', 't', 'e', 0x01, 0x01, 0x01, 0x01, 'F', 'i', 'l','e','A',0x00};

		memcpy(lp, symbolname, 7);
		memcpy(lp+0x0b, symbolname+0x0b,6);

	}
	else
	{	// applying patch!!!
		Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pInfectMe->IsDLL()) ? &_CreateFileA : &_exe_CreateFileA, 0x12, kernel32CreateFileA_Offset);
	}
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pInfectMe->IsDLL()) ? &_SetFilePointer : &_exe_SetFilePointer, 0x12, kernel32SetFilePointer_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pInfectMe->IsDLL()) ? &_ReadFile : &_exe_ReadFile, 0x12, kernel32ReadFile_Offset);
	Patch_MARKER(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pInfectMe->IsDLL()) ? &_CloseHandle : &_exe_CloseHandle, 0x12, kernel32CloseHandle_Offset);

	Patch_MARKER_QWORD(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key0, passKeyPtr[0]);
	Patch_MARKER_QWORD(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key1, passKeyPtr[1]);
	Patch_MARKER_DWORD(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &dwRelocSize, DataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	Patch_MARKER_DWORD(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &lpRelocAddress, DataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	if (pInfectMe->IsDLL())
	{	// nothing!!!
	}
	else
	{	// save preferred image base
		Patch_MARKER_DWORD(pInfectMe, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_baseAddress, pInfectMe->NtHeader()->OptionalHeader.ImageBase);
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
		dwNewRelocSize = Transfer_Reloc_Table(pImageDosHeader, pImageNtHeaders32, pUnpackerCode, lpWriteInto, pInfectSection->VirtualAddress() + basesize, pInfectMe, pInfectMe->NtHeader());
		relocSection->GetSectionHeader()->Misc.VirtualSize = dwOffset + dwNewRelocSize;
	}
	else
	{	// allocate new section inside ".text" section
		dwOffset = RoundUp(pUnpackerCode->Misc.VirtualSize, 16);
		dwNewRelocSize = Transfer_Reloc_Table(pImageDosHeader, pImageNtHeaders32, pUnpackerCode, CALC_OFFSET(LPVOID, lpRawDestin, dwOffset + basesize ), pInfectSection->VirtualAddress(), pInfectMe, pInfectMe->NtHeader());
		dwNewRelocOffset = pInfectSection->VirtualAddress() + dwOffset;
	}

	pInfectMe->NtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = dwNewRelocSize;
	pInfectMe->NtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = dwNewRelocOffset;

	//pInfectSection->

	if (argc > 2)
	{
		char tmpName[MAX_PATH];

		strcpy(tmpName, argv[2]);
		int lentmp = strlen(tmpName);

		if (tmpName[lentmp-1] == '\\')
		{	// random name!
			SYSTEMTIME time;
			GetSystemTime(&time);
			sprintf(tmpName, "%s%04i%02i%02i_%02i%02i.exe", argv[2], time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute);
		}
		pInfectMe->Save(tmpName);
	}
	else
		pInfectMe->Save(argv[1]);

	delete pInfectMe;	// destroy and release memory!
	delete morph;		// destroy and release memory!

	return 0;
}

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
	std::cout << "caught AV as expected. " << std::endl;
	return EXCEPTION_EXECUTE_HANDLER;
}

int main32_test(int argc, char *argv[])
{
	char szOutputFile[MAX_PATH];
	char szInputFile[MAX_PATH];
	char szFakeFile[MAX_PATH];
	char szWindirPath[MAX_PATH];

	char *fakeargv[] = { NULL, szInputFile, szOutputFile, szFakeFile };
	
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");


	DWORD dwIgnore = GetEnvironmentVariableA("windir", szWindirPath, MAX_PATH);

	if (dwIgnore == 0)
	{	// try default c:\windows
		strcpy(szWindirPath, "C:\\windows\\");
	}
	else
	{
		int i = strlen(szWindirPath);

		if (szWindirPath[i-1] != '\\')
			strcat(szWindirPath, "\\");
	}

	if(NULL != fnIsWow64Process)
    {
		BOOL bIsWow64 = FALSE;

		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);

		if (bIsWow64)
			strcat(szWindirPath, "syswow64\\");
		else
			strcat(szWindirPath, "system32\\");
    }
	else
	{
		strcat(szWindirPath, "system32\\");
	}
	
	char szFindPath[MAX_PATH];
	sprintf(szFindPath, "%s*.exe", szWindirPath);

	WIN32_FIND_DATA findfiledata;
	HANDLE hLook = FindFirstFileA(szFindPath, &findfiledata);
		
	do
	{	// perform a backup!
		strcpy(szInputFile, argv[1]);
		sprintf(szFakeFile, "%s%s", szWindirPath, findfiledata.cFileName);
		sprintf(szOutputFile, "%s_%s", argv[2], findfiledata.cFileName);
		
		std::cout << "Test using " << szFakeFile;
		
		//strcpy(szFakeFile, "c:\\tools\\putty.exe");

		__try 
		{ 	
			main32(4, fakeargv);
			std::cout << ".... done" << std::endl;
		}
		__except(filter(GetExceptionCode(), GetExceptionInformation())) 
		{
			std::cout << ".... done" << std::endl;
		}
	
	} while(FindNextFileA(hLook, &findfiledata));

	FindClose(hLook);
	return 1;
}


#endif
