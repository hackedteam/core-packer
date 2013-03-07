#include <Windows.h>
#include "LoadLibrary.h"
#include "macro.h"

static DWORD __stdcall RoundUp(DWORD value, DWORD base)
{
	while((value % base) != 0)
		value++;
	return value;
}

CLoadLibrary::CLoadLibrary(void)
	:	_lpBaseAddress(NULL)
{
}

CLoadLibrary::~CLoadLibrary(void)
{
}


#define PAGE_SIZE 4096

/**
 *	GetLastSectionHeader
 **/
PIMAGE_SECTION_HEADER CLoadLibrary::GetLastSectionHeader()
{
	if (_lpBaseAddress != NULL)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) _lpBaseAddress;

		if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew != 0x00000000)
		{	// valid exe signature
			PIMAGE_NT_HEADERS32 pe = (PIMAGE_NT_HEADERS32)((DWORD) dos + dos->e_lfanew);

			if (pe->Signature == IMAGE_NT_SIGNATURE)
			{
					DWORD sizeHeader = dos->e_lfanew + 
						pe->FileHeader.SizeOfOptionalHeader + 
						sizeof(pe->FileHeader) + 4;

				WORD *pNumOfSections = &pe->FileHeader.NumberOfSections;
				
				PIMAGE_SECTION_HEADER sectionHeader = 
					(PIMAGE_SECTION_HEADER) ((DWORD) _lpBaseAddress + sizeHeader);
				
				return sectionHeader + (*pNumOfSections - 1);
			}
		}
	}

	return NULL;
}


/**
 *	Increment the PE header section count
 **/
PIMAGE_SECTION_HEADER CLoadLibrary::AddSectionHeader()
{
	if (_lpBaseAddress != NULL)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) _lpBaseAddress;

		if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew != 0x00000000)
		{	// valid exe signature
			PIMAGE_NT_HEADERS32 pe = (PIMAGE_NT_HEADERS32)((DWORD) dos + dos->e_lfanew);

			if (pe->Signature == IMAGE_NT_SIGNATURE)
			{
					DWORD sizeHeader = dos->e_lfanew + 
						pe->FileHeader.SizeOfOptionalHeader + 
						sizeof(pe->FileHeader) + 4;

				WORD *pNumOfSections = &pe->FileHeader.NumberOfSections;
				
				PIMAGE_SECTION_HEADER sectionHeader = 
					(PIMAGE_SECTION_HEADER) ((DWORD) _lpBaseAddress + sizeHeader);
				
				DWORD freeBytes = 
					sectionHeader->PointerToRawData -
					sizeHeader -
					sizeof(IMAGE_SECTION_HEADER) * (*pNumOfSections);

				if (freeBytes >= sizeof(IMAGE_SECTION_HEADER))
				{
					PIMAGE_SECTION_HEADER result = &sectionHeader[*pNumOfSections];
					*pNumOfSections = *pNumOfSections + 1 ;
					
					return result;
				}
			}
		}
	}

	return NULL;
}


/**
 *	ExpandOptionalHeader(DWORD addBytes)
 **/
LPVOID CLoadLibrary::ExpandOptionalHeader(WORD requiredBytes)
{
	if (_lpBaseAddress != NULL)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) _lpBaseAddress;

		if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew != 0x00000000)
		{	// valid exe signature
			PIMAGE_NT_HEADERS32 pe = (PIMAGE_NT_HEADERS32)((DWORD) dos + dos->e_lfanew);

			if (pe->Signature == IMAGE_NT_SIGNATURE)
			{
					DWORD sizeHeader = dos->e_lfanew + 
						pe->FileHeader.SizeOfOptionalHeader + 
						sizeof(pe->FileHeader) + 4;

				WORD *pNumOfSections = &pe->FileHeader.NumberOfSections;
				
				PIMAGE_SECTION_HEADER sectionHeader = 
					(PIMAGE_SECTION_HEADER) ((DWORD) _lpBaseAddress + sizeHeader);
				
				DWORD freeBytes = 
					sectionHeader->PointerToRawData -
					sizeHeader -
					sizeof(IMAGE_SECTION_HEADER) * (*pNumOfSections);

				if (freeBytes >= requiredBytes)
				{
					DWORD sectSize = sizeof(IMAGE_SECTION_HEADER) * (*pNumOfSections);

					char *tmp = new char[sectSize];

					memcpy(tmp, (LPVOID) sectionHeader, sectSize);
					memset((LPVOID) sectionHeader, 0, sectSize);

					LPVOID destAddr = (LPVOID)((DWORD) sectionHeader + requiredBytes);

					memcpy(destAddr, tmp, sectSize);
					
					pe->FileHeader.SizeOfOptionalHeader += requiredBytes;
					delete [] tmp;
				}
			}
		}
	}

	return NULL;
}



#define PAGE_SIZE 4096

BOOL CLoadLibrary::SaveLibraryToFile(TCHAR* lpOutFileName)
{
   DWORD numberOfBytesWritten;
   HANDLE hOutFile = CreateFile( lpOutFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

   if(hOutFile == INVALID_HANDLE_VALUE)
       return FALSE;
      // DOS header
   PIMAGE_DOS_HEADER dos_header;

   dos_header = (PIMAGE_DOS_HEADER) _lpBaseAddress;

   if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew == 0)
   {
       CloseHandle(hOutFile);
       return FALSE;
   }

   if( !WriteFile( hOutFile, _lpBaseAddress, dos_header->e_lfanew, &numberOfBytesWritten, NULL))
       return FALSE;

   // PE header
   PIMAGE_NT_HEADERS32 pe_header;   
   pe_header = (PIMAGE_NT_HEADERS32)((DWORD) _lpBaseAddress + (DWORD)dos_header->e_lfanew );
      if (pe_header->Signature != IMAGE_NT_SIGNATURE)
   {
       CloseHandle(hOutFile);
       return FALSE;
   }
      DWORD dwSizeHeader = pe_header->FileHeader.SizeOfOptionalHeader  +
                       sizeof(pe_header->FileHeader) + 4;// +
                      //sizeof(IMAGE_SECTION_HEADER)*pe_header->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER sections = CALC_OFFSET(PIMAGE_SECTION_HEADER, _lpBaseAddress, dwSizeHeader + dos_header->e_lfanew);

   WriteFile( hOutFile, pe_header, sections[0].PointerToRawData - dos_header->e_lfanew, &numberOfBytesWritten,NULL);

   // write sections...
   for(unsigned short i = 0; i < pe_header->FileHeader.NumberOfSections; i++)
   {
       LPVOID addr = (LPVOID)((DWORD)_lpBaseAddress + sections[i].VirtualAddress);

       WriteFile( hOutFile, addr, RoundUp(sections[i].SizeOfRawData, pe_header->OptionalHeader.FileAlignment), &numberOfBytesWritten, NULL);
   }

   CloseHandle(hOutFile);
   return TRUE;
} 

BOOL CLoadLibrary::SaveLibrary64ToFile(TCHAR* lpOutFileName)
{
	DWORD numberOfBytesWritten;
	HANDLE hOutFile = CreateFile( lpOutFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if(hOutFile == INVALID_HANDLE_VALUE)
	return FALSE;
	// DOS header
	PIMAGE_DOS_HEADER dos_header;

	dos_header = (PIMAGE_DOS_HEADER) _lpBaseAddress;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew == 0)
	{
		CloseHandle(hOutFile);
		return FALSE;
	}

	PIMAGE_NT_HEADERS64 pe_header = CALC_OFFSET(PIMAGE_NT_HEADERS64, dos_header, dos_header->e_lfanew);   
	
	PIMAGE_SECTION_HEADER p = IMAGE_FIRST_SECTION(pe_header);

	if( !WriteFile( hOutFile, _lpBaseAddress, p->PointerToRawData, &numberOfBytesWritten, NULL))
		return FALSE;

	// PE header
	
	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
	{
		CloseHandle(hOutFile);
		return FALSE;
	}

	DWORD dwSizeHeader = pe_header->FileHeader.SizeOfOptionalHeader  + sizeof(pe_header->FileHeader) + 4;// +
	//sizeof(IMAGE_SECTION_HEADER)*pe_header->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)(_lpBaseAddress) + dwSizeHeader + dos_header->e_lfanew);

	//WriteFile( hOutFile, pe_header, sections[0].PointerToRawData - dos_header->e_lfanew, &numberOfBytesWritten,NULL);
	
	// write sections...
	for(unsigned short i = 0; i < pe_header->FileHeader.NumberOfSections; i++)
	{
		LPVOID addr = (LPVOID)((DWORD)_lpBaseAddress + sections[i].VirtualAddress);

		WriteFile( hOutFile, addr, RoundUp(sections[i].SizeOfRawData, pe_header->OptionalHeader.FileAlignment), &numberOfBytesWritten, NULL);
	}

	CloseHandle(hOutFile);
	return TRUE;
} 

/**
 *	\!GetNTHeader
 *
 **/
PIMAGE_NT_HEADERS CLoadLibrary::GetNTHeader()
{
	if (_lpBaseAddress != NULL)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) _lpBaseAddress;

		if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew != 0x00000000)
		{	// valid exe signature
			PIMAGE_NT_HEADERS32 pe = (PIMAGE_NT_HEADERS32)((DWORD) dos + dos->e_lfanew);

			if (pe->Signature == IMAGE_NT_SIGNATURE)
			{
				return (PIMAGE_NT_HEADERS) pe;
			}

		}
	}

	return NULL;
}


PIMAGE_SECTION_HEADER CLoadLibrary::SectionHeader()
{
	if (_lpBaseAddress != NULL)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) _lpBaseAddress;

		if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew != 0x00000000)
		{	// valid exe signature
			PIMAGE_NT_HEADERS32 pe = (PIMAGE_NT_HEADERS32)((DWORD) dos + dos->e_lfanew);

			if (pe->Signature == IMAGE_NT_SIGNATURE)
			{
				DWORD sizeHeader = dos->e_lfanew + pe->FileHeader.SizeOfOptionalHeader + sizeof(pe->FileHeader) + 4;

				WORD *pNumOfSections = &pe->FileHeader.NumberOfSections;
				
				PIMAGE_SECTION_HEADER sectionHeader = CALC_OFFSET(PIMAGE_SECTION_HEADER, _lpBaseAddress, sizeHeader);

				return sectionHeader;
			}
		}
	}

	return NULL;
}


BOOL CLoadLibrary::LoadLibrary(TCHAR* lpFileName, DWORD dwAdditionalPages)
{
	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD numberOfBytesread;
	IMAGE_DOS_HEADER dos_header;
	ZeroMemory(&dos_header, sizeof(dos_header));

	if (ReadFile(hFile, &dos_header, sizeof(dos_header), &numberOfBytesread, NULL) == FALSE)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew == 0)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	IMAGE_NT_HEADERS32 pe_header;
	ZeroMemory(&pe_header, sizeof(pe_header));

	SetFilePointer(hFile, dos_header.e_lfanew, NULL, FILE_BEGIN);

	if (ReadFile(hFile, &pe_header, sizeof(pe_header), &numberOfBytesread, NULL) == FALSE)
	{
		CloseHandle(hFile);
		return NULL;
	}

	if (pe_header.Signature != IMAGE_NT_SIGNATURE)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	if (pe_header.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		_lpBaseAddress = VirtualAlloc(NULL, pe_header.OptionalHeader.SizeOfImage + (PAGE_SIZE * 4096), MEM_COMMIT, PAGE_READWRITE);

		if (_lpBaseAddress == NULL)
		{
			CloseHandle(hFile);
			return FALSE;
		}

		DWORD sizeHeader = dos_header.e_lfanew + 
			pe_header.FileHeader.SizeOfOptionalHeader + 
			sizeof(pe_header.FileHeader) + 4;

		IMAGE_SECTION_HEADER section;

		ZeroMemory(&section, sizeof(IMAGE_SECTION_HEADER));

		SetFilePointer(hFile, sizeHeader, NULL, FILE_BEGIN);

		if (ReadFile(hFile, &section, sizeof(section), &numberOfBytesread, NULL) == NULL)
		{
			CloseHandle(hFile);
			VirtualFree(_lpBaseAddress, pe_header.OptionalHeader.SizeOfImage, MEM_FREE);
			_lpBaseAddress = NULL;
			return FALSE;
		}

		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		ReadFile(hFile, _lpBaseAddress, section.PointerToRawData, &numberOfBytesread, NULL);

		PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)(_lpBaseAddress) + sizeHeader);

		for(unsigned short i = 0; i < pe_header.FileHeader.NumberOfSections; i++, sections++)
		{
			LPVOID addrSection = (LPVOID)((DWORD)_lpBaseAddress + (DWORD)(sections->VirtualAddress));

			SetFilePointer(hFile, sections->PointerToRawData, NULL, FILE_BEGIN);
			ReadFile(hFile, addrSection, sections->SizeOfRawData, &numberOfBytesread, NULL);
		}
	}
	else if (pe_header.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		IMAGE_NT_HEADERS64 pe64_header;
		ZeroMemory(&pe64_header, sizeof(pe_header));

		SetFilePointer(hFile, dos_header.e_lfanew, NULL, FILE_BEGIN);

		if (ReadFile(hFile, &pe64_header, sizeof(pe64_header), &numberOfBytesread, NULL) == FALSE)
		{
			CloseHandle(hFile);
			return NULL;
		}

		
		_lpBaseAddress = VirtualAlloc(NULL, pe64_header.OptionalHeader.SizeOfImage + (PAGE_SIZE * 4096), MEM_COMMIT, PAGE_READWRITE);

		if (_lpBaseAddress == NULL)
		{
			CloseHandle(hFile);
			return FALSE;
		}

		DWORD sizeHeader = dos_header.e_lfanew + 
			pe_header.FileHeader.SizeOfOptionalHeader + 
			sizeof(pe_header.FileHeader) + 4;

		IMAGE_SECTION_HEADER section;

		ZeroMemory(&section, sizeof(IMAGE_SECTION_HEADER));

		SetFilePointer(hFile, sizeHeader, NULL, FILE_BEGIN);

		if (ReadFile(hFile, &section, sizeof(section), &numberOfBytesread, NULL) == NULL)
		{
			CloseHandle(hFile);
			VirtualFree(_lpBaseAddress, pe_header.OptionalHeader.SizeOfImage, MEM_FREE);
			_lpBaseAddress = NULL;
			return FALSE;
		}

		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		ReadFile(hFile, _lpBaseAddress, section.PointerToRawData, &numberOfBytesread, NULL);

		PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)(_lpBaseAddress) + sizeHeader);

		for(unsigned short i = 0; i < pe_header.FileHeader.NumberOfSections; i++, sections++)
		{
			LPVOID addrSection = CALC_OFFSET(LPVOID, _lpBaseAddress, sections->VirtualAddress);
			SetFilePointer(hFile, sections->PointerToRawData, NULL, FILE_BEGIN);
			ReadFile(hFile, addrSection, sections->SizeOfRawData, &numberOfBytesread, NULL);
		}

	}
	else
	{	// unsupported file machine
	}

	CloseHandle(hFile);
	return TRUE;
}
