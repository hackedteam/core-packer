#ifndef __LOADLIBRARY_H_
#define __LOADLIBRARY_H_

#pragma once

class CLoadLibrary
{
	private:
		LPVOID	_lpBaseAddress;			// Library Base Address

	public:
		CLoadLibrary(void);
		virtual ~CLoadLibrary(void);

	public:
		PIMAGE_SECTION_HEADER	GetLastSectionHeader();
		PIMAGE_SECTION_HEADER	AddSectionHeader();
		
		LPVOID ExpandOptionalHeader(WORD requiredBytes);
		
		BOOL SaveLibraryToFile(TCHAR* lpOutFileName);
		BOOL SaveLibrary64ToFile(TCHAR* lpOutFileName);

		PIMAGE_NT_HEADERS GetNTHeader();
		PIMAGE_SECTION_HEADER SectionHeader();

		BOOL LoadLibrary(TCHAR* lpFileName, DWORD dwAdditionalPages);
};

#endif
