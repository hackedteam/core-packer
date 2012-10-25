#ifndef __LIBRARY_H__
#define __LIBRARY_H__

/**
 *	Load a DLL in memory, without applying relocations, resolving iat and others...
 **/
LPVOID InternalLoadLibrary(TCHAR* lpFileName, DWORD dwAdditionalPages);
BOOL InternalWriteLibraryToFile(LPVOID lpBase, TCHAR* lpOutFileName);

PIMAGE_NT_HEADERS GetNTHeader(LPVOID lpBaseAddress);
PIMAGE_SECTION_HEADER SectionHeader(LPVOID lpBaseAddress);

/**
 *	Increment the PE header section count
 **/
PIMAGE_SECTION_HEADER AddSection(LPVOID lpBaseAddress);
PIMAGE_SECTION_HEADER LastHeader(LPVOID lpBaseAddress);

/**
 *	Increase the optional header
 **/
LPVOID ExpandOptionalHeader(LPVOID lpBaseAddress, WORD requiredBytes);

DWORD __stdcall RoundUp(DWORD value, DWORD base);

BOOL SaveLibrary64ToFile(LPVOID lpBase, TCHAR* lpOutFileName);
BOOL SaveLibraryToFile(LPVOID lpBase, TCHAR* lpOutFileName);
#endif
