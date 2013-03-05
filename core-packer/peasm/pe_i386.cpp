/****************************************************************************
 * PE Assembly
 *	i386 routine
 ***************************************************************************/

#include <Windows.h>
#include "peasm.h"
#include "pesection.h"

static BOOL load_image(CPeAssembly *pe, HANDLE hFile, SECTION_ARRAY *sections)
{
	DWORD numberOfBytesRead;
	PIMAGE_DOS_HEADER dos_header = pe->DosHeader();
	PIMAGE_NT_HEADERS32 nt_header = pe->NtHeader();

	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
	short NumberOfSections = nt_header->FileHeader.NumberOfSections;

	for(unsigned short i = 0; i < NumberOfSections; i++, section_header++)
	{
		void *region = malloc(pe->round_section(section_header->Misc.VirtualSize));

		SetFilePointer(hFile, section_header->PointerToRawData, NULL, FILE_BEGIN);
		ReadFile(hFile, region, section_header->SizeOfRawData, &numberOfBytesRead, NULL);
		CPeSection *section = new CPeSection(pe, section_header, section_header->VirtualAddress, section_header->Misc.VirtualSize, region);	// duplicate this section!

		SECTION_ITEM dummy = { section_header->VirtualAddress, section };
		sections->push_back(dummy);

		free(region);
	}

	return TRUE;
}

static BOOL write_image(CPeAssembly *pe, HANDLE hFile, SECTION_ARRAY *sections)
{
	DWORD numberOfBytesWritten;
	PIMAGE_DOS_HEADER dos_header = pe->DosHeader();
	PIMAGE_NT_HEADERS32 nt_header = pe->NtHeader();

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew == 0)
	{
		return FALSE;
	}

	if( !WriteFile( hFile, dos_header, dos_header->e_lfanew, &numberOfBytesWritten, NULL))
		return FALSE;

	// PE header

	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	DWORD dwSizeHeader = nt_header->FileHeader.SizeOfOptionalHeader  + sizeof(nt_header->FileHeader) + 4;// +
	//sizeof(IMAGE_SECTION_HEADER)*pe_header->FileHeader.NumberOfSections;

	//PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)(dos_header) + dwSizeHeader + dos_header->e_lfanew);

	// sort items via iterator using "va"
	sections->sort();

	std::list<SECTION_ITEM>::iterator it = sections->begin();

	// -- UPDATE HEADER BEFORE WRITING!!!
	//update_section_header();	// transfer new code!
	/* TODO: adjust SizeOfImage and others... */
	// ++ UPDATE HEADER BEFORE WRITING!!!

	// write PE header!
	WriteFile( hFile, nt_header, 0x400 - dos_header->e_lfanew, &numberOfBytesWritten,NULL);

	// write sections...
	it = sections->begin();	// writing section data!
	do 
	{
		LPVOID rawData = it->descriptor->RawData();
		DWORD size = it->descriptor->SizeOfRawData();

		if (size > 0)
		{	// write
			WriteFile(hFile, rawData, size, &numberOfBytesWritten, NULL);
		}

		it++;
	} while (it != sections->end());

	return TRUE;
}

struct _file_support pe_i386 = 
{
	IMAGE_FILE_MACHINE_I386,
	load_image,
	write_image
};
