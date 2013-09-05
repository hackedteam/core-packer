#include <Windows.h>
#include <delayimp.h>
#include <iostream>
#include "types.h"
#include "peasm.h"
#include "pesection.h"

//#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES  1

#define PAGE_SIZE	4096

typedef struct base_relocation_block
{
	uint32_t PageRVA;
	uint32_t BlockSize;
} base_relocation_block_t;

typedef struct base_relocation_entry
{
	uint16_t offset : 12;
	uint16_t type : 4;
} base_relocation_entry_t;

#define relocation_block_t base_relocation_block_t
#define relocation_entry_t base_relocation_entry_t

typedef short relocation_entry;

extern struct _file_support pe_i386;
extern struct _file_support pe_amd64;

#define SUPPORTED_IMAGE_FORMAT	2

struct _file_support* _file_[SUPPORTED_IMAGE_FORMAT] =
{
	&pe_i386,
	&pe_amd64
};

static struct _file_support *get_by_image_format(DWORD ImageFormat)
{
	for(DWORD i=0; i < SUPPORTED_IMAGE_FORMAT; i++)
		if (_file_[i]->IMAGE == ImageFormat)
			return _file_[i];

	return NULL;
}
	
/**
 *	\!operator <
 *	compare two "SECTION_ITEM" objects only using "virtual address"
 *	required for stl/list/sort method
 **/
bool operator < (SECTION_ITEM &first, SECTION_ITEM &second)
{
	if (first.va < second.va)
		return true;

	return false;
}

/**
 *	\!operator ==
 *	compare two "SECTION ITEM" objects using only "virtual address"
 *	required for stl/list/remove, remove_if ...
 **/
bool operator == (const SECTION_ITEM &first, const SECTION_ITEM &second)
{
	if (first.va == second.va)
		return true;

	return false;
}

//////////////////////////////////////////////////////////////////////////
// virtual address in range?
static bool va_in_range(virtualaddress_t va, virtualaddress_t base, virtualaddress_t size)
{
	if (base <= va && va <= (base + size))
		return true;

	return false;
}

/**
*	!CPeAssembly
*	<<ctor>>
**/
CPeAssembly::CPeAssembly()
{
}

/**
*	!CPeAssembly
*	<<dtor>>
**/
CPeAssembly::~CPeAssembly()
{
	std::list<SECTION_ITEM>::iterator it = _sections.begin();

	while(it != _sections.end())
	{
		delete it->descriptor;

		it->descriptor = NULL;
		it->va = NULL;

		it++;
	}

	_sections.clear();
}

CPeAssembly::CPeAssembly(void *)
{
}

/****************************************************************************
*	Load/Save libraries!
***************************************************************************/
bool CPeAssembly::Load(char *pFileName)
{
	HANDLE hFile = CreateFileA(pFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	this->_lpBase = NULL;
	this->_lpDosHeader = NULL;
	this->_lpNtHeader = NULL;

	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;

	DWORD numberOfBytesread;
	IMAGE_DOS_HEADER dos_header;
	ZeroMemory(&dos_header, sizeof(dos_header));

	if (ReadFile(hFile, &dos_header, sizeof(dos_header), &numberOfBytesread, NULL) == FALSE)
	{
		CloseHandle(hFile);
		return NULL;
	}

	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew == 0)
	{
		CloseHandle(hFile);
		return NULL;
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
		return NULL;
	}

	if (pe_header.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		DWORD sizeHeader = dos_header.e_lfanew + 
			pe_header.FileHeader.SizeOfOptionalHeader + 
			sizeof(pe_header.FileHeader) + 4;

		IMAGE_SECTION_HEADER first_section;

		ZeroMemory(&first_section, sizeof(IMAGE_SECTION_HEADER));

		SetFilePointer(hFile, sizeHeader, NULL, FILE_BEGIN);

		if (ReadFile(hFile, &first_section, sizeof(IMAGE_SECTION_HEADER), &numberOfBytesread, NULL) == NULL)
		{
			//CloseHandle(hFile);
			//VirtualFree(_lpBase, pe_header.OptionalHeader.SizeOfImage, MEM_FREE);
			return NULL;
		}

		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		
		if (first_section.PointerToRawData == 0)
			DebugBreak();

		this->_lpBase = VirtualAlloc(NULL, roundup(first_section.PointerToRawData, 0x1000), MEM_COMMIT, PAGE_READWRITE);

		if (this->_lpBase == NULL)
			return FALSE;	// cannot load this module for insufficient memory!

		BOOL bResult = ReadFile(hFile, _lpBase, (first_section.PointerToRawData != 0) ? first_section.PointerToRawData : 0x1000, &numberOfBytesread, NULL);

				if (bResult == FALSE)
		{
			DebugBreak();
		}

		// set pointer "DOS_HEADER" and "NT_HEADER" to our "alias"
		_lpDosHeader = (PIMAGE_DOS_HEADER) _lpBase;
		_lpNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS32, _lpDosHeader, _lpDosHeader->e_lfanew);
		
		struct _file_support *stream = get_by_image_format(_lpNtHeader->FileHeader.Machine);

		stream->read(this, hFile, &_sections);	// read from file

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

		DWORD sizeHeader = dos_header.e_lfanew + 
			pe_header.FileHeader.SizeOfOptionalHeader + 
			sizeof(pe_header.FileHeader) + 4;

		IMAGE_SECTION_HEADER section;

		ZeroMemory(&section, sizeof(IMAGE_SECTION_HEADER));

		SetFilePointer(hFile, sizeHeader, NULL, FILE_BEGIN);

		if (ReadFile(hFile, &section, sizeof(section), &numberOfBytesread, NULL) == NULL)
		{
			CloseHandle(hFile);
			VirtualFree(_lpBase, pe_header.OptionalHeader.SizeOfImage, MEM_FREE);
			return NULL;
		}

		_lpBase = VirtualAlloc(NULL, roundup(section.PointerToRawData, 0x1000), MEM_COMMIT, PAGE_READWRITE);

		if (_lpBase == NULL)
		{
			CloseHandle(hFile);
			return NULL;
		}
		SetFilePointer(hFile, 0, NULL, SEEK_SET);

		BOOL bResult = ReadFile(hFile, _lpBase, (section.PointerToRawData != 0) ? section.PointerToRawData : 0x1000, &numberOfBytesread, NULL);

		// set pointer "DOS_HEADER" and "NT_HEADER" to our "alias"
		_lpDosHeader = (PIMAGE_DOS_HEADER) _lpBase;
		_lpNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS32, _lpDosHeader, _lpDosHeader->e_lfanew);
		_lpNtHeader64 = CALC_OFFSET(PIMAGE_NT_HEADERS64, _lpDosHeader, _lpDosHeader->e_lfanew);

		struct _file_support *stream = get_by_image_format(_lpNtHeader64->FileHeader.Machine);

		stream->read(this, hFile, &_sections);	// read from file

	}
	else
	{	// unsupported file machine
	}

	// update alias!


	CloseHandle(hFile);
	return true;
}

bool CPeAssembly::Save(char *pFileName)
{	// refactoring to standard C**
	HANDLE hOutFile = CreateFileA(pFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if(hOutFile == INVALID_HANDLE_VALUE)
		return false;


	if (_lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE || _lpDosHeader->e_lfanew == 0)
	{
		CloseHandle(hOutFile);
		return false;
	}

	// PE header

	if (_lpNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		CloseHandle(hOutFile);
		return false;
	}

	DWORD dwSizeHeader = _lpNtHeader->FileHeader.SizeOfOptionalHeader  + sizeof(_lpNtHeader->FileHeader) + 4;// +
	//sizeof(IMAGE_SECTION_HEADER)*pe_header->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)(_lpBase) + dwSizeHeader + _lpDosHeader->e_lfanew);

	// sort items via iterator using "va"
	_sections.sort();

	std::list<SECTION_ITEM>::iterator it = _sections.begin();

	// -- UPDATE HEADER BEFORE WRITING!!!
	update_section_header();	// transfer new code!
	/* TODO: adjust SizeOfImage and others... */
	// ++ UPDATE HEADER BEFORE WRITING!!!

	struct _file_support *stream = get_by_image_format(_lpNtHeader->FileHeader.Machine);

	if (stream == NULL)
	{
		DebugBreak();	// unsupported file format!
		CloseHandle(hOutFile);
		return FALSE;
	}

	stream->write(this, hOutFile, &_sections);	// write into file!

	return TRUE;
}


/****************************************************************************
*	query on virtual address
***************************************************************************/
virtualaddress_t CPeAssembly::getBaseAddress()
{
	return _lpNtHeader->OptionalHeader.ImageBase;
}

/**
 *	 \!setBaseAddress
 *	apply a new base address to image
 **/
void CPeAssembly::setBaseAddress(virtualaddress_t newva)
{
	virtualaddress_t previous = _lpNtHeader->OptionalHeader.ImageBase;
	if (newva != previous)
	{	// 
		update_relocentries(newva, previous);
		_lpNtHeader->OptionalHeader.ImageBase = newva;	// commit change in header!
	}
}


/****************************************************************************
*	I/O in virtual address (read/write bytes)
***************************************************************************/

/// BYTE read/write members
bool CPeAssembly::ReadByte(virtualaddress_t	va, uint8_t *out)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->ReadByte(va, out);
	}
	return false;
}

bool CPeAssembly::PatchByte(virtualaddress_t va, uint8_t *in)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->PatchByte(va, in);
	}
	return false;

}

/// WORD read/write members
bool CPeAssembly::ReadWord(virtualaddress_t	va, uint16_t *out)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->ReadWord(va, out);
	}
	return false;

}

bool CPeAssembly::PatchWord(virtualaddress_t	va, uint16_t *in)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->PatchWord(va, in);
	}
	return false;

}


/// DWORD read/write members
bool CPeAssembly::ReadDword(virtualaddress_t	va, uint32_t *out)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->ReadDword(va, out);
	}
	return false;

}

bool CPeAssembly::PatchDword(virtualaddress_t	va, uint32_t *in)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->PatchDword(va, in);
	}
	return false;
}

/// QWORD read/write members
bool CPeAssembly::ReadQWord(virtualaddress_t	va, uint64_t *out)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->ReadQWord(va, out);
	}
	return false;
}

bool CPeAssembly::PatchQWord(virtualaddress_t	va, uint64_t *in)
{
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return it->descriptor->PatchQWord(va, in);
	}
	return false;
}

/**
 *	\!roundup
 *	round a value to "base"
 **/
virtualaddress_t CPeAssembly::roundup(virtualaddress_t value, virtualaddress_t base)
{
	virtualaddress_t tmpValue = value;

	if (base == 0)
	{
		std::cout << "[ERROR] Address " << std::hex << value << " for base " << std::hex << base;
		return value;
	}

	while((tmpValue % base) != 0)
		tmpValue++;
	return tmpValue;
}

/**
 *	\!	round_section
 *	return "value" aligned to "SectionAlignment" of PE
 **/
virtualaddress_t CPeAssembly::round_section(virtualaddress_t value)
{
	return roundup(value, _lpNtHeader->OptionalHeader.SectionAlignment);
}

/**
 *	\!	round_file
 *	return "value" aligned to "FileAlignment" of PE
 **/
virtualaddress_t CPeAssembly::round_file(virtualaddress_t value)
{
	return roundup(value, _lpNtHeader->OptionalHeader.FileAlignment);
}

void *CPeAssembly::rva2addr(virtualaddress_t address)
{
	virtualaddress_t dwImageDosHeader = (virtualaddress_t) _lpBase;	// new base address!

	if (address > _lpNtHeader->OptionalHeader.ImageBase)
		address -= _lpNtHeader->OptionalHeader.ImageBase;

	address += dwImageDosHeader;

	return (void *) address;	// warning! this is an absolute pointer, /* TODO! */ Patch in new section model!!
}


/**
*
**/
virtualaddress_t CPeAssembly::getMinva()
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(_lpNtHeader);

	return section->VirtualAddress;
}

virtualaddress_t CPeAssembly::getMaxva()
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(_lpNtHeader);

	short nSections = this->NumberOfSections();

	while((--nSections) > 0)
		section++;

	return section->VirtualAddress + section->Misc.VirtualSize;
}

/******************************************************************************
*	section management
*****************************************************************************/

/**
*	!NumberOfSection
**/
short CPeAssembly::NumberOfSections()
{
	//return _lpNtHeader->FileHeader.NumberOfSections;
	return (short) _sections.size();
}

/**
*	!getSection
*	return a CPeSection object that manage "header" and data
**/
CPeSection*	CPeAssembly::getSection(int index)
{
	if (index >= NumberOfSections())
		return NULL;

	std::list<SECTION_ITEM>::iterator it = _sections.begin();

	while(index-- > 0)
		it++;

	return it->descriptor;
}

PIMAGE_SECTION_HEADER CPeAssembly::LastSectionHeader()
{
	PIMAGE_SECTION_HEADER p = IMAGE_FIRST_SECTION(_lpNtHeader);

	short size = NumberOfSections();

	while(--size > 0)
		p++;

	return p;
}

PIMAGE_SECTION_HEADER CPeAssembly::GetSectionHeader(int index)
{
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(_lpNtHeader);

	while(index-- > 0)
		first++;

	return first;
}

/**
 *	\!LookupSectionByName
 *	looking section by name
 **/
CPeSection *CPeAssembly::LookupSectionByName(const char *szSectionName)
{
	for(SECTION_ITERATOR it = _sections.begin(); it != _sections.end(); it++)
	{
		if (memcmp(szSectionName, it->descriptor->GetSectionHeader()->Name, strlen(szSectionName)) == 0)
			return it->descriptor;
	}
		
	return NULL;
}

/**
*	!RemoveSection
*	delete a section from header and virtual address
**/
bool CPeAssembly::RemoveSection(int index)
{
	if (index >= NumberOfSections())
		return NULL;

	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(_lpNtHeader);
	PIMAGE_SECTION_HEADER last = LastSectionHeader();

	PIMAGE_SECTION_HEADER curr = GetSectionHeader(index);

	if (curr == first)
	{	// first section deleted!
		// move descriptor to this!
		virtualaddress_t begin = first->VirtualAddress;			// "VIRTUAL ADDRESS"
		size_t size = first->Misc.VirtualSize;		// "VIRTUAL SIZE"
		size_t phys_size = first->SizeOfRawData;		// "SIZE OF RAW DATA"
		uint32_t phys_off = first->PointerToRawData;	// "POINTER TO RAW DATA"

		while(first < last)
		{

			//void *dest = rva2addr(
		}


		_lpNtHeader->FileHeader.NumberOfSections--;
		memcpy(first, first+1, sizeof(IMAGE_SECTION_HEADER) * NumberOfSections());

	}
	else if (curr == last)
	{	// zeromemory of "curr"
		_lpNtHeader->FileHeader.NumberOfSections--;
		memset(curr, 0, sizeof(IMAGE_SECTION_HEADER));
	}
	else
	{	
		memcpy(curr, curr+1, sizeof(IMAGE_SECTION_HEADER) * (NumberOfSections() - index));
		_lpNtHeader->FileHeader.NumberOfSections--;
	}

	// update header!!!

	/* TODO */ 

	// update header!!!
	return true;
}

bool CPeAssembly::RemoveSection(const char *szSectionName)
{	// lookup section by name!
	PIMAGE_SECTION_HEADER cursor = GetSectionHeader(0);
	PIMAGE_SECTION_HEADER last = LastSectionHeader();

	int index = 0;
	while(cursor <= last)
	{
		if (strncmp(szSectionName, (char *) cursor->Name, 8) == 0)
			return RemoveSection(index);

		index++;
		cursor++;
	}

	return false;
}

/**
 *	\!nextva
 *	return next virtual address!
 **/
virtualaddress_t CPeAssembly::nextva()
{
	_sections.sort();	// sort 
	
	std::list<SECTION_ITEM>::iterator it = _sections.end();
	it--;

	virtualaddress_t va = it->descriptor->VirtualAddress() + it->descriptor->VirtualSize();

	va = roundup(va, _lpNtHeader->OptionalHeader.SectionAlignment);

	return va;
}

/**
 *	\!nextva
 *	return next virtual address!
 **/
virtualaddress_t CPeAssembly::nextrawdata()
{
	_sections.sort();	// sort 
	
	std::list<SECTION_ITEM>::iterator it = _sections.end();
	it--;

	virtualaddress_t va = it->descriptor->PointerToRawData() + it->descriptor->SizeOfRawData();

	va = round_file(va); 

	return va;
}

/**
 *	\!AddSection
 *	create a new section with "rawsize" value
 **/
CPeSection*	CPeAssembly::AddSection(const char *szSectionName, virtualaddress_t newva, size_t size, size_t rawsize)
{
	// update header!!!
	IMAGE_SECTION_HEADER dummy;
	memset(&dummy, 0, sizeof(IMAGE_SECTION_HEADER));

	size_t len = strlen(szSectionName);
	if (len > 8) len = 8;
	memcpy(dummy.Name, szSectionName, len);

	if (newva == 0)	// add section in tail!
	{
		newva = nextva();
		dummy.PointerToRawData = nextrawdata();
	}

	dummy.VirtualAddress = newva;
	dummy.Misc.VirtualSize = size; //round_section(size);
	rawsize = round_file(rawsize);
	dummy.SizeOfRawData = rawsize;

	void *tmp = malloc(rawsize);
	memset(tmp, 0, rawsize);

	// before write section in list.. update next!
	_sections.sort();

	std::list<SECTION_ITEM>::iterator it = _sections.begin();

	virtualaddress_t sum = round_section(size);
	bool bFound = false;

	lock_datadir();

	virtualaddress_t _reloc_from = 0x0;
	virtualaddress_t _reloc_to = 0x0;

	for(it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t va = it->va;
		size_t size = it->descriptor->VirtualSize();

		if (va >= newva || bFound == true)
		{	// first section to move!!
			
			if (dummy.PointerToRawData == 0)
			{	// get first pointer to raw data
				dummy.PointerToRawData = it->descriptor->PointerToRawData();
			}
			
			//virtualaddress_t old = it->va;
			size_t size = it->descriptor->VirtualSize();

			it->va += sum;
			it->descriptor->SetNewVirtualAddress(it->va);

			update_header(it->va, va, size);	// reflect in header!

			update_datadirectory(it->va, va, size);	// reflect in datadirectory

			if (it->descriptor->SizeOfRawData() != 0)
			{	// adjust pointer to raw data!
				virtualaddress_t p = it->descriptor->PointerToRawData();
				p += dummy.SizeOfRawData;
				it->descriptor->SetPointerToRawData(p);
			}

			if (bFound == false)
			{	// only 1st time!
				_reloc_from = va;
				_reloc_to = it->va;
			}

			bFound = true;
		}
	}

	if (_reloc_from != 0)
		update_relocentries(_reloc_to, _reloc_from, 0);

	/* TODO */
	void *region = malloc(round_section(size));
	memset(region, 0, round_section(size));
	CPeSection *n = new CPeSection(this, &dummy, newva, size, region );
	free(region);

	SECTION_ITEM dummy1 = { newva , n };

	_sections.push_back(dummy1);	// put in list
	_sections.sort();	// re-sort!
	
	
	return n;
}

CPeSection*	CPeAssembly::AddSection(const char *szSectionName, virtualaddress_t newva, size_t size)
{
	// update header!!!
	IMAGE_SECTION_HEADER dummy;
	memset(&dummy, 0, sizeof(IMAGE_SECTION_HEADER));

	size_t len = strlen(szSectionName);
	if (len > 8) len = 8;
	memcpy(dummy.Name, szSectionName, len);

	if (newva == 0)	// add section in tail!
	{
		newva = nextva();
		dummy.PointerToRawData = nextrawdata();
	}

	dummy.VirtualAddress = newva;
	dummy.Misc.VirtualSize = size; //round_section(size);
	dummy.SizeOfRawData = round_file(size);

	void *tmp = malloc(size);
	memset(tmp, 0, size);

	// before write section in list.. update next!
	_sections.sort();

	std::list<SECTION_ITEM>::iterator it = _sections.begin();

	virtualaddress_t sum = round_section(size);
	bool bFound = false;

	lock_datadir();

	virtualaddress_t _reloc_from = 0x0;
	virtualaddress_t _reloc_to = 0x0;

	for(it = _sections.begin(); it != _sections.end(); ++it)
	{
		if (it->va >= newva || bFound == true)
		{	// first section to move!!
			if (dummy.PointerToRawData == 0)
			{	// only first time!
				dummy.PointerToRawData = it->descriptor->PointerToRawData();
			}
			
			virtualaddress_t old = it->va;
			size_t size = it->descriptor->VirtualSize();

			it->va += sum;
			it->descriptor->SetNewVirtualAddress(it->va);

			update_header(it->va, old, size);	// reflect in header!

			update_datadirectory(it->va, old, size);	// reflect in datadirectory

			if (it->descriptor->SizeOfRawData() != 0)
			{	// adjust pointer to raw data!
				virtualaddress_t p = it->descriptor->PointerToRawData();
				p += dummy.SizeOfRawData;
				it->descriptor->SetPointerToRawData(p);
			}

			if (bFound == false)
			{	// only 1st time!
				_reloc_from = old;
				_reloc_to = it->va;
			}

			bFound = true;
		}
	}

	if (_reloc_from != 0)
		update_relocentries(_reloc_to, _reloc_from, 0);

	/* TODO */
	void *region = malloc(round_section(size));
	memset(region, 0, round_section(size));
	CPeSection *n = new CPeSection(this, &dummy, newva, size, region );
	free(region);

	SECTION_ITEM dummy1 = { newva , n };

	_sections.push_back(dummy1);	// put in list
	_sections.sort();	// re-sort!
	
	
	return n;
}

//////////////////////////////////////////////////////////////////////////
// \!MergeSection
//	first section is replaced with new "big" section
CPeSection* CPeAssembly::MergeSection(CPeSection *sect0, CPeSection *sect1)
{
	IMAGE_SECTION_HEADER dummy;
	memset(&dummy, 0, sizeof(IMAGE_SECTION_HEADER));

	size_t size_first_section = sect1->VirtualAddress() - sect0->VirtualAddress();
	
	size_t virtualsize = size_first_section + sect1->VirtualSize();
	
	dummy.Misc.VirtualSize = virtualsize;
	dummy.Characteristics = sect0->GetSectionHeader()->Characteristics;
	dummy.PointerToRawData = sect0->GetSectionHeader()->PointerToRawData;

	/**
	 SizeOfRawData of first section ignored... sect0->GetSectionHeader()->SizeOfRawData
	 new size of first section is same of "Virtual Size" */
	dummy.SizeOfRawData = size_first_section + sect1->GetSectionHeader()->SizeOfRawData;

	void *data = malloc(virtualsize);
	
	memcpy(dummy.Name, sect1->GetSectionHeader()->Name, 8);

	dummy.VirtualAddress = sect0->VirtualAddress();
	
	//dummy.SizeOfRawData = sect0->SizeOfRawData() + sect1->SizeOfRawData();

	memset(data, 0xcc, virtualsize);	// fill section with xcc or xdd

	memcpy(data, sect0->RawData(), sect0->VirtualSize());
	memcpy(CALC_OFFSET(void *, data, sect1->VirtualAddress() - sect0->VirtualAddress()), sect1->RawData(), sect1->VirtualSize());
	
	CPeSection *newsection = new CPeSection(this, &dummy, sect0->VirtualAddress(), virtualsize, data);


	SECTION_ITEM d0 = { sect0->VirtualAddress(), NULL };
	SECTION_ITEM d1 = { sect1->VirtualAddress(), NULL };

	_sections.remove(d0);
	_sections.remove(d1);

	// update header!!!
	//PIMAGE_SECTION_HEADER pSection0 = sect0->GetSectionHeader();

	SECTION_ITEM d2 = { newsection->VirtualAddress(), newsection };

	_sections.push_back(d2);

	_sections.sort();
	
	free(data);

	DWORD sect0_RawData= sect0->SizeOfRawData();
	DWORD sect1_RawData = sect1->SizeOfRawData();
	DWORD sect0_PtrRawData = sect0->PointerToRawData();
	DWORD sect1_PtrRawData = sect0->PointerToRawData();

	delete sect0;	// remove section 0
	delete sect1;	// remove section 1

	DWORD sectN_PtrRawData = newsection->PointerToRawData();
	DWORD sectN_RawData = newsection->SizeOfRawData();

	for(SECTION_ITERATOR it = _sections.begin(); it != _sections.end(); ++it)
	{
		if (it->descriptor->PointerToRawData() > newsection->PointerToRawData())
		{
			DWORD delta = sectN_RawData - sect1_RawData - sect0_RawData;
			DWORD newptr = it->descriptor->PointerToRawData() + delta;

			it->descriptor->SetPointerToRawData(newptr);
		}

	}


	return newsection;
}

void CPeAssembly::update_section_header()
{
	PIMAGE_DOS_HEADER dos_header;
	dos_header = (PIMAGE_DOS_HEADER) this->_lpBase;

	PIMAGE_NT_HEADERS32 pe_header;   
	pe_header = (PIMAGE_NT_HEADERS32)((DWORD) _lpBase + (DWORD)dos_header->e_lfanew );

	DWORD dwSizeHeader = pe_header->FileHeader.SizeOfOptionalHeader  + sizeof(pe_header->FileHeader) + 4;// +
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)(_lpBase) + dwSizeHeader + dos_header->e_lfanew);
	std::list<SECTION_ITEM>::iterator it = _sections.begin();

	memset(sections, 0, pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));	// clear array before new size
	pe_header->FileHeader.NumberOfSections = _sections.size();

	size_t SizeOfCode = 0;
	size_t SizeOfImage = _sections.begin()->va;
	PIMAGE_SECTION_HEADER ptr = sections;
	
	do 
	{
		PIMAGE_SECTION_HEADER src = it->descriptor->GetSectionHeader();
		memcpy(ptr, src, sizeof(IMAGE_SECTION_HEADER));

		if (src->Characteristics & IMAGE_SCN_CNT_CODE)
		{
			SizeOfCode += round_file(src->Misc.VirtualSize);
		}
		
		SizeOfImage += round_section(src->Misc.VirtualSize);

		ptr++;
		it++;
	} while (it != _sections.end());

	pe_header->OptionalHeader.SizeOfCode = SizeOfCode;
	pe_header->OptionalHeader.SizeOfImage = SizeOfImage;
}

void* CPeAssembly::RawPointer(virtualaddress_t va)
{	// return a void* to specified virtualaddress! don't check overflow in section!!!!!
	for (std::list<SECTION_ITEM>::iterator it = _sections.begin(); it != _sections.end(); ++it)
	{
		virtualaddress_t begin = it->va;
		virtualaddress_t end = it->descriptor->VirtualSize() + begin;

		if (begin <= va && va <= end)
			return CALC_OFFSET(void *, it->descriptor->RawData(), va - begin);
	}
	return NULL;
}

/**
 *	update_datadirectory
 *	update all directory to new address!
 **/
void CPeAssembly::update_datadirectory(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = _lpNtHeader->OptionalHeader.DataDirectory;
	
	virtualaddress_t end = baseaddress + size;

	for(int i=0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		// it's a valid virtualaddress and processed only 1 time for SECTION i/o
		if (pImageDataDirectory[i].VirtualAddress != 0 && pImageDataDirectory[i].VirtualAddress == _DATADIR[i].VirtualAddress)
		{	// valid address
			if (baseaddress <= pImageDataDirectory[i].VirtualAddress && pImageDataDirectory[i].VirtualAddress <= end)
			{
				pImageDataDirectory[i].VirtualAddress -= baseaddress;
				pImageDataDirectory[i].VirtualAddress += newbaseaddress;

				switch(i)
				{
					case IMAGE_DIRECTORY_ENTRY_IMPORT: 
						update_importentries(newbaseaddress, baseaddress, size);
						break;
					case IMAGE_DIRECTORY_ENTRY_EXPORT:
						update_exportentries(newbaseaddress, baseaddress, size);
						break;
					case IMAGE_DIRECTORY_ENTRY_RESOURCE:
						update_rsrc(newbaseaddress, baseaddress, size);
						break;
					case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
						update_delayimportentries(newbaseaddress, baseaddress, size);
						break;
					case IMAGE_DIRECTORY_ENTRY_BASERELOC:
						// don't trigger!!
						//update_relocentries(newbaseaddress, baseaddress, size);
						break;
				}
			}
		}
	}
}

#define UPDATE_SYMBOLADDRESS(x, base, newbase) if (x != 0) x = x - base + newbase

void CPeAssembly::update_delayimportentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{	// process import entries!
	PImgDelayDescr pDelayDescr = 
		(PImgDelayDescr) this->RawPointer(_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

	while(pDelayDescr->grAttrs != 0)
	{
		UPDATE_SYMBOLADDRESS(pDelayDescr->rvaBoundIAT, baseaddress, newbaseaddress);
		UPDATE_SYMBOLADDRESS(pDelayDescr->rvaDLLName, baseaddress, newbaseaddress);
		UPDATE_SYMBOLADDRESS(pDelayDescr->rvaHmod, baseaddress, newbaseaddress);
		UPDATE_SYMBOLADDRESS(pDelayDescr->rvaIAT, baseaddress, newbaseaddress);
		UPDATE_SYMBOLADDRESS(pDelayDescr->rvaINT, baseaddress, newbaseaddress);
		UPDATE_SYMBOLADDRESS(pDelayDescr->rvaUnloadIAT, baseaddress, newbaseaddress);

		/*iat->Name -= baseaddress;
		iat->Name += newbaseaddress;

		iat->Characteristics -= baseaddress;
		iat->Characteristics += newbaseaddress;
		iat->FirstThunk -= baseaddress;
		iat->FirstThunk += newbaseaddress;

		PULONG rvaName = (PULONG) this->RawPointer(iat->Characteristics);
		PULONG iatRVA = (PULONG) this->RawPointer(iat->FirstThunk);

		while(*rvaName != 0)
		{
			if ((*rvaName & 0x80000000) == 0)
			{	// Import by name
				*rvaName -= baseaddress;
				*rvaName += newbaseaddress;
			}

			*iatRVA -= baseaddress;
			*iatRVA += newbaseaddress;
			
			rvaName++;
			iatRVA++;
		}
		*/
		pDelayDescr++;
	}

}


void CPeAssembly::update_importentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{	// process import entries!
	PIMAGE_IMPORT_DESCRIPTOR iat = 
		(PIMAGE_IMPORT_DESCRIPTOR) this->RawPointer(_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(iat->Characteristics != 0)
	{
		iat->Name -= baseaddress;
		iat->Name += newbaseaddress;

		iat->Characteristics -= baseaddress;
		iat->Characteristics += newbaseaddress;
		iat->FirstThunk -= baseaddress;
		iat->FirstThunk += newbaseaddress;

		PULONG rvaName = (PULONG) this->RawPointer(iat->Characteristics);
		PULONG iatRVA = (PULONG) this->RawPointer(iat->FirstThunk);

		while(*rvaName != 0)
		{
			if ((*rvaName & 0x80000000) == 0)
			{	// Import by name
				*rvaName -= baseaddress;
				*rvaName += newbaseaddress;
			}

			*iatRVA -= baseaddress;
			*iatRVA += newbaseaddress;
			
			rvaName++;
			iatRVA++;
		}

		iat++;
	}

}

void CPeAssembly::update_exportentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{	// process import entries!
	PIMAGE_EXPORT_DIRECTORY eat = 
		(PIMAGE_EXPORT_DIRECTORY) this->RawPointer(_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	eat->AddressOfFunctions -= baseaddress;
	eat->AddressOfFunctions += newbaseaddress;

	eat->AddressOfNameOrdinals -= baseaddress;
	eat->AddressOfNameOrdinals += newbaseaddress;

	eat->Name -= baseaddress;
	eat->Name += newbaseaddress;

	eat->AddressOfNames -= baseaddress;
	eat->AddressOfNames += newbaseaddress;

	DWORD *addressofnames = (DWORD *) this->RawPointer(eat->AddressOfNames);

	for(DWORD d = 0; d < eat->NumberOfNames; d++)
	{
		addressofnames[d] -= baseaddress;
		addressofnames[d] += newbaseaddress;
	}
	//eat->
	DWORD *AddressOfFunctions = (DWORD *) this->RawPointer(eat->AddressOfFunctions);

	for(DWORD d = 0; d < eat->NumberOfFunctions; d++)
	{
		AddressOfFunctions[d] -= baseaddress;
		AddressOfFunctions[d] += newbaseaddress;
	}

}

//////////////////////////////////////////////////////////////////////////
// create a backup of IMAGE_DATA_DIRECTORY
void CPeAssembly::update_relocentries(virtualaddress_t newimagebase, virtualaddress_t imagebase)
{
	// image base!
	uint32_t ImageBase = _lpNtHeader->OptionalHeader.ImageBase;
	void *lpRelocPointer = RawPointer(_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	size_t dwRelocSize = _lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (dwRelocSize == 0 || lpRelocPointer == NULL)
		return;	// no reloc table here!

	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocPointer;

	// for each page!
	while(relocation_page->BlockSize > 0)
	{
		typedef short relocation_entry;

		int BlockSize = relocation_page->BlockSize - 8;
		relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);

		while(BlockSize > 0)
		{
			short type = ((*entries & 0xf000) >> 12);
			long offset = (*entries & 0x0fff);

			ULONG *ptr = (ULONG *) RawPointer(offset + relocation_page->PageRVA);
			ULONG value = *ptr;
			ULONG dwNewValue = 0;

			switch(type)
			{
			case IMAGE_REL_BASED_HIGHLOW:
				value = value - imagebase;
				value = value + newimagebase;
				*ptr = value;
				break;
			case IMAGE_REL_BASED_DIR64:
				dwNewValue = value - imagebase + (ULONG) newimagebase;
				*ptr = dwNewValue;
				break;
			default:
				break;
			}
			entries++;
			BlockSize -= 2;
		}

		relocation_page = CALC_OFFSET(relocation_block_t *, relocation_page, relocation_page->BlockSize);
	}

}

//////////////////////////////////////////////////////////////////////////
// Perform an update of tree after new section!
void CPeAssembly::update_relocentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{
	typedef struct base_relocation_block
	{
		uint32_t PageRVA;
		uint32_t BlockSize;
	} base_relocation_block_t;

	typedef struct base_relocation_entry
	{
		uint16_t offset : 12;
		uint16_t type : 4;
	} base_relocation_entry_t;

	#define relocation_block_t base_relocation_block_t
	#define relocation_entry_t base_relocation_entry_t

	typedef short relocation_entry;

	// image base!
	uint32_t ImageBase = _lpNtHeader->OptionalHeader.ImageBase;
	void *lpRelocAddress = RawPointer(_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	size_t dwRelocSize = _lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (dwRelocSize == 0 || lpRelocAddress == NULL)
		return;	// no reloc table here!

	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;

	// for each page!
	while(relocation_page->BlockSize > 0)
	{
		if (relocation_page->PageRVA >= baseaddress)
		{
			typedef short relocation_entry;

			int BlockSize = relocation_page->BlockSize - 8;
			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);

			while(BlockSize > 0)
			{
				short type = ((*entries & 0xf000) >> 12);
				long offset = (*entries & 0x0fff);

				ULONG *ptr = (ULONG *) RawPointer(offset + (newbaseaddress - baseaddress) + relocation_page->PageRVA);
				ULONG value = *ptr;
				ULONG dwNewValue = 0;

				if ((value ^ this->_lpNtHeader->OptionalHeader.ImageBase) < 0x1000)
				{	// skip this block!
					entries++;
					BlockSize -= 2;
					continue;
				}

				if (value >= baseaddress)
				{
					switch(type)
					{
						case IMAGE_REL_BASED_HIGHLOW:
							if (value >= 0x1000)	
							{	// accepted values are only in first section!
								value = value - baseaddress;
								value = value + newbaseaddress;
								*ptr = value;
							}
							break;
						case IMAGE_REL_BASED_DIR64:
							dwNewValue = value - baseaddress + (ULONG) newbaseaddress;
							*ptr = dwNewValue;
							break;
						default:
							break;
					}
				}
				entries++;
				BlockSize -= 2;
			}
			relocation_page->PageRVA += (newbaseaddress - baseaddress);
		}

		relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
	}

}
/**
 *	explore_rsrc
 *	recursive function to update entry:OffsetToData into RSRC tree directories
 **/
static void explore_rsrc(PIMAGE_RESOURCE_DIRECTORY root, PIMAGE_RESOURCE_DIRECTORY dir, virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = CALC_OFFSET(PIMAGE_RESOURCE_DIRECTORY_ENTRY, dir, sizeof(IMAGE_RESOURCE_DIRECTORY));

	for(WORD i = 0; i < dir->NumberOfIdEntries; i++)
	{
		if (entries->DataIsDirectory)
		{	// another data!!!
			PIMAGE_RESOURCE_DIRECTORY subdir =
				CALC_OFFSET(PIMAGE_RESOURCE_DIRECTORY, root, entries->OffsetToData & 0x7fffffff);

			explore_rsrc(root, subdir, newbaseaddress, baseaddress, size);
		}
		else
		{
			PIMAGE_RESOURCE_DATA_ENTRY entry = CALC_OFFSET(PIMAGE_RESOURCE_DATA_ENTRY, root, entries->OffsetToData);

			entry->OffsetToData -= baseaddress;
			entry->OffsetToData += newbaseaddress;
		}
		entries++;
	}

}
//////////////////////////////////////////////////////////////////////////
// update rsrc
void CPeAssembly::update_rsrc(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{
	PIMAGE_RESOURCE_DIRECTORY dir =  
		(PIMAGE_RESOURCE_DIRECTORY) this->RawPointer(_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

	explore_rsrc(dir, dir, newbaseaddress, baseaddress, size);
}

void CPeAssembly::update_header(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size)
{
	if (va_in_range(_lpNtHeader->OptionalHeader.AddressOfEntryPoint, baseaddress, size))
	{	// set new AddressPoint
		_lpNtHeader->OptionalHeader.AddressOfEntryPoint -= baseaddress;
		_lpNtHeader->OptionalHeader.AddressOfEntryPoint += newbaseaddress;
	}

	
}
//////////////////////////////////////////////////////////////////////////
// perform a "backup" of PE!OPTIONALHEADER!DATADIRECTORY
void CPeAssembly::lock_datadir()
{
	memcpy(_DATADIR, _lpNtHeader->OptionalHeader.DataDirectory, sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
}