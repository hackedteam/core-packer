#include <Windows.h>
#include "types.h"
#include "peasm.h"
#include "pesection.h"

/////////////////////////////////////////////////////////////////////////////
//

/**
*	!CPeSection
*	default <<ctor>> invoked 
**/
CPeSection::CPeSection(CPeAssembly *parent, PIMAGE_SECTION_HEADER header, virtualaddress_t base, virtualaddress_t size)
: _parent(parent), _base(base), _size(size), _rawData(NULL)
{
	memcpy(&_header, header, sizeof(IMAGE_SECTION_HEADER));
}

CPeSection::CPeSection(CPeAssembly *parent, PIMAGE_SECTION_HEADER header, virtualaddress_t base, virtualaddress_t size, void *rawData)
: _parent(parent), _base(base), _size(size)
{
	memcpy(&_header, header, sizeof(IMAGE_SECTION_HEADER));
	_rawData = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
	memcpy(_rawData, rawData, size);
}


CPeSection::~CPeSection()
{
	if (_rawData != NULL)
		VirtualFree(_rawData, _size, MEM_RELEASE);
}

bool CPeSection::ReadByte(virtualaddress_t	VirtualAddress, uint8_t *out)
{
	memcpy(out, CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), 1);
	return true;
}

bool CPeSection::ReadWord(virtualaddress_t	VirtualAddress, uint16_t *out)
{
	memcpy(out, CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), 2);
	return true;
}


bool CPeSection::ReadDword(virtualaddress_t	VirtualAddress, uint32_t *out)
{
	memcpy(out, CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), 4);
	return true;
}

bool CPeSection::ReadQWord(virtualaddress_t	VirtualAddress, uint64_t *out)
{
	memcpy(out, CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), 8);
	return true;
}


bool CPeSection::PatchByte(virtualaddress_t	VirtualAddress, uint8_t *in)
{
	memcpy(CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), in, 1);
	return true;
}

bool CPeSection::PatchWord(virtualaddress_t	VirtualAddress, uint16_t *in)
{
	memcpy(CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), in, 2);
	return true;
}

bool CPeSection::PatchDword(virtualaddress_t	VirtualAddress, uint32_t *in)
{
	memcpy(CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), in, 4);
	return true;
}

/**
*	\!PatchQword
**/
bool CPeSection::PatchQWord(virtualaddress_t	VirtualAddress, uint64_t *in)
{
	memcpy(CALC_OFFSET(LPVOID, _rawData, VirtualAddress - _base), in, 8);
	return true;
}



void CPeSection::AddSize(size_t size)
{
	if (size == 0)
		return;

	size_t newsize = _size + size;

	void *tmp = VirtualAlloc(NULL, newsize, MEM_COMMIT, PAGE_READWRITE);

	memset(tmp, 0x00, _parent->round_section(newsize));
	memcpy(tmp, _rawData, _size);	// ok data transfered!

	VirtualFree(_rawData, _size, MEM_RELEASE);

	_rawData = tmp;
	_size = newsize;
	_header.SizeOfRawData = _parent->round_file(newsize);
	_header.Misc.VirtualSize = _parent->round_section(newsize);
}
