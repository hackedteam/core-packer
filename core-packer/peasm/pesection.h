#ifndef __PESECTION_H_
	#define __PESECTION_H_

class CPeAssembly;	// PIMPL idiom

/**
*	CPeSection
*	SECTION object
**/
class CPeSection
{
public:
	CPeSection(CPeAssembly *parent, PIMAGE_SECTION_HEADER header, virtualaddress_t base, virtualaddress_t size);
	CPeSection(CPeAssembly *parent, PIMAGE_SECTION_HEADER header, virtualaddress_t base, virtualaddress_t size, void *rawdata);
	~CPeSection();

	/****************************************************************************
	*	I/O in virtual address (read/write bytes)
	***************************************************************************/
	bool	ReadByte(virtualaddress_t	VirtualAddress, uint8_t *out);
	bool	ReadWord(virtualaddress_t	VirtualAddress, uint16_t *out);
	bool	ReadDword(virtualaddress_t	VirtualAddress, uint32_t *out);
	bool	ReadQWord(virtualaddress_t	VirtualAddress, uint64_t *out);

	bool	PatchByte(virtualaddress_t	VirtualAddress, uint8_t *in);
	bool	PatchWord(virtualaddress_t	VirtualAddress, uint16_t *in);
	bool	PatchDword(virtualaddress_t	VirtualAddress, uint32_t *in);
	bool	PatchQWord(virtualaddress_t	VirtualAddress, uint64_t *in);

	inline virtualaddress_t	VirtualAddress() { return _base; };
	inline void SetNewVirtualAddress(virtualaddress_t va) { _base = va; _header.VirtualAddress = va; };

	inline virtualaddress_t	VirtualSize() { return _size; };

	inline virtualaddress_t SizeOfRawData() { return _header.SizeOfRawData; };

	inline virtualaddress_t PointerToRawData() { return _header.PointerToRawData; };
	inline void SetPointerToRawData(virtualaddress_t value) { _header.PointerToRawData = value; };

	inline void* RawData() { return _rawData; };
	inline PIMAGE_SECTION_HEADER	GetSectionHeader() { return &_header; };

	void	AddSize(size_t size);

protected:
	inline bool	isInSection(virtualaddress_t va)
	{
		if (va < _base || va > (_base + _size)) return false;
		return true;
	}

private:
	CPeAssembly	*_parent;
	IMAGE_SECTION_HEADER _header;
	virtualaddress_t	_base;
	virtualaddress_t	_size;

	void* _rawData;
};

#endif
