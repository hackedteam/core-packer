/**
*	PE Assembly Library
**/

#ifndef __PEASM_H_
	#define __PEASM_H_

#ifndef CALC_OFFSET
	#define CALC_OFFSET(type, ptr, offset) (type) (((ULONG64) ptr) + offset)
	#define CALC_OFFSET_DISP(type, base, offset, disp) (type)((DWORD)(base) + (DWORD)(offset) + disp)
	#define CALC_DISP(type, offset, ptr) (type) (((ULONG64) offset) - (ULONG64) ptr)
#endif

#include <list>

#include "types.h"

class CPeSection;	// PIMP!
class CPeAssembly;

typedef struct _section_item {
	virtualaddress_t va;
	CPeSection*		 descriptor;
} SECTION_ITEM;

bool operator < (SECTION_ITEM &first, SECTION_ITEM &second);
bool operator == (const SECTION_ITEM &first, const SECTION_ITEM &second);

typedef std::list<SECTION_ITEM>::iterator SECTION_ITERATOR;
typedef std::list<SECTION_ITEM>	SECTION_ARRAY;


struct _file_support {
	DWORD	IMAGE;
	BOOL (*read)(CPeAssembly *pe, HANDLE hFile, SECTION_ARRAY *sections);
	BOOL (*write)(CPeAssembly *pe, HANDLE hFile, SECTION_ARRAY *sections);
};

/**
*	CPeAssembly
*	an editor for PE file (WIN32/WIN64)
**/
class CPeAssembly
{
public:
	CPeAssembly();
	~CPeAssembly();

	CPeAssembly(void *);
	/****************************************************************************
	*	Load/Save libraries!
	***************************************************************************/
	bool	Load(char *pFileName);
	bool	Save(char *pFileName);

	/****************************************************************************
	*	query on virtual address
	***************************************************************************/
	virtualaddress_t	getBaseAddress();	// retrieve virtualaddress
	void				setBaseAddress(virtualaddress_t newva);	//set new virtualaddress

	virtualaddress_t	getMinva();	// retrieve min. virtual address!
	virtualaddress_t	getMaxva();	// retrieve max. virtual address!

	short				NumberOfSections();

	CPeSection*			getSection(int index);
	CPeSection*			LookupSectionByName(char *szSectionName);

	bool				RemoveSection(int index);
	bool				RemoveSection(char *szSectionName);

	CPeSection*			AddSection(char *szSectionName, virtualaddress_t newva, size_t size);
	CPeSection*			MergeSection(CPeSection *sect0, CPeSection *sect1);

	void*				RawPointer(virtualaddress_t va);

	/****************************************************************************
	*	I/O in virtual address (read/write bytes)
	***************************************************************************/
	bool	ReadByte(virtualaddress_t	va, uint8_t *out);
	bool	ReadWord(virtualaddress_t	va, uint16_t *out);
	bool	ReadDword(virtualaddress_t	va, uint32_t *out);
	bool	ReadQWord(virtualaddress_t	va, uint64_t *out);

	bool	PatchByte(virtualaddress_t	va, uint8_t *in);
	bool	PatchWord(virtualaddress_t	va, uint16_t *in);
	bool	PatchDword(virtualaddress_t	va, uint32_t *in);
	bool	PatchQWord(virtualaddress_t	va, uint64_t *in);


	/**
	 *	DataDirectory
	 **/
	inline PIMAGE_DATA_DIRECTORY	DataDirectory() { return _lpNtHeader->OptionalHeader.DataDirectory; };
	inline PIMAGE_DATA_DIRECTORY	DataDirectory64() { return _lpNtHeader64->OptionalHeader.DataDirectory; };


	inline bool IsDLL() { return (_lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) ? true : false; };
	inline bool IsEXE() { return (_lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ? true : false; };

	inline PIMAGE_NT_HEADERS64	NtHeader64() { return _lpNtHeader64; };

	inline PIMAGE_NT_HEADERS32	NtHeader() { return _lpNtHeader; };
	inline PIMAGE_DOS_HEADER	DosHeader() { return _lpDosHeader; };

///////////////////////////////////////////////////////////////////////////////
//
	PIMAGE_EXPORT_DIRECTORY ExportDirectory();
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory();
	PIMAGE_RELOCATION	RelocationDirectory();
	
	PIMAGE_LOAD_CONFIG_DIRECTORY32	LoadConfig32Directory();
	PIMAGE_LOAD_CONFIG_DIRECTORY64	LoadConfig64Directory();


public:	// facility methods
	virtualaddress_t round_section(virtualaddress_t value);
	virtualaddress_t round_file(virtualaddress_t value);

protected:
	void *rva2addr(virtualaddress_t address);

	PIMAGE_SECTION_HEADER LastSectionHeader();
	PIMAGE_SECTION_HEADER GetSectionHeader(int index);

	virtualaddress_t nextva();	// retrieve next virtual address in "sections"
	virtualaddress_t nextrawdata();

private:
	void	lock_datadir();

	virtualaddress_t roundup(virtualaddress_t value, virtualaddress_t base);
	void	update_section_header();
	
	void	update_datadirectory(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size);
	void	update_importentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size);
	void	update_delayimportentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size);
	void	update_exportentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size);
	void	update_relocentries(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size);
	void	update_relocentries(virtualaddress_t newimagebase, virtualaddress_t imagebase);
	void	update_rsrc(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size);
	void	update_header(virtualaddress_t newbaseaddress, virtualaddress_t baseaddress, size_t size);

	std::list<SECTION_ITEM> _sections;

	void*				_lpBase;		// base address of virtual memory!
	PIMAGE_DOS_HEADER	_lpDosHeader;	// alias of "lpBase"
	PIMAGE_NT_HEADERS32	_lpNtHeader;	// alias of DOS->PE pointer (cast must be to PIMAGE_NT_HEADERS64)
	PIMAGE_NT_HEADERS64 _lpNtHeader64;	// alias for x64

	///////////
	// temporary! backup of "DATADIRECTORY" (to remove!)
	IMAGE_DATA_DIRECTORY	_DATADIR[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

#endif
