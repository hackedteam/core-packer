#include <Windows.h>

#include "symbols.h"

#include "rva.h"
#include "tea.h"
#include "macro.h"

#pragma section(".peexe32", read, write, execute)

typedef short relocation_entry;

/**
 *	!_configuration
 **/
typedef struct _configuration
{
	ULONG64			dwRelocSize;
	ULONG64			lpRelocAddress;
	ULONG64			_key0;
	ULONG64			_key1;
	ULONG64			_baseAddress;
	BYTE			decrypted;
} CONFIGURATION;

__declspec(allocate(".peexe32"))
CONFIGURATION exe_configuration = {
		0xBABECAFEBAD00021,
		0xBABECAFEBAD00020,
		0xBABECAFEBAD00010,
		0xBABECAFEBAD00011,
		0xBABECAFEBAD00100,
		FALSE
};

//__declspec(allocate(".peexe32"))
//VirtualProtect_ptr	_exe_VirtualProtect;

//__declspec(allocate(".peexe32"))
//VirtualAlloc_ptr	_exe_VirtualAlloc;


typedef struct base_relocation_block
{
	DWORD PageRVA;
	DWORD BlockSize;
} base_relocation_block_t;

typedef struct base_relocation_entry
{
	WORD offset : 12;
	WORD type : 4;
} base_relocation_entry_t;

#define relocation_block_t base_relocation_block_t
#define relocation_entry_t base_relocation_entry_t

#ifdef _BUILD32

extern "C" IMAGE_DOS_HEADER __ImageBase;


typedef SIZE_T (WINAPI *VirtualQuery_ptr)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

#pragma code_seg(".peexe32")
static LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders32->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders32->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

#pragma code_seg(".peexe32")
void reloc_entry_get(relocation_entry *entry, short *type, long *offset)
{
	*type = ((*entry & 0xf000) >> 12);
	*offset = (*entry & 0x0fff);
	return;
}

#pragma code_seg(".peexe32")
static void Reloc_Process_Entry()
{

}

#pragma code_seg(".peexe32")
base_relocation_block_t* next_page(base_relocation_block_t *page)
{
	return CALC_OFFSET(base_relocation_block_t *, page, page->BlockSize);
}


#pragma code_seg(".peexe32")
static void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer)
{
	if (dwRelocSize == 0 || lpRelocAddress == NULL)
	{
		return;	// no reloc table here!
	}

	//DWORD ImageBase = (DWORD) exe_configuration._baseAddress;
	DWORD delta = (DWORD) exe_configuration._baseAddress - (DWORD) pModule;

	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;

#define RELOC_IN_RANGE(page, section) (page->PageRVA >= section->VirtualAddress) && (page->PageRVA <= (section->VirtualAddress + section->Misc.VirtualSize))

	// for each page!
	while(relocation_page->BlockSize > 0)
	{
		if (RELOC_IN_RANGE(relocation_page, pSectionPointer))
		{	// ok.. we can process this page!

			int BlockSize = relocation_page->BlockSize - 8;
			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);

			while(BlockSize > 0)
			{
				short type;
				long offset;

				reloc_entry_get(entries, &type, &offset);

				ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
				//ULONG value = *ptr;

				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					*ptr += delta;
				}
				else if (type == IMAGE_REL_BASED_ABSOLUTE)
				{	// break!
					break;
				}
		
				entries++;
				BlockSize -= 2;
			}

			relocation_page = next_page(relocation_page);
		}
	}

}

#pragma code_seg(".peexe32")
static void __memcpy(char *dst, char *src, int size)
{
	while(size-- > 0)
	{
		*dst++=*src++;
	}
}

typedef void (tea_decrypt_ptr)(uint32_t* v, uint32_t* k);

#pragma code_seg(".peexe32")
static tea_decrypt_ptr *load_decrypt()
{
	char *decrypt = (char *)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	void *start = static_cast<void *>(&tea_decrypt);
	void *end = static_cast<void *>(&tea_decrypt_end_marker);
	int size = static_cast<int>((int) end - (int) start);

	char *src = static_cast<char *>(start);
	char *dst = decrypt;

	while(size-- > 0) 
	{
		*dst ++ = (*src++ ^ 0x66); 
	}

	return (tea_decrypt_ptr *) decrypt;
}


#pragma code_seg(".peexe32")
static BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hinstDLL;
	PIMAGE_NT_HEADERS32 pImageNtHeaders32 = CALC_OFFSET(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);
	
	tea_decrypt_ptr *decrypt = load_decrypt();

	if (pImageNtHeaders32->Signature != IMAGE_NT_SIGNATURE)
	{	// I'm invalid file?
		return FALSE;	
	}
	
	//short NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections - 1;	// I'm on tail!!! please don't patch myself!
	short NumberOfSections = 2;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32);
		
	DWORD dwOldPermissions = NULL, dwDummy = 0;

	while(NumberOfSections > 0)
	{
		pSection++;
		LPDWORD NameDW = (LPDWORD) (pSection->Name);
		if (!((NameDW[1] == 0x74 && NameDW[0] == 0x7865742e) ||
			(NameDW[1] == 0x61 && NameDW[0] == 0x7461642e)))
		{
			continue;
		}

		
		NumberOfSections--;
		dwOldPermissions = 0;
		dwDummy = 0;

		//if ((pSection->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)	// shared memory!
		//	continue;
		
		LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders32, (LPVOID) pSection->VirtualAddress);

		VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

		ULONG64 rc4key[2] = { exe_configuration._key0, exe_configuration._key1 };

		DWORD sbox[4];

		uint32_t *key = (uint32_t *) sbox;
		__memcpy((char *)key, (char *) rc4key, 16);
		LPDWORD encptr = (LPDWORD) lpAddress;

		for(DWORD dwPtr = 0; dwPtr < pSection->SizeOfRawData; dwPtr += 8, encptr += 2)
			decrypt((uint32_t *) encptr, key);

		VirtualProtect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);
		//pSection++;

	}
	

	NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections - 1;	// I'm on tail!!! please don't patch myself!
	pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32);
		
	while(NumberOfSections > 0)
	{
		pSection++;
		dwOldPermissions = 0;
		dwDummy = 0;
		NumberOfSections--;
		if (exe_configuration.decrypted == 0)	// relocation must be done only 1st time!
		{
			// apply reloc in current section!
			LPVOID lpAddress = rva2addr(pImageDosHeader, pImageNtHeaders32, (LPVOID) pSection->VirtualAddress);
			VirtualProtect(lpAddress, pSection->Misc.VirtualSize, PAGE_READWRITE, &dwOldPermissions);

			ULONG ptrReloc = CALC_OFFSET(ULONG, pImageDosHeader, (ULONG) exe_configuration.lpRelocAddress);
			Reloc_Process((LPVOID) pImageDosHeader, pImageNtHeaders32, pSection, (LPVOID) ptrReloc, exe_configuration.dwRelocSize, IMAGE_FIRST_SECTION(pImageNtHeaders32));
			VirtualProtect(lpAddress, pSection->Misc.VirtualSize, dwOldPermissions, &dwDummy);
		}
	}

	//
	return TRUE;
}

#endif

#ifdef _BUILD32
//#pragma code_seg(".peexe32")
//static BOOL bProcessed = FALSE;

struct _strings
{
	char *szKernel32;
	char szVirtualProtect[0x20];
	char szVirtualQuery[0x20];
	char szGetModuleFileNameA[0x40];
	char szGetModuleHandleA[0x40];
};

#pragma code_seg(".peexe32")
char* WINAPI LookString(LPBYTE lpText, short position)
{
	if (position == 0)
		return (char *) lpText;

	while(position > 0)
	{
		if (*lpText == 0)
		{
			position--;
		}

		lpText++;
	}

	return (char *) lpText;
}

#pragma code_seg(".peexe32")
void WINAPI __fuckcrt0startup(struct _strings *ptr)
{
	LPBYTE base;

	__asm
	{
		call	__end
__kernel32:		
		__emit 'k'
		__emit 'e'
		__emit 'r'
		__emit 'n'
		__emit 'e'
		__emit 'l'
		__emit '3'
		__emit '2'
		__emit 00h

__virtualquery:
		__emit 'V'
		__emit 'i'
		__emit 'r'
		__emit 't'
		__emit 'u'
		__emit 'a'
		__emit 'l'
		__emit 'Q'
		__emit 'u'
		__emit 'e'
		__emit 'r'
		__emit 'y'
		__emit 0x00

__getmodulefilenamea:
		__emit 'G'
		__emit 'e'
		__emit 't'
		__emit 'M'
		__emit 'o'
		__emit 'd'
		__emit 'u'
		__emit 'l'
		__emit 'e'
		__emit 'F'
		__emit 'i'
		__emit 'l'
		__emit 'e'
		__emit 'N'
		__emit 'a'
		__emit 'm'
		__emit 'e'
		__emit 'A'
		__emit 0x00
__getmodulehandlea:
		__emit 'G'
		__emit 'e'
		__emit 't'
		__emit 'M'
		__emit 'o'
		__emit 'd'
		__emit 'u'
		__emit 'l'
		__emit 'e'
		__emit 'H'
		__emit 'a'
		__emit 'n'
		__emit 'd'
		__emit 'l'
		__emit 'e'
		__emit 'A'
		__emit 0x00
	__end:
		pop	eax
		mov dword ptr [base], eax
	}

	//char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x00 };
	
	ptr->szKernel32 = LookString(base, 0);

	//__memcpy(ptr->szVirtualProtect, szVirtualProtect, sizeof(szVirtualProtect));
	__memcpy(ptr->szVirtualQuery, LookString(base, 1), sizeof(ptr->szVirtualQuery));
	__memcpy(ptr->szGetModuleFileNameA, LookString(base, 2), sizeof(ptr->szGetModuleFileNameA));
	__memcpy(ptr->szGetModuleHandleA, LookString(base, 3), sizeof(ptr->szGetModuleHandleA));
}

#pragma code_seg(".peexe32")
HANDLE WINAPI _heap_init (void)
{
	HANDLE h = NULL;
        if ( ( h = HeapCreate(0, 0, 0)) == NULL )
            return NULL;

	return h;
}

void WINAPI _heap_term (HANDLE _crtheap)
{
        //  destroy the large-block heap
        HeapDestroy(_crtheap);
        _crtheap=NULL;
}

#pragma code_seg(".peexe32")
static int __cdecl check_managed_app (
        void
        )
{
        PIMAGE_DOS_HEADER pDOSHeader;
        PIMAGE_NT_HEADERS pPEHeader;

        pDOSHeader = &__ImageBase;

        if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }

        pPEHeader = (PIMAGE_NT_HEADERS) ((BYTE *) pDOSHeader + pDOSHeader->e_lfanew);

        if (pPEHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            return 0;
        }

        if (pPEHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        {
            return 0;
        }

        /* prefast assumes we are overflowing __ImageBase */
#pragma warning(push)
#pragma warning(disable:26000)
        if (pPEHeader->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            return 0;
        }
#pragma warning(pop)

        return pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
}

#ifdef _WIN64
#define DEFAULT_SECURITY_COOKIE 0x00002B992DDFA232
#else  /* _WIN64 */
#define DEFAULT_SECURITY_COOKIE 0xBB40E64E
#endif  /* _WIN64 */

__declspec(allocate(".peexe32"))
UINT_PTR __security_cookie = DEFAULT_SECURITY_COOKIE;

__declspec(allocate(".peexe32"))
UINT_PTR __security_cookie_complement = ~(DEFAULT_SECURITY_COOKIE);

typedef union {
    unsigned __int64 ft_scalar;
    FILETIME ft_struct;
} FT;


#pragma code_seg(".peexe32")
void __cdecl __security_init_cookie(void)
{
    UINT_PTR cookie;
    FT systime={0};
    LARGE_INTEGER perfctr;

    /*
     * Do nothing if the global cookie has already been initialized.  On x86,
     * reinitialize the cookie if it has been previously initialized to a
     * value with the high word 0x0000.  Some versions of Windows will init
     * the cookie in the loader, but using an older mechanism which forced the
     * high word to zero.
     */

    if (__security_cookie != DEFAULT_SECURITY_COOKIE
#if defined (_X86_)
        && (__security_cookie & 0xFFFF0000) != 0
#endif  /* defined (_X86_) */
       )
    {
        //__security_cookie_complement = ~__security_cookie;
        return;
    }


    /*
     * Initialize the global cookie with an unpredictable value which is
     * different for each module in a process.  Combine a number of sources
     * of randomness.
     */

    GetSystemTimeAsFileTime(&systime.ft_struct);
#if defined (_WIN64)
    cookie = systime.ft_scalar;
#else  /* defined (_WIN64) */
    cookie = systime.ft_struct.dwLowDateTime;
    cookie ^= systime.ft_struct.dwHighDateTime;
#endif  /* defined (_WIN64) */

    cookie ^= GetCurrentProcessId();
    cookie ^= GetCurrentThreadId();
    cookie ^= GetTickCount();

    QueryPerformanceCounter(&perfctr);
#if defined (_WIN64)
    cookie ^= perfctr.QuadPart;
#else  /* defined (_WIN64) */
    cookie ^= perfctr.LowPart;
    cookie ^= perfctr.HighPart;
#endif  /* defined (_WIN64) */

#if defined (_WIN64)
    /*
     * On Win64, generate a cookie with the most significant word set to zero,
     * as a defense against buffer overruns involving null-terminated strings.
     * Don't do so on Win32, as it's more important to keep 32 bits of cookie.
     */
    cookie &= 0x0000FFFFffffFFFFi64;
#endif  /* defined (_WIN64) */

    /*
     * Make sure the cookie is initialized to a value that will prevent us from
     * reinitializing it if this routine is ever called twice.
     */

    if (cookie == DEFAULT_SECURITY_COOKIE)
    {
        cookie = DEFAULT_SECURITY_COOKIE + 1;
    }
#if defined (_X86_)
    else if ((cookie & 0xFFFF0000) == 0)
    {
        cookie |= ( (cookie|0x4711) << 16);
    }
#endif  /* defined (_X86_) */

    //__security_cookie = cookie;
    //__security_cookie_complement = ~cookie;

}

int stub0(DWORD dwParam)
{
	int initret;
	int mainret = 0;
	int managedapp;

	STARTUPINFOW StartupInfo;
	GetStartupInfoW(&StartupInfo);

	check_managed_app();
	struct _strings init;
	__fuckcrt0startup(&init);
	HANDLE hHeap = _heap_init();
		
	HMODULE h = LoadLibraryA(init.szKernel32);
	//VirtualProtect_ptr p = (VirtualProtect_ptr) GetProcAddress(h, init.szVirtualProtect);
	VirtualQuery_ptr _vquery = (VirtualQuery_ptr) GetProcAddress(h, init.szVirtualQuery);

	MEMORY_BASIC_INFORMATION buffer;

	_vquery(CALC_OFFSET(LPVOID, &__ImageBase, 0x1000), &buffer, sizeof(buffer));
	
	DWORD newptr = buffer.RegionSize + (DWORD) buffer.BaseAddress;

	_vquery((LPVOID) newptr, &buffer, sizeof(buffer));
	
	DWORD ignore0 = 0x32323232;
	DWORD ignore1 = 0x64646464;

	VirtualProtect((LPVOID) newptr, buffer.RegionSize, PAGE_EXECUTE_READWRITE, &ignore0);
	VirtualProtect((LPVOID) h, 0x1000, PAGE_READONLY, &ignore1);
	// = p;
	
	//exe_g_hKernel32 = (HMODULE) &__ImageBase;
		
	//GetModuleHandleA_ptr _GetModuleHandleA = (GetModuleHandleA_ptr) GetProcAddress(h, init.szGetModuleHandleA);

	 //= _GetModuleHandleA(NULL);
			
	/*init.szVirtualProtect[7] = 'A';
	init.szVirtualProtect[8] = 'l';
	init.szVirtualProtect[9] = 'l';
	init.szVirtualProtect[0x0a] = 'o';
	init.szVirtualProtect[0x0b] = 'c';
	init.szVirtualProtect[0x0c] = 0x00;*/
	
	//if (exe_configuration.decrypted == 0)
		/*exe_configuration.decrypted = */decrypt((HINSTANCE) &__ImageBase, DLL_PROCESS_ATTACH, NULL);

	BOOL bConditions[4];
	bConditions[0] = ((dwParam >> 24) == 0x60);
	bConditions[1] = ((dwParam >> 16) & 0xff) == 0x0d;
	bConditions[2] = ((dwParam >> 8) & 0xff) == 0xb4;
	bConditions[3] = (dwParam & 0xff) == 0xb3;
	
	if (bConditions[0] && bConditions[1] && bConditions[2] && bConditions[3])
	{
		return 0;
	}
	return _CrtStartup((HINSTANCE) &__ImageBase);
}

#pragma code_seg(".peexe32")
_declspec(noreturn) 
	extern "C" VOID WINAPI __crt0Startup(DWORD dwParam)
{
	__security_init_cookie();
	stub0(dwParam);
}

#endif
