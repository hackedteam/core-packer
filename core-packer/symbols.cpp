#include <Windows.h>
#include "symbols.h"

//#pragma section(".hermit", read, write, execute)

typedef struct _configuration
{
	ULONG64			dwRelocSize;
	ULONG64			lpRelocAddress;
	ULONG64			_key0;
	ULONG64			_key1;
	ULONG64			_baseAddress;
	BYTE			decrypted;
	LPVOID			lpTextBaseAddr;
} CONFIGURATION;

//#pragma section(".hermit", read, write, execute)

/*CONFIGURATION dll32_configuration = {
		0xBABECAFEBAD00021,
		0xBABECAFEBAD00020,
		0xBABECAFEBAD00010,
		0xBABECAFEBAD00011,
		0xBABECAFEBAD00100,
		FALSE,
		NULL
};*/
//
//__declspec(allocate(".hermit"))
//ULONG64				dwRelocSize			= 0xBABECAFEBAD00021;
//
//__declspec(allocate(".hermit"))
//ULONG64				lpRelocAddress		= 0xBABECAFEBAD00020;
//
//__declspec(allocate(".hermit"))
//ULONG64				_rc4key0			= 0xBABECAFEBAD00010;
//
//__declspec(allocate(".hermit"))
//ULONG64				_rc4key1			= 0xBABECAFEBAD00011;


//__declspec(allocate(".hermit"))
//ULONG64				_baseAddress		= 0xBABECAFEBAD00100;

// Fixed symbols from loader
//__declspec(allocate(".hermit"))
//LoadLibraryA_ptr	_LoadLibraryA		= (LoadLibraryA_ptr) 0xBABECAFEBAD00004;

//__declspec(allocate(".hermit"))
//GetProcAddress_ptr	_GetProcAddress		= (GetProcAddress_ptr) 0xBABECAFEBAD00003;

//__declspec(allocate(".hermit"))
//HMODULE g_hKernel32 = NULL;

//__declspec(allocate(".hermit"))
//VirtualProtect_ptr	_VirtualProtect;

//__declspec(allocate(".hermit"))
//VirtualAlloc_ptr	_VirtualAlloc;

extern "C" {

//__declspec(allocate(".hermit"))
//BYTE	g_decrypted = FALSE;

//__declspec(allocate(".hermit"))
//LPVOID	g_lpTextBaseAddr = (LPVOID) 0L;

}
