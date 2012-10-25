#include <Windows.h>
#include "rva.h"

#pragma section(".hermit", read, write, execute)

#pragma code_seg(".hermit")
LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG64) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG64) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders64->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders64->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

DWORD diff_rva64(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, DWORD lpAddress1, DWORD lpAddress2)
{
	if (lpAddress1 > lpAddress2)
	{
		return lpAddress1 - lpAddress2;
	}
	else
	{
		DWORD x = (lpAddress2 - lpAddress1);
		x = ~x + 1;
		return x;
	}
}

#pragma code_seg(".hermit")
LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, LPVOID lpAddress)
{
	ULONG64 dwImageDosHeader = (ULONG) pImageDosHeader;	// new base address!
	ULONG64 dwAddress = (ULONG) lpAddress;	// rva

	if (dwAddress > pImageNtHeaders32->OptionalHeader.ImageBase)
		dwAddress -= pImageNtHeaders32->OptionalHeader.ImageBase;

	dwAddress += dwImageDosHeader;

	return (LPVOID) dwAddress;
}

DWORD diff_rva32(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, DWORD lpAddress1, DWORD lpAddress2)
{
	if (lpAddress1 > lpAddress2)
	{
		return lpAddress1 - lpAddress2;
	}
	else
	{
		DWORD x = (lpAddress2 - lpAddress1);
		x = ~x + 1;
		return x;
	}
}
