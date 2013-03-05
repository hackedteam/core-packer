#include <Windows.h>
#include "library.h"
#include "macro.h"
#include "rva.h"
#include "rc4.h"
#include "symbols.h"

DWORD NextPointerToRawData(PIMAGE_NT_HEADERS pHeader)
{
	DWORD dwPointerToRawData = 0;
	PIMAGE_SECTION_HEADER pSectionToProcess = NULL;

	WORD NumberOfSections = pHeader->FileHeader.NumberOfSections;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pHeader); NumberOfSections > 0; NumberOfSections--, pSection++)	
	{
		if (pSection->PointerToRawData > dwPointerToRawData)
		{
			dwPointerToRawData = pSection->PointerToRawData;
			pSectionToProcess = pSection;
		}
	}

	if (pSectionToProcess != NULL)
	{
		dwPointerToRawData = RoundUp(dwPointerToRawData + pSectionToProcess->SizeOfRawData, pHeader->OptionalHeader.FileAlignment);
	}

	return dwPointerToRawData;
}

DWORD NextPointerToRawData64(PIMAGE_NT_HEADERS64 pHeader)
{
	DWORD dwPointerToRawData = 0;
	PIMAGE_SECTION_HEADER pSectionToProcess = NULL;

	WORD NumberOfSections = pHeader->FileHeader.NumberOfSections;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pHeader); NumberOfSections > 0; NumberOfSections--, pSection++)	
	{
		if (pSection->PointerToRawData > dwPointerToRawData)
		{
			dwPointerToRawData = pSection->PointerToRawData;
			pSectionToProcess = pSection;
		}
	}

	if (pSectionToProcess != NULL)
	{
		dwPointerToRawData = RoundUp(dwPointerToRawData + pSectionToProcess->SizeOfRawData, pHeader->OptionalHeader.FileAlignment);
	}

	return dwPointerToRawData;
}

DWORD NextVirtualAddress(PIMAGE_NT_HEADERS pHeader)
{
	DWORD dwNextVirtualAddress = 0;
	PIMAGE_SECTION_HEADER pSectionToProcess = NULL;

	WORD NumberOfSections = pHeader->FileHeader.NumberOfSections;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pHeader); NumberOfSections > 0; NumberOfSections--, pSection++)	
	{
		if (pSection->VirtualAddress > dwNextVirtualAddress)
		{
			dwNextVirtualAddress = pSection->VirtualAddress;
			pSectionToProcess = pSection;
		}
	}

	if (pSectionToProcess != NULL)
	{
		dwNextVirtualAddress = RoundUp(dwNextVirtualAddress + pSectionToProcess->Misc.VirtualSize, pHeader->OptionalHeader.SectionAlignment);
	}

	return dwNextVirtualAddress;
}

DWORD NextVirtualAddress64(PIMAGE_NT_HEADERS64 pHeader)
{
	DWORD dwNextVirtualAddress = 0;
	PIMAGE_SECTION_HEADER pSectionToProcess = NULL;

	WORD NumberOfSections = pHeader->FileHeader.NumberOfSections;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pHeader); NumberOfSections > 0; NumberOfSections--, pSection++)	
	{
		if (pSection->VirtualAddress > dwNextVirtualAddress)
		{
			dwNextVirtualAddress = pSection->VirtualAddress;
			pSectionToProcess = pSection;
		}
	}

	if (pSectionToProcess != NULL)
	{
		dwNextVirtualAddress = RoundUp(dwNextVirtualAddress + pSectionToProcess->Misc.VirtualSize, pHeader->OptionalHeader.SectionAlignment);
	}

	return dwNextVirtualAddress;
}
// find a block of memory to patch!
LPVOID FindBlockMem(LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize)
{
	while(dwSize >= dwSignatureSize)
	{
		if (memcmp(lpInitialMem, lpSignature, dwSignatureSize) == 0)
			return (LPVOID) lpInitialMem;

		dwSize --;
		lpInitialMem++;
	}

	return NULL;
}

void Patch_JMP(LPBYTE lpInstruction, DWORD dwNewOffset)
{
	LPDWORD dummy = CALC_OFFSET(LPDWORD, lpInstruction, 1);

	*dummy = dwNewOffset;
}

void Patch_MOV(LPBYTE lpInstruction, DWORD dwNewOffset)
{
	LPDWORD dummy = CALC_OFFSET(LPDWORD, lpInstruction, 9);
	*dummy = dwNewOffset;
}

void Patch_MARKER_QWORD(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, ULONG64 value)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, 8);

	if (lpInitialByte != NULL)
	{
		memcpy(lpInitialByte, &value, sizeof(ULONG64));
	}
}

void Patch_MARKER_DWORD(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD value)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, 8);

	if (lpInitialByte != NULL)
	{
		ULONG64 qValue = (ULONG64) value;

		memcpy(lpInitialByte, &qValue, sizeof(ULONG64));
	}
}

void Patch_Entry(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, dwSignatureSize);

	if (lpInitialByte != NULL)
	{
		LPDWORD c = CALC_OFFSET(LPDWORD, lpInitialByte, 0x10);
		*c = dwOldOffset;
	}
}

void Patch_Entry(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset, DWORD dwDisp)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, dwSignatureSize);

	if (lpInitialByte != NULL)
	{
		LPDWORD c = CALC_OFFSET(LPDWORD, lpInitialByte, dwDisp);
		*c = dwOldOffset;
	}
}

void Patch_MARKER(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, dwSignatureSize);

	if (lpInitialByte != NULL)
	{
		LPBYTE c = CALC_OFFSET(LPBYTE, lpInitialByte, 0);

		if (*c == 0xe9)	// jmp marker
		{
#ifdef _BUILD64
			ULONG64 rva = ((ULONG64) lpInitialByte + 5) - ((ULONG64) lpInitialMem) + ((ULONG64) lpBaseBlock);
			DWORD dwNewValue = diff_rva64(NULL, NULL, dwOldOffset, (DWORD) rva);
#else
			ULONG64 x = ((ULONG64) lpInitialByte + 5) - ((ULONG64) lpBaseBlock);
			DWORD dwNewValue = diff_rva32(NULL, NULL, dwOldOffset, (DWORD) x);
#endif

			Patch_JMP((LPBYTE) lpInitialByte, dwNewValue);
		}
		else if (*c == 0x48) // mov marker!
		{
			Patch_MOV((LPBYTE) lpInitialByte, dwOldOffset);
		}
		else if (*c = 0x55)
		{	// push ebp ... 
			LPDWORD sum = CALC_OFFSET(LPDWORD, c, 0x0c);
			*sum = dwOldOffset;
		}
	}
}
