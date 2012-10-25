#ifndef __RVA_H_
	#define __RVA_H_

// rva2addr -> Transform a virtual address in "real address"
LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, LPVOID lpAddress);
DWORD diff_rva64(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, DWORD lpAddress1, DWORD lpAddress2);

LPVOID rva2addr(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, LPVOID lpAddress);
DWORD diff_rva32(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, DWORD lpAddress1, DWORD lpAddress2);

#endif

