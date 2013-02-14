#ifndef __PATCHUTILS_H_
#define __PATCHUTILS_H_

/**
 *	@fn NextPointerToRawData
 *	@brief Calculate the new "Pointer to Raw Data" for new section!
 **/
DWORD NextPointerToRawData(PIMAGE_NT_HEADERS pHeader);

/**
 *	@fn NextPointerToRawData64
 *	@brief Calculate the new "Pointer to Raw Data" for new section!
 **/
DWORD NextPointerToRawData64(PIMAGE_NT_HEADERS64 pHeader);

DWORD NextVirtualAddress(PIMAGE_NT_HEADERS pHeader);

DWORD NextVirtualAddress64(PIMAGE_NT_HEADERS64 pHeader);

LPVOID FindBlockMem(LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize);

void Patch_JMP(LPBYTE lpInstruction, DWORD dwNewOffset);
void Patch_MOV(LPBYTE lpInstruction, DWORD dwNewOffset);
void Patch_MARKER_QWORD(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, ULONG64 value);
void Patch_MARKER_DWORD(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD value);

void Patch_Entry(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset);
void Patch_Entry(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset, DWORD dwDisp);
void Patch_MARKER(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD dwSignatureSize, DWORD dwOldOffset);

#endif
