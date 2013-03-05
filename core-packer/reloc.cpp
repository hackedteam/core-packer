//#include <Windows.h>
//#include "reloc.h"
//#include "rva.h"
//#include "macro.h"
//#include "symbols.h"
//
//
//#ifdef _BUILD32
//	#include "dll32.h"
//#endif
//
//#pragma section(".hermit", read, execute)
//
//// Parse reloc table
//#ifdef _BUILD64
//#pragma code_seg(".hermit")
//void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS64 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize)
//{
//	if (dwRelocSize == 0 || lpRelocAddress == NULL)
//		return;	// no reloc table here!
//
//	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;
//
//	if (relocation_page == NULL)
//		return;	// no relocation page available!
//
//	// for each page!
//	while(relocation_page->BlockSize > 0)
//	{
//		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA > (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
//		{	// skip current page!
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//		else
//		{	// ok.. we can process this page!
//			typedef short relocation_entry;
//
//			int BlockSize = relocation_page->BlockSize - 8;
//			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);
//
//			while(BlockSize > 0)
//			{
//				short type = ((*entries & 0xf000) >> 12);
//				long offset = (*entries & 0x0fff);
//
//				ULONG64 *ptr = CALC_OFFSET(PULONG64, pModule, offset + relocation_page->PageRVA);
//				ULONG64 value = *ptr;
//				ULONG64 dwNewValue = 0;
//
//				switch(type)
//				{
//					case IMAGE_REL_BASED_HIGHLOW:
//						value = value - pImageNtHeader->OptionalHeader.ImageBase;
//						value = value + (DWORD) pModule;
//						*ptr = value;
//						break;
//					case IMAGE_REL_BASED_DIR64:
//						dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG64) pModule;
//						*ptr = dwNewValue;
//						break;
//				}
//
//				entries++;
//				BlockSize -= 2;
//			}
//
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//	}
//
//}
//#endif
//
//#ifdef _BUILD32
//
//#pragma code_seg(".hermit")
//BOOL reloc_is_text(PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionText, DWORD offset)
//{
//	DWORD ImageBase = (DWORD) _baseAddress;
//
//	DWORD minVirtualAddress = pSectionText->VirtualAddress;
//	DWORD maxVirtualAddress = pSectionText->VirtualAddress + pSectionText->Misc.VirtualSize;
//
//	offset -= ImageBase;
//	
//	if (minVirtualAddress <= offset && offset < maxVirtualAddress)
//		return TRUE;
//
//	return FALSE;
//}
//
//#pragma code_seg(".hermit")
//void reloctext(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, LPVOID lpTextAddr)
//{
//	DWORD ImageBase = (DWORD) _baseAddress;
//
//	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;
//
//	if (dwRelocSize == 0 || relocation_page == NULL)
//		return;	// no reloc table here!
//
//	// for each page!
//	while(relocation_page->BlockSize > 0)
//	{
//		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA > (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
//		{	// skip current page!
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//		else
//		{	// ok.. we can process this page!
//			typedef short relocation_entry;
//
//			int BlockSize = relocation_page->BlockSize - 8;
//			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);
//
//			while(BlockSize > 0)
//			{
//				short type = ((*entries & 0xf000) >> 12);
//				long offset = (*entries & 0x0fff);
//
//				//ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
//				ULONG *ptr = CALC_OFFSET(PULONG, lpTextAddr, offset + relocation_page->PageRVA - 0x1000);	// base address of .text
//				ULONG value = *ptr;
//				ULONG dwNewValue = 0;
//
//				if (reloc_is_text(pImageNtHeader, pSectionPointer, (DWORD) value) == FALSE)
//				{
//					switch(type)
//					{
//						case IMAGE_REL_BASED_HIGHLOW:
//							value = value - ImageBase;
//							value = value + (DWORD) pModule;
//							*ptr = value;
//							break;
//						case IMAGE_REL_BASED_DIR64:
//							dwNewValue = value - ImageBase + (ULONG) pModule;
//							*ptr = dwNewValue;
//							break;
//						default:
//							break;
//					}
//				}
//				else
//				{	// applying different patch!
//					if (type == IMAGE_REL_BASED_HIGHLOW) 
//					{
//							value = value - ImageBase - 0x1000;
//							value = value + (DWORD) lpTextAddr;
//							*ptr = value;
//					}
//				}
//				
//				entries++;
//
//				BlockSize -= 2;
//			}
//
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//	}
//
//}
//
//#pragma code_seg(".hermit")
//void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer, LPVOID lpTextAddr)
//{
//	DWORD ImageBase = (DWORD) _baseAddress;
//
//	if (dwRelocSize == 0 || lpRelocAddress == NULL)
//		return;	// no reloc table here!
//
//	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;
//
//	if (relocation_page == NULL)
//		return;	// no relocation page available!
//
//	// for each page!
//	while(relocation_page->BlockSize > 0)
//	{
//		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA > (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
//		{	// skip current page!
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//		else
//		{	// ok.. we can process this page!
//			typedef short relocation_entry;
//
//			int BlockSize = relocation_page->BlockSize - 8;
//			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);
//
//			while(BlockSize > 0)
//			{
//				short type = ((*entries & 0xf000) >> 12);
//				long offset = (*entries & 0x0fff);
//
//				ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
//				ULONG value = *ptr;
//				ULONG dwNewValue = 0;
//
//				if (reloc_is_text(pImageNtHeader, pTextPointer, (DWORD) value) == FALSE)
//				{
//					switch(type)
//					{
//						case IMAGE_REL_BASED_HIGHLOW:
//							value = value - ImageBase;
//							value = value + (DWORD) pModule;
//							*ptr = value;
//							break;
//						case IMAGE_REL_BASED_DIR64:
//							dwNewValue = value - ImageBase + (ULONG) pModule;
//							*ptr = dwNewValue;
//							break;
//						default:
//							break;
//					}
//				}
//				else
//				{	// applying different patch!
//					if (type == IMAGE_REL_BASED_HIGHLOW) 
//					{
//							value = value - ImageBase - 0x1000;
//							value = value + (DWORD) lpTextAddr;
//							*ptr = value;
//					}
//				}
//
//
//				/*switch(type)
//				{
//					case IMAGE_REL_BASED_HIGHLOW:
//						value = value - pImageNtHeader->OptionalHeader.ImageBase;
//						value = value + (DWORD) pModule;
//						*ptr = value;
//						break;
//					case IMAGE_REL_BASED_DIR64:
//						dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG) pModule;
//						*ptr = dwNewValue;
//						break;
//				}*/
//				entries++;
//				BlockSize -= 2;
//			}
//
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//	}
//
//}
//
//#endif
