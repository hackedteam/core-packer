/***
 *	DllEntryPoint32.cpp
 *	function
 *	#pragma code_seg(".pedll32")
 *	BOOL WINAPI decrypt(struct _vtbl *vtbl, HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
 *
 ==============================================================================================
	else if (__memcmp((char *) pSection->Name, szData, 5) == 0)
	{
		cypher_msg(sbox, (PBYTE) lpAddress, pSection->SizeOfRawData);	// decrypt done!
	}
++
++//
++//		if ((pSection->Characteristics & 0x03) == 3)
++//		{
++//			DWORD sizeOfSection = 
++//				pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
++//					- pSection->VirtualAddress 
++//					- pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
++//						
++//			LPVOID lpNewAddress = CALC_OFFSET(LPVOID, lpAddress, pImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
++//
++//			cypher_msg(sbox, (PBYTE) lpNewAddress, sizeOfSection);	// decrypt done!
++//
++//		} 
++//		else if (pSection->Characteristics & 0x02)
++//		{	// packed section!
++//			LPDWORD lpSectionName = (LPDWORD) pSection->Name;
++//			if (*lpSectionName == 0x7865742e)
++//			{	// text section! load from disk!!
++//				char szFileName[MAX_PATH];
++//				DWORD dw = _GetModuleFileNameA(hinstDLL, szFileName, MAX_PATH);
++//				HANDLE h = vtbl->file_open(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
++//
++//				g_lpTextBaseAddr = vtbl->mem_alloc(0x0, pSection->Misc.VirtualSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
++//
++//				vtbl->file_seek(h, 0x400, 0, SEEK_SET);			//	<< 0x400 - offset on physical disk of first section
++//				_ReadFile(h, g_lpTextBaseAddr, pSection->Misc.VirtualSize, &dw, NULL); //_ReadFile(h, lpAddress, pSection->Misc.VirtualSize, &dw, NULL);
++//				_CloseHandle(h);
++//				cypher_msg(sbox, (PBYTE) g_lpTextBaseAddr, pSection->Misc.VirtualSize); // cypher_msg(sbox, (PBYTE) lpAddress, pSection->Misc.VirtualSize);
++/////////////	
++//			}
++//			else
++//				
++//		}
   ==============================================================================================
	// apply reloc in current section!
	ULONG ptrReloc = CALC_OFFSET(ULONG, pImageDosHeader, (ULONG) lpRelocAddress);

	if (g_decrypted == 0)	// relocation must be done only 1st time!

***/