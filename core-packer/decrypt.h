#ifndef __DECRYPT_H_

#ifdef _BUILD32
	BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
#else
	BOOL WINAPI decrypt(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
#endif

#endif
