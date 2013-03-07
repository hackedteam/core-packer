#include <Windows.h>

//#pragma section(".hermit", read, execute)

void swap(PBYTE a, PBYTE b)
{
	BYTE tmp = *a;

	*a = *b;
	*b = tmp;
}

void init_sbox(LPBYTE RC4_SBOX)
{
	for (int i = 0; i < 256; i++)
		RC4_SBOX[i] = i;
}

void init_sbox_key(LPBYTE RC4_SBOX, PBYTE key, int length)
{
	int j = 0;

	for(int i = 0; i < 256; i++)
	{
		j = (j + RC4_SBOX[i] + key[i % length]) % 256;
		swap(&RC4_SBOX[i], &RC4_SBOX[j]);
	}
}

void cypher_msg(LPBYTE RC4_SBOX, PBYTE msg, int length)
{
	int i=0, j=0;

	while(length > 0)
	{
		i = (i+1) % 256;
		j = (j+RC4_SBOX[i]) % 256;
		swap(&RC4_SBOX[i], &RC4_SBOX[j]);
		*msg++ ^= RC4_SBOX[(RC4_SBOX[i] + RC4_SBOX[j]) % 256];
		length--;
	}
}
