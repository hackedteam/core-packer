#ifndef __RC4_H_
#define __RC4_H_

void cypher_msg(LPBYTE RC4_SBOX, PBYTE msg, int length);
void init_sbox_key(LPBYTE RC4_SBOX, PBYTE key, int length);
void init_sbox(LPBYTE RC4_SBOX);

#endif
