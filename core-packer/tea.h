#ifndef __TEA_H_
#define __TEA_H_

typedef unsigned int uint32_t;

/**
 *	!tea_encrypt
 *	Tiny Encryption Algorithm - encryption routine!
 **/
void tea_encrypt (uint32_t* v, uint32_t* k);

/**
 *	!tea_decrypt
 *	Tiny Encryption Algorithm - decryption routine!
 **/
void tea_decrypt (uint32_t* v, uint32_t* k);
void tea_decrypt_end_marker(void);	// GENERIC MARKER!

#endif
