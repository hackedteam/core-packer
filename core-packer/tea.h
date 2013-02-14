#ifndef __TEA_H_
#define __TEA_H_

typedef unsigned int uint32_t;

void encrypt (uint32_t* v, uint32_t* k);
void decrypt (uint32_t* v, uint32_t* k);

#endif
