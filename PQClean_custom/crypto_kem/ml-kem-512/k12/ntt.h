#ifndef PQCLEAN_MLKEM512_K12_NTT_H
#define PQCLEAN_MLKEM512_K12_NTT_H
#include "params.h"
#include <stdint.h>

extern const int16_t PQCLEAN_MLKEM512_K12_zetas[128];

void PQCLEAN_MLKEM512_K12_ntt(int16_t r[256]);

void PQCLEAN_MLKEM512_K12_invntt(int16_t r[256]);

void PQCLEAN_MLKEM512_K12_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
