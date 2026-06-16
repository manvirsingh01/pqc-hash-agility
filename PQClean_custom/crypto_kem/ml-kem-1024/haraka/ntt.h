#ifndef PQCLEAN_MLKEM1024_HARAKA_NTT_H
#define PQCLEAN_MLKEM1024_HARAKA_NTT_H
#include "params.h"
#include <stdint.h>

extern const int16_t PQCLEAN_MLKEM1024_HARAKA_zetas[128];

void PQCLEAN_MLKEM1024_HARAKA_ntt(int16_t r[256]);

void PQCLEAN_MLKEM1024_HARAKA_invntt(int16_t r[256]);

void PQCLEAN_MLKEM1024_HARAKA_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
