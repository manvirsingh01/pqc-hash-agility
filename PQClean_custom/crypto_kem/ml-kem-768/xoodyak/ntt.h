#ifndef PQCLEAN_MLKEM768_XOODYAK_NTT_H
#define PQCLEAN_MLKEM768_XOODYAK_NTT_H
#include "params.h"
#include <stdint.h>

extern const int16_t PQCLEAN_MLKEM768_XOODYAK_zetas[128];

void PQCLEAN_MLKEM768_XOODYAK_ntt(int16_t r[256]);

void PQCLEAN_MLKEM768_XOODYAK_invntt(int16_t r[256]);

void PQCLEAN_MLKEM768_XOODYAK_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
