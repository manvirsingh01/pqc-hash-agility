#ifndef PQCLEAN_MLDSA65_XOODYAK_NTT_H
#define PQCLEAN_MLDSA65_XOODYAK_NTT_H
#include "params.h"
#include <stdint.h>

void PQCLEAN_MLDSA65_XOODYAK_ntt(int32_t a[N]);

void PQCLEAN_MLDSA65_XOODYAK_invntt_tomont(int32_t a[N]);

#endif
