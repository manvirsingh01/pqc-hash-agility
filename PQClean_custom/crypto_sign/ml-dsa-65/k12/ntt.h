#ifndef PQCLEAN_MLDSA65_K12_NTT_H
#define PQCLEAN_MLDSA65_K12_NTT_H
#include "params.h"
#include <stdint.h>

void PQCLEAN_MLDSA65_K12_ntt(int32_t a[N]);

void PQCLEAN_MLDSA65_K12_invntt_tomont(int32_t a[N]);

#endif
