#ifndef PQCLEAN_MLDSA87_SHAKE_NTT_H
#define PQCLEAN_MLDSA87_SHAKE_NTT_H
#include "params.h"
#include <stdint.h>

void PQCLEAN_MLDSA87_SHAKE_ntt(int32_t a[N]);

void PQCLEAN_MLDSA87_SHAKE_invntt_tomont(int32_t a[N]);

#endif
