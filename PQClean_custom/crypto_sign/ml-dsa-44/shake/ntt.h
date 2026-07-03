#ifndef PQCLEAN_MLDSA44_SHAKE_NTT_H
#define PQCLEAN_MLDSA44_SHAKE_NTT_H
#include "params.h"
#include <stdint.h>

void PQCLEAN_MLDSA44_SHAKE_ntt(int32_t a[N]);

void PQCLEAN_MLDSA44_SHAKE_invntt_tomont(int32_t a[N]);

#endif
