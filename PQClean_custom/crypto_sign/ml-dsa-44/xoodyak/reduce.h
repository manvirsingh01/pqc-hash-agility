#ifndef PQCLEAN_MLDSA44_XOODYAK_REDUCE_H
#define PQCLEAN_MLDSA44_XOODYAK_REDUCE_H
#include "params.h"
#include <stdint.h>

#define MONT (-4186625) // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

int32_t PQCLEAN_MLDSA44_XOODYAK_montgomery_reduce(int64_t a);

int32_t PQCLEAN_MLDSA44_XOODYAK_reduce32(int32_t a);

int32_t PQCLEAN_MLDSA44_XOODYAK_caddq(int32_t a);

int32_t PQCLEAN_MLDSA44_XOODYAK_freeze(int32_t a);

#endif
