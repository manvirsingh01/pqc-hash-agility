#ifndef PQC_COMMON_HARAKA_H
#define PQC_COMMON_HARAKA_H
/*
 * Minimal ARM-NEON port of the Haraka v2 permutations (Kannwischer et al.,
 * https://github.com/kste/haraka, code/c/neon/haraka.c), trimmed to the two
 * single-instance primitives needed by the ML-KEM "HARAKA" symmetric
 * substitution:
 *
 *   haraka256(out[32], in[32])  -- Haraka-256 (256-bit perm + feedforward)
 *   haraka512(out[32], in[64])  -- Haraka-512 (512-bit perm, Davies-Meyer,
 *                                   truncated to 256 bits)
 *
 * These are the unmodified Haraka v2 round functions; only the surrounding
 * 4x/8x batching and self-test code has been removed.
 */
#include <stdint.h>

void haraka256(unsigned char out[32], const unsigned char in[32]);
void haraka512(unsigned char out[32], const unsigned char in[64]);

#endif
