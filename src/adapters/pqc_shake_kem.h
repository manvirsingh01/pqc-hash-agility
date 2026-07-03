/*
 * pqc_shake_kem.h
 *
 * OQS_KEM constructors for the SHAKE (FIPS 202) baseline variants of
 * ML-KEM-512/768/1024.  These are NOT the liboqs built-ins -- they wrap
 * the forked PQClean "clean" implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/shake, whose
 * symmetric-shake.c is byte-identical to upstream PQClean and is compiled
 * with the exact same Makefile and flags as the five substituted backends
 * (turboshake/k12/blake3/xoodyak/haraka).
 *
 * This makes bench_shake a true hash-substitution baseline: comparing it
 * against the other five backends isolates the hash function itself,
 * with liboqs's separately engineered ML-KEM kept as an independent
 * "production reference" series (bench_liboqs).
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_SHAKE_KEM_H
#define PQC_SHAKE_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_shake_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_shake_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_shake_new(void);

#endif /* PQC_SHAKE_KEM_H */
