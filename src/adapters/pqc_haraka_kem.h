/*
 * pqc_haraka_kem.h
 *
 * OQS_KEM constructors for the Haraka v2 variants of ML-KEM-512/768/1024.
 * These are NOT part of liboqs -- they wrap the forked PQClean "clean"
 * implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/haraka, in which the
 * SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by a
 * NON-STANDARD "Haraka-CTR" counter-mode construction over Haraka512
 * (see symmetric.h in the forked trees for the exact construction), with
 * the domain-separation bytes documented in pqc_bench.c (0x1F matrix,
 * 0x2F CBD noise, 0x3F rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_HARAKA_KEM_H
#define PQC_HARAKA_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_haraka_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_haraka_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_haraka_new(void);

#endif /* PQC_HARAKA_KEM_H */
