/*
 * pqc_k12_kem.h
 *
 * OQS_KEM constructors for the KangarooTwelve (RFC 9861) variants of
 * ML-KEM-512/768/1024.  These are NOT part of liboqs -- they wrap the
 * forked PQClean "clean" implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/k12, in which the
 * SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by
 * KangarooTwelve (KT128 for matrix expansion, KT256 for the CBD-noise PRF
 * and implicit-rejection KDF) with the customization-string bytes
 * documented in pqc_bench.c (0x1F matrix, 0x2F CBD noise, 0x3F rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_K12_KEM_H
#define PQC_K12_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_k12_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_k12_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_k12_new(void);

#endif /* PQC_K12_KEM_H */
