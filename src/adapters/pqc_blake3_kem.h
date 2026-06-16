/*
 * pqc_blake3_kem.h
 *
 * OQS_KEM constructors for the BLAKE3 variants of ML-KEM-512/768/1024.
 * These are NOT part of liboqs -- they wrap the forked PQClean "clean"
 * implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/blake3, in which the
 * SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by BLAKE3's
 * native XOF (blake3_hasher_finalize_seek) with the domain-separation
 * bytes documented in pqc_bench.c (0x1F matrix, 0x2F CBD noise, 0x3F
 * rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_BLAKE3_KEM_H
#define PQC_BLAKE3_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_blake3_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_blake3_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_blake3_new(void);

#endif /* PQC_BLAKE3_KEM_H */
