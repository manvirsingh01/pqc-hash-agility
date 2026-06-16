#ifndef PQCLEAN_MLKEM1024_K12_SYMMETRIC_H
#define PQCLEAN_MLKEM1024_K12_SYMMETRIC_H
#include "fips202.h"
#include "params.h"
#include "KangarooTwelve.h"
#include <stddef.h>
#include <stdint.h>

/*
 * KangarooTwelve (RFC 9861) substitution for the SHAKE128/SHAKE256 uses
 * inside ML-KEM, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> KT128, C=0x1F
 *   Vector 2: CBD noise generation (PRF)      -> KT256, C=0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> KT256, C=0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/K12 swap.
 *
 * K12 has no sponge-level "domain separation byte" the way TurboSHAKE
 * does; instead these single-byte values are used as the K12
 * "customization string" C, which K12 absorbs (with a length encoding)
 * after the message M.  Reusing the same numeric values as the
 * TurboSHAKE build keeps the Vector table in pqc_bench.c consistent.
 */
#define K12_CUSTOM_MATRIX 0x1F
#define K12_CUSTOM_CBD    0x2F
#define K12_CUSTOM_KDF    0x3F

typedef KangarooTwelve_Instance xof_state;

void PQCLEAN_MLKEM1024_K12_kyber_k12_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM1024_K12_kyber_k12_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM1024_K12_kyber_k12_ctx_release(xof_state *s);

void PQCLEAN_MLKEM1024_K12_kyber_k12_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM1024_K12_kyber_k12_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* KT128's underlying TurboSHAKE128 rate (capacity=256) is 1344 bits = 168
 * bytes, identical to SHAKE128 -- so the existing rejection-sampling
 * squeeze loop in indcpa.c works unchanged. */
#define XOF_BLOCKBYTES 168

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM1024_K12_kyber_k12_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM1024_K12_kyber_k12_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM1024_K12_kyber_k12_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM1024_K12_kyber_k12_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM1024_K12_kyber_k12_rkprf(OUT, KEY, INPUT)

#endif
