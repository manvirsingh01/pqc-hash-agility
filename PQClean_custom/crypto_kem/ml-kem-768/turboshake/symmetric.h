#ifndef PQCLEAN_MLKEM768_TURBO_SYMMETRIC_H
#define PQCLEAN_MLKEM768_TURBO_SYMMETRIC_H
#include "fips202.h"
#include "params.h"
#include "TurboSHAKE.h"
#include <stddef.h>
#include <stdint.h>

/*
 * TurboSHAKE (RFC 9861) substitution for the SHAKE128/SHAKE256 uses inside
 * ML-KEM, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> TurboSHAKE128, D=0x1F
 *   Vector 2: CBD noise generation (PRF)      -> TurboSHAKE256, D=0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> TurboSHAKE256, D=0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/TurboSHAKE swap.
 */
#define TURBOSHAKE_DOMAIN_MATRIX 0x1F
#define TURBOSHAKE_DOMAIN_CBD    0x2F
#define TURBOSHAKE_DOMAIN_KDF    0x3F

typedef TurboSHAKE_Instance xof_state;

void PQCLEAN_MLKEM768_TURBO_kyber_turboshake128_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM768_TURBO_kyber_turboshake_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM768_TURBO_kyber_turboshake_ctx_release(xof_state *s);

void PQCLEAN_MLKEM768_TURBO_kyber_turboshake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM768_TURBO_kyber_turboshake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* TurboSHAKE128 rate (capacity=256) is 1344 bits = 168 bytes, identical to SHAKE128. */
#define XOF_BLOCKBYTES 168

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM768_TURBO_kyber_turboshake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM768_TURBO_kyber_turboshake_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM768_TURBO_kyber_turboshake_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM768_TURBO_kyber_turboshake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM768_TURBO_kyber_turboshake256_rkprf(OUT, KEY, INPUT)

#endif
