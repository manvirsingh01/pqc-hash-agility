#ifndef PQCLEAN_MLDSA65_TURBO_SYMMETRIC_H
#define PQCLEAN_MLDSA65_TURBO_SYMMETRIC_H
#include "params.h"
#include "TurboSHAKE.h"
#include <stddef.h>
#include <stdint.h>

/*
 * TurboSHAKE (RFC 9861) substitution for the SHAKE128/SHAKE256 uses inside
 * ML-DSA, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> TurboSHAKE128, D=0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> TurboSHAKE256, D=0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> TurboSHAKE256, D=0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> TurboSHAKE256, D=0x4F
 *
 * Unlike ML-KEM, Dilithium has no separate SHA3-256/512 "hash_h/hash_g"
 * step left untouched -- essentially all hashing in ML-DSA is
 * SHAKE128/256-based, so this substitution touches poly_uniform*,
 * poly_challenge, and every H/CRH call in sign.c.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

/* TurboSHAKE128 rate (capacity=256) = 168 bytes; TurboSHAKE256 rate
 * (capacity=512) = 136 bytes -- identical to SHAKE128/256, so the
 * existing rejection-sampling block-size math in poly.c is unchanged. */
#define STREAM128_BLOCKBYTES 168
#define STREAM256_BLOCKBYTES 136
#define XOF_BLOCKBYTES       136

typedef TurboSHAKE_Instance stream128_state;
typedef TurboSHAKE_Instance stream256_state;
typedef TurboSHAKE_Instance xof_state;

void PQCLEAN_MLDSA65_TURBO_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA65_TURBO_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA65_TURBO_dilithium_squeezeblocks128(uint8_t *out, size_t nblocks, stream128_state *state);
void PQCLEAN_MLDSA65_TURBO_dilithium_squeezeblocks256(uint8_t *out, size_t nblocks, stream256_state *state);

void PQCLEAN_MLDSA65_TURBO_xof_init(xof_state *state);
void PQCLEAN_MLDSA65_TURBO_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA65_TURBO_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA65_TURBO_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA65_TURBO_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA65_TURBO_dilithium_squeezeblocks128(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA65_TURBO_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA65_TURBO_dilithium_squeezeblocks256(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA65_TURBO_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA65_TURBO_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA65_TURBO_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA65_TURBO_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif
