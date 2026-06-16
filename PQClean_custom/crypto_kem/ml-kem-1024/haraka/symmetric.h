#ifndef PQCLEAN_MLKEM1024_HARAKA_SYMMETRIC_H
#define PQCLEAN_MLKEM1024_HARAKA_SYMMETRIC_H
#include "fips202.h"
#include "haraka.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Haraka v2 substitution for the SHAKE128/SHAKE256 uses inside ML-KEM, per
 * the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> Haraka-CTR-XOF, domain 0x1F
 *   Vector 2: CBD noise generation (PRF)      -> Haraka-CTR-XOF, domain 0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> Haraka-CTR-MD,  domain 0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/Haraka swap.
 *
 * !! NON-STANDARD CONSTRUCTION -- NON-FIPS !!
 * Haraka is a fixed-input/fixed-output short-input permutation (Haraka512:
 * 64-byte input -> 32-byte output via Davies-Meyer + truncation), it is
 * NOT an XOF. To stand in for SHAKE's variable-length XOF/PRF/KDF roles,
 * this build defines a non-standard counter-mode construction
 * ("Haraka-CTR"):
 *
 *   - xof_absorb()/squeezeblocks(): build a 64-byte block from
 *     seed(32) || x || y || domain || zero-padding(29) || counter(8, LE),
 *     and squeeze XOF_BLOCKBYTES=32 bytes per block as
 *     Haraka512(block), incrementing counter for each block.
 *
 *   - prf(): same construction seeded from key(32) || nonce || domain.
 *
 *   - rkprf(): a Merkle-Damgard-style chain over Haraka512 used as the
 *     compression function -- cv_0 = key(32); cv_{i+1} =
 *     Haraka512(cv_i || input_block_i) for each 32-byte block of the
 *     (always-32-byte-multiple) ciphertext; final output =
 *     Haraka512(cv_n || domain || zero-padding)[0:32].
 *
 * This is purely an experimental agility benchmark and is NOT a vetted
 * cryptographic construction.
 */
#define HARAKA_CUSTOM_MATRIX 0x1F
#define HARAKA_CUSTOM_CBD    0x2F
#define HARAKA_CUSTOM_KDF    0x3F

typedef struct {
    uint8_t block[64];
    uint64_t counter;
} xof_state;

void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_ctx_release(xof_state *s);

void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* One Haraka512 call produces 32 bytes per "block". */
#define XOF_BLOCKBYTES 32

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_rkprf(OUT, KEY, INPUT)

#endif
