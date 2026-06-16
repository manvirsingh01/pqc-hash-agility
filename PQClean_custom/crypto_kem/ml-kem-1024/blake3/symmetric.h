#ifndef PQCLEAN_MLKEM1024_BLAKE3_SYMMETRIC_H
#define PQCLEAN_MLKEM1024_BLAKE3_SYMMETRIC_H
#include "blake3.h"
#include "fips202.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * BLAKE3 substitution for the SHAKE128/SHAKE256 uses inside ML-KEM, per the
 * agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> BLAKE3 XOF, domain 0x1F
 *   Vector 2: CBD noise generation (PRF)      -> BLAKE3 XOF, domain 0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> BLAKE3 XOF, domain 0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/BLAKE3 swap.
 *
 * BLAKE3 has no sponge-level "domain separation byte"; instead these
 * single-byte values are appended to the absorbed input before
 * finalization, mirroring the customization-string convention used by the
 * K12/TurboSHAKE variants so the Vector table in pqc_bench.c stays
 * consistent across backends.
 *
 * BLAKE3 is a native XOF: blake3_hasher_finalize_seek() can produce any
 * number of output bytes starting at any byte offset, so squeezing in
 * XOF_BLOCKBYTES-sized blocks is purely a convention to match the existing
 * rejection-sampling loop in indcpa.c.
 */
#define BLAKE3_CUSTOM_MATRIX 0x1F
#define BLAKE3_CUSTOM_CBD    0x2F
#define BLAKE3_CUSTOM_KDF    0x3F

typedef struct {
    blake3_hasher hasher;
    uint64_t squeezed;
} xof_state;

void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_ctx_release(xof_state *s);

void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* Arbitrary block size for the squeeze loop -- BLAKE3's XOF has no fixed
 * rate, 168 is chosen to match the SHAKE128 rate used elsewhere. */
#define XOF_BLOCKBYTES 168

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_rkprf(OUT, KEY, INPUT)

#endif
