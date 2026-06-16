#ifndef PQCLEAN_MLDSA87_BLAKE3_SYMMETRIC_H
#define PQCLEAN_MLDSA87_BLAKE3_SYMMETRIC_H
#include "blake3.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * BLAKE3 substitution for the SHAKE128/SHAKE256 uses inside ML-DSA, per
 * the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> BLAKE3 XOF, domain 0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> BLAKE3 XOF, domain 0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> BLAKE3 XOF, domain 0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> BLAKE3 XOF, domain 0x4F
 *
 * BLAKE3 has no sponge-level "domain separation byte"; instead the
 * 1-byte value is appended to the absorbed input before
 * blake3_hasher_finalize_seek() is used to squeeze output, mirroring the
 * customization-string convention used by the K12/TurboSHAKE variants so
 * the Vector table in pqc_bench.c stays consistent across backends.
 *
 * BLAKE3 has no native "128 vs 256" rate split the way SHAKE/TurboSHAKE/K12
 * do, so a single xof_state type and block size serve all four vectors.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

/* Arbitrary block size for the squeeze loop -- BLAKE3's XOF has no fixed
 * rate, 168 is chosen to match the SHAKE128 rate used elsewhere. */
#define STREAM128_BLOCKBYTES 168
#define STREAM256_BLOCKBYTES 168
#define XOF_BLOCKBYTES       168

typedef struct {
    blake3_hasher hasher;
    uint64_t squeezed;
} stream128_state;
typedef stream128_state stream256_state;
typedef stream128_state xof_state;

void PQCLEAN_MLDSA87_BLAKE3_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA87_BLAKE3_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA87_BLAKE3_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state);

void PQCLEAN_MLDSA87_BLAKE3_xof_init(xof_state *state);
void PQCLEAN_MLDSA87_BLAKE3_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA87_BLAKE3_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA87_BLAKE3_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA87_BLAKE3_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA87_BLAKE3_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA87_BLAKE3_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA87_BLAKE3_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA87_BLAKE3_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA87_BLAKE3_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA87_BLAKE3_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA87_BLAKE3_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif
