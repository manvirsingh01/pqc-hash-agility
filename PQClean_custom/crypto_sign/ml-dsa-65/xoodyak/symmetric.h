#ifndef PQCLEAN_MLDSA65_XOODYAK_SYMMETRIC_H
#define PQCLEAN_MLDSA65_XOODYAK_SYMMETRIC_H
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/* ML-DSA's params.h #defines K to the matrix dimension, which collides
 * with Cyclist.h's use of "K" as a function-parameter name. Hide our K
 * macro while parsing the XKCP header, then restore it. */
#pragma push_macro("K")
#undef K
#include "Xoodyak.h"
#pragma pop_macro("K")

/*
 * Xoodyak (NIST LWC finalist, sponge over the 384-bit Xoodoo permutation,
 * via XKCP's Cyclist construction) substitution for the SHAKE128/SHAKE256
 * uses inside ML-DSA, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> Xoodyak hash mode, domain 0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> Xoodyak hash mode, domain 0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> Xoodyak hash mode, domain 0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> Xoodyak hash mode, domain 0x4F
 *
 * Xoodyak's Cyclist mode is used as a plain sponge: Initialize() with no
 * key selects Cyclist_ModeHash (absorb/squeeze rate = Xoodyak_Rhash = 16
 * bytes). The single-byte domain values are appended to the absorbed
 * input, mirroring the customization-string convention used by the
 * K12/TurboSHAKE/BLAKE3 variants so the Vector table in pqc_bench.c stays
 * consistent across backends. A single xof_state type and block size
 * serve all four vectors.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

/* Xoodyak's hash-mode absorb/squeeze rate (Xoodyak_Rhash). Cyclist_Squeeze()
 * handles arbitrary lengths internally, so this just matches the native
 * rate for the rejection-sampling squeeze loop. */
#define STREAM128_BLOCKBYTES 16
#define STREAM256_BLOCKBYTES 16
#define XOF_BLOCKBYTES       16

typedef Xoodyak_Instance stream128_state;
typedef Xoodyak_Instance stream256_state;
typedef Xoodyak_Instance xof_state;

void PQCLEAN_MLDSA65_XOODYAK_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA65_XOODYAK_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA65_XOODYAK_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state);

void PQCLEAN_MLDSA65_XOODYAK_xof_init(xof_state *state);
void PQCLEAN_MLDSA65_XOODYAK_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA65_XOODYAK_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA65_XOODYAK_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA65_XOODYAK_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA65_XOODYAK_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA65_XOODYAK_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA65_XOODYAK_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA65_XOODYAK_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA65_XOODYAK_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA65_XOODYAK_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA65_XOODYAK_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif
